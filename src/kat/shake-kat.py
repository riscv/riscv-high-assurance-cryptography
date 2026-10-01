#!/usr/bin/env python3
"""SHA-3 family KAT for KLEE: <<KLEE-SHA-3>> over <<KLEE-hash-functions-MACs-XOFs>>, <<KLEE-process-VLI>>.
Keccak-f[1600] and a bit-level FIPS 202 reference sponge from scratch; hashlib is only a labeled oracle."""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, mdh_pack, mdh_unpack, IllegalInstruction, ERROR_STATES,
                    KL_STATE_UNCONFIGURED, KL_STATE_READY, KL_STATE_HASH_ABSORB,
                    KL_STATE_HASH_LAST_BLOCK, KL_STATE_HASH_OUTPUT, KL_STATE_SUCCESS,
                    KL_STATE_FAILURE, KL_STATE_INVALID, KL_CFG_PROVISIONING, section, check,
                    control, info, spec_note, raises, done)

# ---------------------------------------------------------------- FIPS 202

RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1
rol = lambda v, s: ((v << s) | (v >> (64 - s))) & M64 if s else v

def keccak(v):
    """KECCAK-p[1600, 24]; lane (x, y) is v[64(5y+x)+63 : 64(5y+x)] (direct mapping, FIPS 202 sect. 3.1)."""
    A = [(v >> (64 * i)) & M64 for i in range(25)]
    for rc in RC:
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        A = [A[i] ^ C[(i - 1) % 5] ^ rol(C[(i + 1) % 5], 1) for i in range(25)]
        T = [0] * 25
        for x in range(5):
            for y in range(5):
                T[y + 5 * ((2 * x + 3 * y) % 5)] = rol(A[x + 5 * y], RHO[x][y])
        A = [T[i] ^ (~T[i - i % 5 + (i + 1) % 5] & T[i - i % 5 + (i + 2) % 5]) for i in range(25)]
        A[0] ^= rc
    return sum(a << (64 * i) for i, a in enumerate(A))

def ref_sponge(rate, msg, nbits, D, nbytes):
    """Bit-level FIPS 202 sponge on M || D || pad10*1 (string bit j = value bit j)."""
    plen = ((nbits + len(D) + 1) // rate + 1) * rate
    P = sl(msg, nbits - 1, 0) if nbits else 0
    P |= (sum(d << j for j, d in enumerate(D)) | 1 << len(D)) << nbits | 1 << (plen - 1)
    st, out = 0, b''
    for off in range(0, plen, rate):
        st = keccak(st ^ sl(P, off + rate - 1, off))
    while len(out) < nbytes:
        out += v2b(sl(st, rate - 1, 0), rate // 8)
        st = keccak(st)
    return out[:nbytes]

# <<KLEE-SHA-3-parameters>>: (c, b, t, XOF, D as bits, first appended first); Type 6, Modes 0-5
PARAMS = {'SHA3-224': (448, 1152, 224, False, (0, 1)), 'SHA3-256': (512, 1088, 256, False, (0, 1)),
          'SHA3-384': (768, 832, 384, False, (0, 1)), 'SHA3-512': (1024, 576, 512, False, (0, 1)),
          'SHAKE128': (256, 1344, 1344, True, (1, 1, 1, 1)), 'SHAKE256': (512, 1088, 1088, True, (1, 1, 1, 1))}
MACHINE = {name: (6 << 4) | mode for mode, name in enumerate(PARAMS)}
N, GRANULARITY = 1600, 32

def ref_hash(name, msg, nbytes=None):
    c, b, t, xof, D = PARAMS[name]
    return ref_sponge(b, b2v(msg), 8 * len(msg), D, nbytes or t // 8)

def oracle(name, msg, nbytes=None):
    """hashlib: labeled reference oracle."""
    h = hashlib.new(name.lower().replace('-', '_').replace('shake', 'shake_'), msg)
    n = nbytes or PARAMS[name][2] // 8
    return h.digest(n) if PARAMS[name][3] else h.digest()[:n]

# ---------------------------------------------------------------- vectors

MSG_ABC, MSG_A3 = b'abc', b'\xa3' * 200
MSGS = {'empty': b'', 'abc': MSG_ABC, 'a3_200': MSG_A3}
# FIPS 202 examples (NIST CSRC "Example Values", incl. the *_1600 files); SHAKE: 64-byte prefixes
VECTORS = {
    ('SHA3-224', 'empty'): '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
    ('SHA3-256', 'empty'): 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    ('SHA3-384', 'empty'): '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a'
                           'c3713831264adb47fb6bd1e058d5f004',
    ('SHA3-512', 'empty'): 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6'
                           '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
    ('SHAKE128', 'empty'): '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'
                           '3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2',
    ('SHAKE256', 'empty'): '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'
                           'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be',
    ('SHA3-224', 'abc'): 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
    ('SHA3-256', 'abc'): '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    ('SHA3-384', 'abc'): 'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2'
                         '98d88cea927ac7f539f1edf228376d25',
    ('SHA3-512', 'abc'): 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e'
                         '10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
    ('SHAKE128', 'abc'): '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8'
                         '44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378',
    ('SHAKE256', 'abc'): '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739'
                         'd5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4',
    ('SHA3-224', 'a3_200'): '9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0',
    ('SHA3-256', 'a3_200'): '79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787',
    ('SHA3-384', 'a3_200'): '1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd'
                            '76197a31fd55ee989f2d7050dd473e8f',
    ('SHA3-512', 'a3_200'): 'e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8'
                            '1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00',
    ('SHAKE128', 'a3_200'): '131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037'
                            'cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe343817197846',
    ('SHAKE256', 'a3_200'): 'cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d'
                            '2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b',
}
V = lambda name, mid: bytes.fromhex(VECTORS[name, mid])

# ---------------------------------------------------------------- KLEE model

class Hart:
    klstart = 0  # bytes, <<KLEE-CSR-klstart>>

HART = Hart()
C1_BITS = -(-(N + 16) // 128) * 128  # Serialized Content: state, block_base; padded to 128

def kl_size(st):
    """<<KLEE-instruction-size>>, AuxDataLen = 0; a supplied PI MDH is _Unconfigured_."""
    if st in ERROR_STATES:
        return 16
    return 16 if st in (KL_STATE_UNCONFIGURED, KL_CFG_PROVISIONING) else 32 + C1_BITS // 8

def make_pi(name):  # the MDH only
    return v2b(mdh_pack(Machine=MACHINE[name], State=KL_STATE_UNCONFIGURED), 16)

class Sha3:
    wrong_suffix = False  # negative control
    pad_case = None       # which padding clause fired

    def __init__(s):
        s.reset(KL_STATE_UNCONFIGURED)

    def reset(s, st=KL_STATE_INVALID):  # SGR10 for an Error State
        s.st, s.state, s.block_base = st, 0, 0

    def set_machine(s, machine):
        s.machine, s.name = machine, {v: k for k, v in MACHINE.items()}[machine]
        c, s.b, s.t, s.xof, s.D = PARAMS[s.name]

    def provision(s, pi):
        f = mdh_unpack(b2v(pi[:16]))
        assert f['State'] == KL_STATE_UNCONFIGURED and len(pi) == 16
        s.set_machine(f['Machine'])
        s.reset(KL_STATE_READY)  # `state` zeroed
        return s

    def mdh(s):
        return v2b(mdh_pack(Machine=s.machine, State=s.st), 16)

    def export(s, at_order=False):
        """Serialized Content in table order from bit 0; at_order: built with `@` (negative control)."""
        v = cat((s.state, N), (s.block_base, 16)) if at_order else s.state | s.block_base << N
        return v2b(v, C1_BITS // 8)

    @classmethod
    def load(cls, mdh, content):
        s, f, v = cls(), mdh_unpack(b2v(mdh)), b2v(content)
        s.set_machine(f['Machine'])
        s.st, s.state, s.block_base = f['State'], sl(v, N - 1, 0), sl(v, N + 15, N)
        if s.block_base >= s.b:  # not a position within a block: inconsistent Content
            s.reset()
        return s

    def enter_output(s):
        """S = D || pad10*1, the shortest making block_base + |S| a positive multiple of b."""
        room = s.b - s.block_base
        n = room if room >= len(s.D) + 2 else room + s.b
        S = sum(d << j for j, d in enumerate(s.D)) | 1 << len(s.D)
        if s.wrong_suffix:  # suffix byte MSB-aligned
            S = (S & ~0xFF) | int(f'{S & 0xFF:08b}'[::-1], 2)
        S |= 1 << (n - 1)
        s.pad_case = 1 if n == room else 2
        s.state = keccak(s.state ^ (sl(S, room - 1, 0) << s.block_base))
        if n > room:
            s.state = keccak(s.state ^ (S >> room))
        s.block_base, s.st = 0, KL_STATE_HASH_OUTPUT  # block[t-1:0] <- finalize() is the identity

    def setst(s, immed, form='A'):
        if immed in (KL_STATE_SUCCESS, KL_STATE_FAILURE):
            raise IllegalInstruction  # SGR7
        if immed == KL_STATE_UNCONFIGURED or immed in ERROR_STATES:  # in any State
            if s.st != KL_STATE_UNCONFIGURED or not immed:
                s.reset(KL_STATE_INVALID if immed > 53 else immed)
        elif s.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction  # SGR12
        elif s.st in ERROR_STATES:
            pass  # SGR15, SGR16
        elif immed == KL_STATE_READY:
            s.reset(KL_STATE_READY)
        elif form == 'A' and (s.st, immed) == (KL_STATE_READY, KL_STATE_HASH_ABSORB):
            s.st = immed  # Form A: max_len is set by the Machine
        elif form == 'A' and (s.st, immed) == (KL_STATE_HASH_ABSORB, KL_STATE_HASH_OUTPUT):
            s.enter_output()
        else:
            s.reset()  # MGR1, SGR5, MGR11, <<KLEE-process-VLI>> same-State rule
        return s.st

    def fail(s, out, status='invalid'):
        """No operation or Error State: the unwritten output window [klstart, top) is zeroed (SGR16)."""
        if status == 'invalid':
            s.reset()
        if out is not None:
            k = min(HART.klstart, len(out))
            out[k:] = bytes(len(out) - k)
        HART.klstart = 0
        return status

    def exec(s, form, inp=None, out=None, sew=None, interrupt_at=None, end_halt=False, klstart_bits=False):
        """kl.exec; sew None = KLIOBUF; halts at the first point >= interrupt_at (window end if end_halt)."""
        if s.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction
        if s.st in ERROR_STATES:
            return s.fail(out, 'noop')
        halt = (interrupt_at, end_halt)
        if s.st == KL_STATE_HASH_ABSORB and form in 'BD' and inp is not None and out is None:
            if sew is not None and sew < GRANULARITY:
                return s.fail(out)  # MGR2
            p, top = HART.klstart, len(inp)
            if p >= top:
                HART.klstart = 0  # empty window: only klstart = 0 (<<KLEE-CSR-klstart>>)
                return 'empty'
            if p and s.block_base:
                return s.fail(out)  # not an interruption point
            r = s.process_vli(b2v(inp), 8 * top, 8 * p, *halt, klstart_bits)
        elif s.st == KL_STATE_HASH_OUTPUT and form in 'CD' and inp is None and out is not None:
            p, top = HART.klstart, len(out)
            if p >= top:
                HART.klstart = 0  # empty window: only klstart = 0
                return 'empty'
            if p and not (s.xof and s.block_base == 0):
                return s.fail(out)  # not an interruption point, also for an output-only operand
            r = s.squeeze(out, 8 * p, *halt)
        else:
            return s.fail(out)  # MGR1; SGR2 in _Ready_; SGR5 in _Success_
        if r != 'interrupted':
            HART.klstart = 0
        return r

    def process_vli(s, INPUT, KLLEN, ib, interrupt_at, end_halt, klstart_bits=False):
        """process_VLI(0, state, b, state, n, input_base, block_base, 0, None, P(), None, xor_accumulate)."""
        while ib < KLLEN:
            amount = min(KLLEN - ib, s.b - s.block_base)
            s.state ^= sl(INPUT, ib + amount - 1, ib) << s.block_base
            ib, s.block_base = ib + amount, s.block_base + amount
            if s.block_base == s.b:
                s.state, s.block_base = keccak(s.state), 0
            if interrupt_at is not None and ib // 8 >= interrupt_at and (ib < KLLEN or end_halt):  # 4.i
                HART.klstart = ib if klstart_bits else ib // 8
                return 'interrupted'
        return 'done'

    def absorb_bits(s, val, nbits):
        """The process_VLI loop on a bit-granular input (no kl.exec transfers this)."""
        assert s.st == KL_STATE_HASH_ABSORB
        s.process_vli(sl(val, nbits - 1, 0), nbits, 0, None, False)

    def squeeze(s, out, ob, interrupt_at, end_halt):
        OUT, KLLEN = b2v(out), 8 * len(out)
        try:
            while ob < KLLEN:
                amount = min(KLLEN - ob, s.t - s.block_base)
                OUT = (OUT & ~(((1 << amount) - 1) << ob)) | sl(s.state, s.block_base + amount - 1, s.block_base) << ob
                ob, s.block_base = ob + amount, s.block_base + amount
                if s.block_base == s.t:
                    if not s.xof:  # bits beyond output_base cleared
                        OUT, s.st = sl(OUT, ob - 1, 0), KL_STATE_SUCCESS
                        return 'success'
                    s.state, s.block_base = keccak(s.state), 0  # update()
                    if interrupt_at is not None and ob // 8 >= interrupt_at and (ob < KLLEN or end_halt):
                        HART.klstart = ob // 8
                        return 'interrupted'
            return 'done'
        finally:
            out[:] = v2b(OUT, len(out))

class KeyDest:
    """A symmetric `key` of n bytes, a destination in _Ready_ (<<KLEE-derive-endpoints>>); only the key is modelled."""
    def __init__(s, n): s.st, s.n, s.key = KL_STATE_READY, n, None
    def reset(s): s.st, s.key = KL_STATE_INVALID, None

def kl_derive(dst, src, length, interrupt_at=None):
    """_Hash_Output_ kl.exec output -> _Hash_Absorb_ kl.exec input (<<KLEE-derive-endpoints>>, DER6, DER8)
    or a KeyDest (DER6 key derivation, unrestricted)."""
    for c in (src, dst):
        if c.st == KL_STATE_UNCONFIGURED:
            raise IllegalInstruction  # SGR19, source first
    if src.st in ERROR_STATES or dst.st in ERROR_STATES:
        HART.klstart = 0
        return 'noop'
    key = isinstance(dst, KeyDest)
    bad = [c for c, ok in ((src, src.st == KL_STATE_HASH_OUTPUT),
                           (dst, dst.st == (KL_STATE_READY if key else KL_STATE_HASH_ABSORB))) if not ok]
    for c in bad:
        c.reset()  # DER1 items 1-2 (SGR5: a SHA3-n in _Success_ admits no kl.exec)
    pos, HART.klstart = HART.klstart, 0
    if not bad and key:
        if length < dst.n or not src.xof and (src.t - src.block_base) // 8 < dst.n:
            dst.reset()  # DER1 item 5
            return 'invalid'
        dst.key = squeeze(src, dst.n)[1]
        return 'done'
    if bad or not length:
        return 'invalid' if bad else 'done'
    assert src.xof or 8 * length <= src.t - src.block_base
    assert pos == 0 or (pos < length and src.block_base == dst.block_base == 0)
    while pos < length:
        amount = min(length - pos, (src.t - src.block_base) // 8, (dst.b - dst.block_base) // 8)
        dst.state ^= sl(src.state, src.block_base + 8 * amount - 1, src.block_base) << dst.block_base
        src.block_base, dst.block_base, pos = src.block_base + 8 * amount, dst.block_base + 8 * amount, pos + amount
        points = 0
        if dst.block_base == dst.b:
            dst.state, dst.block_base, points = keccak(dst.state), 0, points + 1
        if src.block_base == src.t and not src.xof:
            src.st = KL_STATE_SUCCESS
        elif src.block_base == src.t:
            src.state, src.block_base, points = keccak(src.state), 0, points + 1
        if interrupt_at is not None and interrupt_at <= pos < length and points == 2:  # both endpoints
            HART.klstart = pos
            return 'interrupted'
    return 'done'

# ---------------------------------------------------------------- drivers

def new(name):
    HART.klstart = 0
    return Sha3().provision(make_pi(name))

def absorbing(name, msg=b''):
    cl = new(name)
    cl.setst(KL_STATE_HASH_ABSORB)
    if msg:
        assert cl.exec('B', inp=msg) == 'done'
    return cl

def squeezing(name, msg):
    cl = absorbing(name, msg)
    cl.setst(KL_STATE_HASH_OUTPUT)
    return cl

def squeeze(cl, n, fill=0, **kw):
    out = bytearray([fill] * n)
    return cl.exec('C', out=out, **kw), bytes(out)

def kl_hash(name, msg, nbytes=None, chunks=None, interrupt=None, wrong_suffix=False, klstart_bits=False,
            forms='BC'):
    """Full run; interrupt = (chunk index, interrupt_at): that transfer halts once and is re-executed."""
    cl = new(name)
    cl.wrong_suffix = wrong_suffix
    cl.setst(KL_STATE_HASH_ABSORB)
    for i, ch in enumerate(chunks or [msg]):
        at = interrupt[1] if interrupt and interrupt[0] == i else None
        if cl.exec(forms[0], inp=ch, interrupt_at=at, klstart_bits=klstart_bits) == 'interrupted':
            cl.exec(forms[0], inp=ch)
    cl.setst(KL_STATE_HASH_OUTPUT)
    out = bytearray(nbytes or PARAMS[name][2] // 8)
    cl.exec(forms[1], out=out)
    return bytes(out), cl

def bits_hash(name, nbits, pat):
    val = sl(b2v(pat[:(nbits + 7) // 8]), nbits - 1, 0)
    cl = absorbing(name)
    cl.absorb_bits(val, nbits)
    cl.setst(KL_STATE_HASH_OUTPUT)
    return squeeze(cl, 32)[1], ref_sponge(PARAMS[name][1], val, nbits, PARAMS[name][4], 32), cl.pad_case

# ---------------------------------------------------------------- checks

section('Reference sponge and hashlib oracle vs FIPS 202 vectors')
for (name, mid), h in VECTORS.items():
    want = bytes.fromhex(h)
    check(f'reference {name} {mid}', None, ref_hash(name, MSGS[mid], len(want)), want)
    check(f'[oracle] hashlib {name} {mid}', None, oracle(name, MSGS[mid], len(want)), want)

section('Parameters and encodings')
for name, (c, b, t, xof, D) in PARAMS.items():
    check(f'{name}: b = 1600 - c, t = {"b" if xof else "c/2"}, state_offset + b <= n, 8 | b',
          b == N - c and t == (b if xof else c // 2) and b <= N and b % 8 == 0)
    check(f'{name}: _Machine_ = Type 6 Mode {MACHINE[name] & 15}, round trip through the MDH',
          mdh_unpack(b2v(make_pi(name)))['Machine'] == MACHINE[name] and new(name).name == name)

section('KLEE model, single transfer')
for (name, mid), h in VECTORS.items():
    got, cl = kl_hash(name, MSGS[mid], len(h) // 2)
    check(f'{name} {mid}', None, got, bytes.fromhex(h))
    if not PARAMS[name][3]:
        check(f'{name} {mid}: _Success_', None, cl.st, KL_STATE_SUCCESS)
check('Form D (KLIOBUF) for Forms B and C, SHA3-256 a3_200', None,
      kl_hash('SHA3-256', MSG_A3, forms='DD')[0], V('SHA3-256', 'a3_200'))

section('Chunked absorption')
check('SHAKE128 a3_200, transfers 68+4+100+28 B', None,
      kl_hash('SHAKE128', MSG_A3, 64, [MSG_A3[:68], MSG_A3[68:72], MSG_A3[72:172], MSG_A3[172:]])[0],
      V('SHAKE128', 'a3_200'))
check('SHA3-512 a3_200, transfers 12+60+100+28 B', None,
      kl_hash('SHA3-512', MSG_A3, None, [MSG_A3[:12], MSG_A3[12:72], MSG_A3[72:172], MSG_A3[172:]])[0],
      V('SHA3-512', 'a3_200'))
cl = absorbing('SHA3-256')
check('Form B with SEW = 16 < granularity -> _Invalid_ (MGR2)',
      cl.exec('B', inp=MSG_A3[:16], sew=16) == 'invalid' and cl.st == KL_STATE_INVALID)
cl = absorbing('SHA3-256')
check('Form B with SEW = 32 and 64 accepted', cl.exec('B', inp=MSG_A3[:8], sew=32) == 'done'
      and cl.exec('B', inp=MSG_A3[8:24], sew=64) == 'done' and cl.block_base == 192)

section('Interrupted absorption')
cl = absorbing('SHA3-256')
r = cl.exec('B', inp=MSG_A3, interrupt_at=100)
check('halt at the point after the first block: klstart = input_base / 8 = 136', None,
      (r, HART.klstart), ('interrupted', 136))
check('re-execution resumes at 8 * klstart, retires with klstart = 0', None,
      (cl.exec('B', inp=MSG_A3), HART.klstart), ('done', 0))
cl.setst(KL_STATE_HASH_OUTPUT)
check('SHA3-256 a3_200 after interrupt/resume', None, squeeze(cl, 32)[1], V('SHA3-256', 'a3_200'))
cl = absorbing('SHA3-384', MSG_A3[:12])
r = cl.exec('B', inp=MSG_A3[12:], interrupt_at=1)
saved = (cl.mdh(), cl.export(), HART.klstart)
cl.setst(KL_STATE_UNCONFIGURED)
HART.klstart = 0  # other software runs
cl = Sha3.load(*saved[:2])
HART.klstart = saved[2]
cl.exec('B', inp=MSG_A3[12:])
cl.setst(KL_STATE_HASH_OUTPUT)
check('SHA3-384: halt at klstart = 92 (block boundary after a 12-B transfer)', None,
      (r, saved[2]), ('interrupted', 92))
check('SHA3-384 a3_200 after halt, export, clear, import, resumption', None, squeeze(cl, 48)[1],
      V('SHA3-384', 'a3_200'))
cl = absorbing('SHA3-256')
r = cl.exec('B', inp=MSG_A3[:136], interrupt_at=136, end_halt=True)
snap = (cl.state, cl.block_base)
check('halt at the window end (klstart = KLLEN/8): re-execution is an empty window, only klstart = 0',
      (r, cl.exec('B', inp=MSG_A3[:136]), HART.klstart) == ('interrupted', 'empty', 0)
      and (cl.state, cl.block_base) == snap)
cl.exec('B', inp=MSG_A3[136:])
cl.setst(KL_STATE_HASH_OUTPUT)
check('SHA3-256 a3_200 after the end-of-window halt', None, squeeze(cl, 32)[1], V('SHA3-256', 'a3_200'))
cl = absorbing('SHA3-256', MSG_A3[:4])
snap, HART.klstart = (cl.state, cl.block_base), 250
check('input operand, klstart = 250 > KLLEN/8: empty window, only klstart = 0',
      (cl.exec('B', inp=MSG_A3), (cl.state, cl.block_base), HART.klstart) == ('empty', snap, 0))
HART.klstart = 100
check('input klstart = 100, block_base = 32 (no interruption point): _Invalid_, klstart = 0',
      (cl.exec('B', inp=MSG_A3), cl.st, HART.klstart) == ('invalid', KL_STATE_INVALID, 0))
check('the invalidated locker retains only its MDH (SGR10)', (cl.state, cl.block_base) == (0, 0))
check('kl.setst on the Error State locker: no operation (SGR16)', cl.setst(KL_STATE_HASH_OUTPUT) == KL_STATE_INVALID)
check('Form C kl.exec on it: no operation, output window zeroed (SGR16)', None,
      (squeeze(cl, 32, 0xee), cl.st), (('noop', bytes(32)), KL_STATE_INVALID))

section('Suffix and padding')
pat = bytes((7 * i + 3) & 0xff for i in range(256))
for name, (c, b, t, xof, D) in PARAMS.items():  # |S| = 8: suffix and both pad bits in one byte
    msg, n = pat[:b // 8 - 1], min(32, t // 8)
    got, cl = kl_hash(name, msg, n)
    check(f'[oracle] {name}, rate-1-byte message: one-block clause', (got, cl.pad_case) == (oracle(name, msg, n), 1))
for name in ('SHAKE128', 'SHA3-512'):  # block_base = 0: a full padding block
    msg = pat[:PARAMS[name][1] // 8]
    got, cl = kl_hash(name, msg, 32)
    check(f'[oracle] {name}, rate-exact message: |S| = b', (got, cl.pad_case) == (oracle(name, msg, 32), 1))
for name, nbits in (('SHAKE128', 1342), ('SHA3-256', 1085), ('SHA3-512', 573)):  # b - block_base < |D| + 2
    got, ref, case = bits_hash(name, nbits, pat)
    check(f'{name} {nbits}-bit message: two-block clause = bit-level reference', (got, case) == (ref, 2))
got, ref, case = bits_hash('SHA3-256', 1084, pat)
check('SHA3-256 1084-bit message: one-block clause at |S| = |D| + 2', (got, case) == (ref, 1))

section('Squeezing (XOF)')
stream = oracle('SHAKE128', MSG_ABC, 512)
check('[oracle] SHAKE128 abc stream prefix = FIPS 202 vector', None, stream[:64], V('SHAKE128', 'abc'))
got, cl = kl_hash('SHAKE128', MSG_ABC, 512)
check('[oracle] SHAKE128 512 B in one kl.exec; stays in _Hash_Output_', (got, cl.st) == (stream, KL_STATE_HASH_OUTPUT))
cl = squeezing('SHAKE128', MSG_ABC)
parts = [squeeze(cl, n) for n in (100, 68, 200, 144)]
check('[oracle] SHAKE128 512 B over kl.exec of 100+68+200+144 B; stays in _Hash_Output_',
      b''.join(p[1] for p in parts) == stream and cl.st == KL_STATE_HASH_OUTPUT)
cl = squeezing('SHAKE128', MSG_ABC)
out = bytearray(b'\xee' * 400)
r = cl.exec('C', out=out, interrupt_at=1)
check('squeeze halts at klstart = output_base / 8 = 168; bytes beyond left unwritten (IRR6)',
      (r, HART.klstart, bytes(out[168:])) == ('interrupted', 168, b'\xee' * 232))
check('resumed squeeze retires with klstart = 0', (cl.exec('C', out=out), HART.klstart) == ('done', 0))
check('[oracle] SHAKE128 400 B with interrupt/resume', None, bytes(out), oracle('SHAKE128', MSG_ABC, 400))
cl = squeezing('SHAKE256', MSG_A3)
check('[oracle] SHAKE256 a3_200 336 B over kl.exec of 64+8+264 B', None,
      b''.join(squeeze(cl, n)[1] for n in (64, 8, 264)), oracle('SHAKE256', MSG_A3, 336))
cl = squeezing('SHAKE256', MSG_A3)
out = bytearray(136)
r = cl.exec('C', out=out, interrupt_at=136, end_halt=True)
kept = bytes(out)
check('halt at klstart = KLLEN/8; re-execution is an empty window: OUTPUT intact, klstart = 0',
      (r, cl.exec('C', out=out), bytes(out), HART.klstart) == ('interrupted', 'empty', kept, 0))
check('[oracle] SHAKE256 stream continues at byte 136', None, kept + squeeze(cl, 64)[1],
      oracle('SHAKE256', MSG_A3, 200))
cl = squeezing('SHAKE128', MSG_ABC)
squeeze(cl, 10)
snap = (cl.st, cl.state, cl.block_base)
HART.klstart = 64
check('output only, klstart = KLLEN/8 (empty window): only klstart = 0',
      squeeze(cl, 64, 0xee) == ('empty', b'\xee' * 64) and (cl.st, cl.state, cl.block_base) == snap
      and HART.klstart == 0)
check('[oracle] SHAKE128 stream intact after the empty window', None, squeeze(cl, 502)[1], stream[10:])
snap, HART.klstart = (cl.st, cl.state, cl.block_base), 65
check('output only, klstart = 65 > KLLEN/8: empty window, only klstart = 0', None,
      (squeeze(cl, 64, 0xee), (cl.st, cl.state, cl.block_base), HART.klstart), (('empty', b'\xee' * 64), snap, 0))
HART.klstart = 5
check('output only, klstart = 5, block_base > 0 (no interruption point): _Invalid_, [5, 64) zeroed', None,
      (squeeze(cl, 64, 0xee), cl.st, HART.klstart), (('invalid', b'\xee' * 5 + bytes(59)), KL_STATE_INVALID, 0))

section('SHA3-n: _Success_ after t bits')
cl = squeezing('SHA3-256', MSG_ABC)
r1, d1 = squeeze(cl, 12)
st1 = cl.st
r2, d2 = squeeze(cl, 20)
check('12-B read stays in _Hash_Output_; the next reaches _Success_ at the t-th bit',
      (r1, st1, r2, cl.st) == ('done', KL_STATE_HASH_OUTPUT, 'success', KL_STATE_SUCCESS))
check('SHA3-256 abc digest split 12+20 B', None, d1 + d2, V('SHA3-256', 'abc'))
cl = squeezing('SHA3-384', MSG_ABC)
check('64-B read of SHA3-384: returns at _Success_, bytes [48, 64) cleared', None,
      squeeze(cl, 64, 0xee), ('success', V('SHA3-384', 'abc') + bytes(16)))
cl = squeezing('SHA3-256', MSG_ABC)
squeeze(cl, 32)
check('kl.exec in _Success_ -> _Invalid_, output zeroed (SGR5)', None,
      (squeeze(cl, 32, 0xee), cl.st), (('invalid', bytes(32)), KL_STATE_INVALID))
cl = squeezing('SHA3-256', b'')
squeeze(cl, 32)
ok = cl.setst(KL_STATE_READY) == KL_STATE_READY and (cl.state, cl.block_base) == (0, 0)
check('_Success_ -> _Ready_ (SGR6) zeroes state and block_base', ok)
cl.setst(KL_STATE_HASH_ABSORB)
cl.exec('B', inp=MSG_ABC)
cl.setst(KL_STATE_HASH_OUTPUT)
check('SHA3-256 abc from the CC reused after _Ready_', None, squeeze(cl, 32)[1], V('SHA3-256', 'abc'))

section('States, transitions, Forms')
ab, out_ = (lambda n: absorbing(n, MSG_ABC)), (lambda n: squeezing(n, MSG_ABC))
for label, name, prep, act in [
        ('kl.exec in _Ready_ (SGR2)', 'SHA3-256', new, lambda c: c.exec('B', inp=MSG_ABC)),
        ('_Ready_ -> _Hash_Output_', 'SHA3-256', new, lambda c: c.setst(KL_STATE_HASH_OUTPUT)),
        ('Form B kl.setst to _Hash_Absorb_ (Form A required)', 'SHA3-256', new,
         lambda c: c.setst(KL_STATE_HASH_ABSORB, 'B')),
        ('same-State kl.setst in _Hash_Absorb_', 'SHA3-256', ab, lambda c: c.setst(KL_STATE_HASH_ABSORB)),
        ('kl.setst #kl_state_hash_last_block', 'SHA3-256', ab, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B')),
        ('Form C kl.exec in _Hash_Absorb_ (MGR1)', 'SHA3-256', ab, lambda c: c.exec('C', out=bytearray(32))),
        ('Form A kl.exec in _Hash_Absorb_ (MGR1)', 'SHA3-256', ab,
         lambda c: c.exec('A', inp=MSG_ABC + bytes(1), out=bytearray(4))),
        ('Form B kl.exec in _Hash_Output_ (MGR1)', 'SHAKE256', out_, lambda c: c.exec('B', inp=MSG_ABC)),
        ('same-State kl.setst to _Hash_Output_ (MGR11)', 'SHAKE256', out_, lambda c: c.setst(KL_STATE_HASH_OUTPUT)),
        ('_Hash_Output_ -> _Hash_Absorb_', 'SHAKE256', out_, lambda c: c.setst(KL_STATE_HASH_ABSORB)),
        ('_Success_ -> _Hash_Absorb_ (SGR5, SGR6)', 'SHA3-224', out_,
         lambda c: (squeeze(c, 28), c.setst(KL_STATE_HASH_ABSORB)))]:
    cl = prep(name)
    act(cl)
    check(f'_Invalid_: {label}', cl.st == KL_STATE_INVALID)
cl = squeezing('SHA3-224', MSG_ABC)
check('kl.setst #kl_state_success raises, State kept (SGR7)',
      raises(cl.setst, KL_STATE_SUCCESS) and cl.st == KL_STATE_HASH_OUTPUT)
for mid in ('_Hash_Absorb_', '_Hash_Output_'):
    cl = absorbing('SHAKE128', MSG_A3[:50])
    if mid == '_Hash_Output_':
        cl.setst(KL_STATE_HASH_OUTPUT)
        squeeze(cl, 20)
    cl.setst(KL_STATE_READY)
    cl.setst(KL_STATE_HASH_ABSORB)
    cl.exec('B', inp=MSG_ABC)
    cl.setst(KL_STATE_HASH_OUTPUT)
    check(f'{mid} -> _Ready_ restarts SHAKE128 (abc)', None, squeeze(cl, 64)[1], V('SHAKE128', 'abc'))

section('Provisioning Input and Serialized Content')
check('PI = MDH only; kl.size of a PI MDH = 16',
      len(make_pi('SHA3-256')) == 16 and kl_size(KL_STATE_UNCONFIGURED) == 16)
check('Serialized Content 1600 + 16 bits padded to 1664; kl.size 32 + 208; Error State 16',
      (C1_BITS, kl_size(KL_STATE_HASH_ABSORB), kl_size(KL_STATE_INVALID)) == (1664, 240, 16))
cl = absorbing('SHA3-256', MSG_A3[:100])
c1 = cl.export()
check('layout: [0,200) state, [200,202) bin(block_base, 16) = 800 bits, [202,208) zero',
      (len(c1), c1[:200], c1[200:202], c1[202:]) == (208, v2b(cl.state, 200), v2b(800, 2), bytes(6)))
for label, name, n_abs, n_out, want in [
        ('SHA3-256 in _Hash_Absorb_, block_base 800', 'SHA3-256', 100, None, V('SHA3-256', 'a3_200')),
        ('SHA3-512 in _Hash_Absorb_, block_base 0', 'SHA3-512', 144, None, V('SHA3-512', 'a3_200')),
        ('SHA3-384 in _Hash_Output_, block_base 160', 'SHA3-384', 200, 20, V('SHA3-384', 'a3_200')),
        ('SHAKE128 in _Hash_Output_, block_base 800', 'SHAKE128', 200, 100, oracle('SHAKE128', MSG_A3, 336)),
        ('SHAKE256 in _Hash_Output_, block_base 0', 'SHAKE256', 200, 136, oracle('SHAKE256', MSG_A3, 336)),
        ('SHAKE256 in _Ready_, then abc', 'SHAKE256', 0, None, V('SHAKE256', 'abc'))]:
    cl = absorbing(name, MSG_A3[:n_abs]) if n_abs else new(name)
    head = b''
    if n_out:
        cl.setst(KL_STATE_HASH_OUTPUT)
        head = squeeze(cl, n_out)[1]
    cl = Sha3.load(cl.mdh(), cl.export())
    if not n_out:
        if not n_abs:
            cl.setst(KL_STATE_HASH_ABSORB)
        cl.exec('B', inp=MSG_A3[n_abs:] if n_abs else MSG_ABC)
        cl.setst(KL_STATE_HASH_OUTPUT)
    check(f'export/import round trip, {label}', None, head + squeeze(cl, len(want) - len(head))[1], want)

section('kl.derive')
src, dst = squeezing('SHAKE128', MSG_ABC), absorbing('SHA3-256', MSG_A3[:10])
r = kl_derive(dst, src, 336)
xof = oracle('SHAKE128', MSG_ABC, 400)
check('SHAKE128 -> SHA3-256 (336 B) completes, klstart = 0', (r, HART.klstart) == ('done', 0))
dst.exec('B', inp=MSG_ABC)
dst.setst(KL_STATE_HASH_OUTPUT)
check('[oracle] SHA3-256(a3[:10] || SHAKE128(abc)[:336] || abc) through the open destination', None,
      squeeze(dst, 32)[1], oracle('SHA3-256', MSG_A3[:10] + xof[:336] + MSG_ABC))
check('[oracle] the SHAKE128 source continues at byte 336', None, squeeze(src, 64)[1], xof[336:])
src, dst = squeezing('SHA3-512', MSG_A3), absorbing('SHAKE256')
r = kl_derive(dst, src, 64)
dst.setst(KL_STATE_HASH_OUTPUT)
check('whole SHA3-512 digest -> SHAKE256: source _Success_', (r, src.st) == ('done', KL_STATE_SUCCESS))
check('[oracle] SHAKE256(SHA3-512(a3_200))', None, squeeze(dst, 64)[1], oracle('SHAKE256', V('SHA3-512', 'a3_200'), 64))
src, dst = squeezing('SHAKE128', MSG_A3), absorbing('SHA3-512')
r1 = kl_derive(dst, src, 600, interrupt_at=1)
k1 = HART.klstart
r2 = kl_derive(dst, src, 600)
dst.setst(KL_STATE_HASH_OUTPUT)
check('SHAKE128 (t = 168 B) -> SHA3-512 (b = 72 B): halt at the first common point 504, resumed',
      (r1, k1, r2, HART.klstart) == ('interrupted', 504, 'done', 0))
check('[oracle] SHA3-512(SHAKE128(a3_200)[:600]) after the interrupted derive', None, squeeze(dst, 64)[1],
      oracle('SHA3-512', oracle('SHAKE128', MSG_A3, 600)))
src, dst = squeezing('SHAKE256', MSG_ABC), absorbing('SHA3-224', MSG_ABC)
snap = (src.state, src.block_base, dst.state, dst.block_base)
check('length 0: nothing transferred, no state change (DER8)',
      kl_derive(dst, src, 0) == 'done' and snap == (src.state, src.block_base, dst.state, dst.block_base))
dst = squeezing('SHA3-224', MSG_ABC)
squeeze(dst, 28)
snap = (src.st, src.state, src.block_base)
r = kl_derive(dst, src, 16)
check('destination in _Success_ (SGR5): _Invalid_, nothing taken from the source',
      (r, dst.st) == ('invalid', KL_STATE_INVALID) and snap == (src.st, src.state, src.block_base))

src, dst, s224, d224 = squeezing('SHAKE128', MSG_ABC), KeyDest(16), squeezing('SHA3-224', MSG_ABC), KeyDest(32)
check('DER6 key derivation: SHAKE128(abc) -> a 16-byte `key` in _Ready_ (length 32: 16 B), the XOF continues at '
      'byte 16; SHA3-224 (28 B) -> a 32-byte key (DER1 item 5): destination _Invalid_, source untouched', None,
      (kl_derive(dst, src, 32), dst.key, squeeze(src, 16)[1], kl_derive(d224, s224, 32), d224.st, s224.st),
      ('done', xof[:16], xof[16:32], 'invalid', KL_STATE_INVALID, KL_STATE_HASH_OUTPUT))

section('Negative controls')
control('SHA3-256 suffix byte 0x06 MSB-aligned',
        kl_hash('SHA3-256', b'', wrong_suffix=True)[0] != V('SHA3-256', 'empty'))
control('SHAKE128 suffix byte 0x1F MSB-aligned',
        kl_hash('SHAKE128', b'', 64, wrong_suffix=True)[0] != V('SHAKE128', 'empty'))
control('klstart written in bits, read as bytes',
        kl_hash('SHA3-256', MSG_A3, interrupt=(0, 100), klstart_bits=True)[0] != V('SHA3-256', 'a3_200'))
cl = absorbing('SHA3-256', MSG_A3[:100])
cl = Sha3.load(cl.mdh(), cl.export(at_order=True))
cl.exec('B', inp=MSG_A3[100:])
cl.setst(KL_STATE_HASH_OUTPUT)
control('Serialized Content built with @ (first field most significant)', squeeze(cl, 32)[1] != V('SHA3-256', 'a3_200'))

info('the two-block padding clause needs b - block_base < |D| + 2 <= 6, unreachable with whole-byte transfers; '
     'exercised at bit level')
done()
