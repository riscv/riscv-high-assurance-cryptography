#!/usr/bin/env python3
"""SHA-3 family KAT for KLE: <<KLE-SHA-3>> over <<KLE-hash-functions-MACs-XOFs>>, <<KLE-process-VLI>>.
Keccak-f[1600] and a bit-level FIPS 202 reference sponge from scratch; hashlib is only a labeled oracle."""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, mdh_pack, mdh_unpack, ERROR_STATES, inert,
                    KL_STATE_INERT, KL_STATE_READY, KL_STATE_HASH_ABSORB,
                    KL_STATE_HASH_LAST_BLOCK, KL_STATE_HASH_OUTPUT, KL_STATE_SUCCESS,
                    KL_STATE_FAILURE, KL_STATEEXT_INVALID, KL_STATEEXT_UNSUPPORTED, KL_CFG_PROVISIONING, section, check,
                    control, info, raises, done, HashPort, hash_run, hash_msgs, check_hash, IllegalInstruction)

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

# <<KLE-SHA-3-parameters>>: (c, b, t, XOF, D as bits, first appended first); Type 6, Modes 0-5
PARAMS = {'SHA3-224': (448, 1152, 224, False, (0, 1)), 'SHA3-256': (512, 1088, 256, False, (0, 1)),
          'SHA3-384': (768, 832, 384, False, (0, 1)), 'SHA3-512': (1024, 576, 512, False, (0, 1)),
          'SHAKE128': (256, 1344, 1344, True, (1, 1, 1, 1)), 'SHAKE256': (512, 1088, 1088, True, (1, 1, 1, 1))}
MACHINE = {name: (6 << 4) | mode for mode, name in enumerate(PARAMS)}
N, GRANULARITY = 1600, 8

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
CAVP_BITS = [  # NIST CAVP bit-oriented vectors (CAVS 19.0: SHA3AllBits1-28-16, SHAKE3AllBitsGT)
    # (name, Len, whole bytes absorbed in _Hash_Absorb_, exercises, Msg, MD / Output)
    ('SHA3-224', 5, 0, 'piece only',
     '1f',
     '65ad282dcf9642a2facc1e7545c58f3b17523e795fee58e4d21b10bf'),
    ('SHA3-224', 1149, 100, 'two-block padding',
     'cbcdc748275692f43e01048321e8e07dc87201200876efa8bfa3b0ce521fe18f596e052e98961c7c3280785719a2cc71'
     'c9db8653369e5ea102532f9ff4fa06f4a61279ae7db93b87de14ed669ff13629bcab15a24c4e76dfb3fc04af18903f61'
     '1a80cecfbe08169cac850bb99c1f462e0baa591732ce5fec3866d706a727b25f1d82aa9a44cbd643039a7b57f6722607',
     '9c8ec99effb33fdad7d56d06732992a9cf96a6d8f6c5990133b85be0'),
    ('SHA3-256', 5, 0, 'piece only',
     '1f',
     '3620b189e194c3ca52f6357aefb4d2473ef4ca23011ca75eccb4cc4cb438d54b'),
    ('SHA3-256', 1085, 100, 'two-block padding',
     'ae9a9e2be9f4b0d29b20a1dc23d4e24990b31483b416c040790c48a979a01dbcc85a33ef1408b216f1bdef866e1b9a7b'
     'ecce39b73059d46cb615f25c4876c53fd091a2656bdbb49cbe34f0548d244b0189642bc16aa01c3f3e7bc5d701d41afb'
     '6d47d3d513f71c2dab8b8e8ea9775ea4117dd4e98b73ff81ba46a861ca3f84b74885ad8637e45311',
     'bfd6c9d1de5548e9373e8832bb833ac961fd003031258ec0c8812cfb95e3acba'),
    ('SHA3-384', 5, 0, 'piece only',
     '03',
     'e920d1d4daddf9632104373762c8b61e27a3f44700c2f7321c40e8612fcae37c3f8911547104780e49748cb5365fb379'),
    ('SHA3-384', 829, 100, 'two-block padding',
     '1d82c883e189f86909bf8d42f8c7325dcc1a0a9dee4de9dae793c58476826789df1a6679850356e9bb163d15d81f46c9'
     '89e1ba816c5b2bcfda4af3fd04efddf34112215ca6479605d87023851e837623ba8ef9f47af802448a094b378caca1b0'
     'ea74e0726bde1e06',
     '54c8e154fab200096f212cfe1114357812b930500514ca5ddce6cdc0c55010b3d796c7278ead7c231f7e39b8efeafe4f'),
    ('SHA3-512', 5, 0, 'piece only',
     '00',
     '831a797057a769057ebf9663817495b71f2d00dd6503f8ac5f76433d4c5cb1e834e0727841e2d3761fd2489c728d7721'
     '0916b43e7d27398a9ec66f0376135e45'),
    ('SHA3-512', 573, 40, 'two-block padding',
     'acf697ea3aa0dc8b49e5fe9bf875b38757322d46ccfa9fd4b6c0fee251e205ccdab67bcbf366b86c48ff664073c485d5'
     '1dc8b1e666bca8cf87050743b61254414bec4144200e2f1b',
     'b9d89cbb1ad32fc08004fe4fcf74a4df4a80a30e084be96fd663412c28960da1b9b3fe9945ec38bf283123a6cd0cdd89'
     'f804ec56ec882a697cce8f13f272d19b'),
    ('SHAKE128', 5, 0, 'piece only',
     '16',
     '385ad8869459c849df754797ea900692'),
    ('SHAKE128', 1339, 100, 'two-block padding',
     '7e5ce2606ab1d7df0f9cca2fe4080739c2b950879931304c62d58ca4544c7b1c5b285875c6c815a53f7cd11f01ebad54'
     '45b2dc7afd4efa8cc53c9f92175e3322bea104278ddd95e150fd3a2d035fe107427e334d01cedcc57de7266272e6cdc3'
     '8f100ffd27b9029a29652ae2522c4b59a1637c880c787d00711e4a9dcfaaf008b6bda07ffc2402d9b2fccbc4561a9252'
     '4aaae0b485158645892933ca957445f71bf0e03674e63d05',
     '95ecd5dcf37aad409bf8168fb5046c8d'),
    ('SHAKE256', 5, 0, 'piece only',
     '0f',
     'ae9b76a226ac1b0b8b75dc60ce74724fba5a98f68b5544bd54746f5673bfffda'),
    ('SHAKE256', 1083, 100, 'two-block padding',
     '9cd56b9c1f83ff404cef23de9eb7cc1d6bed97bec569c58a9f63838930416f759dad596ed2eb46efb069bb016e9838af'
     '39fb02b91e7e258d2a08ba72d05366078afc23ecc3d643bff584b24a0f477bfa19148d931aeac0233a62133524883746'
     'aee9527dbcedfd9661678e20486b9de85360c1b581559b3515991638f585ec1c509d6d8883d87c06',
     'da4a3e02de8337573033a8900c39e6013945087e5ad3ce84028069135508a86d'),
    ('SHA3-512', 1153, 100, 'piece crosses a block boundary',
     '5c2b3cfb98248aa4232fa1fd83104190ac3534d7bb989647e6e7758db3e39a176906a5d6c4686042ede34d9fa975817f'
     'd1e7b58902ac9b78950c6e67d282cd4b6062c9c100be3d0a7c8b5e53d900923ad43f868f8d377a577dc9e017ad29264f'
     '2a88d044b4f0c902b66ffba27b771dc99e85cc71c201deec8465f325aea24c2aadc0e1e746c4ad3484d64d13f5a3c932'
     '00',
     'fc6c2b313a4ece52c4d4688daf433262e95d9680aec58e2b3d7c043770322ee6ae111e1d34fe5341048837776224e5b6'
     '805910481aa2766419ce5548bea53e5a'),
    ('SHAKE128', 1357, 100, 'piece crosses a block boundary',
     '756e24114a111ad25e0dba7822e3102a2e9c95d2d50a5d7efd5093062da523efe854b68f3a07e3729046a3fdcd3b0651'
     '99b82572fc7b58a92db0a926a4b788ea7628c0e4e214a95a278e9f8b996ab493f445a28ef0c604001622c575d1e6d864'
     'c8f129596bbfd453ccee966bb1fa80b7e74cf36ed973c84d61b1cf39ddb97b2586b7db36fd91cc25276c6ee63b73d487'
     '19d3005ade0a0e56b562afbbf0b8d9f55782bdc3bf11fa98df13',
     'd846859ba7da90c700f9f8fc8e718ecd'),
    ('SHAKE256', 2176, 136, 'Form A: a full-block piece',
     '0e3bd320a9b1dff29504e1371ea0a95898dc39174e2463d0bb579afefd6e0200865fc91e1540bac7e4b00f1c237387b3'
     'a65cb994db70a888fe48979490b71fc005ad7e1cbd5b32053598c7a57f84edb9ef6bcd9718ec9d6ff65a72d16d62566f'
     'f2ee9b25894a6f36ef85b0d9181b01f4dcd01d27eddf6b0c0c54d3bd7cb7d197b7eac73e615498e17a4072c0d77febeb'
     'd355504c429339e7a6006161a6fdb5bfbb69ab712dc3d58f3e8eb662a4fad4263dc00e0eff4e30892e24c5c4d17e2d70'
     '6633efc5d5dd50c7a33a24c868d2e42e83da01760c5978790a89a7eee6805e31200f3a4341eb2e11110a63f90950428a'
     '0b6bcf8b51fc383fa4f7ade8ce4c738a51c734f159349af5f0c81cfd71bc17c2',
     'e5c33665acd47f77ec88cff924e6e770fb3836343d3ca75730a1fefcb8961c0a'),
]

# ---------------------------------------------------------------- KLE model

class Hart:
    klstart = 0  # bytes, <<KLE-CSR-klstart>>

HART = Hart()
C1_BITS = -(-(N + 64) // 128) * 128  # Serialized Content: state, block_base, last_block_len, out_len; padded

def kl_size(st):
    """<<KLE-instruction-size>>, AuxDataLen = 0; a supplied PI MDH is _Unconfigured_."""
    return 16 if st in ERROR_STATES or st in (KL_STATE_INERT, KL_CFG_PROVISIONING) else 32 + C1_BITS // 8

def make_pi(name):  # the MDH only
    return v2b(mdh_pack(Machine=MACHINE[name], State=KL_STATE_INERT), 16)

class Sha3:
    wrong_suffix = False  # negative control
    bound = 0             # the Form B Xs of the kl.setst into _Hash_Output_
    pad_case = None       # which padding clause fired

    def __init__(s):
        s.reset(KL_STATE_INERT)

    def reset(s, st=KL_STATEEXT_INVALID):  # GR36 for an Error State
        s.st, s.state, s.block_base, s.last_block_len, s.out_len = st, 0, 0, 0, 0

    def set_machine(s, machine):
        s.machine, s.name = machine, {v: k for k, v in MACHINE.items()}[machine]
        c, s.b, s.t, s.xof, s.D = PARAMS[s.name]

    def provision(s, pi):
        f = mdh_unpack(b2v(pi[:16]))
        assert f['State'] == KL_STATE_INERT and len(pi) == 16
        s.set_machine(f['Machine'])
        if f['MachinePolicy']:  # unsupported Metadata (<<KLE-hash-functions-MACs-XOFs>>, MDH: MachinePolicy)
            s.reset(KL_STATEEXT_UNSUPPORTED)
            return s
        s.reset(KL_STATE_READY)  # `state` zeroed
        return s

    def restrictl(s, rq):  # kl.restrictl of the _MachinePolicy_ that the Machine does not use:
        return s  # the field stays zero, whatever `rq` holds (<<KLE-instruction-restrict>>)

    def mdh(s):
        return v2b(mdh_pack(Machine=s.machine, State=s.st), 16)

    def export(s, at_order=False):
        """Serialized Content in table order from bit 0; at_order: built with `@` (negative control)."""
        if at_order:
            v = cat((s.state, N), (s.block_base, 16), (s.last_block_len, 16), (s.out_len, 32))
        else:
            v = s.state | s.block_base << N | s.last_block_len << (N + 16) | s.out_len << (N + 32)
        return v2b(v, C1_BITS // 8)

    @classmethod
    def load(cls, mdh, content):
        s, f, v = cls(), mdh_unpack(b2v(mdh)), b2v(content)
        s.set_machine(f['Machine'])
        s.st, s.state, s.block_base = f['State'], sl(v, N - 1, 0), sl(v, N + 15, N)
        s.last_block_len, s.out_len = sl(v, N + 31, N + 16), sl(v, N + 63, N + 32)
        if s.block_base > (s.t if s.st == KL_STATE_SUCCESS else s.b - 1) or s.last_block_len > s.b:  # inconsistent Content
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
        s.block_base, s.last_block_len, s.st = 0, 0, KL_STATE_HASH_OUTPUT  # block[t-1:0] <- finalize() is the identity
        s.out_len = s.bound or (0 if s.xof else s.t)  # <<KLE-hash-functions-MACs-XOFs>>: the output bound

    def setst(s, immed, form='A', xs=None):
        if immed == KL_STATE_INERT or immed in ERROR_STATES:  # in any State
            if s.st != KL_STATE_INERT or immed:
                s.reset(immed)
        elif inert(s.st):
            pass  # GR37, GR33
        elif immed == KL_STATE_READY and form == 'A':  # GR23: Form A
            s.reset(KL_STATE_READY)
        elif form == 'A' and (s.st, immed) == (KL_STATE_READY, KL_STATE_HASH_ABSORB):
            s.st, s.last_block_len = immed, s.b  # Form A: max_len is set by the Machine
        elif (s.st, immed) == (KL_STATE_HASH_ABSORB, KL_STATE_HASH_LAST_BLOCK) and (
                form == 'A' or form == 'B' and xs is not None and 0 <= xs <= s.b):
            s.st = immed  # Form A keeps last_block_len = b; any bit length (MR14, FIPS 202 bit order)
            if form == 'B':
                s.last_block_len = xs
        elif form in 'AB' and immed == KL_STATE_HASH_OUTPUT and (
                s.st == KL_STATE_HASH_ABSORB or s.st == KL_STATE_HASH_LAST_BLOCK and s.last_block_len == 0):
            s.bound = (xs or 0) if form == 'B' else 0
            if s.bound and (s.bound % 8 or s.bound > (s.t if not s.xof else (1 << 32) - 1)):
                s.reset()  # a multiple of 8, at most d, below 2^32 for an XOF
            else:
                s.enter_output()
        else:
            s.reset()  # GR22, GR23, GR21, <<KLE-process-VLI>> same-State rule
        return s.st

    def fail(s, out, status='invalid'):
        """No operation or Error State: the unwritten output window [klstart, top-1] is zeroed (GR35)."""
        if status == 'invalid':
            s.reset()
        if out is not None:
            k = min(HART.klstart, len(out))
            out[k:] = bytes(len(out) - k)
        HART.klstart = 0
        return status

    def empty(s, top):
        """Empty window (klstart >= KLLEN/8): only klstart = 0 (<<KLE-GR-transfer-window-checks>>)."""
        if HART.klstart >= top:
            HART.klstart = 0
            return True
        return False

    def exec(s, form, inp=None, out=None, sew=None, interrupt_at=None, klstart_bits=False):
        """kl.exec; sew None = KLIOBUF; halts at the first point >= interrupt_at inside the window."""
        if inert(s.st):
            return s.fail(out, 'noop')  # GR33, GR35
        halt = (interrupt_at,)
        if s.st == KL_STATE_HASH_ABSORB and form in 'BD' and inp is not None and out is None:
            if sew is not None and sew < GRANULARITY:
                return s.fail(out)  # MR1
            if s.empty(len(inp)):
                return 'empty'
            if HART.klstart and s.block_base:
                return s.fail(out)  # not an interruption point
            r = s.process_vli(b2v(inp), 8 * len(inp), 8 * HART.klstart, *halt, klstart_bits)
        elif s.st == KL_STATE_HASH_LAST_BLOCK and form in 'BD' and inp is not None and out is None:
            if sew is not None and sew < GRANULARITY:
                return s.fail(out)  # MR1
            if 8 * len(inp) < s.last_block_len:
                return s.fail(out)  # MR1, GR53 item 1: the length first
            if s.empty(len(inp)):
                return 'empty'
            if HART.klstart or s.last_block_len == 0:
                return s.fail(out)  # only interruption point 0; MR8
            s.process_vli(sl(b2v(inp), s.last_block_len - 1, 0), s.last_block_len, 0, None, False)
            s.last_block_len, r = 0, 'done'  # process_last_block() = None; atomic: no halt
        elif s.st == KL_STATE_HASH_OUTPUT and form in 'CD' and inp is None and out is not None:
            if s.empty(len(out)):
                return 'empty'
            if HART.klstart and s.block_base:
                return s.fail(out)  # not an interruption point
            r = s.squeeze(out, 8 * HART.klstart, *halt)
        else:
            return s.fail(out)  # GR22; GR21 item 1 in _Ready_
        if r != 'interrupted':
            HART.klstart = 0
        return r

    def process_vli(s, INPUT, KLLEN, ib, interrupt_at, klstart_bits=False):
        """PROCESS_VLI(0, state, b, state, n, input_base, block_base, 0, None, P(), None, xor_accumulate)."""
        while ib < KLLEN:
            amount = min(KLLEN - ib, s.b - s.block_base)
            s.state ^= sl(INPUT, ib + amount - 1, ib) << s.block_base
            ib, s.block_base = ib + amount, s.block_base + amount
            if s.block_base == s.b:
                s.state, s.block_base = keccak(s.state), 0
            if interrupt_at is not None and ib // 8 >= interrupt_at and ib < KLLEN:  # 3.i
                HART.klstart = ib if klstart_bits else ib // 8
                return 'interrupted'
        return 'done'

    def absorb_bits(s, val, nbits):
        """The PROCESS_VLI loop on a bit-granular input (no kl.exec transfers this)."""
        assert s.st == KL_STATE_HASH_ABSORB
        s.process_vli(sl(val, nbits - 1, 0), nbits, 0, None, False)

    def squeeze(s, out, ob, interrupt_at):
        OUT, KLLEN = b2v(out), 8 * len(out)
        try:
            while ob < KLLEN:
                amount = min(KLLEN - ob, s.t - s.block_base, *([s.out_len] if s.out_len else []))
                OUT = (OUT & ~(((1 << amount) - 1) << ob)) | sl(s.state, s.block_base + amount - 1, s.block_base) << ob
                ob, s.block_base = ob + amount, s.block_base + amount
                if s.out_len:
                    s.out_len -= amount
                    if not s.out_len:  # bits beyond output_base cleared
                        OUT, s.st = sl(OUT, ob - 1, 0), KL_STATE_SUCCESS
                        return 'success'
                if s.block_base == s.t:
                    s.state, s.block_base = keccak(s.state), 0  # update()
                    if interrupt_at is not None and ob // 8 >= interrupt_at and ob < KLLEN:
                        HART.klstart = ob // 8
                        return 'interrupted'
            return 'done'
        finally:
            out[:] = v2b(OUT, len(out))

class Port(HashPort):
    """<<Zkl-software.adoc#KLE-pseudocode-hash>> on a SHA-3 locker."""
    def __init__(p, name='SHA3-256', cl=None):
        p.name, p.cl = name, cl or new(name)
        p.b = p.cl.b
    st = property(lambda p: p.cl.st)
    klstart = property(lambda p: HART.klstart)
    def setst(p, immed, form='A', xs=None): p.cl.setst(immed, form, xs)
    def exec_in(p, d, halt_at=None):
        return p.cl.exec('B', inp=d, interrupt_at=None if halt_at is None else halt_at + 1)
    def exec_out(p, n, halt_at=None, prior=None):
        out = bytearray(prior or bytes(n))
        r = p.cl.exec('C', out=out, interrupt_at=None if halt_at is None else halt_at + 1)
        return r, bytes(out)
    def export(p): return p.cl.mdh(), p.cl.export()
    def imported(p, img): return Port(p.name, Sha3.load(*img))

class KeyDest:
    """A symmetric `key` of n bytes, a destination in _Ready_ (<<KLE-derive-endpoints>>); only the key is modelled."""
    def __init__(s, n): s.st, s.n, s.key = KL_STATE_READY, n, None
    def reset(s): s.st, s.key = KL_STATEEXT_INVALID, None

class Source:
    """A source endpoint, only its bytes modelled: a shared secret field (an ECC shared secret in _Output_ or the
    ML-KEM `sharedkey`, GR43) or, with secret=False, the `hash` of a CMAC in _Hash_Output_ (GR44).  A SHA-3 or
    SHAKE _Hash_Output_ is not a source (<<KLE-derive-endpoints>>)."""
    def __init__(s, data, secret=True): s.st, s.data, s.secret = KL_STATE_HASH_OUTPUT, data, secret
    def reset(s): s.st = KL_STATEEXT_INVALID

def kl_derive(dst, src, length):
    """A Source -> the _Hash_Absorb_ kl.exec input (GR43: a shared secret only) or a KeyDest (GR43, GR44);
    uninterruptible (GR47): it never halts, and retires with klstart = 0."""
    if inert(src.st) or inert(dst.st):  # GR33: an inert endpoint makes it a no-op
        HART.klstart = 0
        return 'noop'
    key = isinstance(dst, KeyDest)
    bad = [c for c, ok in ((src, isinstance(src, Source)),
                           (dst, dst.st == (KL_STATE_READY if key else KL_STATE_HASH_ABSORB))) if not ok]
    for c in bad:
        c.reset()  # GR40 items 1-2 (no endpoint in _Success_)
    pos, HART.klstart = HART.klstart, 0
    if bad:
        return 'invalid'
    if not (key or src.secret):
        src.reset()  # GR40 item 3: both
        dst.reset()
        return 'invalid'
    n = len(src.data)  # granularity 8 bits: a hash input receives exactly the secret
    if pos or (min(length, n) < dst.n if key else length != n):
        dst.reset()  # GR40 item 5
        return 'invalid'
    if key:
        dst.key = src.data[:dst.n]
    else:
        assert dst.exec('B', inp=src.data) == 'done'  # GR39: as kl.exec; the field does not advance
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

section('KLE model, single transfer')
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
check('Granularity 8 bits: Form B with SEW = 8, 16, 32 and 64 accepted',
      cl.exec('B', inp=MSG_A3[:1], sew=8) == 'done' and cl.exec('B', inp=MSG_A3[1:3], sew=16) == 'done'
      and cl.exec('B', inp=MSG_A3[3:7], sew=32) == 'done'
      and cl.exec('B', inp=MSG_A3[7:23], sew=64) == 'done' and cl.block_base == 184)

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
cl.setst(KL_STATE_INERT)
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
r = cl.exec('B', inp=MSG_A3[:136])
snap, HART.klstart = (cl.state, cl.block_base), 136
check('klstart = KLLEN/8, which no halt in _Hash_Absorb_ produces (PROCESS_VLI step 3.i): an empty window, '
      'only klstart = 0', (r, cl.exec('B', inp=MSG_A3[:136]), HART.klstart) == ('done', 'empty', 0)
      and (cl.state, cl.block_base) == snap)
cl.exec('B', inp=MSG_A3[136:])
cl.setst(KL_STATE_HASH_OUTPUT)
check('SHA3-256 a3_200 after the empty window', None, squeeze(cl, 32)[1], V('SHA3-256', 'a3_200'))
cl = absorbing('SHA3-256', MSG_A3[:4])
snap, HART.klstart = (cl.state, cl.block_base), 250
check('input operand, klstart = 250 > KLLEN/8: empty window, only klstart = 0',
      (cl.exec('B', inp=MSG_A3), (cl.state, cl.block_base), HART.klstart) == ('empty', snap, 0))
HART.klstart = 100
check('input klstart = 100, block_base = 32 (no interruption point): _Invalid_, klstart = 0',
      (cl.exec('B', inp=MSG_A3), cl.st, HART.klstart) == ('invalid', KL_STATEEXT_INVALID, 0))
check('the invalidated locker retains only its MDH (GR36)', (cl.state, cl.block_base) == (0, 0))
check('kl.setst on the Error State locker: no operation (GR33)', cl.setst(KL_STATE_HASH_OUTPUT) == KL_STATEEXT_INVALID)
check('Form C kl.exec on it: no operation, output window zeroed (GR33, GR35)', None,
      (squeeze(cl, 32, 0xee), cl.st), (('noop', bytes(32)), KL_STATEEXT_INVALID))

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
check('squeeze halts at klstart = output_base / 8 = 168; bytes beyond left unwritten (GR52, GR50)',
      (r, HART.klstart, bytes(out[168:])) == ('interrupted', 168, b'\xee' * 232))
check('resumed squeeze retires with klstart = 0', (cl.exec('C', out=out), HART.klstart) == ('done', 0))
check('[oracle] SHAKE128 400 B with interrupt/resume', None, bytes(out), oracle('SHAKE128', MSG_ABC, 400))
cl = squeezing('SHAKE256', MSG_A3)
check('[oracle] SHAKE256 a3_200 336 B over kl.exec of 64+8+264 B', None,
      b''.join(squeeze(cl, n)[1] for n in (64, 8, 264)), oracle('SHAKE256', MSG_A3, 336))
cl = squeezing('SHAKE256', MSG_A3)
out = bytearray(136)
r = cl.exec('C', out=out)
kept, HART.klstart = bytes(out), 136
check('klstart = KLLEN/8, which no halt in _Hash_Output_ produces: an empty window, OUTPUT intact, only klstart = 0',
      (r, cl.exec('C', out=out), bytes(out), HART.klstart) == ('done', 'empty', kept, 0))
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
check('output only, klstart = 5, block_base > 0 (no interruption point): _Invalid_, [5, 63] zeroed', None,
      (squeeze(cl, 64, 0xee), cl.st, HART.klstart), (('invalid', b'\xee' * 5 + bytes(59)), KL_STATEEXT_INVALID, 0))

section('SHA3-n: _Success_ after t bits')
cl = squeezing('SHA3-256', MSG_ABC)
r1, d1 = squeeze(cl, 12)
st1 = cl.st
r2, d2 = squeeze(cl, 20)
check('12-B read stays in _Hash_Output_; the next reaches _Success_ at the t-th bit',
      (r1, st1, r2, cl.st) == ('done', KL_STATE_HASH_OUTPUT, 'success', KL_STATE_SUCCESS))
check('SHA3-256 abc digest split 12+20 B', None, d1 + d2, V('SHA3-256', 'abc'))
cl = squeezing('SHA3-256', MSG_ABC)
HART.klstart = 4
check('SHA3-256: klstart = 4 at the start of _Hash_Output_ (block_base = 0) writes the first 28 digest bytes '
      'into [4, 31] and keeps [0, 3]', None, (squeeze(cl, 32, 0xee), cl.st, HART.klstart),
      (('done', b'\xee' * 4 + V('SHA3-256', 'abc')[:28]), KL_STATE_HASH_OUTPUT, 0))
cl = squeezing('SHA3-384', MSG_ABC)
check('64-B read of SHA3-384: returns at _Success_, bytes [48, 63] cleared', None,
      squeeze(cl, 64, 0xee), ('success', V('SHA3-384', 'abc') + bytes(16)))
cl = squeezing('SHA3-256', MSG_ABC)
squeeze(cl, 32)
check('kl.exec in _Success_ -> _Invalid_, output zeroed (GR22, GR35)', None,
      (squeeze(cl, 32, 0xee), cl.st), (('invalid', bytes(32)), KL_STATEEXT_INVALID))
cl = squeezing('SHA3-256', b'')
squeeze(cl, 32)
ok = cl.setst(KL_STATE_READY) == KL_STATE_READY and (cl.state, cl.block_base) == (0, 0)
check('_Success_ -> _Ready_ (GR23) zeroes state and block_base', ok)
cl.setst(KL_STATE_HASH_ABSORB)
cl.exec('B', inp=MSG_ABC)
cl.setst(KL_STATE_HASH_OUTPUT)
check('SHA3-256 abc from the CC reused after _Ready_', None, squeeze(cl, 32)[1], V('SHA3-256', 'abc'))

section('States, transitions, Forms')
ab, out_ = (lambda n: absorbing(n, MSG_ABC)), (lambda n: squeezing(n, MSG_ABC))
for label, name, prep, act in [
        ('kl.exec in _Ready_ (GR21)', 'SHA3-256', new, lambda c: c.exec('B', inp=MSG_ABC)),
        ('_Ready_ -> _Hash_Output_', 'SHA3-256', new, lambda c: c.setst(KL_STATE_HASH_OUTPUT)),
        ('Form B kl.setst to _Hash_Absorb_ (Form A required)', 'SHA3-256', new,
         lambda c: c.setst(KL_STATE_HASH_ABSORB, 'B')),
        ('same-State kl.setst in _Hash_Absorb_', 'SHA3-256', ab, lambda c: c.setst(KL_STATE_HASH_ABSORB)),
        ('a kl.exec after a Form B kl.setst to _Hash_Absorb_Last_Block_ with Xs = 0 (MR8)', 'SHA3-256', ab,
         lambda c: (c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 0), c.exec('B', inp=b'x'))),
        ('Form C kl.exec in _Hash_Absorb_ (GR22)', 'SHA3-256', ab, lambda c: c.exec('C', out=bytearray(32))),
        ('Form A kl.exec in _Hash_Absorb_ (GR22)', 'SHA3-256', ab,
         lambda c: c.exec('A', inp=MSG_ABC + bytes(1), out=bytearray(4))),
        ('Form B kl.exec in _Hash_Output_ (GR22)', 'SHAKE256', out_, lambda c: c.exec('B', inp=MSG_ABC)),
        ('same-State kl.setst to _Hash_Output_ (GR21)', 'SHAKE256', out_, lambda c: c.setst(KL_STATE_HASH_OUTPUT)),
        ('_Hash_Output_ -> _Hash_Absorb_', 'SHAKE256', out_, lambda c: c.setst(KL_STATE_HASH_ABSORB)),
        ('_Success_ -> _Hash_Absorb_ (GR23)', 'SHA3-224', out_,
         lambda c: (squeeze(c, 28), c.setst(KL_STATE_HASH_ABSORB)))]:
    cl = prep(name)
    act(cl)
    check(f'_Invalid_: {label}', cl.st == KL_STATEEXT_INVALID)
cl = squeezing('SHA3-224', MSG_ABC)
check('kl.setst #kl_state_success -> Invalid (GR25, GR24)',
      (raises(cl.setst, KL_STATE_SUCCESS), cl.st) == (False, KL_STATEEXT_INVALID))
cl.setst(KL_STATE_INERT)
out = bytearray(b'\xaa' * 8)
check('kl.clear; a later kl.exec or kl.setst performs no operation, output zeroed (GR33, GR35)',
      (cl.exec('C', out=out, sew=8), bytes(out), cl.setst(KL_STATE_READY))
      == ('noop', bytes(8), KL_STATE_INERT))
check('kl.setst #kl_state_failure on an Unconfigured locker: no operation (GR24, GR33)',
      (raises(cl.setst, KL_STATE_FAILURE), cl.st) == (False, KL_STATE_INERT))
check('kl.setst #48, #53 on an Unconfigured locker: no operation (GR33)',
      (raises(cl.setst, 48), raises(cl.setst, 53), cl.st) == (False, False, KL_STATE_INERT))
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
      len(make_pi('SHA3-256')) == 16 and kl_size(KL_STATE_INERT) == 16)
check('Serialized Content 1600 + 16 + 16 + 32 bits (out_len in Position iv) = 1664; kl.size 32 + 208; Error State 16',
      (C1_BITS, kl_size(KL_STATE_HASH_ABSORB), kl_size(KL_STATEEXT_INVALID)) == (1664, 240, 16))
cl = absorbing('SHA3-256', MSG_A3[:100])
c1 = cl.export()
check('layout: [0,199] state, [200,201] block_base = 800, [202,203] last_block_len = b = 1088, [204,207] out_len = 0',
      (len(c1), c1[:200], c1[200:202], c1[202:204], c1[204:])
      == (208, v2b(cl.state, 200), v2b(800, 2), v2b(1088, 2), bytes(4)))
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

pol = Sha3().provision(v2b(mdh_pack(Machine=MACHINE['SHA3-256'], MachinePolicy=1), 16)).st
check('a PI with _MachinePolicy_ = 1: unsupported Metadata; a kl.restrictl keeps the unused _MachinePolicy_ '
      'zero, whatever its request (<<KLE-hash-functions-MACs-XOFs>>, <<KLE-instruction-restrict>>)',
      None, (pol, absorbing('SHAKE128', MSG_ABC).restrictl(1).st, absorbing('SHAKE128', MSG_ABC).restrictl(0).st),
      (KL_STATEEXT_UNSUPPORTED, KL_STATE_HASH_ABSORB, KL_STATE_HASH_ABSORB))

section('kl.derive')
SEC, SEC66 = bytes(range(0x40, 0x60)), bytes(range(0x80, 0xc2))  # shared secrets: ML-KEM, P-521 sizes
src, dst = Source(SEC), absorbing('SHA3-256', MSG_A3[:10])
r = kl_derive(dst, src, 32)
check('shared secret (32 B) -> SHA3-256 completes, klstart = 0', (r, HART.klstart) == ('done', 0))
dst.exec('B', inp=MSG_ABC)
dst.setst(KL_STATE_HASH_OUTPUT)
check('[oracle] SHA3-256(a3[:10] || secret || abc) through the open destination', None,
      squeeze(dst, 32)[1], oracle('SHA3-256', MSG_A3[:10] + SEC + MSG_ABC))
src, dst = Source(SEC66), absorbing('SHAKE256')
r = kl_derive(dst, src, 66)
dst.setst(KL_STATE_HASH_OUTPUT)
check('[oracle] 66-byte shared secret -> SHAKE256: SHAKE256(secret), the field source unchanged', None,
      (r, src.st, squeeze(dst, 64)[1]), ('done', KL_STATE_HASH_OUTPUT, oracle('SHAKE256', SEC66, 64)))
src, dst = squeezing('SHAKE128', MSG_ABC), absorbing('SHA3-256', MSG_A3[:10])
snap = (dst.state, dst.block_base)
r = kl_derive(dst, src, 336)
check('SHAKE128 output in _Hash_Output_ as a source (GR40 item 1): source _Invalid_, destination untouched',
      (r, src.st, dst.st) == ('invalid', KL_STATEEXT_INVALID, KL_STATE_HASH_ABSORB)
      and snap == (dst.state, dst.block_base))
dst = absorbing('SHA3-256', MSG_ABC)
dst.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 0)
check('shared secret into SHA3-256 _Hash_Absorb_Last_Block_ (not an endpoint, GR40 item 2): destination _Invalid_',
      (kl_derive(dst, Source(SEC), 32), dst.st) == ('invalid', KL_STATEEXT_INVALID))
src, dst = Source(bytes(range(16)), secret=False), absorbing('SHA3-256')
check('a CMAC (16 B) -> SHA3-256: pair not admitted (GR40 item 3), both _Invalid_',
      (kl_derive(dst, src, 16), src.st, dst.st) == ('invalid', KL_STATEEXT_INVALID, KL_STATEEXT_INVALID))
src, dst = Source(SEC), absorbing('SHA3-512')
HART.klstart = 8
r = kl_derive(dst, src, 32)
check('uninterruptible: klstart = 8 at issue (no resumption, GR40 item 7): destination _Invalid_, klstart = 0',
      (r, dst.st, src.st, HART.klstart) == ('invalid', KL_STATEEXT_INVALID, KL_STATE_HASH_OUTPUT, 0))
res = []
for length in (0, 31, 33):
    dst = absorbing('SHA3-224', MSG_ABC)
    res.append((kl_derive(dst, Source(SEC), length), dst.st))
check('a 32-byte shared secret with length 0, 31 or 33 (GR40 item 5: exactly the secret, granularity 8 bits): '
      'destination _Invalid_', None, res, [('invalid', KL_STATEEXT_INVALID)] * 3)
src, dst = Source(SEC), squeezing('SHA3-224', MSG_ABC)
squeeze(dst, 28)
r = kl_derive(dst, src, 32)
check('destination in _Success_ (GR40 item 2): _Invalid_, the source untouched',
      (r, dst.st, src.st) == ('invalid', KL_STATEEXT_INVALID, KL_STATE_HASH_OUTPUT))

src, dst, s28, d28 = Source(SEC), KeyDest(16), Source(SEC[:28]), KeyDest(32)
h, dh, cm, dc = squeezing('SHAKE128', MSG_ABC), KeyDest(16), Source(SEC[16:], secret=False), KeyDest(16)
check('shared secret -> a 16-byte `key` in _Ready_ (length 32: 16 B); a 28-byte secret -> a 32-byte key (GR40 item 5): '
      'destination _Invalid_, source untouched; SHAKE128(abc) -> a key (GR40 item 1): source _Invalid_, key '
      'untouched; a CMAC -> a key (GR44): the CMAC', None,
      (kl_derive(dst, src, 32), dst.key, kl_derive(d28, s28, 32), d28.st, s28.st, kl_derive(dh, h, 16), h.st, dh.st,
       kl_derive(dc, cm, 16), dc.key),
      ('done', SEC[:16], 'invalid', KL_STATEEXT_INVALID, KL_STATE_HASH_OUTPUT, 'invalid', KL_STATEEXT_INVALID,
       KL_STATE_READY, 'done', SEC[16:]))

section('Final piece of any bit length: _Hash_Absorb_Last_Block_ (NIST CAVP bit-oriented vectors)')

def piece_hash(name, nbits, nb, msg, nout, form=None, junk=True, msb_piece=False, split_at=None):
    """Whole bytes msg[:nb] in _Hash_Absorb_, then the final nbits - 8 nb bits in _Hash_Absorb_Last_Block_;
    junk: the bits of INPUT above last_block_len set, plus one extra byte (MR5)."""
    L, cl = nbits - 8 * nb, absorbing(name, msg[:nb])
    pv = sl(b2v(msg[nb:]), L - 1, 0)
    if msb_piece:  # negative control: a partial last byte taken from its most significant bits
        pv = sl(b2v(msg[nb:]), 8 * ((L + 7) // 8) - 1, 8 * ((L + 7) // 8) - L) if L % 8 else pv
    inp = v2b(pv | (((1 << 8 * ((L + 7) // 8 + 1)) - 1) >> L << L if junk else 0), (L + 7) // 8 + junk)
    form = form or ('A' if L == cl.b else 'B')
    cl.setst(KL_STATE_HASH_LAST_BLOCK, form, None if form == 'A' else L)
    snap = (cl.st, cl.last_block_len)
    r = cl.exec('B', inp=inp, interrupt_at=0)
    cl.setst(KL_STATE_HASH_OUTPUT)
    return squeeze(cl, nout)[1], snap, r, cl.pad_case

for name, nbits, nb, what, msg, md in CAVP_BITS:
    msg, md = bytes.fromhex(msg), bytes.fromhex(md)
    got, snap, r, case = piece_hash(name, nbits, nb, msg, len(md))
    L = nbits - 8 * nb
    check(f'CAVP {name} Len = {nbits}: {nb} B, then a {L}-bit piece ({what})', None, got, md)
    check('  = bit-level reference sponge', None,
          ref_sponge(PARAMS[name][1], sl(b2v(msg), nbits - 1, 0), nbits, PARAMS[name][4], len(md)), md)
    if what == 'two-block padding':
        check(f'  {name}: b - block_base < |D| + 2: two-block clause', case == 2)
check('the piece kl.exec is atomic: interrupt_at = 0 does not halt it, klstart = 0, last_block_len -> 0', None,
      (r, HART.klstart, snap), ('done', 0, (KL_STATE_HASH_LAST_BLOCK, PARAMS[name][1])))

def last(name='SHA3-256', L=13, nb=10):
    cl = absorbing(name, MSG_A3[:nb])
    cl.setst(KL_STATE_HASH_LAST_BLOCK, 'B', L)
    return cl
for label, prep, act in [
        ('a kl.exec after Xs = 0', lambda: absorbing('SHA3-256', MSG_A3[:10]),
         lambda c: (c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 0), c.exec('B', inp=b'x'))),
        ('Xs = b + 1', lambda: absorbing('SHA3-256', MSG_A3[:10]),
         lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 1089)),
        ('from _Ready_', lambda: new('SHA3-256'), lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 8)),
        ('KLLEN = 8 < last_block_len = 13 (MR1)', last, lambda c: c.exec('B', inp=b'\x01')),
        ('KLLEN = 0 < last_block_len = 16: the length before the empty window (GR53 item 1)',
         lambda: last(L=16), lambda c: c.exec('B', inp=b'')),
        ('a second kl.exec (MR8)', last, lambda c: (c.exec('B', inp=b'\x01\x02'), c.exec('B', inp=b'\x01\x02'))),
        ('_Hash_Output_ before the piece (last_block_len != 0)', last, lambda c: c.setst(KL_STATE_HASH_OUTPUT)),
        ('same-State kl.setst (GR21)', last, lambda c: c.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 13)),
        ('klstart = 1: not an interruption point', last,
         lambda c: (setattr(HART, 'klstart', 1), c.exec('B', inp=b'\x01\x02')))]:
    cl = prep()
    act(cl)
    check(f'_Invalid_: _Hash_Absorb_Last_Block_, {label}', cl.st == KL_STATEEXT_INVALID)
    HART.klstart = 0
cl = last()
check('_Hash_Absorb_Last_Block_ -> _Ready_ with the piece pending: restarts (abc)', None,
      (cl.setst(KL_STATE_READY), cl.last_block_len, kl_hash('SHA3-256', MSG_ABC)[0]),
      (KL_STATE_READY, 0, V('SHA3-256', 'abc')))
name, nbits, nb, what, msg, md = CAVP_BITS[-3]  # SHA3-512 Len = 1153, the piece crosses a block boundary
msg, md, L = bytes.fromhex(msg), bytes.fromhex(md), nbits - 8 * nb
cl = absorbing(name, msg[:nb])
cl.setst(KL_STATE_HASH_LAST_BLOCK, 'B', L)
c1 = cl.export()
cl = Sha3.load(cl.mdh(), c1)
cl.exec('B', inp=msg[nb:])
cl.setst(KL_STATE_HASH_OUTPUT)
check(f'export/import between the kl.setst and the kl.exec of the piece: last_block_len = {L} serialized', None,
      (c1[202:204], squeeze(cl, 64)[1]), (v2b(L, 2), md))

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
name, nbits, nb, what, msg, md = CAVP_BITS[0]
control('a partial final byte taken from its most significant bits (CAVP SHA3-224 Len = 5)',
        piece_hash(name, nbits, nb, bytes.fromhex(msg), 28, msb_piece=True)[0] != bytes.fromhex(md))

section('The generic sequence (<<Zkl-software.adoc#KLE-pseudocode-hash>>), the final piece, the bound')
for name, (c, b, t, xof, D) in PARAMS.items():
    ref = lambda m, nb, o, b=b, D=D: ref_sponge(b, b2v(m), nb, D, o)
    msgs = hash_msgs(b // 8, bits=True)
    check_hash(name, lambda name=name: Port(name), ref, msgs if name in ('SHA3-256', 'SHAKE128') else msgs[::3],
               t // 8 if not xof else 200)
cl = absorbing('SHA3-256', MSG_ABC)
cl.setst(KL_STATE_HASH_LAST_BLOCK, 'B', 0)
st = cl.st
cl.setst(KL_STATE_HASH_OUTPUT)
check('Xs = 0: no final piece, the State stays; the kl.setst into _Hash_Output_ gives the digest of the message', None,
      (st, squeeze(cl, 32)[1]), (KL_STATE_HASH_LAST_BLOCK, V('SHA3-256', 'abc')))
r = []
for name, xs in (('SHA3-256', 8), ('SHA3-256', 248), ('SHA3-256', 256), ('SHAKE128', 8), ('SHAKE128', 8 * 400)):
    o, st, _ = hash_run(Port(name), MSG_ABC, 24, xs // 8, end=('B', xs))
    r.append((o == oracle(name, MSG_ABC, xs // 8), st))
check('bound: SHA3-256 Xs = 8, t - 8, t and SHAKE128 Xs = 8, 3200 (over two rate blocks) give that prefix, then '
      '_Success_', None, r, [(True, KL_STATE_SUCCESS)] * 5)
res = []
for name, xs in (('SHA3-256', 264), ('SHA3-256', 12), ('SHAKE128', 12), ('SHAKE128', 1 << 32)):
    cl = absorbing(name, MSG_ABC)
    res.append(cl.setst(KL_STATE_HASH_OUTPUT, 'B', xs))
check('bound: SHA3-256 Xs = t + 8 or 12, SHAKE128 Xs = 12 or 2^32 -> _Invalid_', None, res, [KL_STATEEXT_INVALID] * 4)
cl = absorbing('SHAKE256', MSG_ABC)
cl.setst(KL_STATE_HASH_OUTPUT, 'B', 8 * 150)
o1 = squeeze(cl, 100)[1]
cl = Sha3.load(cl.mdh(), cl.export())
o2 = squeeze(cl, 64, 0xee)
check('SHAKE256 bound 150 B: 100 B, export/import (out_len kept), then 64 B: 50 B and the excess cleared, _Success_',
      None, (o1 + o2[1], cl.st, cl.exec('C', out=bytearray(8))),
      (oracle('SHAKE256', MSG_ABC, 150) + bytes(14), KL_STATE_SUCCESS, 'invalid'))
cl = absorbing('SHAKE128', MSG_ABC)
cl.setst(KL_STATE_HASH_OUTPUT, 'A')
check('SHAKE128 Form A: unbounded, never _Success_', None, (squeeze(cl, 400)[1], cl.st),
      (oracle('SHAKE128', MSG_ABC, 400), KL_STATE_HASH_OUTPUT))

info('the two-block padding clause needs b - block_base < |D| + 2 <= 6: reached only through a final piece')
cl = absorbing('SHAKE128', MSG_ABC)
cl.setst(KL_STATE_HASH_OUTPUT, 'B', 1344)
o1 = squeeze(cl, 168)[1]
cl = Sha3.load(cl.mdh(), cl.export())
check('SHAKE128 bound t = 1344 bits: _Success_ with block_base = t (the loop returns before update()); '
      'export/import keeps _Success_', None, (o1, cl.st, cl.block_base),
      (oracle('SHAKE128', MSG_ABC, 168), KL_STATE_SUCCESS, 1344))
done()
