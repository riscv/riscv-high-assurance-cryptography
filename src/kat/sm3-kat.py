#!/usr/bin/env python3
"""SM3 KAT for the ACE specification (<<ACE-SM3>> over <<ACE-SHA-2>>/<<ACE-hash-functions>>).

<<ACE-SM3>> says SM3 "follows exactly the rules of the SHA-2 family (<<ACE-SHA-2>>)
with w = 32, b = 512, n = 256, t = 256: it has a big-endian representation with the
same padding rule and word mapping as SHA-256, and the same state machine.  The
initial hash value and the compression function are those of the SM3 standard."
This harness therefore instantiates the same ACE model as kat/sha2-kat.py -- the
process_VLI absorb loop, the int(bswap(block[(j+1)w-1 : jw])) word extraction, the
caller-supplied FIPS-180-4-style padding, the block_base = 0 requirement at
_Hash_Output_, and the generic squeeze loop -- with the GB/T 32905-2016 IV and
compression function, which are implemented from scratch here.

Checks performed:
  * both GB/T 32905-2016 appendix A vectors, each absorbed two ways: a multi-chunk
    plan whose ace.exec cuts fall inside blocks (granularity 32 bits respected), and
    a single transfer interrupted and resumed at every process_VLI interruption
    point.  M4 (earlier review, since fixed): the spec literally assigns the bit count
    input_base to/from the byte-counting acestart CSR; the corrected interpretation
    acestart = input_base/8 is used here, matching the explicit /8 of _Hash_Output_.
  * the digest is read out over two Form C ace.exec instructions in the multi-chunk
    plan, exercising the t/block_base accounting of <<ACE-hash-functions>>.
  * a length-extension-style consistency check over many message lengths against an
    independent straight byte-oriented SM3 reference written in the big-endian view
    (hashlib has no portable 'sm3', so the oracle is this second implementation plus
    the two standard vectors that anchor both).
  * an unpadded message must be rejected at _Hash_Output_ (block_base != 0).

NEGATIVE CONTROL (KAT-EXPECT-FAIL: no-bswap): omitting the bswap in the message-word
extraction must not reproduce the GB/T vector.

VECTOR PROVENANCE / DISCREPANCY NOTE: GB/T 32905-2016 appendix A gives
  SM3("abc")          = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
  SM3("abcd" x 16)    = debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
The first of these differs from the value quoted in this harness's commissioning
brief (66c7f0f4a54445d3...d28b), which is not the standard's digest; the value used
here is the published one and is the one both implementations reproduce.
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import b2v, v2b, sl, bswap, bin_

T0 = time.time()

# ------------------------------------------------------- SM3 core (GB/T 32905-2016)

M32 = 0xffffffff
IV_SM3 = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
          0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

def rotl(x, r):
    r %= 32
    return ((x << r) | (x >> (32 - r))) & M32 if r else x

def P0(x): return x ^ rotl(x, 9) ^ rotl(x, 17)
def P1(x): return x ^ rotl(x, 15) ^ rotl(x, 23)

def sm3_compress(V, W16):
    """CF of GB/T 32905-2016 sect. 5.3.3 on the eight 32-bit chaining words."""
    W = list(W16)
    for j in range(16, 68):
        W.append(P1(W[j - 16] ^ W[j - 9] ^ rotl(W[j - 3], 15))
                 ^ rotl(W[j - 13], 7) ^ W[j - 6])
    Wp = [W[j] ^ W[j + 4] for j in range(64)]
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        T = 0x79cc4519 if j < 16 else 0x7a879d8a
        SS1 = rotl((rotl(A, 12) + E + rotl(T, j)) & M32, 7)
        SS2 = SS1 ^ rotl(A, 12)
        FF = (A ^ B ^ C) if j < 16 else ((A & B) | (A & C) | (B & C))
        GG = (E ^ F ^ G) if j < 16 else ((E & F) | (~E & G & M32))
        TT1 = (FF + D + SS2 + Wp[j]) & M32
        TT2 = (GG + H + SS1 + W[j]) & M32
        D, C, B, A = C, rotl(B, 9), A, TT1
        H, G, F, E = G, rotl(F, 19), E, P0(TT2)
    return [v ^ x for v, x in zip(V, [A, B, C, D, E, F, G, H])]

def sm3_ref(msg):
    """Independent byte-oriented reference: plain big-endian SM3, no ACE model."""
    m = msg + b'\x80' + bytes((-(len(msg) + 9)) % 64) + (8 * len(msg)).to_bytes(8, 'big')
    V = list(IV_SM3)
    for i in range(0, len(m), 64):
        V = sm3_compress(V, [int.from_bytes(m[i + 4 * j: i + 4 * j + 4], 'big')
                             for j in range(16)])
    return b''.join(v.to_bytes(4, 'big') for v in V)

# ------------------------------------------------------- the ACE model

def set_slice(v, hi, lo, x):
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    return (v & ~mask) | ((x << lo) & mask)

class Invalid(Exception):
    """CR transition to Error State _Invalid_."""

class AceSm3:
    """SM3 CC per <<ACE-SM3>>; all quantities are ACE little-endian values."""
    w, b, n, t = 32, 512, 256, 256

    def __init__(self, be_words=True):
        self.be_words = be_words
        self.state = list(IV_SM3)       # _Ready_: state <- IV of the algorithm
        self.block = 0
        self.block_base = 0
        self.cumul_len = 0
        self.acestart = 0
        self.state_name = 'Hash_Absorb'

    def _absorb(self):
        """absorb(): word j = int(bswap(block[(j+1)w-1 : jw])) per <<ACE-SHA-2>>."""
        W = []
        for j in range(16):
            word = sl(self.block, (j + 1) * self.w - 1, j * self.w)
            W.append(bswap(word, 4) if self.be_words else word)
        self.state = sm3_compress(self.state, W)

    def exec_input(self, data, resume=False, interrupt_after=None):
        """Form B ace.exec in _Hash_Absorb_ = process_VLI (<<ACE-process-VLI>>), len=0."""
        assert self.state_name == 'Hash_Absorb'
        INPUT, ACELEN = b2v(data), 8 * len(data)
        # M4 (fixed): the spec now writes `input_base <- 8 * acestart` explicitly.
        input_base = 8 * self.acestart if resume else 0
        iters = 0
        while input_base < ACELEN:
            amount = min(ACELEN - input_base, self.b - self.block_base)
            self.block = set_slice(self.block, self.block_base + amount - 1,
                                   self.block_base,
                                   sl(INPUT, input_base + amount - 1, input_base))
            input_base += amount
            self.block_base += amount
            self.cumul_len += amount
            if self.block_base == self.b:
                self._absorb()
                self.block_base = 0
            iters += 1
            # M4 (fixed): the spec now writes `acestart <- input_base / 8`.
            if interrupt_after is not None and iters >= interrupt_after \
                    and input_base < ACELEN:
                self.acestart = input_base // 8
                return 'interrupted'
        return 'done'

    def setst_output(self):
        """_Hash_Absorb_ -> _Hash_Output_ (stand-alone hashing: block_base must be 0)."""
        if self.block_base != 0:
            raise Invalid('block_base != 0 on entry to _Hash_Output_')
        dig = 0
        for i, hi in enumerate(self.state):
            dig |= bswap(bin_(hi, self.w), 4) << (i * self.w)
        self.block = sl(dig, self.t - 1, 0)
        self.block_base = 0
        self.state_name = 'Hash_Output'

    def exec_output(self, nbytes):
        """Form C ace.exec squeeze loop of <<ACE-hash-functions>>."""
        assert self.state_name == 'Hash_Output'
        ACELEN, OUTPUT, output_base = 8 * nbytes, 0, 0
        while output_base < ACELEN:
            amount = min(ACELEN - output_base, self.t - self.block_base)
            OUTPUT |= sl(self.block, self.block_base + amount - 1,
                         self.block_base) << output_base
            output_base += amount
            self.block_base += amount
            if self.block_base == self.t:
                self.state_name = 'Success'
                break
        return v2b(OUTPUT, output_base // 8)

def caller_pad(msg):
    """The padding of FIPS 180-4 sect. 5.1.1 / GB/T 32905 sect. 4.2, applied caller-side."""
    return (msg + b'\x80' + bytes((-(len(msg) + 9)) % 64)
            + (8 * len(msg)).to_bytes(8, 'big'))

def ace_sm3(msg, plan='multi', be_words=True):
    cc = AceSm3(be_words)
    mp = caller_pad(msg)
    if plan == 'multi':
        c1 = 4 if len(mp) > 12 else len(mp)          # 32-bit granularity
        c2 = max(4, (len(mp) - c1) // 2 // 4 * 4)
        pieces = [p for p in (mp[:c1], mp[c1:c1 + c2], mp[c1 + c2:]) if p]
        for p in pieces:
            assert cc.exec_input(p) == 'done'
        cc.setst_output()
        out = cc.exec_output(24) + cc.exec_output(8)
    else:
        st = cc.exec_input(mp, interrupt_after=1)
        while st == 'interrupted':
            st = cc.exec_input(mp, resume=True, interrupt_after=1)
        cc.setst_output()
        out = cc.exec_output(32)
    assert cc.state_name == 'Success'
    return out

# ------------------------------------------------------- vectors and checks

TV = [  # GB/T 32905-2016 appendix A
    ('"abc"', b'abc',
     '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
    ('"abcd" x 16 (512b)', b'abcd' * 16,
     'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'),
]

ok = True
print('SM3 per <<ACE-SM3>> (= <<ACE-SHA-2>> rules with the GB/T 32905-2016 core)')
print('NOTE (spec, M4): process_VLI resumption modeled with acestart = input_base/8.\n')
print(f'{"message":22} {"multi-chunk":12} {"interrupted":12} {"byte-oriented ref"}')
for label, msg, exp_hex in TV:
    exp = bytes.fromhex(exp_hex)
    a, b = ace_sm3(msg, 'multi'), ace_sm3(msg, 'interrupt')
    r = sm3_ref(msg)
    ga, gb, gr = a == exp, b == exp, r == exp
    ok &= ga and gb and gr
    print(f'{label:22} {"PASS" if ga else "FAIL":12} {"PASS" if gb else "FAIL":12} '
          f'{"PASS" if gr else "FAIL"}')

# ACE model vs the independent byte-oriented reference over many lengths, covering
# every partial-block boundary and multi-block cases
lens = list(range(0, 130)) + [200, 255, 256, 512, 1000]
mism = [L for L in lens
        if ace_sm3(bytes((i * 7 + 3) & 0xff for i in range(L))) !=
           sm3_ref(bytes((i * 7 + 3) & 0xff for i in range(L)))]
mism += [L for L in lens
         if ace_sm3(bytes((i * 7 + 3) & 0xff for i in range(L)), 'interrupt') !=
            sm3_ref(bytes((i * 7 + 3) & 0xff for i in range(L)))]
ok &= not mism
print(f'\nACE model vs byte-oriented reference, {2 * len(lens)} messages of '
      f'0..1000 bytes: {"PASS" if not mism else f"FAIL {mism[:5]}"}')

cc = AceSm3()
cc.exec_input(b'abc')
try:
    cc.setst_output(); rejected = False
except Invalid:
    rejected = True
ok &= rejected
print(f'unpadded message rejected at _Hash_Output_ (block_base != 0 -> _Invalid_): '
      f'{"PASS" if rejected else "FAIL"}')

print('KAT-EXPECT-FAIL: no-bswap')
fired = ace_sm3(b'abc', 'multi', be_words=False) != bytes.fromhex(TV[0][2])
print(f'no-bswap control, SM3("abc") vs GB/T vector: '
      f'{"FAIL (expected: control is effective)" if fired else "PASS (CONTROL IS DEAD)"}')
ok &= fired

print(f'\nruntime: {time.time() - T0:.2f} s')
print(f'KAT-RESULT: {"PASS" if ok else "FAIL"}')
sys.exit(0 if ok else 1)
