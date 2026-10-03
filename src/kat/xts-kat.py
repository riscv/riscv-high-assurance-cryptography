#!/usr/bin/env python3
"""XEX/XTS KAT: the Machine of <<KLEE-XEX-XTS-modes>> and the <<KLEE-XTS-from-XEX>> procedure
against the IEEE 1619-2007 / SP 800-38E vectors (as in Botan's xts.vec, whose Nonce is bin(i, 128))."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (aes_decrypt, aes_encrypt, b2v, bin_, bxor, cat, double_ocb, sl, update_mask, v2b,
                    MASK128, MDH_FIELD, mdh_pack,
                    KL_STATE_UNCONFIGURED as UNCONFIGURED, KL_STATE_READY as READY,
                    KL_STATE_ENCRYPT as ENCRYPT, KL_STATE_DECRYPT as DECRYPT,
                    KL_STATE_INVALID as INVALID, ERROR_STATES,
                    section, check, control, info, done)

B, ONES64 = 128, (1 << 64) - 1
POL_ENC, POL_DEC = 0b01, 0b10                     # <<KLEE-Machine-field>>
CIPHERS = {'AES-128': 128, 'AES-192': 192, 'AES-256': 256}
XEX_MACHINES = {(t << 4) | 3: c for t, c in enumerate(CIPHERS)}   # <<KLEE-exec-encodings>> Mode 3
XEX_OF = {v: k for k, v in XEX_MACHINES.items()}
fget = lambda v, f: sl(v, *MDH_FIELD[f])
padded = lambda bits: -(-bits // 128) * 16

def fset(v, f, x):
    hi, lo = MDH_FIELD[f]
    return (v & ~(((1 << (hi - lo + 1)) - 1) << lo)) | (x << lo)

def kl_size(mdh, c1_size, pi_size):
    """<<KLEE-instruction-size>> from an MDH, AuxDataLen = 0."""
    st = fget(mdh, 'State')
    return 16 if st in ERROR_STATES else 16 + pi_size if st == UNCONFIGURED else 32 + c1_size

def build_pi(mach, keytype, key1, key2=0, policy=POL_ENC | POL_DEC):
    """MDH (i), then `key1` or the SKID (ii), then `key2` (iii, empty with a SKID: SKR2)."""
    k = CIPHERS[XEX_MACHINES[mach]]
    content, w = (key1, 64) if keytype else (cat((key2, k), (key1, k)), 2 * k)
    return v2b(mdh_pack(Machine=mach, MachinePolicy=policy, KeyType=keytype), 16) + v2b(content, padded(w))

def kl_update_mask(V):
    """<<KLEE-XEX-XTS-modes>> update_mask, b = 128, transcribed."""
    if sl(V, 127, 127) == 0:
        return (V << 1) & MASK128
    return ((V << 1) & MASK128) ^ cat((0, 120), (0b10000111, 8))

# ---------------------------------------------------------------- REF (IEEE 1619-2007, byte strings)
def ref_mul_alpha(t):
    """IEEE 1619-2007 5.2: multiplication of the tweak byte array by alpha."""
    t, cin = bytearray(t), 0
    for j in range(16):
        t[j], cin = ((t[j] << 1) + cin) & 0xFF, t[j] >> 7
    t[0] ^= 0x87 * cin
    return bytes(t)

def ref_xts(key1, key2, seq, data, encrypt=True):
    f = aes_encrypt if encrypt else aes_decrypt
    m, s = divmod(len(data), 16)
    tw = [aes_encrypt(key2, seq.to_bytes(16, 'little'))]
    for _ in range(m):
        tw.append(ref_mul_alpha(tw[-1]))
    tbc = lambda x, t: bxor(f(key1, bxor(x, t)), t)
    blk = lambda q: data[16 * q:16 * q + 16]
    if s == 0:
        return b''.join(tbc(blk(q), tw[q]) for q in range(m))
    out = b''.join(tbc(blk(q), tw[q]) for q in range(m - 1))
    a, b = (m - 1, m) if encrypt else (m, m - 1)      # decryption swaps the last two tweaks
    cc = tbc(blk(m - 1), tw[a])
    return out + tbc(data[16 * m:] + cc[s:], tw[b]) + cc[:s]

# ---------------------------------------------------------------- KLEE model
class XexLocker:
    def __init__(s, sks=None, doubling=kl_update_mask, rng=None, msb_first=False):
        s.mdh, s.key1, s.key2, s.skid, s.mask = 0, None, None, None, None
        s.sks, s.doubling, s.rng, s.msb_first = sks or {}, doubling, rng or random.Random(2026), msb_first
    state = property(lambda s: fget(s.mdh, 'State'))
    keytype = property(lambda s: fget(s.mdh, 'KeyType'))
    k = property(lambda s: CIPHERS[XEX_MACHINES[fget(s.mdh, 'Machine')]])
    widths = property(lambda s: (64, 0) if s.keytype == 1 else (s.k, s.k))
    def invalidate(s):                            # SGR11
        s.mdh = fset(s.mdh, 'State', INVALID)
        s.key1 = s.key2 = s.skid = s.mask = None
    def _install(s, field, key2, importing):
        if s.keytype == 0:
            s.key1, s.key2 = field, key2
        elif field == ONES64 and not importing:   # <<KLEE-KeyType-field>>: random keys, KeyType 0
            s.key1, s.key2 = s.rng.getrandbits(s.k), s.rng.getrandbits(s.k)
            s.mdh = fset(s.mdh, 'KeyType', 0)
        elif field != ONES64 and field in s.sks:
            s.skid, (s.key1, s.key2) = field, s.sks[field]   # one SKID, two keys (SKR2)
        else:
            s.invalidate()                        # <<KLEE-MVR-open>>
    def provision(s, pi):
        s.mdh = b2v(pi[:16])
        w1, w2 = s.widths
        c = b2v(pi[16:])
        s._install(sl(c, w1 - 1, 0), sl(c, w1 + w2 - 1, w1) if w2 else 0, False)
        if s.state not in ERROR_STATES:
            s.mdh, s.mask = fset(s.mdh, 'State', READY), 0
    def content1(s):
        """key1 or SKID (i), key2 (ii, empty with a SKID), mask (iii)."""
        w1, w2 = s.widths
        first = s.skid if s.keytype == 1 else s.key1
        return v2b(cat((s.mask, B), (s.key2 if w2 else 0, w2), (first, w1)), padded(w1 + w2 + B))
    def import_scc(s, mdh, c1):
        s.mdh, v = mdh, b2v(c1)
        w1, w2 = s.widths
        s.mask = sl(v, w1 + w2 + B - 1, w1 + w2)
        s._install(sl(v, w1 - 1, 0), sl(v, w1 + w2 - 1, w1) if w2 else 0, True)

    def setst(s, immed, form='C', operand=0, KLLEN=128):
        """form 'A' (no operand), 'A/iobuf' (substituted Form C, operand = KLIOBUF bytes) or 'C'."""
        if s.state in ERROR_STATES:               # SGR15
            return
        pol = fget(s.mdh, 'MachinePolicy')
        if immed == READY and form == 'A':
            s.mdh, s.mask = fset(s.mdh, 'State', READY), 0
        elif (immed in (ENCRYPT, DECRYPT) and form in ('C', 'A/iobuf')
              and (s.state == READY and pol & (POL_ENC if immed == ENCRYPT else POL_DEC)
                   or s.state == immed)):         # SGR5: same State re-tweaks
            value = b2v(operand) if form == 'A/iobuf' else sl(operand, KLLEN - 1, 0)
            s.mask = sl(value, B - 1, 0)          # mask <- INPUT (MGR7)
            s.mask = b2v(aes_encrypt(v2b(s.key2, s.k // 8), v2b(s.mask, 16)))
            s.mdh = fset(s.mdh, 'State', immed)
        else:
            s.invalidate()                        # MGR1

    def exec(s, inp, KLLEN, klstart=0, out=None, halt_after=None):
        """Form A kl.exec (or its Form D substitution, Vd = Vs2); returns (output operand, klstart)."""
        out = inp if out is None else out
        lo = 8 * klstart
        window = (((1 << KLLEN) - 1) >> lo) << lo if lo < KLLEN else 0
        if s.state in ERROR_STATES:
            return out & ~window, 0               # SGR15
        if s.state not in (ENCRYPT, DECRYPT) or KLLEN % B:   # SGR6, MGR1; MGR2 (<<KLEE-CSR-klstart>>: length first)
            s.invalidate()
            return out & ~window, 0
        if lo >= KLLEN:
            return out, 0                         # empty window: only klstart = 0
        if lo % B:                                # not an interruption point
            s.invalidate()
            return out & ~window, 0
        f, key1 = aes_encrypt if s.state == ENCRYPT else aes_decrypt, v2b(s.key1, s.k // 8)
        pos = list(range(lo, KLLEN, B))           # MGR3
        for q, i in enumerate(reversed(pos) if s.msb_first else pos):
            if q == halt_after:
                return out, i // 8                # precise halt
            res = s.mask ^ b2v(f(key1, v2b(sl(inp, i + B - 1, i) ^ s.mask, 16)))
            s.mask = s.doubling(s.mask)
            out = (out & ~(MASK128 << i)) | (res << i)
        return out, 0
    def exec1(s, value):
        return s.exec(value, B)[0]
    def clone(s):
        c = XexLocker(s.sks, s.doubling, s.rng, s.msb_first)
        c.mdh, c.key1, c.key2, c.skid, c.mask = s.mdh, s.key1, s.key2, s.skid, s.mask
        return c
    def clear(s):
        s.mdh, s.key1, s.key2, s.skid, s.mask = 0, None, None, None, None

    def derive_dest(s, src, length):
        """kl.derive into `key1 || key2` (<<KLEE-derive-endpoints>>), in Ready."""
        if s.state in ERROR_STATES:
            return False
        n = s.k // 4                              # dest_length: both keys
        if s.state != READY or s.keytype == 1 or length < n or len(src) < n:   # DER1 items 2, 5; DER4
            s.invalidate()
            return False
        s.key1, s.key2 = b2v(src[:n // 2]), b2v(src[n // 2:n])
        return True

def derive(src, dst, length):
    """kl.derive into an XEX locker; XEX defines no source endpoint (DER1 items 1-2)."""
    if isinstance(src, XexLocker):
        return src.invalidate() or False
    return dst.derive_dest(src, length)

def new_xex(key1, key2, policy=POL_ENC | POL_DEC, **kw):
    cl = XexLocker(**kw)
    cl.provision(build_pi(XEX_OF[f"AES-{len(key1) * 8}"], 0, b2v(key1), b2v(key2), policy))
    return cl

def cl_run(cl, data, per_block=False, klstart=0, halt_after=None):
    if not data:
        return b'', 0
    if per_block:
        return b''.join(v2b(cl.exec1(b2v(data[i:i + 16])), 16) for i in range(0, len(data), 16)), 0
    out, ks = cl.exec(b2v(data), 8 * len(data), klstart, halt_after=halt_after)
    return v2b(out, len(data)), ks

def kl_xts(key1, key2, seq, data, encrypt=True, per_block=False, discard=0, **kw):
    """<<KLEE-XTS-from-XEX>>, step by step; s = 0 is the plain XEX sequence."""
    m, sb = divmod(len(data), 16)
    s = 8 * sb
    cl = new_xex(key1, key2, **kw)
    cl.setst(ENCRYPT if encrypt else DECRYPT, 'C', bin_(seq, B), 128)   # the tweak is bin(i, b)
    if s == 0:
        return cl_run(cl, data, per_block)[0]
    out = cl_run(cl, data[:16 * (m - 1)], per_block)[0]      # mask now at index m-1
    last, tail = b2v(data[16 * (m - 1):16 * m]), b2v(data[16 * m:])
    if encrypt:
        cc = cl.exec1(last)                                  # index m-1
        c_m1 = cl.exec1(cat((sl(cc, 127, s), B - s), (tail, s)))   # CP @ P_m at index m
        return out + v2b(c_m1, 16) + v2b(sl(cc, s - 1, 0), sb)
    clone = cl.clone()
    clone.exec1(discard)                                     # discarded: index m-1 consumed
    pp = clone.exec1(last)                                   # C_{m-1} at index m
    p_m1 = cl.exec1(cat((sl(pp, 127, s), B - s), (tail, s)))  # CP @ C_m at index m-1
    clone.clear()
    return out + v2b(p_m1, 16) + v2b(sl(pp, s - 1, 0), sb)

# IEEE 1619-2007 XTS-AES vectors (Botan src/tests/data/modes/xts.vec)
_PATTERN = (bytes(range(256)) * 2).hex()

# (label, key1||key2, sequence-number encoding (little-endian, 16 B), plaintext, ciphertext)
IEEE1619 = [
    ("vector 1 (32 B, XTS-AES-128)",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"),
    ("vector 2 (32 B, XTS-AES-128)",
     "1111111111111111111111111111111122222222222222222222222222222222",
     "33333333330000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0"),
    ("vector 3 (32 B, XTS-AES-128)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
     "33333333330000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89"),
    ("vector 15 (32 B, XTS-AES-128)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "4444444444444444444444444444444444444444444444444444444444444444",
     "b01f86f8edc1863706fa8a4253e34f28af319de38334870f4dd1f94cbe9832f1"),
    ("vector 4 (512 B, XTS-AES-128)",
     "2718281828459045235360287471352631415926535897932384626433832795",
     "00000000000000000000000000000000", _PATTERN,
     "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c"
     "c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412"
     "328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce"
     "93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265"
     "5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8"
     "a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434"
     "1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c"
     "5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e"
     "94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc"
     "1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3"
     "e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344"
     "b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd"
     "74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752"
     "afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e"
     "bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d"
     "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568"),
    ("vector 10 (512 B, XTS-AES-256)",
     "2718281828459045235360287471352662497757247093699959574966967627"
     "3141592653589793238462643383279502884197169399375105820974944592",
     "ff000000000000000000000000000000", _PATTERN,
     "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
     "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
     "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
     "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
     "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
     "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
     "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
     "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
     "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
     "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
     "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
     "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
     "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
     "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
     "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
     "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151"),
    ("vector 19 (512 B, XTS-AES-128)",
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
     "21436587a90000000000000000000000", _PATTERN,
     "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6"
     "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc"
     "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854"
     "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177"
     "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3"
     "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4"
     "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe"
     "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d"
     "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64"
     "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272"
     "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648"
     "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394"
     "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2"
     "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a"
     "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf"
     "92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3"),
]

# Ciphertext-stealing vectors: data unit not a multiple of 16 bytes.
IEEE1619_CTS = [
    ("vector 15 (17 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f10",
     "6c1625db4671522d3d7599601de7ca09ed"),
    ("vector 16 (18 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f1011",
     "d069444b7a7e0cab09e24447d24deb1fedbf"),
    ("vector 17 (19 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f101112",
     "e5df1351c0544ba1350b3363cd8ef4beedbf9d"),
    ("vector 18 (20 B)",
     "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
     "9a785634120000000000000000000000",
     "000102030405060708090a0b0c0d0e0f10111213",
     "9d84c813f719aa2c7be3f66171c7c5c2edbf9dac"),
    ("vector 19 (520 B, 32 blocks + 8 B)",
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
     "21436587a90000000000000000000000",
     _PATTERN + "0001020304050607",
     "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6"
     "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc"
     "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854"
     "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177"
     "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3"
     "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4"
     "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe"
     "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d"
     "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64"
     "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272"
     "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648"
     "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394"
     "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2"
     "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a"
     "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf"
     "92cefc151b5cc1611a167893819b63fb37ec662bc0fc907db74a94468a55a7bc"
     "8a6b18e86de60290"),
]

def split_keys(k):
    kb = bytes.fromhex(k)
    return kb[:len(kb) // 2], kb[len(kb) // 2:]

VEC = [(name, *split_keys(k), int.from_bytes(bytes.fromhex(nonce), 'little'), bytes.fromhex(p),
        bytes.fromhex(c)) for name, k, nonce, p, c in IEEE1619 + IEEE1619_CTS]
FULL, CTS = VEC[:len(IEEE1619)], VEC[len(IEEE1619):]

section("REF against IEEE 1619-2007 / SP 800-38E")
for name, k1, k2, i, p, c in VEC:
    check(f"{name} encrypt, decrypt", True, (ref_xts(k1, k2, i, p), ref_xts(k1, k2, i, c, False)), (c, p))
rnd = random.Random(7)
check("update_mask transcribed from <<KLEE-XEX-XTS-modes>> == common.update_mask",
      all(kl_update_mask(v) == update_mask(v)
          for v in [0, 1, 1 << 127, MASK128] + [rnd.getrandbits(128) for _ in range(64)]))
check("update_mask on the value view == IEEE 1619 5.2 on the byte view", True,
      [v2b(kl_update_mask(b2v(bytes([q]) + bytes(15))), 16) for q in (1, 0x80, 0xff)],
      [ref_mul_alpha(bytes([q]) + bytes(15)) for q in (1, 0x80, 0xff)])

section("KLEE XEX locker, full blocks (tweak = bin(i, 128))")
for name, k1, k2, i, p, c in FULL:
    check(f"{name}: encrypt (one multi-block kl.exec, MGR3), decrypt, one kl.exec per block", True,
          (kl_xts(k1, k2, i, p), kl_xts(k1, k2, i, c, False), kl_xts(k1, k2, i, p, per_block=True)),
          (c, p, c))

section("<<KLEE-XTS-from-XEX>> ciphertext stealing")
for name, k1, k2, i, p, c in CTS:
    check(f"{name}: encrypt, decrypt (kl.clone + discarded kl.exec, fed zeros or ones)", True,
          (kl_xts(k1, k2, i, p), kl_xts(k1, k2, i, c, False), kl_xts(k1, k2, i, c, False, discard=MASK128)),
          (c, p, p))

section("kl.clone")
k1, k2, i = CTS[0][1:4]
cl = new_xex(k1, k2)
cl.setst(DECRYPT, 'C', bin_(i, B), 128)
before, clone = cl.mask, cl.clone()
clone.exec1(0)
clone.exec1(0)
check("two kl.exec on the clone: original mask unchanged, clone advanced twice", True,
      (cl.mask, clone.mask), (before, kl_update_mask(kl_update_mask(before))))
check("the clone is a perfect copy (MDH, keys)", True, (clone.mdh, clone.key1, clone.key2),
      (cl.mdh, cl.key1, cl.key2))
clone.clear()
check("kl.clear: Unconfigured, no key material", True,
      (clone.state, clone.key1, clone.key2, clone.mask), (UNCONFIGURED, None, None, None))

section("States, transitions and general rules (vector 2)")
name, k1, k2, i, data, c = FULL[1]
tw = lambda cl, st=ENCRYPT, t=i: cl.setst(st, 'C', bin_(t, B), 128) or cl
check("state constants: Ready 1, Encrypt 7, Decrypt 8, Invalid 49", True,
      (READY, ENCRYPT, DECRYPT, INVALID), (1, 7, 8, 49))
cl = new_xex(k1, k2)
check("provisioning completes in Ready with mask = 0", True, (cl.state, cl.mask), (READY, 0))
res = cl.exec(b2v(data), 256)[0]
check("kl.exec in Ready: Invalid, window zeroed, Content cleared", True,
      (cl.state, res, cl.key1, cl.mask), (INVALID, 0, None, None))
cl = tw(new_xex(k1, k2))
check("kl.setst #kl_state_encrypt: State 7, mask = enc_blk(key2, bin(i, b))", True,
      (cl.state, cl.mask), (ENCRYPT, b2v(aes_encrypt(k2, v2b(bin_(i, B), 16)))))
check("Encrypt -> Decrypt is not an allowed transition -> Invalid", True, tw(cl, DECRYPT).state, INVALID)
check("MachinePolicy decrypt-only: -> Encrypt gives Invalid", True,
      tw(new_xex(k1, k2, POL_DEC)).state, INVALID)
check("MachinePolicy decrypt-only: -> Decrypt decrypts", True,
      cl_run(tw(new_xex(k1, k2, POL_DEC), DECRYPT), c)[0], data)
cl = tw(new_xex(k1, k2))
cl_run(cl, data)
cl.setst(READY, 'A')
zeroed = (cl.state, cl.mask)
check("Encrypt -> Ready zeroes the mask; the CC is reusable with a new tweak", True,
      (zeroed, cl_run(tw(cl), data)[0]), ((READY, 0), c))
cl = tw(new_xex(k1, k2), t=0xdead)
cl_run(cl, data)
check("same-State kl.setst (SGR5) re-tweaks: mask index back to 0", True,
      (tw(cl).state, cl_run(cl, data)[0]), (ENCRYPT, c))
info("a same-State kl.setst is read as the Form C transition into that State: it sets the tweak afresh.")
cl = new_xex(k1, k2)
cl.setst(ENCRYPT, 'C', (b2v(bytes.fromhex("5a" * 16)) << B) | bin_(i, B), 256)
check("KLLEN = 256 > b: only the b low bits of INPUT are the tweak (MGR7)", True, cl_run(cl, data)[0], c)
cl = new_xex(k1, k2)
cl.setst(ENCRYPT, 'A/iobuf', v2b(bin_(i, B), 16))
check("Form A kl.setst and Form D kl.exec through the KLIOBUF", True, cl_run(cl, data)[0], c)
for kl_, ks, want, what in ((136, 0, (INVALID, 0, 0), "KLLEN = 136 (MGR2): Invalid, window zeroed"),
                            (256, 8, (INVALID, b2v(data[:8]), 0), "klstart = 8, no interruption point: Invalid"),
                            (256, 32, (ENCRYPT, b2v(data), 0), "klstart = KLLEN/8: empty window, only klstart = 0"),
                            (256, 48, (ENCRYPT, b2v(data), 0), "klstart = 48 > KLLEN/8: empty window"),
                            (136, 17, (INVALID, b2v(data[:17]), 0), "KLLEN = 136, klstart = 17: invalid length first")):
    cl = tw(new_xex(k1, k2))
    res = cl.exec(b2v(data[:kl_ // 8]), kl_, ks)
    check(what, True, (cl.state, *res), want)
_, k41, k42, i4, p4, c4 = FULL[4]                 # vector 4: 32 blocks
for q in (1, 7, 31):
    cl = tw(new_xex(k41, k42), t=i4)
    part, ks = cl_run(cl, p4, halt_after=q)
    whole, ks2 = cl.exec(b2v(part), 8 * len(p4), klstart=ks)
    check(f"vector 4: kl.exec halted after {q} block(s), resumed at klstart {16 * q}", True,
          (ks, v2b(whole, len(p4)), ks2), (16 * q, c4, 0))
m0 = b2v(aes_encrypt(k1, v2b(bin_(i, B), 16)))
m1 = kl_update_mask(m0)
enc1 = lambda m: b2v(aes_encrypt(k1, v2b(b2v(data[:16]) ^ m, 16))) ^ m
check("key2 = key1: the mask is the raw enc_blk(key1, T), no alpha applied", True,
      (tw(new_xex(k1, k1)).exec1(b2v(data[:16])), enc1(m0) != enc1(m1)), (enc1(m0), True))

section("Provisioning Input and Serialized Content")
SKID = 0x0123456789abcdef
SKS = {SKID: (b2v(k1), b2v(k2))}
for cipher, kt, size in (('AES-128', 0, 48), ('AES-256', 0, 80), ('AES-128', 1, 32)):
    kk = CIPHERS[cipher]
    pi = build_pi(XEX_OF[cipher], kt, SKID if kt else (1 << kk) - 1, 0 if kt else (1 << kk) - 1)
    cl = XexLocker(sks=SKS)
    cl.provision(pi)
    check(f"{cipher} {'SKID' if kt else 'by value'}: PI {size} B, Content1 {size} B, kl.size", True,
          (len(pi), kl_size(b2v(pi[:16]), 0, len(pi) - 16), len(cl.content1()),
           kl_size(cl.mdh, len(cl.content1()), 0)), (size, size, size, 32 + size))
mask2 = ref_mul_alpha(ref_mul_alpha(aes_encrypt(k2, v2b(bin_(i, B), 16))))
for label, kt, want in (("by value", 0, k1 + k2 + mask2), ("by SKID", 1, v2b(SKID, 8) + mask2 + bytes(8))):
    cl = XexLocker(sks=SKS)
    cl.provision(build_pi(XEX_OF['AES-128'], kt, SKID if kt else b2v(k1), 0 if kt else b2v(k2)))
    head = cl_run(tw(cl), data)[0]
    cl2 = XexLocker(sks=SKS)
    cl2.import_scc(cl.mdh, cl.content1())
    check(f"{label}: vector 2, Content1 = key(s) | mask after 2 blocks; import, 2 more blocks", True,
          (head, cl.content1(), cl2.state, cl_run(cl2, data)[0]),
          (c, want, ENCRYPT, ref_xts(k1, k2, i, data + data)[32:]))
cl = XexLocker(sks=SKS)
cl.provision(build_pi(XEX_OF['AES-128'], 1, SKID + 1))
check("unresolved SKID at provisioning -> Invalid", True, cl.state, INVALID)
cl = XexLocker(sks=SKS)
cl.provision(build_pi(XEX_OF['AES-128'], 1, ONES64))
rand_ct = cl_run(tw(cl), data)[0]
check("all-ones SKID: two independent random keys, KeyType 0, Content1 48 B", True,
      (cl.keytype, cl.key1 != cl.key2, len(cl.content1()),
       rand_ct == ref_xts(v2b(cl.key1, 16), v2b(cl.key2, 16), i, data)), (0, True, 48, True))

section("kl.derive: `key1 || key2` in Ready")
src = k1 + k2 + bytes.fromhex("5a" * 16)
for length in (32, 48):
    cl = new_xex(bytes(16), bytes(16))
    ok = derive(src, cl, length)
    check(f"length {length}: key1 || key2 = the first 32 bytes, then vector 2", True,
          (ok, cl_run(tw(cl), data)[0]), (True, c))
for what, mk, s_, n in (("length 16 < 32, no zero-fill (DER1 item 5)", None, src, 16),
                        ("length 0 (DER1 item 5)", None, src, 0),
                        ("24-byte source (DER1 item 5)", None, src[:24], 32),
                        ("destination in Encrypt (DER1 item 2)", tw, src, 32),
                        ("KeyType 1 destination (DER4, DER1 item 2)", 'skid', src, 32)):
    if mk == 'skid':
        cl = XexLocker(sks=SKS)
        cl.provision(build_pi(XEX_OF['AES-128'], 1, SKID))
    else:
        cl = new_xex(bytes(16), bytes(16))
        mk and mk(cl)
    check(f"{what} -> Invalid", True, (derive(s_, cl, n), cl.state, cl.key1), (False, INVALID, None))
src_l, dst = new_xex(k1, k2), new_xex(bytes(16), bytes(16))
check("an XEX locker as a kl.derive source (no source endpoint) -> only the source Invalid", True,
      (derive(src_l, dst, 32), src_l.state, dst.state), (False, INVALID, READY))

section("round trip over many lengths")
rt = True
for length in list(range(16, 80)) + [128, 129, 255, 256]:
    payload = bytes((7 * n + 1) & 0xFF for n in range(length))
    for seq in (0, 1, 0x123456789A):
        ref = ref_xts(k41, k42, seq, payload)
        rt &= (kl_xts(k41, k42, seq, payload) == ref == kl_xts(k41, k42, seq, payload, per_block=True)
               and kl_xts(k41, k42, seq, ref, False) == payload == ref_xts(k41, k42, seq, ref, False))
check("KLEE == REF and round trips, lengths 16..79, 128, 129, 255, 256", rt)

section("negative controls")
control("OCB3 big-endian `double` for update_mask",
        all(kl_xts(*v[1:5], doubling=double_ocb) != v[5] for v in FULL[:4] + CTS[:4]))
control("multi-block kl.exec, most significant block first (2-block units)",
        all(kl_xts(*v[1:5], msb_first=True) != v[5] for v in FULL[:4]))
done()
