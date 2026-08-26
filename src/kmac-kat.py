"""KMAC128 / KMAC256 per SP 800-185, and the ACE formulation of them.

Two implementations:
  REF - straight from SP 800-185: bytepad / encode_string / cSHAKE
  ACE - as ace-ISA-algorithms.adoc specifies it: the CC holds two prefabricated
        rate-sized blocks (the cSHAKE prefix and the padded key), the unit absorbs
        message blocks, then right_encode(L), then the cSHAKE suffix 00 || pad10*1.
They are checked against each other and against the SP 800-185 sample data.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shake-kat.py'))
     .read().split('# spec table')[0])          # keccak_f, sponge helpers

RATE = {128: 168, 256: 136}                      # bytes; c = 256 / 512

def keccak(rate_bytes, data, suffix_bits, outlen):
    """Sponge over a byte string; suffix_bits is the domain suffix, LSB-first."""
    rb = rate_bytes
    suf = 0
    for j, bit in enumerate(suffix_bits): suf |= bit << j
    suf |= 1 << len(suffix_bits)                 # pad10*1 leading 1
    P = bytearray(data) + bytes([suf]) + bytes((-len(data)-1) % rb)
    P[-1] |= 0x80
    A = [[0]*5 for _ in range(5)]
    for off in range(0, len(P), rb):
        blk = P[off:off+rb]
        for i in range(rb//8):
            A[i % 5][i//5] ^= int.from_bytes(blk[i*8:i*8+8], 'little')
        A = keccak_f(A)
    out = b''
    while len(out) < outlen:
        for i in range(rb//8): out += A[i % 5][i//5].to_bytes(8, 'little')
        if len(out) < outlen: A = keccak_f(A)
    return out[:outlen]

# ---- SP 800-185 §2.3 encodings ----
def left_encode(x):
    n = max(1, (x.bit_length()+7)//8)
    return bytes([n]) + x.to_bytes(n, 'big')
def right_encode(x):
    n = max(1, (x.bit_length()+7)//8)
    return x.to_bytes(n, 'big') + bytes([n])
def encode_string(S):
    return left_encode(len(S)*8) + S
def bytepad(X, w):
    z = left_encode(w) + X
    return z + bytes((-len(z)) % w)

# ---- REF: SP 800-185 ----
def ref_kmac(variant, K, X, L, S=b''):
    w = RATE[variant]
    newX = bytepad(encode_string(K), w) + X + right_encode(L)
    prefix = bytepad(encode_string(b"KMAC") + encode_string(S), w)
    return keccak(w, prefix + newX, [0,0], L//8)      # cSHAKE suffix 00

# ---- ACE: the two prefabricated blocks live in the CC ----
def ace_provision(variant, K, S=b''):
    """What the provisioner puts in the PI: cshake_block and key_block, one rate each."""
    w = RATE[variant]
    cshake_block = bytepad(encode_string(b"KMAC") + encode_string(S), w)
    key_block    = bytepad(encode_string(K), w)
    assert len(cshake_block) == w, "customization string too long for one rate block"
    assert len(key_block)    == w, "key too long for one rate block"
    return cshake_block, key_block

def ace_kmac(variant, cshake_block, key_block, X, L):
    """_Initial_ absorbs the two CC blocks; _Hash_Absorb_ absorbs X; finalize appends
       right_encode(L) and the cSHAKE suffix."""
    w = RATE[variant]
    return keccak(w, cshake_block + key_block + X + right_encode(L), [0,0], L//8)

# ---- SP 800-185 sample data (from memory; flagged if they disagree) ----
K32 = bytes(range(0x40, 0x60))
SAMPLES = [
 (128, K32, bytes([0,1,2,3]), 256, b"",
  "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"),
 (128, K32, bytes([0,1,2,3]), 256, b"My Tagged Application",
  "3B1FBA963CD8B0B59E8C1A6D71888B714365 1AF8BA0A7070C0979E2811324AA5".replace(" ",""),),
 (128, K32, bytes(range(200)), 256, b"My Tagged Application",
  "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230"),
 (256, K32, bytes([0,1,2,3]), 512, b"My Tagged Application",
  "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
  "F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"),
]

print(f"{'variant':8} {'|X|':>5} {'|S|':>4}  {'ACE == REF':11} {'REF == sample'}")
agree = True
for variant, K, X, L, S, exp in SAMPLES:
    cb, kb = ace_provision(variant, K, S)
    a = ace_kmac(variant, cb, kb, X, L)
    r = ref_kmac(variant, K, X, L, S)
    agree &= (a == r)
    m = "PASS" if a == r else "FAIL"
    v = "PASS" if r.hex().upper() == exp.upper() else "differs"
    print(f"KMAC{variant:<4} {len(X):>5} {len(S):>4}  {m:11} {v}")
print()
print("ACE formulation agrees with SP 800-185 reference:", agree)
