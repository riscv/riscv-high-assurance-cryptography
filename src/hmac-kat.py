"""Check the ACE HMAC meta-algorithm against RFC 4231 / FIPS 198-1.

Implements HMAC exactly as ace-ISA-algorithms.adoc now describes it:
  key held as K0 (b bits, derived by the provisioner);
  entering _Hash_Absorb_: state <- IV, absorb K0 xor ipad, absorb message;
  entering _Hash_Output_: finalize inner (d bits), state <- IV, absorb K0 xor opad,
                          absorb inner, finalize.
The "no re-initialisation" variant is run too, to show the step is load-bearing.
"""
import struct
K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
     0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
     0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
     0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
     0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
     0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
     0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
     0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
IV = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
M32 = 0xffffffff
def rotr(x,n): return ((x>>n)|(x<<(32-n))) & M32

def compress(H, blk):
    w = list(struct.unpack('>16I', blk))
    for i in range(16,64):
        s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3)
        s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10)
        w.append((w[i-16]+s0+w[i-7]+s1) & M32)
    a,b,c,d,e,f,g,h = H
    for i in range(64):
        S1 = rotr(e,6)^rotr(e,11)^rotr(e,25); ch = (e&f)^((~e & M32)&g)
        t1 = (h+S1+ch+K[i]+w[i]) & M32
        S0 = rotr(a,2)^rotr(a,13)^rotr(a,22); mj = (a&b)^(a&c)^(b&c)
        t2 = (S0+mj) & M32
        h,g,f,e,d,c,b,a = g,f,e,(d+t1)&M32,c,b,a,(t1+t2)&M32
    return [(x+y)&M32 for x,y in zip(H,[a,b,c,d,e,f,g,h])]

def sha256(msg, H=None):
    H = list(IV) if H is None else list(H)
    L = len(msg)*8
    m = msg + b'\x80' + bytes((-len(msg)-9) % 64) + struct.pack('>Q', L)
    for i in range(0,len(m),64): H = compress(H, m[i:i+64])
    return b''.join(struct.pack('>I',x) for x in H)

b_bits, d_bits = 512, 256
ipad = bytes([0x36])*(b_bits//8)
opad = bytes([0x5c])*(b_bits//8)

def K0(key):                       # FIPS 198-1 §3, done by the provisioner
    if len(key)*8 > b_bits: key = sha256(key)
    return key + bytes(b_bits//8 - len(key))

def ace_hmac(key, msg, reinit=True):
    k0 = K0(key)
    inner = sha256(bytes(x^y for x,y in zip(k0, ipad)) + msg)      # state <- IV, absorb
    if reinit:
        return sha256(bytes(x^y for x,y in zip(k0, opad)) + inner) # state <- IV again
    # variant without re-initialisation: continue from the inner state
    Hc = list(struct.unpack('>8I', inner))
    return sha256(bytes(x^y for x,y in zip(k0, opad)) + inner, H=Hc)

VEC = [  # RFC 4231
 (bytes.fromhex("0b"*20), b"Hi There",
  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
 (b"Jefe", b"what do ya want for nothing?",
  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
 (bytes.fromhex("aa"*131), b"Test Using Larger Than Block-Size Key - Hash Key First",
  "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
]
assert sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 self-test failed"
print("SHA-256 self-test (FIPS 180-4): PASS\n")
print(f"{'vector':8} {'as specified':14} {'without re-init'}")
ok = True
for i,(k,m,exp) in enumerate(VEC):
    a = ace_hmac(k,m).hex(); n = ace_hmac(k,m,reinit=False).hex()
    ok &= (a == exp)
    print(f"{i:<8} {'PASS' if a==exp else 'FAIL':14} {'PASS' if n==exp else 'FAIL'}")
print()
print("HMAC as specified matches RFC 4231:", ok)
