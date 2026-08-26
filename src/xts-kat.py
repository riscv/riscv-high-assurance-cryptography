"""Check the XTS-from-XEX procedure of ACE-XTS-from-XEX against IEEE 1619 / SP 800-38E.

REF - XTS with ciphertext stealing, written directly from the standard.
ACE - the procedure as ace-ISA-algorithms.adoc gives it: an XEX CC whose mask advances
      after every ace.exec, plus one ace.clone and one discarded block for decryption.
"""
import os, sys
d = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, d)
import io, contextlib
with contextlib.redirect_stdout(io.StringIO()):          # ocb-kat.py prints its own report
    exec(open(os.path.join(d, 'ocb-kat.py')).read())

M128 = (1 << 128) - 1
def mul_alpha(v):                      # XTS: little-endian byte order, poly x^128+x^7+x^2+x+1
    return ((v << 1) & M128) ^ (0x87 if (v >> 127) & 1 else 0)

# ---------- REF: IEEE 1619 ----------
def ref_xts(key1, key2, i, data, encrypt=True):
    E = lambda K, b: aes_encrypt(K, b)
    D = lambda K, b: aes_decrypt(K, b)
    T = int.from_bytes(E(key2, i.to_bytes(16, 'little')), 'little')
    n, s = divmod(len(data), 16)
    blk = lambda q: data[q*16:(q+1)*16]
    def be(x, T):                      # XEX block encrypt/decrypt with tweak value T
        f = E if encrypt else D
        return int.from_bytes(f(key1, ((x ^ T) & M128).to_bytes(16,'little')),'little') ^ T
    out = b''
    if s == 0:
        for q in range(n):
            out += be(int.from_bytes(blk(q),'little'), T).to_bytes(16,'little'); T = mul_alpha(T)
        return out
    m = n                              # m full blocks, then s bytes
    for q in range(m-1):
        out += be(int.from_bytes(blk(q),'little'), T).to_bytes(16,'little'); T = mul_alpha(T)
    Tm1, Tm = T, mul_alpha(T)
    if encrypt:
        CC = be(int.from_bytes(blk(m-1),'little'), Tm1).to_bytes(16,'little')
        Cm, CP = CC[:s], CC[s:]
        PP = data[m*16:] + CP
        out += be(int.from_bytes(PP,'little'), Tm).to_bytes(16,'little') + Cm
    else:
        PP = be(int.from_bytes(blk(m-1),'little'), Tm).to_bytes(16,'little')
        Pm, CP = PP[:s], PP[s:]
        CC = data[m*16:] + CP
        out += be(int.from_bytes(CC,'little'), Tm1).to_bytes(16,'little') + Pm
    return out

# ---------- ACE: an XEX CC, mask advancing after each ace.exec ----------
class XexCC:
    """State of an ACE XEX CC with two independent keys."""
    def __init__(self, key1, key2, tweak=None, mask=None):
        self.k1, self.k2 = key1, key2
        self.mask = mask if mask is not None else \
            int.from_bytes(aes_encrypt(key2, tweak.to_bytes(16,'little')),'little')
    def clone(self): return XexCC(self.k1, self.k2, mask=self.mask)      # ace.clone
    def exec(self, x, encrypt=True):                                     # ace.exec
        f = aes_encrypt if encrypt else aes_decrypt
        y = int.from_bytes(f(self.k1, ((x ^ self.mask) & M128).to_bytes(16,'little')),'little') ^ self.mask
        self.mask = mul_alpha(self.mask)                                 # mask <- update_mask(mask)
        return y

def ace_xts(key1, key2, i, data, encrypt=True):
    cc = XexCC(key1, key2, tweak=i)
    n, s = divmod(len(data), 16)
    b2i = lambda x: int.from_bytes(x,'little'); i2b = lambda x: (x & M128).to_bytes(16,'little')
    out = b''
    if s == 0:
        for q in range(n): out += i2b(cc.exec(b2i(data[q*16:(q+1)*16]), encrypt))
        return out
    m = n
    for q in range(m-1): out += i2b(cc.exec(b2i(data[q*16:(q+1)*16]), encrypt))
    last_full, tail = data[(m-1)*16:m*16], data[m*16:]
    if encrypt:
        CC = i2b(cc.exec(b2i(last_full), True))          # mask index m-1
        Cm, CP = CC[:s], CC[s:]
        out += i2b(cc.exec(b2i(tail + CP), True)) + Cm   # mask index m
    else:
        clone = cc.clone()                               # ace.clone, both at m-1
        clone.exec(0, False)                             # discarded, clone now at m
        PP = i2b(clone.exec(b2i(last_full), False))      # mask index m
        Pm, CP = PP[:s], PP[s:]
        out += i2b(cc.exec(b2i(tail + CP), False)) + Pm  # original still at m-1
    return out

k1 = bytes.fromhex("27182818284590452353602874713526")
k2 = bytes.fromhex("31415926535897932384626433832795")
print(f"{'len':>5} {'ACE==REF enc':14} {'ACE==REF dec':14} {'round-trip'}")
ok = True
for L in (16, 31, 32, 33, 48, 63, 64, 65, 100, 128, 129):
    data = bytes((i*7+1) & 0xff for i in range(L))
    for i in (0, 1, 0x123456789a):
        re_, ae = ref_xts(k1,k2,i,data,True),  ace_xts(k1,k2,i,data,True)
        rd, ad = ref_xts(k1,k2,i,ae,False),    ace_xts(k1,k2,i,ae,False)
        good = (re_==ae) and (rd==ad) and (ad==data)
        ok &= good
    print(f"{L:>5} {'PASS' if re_==ae else 'FAIL':14} {'PASS' if rd==ad else 'FAIL':14} "
          f"{'PASS' if ad==data else 'FAIL'}")
print()
print("ACE XTS-from-XEX procedure agrees with IEEE 1619 and round-trips:", ok)
