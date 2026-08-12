"""Check the SHA-3 / SHAKE parameters and domain suffixes now in the spec.

Keccak-f[1600] + sponge, driven entirely by the spec's own table:
  (c, b=1600-c, t, D) and S = D || pad10*1, bit j of S at rate bit block_base+j.
Verified against FIPS 202 known answers for the empty message.
"""
RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
      0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
      0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
      0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
      0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
      0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
R = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
M = (1<<64)-1
def rol(x,n): return ((x<<n)|(x>>(64-n))) & M

def keccak_f(A):
    for rnd in range(24):
        C=[A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D=[C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
        for x in range(5):
            for y in range(5): A[x][y]^=D[x]
        B=[[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5): B[y][(2*x+3*y)%5]=rol(A[x][y],R[x][y])
        for x in range(5):
            for y in range(5): A[x][y]=B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y])
        A[0][0]^=RC[rnd]
    return A

def sponge(msg, c, D_bits, outlen):
    r = 1600-c; rb = r//8
    # S = D || pad10*1 , bit j of S at rate bit (block_base + j); block_base=|msg| here
    suffix = 0
    for j,bit in enumerate(D_bits): suffix |= bit << j
    suffix |= 1 << len(D_bits)                     # pad's leading 1
    P = bytearray(msg) + bytes([suffix]) + bytes((-len(msg)-1) % rb)
    P[-1] |= 0x80                                  # pad's final 1 at bit r-1
    A=[[0]*5 for _ in range(5)]
    for off in range(0,len(P),rb):
        blk=P[off:off+rb]
        for i in range(rb//8):
            lane=int.from_bytes(blk[i*8:i*8+8],'little')
            A[i%5][i//5]^=lane
        A=keccak_f(A)
    out=b''
    while len(out)<outlen:
        for i in range(rb//8): out+=A[i%5][i//5].to_bytes(8,'little')
        if len(out)<outlen: A=keccak_f(A)
    return out[:outlen]

# spec table: (name, c, b, t, XOF, D)
TBL=[("SHA3-224",448,1152,224,False,[0,1]), ("SHA3-256",512,1088,256,False,[0,1]),
     ("SHA3-384",768,832,384,False,[0,1]),  ("SHA3-512",1024,576,512,False,[0,1]),
     ("SHAKE128",256,1344,1344,True,[1,1,1,1]), ("SHAKE256",512,1088,1088,True,[1,1,1,1])]
# FIPS 202 known answers, empty message
KAT={"SHA3-224":"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
     "SHA3-256":"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
     "SHA3-384":"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
     "SHA3-512":"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
     "SHAKE128":"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
     "SHAKE256":"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"}
print(f"{'function':10} {'c':>5} {'b':>5} {'t':>5} {'XOF':>4} {'suffix octet':>13}  KAT")
ok=True
for name,c,b,t,xof,D in TBL:
    assert b==1600-c, name
    if not xof: assert t==c//2, name
    else:       assert t==b, name
    suf=sum(bit<<j for j,bit in enumerate(D)) | (1<<len(D))
    dig=sponge(b'', c, D, 32)
    good = dig.hex().startswith(KAT[name][:64]) if xof else dig.hex()[:len(KAT[name])]==KAT[name] or KAT[name].startswith(dig.hex())
    if not xof: good = KAT[name].startswith(dig.hex()[:t//4])
    ok &= good
    print(f"{name:10} {c:5} {b:5} {t:5} {str(xof):>4} {'0x%02X'%suf:>13}  {'PASS' if good else 'FAIL'}")
print()
print("all parameters self-consistent and KATs match:", ok)
