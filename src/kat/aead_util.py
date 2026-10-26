"""Software-side drivers (the instruction sequences of Zkl-software.adoc) over aead_model Machines.
All data in the STANDARDS' byte order (bytes); conversion to the spec's values is done here with b2v/v2b."""
from common import *
from aead_model import *

def pad16(d): return d + bytes(-len(d) % 16)
def lenblk_gcm(lp, la): return cat((bswap(8 * lp, 8), 64), (bswap(8 * la, 8), 64))
def lenblk_siv(lp, la): return cat((8 * lp, 64), (8 * la, 64))
def feed(m, form, data, st_out=True):
    """exec over whole 16-byte blocks of data (padded); returns output bytes."""
    if not data: return b''
    d = pad16(data)
    return v2b(m.exec(form, b2v(d), 8 * len(d)), len(d))[:len(data)] if form == 'A' else (m.exec(form, b2v(d), 8 * len(d)), b'')[1]

def _body(m, form, data, last_st):
    """full blocks then the final partial block (state last_st); returns output bytes."""
    out, n = b'', len(data) - len(data) % 16
    if n: out += v2b(m.exec('A', b2v(data[:n]), 8 * n), n)
    return out

def gcm_enc(m, iv, aad, pt, taglen=128):
    if not m.IV:
        d = pad16(iv); m.setst(SAV, 'B', 8 * len(iv)); m.exec('B', b2v(d), 8 * len(d))
    else: m.setst(ABSORB)
    feed(m, 'B', aad)
    m.setst(ENC)
    out = _body(m, 'A', pt, ELB)
    r = len(pt) % 16
    if r:
        m.setst(ELB, 'B', 8 * r); out += v2b(m.exec('A', b2v(pt[-r:]), 128), r)
    m.setst(ETF, 'C', inp=lenblk_gcm(len(pt), len(aad)))
    return out, v2b(m.exec('C', 0, taglen), taglen // 8)

def gcm_dec(m, iv, aad, ct, tag):
    if not m.IV:
        d = pad16(iv); m.setst(SAV, 'B', 8 * len(iv)); m.exec('B', b2v(d), 8 * len(d))
    else: m.setst(ABSORB)
    feed(m, 'B', aad)
    m.setst(DEC)
    out = _body(m, 'A', ct, DLB)
    r = len(ct) % 16
    if r:
        m.setst(DLB, 'B', 8 * r); out += v2b(m.exec('A', b2v(ct[-r:]), 128), r)
    m.setst(DTF, 'C', inp=lenblk_gcm(len(ct), len(aad)))
    m.setst(HV, 'B', 8 * len(tag))
    m.exec('B', b2v(tag), 8 * len(tag))
    return out, m.st == SUCCESS

def siv_enc(m, nonce, aad, pt):
    m.setst(SAV, 'C', inp=b2v(nonce)); m.setst(ABSORB)
    feed(m, 'B', aad); feed(m, 'B', pt)
    m.setst(ETF, 'A')
    tag = v2b(m.exec('A', lenblk_siv(len(pt), len(aad)), 128), 16)
    out = _body(m, 'A', pt, ELB)
    r = len(pt) % 16
    if r:
        m.setst(ELB, 'B', 8 * r); out += v2b(m.exec('A', b2v(pt[-r:]), 128), r)
    return out, tag

def siv_dec(m, nonce, aad, ct, tag):
    m.setst(SAV, 'C', inp=b2v(nonce)); m.setst(SAV2, 'C', inp=b2v(tag)); m.setst(ABSORB)
    feed(m, 'B', aad)
    m.setst(DEC)
    out = _body(m, 'A', ct, DLB)
    r = len(ct) % 16
    if r:
        m.setst(DLB, 'B', 8 * r); out += v2b(m.exec('A', b2v(ct[-r:]), 128), r)   # auto-transition to Dec_Tag_Finalize
    else:
        m.setst(DTF, 'A')
    m.exec('B', lenblk_siv(len(ct), len(aad)), 128)
    return out, m.st == SUCCESS

def nonce_bytes(bits, n):
    q = -(-n // 8); return (bits << (8 * q - n)).to_bytes(q, 'big')

def ocb_enc(m, nbits, n, aad, pt, taglen=128, preset=False, viasetst=False):
    if not preset:
        m.setst(SAV, 'B', n); m.exec('B', b2v(nonce_bytes(nbits, n)), 128)
    m.setst(ABSORB, 'B', taglen)
    ocb_aad(m, aad)
    m.setst(ENC)
    out = _body(m, 'A', pt, ELB)
    r = len(pt) % 16
    m.setst(ELB, 'B', 8 * r)
    out += v2b(m.exec('A', b2v(pt[-r:]), 128), r) if r else (m.setst(ETF, 'A') if viasetst else m.exec('D'), b'')[1]
    return out, v2b(m.exec('C', 0, taglen), taglen // 8)

def ocb_aad(m, aad):
    n = len(aad) - len(aad) % 16
    if n: m.exec('B', b2v(aad[:n]), 8 * n)
    r = len(aad) % 16
    m.setst(HABL, 'B', 8 * r)
    if r: m.exec('B', b2v(aad[n:]), 128)

def ocb_dec(m, nbits, n, aad, ct, tag, preset=False, viasetst=False):
    if not preset:
        m.setst(SAV, 'B', n); m.exec('B', b2v(nonce_bytes(nbits, n)), 128)
    m.setst(ABSORB, 'B', 8 * len(tag))
    ocb_aad(m, aad)
    m.setst(DEC)
    out = _body(m, 'A', ct, DLB)
    r = len(ct) % 16
    m.setst(DLB, 'B', 8 * r)
    out += v2b(m.exec('A', b2v(ct[-r:]), 128), r) if r else (m.setst(HV, 'A') if viasetst else m.exec('D'), b'')[1]
    m.exec('B', b2v(tag), 8 * len(tag))
    return out, m.st == SUCCESS

def cmac_gen(m, msg, tlen=None):
    bs = m.B // 8; tlen = tlen or m.B
    m.setst(ABSORB)
    n = max(1, -(-len(msg) // bs)); full = (n - 1) * bs
    if full: m.exec('B', b2v(msg[:full]), 8 * full)
    last = msg[full:]
    m.setst(HABL, 'B', 8 * len(last))
    if last: m.exec('B', b2v(last + bytes(bs - len(last))), m.B)
    m.setst(HOUT, 'A')
    return v2b(m.exec('C', 0, tlen), tlen // 8)

def cmac_ver(m, msg, tag):
    bs = m.B // 8
    m.setst(ABSORB)
    n = max(1, -(-len(msg) // bs)); full = (n - 1) * bs
    if full: m.exec('B', b2v(msg[:full]), 8 * full)
    last = msg[full:]
    m.setst(HABL, 'B', 8 * len(last))
    if last: m.exec('B', b2v(last + bytes(bs - len(last))), m.B)
    m.setst(HV, 'B', 8 * len(tag))
    m.exec('B', b2v(tag), 8 * len(tag))
    return m.st == SUCCESS
