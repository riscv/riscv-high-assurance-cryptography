"""Software-side CMAC drivers (the instruction sequences of Zkl-software.adoc) over aead_model Machines.
All data in the STANDARDS' byte order (bytes); conversion to the spec's values is done here with b2v/v2b."""
from common import *
from aead_model import *

def cmac_gen(m, msg, tlen=None):
    bs = m.B // 8; tlen = m.tag_len_p if tlen is None else tlen
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
