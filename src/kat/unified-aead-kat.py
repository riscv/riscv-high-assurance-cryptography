#!/usr/bin/env python3
"""Separate KATs for the unified AEAD protocol, its common driver and Content layout.

Compare with independent standards references and the unchanged extension-0
drivers.  SKIDs, instruction privilege traps and resource allocation are not
modeled here; SCC authentication is checked through the existing sealing core.
"""
import hashlib

from common import *
from unified_aead import *
import aead_ref as R
import aead_util as U
import sponge_ref as S
from scc_core import scc_encrypt, scc_decrypt

KEY = bytes(range(16))
FAMILIES = ('GCM', 'GCM-SIV', 'OCB', 'Ascon')


def msg(n, seed=1): return hashlib.shake_128(bytes([seed])).digest(n)
def nonce(f): return bytes(range(16 if f == 'Ascon' else 12))
def narg(n): return b2v(n), len(n) * 8
def model(f, **kw): return UnifiedAEAD(f, KEY, **kw)


def reference(f, n, ad, pt, tag_len=128, ptbits=None, adbits=None, key=KEY, cipher='AES128'):
    if f == 'GCM':
        E = lambda b: cipher_enc(cipher, key, b)
        c, t = R.gcm_enc(E, n, ad, pt)
    elif f == 'GCM-SIV': c, t = R.siv_enc(cipher, key, n, ad, pt)
    elif f == 'OCB': c, t = R.ocb_enc(cipher, key, int.from_bytes(n, 'big'), len(n) * 8, ad, pt, tag_len)
    else:
        c, nb, t = S.ref_ascon_aead(key, n, ad, pt, ptbits, adbits)
        return v2b(c, (nb + 7) // 8), v2b(t & mask(tag_len), (tag_len + 7) // 8)
    return c, v2b(b2v(t) & mask(tag_len), (tag_len + 7) // 8)


def legacy(f, n, ad, pt):
    if f == 'GCM': return U.gcm_enc(GCM(KEY), n, ad, pt)
    if f == 'GCM-SIV': return U.siv_enc(GCMSIV(KEY), n, ad, pt)
    if f == 'OCB': return U.ocb_enc(OCB(KEY), int.from_bytes(n, 'big'), len(n) * 8, ad, pt)
    c = Locker('ASCON-AEAD128', key=KEY)
    c.setst(ABSORB, 'C', inp=n)
    if ad: c.exec('B', ad + b'\x01' + bytes((-len(ad) - 1) % 16))
    c.setst(ENC, 'A'); out = b''
    full = len(pt) // 16 * 16
    for i in range(0, full, 16):
        o = bytearray(16); c.exec('A', pt[i:i + 16], out=o); out += o
    r = len(pt) - full; c.setst(ELB, 'B', 8 * r)
    if r:
        o = bytearray(16); c.exec('A', pt[full:], out=o); out += o[:r]
    t = bytearray(16); c.exec('C', out=t)
    return out, bytes(t)


def setup(f, tag=None, **kw):
    m = model(f, **kw); n = nonce(f)
    if m.getinfo() & 1 << 12: m.setst(ABSORB)
    else: m.setst(SAV, 'B', len(n) * 8); m.exec('B', b2v(n), len(n) * 8)
    if tag is not None:
        m.setst(SAV2, 'B', m.tag_len_p); m.exec('B', b2v(tag), len(tag) * 8)
    return m


def restore(m):
    sc, st = m.export(), m.st
    other = UnifiedAEAD(m.family, KEY, policy=m.policy, tag_len_p=m.tag_len_p,
                        cipher=m.CIPHER, preset=m.preset, mask_key=m.mask_key)
    other.import_(sc, st)
    check(m.family + ' raw Content round trip, State ' + str(st), other.st == st and other.export() == sc)
    return other


section('Descriptor: one GPR, public properties only')
for f in FAMILIES:
    m = model(f); i = m.getinfo()
    check(f + ' descriptor fields', i & 15 == (0 if f == 'Ascon' else 3)
          and bool(i & 16) == (f == 'GCM-SIV') and not i >> 5)
    check(f + ' descriptor independent of key', i == UnifiedAEAD(f, msg(16)).getinfo())
    before = m.export(); check(f + ' query leaves Content unchanged', m.getinfo() == i and m.export() == before)
    m._fail(); check(f + ' invalid locker returns zero', m.getinfo() == 0)

section('Common driver: independent reference and extension-0 comparison')
for f in FAMILIES:
    good = []
    for al in (0, 1, 15, 16, 17, 32, 33):
        for pl in (0, 1, 15, 16, 17, 31, 32, 33, 65):
            ad, pt, n = msg(al), msg(pl, 2), nonce(f)
            m = model(f); c, t = run_aead(m, narg(n), ad, pt)
            expected = reference(f, n, ad, pt)
            old = legacy(f, n, ad, pt)
            d = model(f); p, ok = run_aead(d, narg(n), ad, c, t)
            good.append(m.st == SUCCESS and (c, t) == expected == old and p == pt and ok)
    check(f + ': 63 AD/PT length pairs, both interfaces and reference', all(good))
    for tag_len in model(f).tlps():
        m = model(f, tag_len_p=tag_len); n, ad, pt = nonce(f), msg(17), msg(33, 2)
        c, t = run_aead(m, narg(n), ad, pt)
        d = model(f, tag_len_p=tag_len); p, ok = run_aead(d, narg(n), ad, c, t)
        check(f + ' tag length ' + str(tag_len), (c, t) == reference(f, n, ad, pt, tag_len) and ok and p == pt)

section('Ascon: arbitrary meaningful bit lengths and ignored tail bits')
for an in (0, 1, 7, 9, 63, 65, 127, 128, 129, 255, 256):
    for pn in (0, 1, 7, 9, 63, 65, 127, 128, 129, 255, 256):
        ad, pt, n = msg((an + 7) // 8), msg((pn + 7) // 8, 2), nonce('Ascon')
        m = model('Ascon'); c, t = run_aead(m, narg(n), ad, pt, data_bits=pn, ad_bits=an)
        d = model('Ascon'); p, ok = run_aead(d, narg(n), ad, c, t, data_bits=pn, ad_bits=an)
        check('Ascon AD/PT bits %d/%d' % (an, pn), (c, t) == reference('Ascon', n, ad, pt, ptbits=pn, adbits=an)
              and ok and b2v(p) == b2v(pt) & mask(pn))

section('Chunking, interruption, final blocks and Content restoration')
for f in FAMILIES:
    n, ad, pt = nonce(f), msg(53), msg(69, 2)
    for partial in (False, True):
        m = setup(f)
        for data, state, last, form in ((ad, ABSORB, LAST, 'B'), (pt, PRE if m.two_pt else ENC, PRELAST if m.two_pt else ELB, 'B' if m.two_pt else 'A')):
            if state != ABSORB: m.setst(state)
            out = m.exec(form, b2v(data[:48]), 384, halt_at=16)
            check(f + ' committed-prefix counter', m.klstart == 16 and (m.ad_len if state == ABSORB else m.payload_len) == 128)
            m = restore(m)
            out |= m.exec(form, b2v(data[:48]), 384, klstart=16)
            full = len(data) // 16 * 16
            if full > 48: out |= m.exec(form, b2v(data[48:full]), (full - 48) * 8) << 384
            if partial: m = restore(m)
            r = len(data) - full; m.setst(last, 'B', r * 8)
            m = restore(m)
            out |= m.exec(form, b2v(data[full:]) | mask(128) << (r * 8), 128) << (full * 8)
            if state != ABSORB: output = out
        if m.two_pt:
            first_tag = m.exec('C', kllen=128); m = restore(m)
            output = m.exec('A', b2v(pt[:64]), 512)
            check('GCM-SIV counts replay separately', m.payload_len == 552 and m.replay_len == 512)
            m.setst(ELB, 'B', 40); output |= m.exec('A', b2v(pt[64:]), 128) << 512
        tag = m.exec('C', kllen=128)
        check(f + ' resumed ciphertext/tag', m.st == SUCCESS and (v2b(output, len(pt)), v2b(tag, 16)) == reference(f, n, ad, pt))
        check(f + ' counts meaningful bits only', m.ad_len == 424 and m.payload_len == 552 and m.replay_len == (552 if m.two_pt else 0))
        m = restore(m); m.setst(READY); check(f + ' Ready resets lengths and flags', not (m.ad_len | m.payload_len | m.replay_len | m.flags))

section('Nonce variants and nonce-length handling')
for f in ('GCM', 'OCB', 'Ascon'):
    n, ad, pt = nonce(f), msg(17), msg(33, 2)
    c, t = reference(f, n, ad, pt)
    preset = b2v(n) if f == 'GCM' else (b2v(n), 96) if f == 'OCB' else n
    m = model(f, preset=preset)
    p, ok = run_aead(m, None, ad, c, t)
    check(f + ' preset nonce: common driver decrypts', ok and p == pt and m.policy == 2)
    m = restore(m); m.setst(READY); p, ok = run_aead(m, None, ad, c, t)
    check(f + ' preset nonce survives import/Ready', ok and p == pt)
    check(f + ' preset variant rejects encryption policy', raises(model, f, preset=preset, policy=3, exc=ValueError))
n, mk = nonce('Ascon'), msg(16, 7)
m = model('Ascon', mask_key=mk); c, t = run_aead(m, narg(n), msg(17), msg(33, 2))
check('Ascon nonce mask is internal', (c, t) == reference('Ascon', bxor(n, mk), msg(17), msg(33, 2)))
m = restore(m); m.setst(READY); c2, t2 = run_aead(m, narg(n), msg(17), msg(33, 2))
check('Ascon mask survives import/Ready', (c2, t2) == (c, t))
for nl in (1, 12, 13, 16, 17, 1024):
    n = msg(nl); m = model('GCM'); c, t = run_aead(m, narg(n), msg(17), msg(33, 2))
    check('GCM IV bytes ' + str(nl), (c, t) == reference('GCM', n, msg(17), msg(33, 2)))
m = model('GCM'); n = msg(33); m.setst(SAV, 'B', 264)
m.exec('B', b2v(n), 256, halt_at=16); m = restore(m)
m.exec('B', b2v(n), 256, klstart=16); m = restore(m)
m.exec('B', b2v(n[32:]), 8)
check('GCM IV load resumes across instructions and Content import', m.st == ABSORB and m.nonce_done == 264)
for nb in (6, 7, 8, 95, 119, 120):
    bits = (1 << nb) - 3; nv = b2v(U.nonce_bytes(bits, nb)); m = model('OCB')
    c, t = run_aead(m, (nv, nb), msg(17), msg(33, 2))
    check('OCB nonce bits ' + str(nb), (c, t) == R.ocb_enc('AES128', KEY, bits, nb, msg(17), msg(33, 2)))

section('Additional standardized key/cipher profiles')
for f, cipher in (('GCM', 'AES128'), ('GCM', 'AES192'), ('GCM', 'AES256'), ('GCM', 'SM4'),
                  ('GCM-SIV', 'AES128'), ('GCM-SIV', 'AES256'),
                  ('OCB', 'AES128'), ('OCB', 'AES192'), ('OCB', 'AES256')):
    key = msg(24 if cipher == 'AES192' else 32 if cipher == 'AES256' else 16)
    n, ad, pt = nonce(f), msg(17), msg(33, 2)
    m = UnifiedAEAD(f, key, cipher=cipher); c, t = run_aead(m, narg(n), ad, pt)
    check(f + '/' + cipher, (c, t) == reference(f, n, ad, pt, key=key, cipher=cipher))

section('Every preset-nonce AEAD profile')
for f, cipher in (('GCM', 'AES128'), ('GCM', 'AES192'), ('GCM', 'AES256'), ('GCM', 'SM4'),
                  ('OCB', 'AES128'), ('OCB', 'AES192'), ('OCB', 'AES256')):
    key = msg(24 if cipher == 'AES192' else 32 if cipher == 'AES256' else 16)
    n, ad, pt = nonce(f), msg(17), msg(33, 2)
    preset = b2v(n) if f == 'GCM' else (b2v(n), 96)
    for tag_len in ((64, 96, 104, 112, 120, 128) if f == 'GCM' else (64, 96, 128)):
        c, t = reference(f, n, ad, pt, tag_len, key=key, cipher=cipher)
        m = UnifiedAEAD(f, key, cipher=cipher, preset=preset, tag_len_p=tag_len)
        p, ok = run_aead(m, None, ad, c, t)
        check(f + '/' + cipher + ' preset nonce tag length ' + str(tag_len), ok and p == pt and m.st == SUCCESS)
for tag_len in range(64, 129):
    n, ad, pt = nonce('Ascon'), msg(17), msg(33, 2)
    c, t = reference('Ascon', n, ad, pt, tag_len)
    m = UnifiedAEAD('Ascon', KEY, preset=n, tag_len_p=tag_len)
    p, ok = run_aead(m, None, ad, c, t)
    check('Ascon preset nonce tag length ' + str(tag_len), ok and p == pt)

section('Invalid sequencing, forms, lengths and direction policies')
for f in FAMILIES:
    m = setup(f); m.setst(LAST, 'B', 8); m.setst(ENC)
    check(f + ' cannot leave an unconsumed AD final', m.st == INV)
    m = setup(f); m.setst(LAST, 'B', 0); m.setst(LAST, 'B', 0)
    check(f + ' duplicate AD final is invalid', m.st == INV)
    m = setup(f); m.setst(LAST, 'B', 0); m.exec('B', 0, 0)
    check(f + ' closed AD admits no exec, even with empty window', m.st == INV)
    m = setup(f); m.setst(LAST, 'B', 0); m.setst(DEC)
    check(f + ' decryption requires received tag', m.st == INV)
    m = setup(f); m.exec('C', 0, 128)
    check(f + ' wrong data Form invalidates', m.st == INV)
    m = setup(f); m.exec('B', 0, 8)
    check(f + ' non-block streaming transfer invalidates', m.st == INV)
    m = setup(f); before = m.export(); m.exec('B', 0, 0)
    check(f + ' empty admitted transfer changes nothing', m.st == ABSORB and m.export() == before)
    m = setup(f); m.exec('B', 0, 256, klstart=1)
    check(f + ' invalid interruption point invalidates', m.st == INV)
    m = setup(f, policy=2); m.setst(LAST, 'B', 0); m.setst(PRE if m.two_pt else ENC)
    check(f + ' disabled encryption invalidates at entry', m.st == INV)
    m = setup(f, policy=1); m.setst(SAV2, 'B', 128)
    check(f + ' disabled decryption invalidates tag load', m.st == INV)
    m = setup(f); m.setst(LAST, 'B', 129)
    check(f + ' oversized final piece invalidates', m.st == INV)
    if f != 'Ascon':
        m = setup(f); m.setst(LAST, 'B', 7)
        check(f + ' non-byte message length rejected, not rounded', m.st == INV)

section('Authentication failure and replay consistency')
for f in FAMILIES:
    n, ad, pt = nonce(f), msg(17), msg(33, 2)
    c, t = reference(f, n, ad, pt)
    for which in ('AD', 'CT', 'tag'):
        aa, cc, tt = ad, c, t
        if which == 'AD': aa = bytes([ad[0] ^ 1]) + ad[1:]
        elif which == 'CT': cc = bytes([c[0] ^ 1]) + c[1:]
        else: tt = bytes([t[0] ^ 1]) + t[1:]
        m = model(f); p, ok = run_aead(m, narg(n), aa, cc, tt)
        check(f + ' changed ' + which + ': Failure', not ok and m.st == FAILURE)
    m = model(f); run_aead(m, narg(n), ad, pt); m.exec('C', kllen=128)
    check(f + ' repeated finalization invalidates', m.st == INV)

def replay_ready():
    m = setup('GCM-SIV'); m.setst(LAST, 'B', 0); m.setst(PRE)
    m.exec('B', b2v(msg(32)), 256); m.setst(PRELAST, 'B', 0); m.exec('C', kllen=128)
    return m

m = replay_ready(); m.exec('A', b2v(msg(32)) ^ 1, 256); m.setst(ELB, 'B', 0); t = m.exec('C', kllen=128)
check('changed PT replay is detected cryptographically', m.st == FAILURE and t == 0)
m = replay_ready(); m.exec('A', 0, 128); m.setst(ELB, 'B', 0)
check('short PT replay invalidates', m.st == INV)
m = replay_ready(); m.exec('A', 0, 384)
check('long PT replay invalidates', m.st == INV)
m = setup('GCM'); m.ad_len = mask(64) - 7; m.exec('B', 0, 128)
check('AD counter overflow invalidates without wrapping', m.st == INV)
for f, limit in (('GCM', (1 << 39) - 256), ('GCM-SIV', 1 << 39), ('OCB', 1 << 55), ('Ascon', mask(64))):
    m = setup(f); m.setst(LAST, 'B', 0); m.setst(PRE if m.two_pt else ENC)
    m.payload_len = limit; m.exec('B' if m.two_pt else 'A', 0, 128)
    check(f + ' message-length limit enforced', m.st == INV)

section('SCC authenticates public lengths; raw Content checks reject malformed headers')
for f in FAMILIES:
    m = setup(f); m.exec('B', b2v(msg(32)), 256); sc = m.export()
    blocks = [b2v(sc[i:i + 16]) for i in range(0, len(sc), 16)]
    mdh = mdh_pack(Machine=7, MachineExtension=0, MachinePolicy=3, State=m.st, SCProtection=1)
    siv, encrypted = scc_encrypt([mdh] + blocks[:2], 0, blocks[2:], b2v(msg(32, 9)))
    ok, decoded = scc_decrypt([mdh] + blocks[:2], 0, siv, encrypted, b2v(msg(32, 9)), nclear=2)
    check(f + ' SCC public prefix and private suffix round trip', ok and decoded == blocks[2:])
    for index in (0, 1):
        dirty = blocks[:2]; dirty[index] ^= 1
        ok, _ = scc_decrypt([mdh] + dirty, 0, siv, encrypted, b2v(msg(32, 9)), nclear=2)
        check(f + ' SCC authenticates public block ' + str(index), not ok)
    changed = bytearray(sc); changed[30] = 1
    m.import_(changed, m.st); check(f + ' nonzero reserved header rejected', m.st == INV)

done()
