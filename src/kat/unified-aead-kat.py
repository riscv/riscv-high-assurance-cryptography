#!/usr/bin/env python3
"""Separate KATs for the unified AEAD protocol, its common driver and Content layout.

Compare with published vectors (McGrew-Viega GCM, RFC 8452, RFC 7253) and
independent standards references.  SKIDs, instruction privilege traps and resource allocation are not
modeled here; SCC authentication is checked through the existing sealing core.
"""
import hashlib

from common import *
from unified_aead import *
import aead_ref as R
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


def setup(f, tag=None, **kw):
    m = model(f, **kw); n = nonce(f)
    if m.getinfo() & 1 << 12: m.setst(ABSORB)
    else: m.setst(SAV, 'B', len(n) * 8); m.exec('B', b2v(n), len(n) * 8)
    if tag is not None:
        m.setst(SAV2, 'B', m.tag_len_p); m.exec('B', b2v(tag), len(tag) * 8)
    return m


def restore(m):
    sc, st, machine_use = m.export(), m.st, m.machine_use
    other = UnifiedAEAD(m.family, KEY, policy=m.policy, tag_len_p=m.tag_len_p,
                        cipher=m.CIPHER, preset=m.preset, mask_key=m.mask_key)
    other.import_(sc, st, machine_use)
    check(m.family + ' raw Content and MachineUse round trip, State ' + str(st),
          other.st == st and other.machine_use == machine_use and other.export() == sc)
    return other


section('Descriptor: one GPR, public properties only')
for f in FAMILIES:
    m = model(f); i = m.getinfo()
    check(f + ' descriptor fields', i & 15 == (0 if f == 'Ascon' else 3)
          and bool(i & 16) == (f == 'GCM-SIV') and not i >> 5)
    check(f + ' descriptor independent of key', i == UnifiedAEAD(f, msg(16)).getinfo())
    before = m.export(); check(f + ' query leaves Content unchanged', m.getinfo() == i and m.export() == before)
    m._fail(); check(f + ' invalid locker returns zero', m.getinfo() == 0)

section('Common driver: independent reference')
for f in FAMILIES:
    good = []
    for al in (0, 1, 15, 16, 17, 32, 33):
        for pl in (0, 1, 15, 16, 17, 31, 32, 33, 65):
            ad, pt, n = msg(al), msg(pl, 2), nonce(f)
            m = model(f); c, t = run_aead(m, narg(n), ad, pt)
            expected = reference(f, n, ad, pt)
            d = model(f); p, ok = run_aead(d, narg(n), ad, c, t)
            good.append(m.st == SUCCESS and (c, t) == expected and p == pt and ok)
    check(f + ': 63 AD/PT length pairs against the reference', all(good))
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
            counted = (m.ad_len if state == ABSORB else m.payload_len) == 128 if f in ('GCM', 'GCM-SIV') else True
            check(f + ' committed prefix', m.klstart == 16 and counted)    # only GCM and GCM-SIV keep lengths
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
            check('GCM-SIV second pass recounts the PT', m.payload_len == 512)
            m.setst(ELB, 'B', 40); output |= m.exec('A', b2v(pt[64:]), 128) << 512
        tag = m.exec('C', kllen=128)
        check(f + ' resumed ciphertext/tag', m.st == SUCCESS and (v2b(output, len(pt)), v2b(tag, 16)) == reference(f, n, ad, pt))
        if f in ('GCM', 'GCM-SIV'): check(f + ' counts meaningful bits only', m.ad_len == 424 and m.payload_len == 552)
        m = restore(m); m.setst(READY); check(f + ' Ready resets lengths and flags', not (m.ad_len | m.payload_len | m.flags))

section('Routines of KLE-pseudocode-unified-AEAD-final: eight blocks per kl.exec, final piece = length mod 128')
def listing_drive(m, n, ad, data, tag=None):
    """Instruction sequence of the software chapter's unified AEAD routines (byte-length inputs)."""
    def full_blocks(form, buf):              # absorb_full_blocks / crypt_full_blocks
        out, full = b'', len(buf) // 16 * 16
        for i in range(0, full, 128):
            chunk = buf[i:min(i + 128, full)]
            y = m.exec(form, b2v(chunk), len(chunk) * 8)
            if form == 'A': out += v2b(y, len(chunk))
        return out, buf[full:]
    def final(st, form, tail):               # AD_FINAL / PREPASS_FINAL / DATA_FINAL
        m.setst(st, 'B', len(tail) * 8)
        return v2b(m.exec(form, b2v(tail), len(tail) * 8), len(tail)) if tail else b''
    m.setst(SAV, 'B', len(n) * 8)            # setup_nonce
    for i in range(0, len(n), 128): m.exec('B', b2v(n[i:i + 128]), len(n[i:i + 128]) * 8)
    if tag is not None: m.setst(SAV2, 'B', m.tag_len_p); m.exec('B', b2v(tag), m.tag_len_p)
    final(LAST, 'B', full_blocks('B', ad)[1])
    if tag is None and m.two_pt:
        m.setst(PRE); final(PRELAST, 'B', full_blocks('B', data)[1]); m.exec('C', kllen=m.tag_len_p)
    else: m.setst(ENC if tag is None else DEC)
    out, tail = full_blocks('A', data)
    out += final(ELB if tag is None else DLB, 'A', tail)
    if tag is not None: m.exec('D'); return out, m.st == SUCCESS
    return out, v2b(m.exec('C', kllen=m.tag_len_p), 16)
for f in FAMILIES:
    good = []
    for al in (0, 15, 16, 128, 130, 144):
        for pl in (0, 15, 16, 32, 128, 129, 144, 300):
            ad, pt, n = msg(al), msg(pl, 2), nonce(f)
            c, t = listing_drive(model(f), n, ad, pt)
            p, ok = listing_drive(model(f), n, ad, c, t)
            good.append((c, t) == reference(f, n, ad, pt) and p == pt and ok)
    check(f + ': 48 AD/PT length pairs through the listing routines', all(good))
n, ad, pt = msg(200, 5), msg(40), msg(50, 2)     # GCM IV of 1600 bits: two Set_Aux_Value kl.exec
c, t = listing_drive(model('GCM'), n, ad, pt); p, ok = listing_drive(model('GCM'), n, ad, c, t)
check('GCM long IV through setup_nonce in 128-byte pieces', (c, t) == reference('GCM', n, ad, pt) and p == pt and ok)

section('Published vectors through the listing routines (McGrew-Viega GCM, RFC 8452 C.1/C.2, RFC 7253 App. A)')
H = bytes.fromhex
P64 = H('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255')
GAD = H('feedfacedeadbeeffeedfacedeadbeefabaddad2')
GK1, GK2 = H('feffe9928665731c6d6a8f9467308308'), H('feffe9928665731c6d6a8f9467308308' * 2)
IV12, IV8 = H('cafebabefacedbaddecaf888'), H('cafebabefacedbad')
IV60 = H('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b')
SK1, SK2, SN = H('01' + '00' * 15), H('01' + '00' * 31), H('03' + '00' * 11)
A8 = bytes(range(8)); ON = lambda i: H('BBAA9988776655443322110' + '%x' % i)
VECTORS = [  # (family, key, nonce, AD, PT, published output: CT || tag, or tag only)
 ('GCM', bytes(16), bytes(12), b'', b'', '58e2fccefa7e3061367f1d57a4e7455a'),
 ('GCM', bytes(16), bytes(12), b'', bytes(16), 'ab6e47d42cec13bdf53a67b21257bddf'),
 ('GCM', GK1, IV12, b'', P64, '4d5c2af327cd64a62cf35abd2ba6fab4'),
 ('GCM', GK1, IV12, GAD, P64[:60], '5bc94fbc3221a5db94fae95ae7121a47'),
 ('GCM', GK1, IV8, GAD, P64[:60], '3612d2e79e3b0785561be14aaca2fccb'),
 ('GCM', GK1, IV60, GAD, P64[:60], '619cc5aefffe0bfa462af43c1699d050'),
 ('GCM', bytes(32), bytes(12), b'', b'', '530f8afbc74536b9a963b4f1c4cb738b'),
 ('GCM', bytes(32), bytes(12), b'', bytes(16), 'd0d1c8a799996bf0265b98b5d48ab919'),
 ('GCM', GK2, IV12, b'', P64, 'b094dac5d93471bdec1a502270e3cc6c'),
 ('GCM', GK2, IV12, GAD, P64[:60], '76fc6ece0f4e1768cddf8853bb2d551b'),
 ('GCM', GK2, IV8, GAD, P64[:60], '3a337dbf46a792c45e454913fe2ea8f2'),
 ('GCM', GK2, IV60, GAD, P64[:60], 'a44a8266ee1c8eb0c8b5d4cf5ae9f19a'),  # TC18, confirmed with OpenSSL
 ('GCM-SIV', SK1, SN, b'', b'', 'dc20e2d83f25705bb49e439eca56de25'),
 ('GCM-SIV', SK1, SN, b'', H('0100000000000000'), 'b5d839330ac7b786578782fff6013b815b287c22493a364c'),
 ('GCM-SIV', SK1, SN, b'', H('01' + '00' * 11), '7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639'),
 ('GCM-SIV', SK1, SN, b'', H('01' + '00' * 15), '743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4'),
 ('GCM-SIV', SK2, SN, b'', b'', '07f5f4169bbf55a8400cd47ea6fd400f'),
 ('GCM-SIV', SK2, SN, b'', H('0100000000000000'), 'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28'),
 ('GCM-SIV', SK2, SN, b'', H('01' + '00' * 11), '9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e'),
 ('GCM-SIV', SK2, SN, b'', H('01' + '00' * 15), '85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366'),
 ('OCB', KEY, ON(0), b'', b'', '785407BFFFC8AD9EDCC5520AC9111EE6'),
 ('OCB', KEY, ON(1), A8, A8, '6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009'),
 ('OCB', KEY, ON(2), A8, b'', '81017F8203F081277152FADE694A0A00'),
 ('OCB', KEY, ON(3), b'', A8, '45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9'),
]
CIPHER = {16: 'AES128', 32: 'AES256'}
for i, (f, k, n, ad, pt, want) in enumerate(VECTORS):
    cph = CIPHER[len(k)]; mk = lambda: UnifiedAEAD(f, k, cipher=cph)
    c, t = listing_drive(mk(), n, ad, pt)
    got = t if f == 'GCM' else c + t         # the GCM entries give the tag only
    check('%s vector %d (%s): published output' % (f, i, cph), got == H(want)
          and c == reference(f, n, ad, pt, key=k, cipher=cph)[0])
    p, ok = listing_drive(mk(), n, ad, c, t)
    _, bad = listing_drive(mk(), n, ad, c, bytes([t[0] ^ 1]) + t[1:])
    check('%s vector %d: decrypts; corrupted tag fails' % (f, i), ok and p == pt and not bad)

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
check('GCM IV load resumes across instructions and Content import', m.st == ABSORB and m.nonce_len == 264)
for nb in (6, 7, 8, 95, 119, 120):
    bits = (1 << nb) - 3; nv = b2v((bits << (-nb % 8)).to_bytes(-(-nb // 8), 'big')); m = model('OCB')
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
for tag_len in range(64, 129, 8):
    n, ad, pt = nonce('Ascon'), msg(17), msg(33, 2)
    c, t = reference('Ascon', n, ad, pt, tag_len)
    m = UnifiedAEAD('Ascon', KEY, preset=n, tag_len_p=tag_len)
    p, ok = run_aead(m, None, ad, c, t)
    check('Ascon preset nonce tag length ' + str(tag_len), ok and p == pt)
for tag_len in (65, 100, 127):
    check('Ascon tag length %d is not admitted' % tag_len, UnifiedAEAD('Ascon', KEY, tag_len_p=tag_len).st == INV)

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
    # Interface path: Set_Tag_Value only from Hash_Absorb, before any AD, once, with Xs = tag_len_p
    m = model(f); m.setst(SAV2, 'B', m.tag_len_p)
    check(f + ' tag load from Ready invalidates', m.st == INV)
    m = model(f); m.setst(SAV, 'B', len(nonce(f)) * 8); m.setst(SAV2, 'B', m.tag_len_p)
    check(f + ' tag load before nonce setup completes invalidates', m.st == INV)
    m = setup(f); m.exec('B', 0, 128); m.setst(SAV2, 'B', m.tag_len_p)
    check(f + ' tag load after AD invalidates', m.st == INV)
    m = setup(f, bytes(16)); m.setst(SAV2, 'B', m.tag_len_p)
    check(f + ' second tag load invalidates', m.st == INV)
    m = setup(f); m.setst(SAV2, 'B', m.tag_len_p); m.setst(SAV2, 'B', m.tag_len_p)
    check(f + ' same-State tag load invalidates', m.st == INV)
    n = nonce(f); m = model(f); m.setst(SAV, 'B', len(n) * 8); m.setst(SAV, 'B', len(n) * 8)
    m.exec('B', b2v(n), len(n) * 8); m.setst(LAST, 'B', 0); m.setst(PRE if m.two_pt else ENC)
    check(f + ' same-State nonce kl.setst restarts the load', m.st in (PRE, ENC))
    m = setup(f); m.setst(SAV2, 'B', m.tag_len_p - 8 if m.tag_len_p > 64 else 72)
    check(f + ' tag load with Xs != tag_len_p invalidates', m.st == INV)
    # Empty final piece: Form A bypass of the last-block State
    n, ad, pt = nonce(f), msg(16, 3), msg(32, 4)
    c, t = reference(f, n, ad, pt)
    m = setup(f); m.exec('B', b2v(ad), 128); m.setst(LAST, 'B', 0)
    if m.two_pt:
        m.setst(PRE); m.exec('B', b2v(pt), 256); m.setst(PRELAST, 'B', 0); m.exec('C', kllen=128)
    else: m.setst(ENC)
    out = m.exec('A', b2v(pt), 256); m.setst(ETF); tag = m.exec('C', kllen=128)
    check(f + ' Form A bypass into Enc_Tag_Finalize', m.st == SUCCESS and (v2b(out, 32), v2b(tag, 16)) == (c, t))
    m = setup(f, t); m.exec('B', b2v(ad), 128); m.setst(LAST, 'B', 0); m.setst(DEC)
    out = m.exec('A', b2v(c), 256); m.setst(DTF); m.exec('D', 0)
    check(f + ' Form A bypass into Dec_Tag_Finalize', m.st == SUCCESS and v2b(out, 32) == pt)
    m = setup(f, t); m.setst(LAST, 'B', 0); m.setst(DEC); m.setst(DTF, 'B', 0)
    check(f + ' Form B bypass into Dec_Tag_Finalize invalidates', m.st == INV)
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
m = replay_ready(); m.exec('A', b2v(msg(16)), 128); m.setst(ELB, 'B', 0); m.exec('C', kllen=128)
check('short PT replay fails the tag check', m.st == FAILURE)
m = replay_ready(); m.exec('A', b2v(msg(48)), 384); m.setst(ELB, 'B', 0); m.exec('C', kllen=128)
check('long PT replay fails the tag check', m.st == FAILURE)
m = setup('GCM'); m.ad_len = mask(64) - 7; m.exec('B', 0, 128)
check('AD counter overflow invalidates without wrapping', m.st == INV)
for f, limit in (('GCM', (1 << 39) - 256), ('GCM-SIV', 1 << 39)):
    m = setup(f); m.setst(LAST, 'B', 0); m.setst(PRE if m.two_pt else ENC)
    m.payload_len = limit; m.exec('B' if m.two_pt else 'A', 0, 128)
    check(f + ' message-length limit enforced', m.st == INV)
m = setup('OCB'); m.setst(LAST, 'B', 0); m.setst(ENC); m.core.index = MAX_BLOCKS + 1; m.exec('A', 0, 128)
check('OCB message-length limit enforced by index', m.st == INV)

section('SCC authenticates public lengths and MachineUse flags; raw Content checks reject malformed headers')
for f in FAMILIES:
    m = setup(f); m.exec('B', b2v(msg(32)), 256); sc = m.export(); h = sum(m.header_widths()) // 8; nc = h // 16
    blocks = [b2v(sc[i:i + 16]) for i in range(0, len(sc), 16)]
    mdh = mdh_pack(Machine=7, MachineExtension=0, MachinePolicy=3, State=m.st, SCProtection=1,
                   MachineUse=m.machine_use)
    siv, encrypted = scc_encrypt([mdh] + blocks[:nc], 0, blocks[nc:], b2v(msg(32, 9)))
    ok, decoded = scc_decrypt([mdh] + blocks[:nc], 0, siv, encrypted, b2v(msg(32, 9)), nclear=nc)
    check(f + ' SCC public prefix and private suffix round trip', ok and decoded == blocks[nc:])
    for index in range(nc):
        dirty = blocks[:nc]; dirty[index] ^= 1
        ok, _ = scc_decrypt([mdh] + dirty, 0, siv, encrypted, b2v(msg(32, 9)), nclear=nc)
        check(f + ' SCC authenticates public block ' + str(index), not ok)
    changed_mdh = mdh ^ (1 << 48)
    ok, _ = scc_decrypt([changed_mdh] + blocks[:nc], 0, siv, encrypted, b2v(msg(32, 9)), nclear=nc)
    check(f + ' SCC authenticates MachineUse flags', not ok)
    changed = bytearray(sc); changed[h - 2] = 1
    m.import_(changed, m.st); check(f + ' nonzero reserved header rejected', m.st == INV)

done()
