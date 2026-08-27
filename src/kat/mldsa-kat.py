#!/usr/bin/env python3
"""Known-Answer Tests for the ACE ML-DSA algorithm (src/ace-ISA-algorithms.adoc,
anchor [[ACE-PQC-ML-DSA]]) against FIPS 204.

What this harness validates
---------------------------
1.  *Standards conformance of what the spec delegates.*  kat/fips204.py is a real,
    complete FIPS 204 implementation (NTT over Z_8380417, ExpandA / ExpandS /
    ExpandMask, SampleInBall, Power2Round / Decompose / HighBits / LowBits /
    MakeHint / UseHint, SimpleBitPack / BitPack / HintBitPack, pkEncode /
    skEncode / sigEncode / w1Encode, KeyGen_internal, Sign_internal with its
    rejection loop, and Verify_internal).  It is anchored here, byte for byte,
    against official NIST ACVP vectors for all three parameter sets, including
    the *external-mu* interface -- which is exactly the interface the ACE unit
    exposes (mu = SHAKE256(tr @ M', 64) supplied through State _mu_Input_).

2.  *The ACE specification text itself*: the size table <<ACE-ML-DSA-sizes>>, the
    `HasPrivKey` / `HasPubKey` flags and their _*_Input_ clearing rules, the
    external-mu convention with the `ctx` / `ctxlen` binding, hedged
    (rnd random) versus deterministic (rnd = 0) selection through the Form B
    `ace.setst` auxiliary `Xs`, _Sign_Generate_ via ML-DSA.Sign_internal,
    _Sign_Verify_ via ML-DSA.Verify_internal, _compute_pubKey_ with its
    tr-consistency check, and the _AlgorithmUse_ transfer-counter rules
    (excess bits ignored on input, past-the-end -> Error State _Invalid_).

3.  *Review finding M12, since FIXED*: <<ACE-PQC-ML-DSA>> now splits a malformed
    `privkey`/`pubkey` (a configuration error -> Error State Invalid) from a
    well-formed value that does not verify (a data error -> State Failure, a
    valid state), no longer calls state 23 an "Error State", and states the
    _Sign_Verify_ outcome in terms of the Boolean that FIPS 204 Algorithm 8
    actually returns.  This harness had already modelled that reading.

Vector provenance
-----------------
    usnistgov/ACVP-Server, gen-val/json-files/ML-DSA-keyGen-FIPS204/
        internalProjection.json  (tcId 1 / 26 / 51, ML-DSA-44 / 65 / 87)
    usnistgov/ACVP-Server, gen-val/json-files/ML-DSA-sigGen-FIPS204/
        internalProjection.json  (tgId 7  = ML-DSA-44 internal, externalMu,
                                            deterministic: tcId 91, 92;
                                  tgId 19 = ML-DSA-44 internal, externalMu,
                                            hedged (rnd given): tcId 271, 272;
                                  tgId 1  = ML-DSA-44 external, pure,
                                            deterministic, with context: tcId 1, 2)
    usnistgov/ACVP-Server, gen-val/json-files/ML-DSA-sigVer-FIPS204/
        internalProjection.json  (tgId 7 = ML-DSA-44 externalMu:
                                  tcId 91, 92, 94, 95, 96)
    fetched 2026-08-26; each embedded record carries its own case identifier.

Negative control (KAT-EXPECT-FAIL): a verifier that skips FIPS 204 Algorithm 21's
malformed-hint checks (the omega bound and the canonical-encoding conditions)
accepts a signature it must reject.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fips204 as D
from common import sl

# ---------------------------------------------------------------- reporting

_results = []

def chk(name, ok, note=''):
    _results.append(bool(ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{note}]" if note else ''))
    return ok

# ================================================================ ACE model

# MDH field positions, src/ace-ISA-unpriv.adoc <<ACE-metadata-header>>.
F_ALGORITHM    = (11, 0)
F_ALGPOLICY    = (13, 12)
F_STATE        = (25, 21)
F_STATEEXT     = (29, 26)
F_AUXINFO      = (61, 46)
F_ALGORITHMUSE = (95, 80)

def mdh_get(mdh, fld):
    hi, lo = fld
    return sl(mdh, hi, lo)

def mdh_set(mdh, fld, val):
    hi, lo = fld
    m = ((1 << (hi - lo + 1)) - 1) << lo
    return (mdh & ~m) | ((val << lo) & m)

# States from the ML-DSA state list in [[ACE-PQC-ML-DSA]] plus the global ones.
S_READY, S_GENKEYPAIR = 1, 2
S_PK_OUT, S_PK_IN, S_CTX_IN, S_MU_IN, S_TR_IN = 3, 4, 5, 6, 7
S_SIGN_GEN, S_SIGN_OUT, S_SIGN_VERIFY, S_SIGN_IN = 8, 9, 10, 11
S_SK_IN, S_COMPUTE_PK = 12, 13
S_SUCCESS, S_FAILURE, S_INVALID = 22, 23, 25

IN_STATES  = {S_PK_IN: 'pubkey', S_CTX_IN: 'ctx', S_MU_IN: 'mu',
              S_TR_IN: 'tr', S_SIGN_IN: 'signature', S_SK_IN: 'privkey'}
OUT_STATES = {S_PK_OUT: 'pubkey', S_SIGN_OUT: 'signature'}

# StateExtension bit assignment for the two booleans of [[ACE-PQC-ML-DSA]]
# ("Apart from HasPrivKey and HasPubKey (which are stored in StateExtension)").
SE_HASPRIVKEY, SE_HASPUBKEY = 1, 2


class Invalidated(Exception):
    """The CR transitioned to Error State _Invalid_ (ace_state_invalid, 25)."""


class MLDSAContext:
    """Model of an ACE Cryptographic Context running an ML-DSA algorithm."""

    def __init__(self, ps, algpolicy=0b11, auxinfo=0):
        self.ps = ps
        self.sk_len, self.pk_len, self.sig_len = D.sizes(ps)
        if algpolicy == 0:
            # "An AlgorithmPolicy of 0 is not valid, and it causes the CR to
            #  transition to Error State Invalid."
            raise Invalidated('AlgorithmPolicy == 0 at provisioning')
        self.mdh = mdh_set(0, F_ALGPOLICY, algpolicy)
        self.mdh = mdh_set(self.mdh, F_AUXINFO, auxinfo)
        self.mdh = mdh_set(self.mdh, F_STATE, S_READY)
        # "Upon provisioning, fields privkey and pubkey are cleared, both flags
        #  HasPrivKey and HasPubKey are false, ... transitions to State Ready."
        self.privkey = b''
        self.pubkey = b''
        self._clear_volatile()

    def _clear_volatile(self):
        self.signature = b''
        self.ctxlen = 0
        self.ctx = b''
        self.mu = b''
        self.rnd = b'\0' * 32
        # tr is not listed among the fields cleared on entering Ready.

    # -- MDH views ------------------------------------------------------
    @property
    def state(self):
        return mdh_get(self.mdh, F_STATE)

    @property
    def alguse(self):
        return mdh_get(self.mdh, F_ALGORITHMUSE)

    @alguse.setter
    def alguse(self, v):
        self.mdh = mdh_set(self.mdh, F_ALGORITHMUSE, v)

    def _flag(self, bit):
        return bool(mdh_get(self.mdh, F_STATEEXT) & bit)

    def _set_flag(self, bit, val):
        se = mdh_get(self.mdh, F_STATEEXT)
        se = (se | bit) if val else (se & ~bit)
        self.mdh = mdh_set(self.mdh, F_STATEEXT, se)

    @property
    def has_privkey(self):
        return self._flag(SE_HASPRIVKEY)

    @property
    def has_pubkey(self):
        return self._flag(SE_HASPUBKEY)

    def _invalidate(self, why):
        self.mdh = mdh_set(self.mdh, F_STATE, S_INVALID)
        raise Invalidated(why)

    # -- field bookkeeping ----------------------------------------------
    def field_bits(self, name):
        return {'privkey': self.sk_len * 8, 'pubkey': self.pk_len * 8,
                'signature': self.sig_len * 8, 'mu': 512, 'tr': 512,
                'ctx': self.ctxlen * 8}[name]

    # -- instructions ---------------------------------------------------
    def setst(self, state, aux=None, rnd=None):
        """Form A `ace.setst` (aux None) or Form B (aux = Xs)."""
        if state == S_CTX_IN:
            # "a Form B ace.setst instruction must be used where the GPR
            #  contains the parameter ctxlen.  Only values 0..255 are valid."
            if aux is None or not (0 <= aux <= 255):
                self._invalidate(f'ctx_Input with invalid ctxlen {aux}')
            self.ctxlen = aux
            self.ctx = b''
        if state == S_PK_OUT and not self.has_pubkey:
            self._invalidate('pubkey_Output entered with HasPubKey false')
        if state == S_SIGN_GEN:
            if not self.has_privkey:
                self._invalidate('Sign_Generate entered with HasPrivKey false')
            # "If Xs = 0 ... hedged signing is selected ... If Xs is non-zero,
            #  then deterministic signing is selected. rnd is set to zeros(256)."
            if aux in (None, 0):
                if rnd is None:
                    raise AssertionError('hedged signing needs an RBG value')
                self.rnd = rnd                       # 256 bits from the RBG
            else:
                self.rnd = b'\0' * 32
        self.mdh = mdh_set(self.mdh, F_STATE, state)
        if state == S_READY:
            self._clear_volatile()
        if state in IN_STATES or state in OUT_STATES:
            self.alguse = 0
        if state == S_SK_IN:
            # "Upon entering State privkey_Input, HasPrivKey is set to false, and
            #  pubkey is erased and HasPubKey set to false."
            self._set_flag(SE_HASPRIVKEY, False)
            self.pubkey = b''
            self._set_flag(SE_HASPUBKEY, False)
        if state == S_PK_IN:
            self._set_flag(SE_HASPUBKEY, False)

    def exec_input(self, data):
        """Form B `ace.exec ..., INPUT` in an _*_Input_ state (process_VLI with
        process_block = finalize = None)."""
        name = IN_STATES[self.state]
        n = self.field_bits(name)
        cum = self.alguse
        if cum >= n:
            self._invalidate(f'{name}_Input with AlgorithmUse >= n ({cum} >= {n})')
        amount = min(len(data) * 8, n - cum)         # bits in excess are ignored
        buf = bytearray(getattr(self, name).ljust(n // 8, b'\0'))
        buf[cum // 8: cum // 8 + amount // 8] = data[:amount // 8]
        setattr(self, name, bytes(buf))
        self.alguse = cum + amount
        if self.alguse == n:
            if name == 'privkey':
                self._set_flag(SE_HASPRIVKEY, True)
                self.tr = self.privkey[64:128]       # tr is embedded in privkey
            elif name == 'pubkey':
                self._set_flag(SE_HASPUBKEY, True)
        return amount

    def exec_output(self, nbytes):
        """Form C `ace.exec` in _pubkey_Output_ / _Sign_Output_.

        NOTE the asymmetry in the spec text: on *input* "the bits in excess are
        ignored", but on *output* an over-long transfer sends the CR to Error
        State _Invalid_.  Modelled literally.
        """
        name = OUT_STATES[self.state]
        n = self.field_bits(name)
        cum = self.alguse
        if cum >= n:
            self._invalidate(f'{name}_Output with AlgorithmUse >= n')
        if cum + nbytes * 8 > n:
            self._invalidate(f'{name}_Output transfer past the end of the field')
        out = getattr(self, name)[cum // 8: cum // 8 + nbytes]
        self.alguse = cum + nbytes * 8
        return out

    def exec_d(self, xi=None):
        """Form D `ace.exec Kn|K{Xn}`."""
        st = self.state
        if st == S_GENKEYPAIR:
            self.pubkey, self.privkey = D.keygen_internal(xi, self.ps)
            self.tr = self.privkey[64:128]
            self._set_flag(SE_HASPRIVKEY, True)
            self._set_flag(SE_HASPUBKEY, True)
            self.mdh = mdh_set(self.mdh, F_STATE, S_SUCCESS)
            return

        if st == S_COMPUTE_PK:
            if not self.has_privkey:
                self._invalidate('compute_pubKey with HasPrivKey false')
            pk, tr_from_pk, tr_in_sk = D.compute_pubkey(self.privkey, self.ps)
            if tr_from_pk != tr_in_sk:
                self._invalidate('compute_pubKey: pubkey does not hash to tr')
            self.pubkey = pk
            self._set_flag(SE_HASPUBKEY, True)
            self.mdh = mdh_set(self.mdh, F_STATE, S_SUCCESS)
            return

        if st == S_SIGN_GEN:
            if not self.has_privkey:
                self._invalidate('Sign_Generate with HasPrivKey false')
            sig = D.sign_internal_mu(self.privkey, self.mu, self.rnd, self.ps)
            if sig is None:
                self.mdh = mdh_set(self.mdh, F_STATE, S_FAILURE)
                return
            self.signature = sig
            self.mdh = mdh_set(self.mdh, F_STATE, S_SUCCESS)
            return

        if st == S_SIGN_VERIFY:
            if not self.has_pubkey:
                self._invalidate('Sign_Verify with HasPubKey false')
            # <<ACE-PQC-ML-DSA>>: Verify_internal returns a Boolean only, and
            # nothing is written to `signature` on this path (M12, fixed).
            ok = D.verify_internal_mu(self.pubkey, self.mu, self.signature, self.ps)
            self.mdh = mdh_set(self.mdh, F_STATE,
                               S_SUCCESS if ok else S_FAILURE)
            return

        if st == S_READY:
            self._invalidate('ace.exec in State Ready')
        raise AssertionError(f'no Form D ace.exec defined in state {st}')

    def restrictl_algpolicy(self, mask):
        """`ace.restrictl` on _AlgorithmPolicy_: clearing the field is not
        admissible."""
        new = mdh_get(self.mdh, F_ALGPOLICY) & mask
        if new == 0:
            self._invalidate('ace.restrictl cleared AlgorithmPolicy')
        self.mdh = mdh_set(self.mdh, F_ALGPOLICY, new)


# ================================================================ tests

def t_sizes():
    print('\n-- Size table <<ACE-ML-DSA-sizes>> vs FIPS 204 --')
    for ps, want in ((44, (2560, 1312, 2420)), (65, (4032, 1952, 3309)),
                     (87, (4896, 2592, 4627))):
        chk(f'ML-DSA-{ps} (privkey, pubkey, signature)', D.sizes(ps) == want,
            str(want))
    # Internal-state bit sizes quoted by the spec.
    for ps, bits in ((44, (20480, 10496, 19360)), (65, (32256, 15616, 26472)),
                     (87, (39168, 20736, 37016))):
        chk(f'ML-DSA-{ps} field bit sizes quoted in the spec',
            tuple(8 * x for x in D.sizes(ps)) == bits)
    # Serialized Context arithmetic quoted by the spec.
    for ps, total, padded in ((44, 53280, 53376), (65, 77288, 77312),
                              (87, 99864, 99968)):
        sk, pk, sig = D.sizes(ps)
        got = 128 + 8 * (sk + pk + sig) + 8 + 2040 + 512 + 256
        pad = -got % 128
        chk(f'ML-DSA-{ps} Serialized Context before/after padding',
            got == total and got + pad == padded,
            f'{got} + {pad} = {got + pad} bits = {(got + pad) // 128} blocks')
    # The AuxInfo field has "the same format as the Algorithm and
    # AlgorithmPolicy Fields and the next two Reserved bits" -> 12 + 2 + 2 = 16.
    chk('_AuxInfo_ is 16 bits, matching Algorithm+AlgorithmPolicy+2 Reserved',
        (F_AUXINFO[0] - F_AUXINFO[1] + 1) == 16 and
        (F_ALGORITHM[0] - F_ALGORITHM[1] + 1) +
        (F_ALGPOLICY[0] - F_ALGPOLICY[1] + 1) + 2 == 16)


def t_keygen():
    print('\n-- ML-DSA.KeyGen (FIPS 204 Alg. 1/6) vs ACVP vectors --')
    for v in VECTORS['keyGen']:
        pk, sk = D.keygen_internal(bytes.fromhex(v['seed']), v['ps'])
        chk(f"KeyGen ML-DSA-{v['ps']}  {v['src']}",
            pk.hex() == v['pk'] and sk.hex() == v['sk'])
        chk(f"KeyGen ML-DSA-{v['ps']}: tr embedded in privkey = SHAKE256(pubkey, 64)",
            sk[64:128] == D.H(pk, 64))


def t_sign():
    print('\n-- ML-DSA.Sign_internal (FIPS 204 Alg. 7) vs ACVP vectors --')
    for v in VECTORS['sigGenMu']:
        rnd = bytes.fromhex(v['rnd'])
        sig = D.sign_internal_mu(bytes.fromhex(v['sk']), bytes.fromhex(v['mu']),
                                 rnd, v['ps'])
        mode = 'deterministic (rnd = 0)' if rnd == bytes(32) else 'hedged (rnd given)'
        chk(f"Sign_internal external-mu, {mode}  {v['src']}",
            sig is not None and sig.hex() == v['sig'])

    print('   the ACE external-mu convention against the FIPS 204 external '
          'interface vectors:')
    for v in VECTORS['sigGenCtx']:
        sk = bytes.fromhex(v['sk'])
        Mp = D.format_Mp(bytes.fromhex(v['ctx']), bytes.fromhex(v['msg']))
        mu = D.mu_external(sk[64:128], Mp)          # tr @ M'
        sig = D.sign_internal_mu(sk, mu, bytes(32), v['ps'])
        chk(f"mu = SHAKE256(tr @ 0x00 @ bin(|ctx|,8) @ ctx @ M, 64) reproduces "
            f"the pure-ML-DSA vector  {v['src']}",
            sig is not None and sig.hex() == v['sig'],
            f"ctxlen={len(v['ctx']) // 2}")


def t_verify():
    print('\n-- ML-DSA.Verify_internal (FIPS 204 Alg. 8) vs ACVP vectors --')
    for v in VECTORS['sigVerMu']:
        got = D.verify_internal_mu(bytes.fromhex(v['pk']), bytes.fromhex(v['mu']),
                                   bytes.fromhex(v['sig']), v['ps'])
        chk(f"Verify_internal external-mu  {v['src']}  ({v['reason']})",
            got == v['pass'], 'accepted' if got else 'rejected')


def t_state_machine():
    print('\n-- ACE state machine, flags and _AlgorithmUse_ accounting --')
    ps = 44
    kv = VECTORS['keyGen'][0]
    sk = bytes.fromhex(kv['sk'])
    pk = bytes.fromhex(kv['pk'])

    # GenerateKeyPair sets privkey, pubkey, tr and both flags
    cc = MLDSAContext(ps)
    chk('after provisioning: HasPrivKey = HasPubKey = false, State _Ready_',
        not cc.has_privkey and not cc.has_pubkey and cc.state == S_READY)
    cc.setst(S_GENKEYPAIR)
    cc.exec_d(xi=bytes.fromhex(kv['seed']))
    chk('GenerateKeyPair -> State _Success_, both flags set, keys match the vector',
        cc.state == S_SUCCESS and cc.has_privkey and cc.has_pubkey and
        cc.privkey == sk and cc.pubkey == pk, kv['src'])
    chk('GenerateKeyPair computes tr = SHAKE256(pubkey, 64) inside the unit',
        cc.tr == D.H(pk, 64))

    # pubkey_Output streams the public key; over-long transfer -> Invalid
    cc.setst(S_PK_OUT)
    chk('setst(_pubkey_Output_) zeroes _AlgorithmUse_', cc.alguse == 0)
    out = b''
    for n in (512, 512, 288):
        out += cc.exec_output(n)
    chk('_pubkey_Output_ streams the ACVP public key',
        out == pk and cc.alguse == 1312 * 8)
    try:
        cc.exec_output(16)
        chk('_pubkey_Output_ past the end -> Error State _Invalid_', False)
    except Invalidated:
        chk('_pubkey_Output_ past the end -> Error State _Invalid_',
            cc.state == S_INVALID)

    # Ready clears the volatile fields but not the keys or the flags
    cc = MLDSAContext(ps)
    cc.setst(S_GENKEYPAIR); cc.exec_d(xi=bytes.fromhex(kv['seed']))
    cc.setst(S_MU_IN); cc.exec_input(bytes(64))
    cc.setst(S_READY)
    chk('_Ready_ clears signature/ctxlen/ctx/mu/rnd but keeps privkey, pubkey '
        'and the two flags',
        cc.signature == b'' and cc.ctx == b'' and cc.ctxlen == 0 and
        cc.mu == b'' and cc.rnd == bytes(32) and
        cc.privkey == sk and cc.pubkey == pk and
        cc.has_privkey and cc.has_pubkey)

    # privkey_Input erases pubkey and HasPubKey
    cc.setst(S_SK_IN)
    chk('entering _privkey_Input_ clears HasPrivKey, erases pubkey and clears '
        'HasPubKey',
        not cc.has_privkey and not cc.has_pubkey and cc.pubkey == b'')
    off = 0
    for n in (1000, 1000, 560):
        cc.exec_input(sk[off:off + n]); off += n
    chk('privkey loaded in chunks; HasPrivKey set only when the value is complete',
        cc.privkey == sk and cc.has_privkey and cc.alguse == 2560 * 8)

    # excess bits of the last input transfer are ignored
    cc2 = MLDSAContext(ps)
    cc2.setst(S_SK_IN)
    cc2.exec_input(sk[:2048])
    took = cc2.exec_input(sk[2048:] + b'\x5A' * 100)
    chk('_privkey_Input_: bits in excess of the last transfer are ignored',
        took == 512 * 8 and cc2.privkey == sk and cc2.has_privkey)
    try:
        cc2.exec_input(b'\x00' * 8)
        chk('ace.exec with _AlgorithmUse_ >= n -> Error State _Invalid_', False)
    except Invalidated:
        chk('ace.exec with _AlgorithmUse_ >= n -> Error State _Invalid_',
            cc2.state == S_INVALID)

    # pubkey_Input does not disturb the private key
    cc.setst(S_PK_IN)
    chk('entering _pubkey_Input_ clears HasPubKey only',
        not cc.has_pubkey and cc.has_privkey and cc.privkey == sk)
    cc.exec_input(pk)
    chk('pubkey loaded; HasPubKey set on completion; privkey untouched',
        cc.has_pubkey and cc.pubkey == pk and cc.privkey == sk)

    # pubkey_Output with HasPubKey false -> Invalid
    cc3 = MLDSAContext(ps)
    try:
        cc3.setst(S_PK_OUT)
        chk('_pubkey_Output_ with HasPubKey false -> Error State _Invalid_', False)
    except Invalidated:
        chk('_pubkey_Output_ with HasPubKey false -> Error State _Invalid_',
            cc3.state == S_INVALID)

    # ctx_Input: Form B, ctxlen 0..255
    cc4 = MLDSAContext(ps)
    cc4.setst(S_CTX_IN, aux=0)
    chk('_ctx_Input_ with ctxlen = 0 is valid', cc4.state == S_CTX_IN)
    cc4.setst(S_CTX_IN, aux=255)
    cc4.exec_input(bytes(range(255)))
    chk('_ctx_Input_ with ctxlen = 255 loads the whole context',
        cc4.ctx == bytes(range(255)) and cc4.alguse == 255 * 8)
    for bad in (256, 1 << 16, -1):
        cc5 = MLDSAContext(ps)
        try:
            cc5.setst(S_CTX_IN, aux=bad)
            chk(f'_ctx_Input_ with ctxlen = {bad} -> Error State _Invalid_', False)
        except Invalidated:
            chk(f'_ctx_Input_ with ctxlen = {bad} -> Error State _Invalid_',
                cc5.state == S_INVALID)

    # AlgorithmPolicy
    try:
        MLDSAContext(ps, algpolicy=0)
        chk('provisioning with _AlgorithmPolicy_ = 0 -> Error State _Invalid_', False)
    except Invalidated:
        chk('provisioning with _AlgorithmPolicy_ = 0 -> Error State _Invalid_', True)
    cc6 = MLDSAContext(ps, algpolicy=0b11)
    cc6.restrictl_algpolicy(0b10)
    chk('ace.restrictl may narrow _AlgorithmPolicy_ to verify-only',
        mdh_get(cc6.mdh, F_ALGPOLICY) == 0b10)
    try:
        cc6.restrictl_algpolicy(0b00)
        chk('ace.restrictl clearing _AlgorithmPolicy_ -> Error State _Invalid_', False)
    except Invalidated:
        chk('ace.restrictl clearing _AlgorithmPolicy_ -> Error State _Invalid_',
            cc6.state == S_INVALID)


def t_tr_recompute_on_import():
    """m4/m15 (fixed): tr survives export/import of a verification-only CC.

    The Serialized Context carries tr only inside privkey, so a CC configured
    for verification only (pubkey loaded via _pubkey_Input_, tr via _tr_Input_)
    would lose it. The spec now says that on completing an import with
    HasPrivKey false the unit recomputes tr <- SHAKE256(pubkey, 64), so nothing
    has to be carried and no format change is needed.
    """
    print('\n-- tr across export/import of a verification-only CC (m15) --')
    kv = VECTORS['keyGen'][0]
    ps = kv['ps']
    sk, pk = bytes.fromhex(kv['sk']), bytes.fromhex(kv['pk'])
    sk_len = D.sizes(ps)[0]
    tr_expected = D.H(pk, 64)
    chk('tr = SHAKE256(pubkey, 64) equals the tr embedded in privkey',
        sk[64:128] == tr_expected)

    def complete_import(cc):
        """<<ACE-PQC-ML-DSA>>: on completing an import, if HasPrivKey is false
        the unit recomputes tr <- SHAKE256(pubkey, 64)."""
        if not cc.has_privkey:
            cc.tr = D.H(getattr(cc, 'pubkey', b''), 64)

    # A verification-only CC: public key only, no private key.
    cc = MLDSAContext(ps)
    cc.setst(S_PK_IN); cc.exec_input(pk)
    chk('verification-only CC: HasPubKey set, HasPrivKey clear',
        cc.has_pubkey and not cc.has_privkey)

    # The Serialized Context carries tr only inside privkey, which is absent
    # here, so nothing in the image holds tr.
    image_privkey = bytes(sk_len)
    chk('the serialized privkey field carries no tr when HasPrivKey is false',
        image_privkey[64:128] == bytes(64))

    # Without the recompute rule tr would be lost across the round trip ...
    imported = MLDSAContext(ps)
    imported.setst(S_PK_IN); imported.exec_input(pk)
    chk('without the rule, an imported verification-only CC has no tr',
        getattr(imported, 'tr', None) != tr_expected)
    # ... and with it, tr is recovered from the public key.
    complete_import(imported)
    chk('after import, tr is recomputed as SHAKE256(pubkey, 64)',
        imported.tr == tr_expected)

    # A signing CC keeps the tr embedded in its privkey; the rule does not fire.
    signing = MLDSAContext(ps)
    signing.setst(S_SK_IN); signing.exec_input(sk)
    complete_import(signing)
    chk('a signing CC keeps the tr embedded in its privkey across import',
        signing.has_privkey and signing.tr == tr_expected)


def t_compute_pubkey():
    print('\n-- State _compute_pubKey_ and the tr-consistency check --')
    ps = 44
    kv = VECTORS['keyGen'][0]
    sk, pk = bytes.fromhex(kv['sk']), bytes.fromhex(kv['pk'])

    cc = MLDSAContext(ps)
    try:
        cc.setst(S_COMPUTE_PK); cc.exec_d()
        chk('_compute_pubKey_ with HasPrivKey false -> Error State _Invalid_', False)
    except Invalidated:
        chk('_compute_pubKey_ with HasPrivKey false -> Error State _Invalid_',
            cc.state == S_INVALID)

    cc = MLDSAContext(ps)
    cc.setst(S_SK_IN); cc.exec_input(sk)
    cc.setst(S_COMPUTE_PK); cc.exec_d()
    chk('_compute_pubKey_ re-derives the ACVP public key from privkey alone',
        cc.pubkey == pk and cc.has_pubkey and cc.state == S_SUCCESS, kv['src'])

    bad = bytearray(sk)
    bad[64] ^= 0x01                    # corrupt tr inside privkey
    cc = MLDSAContext(ps)
    cc.setst(S_SK_IN); cc.exec_input(bytes(bad))
    try:
        cc.setst(S_COMPUTE_PK); cc.exec_d()
        chk('_compute_pubKey_ with corrupted tr in privkey -> Error State _Invalid_',
            False)
    except Invalidated:
        chk('_compute_pubKey_ with corrupted tr in privkey -> Error State _Invalid_',
            cc.state == S_INVALID)

    # a corrupted s1 also breaks the tr check, since pubkey then changes
    bad = bytearray(sk)
    bad[128] ^= 0x01
    cc = MLDSAContext(ps)
    cc.setst(S_SK_IN); cc.exec_input(bytes(bad))
    try:
        cc.setst(S_COMPUTE_PK); cc.exec_d()
        chk('_compute_pubKey_ with corrupted s1 in privkey -> Error State _Invalid_',
            False)
    except Invalidated:
        chk('_compute_pubKey_ with corrupted s1 in privkey -> Error State _Invalid_',
            cc.state == S_INVALID)


def t_sign_verify_flow():
    print('\n-- _Sign_Generate_ / _Sign_Verify_ flows --')
    ps = 44
    det = [v for v in VECTORS['sigGenMu'] if v['rnd'] == '00' * 32][0]
    hed = [v for v in VECTORS['sigGenMu'] if v['rnd'] != '00' * 32][0]

    # deterministic: Form B setst with Xs != 0
    cc = MLDSAContext(ps)
    cc.setst(S_SK_IN); cc.exec_input(bytes.fromhex(det['sk']))
    cc.setst(S_MU_IN); cc.exec_input(bytes.fromhex(det['mu']))
    cc.setst(S_SIGN_GEN, aux=1)
    chk('setst(_Sign_Generate_, Xs != 0) selects deterministic signing '
        '(rnd = zeros(256))', cc.rnd == bytes(32))
    cc.exec_d()
    chk(f"_Sign_Generate_ deterministic reproduces the ACVP signature  {det['src']}",
        cc.signature.hex() == det['sig'] and cc.state == S_SUCCESS)
    cc.setst(S_SIGN_OUT)
    out = b''
    while cc.alguse < D.sizes(ps)[2] * 8:
        n = min(1024, D.sizes(ps)[2] - cc.alguse // 8)
        out += cc.exec_output(n)
    chk('_Sign_Output_ streams the signature, _AlgorithmUse_ complete',
        out.hex() == det['sig'] and cc.alguse == 2420 * 8)

    # hedged: Form B setst with Xs = 0, rnd injected from the "RBG"
    cc = MLDSAContext(ps)
    cc.setst(S_SK_IN); cc.exec_input(bytes.fromhex(hed['sk']))
    cc.setst(S_MU_IN); cc.exec_input(bytes.fromhex(hed['mu']))
    cc.setst(S_SIGN_GEN, aux=0, rnd=bytes.fromhex(hed['rnd']))
    chk('setst(_Sign_Generate_, Xs = 0) selects hedged signing (rnd from the RBG)',
        cc.rnd == bytes.fromhex(hed['rnd']))
    cc.exec_d()
    chk(f"_Sign_Generate_ hedged with the vector rnd reproduces the ACVP "
        f"signature  {hed['src']}",
        cc.signature.hex() == hed['sig'] and cc.state == S_SUCCESS)
    chk('hedged and deterministic signatures over the same mu differ',
        D.sign_internal_mu(bytes.fromhex(hed['sk']), bytes.fromhex(hed['mu']),
                           bytes(32), ps).hex() != hed['sig'])

    # Sign_Generate with HasPrivKey false
    cc = MLDSAContext(ps)
    cc.setst(S_PK_IN); cc.exec_input(bytes.fromhex(VECTORS['keyGen'][0]['pk']))
    try:
        cc.setst(S_SIGN_GEN, aux=1)
        chk('_Sign_Generate_ with HasPrivKey false -> Error State _Invalid_', False)
    except Invalidated:
        chk('_Sign_Generate_ with HasPrivKey false -> Error State _Invalid_',
            cc.state == S_INVALID)

    # Sign_Verify flow over the ACVP verification vectors
    for v in VECTORS['sigVerMu']:
        cc = MLDSAContext(ps)
        cc.setst(S_PK_IN); cc.exec_input(bytes.fromhex(v['pk']))
        cc.setst(S_MU_IN); cc.exec_input(bytes.fromhex(v['mu']))
        cc.setst(S_SIGN_IN); cc.exec_input(bytes.fromhex(v['sig']))
        cc.setst(S_SIGN_VERIFY); cc.exec_d()
        want = S_SUCCESS if v['pass'] else S_FAILURE
        chk(f"_Sign_Verify_ {v['src']} ({v['reason']}) -> State "
            f"{'_Success_' if v['pass'] else '_Failure_'}",
            cc.state == want)

    # Sign_Verify with HasPubKey false
    cc = MLDSAContext(ps)
    cc.setst(S_SK_IN); cc.exec_input(bytes.fromhex(det['sk']))
    cc.setst(S_MU_IN); cc.exec_input(bytes.fromhex(det['mu']))
    cc.setst(S_SIGN_IN); cc.exec_input(bytes.fromhex(det['sig']))
    try:
        cc.setst(S_SIGN_VERIFY); cc.exec_d()
        chk('_Sign_Verify_ with HasPubKey false -> Error State _Invalid_', False)
    except Invalidated:
        chk('_Sign_Verify_ with HasPubKey false -> Error State _Invalid_',
            cc.state == S_INVALID)

    # sign -> verify round trip inside one CC (GenerateKeyPair, then both roles)
    cc = MLDSAContext(ps)
    cc.setst(S_GENKEYPAIR); cc.exec_d(xi=bytes([7] * 32))
    Mp = D.format_Mp(b'ACE', b'round trip')
    mu = D.mu_external(cc.tr, Mp)
    cc.setst(S_CTX_IN, aux=3); cc.exec_input(b'ACE')
    cc.setst(S_MU_IN); cc.exec_input(mu)
    cc.setst(S_SIGN_GEN, aux=1); cc.exec_d()
    sig = cc.signature
    cc.setst(S_SIGN_VERIFY); cc.exec_d()
    chk('sign -> verify round trip within one CC -> State _Success_',
        cc.state == S_SUCCESS and len(sig) == 2420)
    # a one-bit change of mu (i.e. of ctx, or of the message) must not verify
    cc.setst(S_MU_IN); cc.exec_input(bytes([mu[0] ^ 1]) + mu[1:])
    cc.setst(S_SIGN_IN); cc.exec_input(sig)
    cc.setst(S_SIGN_VERIFY); cc.exec_d()
    chk('verification under a different mu -> State _Failure_ (23, a VALID state)',
        cc.state == S_FAILURE)
    # determinism of the rejection loop
    cc2 = MLDSAContext(ps)
    cc2.setst(S_GENKEYPAIR); cc2.exec_d(xi=bytes([7] * 32))
    cc2.setst(S_MU_IN); cc2.exec_input(mu)
    cc2.setst(S_SIGN_GEN, aux=1); cc2.exec_d()
    chk('deterministic signing is reproducible (same rejection-loop trajectory)',
        cc2.signature == sig)


def _tamper_hint_padding(sig, ps):
    """Return a signature whose hint section is non-canonically encoded: a byte
    beyond the last declared index is non-zero.  FIPS 204 Algorithm 21 requires
    those bytes to be zero, so this signature must be rejected."""
    p = D.PARAMS[ps]
    omega, k = p['omega'], p['k']
    y = bytearray(sig[-(omega + k):])
    used = y[omega + k - 1]                # total number of declared indices
    assert used < omega - 1
    y[omega - 1] = 0xFF                    # padding byte, must be zero
    return sig[:-(omega + k)] + bytes(y), used


def t_hint_checks():
    print('\n-- FIPS 204 Algorithm 21 hint-decoding checks --')
    ps = 44
    p = D.PARAMS[ps]
    omega, k = p['omega'], p['k']
    v = VECTORS['sigVerMu'][0]
    assert v['pass']
    sig = bytes.fromhex(v['sig'])
    pk, mu = bytes.fromhex(v['pk']), bytes.fromhex(v['mu'])
    chk('reference signature verifies', D.verify_internal_mu(pk, mu, sig, ps))

    # declared hint count greater than omega
    y = bytearray(sig[-(omega + k):])
    y[omega + k - 1] = omega + 1
    over = sig[:-(omega + k)] + bytes(y)
    chk('signature declaring a hint count > omega is rejected (Algorithm 21)',
        D.hint_bit_unpack(bytes(y), omega, k) is None and
        D.verify_internal_mu(pk, mu, over, ps) is False, f'omega = {omega}')

    # non-monotone indices
    y = bytearray(sig[-(omega + k):])
    if y[omega] >= 2:
        y[0], y[1] = y[1], y[0]
        chk('signature with non-increasing hint indices is rejected (Algorithm 21)',
            D.hint_bit_unpack(bytes(y), omega, k) is None)
    else:
        _results.append(True)
        print('  PASS  (non-monotone case not constructible on this vector)')

    # non-canonical padding
    tampered, used = _tamper_hint_padding(sig, ps)
    chk('signature with a non-zero hint padding byte is rejected (Algorithm 21)',
        D.verify_internal_mu(pk, mu, tampered, ps) is False,
        f'{used} hint indices used of omega = {omega}')
    chk('an over-omega hint is not even encodable in a well-formed signature: '
        'HintBitPack has exactly omega index slots',
        len(D.hint_bit_pack([[0] * 256 for _ in range(k)], omega, k)) == omega + k)


def _verify_lenient(pk, mu, sig, ps):
    """Verify_internal with FIPS 204 Algorithm 21's malformed-hint checks removed
    (omega bound, monotone indices, zero padding).  Used only as the negative
    control: it must accept a signature that the conforming verifier rejects."""
    p = D.PARAMS[ps]
    omega, k, cl = p['omega'], p['k'], p['lam'] // 4
    c = D.bitlen(2 * p['gamma1'] - 1)
    off = cl + 32 * c * p['l']
    y = sig[off:off + omega + k]
    h = [[0] * 256 for _ in range(k)]
    index = 0
    for i in range(k):
        while index < y[omega + i]:            # no bound / ordering / padding check
            h[i][y[index]] = 1
            index += 1
    z = [D.bit_unpack(sig[cl + 32 * c * j: cl + 32 * c * (j + 1)],
                      p['gamma1'] - 1, p['gamma1']) for j in range(p['l'])]
    rho, t1 = D.pk_decode(pk, ps)
    A = D.expand_A(rho, ps)
    cc = D.sample_in_ball(sig[:cl], ps)
    t1s = [[(x << D.D) % D.Q for x in poly] for poly in t1]
    az = D.matvec(A, [D.ntt(x) for x in z])
    ct = [D.pmul(D.ntt(cc), D.ntt(x)) for x in t1s]
    wapp = [D.intt(D.psub(a, b)) for a, b in zip(az, ct)]
    w1 = [[D.use_hint(h[i][j], wapp[i][j], p['gamma2']) for j in range(256)]
          for i in range(k)]
    return (D.inf_norm(z) < p['gamma1'] - p['beta'] and
            sig[:cl] == D.H(mu + D.w1_encode(w1, ps), cl))


def t_negative_control():
    print('\n-- negative control --')
    print('KAT-EXPECT-FAIL: lenient hint decoder')
    ps = 44
    v = VECTORS['sigVerMu'][0]
    sig = bytes.fromhex(v['sig'])
    pk, mu = bytes.fromhex(v['pk']), bytes.fromhex(v['mu'])
    tampered, _ = _tamper_hint_padding(sig, ps)
    got = _verify_lenient(pk, mu, tampered, ps)
    chk('lenient hint decoder (Algorithm 21 omega/canonicity checks removed) '
        'must not accept the malformed signature', got is False)
    return _results.pop()


def main():
    print('ACE ML-DSA known-answer tests (FIPS 204, [[ACE-PQC-ML-DSA]])')
    t_sizes()
    t_keygen()
    t_sign()
    t_verify()
    t_state_machine()
    t_compute_pubkey()
    t_tr_recompute_on_import()
    t_sign_verify_flow()
    t_hint_checks()
    control_fired = not t_negative_control()
    print()
    ok = all(_results) and control_fired
    if not control_fired:
        print('  FAIL  negative control did not fire')
    print(f'{sum(_results)}/{len(_results)} checks passed; '
          f'negative control {"fired" if control_fired else "DID NOT FIRE"}')
    print('KAT-RESULT:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


# ---------------------------------------------------------------- vectors
# Official NIST ACVP-Server vectors; see the module docstring for provenance.
VECTORS = {
    'keyGen': [
        {
            'ps': 44,
            'src': 'keyGen tcId 1',
            'seed': '7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161',
            'pk':
                '0b89806f0eec39f2891116152ed4319d4260dfb8ac0710765bd497e6e1de17783cf81e435a412eabef5db3af5d15867b'
                'bb4c60f8cf98ba31bad6d41a5f8eb0c11b632c3f19d844a223c353bd182883dcf13b5c97823d0c0e6902db25ad8d344a'
                '37f59f4afaca5bc8874792da1e6a3eae742ab7034b20a4ab75a93bca4b68002dd242ced348920b7e5abf645a0e2e7961'
                '7bcb3ee7ba972b3e718d3effc59b1869814ba3f526927477b12bf25cbad8b04b09905fdad3820715a8b9a905de1cd65e'
                'ff6b0b0886305efb6cfeec9e90b5ef9a5aaec45c753298e8df9b017ce0fec9b7431b20775ce8cb11f1f42d1d9fe936d0'
                '803196e71addc26cc430cc3b69760c7ccafab7651e21baa28f92bbff1c4a6eef156d6f08f80b5e3b6fc943e6e984378b'
                '90888d09a6ea38b0ba86a3446211452e076dc9f65620014205d5271c7a44fec3cc5375eb246affc11b26cafb8b96cee3'
                'a68e31642e3d69b9130795f25ed818ebb211cd8be648adb5c8a120c8186017727fbcab31c7425c08fe9195de6bdbada5'
                '778d727ee5cde0674facb7ab81786357b529c71ddb24df770e8e95e5f3112bd297b352cb91b08ed1097a98e87bd7ce42'
                '35b8dd42292cd4c59d87c1f0ff00734aa22d7cae4361adc47742c897601048526702538828ba3c3a959990c0e99463fd'
                '22417e147ff2daa74c0c8d3a06e9703a2e160590086db8011a3d9cec5ae6348706f87cb2379632ce56e660a0ba1b30e3'
                '846c5b5c6c0339dd993e543a5322af5a11fc7040a2df23a0b43e882d7a0ff4431a723bbb918aff7f14bc045cbe94bcab'
                '27ae3109147b588665ef486006562b1297016efde787b46237060ee431e0f011166f916aa0789a7647103b7400a1cbcf'
                '0e22bd7b6dd2bb3ec51ec98f0ec6a5baa4cdc83f993d302f8fa849f2046b78aa32f0b3751885ecb941799e250e6546dc'
                'a5c20c24845190f239edc20dda77353d555de61509ca6d3c6dc3195bbc6f1703cb03ead5e7fcbcf5d196e9ab71522408'
                'e11d6337c74f9a31eb22ad084a19132bf72e7076a9743ed070aba78789791824e050cd27694c2648263d1200811fa1b8'
                '1a00b8fc09cb7a338795e54f6598d7753395f05c60e6eba9630912b7aa8caab3017565def72c7929f4e7736c2b8043fe'
                'b448801e2ded704e834294b69f6a109c0968214fdc5c3ff0d1b1555d617e16df61829231962c59b22a10fe400f8b8cb2'
                'a3f19fb4b2e8d087f22687506e7f0d061857d1c1789c7f55b899ff4b322982d64bd0aa751d5bee320b135c7f5ddcd5e6'
                '245b57dd22f44042f2ba6de942365a59fd0c6b0f20c07b71277c6ee7dd9d225032605aed1d3cf8242eb85c33a0afc3ab'
                '42764088d8f4a80faf804cd84360b2055181e58a0b5ad4c367abc667982045ad0fd7e048af8c326d5db60233302b107e'
                '515b15b0f90e5f348c54192b559b4c0a86cdf0719387ea3ff6b1d60b324a98963c56927e2b8dd5a39ac792aeb85ebdbd'
                '8dc34b395c2b4def4d853ac21a7660348ea8c96c943de0baff3aa6849179e5ef2baa1731c81c605bec3860fc4a6a08cc'
                '9f75bde9533511780ff1e0b01d34c0dc3eb80a7e2f52a7a4b815dda98ea775dfe0c5b3d419b05934dda05a9616c0978c'
                'c99cc8d7b68227bd846419d765956c3d7aa811ce60af22df322fef0dce38c4278e0237f1d29ef139e201c8ecb4d36e79'
                '910d06c5ca4caa8c2886b96de6edd40d2499e30eb942f22bebf6ed5c8e37df9557e74d67dc467baafa68f1ce37c8bd9b'
                '3a4f9de71670128125aa16aca7232239575e1c6819c820ad16832f23647dd53c5740a8552f86901aa4f883efd5a3efd7'
                'c3bf458c5122712d44be43306c9b8264',
            'sk':
                '0b89806f0eec39f2891116152ed4319d4260dfb8ac0710765bd497e6e1de17786cdec899f1c6534284585dda4df03e45'
                'e4d39b4526015a7b3d65f8bf875452560db3223594a1fce8db48c8f1793611a17fcc0006ffea26cf7094d8325037288f'
                '8af7d062833b71b8c0f06108442786e3de59d649162273ef179aeadbbd48cc981ca86463082a0020220cc10003b160c0'
                'b82c20a70409c521649820e3a84409c689832621e20832c1b04c1c8911429420193789c12462e4c661643600d8484a09'
                '98601902621b104cc2a4495a1600444690a3800cd3889098a49024c3901a344d594052614411248101c416261308881c'
                '818083a86142200d23262a1b2501d0422464c4911315094092641b071208956c513830a20831cbb84153240e99c41111'
                'a1241a297003a74011b744a2442ddac0041c21611222684b126821c3104082600a2352c43890cc967063206553486d84'
                '124c0239328a0640112689e49841114871d22652e3c2240a98889802891b8031e4089140b404534286411826d102929c'
                '946180c84801134118348509b76984180d0a404ae2340e0181809c04662481299aa424a2b8445c38491ac20dd9b045a2'
                '86491c864011036c13b78044b2618498700a1989a00024e1c2488cb09063b8100a408c18171009b76c1108249136404b'
                'c29104a96901b525044802c300319c380e0a26229cc4841a04306184201a1300a1940460982912924d12144ae1068d80'
                'b62d1aa5855c240849a20401b56880b449d9b21163240a98424414b40401264282008c0b04651b21409a488494866d18'
                'b380c4a801020326cc44491922208a364264048d1205814ab20401426a5886201034110039295a98654138080cc964d3'
                '849021a788e0088901386012222859488290c20c538430823626818051a4c871819431e0386ed3a22121186e8b027151'
                '240ed13689903408a3480a0b34894c040608314c81280400894503920d010208e0c011d1041288482e01280e08c161c1'
                '1820c4c84800242a24c545d80020c8368498c885d4b40cc3062942b00d98487002a7899b303152284e10860c23b12490'
                '1829c2c84462b269431824098621d2062989020a1ca76023c00448426ca4902ce09681c2c66d23286c40206a4404210c'
                '3405c980814b0892a0162151b001c1148d413849dc968c212244c4a00d18049240083209126a00177109118114962402'
                'c22d109591a1084d0b316c01466aca8291ca1252d3b23018094d44c4845490411fb45680a1b2685ff6f4075d76e422ee'
                '9b1dd39048a2c6b0c1c441689316aee550c179a8e55b87627071ed299fcbfacfd13cfbe61a9f87be0579a19357c4e7b0'
                'f125d354dcec0ca0eaeb5e116fbd87efb3049ade6f28921d56ed84487cad51bd84f7c07ff460b09b4201e7b9df1801da'
                '2771c2da20d2b687a44d4d1f49da38bcf9ae30713acd86e32f52fa8735dcdedf1cda4a5c2c8880784a5b7c3ac395ff8c'
                '4bd1a0303868cd3e6d1f7ef258f38f5cf560ab9e8357272222123821d25c141258a6b132f9f99d014584bfe23ad4957f'
                '6692cd7e8327cf66e581a598c4ff3c7cbf5316b3ab028ff82e8bc3250f250e6a451996bfaa00a1458a86f8304f2a839d'
                'd1b929eae4e53e919aea13ba09569b14148ece44cb27650eae5fb352061c7301d8dd9cb5156bc15de1f578ad95d6505c'
                'cfd485d99867d48bc6910a491856d30b17fd8952b774a70f57a24458cd9b18d0a222bc5b307a34ee347106a9b7660950'
                '5e7c81495f88d8da05d742188f01820ebb8ac559ff3417a33e6cd4fda1d60c1a6d37c3d27f51717645adee9020f10748'
                'f7cdb0d5b142f465c54fe5d70cb787eb47b8741a162bf373afa1c8db3985900c6a8b9035006cedb7eb9854d3c50e1c30'
                'c8a6b34269d85d7c683edb1be1455ece1c9768ea9c9a140036e8ead9a19d9f167e52ca10da5fa7fe2bed7c0adb0a45c6'
                '42ac02ecb5b1c5199ad5d6227cb4f506a973d696908c15791513783736fffe5a47395ce2e7ce1c42e7f6541825a2bde5'
                '617f53b5155ac30e3ec43bb4ef5ad727ace5a5adcc7f036a1bb606f7c943c112b372db92832639db2f488a3ed64e4360'
                '9dd93b43f38db939f6bae61e3e44772929e65f43d739a061ae3272021a220387a43be3a985ad713999f75e040df53da8'
                '1801bf165052a68179e6bb1fd4f624c31edab74f6e2e7efc31eda78103bfcb32b837ba07c5d37e922440de741be0029b'
                'e98dc86739324d73e62b3fd09b9ee00ef8dbcfd0ed687c5269bf3a4f84afe2b8fb52bbd118e718df5972038cdab018cf'
                '8ac7d6785c958ac5b9b23785de1a90b9be64279015fce8c36c87453e392da20cc72c533d115bc0f53a385a0df6127b3a'
                '81592552b7cf0e8af3797869683ff0c42d2a189c04442966b37ca321a4dbf02067447d50d09f92e4e63a272a97e0460f'
                'f1bfbf82f61412bbbdeae83d0843f5b38e10a53dc5ca86a4c6aeb17601fb560a8852bc60c25767c2489f95143fcf75b6'
                '48e814374ba98dfa753d08a53f02377f551c9aa374301ce7c84b1a48e6f750794e5386361815155053175db12e29ef9d'
                '49920d7704cc343da6021249479e5e5405f3bede4dbd612009c34e659c3c9d7c59da97d104f47d4b314d1c0e2414f874'
                '6ca658a9731c18a0c89f61e11f617b197093addefa42ca0df723f93a12ed83c352b05f8f5039b2c8d321c4992d0df249'
                'bc5148e0c27519430a9e70a5cc24b8e0217d6f9bd04737a4fcf7351c7670269dad9da97858a1fa9da23dfab215172bff'
                '72962f62406d2c5747ca0f273ef8f31761f99caf2f417685f971c3415fd1c79d7a4e75ec50a6b7b795a35bc45edaa824'
                'ee71e651830c96ac2905c1eaf817b8e833c9be77242a6b43fffbc108dac12631ebc86bc06bd7e506f827b142f0347635'
                '7c9ae5b98b447dbe0f408c75535fd9341fa3693f2887face3b72cecfd62cbf908319a22336ac43e57e2a46c42b28b6e5'
                '5d7075b5cfed7d8c0a8a1a4adaae79b4a09b7ccfc04fd99febe3a0de1f8a9b43f97a2f93cd758ad546c0a1c3801e3bcf'
                'e1adc246e7a34044cf56bfbdf5a5035c2b8d1e19a3a7243c225be23eba7fff8e052c3845310f4b2b7393bdc15b766ba0'
                'b3cb45bd0a1cc693c947a5a964dd39287828ee86eb6c2db9d8967edf4b75c78ef4b34561ea1a9d93bb8e1209381e9d1f'
                '2c0e61edbab542e07e2c3c71f4841a3f2117f26b608ca244c46663c3fbd6a6a20f55c8c778c585bac5dbefde74a7efa8'
                '658d95b12ee9412bc8cc24333bb2a3e994e887a8140fe482edfeca89e887531a536bc13fc44af7b595b06e6b122e59a3'
                '24992c553d6278af277e5c545b126105d1a180d2cf769abbcd9b8db72330e6548521ff4569c674e60d35923b86f0166c'
                'd24d8ac7fa4f49743e7e2c90bcf3e66955c6f5ca430024902c536d0e0f5d3a637c033a3ba6f9778475c455e440a5e03b'
                '485f7c8263f5d007a8a1b3def7ae943dd38633715b50a2e76228521eb1d0caaeab48951c1e395df94f9a63313dbccf1a'
                '6be8c0954388aebb0ae472e741a8006dc0299f5e4073e89a3d097512321ba8037c391cbee65977354b3739cb04fae766'
                '3d86e9ce04bef14d3615b9df81aea3e4',
        },
        {
            'ps': 65,
            'src': 'keyGen tcId 26',
            'seed': 'a991fd42b071d49c48ae3e75c647459e0daad1e1ba356a04801912d3294bcff8',
            'pk':
                '36db0b5dce98bd190cb139e80b71b49c7d7040b71c5a1f3412c46bde939192b1b57ccb88ac2714c1240cb0eb62c689e0'
                '31aea3d9f3eb3ed7bfa45931d288dcae3413199b31a7032560dce8a61e195d13a1440615c2f3aa7dd28c5b1b742bfa40'
                '0052186721f13d3df9dcfaee348b10d66913c7148913e085e1a4a03c659398dadc6a8e0e0c1a7f9f44d30436db90fd65'
                'a6ab8f36137338255653baae8da21526a333426dbd9f76cce0f43212643e854d772018b35ce726bcaaa5ab0651baf8c1'
                '22e13929bb35b6e4963df2595fdc7237cdaa7234bf776b07f353ccdba12ad3e025138e3492d7f8e929db55dc23e23075'
                'f66d57a10492e6a10ae7b758acc2291ca18ba1ca07a5b574ab6d8aac18b9524990ad2f110225b7d82f696300a660a166'
                'ad35b3c57ecbab77117c79656fa8ae2a19a7defb2afd2af54683d043be0f933b8eae0d591448ed55d00068cd9fe10b06'
                '7fcfaac53aedb1e9b667e36c4e30231f85c7aa0a474af2fa4776226f4479555e155528d78b98183cbdf7fae4e7301140'
                'f163eb71e991d15fad4a0d2f25a5a62fa2e9bcc823cc2927662e40c538213ded9e2df508e911e4924e507a50861fbb05'
                '0edbbf56d937206f8fbc6f4cead4cd10d06b73aadcd4aa39703a7a2bffae68b7baa47341b699da9f3b167d4d90efee0a'
                '07ee3529a3b5e8648b9cb07ee973e1d8dccf1d16e95092c4a0184ccb4902d6086d9f444aca5fa45f43ca91b351e82585'
                '989ffcbd6d2c3471d6b8593aa46f29d0dd9b44e8aa4d8f9a0bc886bb7982c56aab11e23bfdbd8bc674732fadacacae25'
                'fa416b2d0cc7743827293336507da4b14c1f0aa2e929af975466dadc89a016f33a0cca2d5c08114cf04b02358805a772'
                '536432c44dbe9886130d2d3a0ffa0e175875a2207686f5e562b879eb2957573ab706b942468c20cc69bc566d29d9f151'
                'f3cfae71cc97ce4a30722d4679fc1c089b5009935931ee60aac5496b0fd5f24e514c0e20fa1dcc7729184a50fc85fad1'
                'd2f32f715fbf55666e49f5a19761f2dd1aa5d1a33c7916eb6a794981c0334176abc493ef30d9eaeaad42e705989dcfcd'
                'eb578529a700bd14076a348a2062d6483cc63cd7f55136587aac0e531a06eb2de74e61cfcbbce18f2ada5a741f683bf1'
                '01f71432ee659dd1508e0c8fb2400e0ccbe435da3466d543d3ef5ba369e125c0b84d855efe6d4a22ff929a7a7a984e44'
                '8d23871e09b88a0bc3f3b7da55dd2edfb5a6daa102819ff50cd4dccd0a95d2f27354668065d4a56c31fb18b92b2a8db2'
                'c6453baa9333aea6eabb1bd6411d584dd5900262057a707f81cc5137dbdd9ac1079bb98da78a8e4bd1b2e0546c2b3d95'
                '6fcc280d37d855e31f1e4315b387a742280f057f3219eae512884ae7ec4d2e3a72265b1d0163fbcbf616b2e289b0eaf9'
                'c63437d50b7b50ce408f5b4562f2abf510c19f5e8a0ace264db6e0f2a69a7d0b4a5e62a2b964f08c8ffe9c295f5773bd'
                'd7fab054a13822d428fae28ae5e4adc9d9f6e4dffc457a3e49f0bcf62b32961c4667b60960452afd917fdd00d954fa30'
                'c8533e5629f90af85948dc1bad889f91832ddf9b738254c9e7939726c37ab4557c2ce363c1391816c467537b471e5985'
                'e8084c277b62be514922d352e20689eabb3eb91c343f36e77b152d5e85afd088f4d02e7024b248a7420f58c7ebbeb480'
                'cae39b56164f5acd37a4f56b3db6e1cc6b7c8c96cd3c44a69d9ac99175257bab7fd83c5b574b5c9702c0fd13a5b176c6'
                '0f82d2dfff50c2af25d96e0f8d27ec818d499e479b9642aed4a4a0e6af5f14cc5e1299eabae055ef3c763d1e350e2d76'
                'e92cee47a4233368466a298afb4ca108a325d2a4f8b79f21ee7349c1c186ecd7897f9886cf27ec01b05388870484867f'
                '84bae2c016d04a3762241907c4de207798dd125a2cebb6c2982f779e04117bdd65cd7ff0361a59d3ec05f6d903b6d155'
                '54beefb6d40d96a0d4b37ae76c69c1b9592088b7db878f95abedcb5fd5423ed93df1b27d01a4dc9f4438e7c55f35b0ae'
                'b7395b08e1ecbf15cb2b61d043c0454aeaef2d487093fa0d7de3fc6caf084b6a0f15a5cb05d9340d4e6763983dc45b78'
                '28539c77a60d5e081a03fe29949d916392b6d989b4c8c047e3635a76ba88ac18a7a18ccff5c7e06b02a43d2dff169fa4'
                '49739e382bd020e0963c14a9acae6b6561c722d2bda183f33ee6a904df0207f5b098e56335cc063f9640c4997f593218'
                'd502f6b382354c73979e93c4b1b2471965ffa5a0dc8ee8eca9f5697e7ef08dc0eefd9ad75cd4122194b450201dfd73cd'
                'a46a7b2478df66129fbb9c75b774213f9615bd990f8d07501fed440fd25d6cb912b8ecfa678d887a4ee28677e6e0491d'
                '49efc7a3b34b9815c5c22983da280d0afde2324f5281bc8b796ddacfd82723bbd9aa34b0c96075b36848591e47b80086'
                '897846fa76d092bc8bc6200837bfb5545039f8602b7ea49f63c0c3b8317eeeb7612f8e818dde09e43c7da76fd2ff6847'
                '906a45da3d993e8eaed9fb3b1e579d8cc6900c89522aaeb0b4a80da1e66ab8dfd62dfe4e4d77a3a77e5bd669207c70aa'
                '8537dd6d80a647b0420d79531a7456052c3c989f0f08de3d343c40067680b39ece95a17aac8a622d1d5d95b38ca0f11d'
                '94e5b0a7634eef4055517ace79f0df1d7c172e0246abb2ab6b135ee1a38a3b84f86fd7c3caf178cd4446d0b554256ad4'
                '5c657e1192070aba7df480f489ebdf9753a79ccbc6aa893913c5f1271f1c6035',
            'sk':
                '36db0b5dce98bd190cb139e80b71b49c7d7040b71c5a1f3412c46bde939192b133824e8fa472bead7a4d3bf6ddc323bb'
                '37e0d8d50854522dbbff2890d5fd9736ec39b00c9031e14e972d23b06640342d1a78fa5df0ef12aa3236a50ac6e7bd8f'
                'b80c402ec98f22a4e2bb6e9e26e516e7e01baad986920061e5dad927e4e0061a38666060156372310560633654877625'
                '855268876758784874776382362803648170563705826256260401508556012810214153756583600818140032383441'
                '328634100877541203088254485055836358614834885227814501155307240372884521806455328513764258115780'
                '327860321688361770522717831002015568734052858558406872611417841144106558087511307421731832678013'
                '258838300464802830058525115710771261114132733383055817278253231538114401046520512222102263834200'
                '423403223080561663528280432472786114635853020278472335625684280331663454430030658802100473653673'
                '151607487300108657347383052322225237528207116256157670424353153145030413751646603661214051806248'
                '020711643342306257186528335186225218544413533582231213525403003884842525367620438555288824001607'
                '485232783717741118741354361414402733103853408555860321871043814750575711827802227315653485343875'
                '710467246738882546043543855083080430282058732045704011804321635757342405317686067152144268333256'
                '345207637637235187404651451775152571283672522257103688108753414113012583484542327610483628677732'
                '603831803817381623350555154820418653812333341858783545874513370647810245544438876776736326520738'
                '660184257576264377082283757203448301444647132141601635034614530877712773851665322470653301675881'
                '500543625584646183630126671701480452551555058525274576050551860315386456542186027874178817246402'
                '477124543028180757130487576727212634322748147100433210537070373230765504006074277254603047543701'
                '648741746601128135410573316811526010541038668537110653478086758672806450766615078445846174313508'
                '015067357056555885577630387707221373063544342257261483567481454484053376745013671557433231214307'
                '772376013751318427818225416377376848661360335628748060774546523433445233766888652078373682614606'
                '631740857158814862777711050306633075165608653706051411514275756265573058341816010106766111403755'
                '853584073276051307776288454280750770428800472125743878275027313876630763640114007116253714778431'
                '004564421140082550624811810222704872353806610137347003641443465741172010046646240343831024614078'
                '551522446541143850243373240322076288182031358377640285255046226460605463215036041416383117776727'
                '362517361164854821555867260051557415012572145606674360873338106042100007682483287167536627131018'
                '225236128406134024682656151336520470732506077575680233572765612807174021601183080416012282571281'
                '064306113438830160857044720438830820275448288774068387441754387403211030255878682686008544658107'
                '765685734880810688346262046715611520014375240508187301161088674263506187325857682717333546057578'
                '728400025651847664807045861663333686304165386337683480047070411064572321847327327230566250676686'
                '046413022615204145886706164027674466378102136347247845000511711748548511105036378151613146550840'
                '241110514002674615625472843567658436607278565431725436185103168273127363883415138642804547008533'
                '333758214316154200438004228865634564703881255470227718801885502868336880235274121112504338201453'
                '08e4ee45b2c9ca523459c49bf1604acbacca7fec3ed15fbd497eea72b009e7ead6eeff7dad65c246dc26dcbb2973bd2d'
                '305993e843581c4b2a4ff45acc882cbae751e63e925f84ea3fdf722fbbd9ae92f18cc4b26f188bb6b425449770453104'
                '1139ac623381b1117f51deb204938c82b278e01ae4969eb587e51e5ccacd12f60e4aa2b5367a2cb34d2d442c4e124a3b'
                'a2cba083fae8ce72f39c7513d80574a06c02383451e653da50c2fe71dcbe1609cab5f6f0d1b7aaf21844466fa1af79c6'
                '71216792fcc2018e633ef173fb4cf7e767e1705db9939ea2c185dc3aec7bed66ee13cd8814d790287ccbf859eb646e58'
                'ebeba9d081f811b653a25c8fad64dd6fcbd6290e8f55320c51474e18882bca350a33768b9db737ffd1b7ca5baf257952'
                '6438cb086a6c9abc3fd387907a6d35cca79f6f1c9801709ea1d02dce59676e8c002e464a660f9e410e81e75a62f59a80'
                'e95c058ee950bf0804c5e8a0ada205d71ec2e6e4f929ab17b47708ba00e4bf64452bee8483fbb68627d57475d8692254'
                '7b7cceb7f7a7eff98f46fd6451346e1314f8f694ba16c27234eec848fb7edb442d845e55825ab01b829de26f76c275d5'
                '609be4c36212f9837cceb4628ca7899f214c9b06e7db5eb9bc24522475de460994a89c583a9d3c885c9b74c7d6271b87'
                '02778e84df19f13015655c9d06804bb1237a17a93e19bd46232faff39d6e1a6ace3495022c265638fc97b59b86a38eaa'
                '8f8a03bbcafa35eed6576d109396203e19dcf1d151836cc7bf46c818b9959a53f0502464ba199f400e412b30902264f1'
                'e4909f52f2031d9ea8396c2f735a2da81a389a792031418f2bf73a767f42db0ee14fe1cbea5a99b5b95c6137fa4621de'
                'f9b4f6069ca4709242d15c797cdbb71ee507b22fbe95825da5aa4d9beaadc3c898ab122629ea717c6934e5a4170de7ee'
                'b5d608684da36a318f18e559f1dc9d18104271913efb0ee8cd2379ff1b31c575c71d90a54e61185e1399e1ad710b4e96'
                '0a7b41c88ce2f4889b0b2c7b3c208a1f14d750db138fce86fadd7072296155022ab24665c95a7719e92a1cf9faef424f'
                '90e945c905d7908013a0e0a5b9c7819bec35b06dad1a146e75d345de5d18565a1d30c862c122ba4e87cf21cc63b87347'
                'b3ed90015edc1b5d3125956bfad93335495a74107b8af62b50b4c56b48e2a3293f56dc7cbc09f2f6fbde9a96caaa2787'
                '892e3d04238d9f988125d8bee2eb6299ec5c678afe42d3441bf6e4b22eb6975e6dec06aa507aa7c787d70eb97b60db05'
                '6d658f7404fa409939b8f4a321b7722f0fca1404e79ffcd87d2a6ee13d508b6a193af891e587e4f0e502d68784c55e96'
                '62b0905d912bda6c678d14e5424781e0e86fb2be43d7618da355cde8617f7254870f84e4641e7e16fdf3b6db86b60bd8'
                '73e8d432b95f53c4119dec7a711cc8f2bf901e38b692a54e7ed9d8a2dbc4cf5f271f4bb1a4678e6a19f370486984045a'
                '1b4f8521c9a6f811d49bf7c182e8175f75cc1421486abd75130329ec1c87594055a2f0773ebb3ce3dfe073de8955f15e'
                'a3c10d75b6f67ac2d639c3575e7c0bcec031f902e90235ba405da6b2570ec9a0635af9a3eb05caff00ab4767df1c5b0c'
                '01df45569d2f11c58061c848fa8d94ca4e9671ff94a440fba63956ebd924e2eaa2a2ca5e21fa24ecce4a1b82cec6f55e'
                '5e2e6b1c2416e4cd1c2fa0dec1b07c6e415a75075662cb6ffae761ab7fe771ea54bc5f4a53acc7b64a545a2562795005'
                '7f336b9751fcce479820bcc2cb25a92781af13ce3572a0cf0d946798d44bfe0bfb5bab4786e6e024971a1ff320b8c931'
                '329f8fd12e17e794058a809d849b333cd98d66fbbc18c216d0f01acda3e50f712691099336897d449ac15e77ba6fd29c'
                '6042d50ecddea4e9d578e2054b56b2645c97990b87251ad09b76f029dab7498404c9294acf6535e65b74d0bf345dfac9'
                '5fe020308a931bce8635c78a2fc0f67910c63633e5fe9004846ed9efc411235028eabdbd4ff10788fbb081ab51187f30'
                '020091486241900da3badc323aff56db7be0da078c69e535422e04ffd8ea8661c559bc311bd8d26ea8486832d839536f'
                '59b79e1d0443b938dd621758cb2ebbf41f87290590042913c761650481aff1ed1f5a3e10b4c9d2b198df8f2ef9fa7eb5'
                '3fbab3e04450678770fcec45ed3b78591e9f643a53702c404a1ea13638455e43427a807607f7091e4fd7e3fd29901026'
                'ca4c724c1cbd2cc4c9f50ab48d02c451ecdb5e8e9020d214f3dad92a6321f0c2b25c4d20fe09e10a4bc26b578c09e288'
                'a0796f97c04c45370ad42e1b920671355a6dff3a10c3c9ea96f569a90e9380f5ee4a91eed1cbb644d890f0d755425ab1'
                '6a92687d6e194b17374c4ccbbf924043bcf84cc6956835de8a2a42e91e139169ec1b54ad1b7c0fb1488c8e98ae3eb2d5'
                'aca80e1790c49efcb98e50fe03ef3ed2040d10dab1b3b69da0a903efb56686199ac2863cd04032a78290aac30e600fb8'
                'e1dafbc8f54f0e485bb47212a46eb81505890c67905d6900572f1693cf75e2143872b420c0348ad08ce8ba2f3fdac849'
                '26b9e8fa40231e6ee7be6ce6f115a62a57825ecdd19670fe5c236477245701d30208099c4430f053c46911eb51e94819'
                'f59404c90f7282e149e60321921d0d197f8a73e1d7bad4f63659add3bbffb5c2b71a4c3a9a0ce5add6dc9181c31a040b'
                '1d143891663d0361255bdceb5a6ef9a414abce158030f8664b1c42242adbab2112eaf420699d1ec1fa2bfc9ecca599f4'
                'a1795f7cf8593057c835127700a6703c6786bb75f1002dadb09cd7097e5ff978000115fa6278b912258e945e37461d00'
                'd9d5827c231a76b47fa58f68a363705e3b8109d364c89e510d84367d2092c501399250f482719f9c5f9d68c7896650aa'
                '91ddd17d0fa75160a2586c5f6846e411d7ce9d040114360fd948705fb60ff93c6c1320240dfdd132360c5b8f99384db7'
                'e9147fd93d0d745a763a48a76ea7e9e06aa0bac02ccf341fa505354606750d3d4f60b28fff171f5b656c231640d82498'
                'bdfb874773274ca568ce2b2b824ce5793b86ef02aa7cee6a027f27c89be27c519c0bb356359a98a1c011551cc106a78e'
                '6d675ce68fca86af5f6f28b9dbf9b464a26836a328f6aad6b01243e7be9ee2bb6db1fcc2e8b52cd64ac5d62000976a78'
                'be4948f36513c48c8bcc0205dcbfa3f7f1018986a2734205690e26485e24188f6ea5be3eb5e13bce8bb2e748943d7bb0'
                'e30125011e074adf4aba8f1c24962372bcda4622794d3c04fd99f5428eb2f45c829048e117cf5e3e53c881a8b3eb740b'
                '5be99c6aa7cafd7b5190a19fa4117ee8b0c9d1e501db54c1c65c30e62e7787987722ac90708adfe64784fe5d89c07fc5'
                '9e01ebc02ef6e3fb86f44403a25ac4a276ab8a639867e9c13a3e7cb127743e5de2695ac25ad2bcd8036bc601d663eea1'
                '7fbc26958671a116ec5055c53ea1ad7cd5f0685b20ba2bfdd699b83b9866190fc9364d34e3ec342ae3881b934047d577',
        },
        {
            'ps': 87,
            'src': 'keyGen tcId 51',
            'seed': 'a16f5b0796703e2d1a0140a35cbf36efabe70e752ba59b6a9a0e9c4b05302f73',
            'pk':
                'a5787e8044248f3f85aac54e9469fc98f1b1138cc127b120f9946c80b96e3d89ccfe38c995645d4b6a559eacb2afb816'
                '21d765c6e42e73031d44cbe74d322c7b16249576eb4c500253538d1a2c6b408e681b93b9014e3147dfbecf9d9858f7e8'
                '635f8598ba6847127d216a888ffb1636cc761616a0389c39a4245695dde0c86ccf8a3bc5a50ea6fdbcc0a34457d4defe'
                '35f775c5993685aef2237c31912a619ff804afe8ac3418c13502820aee5249d6e577ee0b2a5e3e8da2dd30f514a076b5'
                '0556d7581ba1f9b2e4671756a63065c20ebda6ee2c33c9d97ab14c5f2204fc5359adb2bdaa3aab7ae1dacff18a67d801'
                'bcb8f054bbc444f0fd0001a7908ebdcdf2b84f3c026eec1282498d31ac33ae6a309acab17b70dc9f0efbe52648d1ad2a'
                '4cd5964dc619b66cdc9d35eda7a3dc21c729b9929024db8b852dfdf102a086845702fd249ee43b54d2d033aba95110c4'
                'f0a66eeaee78f3c41d5d792a37d1d2299252a5498a44ca354f6f37fdc2f3b72b1a8378a5ba8b4997556e5a6f4125ad94'
                '6bd4fc402c4320b27111bc204b8b5448f43f7e77a8166a48137d85584befe2d9c85cccd9bbf3f8a4e05930180afdd697'
                'da82ed9f1069150ffc76578c941cdbcc5bd2ecb7d6abf9e68327df51c26c8b42cb1dd8bda98a82c4c6ba6a991e651bdf'
                'f68f0a62d5dbfea020d4303e0c53d474cb11d553c5bee1156917d72ac2a6ccc4ec1c775d41ee660e2485a45af5a7ca08'
                '3dddcc3ee4fffc5e77ba97cc4473303c77d8b6fdb35e2a20627bebbe327dd2d1ad1f880ca8eae1e0067a9093929e5ab1'
                '8d406a518edd8c1e0f0ab07736f55fcecf4a3b2adce1ce3e080b58ddf85a2262d0803a7e5b4e485e642ba533e2ec7a43'
                'f9e8db20f75292adac704395469408c15641a9c28b83e8c1c799fae0652f51369978f4c089fe15dd78c5f560cd28f5f7'
                '5fe0a39a60a61aef6c7d802141e9809e7aca68a38be9bdf5312258704f8b11af4262220cb55641fe95df83ec9f786d6e'
                '69202c91ec4caa4e38a21c3cc609c28b8f65552fe8334850858bbb30b837d874867ead330a1f5b4d7f6bec4748be54a7'
                '82d5b21a192bc00a7f2240fbd900460785d1971a94c587493d21cda249676edac6c865147e269488b9ca78faefdc778f'
                'f60e79735dd5539879182424b054fae8a9e153bffd6957c533aedc105e43ad7626312c8d229327d3e72aa9644bf3e2c9'
                'a08abf807cf3a472c7daf0ac4290a9e8f88d07ae8fedb8a4b218c3ebbdbe53882781f2de034b17fefe69302b4975cf43'
                'e03645dc53bd355af988b3a3d2431bf9d9a865750051eed7baefd1bad4939c7ec293509a5851a145f79dcbeefd195571'
                'ac2172ac6036812b4dc8040d186b8984cf9dc24f8f765166c6b2e8389dd24ed63cee951442861669bda0622bd90b041d'
                'c477c01a0d95d547e07a892ce1f26275abc6f97702e03b776e2ca71e3d0ebb88d1adf591122e6f0ec95a6cfbb976ae64'
                'bd0c7f074cb6e78e644dee8200e2d626435907b9134000dbc3b50271f5a8f254d2cf02da039d458e80fa13a33567aa9b'
                '374b47b799d0ff1a14ca92a50efa192ea1641fe29a380e11386528b7248d6de6aa90e1c9744713b768264b72a13ccaa9'
                '4f3e19ada5129e0d8155ec1b267e2cdc7f0e7a08f203d9a18f8c8d18529709ef746a21d5fec36eb547a2fd4490092ad0'
                'f06c55ee0a1cb104e2c3c3cf2bcbcbffeaec744a13e37310962ce40e072e7ecae223943a03002077d3d96c7b4c3fb1e2'
                'c9ee9c5222a63252f26372bc2bd94507ce5728ceb7a0aa33527e0662b4561d1bd255806450772eabb7ed40f787a2e3c6'
                '64fa6bc3be9bcd84fc7b42f16f94cc56cfb67297e475177e19e51010cfb74ba996ba1c3d793ea010c99901e2223b375e'
                '364ba193772b329d5d05aed959ebb924b698f0657af43eee8e0d54d15c93511209aaa9e10251bf81ad8b467d8faee2a4'
                '40782c372f55a62cfef408803e4b3bd8efb94061eab525bd31957779b89eb1c75ab97f278b3eaf99a05686e04873d7a6'
                '85868d1c0f4510adab0b267fe4d3cb70c35b295afc671b60c6575b60eeb99756e7b204a24d7095df277be18668e0f1aa'
                '5621d16f204575f76c3b13385baf61aff7f36d56111fd88ff093bec4ffc26ba63720660b5bd209a9c14c0ac6b4e08b38'
                'ff580c18e39a22a9ac36912892537b0fd42800445dbef1a03d2d8624c1b125519927c282eefac4afc16128b07456fbc9'
                '9d34c783ae08ebb0c46915971429fe64e448f1678bf76c7c20f91ad80e213e39ad89962aea44e06eab351c9b3a5859d5'
                'a884de0cd767260cb60a96f508c62b731047cb1f3ca6ae28742771f4ec3be45df500f0132b6e947d2468aab9410bc1f5'
                '81328471b3e53e8e29a0794f4ea8bdf9fdb3922cecbd2aaaf75a2af4c7ceba03382332d39dfb770559789708930e4c77'
                '966c7364e2a4d762c122be3fcbd37276ea6194071bb7c18e2627524f3ab2be7c0c6e59f62d1f075e1951dd3352f6ca97'
                '62f243f6691fe6a9dce4278b178f688e433b990272000f23c92f74a1cff1429bdf1c3fe1b9aa1c0e7a58abffbb54d3f3'
                '8ed93b11fb12233cff48c812a227747849012f7bb85529d87459e11dca9f7a9c3242054db6bb93b48a47d69ba791b2a5'
                'd694a8776b22b8881bb2d192ab0a45aec71a7171f844e3b1c4149d118efa899e88d96a296d5eb811af923afd1a92e0c7'
                '1464b90c8e5ec24954fe8c9bfb518a308b3d301d8d6c62e5ad40f63bce24699af0bbd2e48fd9aa7c3a1c597731700e3d'
                '86e16ad36a67bc031bf381b82cf40b1b235f51727913bbc311a186fdc23ee267739740cc57c36be05f9331ea40279c34'
                'c44fb8fdfcc7e9cda54c394cef9c17f8529a56e3bccba327cabd07f5f9c567b70dfbd9d7139e39b7e1a493482321b11c'
                '881ba9d44cbabea64f1af18c18b3b5f98ff4a95fd907e112aed857b033bb7e0ff9466cf5fc691ccc1142bfb8ce81bad7'
                'db554409b79e23d0a41063857e4aa05583525e69edaa017f6a7fa96c25a38e7a7d01e22f96adbb683b4eb8a487202426'
                'd68d297b30be0a803d4fca1e037db3bd63a2f06efd68bd4d7bead8338d36ac1425163b3c739b86ac9d967ed54de24ca5'
                '8bc129cff73585b667dc33f32bc4a4d9e106076849bc2574f0e5ab2c0b5cbdbca59bb644bc86f3339b23b3b12959fc78'
                '87f7291136343e54f4a56c344dc5be641dbce62aed4d4bb958c4d54d7196db4acb8a1f43f88cdbb758546f44c5929350'
                '1e0569f00b97fc244507c248031d07ee4dbb6a97270b772791e758e582989d93124ab82f15a9dca469c1a0e98cc75ff6'
                '83430036f16b4e94e94deca06ebe7fe2b8e9c0a690aad7a91877799fcf24ce275844a63e68f1a5c799bc83c7f5384cd9'
                '322e20b619d39d0031482ffed8224f6c522c8533cb29c04af154d920d747d81616ea219e358385aa9fdb8e94a7ee5b53'
                'f2cc31b3a7bac787e54ab9536fc42a3e369043c6f5c11d0f7d452852c3fb3f1845942186044385fb9e482962b1daebd2'
                'b3df125d1a61843f71a272e3a1d97aab97de5831c56d16a6a6620f8c6cd0f4f1e41afe6895ba3664d23a03eab3531126'
                'e87335f4bcbbf2e39c47b5a58ba15066f79717d8296667553ecd0991f14d42f8934d753929f146e4b58d00a3e0139d66',
            'sk':
                'a5787e8044248f3f85aac54e9469fc98f1b1138cc127b120f9946c80b96e3d898cfb9219f5616156c30e9ed4c2c06025'
                '6a1248dc7b0ba16b8a37c9412493d4dd2674a8ff7151b493fb452daa920a5feb5ce5e8d70677735c0543aec2bb161c07'
                'e2c1065fc5cca8ea34ea53c7d879a57f60bef6d318280489cd568229dea833ea03326c82482218104dca1070c3280111'
                '834900b2691b3544e408061935600398441bb509c19285c3200c8a488ad4842d4ac08881b24811c851589845a1c80521'
                '424c58248e0c298899a46584a220114606d4c04018b704e2c085c91668a330621aa090d9183154a40421086e189408d3'
                '4604dc24264204125b0221541401d4a240242206822892889890643884c11671c2340423978d4408449008450184510b'
                '31690b30900217641388001885711c89650ac770d3c870d0a021e124015c202a94864090425063142890c21104452800'
                '2552642046982841e3346d220202d4006a2319500a40814884204c02529a468c1aa028c32002da14041b208c01286cd4'
                '106493108cd3966cd32652e148224842005042889b4470dab468e2805101262052404108328254a0601247255a928c00'
                '0632819849d9386ac846848ab28121a16d88a085092530c2908d9c4040d14222d9a440e1045043165219016524354c11'
                '08608b4689100551e4008d03b161d306060a2049491850e1c888580691480621e486704042918b46108a128123189214'
                '474562281193c64904b66dcc2008a002208c284e90a84103b9640a058980881014957160a621591864c2029019154a13'
                '278d21904804800902440901a29001c750d3262913c9448c88082433629994518400118ab0700882255924404288099a'
                '407210b26ca12011912485a000520840600946899388911b46111b906c84002d1b1642122012cc3042cb806988126c80'
                '10884c9064c9125262886889b48190922123b711c1228c12b88908069210044513094502068c01b6508b080014886900'
                '4028620245d42204a0c68088b0004b128000388ed040844cb65103169221a249d4824101408d02923058b4241104650b'
                '0044134586c8a40c238610c3208ec9404a2393050cc08553164c11170adbb64c593804d13040c8442601326019268a43'
                '4465e03460e4308d22416403484d09384890900954800818104d82c27021c55123377043340408818c88c661d0404a42'
                '24880c26490481314a94211c1025040391d93089e0063181348d24388e84a82584888c4a40669a220a48120d1b012699'
                '266814c74cd24291244332228920980668a006260849890bb340a4086ad4040d58268dc1c07182484ecca84ce0380d01'
                '166208c8409c046dc2a2898b0629c106312386300a9365e3347280a4616486711aa50121a581cc006accc02cc108644b'
                '304d931231104090914246024048db182e611691d34800cc34890c888898182114018611a3601906211a053208044d4a'
                '40105b444914429111384413110442462223366d44b22559b0650b161163c62dd22621188408d2a66c0b120e92904510'
                '955053186919b16920a06524436ed9c6480126600ca02ca3062110c62c94c68118128141262408439009310d0a276a09'
                '040909482883b480609800208824199730a1b461d4382ad08680182026248984a4b661c0462d4ac60d09c97019c50408'
                '438224888091c8851ab50d44b08dd416289a8224c0864c03246c200546182912a046654224281110501a1961c9b48082'
                'a2810b0708caa06011a920e216655a103094266a0bc52522046dc08091a232724c4621dbc068181701633085d4408989'
                '0086cb2204224650d4168000432688844c2280911845722400054bb42c81b02908256ad8402d00a43088341010153009'
                '323100404e13c31123a420114921432860c1206d51c62dd1108a19339108312d5b346984022644a064c1168194446518'
                '9500dbc04c9a2850c2183218b869d2a28100b131648061d0126d14a3242283711c0880c80050a1402e0a838c9b9028d2'
                '96510c144da1940880420810320a09198891b609d9b67123b44c903468d286891c906c00248a52362418418ee0c64580'
                '426c1cc77118124882184d502272d1384c0c14881b187100299121934544842d9b8210dc28285b2052c1346ce4802500'
                '448164044cc9222e14435010474293206519b83080122d1c006163108924c34cf692ddf651a0f08dde43395656847184'
                'f33e137c04f3426909179e9def4a914bcbeb9a4530adaed1adbec4d3affbb57a70bcc7fd6be902f7b19a13b6255ba27a'
                'f9ca8028d67403be3e5dc168244a989165899d0e759104b072114f7b6cc107d7514235468dd88420616eedea618b8b6c'
                'f692981087ecd26eb7c049ba29e1918456154b4b62d7f2054b2dfa8d56bda46605726c47edc9a3f82ec1aa4123588884'
                '6c3c428815d4607eadebd81ab7b72e6a5d92abe542e2c9f1c64e3b54fdbecac29df0c45e0bae8aeb2427073355a2c4df'
                'db8b633c77e9d438dc8c4786ad5fdabd817aa011c18ed90f4b6a0542ad5ee5b42224283392af775b1122b8cf27b126ad'
                '2d806cba48dd6d6d0fc97a3f123e4a3964f579a6345c2468d9f8c0a5388beeeb15657a150d7c73d4ec6395cd3f24ddcc'
                'ce2fde77f6335a22a79463e071050fca1da34e04e224b4c6759c54e08359a7b228f7f7936d45452b9a8e793bbd87eda4'
                'f6d81189aa5501b8957cd54b9ed4690814811aad2afb3dd8e9464a829fd82cf4d941bc86a749c72f82af36afe766812f'
                '0367dcfa395b9a5d2a38eec569edaa793164080188540b070e1f9e3c2921c2115e456ed7b3c7eb8e4063517133cea544'
                'e4b81a3ab24cbc4b58d2bebc6b7094acf1a8e3dc22198d1e85b42e80a09a138023d1fb2c9d0c4650cf2d3be3e5d43f57'
                'da4ca25f23d0e58373161810bfedab0ddecf0f1bafd5229e07c5bf15e52af391876bd2751c57f8d8bea0ac50e110178d'
                'b04456cfb1fb7b174f5bd3471c5cb572b5b052f0525225e694de9588a8372831139a5eb41b6a58ab0e590186472c1512'
                '09f2d2bf99d6d9e583bbfee0b2e2a5e26265884cf6d2b0f498442e6cff79a7333fb0835391145f4075758b04dff4b3f8'
                '6b9ad8be10ff01e4ddf067b6e66ea96cc9d335b36a4c9ecdcb89a591ca4834b5abef15560ccd78396568851b4ba0ecdb'
                '7831c5b27ac459aca7d307d97868a8613636a3d7845ba2110781d200c2af170983c5d773379d350f70f48ddd3b37d02e'
                '750fd0beac3951ee52c831bbed1b26ec3b086cc5e901efb1b7392b2643ff7328210cad3cc0529d9909569b7a77e7b459'
                '425e1e6e717155b3a7cbf2a62f8c5436f4668f7edc652189fb54fe49885cde2b35f7b7bab41e460f99b3621d73e1c07d'
                'ee392661a0066bc40002422f2e3c0cce1aba02b1acc0b4792f3bb9950db6638e89cf9467cc716fd31bf08c70ef7b0695'
                '197656f1f07ec01797d84d332dbc440e8c8b48f3b4399ea8de593fcd36a8c4ae69c275e69cb7c2f80f284b0a05b25f8b'
                'a4597cb56b18c1150f4127ba1054cad65ceebeac54ed8210a61caf049ad212995ff924157d8b6827f73aa46ff5534c71'
                '87ba24705b68f7c6c7998e60f54dd77038d4902cd923d137ed447c157e647ae91c85096a8a3a13b4c7829cc4bb5b05c1'
                'bdc2673ada69ed599dd9f379182c7b7de21da504c7c2283b1e10ac2ae9ec092b95027f27f1364401b3cf9e6e2270df1b'
                '607cbd7da8f9ab36d340c9057d7a38de7f7197dd75a4e24ba5525accff7b6e0be21136e08d6aed502864b8b6defb690a'
                'ea7adbf36d75d37437693f279e57ab7e8048e031ab029ea799a45c46ff8491087372c787e36c9093a0926b15d383b4f8'
                'ca26201272f97f91aea95b05bff56d1d35e047e4d19b234082fb13b754bf87f9a998d94d81ab5ec9b7db5f182df41f9d'
                '64264bfcacc3810919f9df780fe00eafde884a70f17e8913ddd14bde92d915544dfc830690a980beca539dce75cbfaad'
                'c80291d6daad7c871fedee7dbe20dc7abcc56e0d4f317ea57791ef8da9569c9c4db52dc5135e7806a2821788d7e3bb43'
                'c44c827afff07302d21d14ab0f47b0e74a0973e05471259bfd650787b7caade4cd7ae155f01867c624df65a0f47f65f6'
                '75b48af6671c39aeaa0f1660d5efcade3212bd70fac0ac342ea12e686e79cfdbc4c0068faaf6b801c5e9b6c687c0ba9e'
                '883cefc3d59263458736c6fd358ece9eadbeb5da31d03a87f3a5ef581947e80116696097f916808ce634fd5455296bd8'
                'd9dd899ce19c34ade6cfcee97f3d8930ab5d24f33706af6a315c6b4021756f8d1ca3c5adbdbed71d0ccf3ac15b75ae7b'
                'ede62f08760d4ef03d584674b7e4b98caaf9b05904ce4a30896d42c78d31c5d3e548d1aac12ba1b4af6d5deee2bec4b9'
                '242e9ce340d2b5c94197c736ba15fa2d40fb9adcb840ce8b905e05ea928fc1cef280c68a2bd3fe1fbd4ed47443da3f42'
                'f482db6bd467724eba128fae13e28f325ffac53061b9bd009cb00100b2cf0998f8cfc498ab723fb093fa5f68b573595e'
                '50518ef184fb04db336fb9335781bf7a9ccb5bef71ac131f61a87ff2a07a2131bc40003fa7170f7f43d10bb53368ef7c'
                'baed8208f5ed1db135e5232e06db1b394e88d99d8e9e4997326db9f5367f0da6f26b24f8e7f772e4d23e0f4be11c7f91'
                'e7f643dd932772887f50a82dc5c2d3b916e612b53aa402731e99a401bbfbcf5d3182b3d85126288c160ec5a442a8f95d'
                '4929756cfa5de4b98ccf93bb9edf0c5e6717d52651eaa58633ababc4b10c0a0ea14ef796c3724312e97e4d2a7265e006'
                'a325d27517f11547b91baf56ad11268bffd0e864962830200f1d85f9571affadbbf24fbf69f1e0a658e4b3f97726ada1'
                '3d7def371855a535826be77aab5f03d520e3c3f3aaa83df603019b635b047d58210badcf9252857a49af7909942d7930'
                '69f441b1133c855d71f9c5702e0deb6ec2e406a617219f928f9add14848b73aa14af4c22f9607814a53bd832147060c7'
                '97345d9017653f166723f484a4cb271daa3cbf64d70fdf7110c1c4864ba12414f23c06c79ae70c0f3973716c114c7c64'
                'c8537d76188ddc0b5e5f99cdac1b93a6d67444c3238f586322083eaaca34b5a791e74957fd3eed8f1a0a297b4f72880f'
                '9f08618f0bb92a599797c206190973e9daf2fdf0b9c06f6bf70603b9d2f9233a14b14f263f0f9e0b200342d4099eff7c'
                '405d18de9ff10d3a7ced4867bb12ee110984cb51f46acc1a63fd4a8577eb6b6e0a35805390882538f203f8c96e6e9e44'
                'f9fc0cf891bca0d3d49abdae3e0cf6ebd1c5cb231edec40baf1d8c63828b41033d5de389abad6ff95e497af0753e7981'
                '72fb638b93d49d96766a1ec78edfb13a8c6862daa245a59d3c36c408349c62aab197d9308420cde0a26f77d9db8bc64c'
                'ed2349fa0199a977520442cc787f9432cd9f07279d19ac77d0d3b35b6e04508108ede9842ef22ae5dd3d8b96d8dfbd77'
                '5b2eb150fd70ed80f3f3259b289203265f7a4e26bc7855562481a7705ceb34f1b3f917a28cac6efe47ed3ecc170c7ff2'
                '9961eef0299acccb6696606aac9699d7992099c6bb2b288eb17b5907d78319a15d0cafb8ce96b654be2f1200b722164a'
                '4a5a3289d314b46bad462ec95e9d069f82652c3c4095314b3504df63463d0cf2f2d746ce2f883b8c6a7805dbcc94004c'
                'de0b5a3a79c3549b3c312a426cbf1fe3e8d46ccf15375959d8de784c725653152db3b97917a1951f6fdf313fc593cd84'
                '25d6a4ee55f321d27cce899c4af8c83ec25a95669267080f6cdc4b16dcb0e2d9bad8ffd1f31590bfc5c82c80bee12143'
                'c210b6c104f3e173438d6cbe0f42e6f2eb6a2750af3a1380d2125d8ede383e6162065745400b90af9682b2bce9feb2ca'
                '3d187b148a3a592772d4bf135105c938fdc7904a799a5db2d7503515a54ef84f5da5fad4d83369652a32eaddd555adeb'
                '6b3218bf2932c54ac95b552d12e27ba99bbc9119645594eafb5ba859aa77683e294d3cc12e8a8a88bc8892675f3aa1e1'
                '66c027a0686b33323ea45a9274d51db772b15c5d06a66e179ff5ab8952b2d3cf78627b47f9a8911847f59f99387970ff'
                'c27dda6a24daef8ad873665c9b7d5c85fa2dec1fcce52e680d3622b930b42597f09b72dcaa7c9661306243531ac1a20a'
                '3963dada81974dd2c22ab535ff2d87870c9b73cd95d64c41f4f40c0884d980fdde9445f3acccf66d9d5aa44ddf823448'
                'f1162a99ca017ff44b309550d1793cf3be8df7e6fcef5f440127799d6e6411c4c8fdd31e4d8ca550f0226817309e233b'
                '7ef9aff3d1e65132740c79263b62bcdfa974682d3c4314d9033e295d0d712c2881f6a0e1edebeaf922b6e410cc9a1d2d'
                'd9a0cae142914c4845b3ac60cb9d71852ec35ad7fe74cdfb1d1f4e5560a77fae212bcde1d6ae651aff3c6b18185f8f6d'
                '32933dc524a1c5be33146c8c6fa37b01f722354b9dfafc8a4f769cd7b304a3c088366c4c7bc6d8ed6283e1555b4a2f7f'
                '6cf9c462ab5b4d52d8cfe937fa855f008ece0c2c02ee3787cfdf8c16200619fa7f956f41696ca78cc0d691c55b018870'
                'd26f236fd30785d7aea9f90f16491488e3f615ed6ac390dc14e5fc8032d23579c24afa29241830c4d2628d790179b792'
                'caacb5ef865997da83a60ac8305b09c133003121f6b3f0cbabcb74a62a7dd2afdd1501e2ab594c6e3fba51d83d68a68a'
                '835c726ce42d966215c0ba4bc7774a439a1d6dd12b4578f5e713cf500ec7d456095eaf9bbff8a6779de5136bd8980d90'
                '301a1584f221989794cd651057b021a9d6e15c030fdf04ebe6bcc85353ea23a4c1ef70bad07846d81b948761dd83d18b'
                '09cfcb09e487a518be97733e799e8a55083ba3409b9139ab44144f6e283d7532284ffa52a1ce1ead335f5afe051fc50a',
        },
    ],
    'sigGenMu': [
        {
            'ps': 44,
            'src': 'sigGen tgId 7 tcId 91',
            'mu':
                '3e240aef582154f8ab1879a5b6e0dc69a5a214da86ba5585b4268c68b5449a81e20b8a8cbad23e37ee42c9e51a4892d7'
                '6859143fa70b51c9b0c4c19758433a74',
            'rnd': '0000000000000000000000000000000000000000000000000000000000000000',
            'sk':
                '6beb6817bdef24413265898baeab86c94bf2fa5533ccfc0c0d42e92f34b5e7b5aaa3e9c5f83e71b3a69c77ffd8802d23'
                'ca07a53eedc12560cee54f317c9247e499ff7dc3fa2de3963de39f405088d8db8c977bffe9e46e5f7a1fb02a000452a5'
                'efb967c1258a339e5fb15adb410a5cc77ffa26f3491f6dd0f54d46bf9b3946e208a86103c740ca146c114812c40490d9'
                '844804a048522640a4122a242085c3106a23068dd9a205502891a0961061128d991680c2a86803b28004c14c21b64964'
                'b429d4968589b200c03622048240a0068e231644e1240cd434711908680a4304802830e43424e2a2899c042103340898'
                '006582266d1a396e00862d14a42012a52d98b8440a944011b52149368a09034d44066c18b8701a454901b5885a324414'
                '038218b08123462e22a82140a26493448159c60051464a1a124520461061b2019a08498b246dd9a86920b56943186112'
                '46454c282a08a0254a88494b8684203630109708e3840c521241021461132571e048858c02884412890c12920cb24d12'
                '280d1204421cb70564165208178251942823b83063206549028ecb1842d4080522c1601b252a040609c4227049162a0a'
                '062210b36c1c30211017800895108a9005402828840064810671521431c0466603880049a00008c32dc09489da024a19'
                '288a83484a13409014080d0b1629124092d20862404289dbc86dd298898838005bb80d21126d440869194188941030e2'
                '202589444a8ba06004070409142d22166c24062a0c430088b68d43808c094012544665111784e244611a086d4a140981'
                '069024b80ddbb0719b848812a38008362e023488d0846003114111c14981b660c81672c9064d1a136d23c708d1340042'
                '064982c009d84428d0b268e2222e589068a2320000362851262d1b262d9c948dc4c491c9a2841137900c40259c285021'
                '8751c226468302820a0452da3405901420d2142e8388219b302290184851166212245292a20800372288484dc2446619'
                '080d0a05821c34269096910a06044b1211203009c9866908852898204d48b84448008402b60101418e1c182190b00589'
                '940913224e1025328cb644d840241b474153c22c613601c08880a348288210801b09648038619930318c220c10c41014'
                'a54c60a8081c338554205111a289d4204da348441845410a118620c16c60340641348960902910b68154320010105261'
                '284820b50859006d23c7916486458942856134890a972958404e92266d58c440aa56b190495fd1285669bf1f0f6beba5'
                '3a52aff58c90ed5dc9396f108bd5a8bf6f4da9d8ca99f0cf13f1dabe503df3612aeefa0f5f8521c9b98536fdc1a13596'
                '0fd342af86b8af34a7496e723fba8dd8e4b5e9668efc7daec509c42908036346c46029c74c3c401243d303117defcd85'
                'fa2d33a8e8f09bb402f1c33de1bbc4c604a3f289a8210f7104e2c6e1fbc1eef2ed3dca16df6264feab235e3a75fd800c'
                '4fd028239456bfb8a141f90b573897fcc6a2be6e8fe61509911733980861917c915bdd8d42bb8c36bebf80eb82920539'
                'dfe783094691767af801fa93ddd3bbd6041951075f504d3edbc580f506506469fd6c2f75992c2dd1c988b50a3096df77'
                '02ab254340d6b06ec8d06f8d67fb3e78083b1e31098a5e0f02f8a7c0c110a99b8d0d619bc1e7a5c7998c7801db708499'
                '244af761fabac5691035f97c4115dc6940f6f51bea5eb878e296b166e1de0aa5d7a3c86b6de58ee4f21048a46436be55'
                'a57c483016e4af2fef7ef51ecaf42fc40961b63070961cef97cd5fc63372eff708d9f9398a06cb279a5f5c1ee3d30ca9'
                '52b04b2503c31aa4784d279e249c5b7dc2235adf5e0ed0b561ec1d585065b73f1299a082d535bf0613808870d5cf8af3'
                '9c14de9e385fdcb95a5661adc0bc7cbaa4ff3589b3412a1d324ff3563ca895bc17a6cb2daf83b704bdbbd72ef48d3440'
                '0b2698ce3fe0ebc525d542cfd2c6d0b955dbeefe69a0407d2dd475400947179e583bcd11b521ba9d2578586847c7c41e'
                'b50fe0018cd200515cd7165e711da5b4a9dffaf6c27e2ff8f8c18b9cead63de207fab139e8dd6e4f759020e8b35c0e2c'
                'bf1287f67badc2312a3a9238f87324ed45216eca8d2504b7a359b2a9277474bdf67d0da9e5effe4c0d9f891e57cd78a9'
                '46ffe6c0f4ca6c9bdc4949d7f0957072c4764dd914ffb3d24a03026a9dc3c619294456af6429c33256417932d9c15c47'
                'f082409760262f896bda28e1e3cf9bd7407289485ac0f8832177e79098f602e98582ab2463546a671cb329c6db14f51a'
                '6b51ff74a76dd0a91314ba2b691fd314668bb8b1ee2c8e2bc7b9e8c97e8d6105ee3db67aaa7ecd9fadf7bf2ab94ebd4d'
                'aab42749ea118634c729d0926a413eece91c4689563f8825d5c61f50cbb3177a20c293e5e667f346f22c48460a650494'
                'c17839ea5d388d212d9e1a7ddda0b975ea546977ba2175339e7f994de50af65df644dc48dbc9641ce2816ad53d0bc975'
                '7bd8f209de8a65726c489532daf43e4f51f0cc66b45a1f7df7055cb524f968b8a3fad56140204d2f8c123180e7004dc6'
                '5eb587320c72cb89cc3a7fa4f60b907649f2e6a2bbac02be39906b669e18fac21a9470276813a391c385958089d8fdef'
                'a383df21c8bd054c48f418391343dfc9424e749c55fe0d9cbd7e0917f01adffd622ade02d7d811bd7f64925a67d7288f'
                'c8791422f0d44d4de8e740b7722da907a772849be8c3d624fa2a4c1786927754c1796e1e305f781cbcf4f78c06326ced'
                'b433be9f9cf7a05d0d387ed62b1dd6f7fd90a0bb9451d3c7f7d5cf5dc741157d7dfc572886b81954cc7217f2eb1bcef0'
                '2cdc034dfec787585806e78c81f8cf63dee8a872ada2247cdc57ae9e210d54b4a611683c2806d572cce09dab6395fe6d'
                'c3051078ce9ea3058b4e9657e6c28144c4c54cc35ad4d99ca224e20b840bc1f8e9f983c1c3ccd93e7cbb3d8d47c4f6eb'
                '97f9ba0e3ccf259aba488684d9b60f0a796c80f7f4b9dc12029c12782f9ea0f1e78cc3dcd0e0f6267cae3a10cd2c57db'
                '71044926a3bdaaca6d9835a941ffaff43107d7c05ec42f09f30ead88f863689eaaedf4df9107f21bc39993988b3a907f'
                '5ad5d89535cfc2011560a15bcd1bd5175c09e972528c778bc6325b87d79434bbefbc813c0565a959c687e0718577a91b'
                '2f031b9a278d80af8f749b9ecb855802202aaa6b6586087d6b2c939c81840180f5070739990c2ffc913f8cdcb55a2e96'
                '5bb186dac8d1738aff04046ea10849faaa627cef16798cfcec8377a937cfdbb1804f86fa1815ee4d32b429ae016224ed'
                '67d310f7006a3109aad22798828cffbc0bb65c2ae5eb0a7fedc7b9e2f6d810e5538bc20aef00c531ce5468bb49d97976'
                '540310462560aab008a50c7bd12e73f0813a3089c1e0c24c54de1dfe81637e4a45511002fa4ee12629edc887c4fc401e'
                'eee8ab22987b79c7fe07bb938d9707f971d22f5817f5b65cfceb62a0033cad9b83f56ae7e4f0f09ae8d091a380cd4a13'
                '533ed9498a4a903501cbc0ecd4c787d06ed61917c6e2119a79ead8c9c21e6c25e18c8ed2a7bc82e039bcd9da09d8dcea'
                '9d47e4c610ccb31fc92abdf99ba06237',
            'sig':
                '3327aa270451d3e5aaa3e1e27a8414138d9270c1b44710f249693b205f890350c970bc577e0d2e9ffe641147a7e877ca'
                '86d6b31c64a8d80b9cb55a3fb1ee6c09e0e78f7e01c3a576d92fe1c26d745bb194efbb375840cc916595dff2bc021964'
                '2439e9a85d64ede176ae94e51cf6f9b0506e2595c934ddf7432103ca8dc93dd3e2087d9fdd0746c8e14255194abf853d'
                '9bfc7a6d421c726d2adbbc2af70d2cec2a59a12a59cba49ea33e015ef457fcee9d3e4a2759816267283e0c2e9850c36e'
                '1192ebc92252f11b0ae6c029f5f1f8e9844c4a1d5252c6969b42f231461992391f97067f2d98ccaf750a80e582d5992e'
                '684e7d415c486c28ce519a3506fb2cba2467ef083de349d5cfd8dbb84bdef507f0afd6e9682a465d4116531552e12127'
                'cbd721cfe10c18c20904085ad05d8babe2ed9c215b1f83fc425225843d767dffacbca2e9e58e388b689e208d0723e612'
                '4dd8ce9e31d1ccbee25987edaf7be55e1e0d8436963c98c99a11d32fef8440c44cdb83dea2481527dfa349c2b9e2f352'
                '7d0887f1f718b758a7ac3163007abbcb77bf6c1ccfc23dc155dc1b0ba876f34776d35a2ecc44f4c7d996c4807965f2e3'
                '584fd4cdd8bd50f134a78ae672e4d7cc10abb16892f68d83486fabfcced9316ca17ef5109559a97d84b6b0835e36e063'
                '5dc29e5159f872b3b15227e28b7e2971371444d1918301a7a0bc6d682dd3567d22b055d5b339a3c09c6272448d52e4e9'
                'eb59007facf2fec44559966599d1ea6772a9b08134edb7ec533ad84709a4811465d46eb26c8a5f7aaf648ad43abca302'
                'bb85274984f8b6fb8ec663fa0338ad8f2584a0bb0070ecf58e3d8aac634bb1b8ed7cdaa8efbd461f49513b1538febe6c'
                'd55dfca881366c3f146836bd4eaca6fc31d56814c058731ddeb45df78f86615fe2a10683361f6d76babb9d0653cd51c7'
                'd81da0bf05e937c35f75b87c9b684840159a7efa578f770e2f777fa7c190f9dc54bcf65690327142612f7f9d1aabdc84'
                '6b72419752a9dba8d3271de3da8d35b065091e9b601b00285fa7162431540617000b949509e24e6ca4913b316f157a5e'
                'ea97afd9e82489b26dd8213e0f1e62d5a96bbc94c8ed9b4e1dcd57af129be73faacf704acbf5e1277d23760be2dd4718'
                'a744f5b450410165e61f4793d9cdf639985f1de12c981bd2a4c7167e681c7aec4d016b6839488f9bf8a77f9a9795894e'
                '48db3d7456f3dc7f620e8a2266720d1c3c325377d9528ec4c82bd54ef806bfd7b001e87e6fcab79011fd9827ed7c9d95'
                '4d192fc7748c2dfc2d3190110201ac8c84e1b72287793cf57941cf555beef8f6c61d08f0ea3094949384277ba95e2cc4'
                '7cc627e071abade48077423610fa37be30e264e40c9f58a59f0944fee0d15983a2b31f72f591ed3b04b1fd5b82ebc6b7'
                '30a358638fa97e67c4d1a79de19c73b9a561a70dd221e94807a840a2138fe88f5e083facc31e6a08c2729810a22c6653'
                '324094d2ea278d5d3ee266ef10b4cd79c00791cf63fd16cad0ead7ec9be7010a80f8fadabbd98740cd52138ded90443e'
                'a770ecf2b0187dd33dacf6f4f034d364042b80a58156a976b94da79436b58c6726a7a55ad58d9c85234e79cdde7058e3'
                '18af3084dfc203e23ac33e4691ae923a0cb17c61b2432ded3f61d74d7940b8a1ad7bae8dc524efe024a0eb178508ee4b'
                '55b864f78bcb5e6fee4b04bd6ad94d8c366f7beaf8c161f286750eeac00fd79c041be0e424680fb29439bb8a0027ae1e'
                'ea94d11e32c07ef01745a335da969fd77e3e8b2471441e150c40e66979dbe238801ac27f623ee12d9854662e310a613c'
                '9fb0f10d4821f98b6ac5c0f2cc61202992fc10b0460c82a943ad7d87832ff11d4fff800cc0e7f91659c53e3ed9740c7c'
                'c24be4684efab1e929a78f2b73b48eca5249b56b320f5b07d398112985d60e04c6a83f2fb9f042700042aa3252108c32'
                '770d149a7e905e18dae0073b3e2694489b5fd9097f3a1d0d77b4cf9b7763eafb6bc8f01c13624f4ae7eb22a2e22ecdde'
                '934f6105547254792b95ea91458562ab39ad8fcde3247c91dfe3c5037fabb273468a9d7c9082066a7519b2141d021afa'
                '8cf3ea64439f019fe18184179f04ad744fb9a1e65f39ec1df77c275497ee07f666f3200d4f07f0e9acaaa721b543d965'
                'd162bcc82eae574b272443297c5dbbe68565d22cedaf11cd07e2129a5f0b6580a1bace3a2c69946010683c046a8779a0'
                'f8ab08e813cd14481b0826c8463ab06b30f23cd6a289ff20c68c9a0a0c0b73f6ebd4bb31eb6fd11fe4650bd5769fab9a'
                '2cf71233de64c7fba84b10c2b172f674b3ed2d85bed4a7701b785593f2729c3d4e83c46b8211d11cfcf33a9198ac9086'
                'fda7c97ba07c69072427815076a39a825bd53572dae9addf9d4de6a67b51b8c785bb2402021d369ac58d42bc09c4d59c'
                '3cc1acf41966d2b19165723d9836f50fefd4cb42a8fa3156b96423b76fa40a3120840d874a0b7b991720ac95f15d1b85'
                '6d8f4275c7c136257f49057b78cae101c97360d3a90510598f99021f44243f62151b13fab61ba3947b9f605dd7c850fe'
                '9860f6b9a10843deea99ece225c40a5da1cdd026612a3088566f798e59082221924f823caedbeaedc3b12ba29ed40038'
                '7ae33f201ddae901b21e3343870ad91c7c9cceadf8dec329efb9f2ff8ec1f8e103a508c8e1e938eeadd307455153f892'
                'c612b4597d569ae72250eee17df0b97353c05f766278e91951a7314d05c52bb32a4d35e752bd799f11a84e5c1eb4cb9e'
                'fc83caba48b74bbef5d53b796e93b0178e72a46e3a7010a900d4ad3a20724f84f3ca8ccd5720edc4a3e65523ae5f1674'
                '51edbb5623738ffb626d6287a249c763f6498f5180f79f1a9137d72cb52497581217d0fd0bbb05183f63ee788dd01caf'
                'ccda55bdaddd882ea716915a888c6e040f4a29df30ed6424330fcce93e3c4b204c1286f357ad0501662ae6ef6a56f795'
                'e65505c7adb776714e26549b41efe8520846e46fde5b1a06dea4774477213d8dbb410b6a2dc9063f04d48e7aea33e032'
                '48178f025ca5480a91279fdbd57639d28ff8117455e8ebba89a0e983adb00145477f29eacae2f778faa5bb2db971812c'
                '7272931097011b0943ea530b5d3fce1ec77b30a2c1a31de96239594e63519ca451ba614388e65e590385a0efb6404ea6'
                'b8905852812f4d6ac7c45f15179449fbaad3564adb018b777317a1e2e940ea29ce40615bfbe3c319f3cab0597c5df6bb'
                '11e729379b2239df06856cdc3fd1dca85d28a8ccca86d0fe0b9970b22d23e7141e27282e3a515770717f939699a0a1ad'
                'bcebfe02101d2e303a4345465887a0a9bbbdc2d5dee4f412313d41798590eb152c373a3e44525a8f9bbdcbceebf00000'
                '0000000000000000000000000000000013272f3e',
        },
        {
            'ps': 44,
            'src': 'sigGen tgId 7 tcId 92',
            'mu':
                'dc4383226cd33c0b7d92731b02d912d5ef5377bd749f3ff07a4ff66a407c037f30cb0707f2ac1f5c1c1c42b8143cf1c8'
                '0c6ceae062a4d5e34a75cf8b2f5927c0',
            'rnd': '0000000000000000000000000000000000000000000000000000000000000000',
            'sk':
                '488b4c818af609b95e6e4155e9ef417d79e68f726222741341d9ca323988041b682c63fd08aedd4565e8d2bb23992855'
                'a9fb95a25740bde8008e1a18932a5e61d17d8a0881400b2e53d82fd62c4a8fd735bff5f3a22dcc7e9586babe39a5ad8c'
                'be8b799e71f4f19cea5955c27a53f67afe8558c59caf0077c0a1dcf94719eed94c288c18892ce0864948304d8c284e9a'
                '4830a44466d41801c9448424a024dcb661c432128ac869a28640a40092e3c468638085d1100860028a81c62481a2418c'
                '366dd9b48163280e90326e23866400c064e046801a8288894685c0440212c51084922c0c0642831445c8400cd2302548'
                '8210dc267089402ca04460e4c66118438001202cdb066844986818a32864022dd41471588251828884c11268e334254c'
                '446153860410c70451960820244520c489e3b491408824c0b00d228885c8460aa2b80041128614a72c9c186624253102'
                '032ac220060a97648cb625cba66419126a834611222312c3b66cd3008658268509853110c18dcc12099890602426014b'
                '90094c16661301680ca76419914d90b48d4302510b1449194065831832522689510430db469014484aa2c66188a880cb'
                '245204a19122a64c42984899482121b82d4cb2680019698442008b082943b0810a2384e03292c2065041245003433012'
                '144a08084111099214078819406121090e08392a59228ad8200c4c068c4b26424c464dd0489089006e1ba04ddb1048a1'
                '2240dca66584428c010966c14609c9400c5c463081a265238425534889a3c665a44470da900dd3282890c88158a80808'
                '495051866922c74414126ac0440e82064853380104b36418b205219149da008859146c40a8459c344449082d130446c9'
                '14050c890d9a948dc4228c93c02823908948802122182110149220278e9c382dc9c60501336e13252214b924d00011e0'
                '082e23474153262a0c210ca042060c840d12800803c84c43920dc42664d3426d2126328cc684184800200128214108dc'
                '28041c4912008109590281da844954c480d8884814024ad3b42d24172c4a062a1985048228892136460cc9315a006cd8'
                'c09019278e51c01194482d60042cc386610ba5240848401043005384645cc0290088311c182d9cc050608045c3324e44'
                '1648c49409442681c3463290268290248691902903482d13a61189a44018b545433602214720d2284818134d09473090'
                '204ce00085022552c134651924458ba28524288d8cc66018429081486c13930ce2b87124d15a3dfcb69318a81bf2a17b'
                '49c55335386cd061a38cf6130817e7af525feb7805b67e3863c3d71126730ff67b51a575800f5db7b2805144e0c992f9'
                '01c46dbebf5f110050eee06bc5d33b3b35d96de0c51782e765ad60d3a4ede408c394324ad7c211f0d811a204402372c1'
                '0ad71b8fda173ad493aed91f3e56577ab33e471d538cd2f67f589b0a02b8b7cf26e63f41597260cb099a480124d12432'
                '3e1441b18af533c82a1da938137f0072f55865ccd6156978599d52ef7718a94b032eb7e50770944c13d2cf7022dfea4a'
                'bdfab7ed0bcdbee7b8453bc97d59972180a2e06a339c49d7de6c25f75130ab2375b2fd0de3a178c0d8b2beee94363b79'
                '23a8bf655b324128414a916efe2ca01486061e9311a776e227c428fc1feb125ecbd8daae43e6ed0020274c7e688e03d5'
                '89b116e56377031f691dabc8db6a77ee177a1b26cd369494f1523d2d46fdf26d79ff918611a899a729ebdd91ce6d105b'
                'b6cde9aae28b777e9e62ec9beb9cb7c488b52865038a54ccaf3e8af26c1ec8e6ccaf091a62f17e8edb9e14b2a60bd5ae'
                '6dd514b70eac385b89abb7502eac612c47fa9ffa0517c541c5622cccccf0b05e035e6935fdc089fb9d89b80b5e543dd2'
                '85088852a52dde047b1cbfe75b31cf5f99dd71ee2cd156e7064ea738b0820b77a52c2757ce94ce4769039a41eeaa87c6'
                'fa54db991f456dddcb7ae0366c325779cac3efa99ba5cc3a56bb260716f0843cbc91725bf461fb526832ba38e9f1fa0d'
                'a78deec48934067c3ec0e646cea13c01b26bb4f5e0d11e2e4bd55304ae5d8971aac01bc2fedb8ee661db5c7dca8e4d96'
                '3adc865223eddf7ba24ec9b33187b7c9f18d59332310cd09fa8b7ede9207df3e9dca818645a1940c87a40b99cac0b042'
                '28d4d6c128e551695483b595762411a90cfb2cfe3443b961ad260dec6ebcb293ff32841f0fefec09262d856f13dfc993'
                '7ff9a85ec22801ffb9ace7a75136c4ced2bfd33677f67a27241a04510cd92eec8051b2c3beb0c3a6b5ba4fcd6e012757'
                '0d339836c6fb993b93740970e5e15101e1fd63b437b31bbfb1433010f52757cd475ce3d431b60d00510ef63f57233a79'
                '34ec0f84947de8299b6ba54bc1c636c16ba41158a8c0a071cd5be064fc589639922a3c32e25e78b79e76e4a7fd1e65d6'
                '14b002a32879113de8579d9e48c62ebd133fd36517de83e1101f3f1939b2419df3e9640f1f853e24f6dd3beb8cdaa7d2'
                '5fa8ddb93917fd14d25a8d7e4d9a1375f283aff269144d6e98a1db3a639c3353e8ce0f2a499d9d5c27c4fe63770c3b88'
                '81070a8924c9ec49de32385aa117f2e97b2b01c7ad66ac05fcdf93caaeaccc08a4959251b633961f16f0f1bece61fc20'
                '1cfd18ff48726bd62141dc0095abfeac8b402257cc3c0fc4579fca6f7a2a1545403e3b09d58071bc12d9dfca694c70c9'
                '9cfd15f4c3097c3a6d8da896e5dacb9eae8f70608e65513c9d7ee409eb0b5cb1f28383398d0ae9c6d0ad281638f86082'
                '90eb5fc58e8188597a1f50c8468a95e3bc39730c8712f728aa69e291071b1ed2398d12aec9d50e73c12b9b6bc2902196'
                '9a02851bc7db6f8daf020fff1a6829189e71d3ad8bd76fb7ed95a557604b7ef64ff249f6f8164cdbf57a2f1caa090d2b'
                '7c518e3812b18b1c57848bcafc438f3addef491bfc66c1791c6d6668a374e52a68773b3bbae037dfa326ad1d3979de9e'
                'b39f518b90cc98b6c7c2d57b5c61631000db7905cdd2835c42dc81d6bbe7b630c0fa75372ca3614341327dd45fcc565d'
                '69496e91b47e8d8c295ecaddd123732e55fb80d03d4f6697fda8f16baa855c1bcf0860dfddd52ae294d740862e12ea08'
                '683d7475e2cbde43fca77b5efe8d288a6cf831fefde9709803c28e414fcfc2b12cc3ef9a7f945a180622c1d06636c912'
                '5d41f6e92b2c19fcebcaf39b35bb2039543dfb7d3a58bf0ff594ef2716091708717e18f002b385d7cce02c7140eff434'
                'd72656dcc6260e4ef90695a38117ca5ea550930bcdf5a6ea4986f11d96cd7757b64bb9053644772ea83dc375b83d671f'
                '3361ab4f181804c00ae13780603e077037ca90d7a5b2ffde01464b5aae99c031c3158555033e2a2bbf740fff064991cf'
                '275a9c0cc655a79ec871d71c40cf3a91b8b37dc5af28df464393926ff85205e914e405d9fab5da95945f22c8a3a0a54c'
                '3a1a6a39c8135d5a22ab26bf94f30dcf925cb85f02de1df5c7ccb2ad5f8a53ed5dde5031a7d2c4a90292a587982bf8fb'
                '0e6ebf84f41ae8d366b21f19f03343e5f9aef56d621265ceb8730265c1939c89292b1e33dc5754cdfe5b2da26d0e1d7d'
                '6785779806c2f7d98980411ab9192d5c',
            'sig':
                '2613031eef8529a0c361b7088eedea4e9b32e97556e4e19bdb7b3e9f47ab68d43e17355efb3bd2d5e43a3eecb24dacc1'
                '9f7b4f211c04324cf812e52f1756a8defd2dbdb9f162c9af1509292678dcd6ae90b725205d7c7ad9cd2184245ab5b50a'
                'fa6928cd01a179d133b0bee2dbb1130404f80d4f2b8e50ff0f6f654683e263c8a5f7f21c5a499683feb7a10e5d489e22'
                'e748a36fe6772d348fab35aefac25e017255985df18fa0a467c0e40d01e6983ecc18fb05ee1c50e0459fcd895d666206'
                '6c10eb1fa5d31cec605ff7a7a8f26408ae4610bc7e71968d8b4183621941f5e655efa723c467868e07e8529f16ed509f'
                '98447e8936a2f044a17ca434f9f1081214459ee8f94ec28fd219b5d6096983cf55c33cc35c1d9a6a2b0bff3db17298ef'
                '999b6a13e339fa92d65ce5edcc73c719e14a5d9573ee9ff56cd632b067afa8d39b98cf9055160530a2b717bad27971b0'
                'c69e5b75d2db052e0d41f8134127b192e55792a22e37b968bf2772e2b012fe2c764714a1f6a0dfdced5a69a4333b308a'
                '62d9cdbc49c6bca7d2228a7bd730fb0a8c140f2fab57c2637638277d12cdee353c59db52dbba4da939b93609a0e2847b'
                'e5fdc725d8adb44fef262bf6f6df24b90b60534341302ad4275b7334bdaf48d4c46fe7b6c62c7791691cf5c9d579175b'
                'fd27267c70b3e87c37918d3ba899401b7dcee53de9219e04083a2acff56c87f8e0baa9544a4766d52e1c768d687b2ff0'
                '616f179b6f74b8d7edebaa90efb13f6b76be6376987adc94dff4a3aa3b0187e5a07ac04bbb1ba49766d38908901e4343'
                '89795e735b89037b197051573d54b18d4d0281debf179b7008666c88b19d5f3c404b09c2b2b1741721904bea48b6da8b'
                '546c3e7849c95bacd0c9a256f9699ae0a6c179965f334b2b1a6f8929c2fb9a6f56f31c837610de921b3688734e52c0ed'
                'dfccd3810bb60134dbeaa5327f31765d236188959b7f9eeb611d3f9a40adf5725e68ba874ddedc26b8d24a76e8766d8b'
                'cc5e550bd898851ca9c987ed849796026e2d3365e087172358b87d69fbe251a422fef68721cd61ef9428d7b59984671e'
                'b6f97e50835420f71f3193d7b01c46f61b184b6c6fc14b9ca4ad52de14b5312e0546bce330dec0b0a55b42555beb512d'
                '7366c32ea6bdfcf762bfb9506d20ef051a87f81797f9905c3d38c385e9c72845d2111af16047821a58c6f57de2474341'
                '4b6fbb033a0edbe9a0245f91ca51147d4299c9115ef198d0d2705cdd8c3eb5f480d533626d66ae1c06c398d55d6d0478'
                '49716d278c0afedab761b6c614ec5bc38796265dd161e26fc8e516b736f102201950ab874d5806210113f21855c172f0'
                '663b461817859c1d0c3205e053a36e6ab5ca7becb9794d1ee4e62788e4925be52b208ff66a9072e0021b524bdba99508'
                '1c7768d715e98d9fcb44c5ffa50755530b8bc51f20717c9d1b48a44c1c62ef100fd5fe629c435e7e35773bf6f5f34fdb'
                '8fb2f5e7ee9fe3939e10c184d6df7a1c8195d7ca5490efe81ca4bfa5fe106ca8f576fb7d87c29385c20e63765d28d081'
                '6d91ac782ea485523820f1d55f01dc941a6725e5a0686209ad104e4e1d4a2e511528c91e0896f1fb6ce6aeb2d3d99b31'
                '2dbab3e0a7907d1bbdc119574cbdf0ce6b6eab8005e035d19a70185d38392e3c6f98ae6dd9a1b4d4fb490699650ae58e'
                '8bc68ec7997d40b2969976642d73fb1efa00cb33406ccb63f7040ab404c25dc88552838a8ea8c1fa11c07cf775c4c776'
                '4c61978acf31a7172f7701e8727713ae4b40de12e3200ca05690bf8e047b40c03b2033804d2cc40cbc64f92c2b9cd32b'
                'c8abb76d20ed497faea98b2c7b7033bd9be2799be8534ec28b65401397d458158cb20cbdbd39dab118543729f132f04a'
                '3f80d2b3022c96013827dcc3348635b145a7b3242c1e8b392a01325735c55cbbc83e9205be5e3aec8f6bbe1ecc1fcd51'
                '24d949cc9e54c0c15277d48b5132133848b4494d1dc4b8793e452aae32dac91fecb3e9ceb6bc3d4e2bcf6d2167a9edd8'
                'df97d502159eb1d5580f72e9a3d0da8114fe36dbe790f383089bce74b196945e8b52d7ff59b7c6ca2feb87d680390d2e'
                'ac8c457280c10679c953bf0f6df6e3c2968a0bb49c5cc2c18a26b8f2284d21ede9c49a95722490a49b0a6cad81ca65eb'
                '0fc5da86300d6938eed3e42849e90b53679599b9651c9bde20ade01766247bfc768542226d8a06f509c57569e9bde176'
                'f203afdd74cb3956b072b9a3fe126a2af1a5f7a8ba64983333f1ce0069baf9200803fd989c92de16b58b5b597a2f3ce3'
                'f1320c69828e39eb2fde681b1df9351becccb191d2595ae9d1903fe2d08bbc037a446b7d58596bb9e156ece8368a9e30'
                '8717a865116c17570785de6dee4ebf2101d9605b9c57444665285abcffbb713d455aecd042ea0bfd1ab2109aebddc884'
                'ffa01b86166390fd91e3ac8b0132d549ff074f6f1d2a5235f3ede122d16f7f8d5ae993db2656bb6837780265e15ce2b3'
                'cff013a35a44d96d103305d5248a95b9c5efdfc599b7362b24718a169cc37e3886dc7b94e87ffd0bb2b1f4ac2df77efb'
                '850b93f2f72f41bf015c8fe3fd51e7f12275970f43fa700b26fb8b3c7a1a801b4c1430a996183a8cf987f0381ea7dc91'
                '92315e0e2bfd1853b1fb45c6149ae04ee15a0190f73f4efcc9b5783735fed9db5708c040bb22abb988bbe738c3645872'
                '85e4017baf1846437f6cd0007ba0679d85c0e0a03322da58c10e997885e99ca2671b6556d76440c4cb0144870d6dda8c'
                'a9204aef1825dd1282c7755347426647607ef2edb49d1594a00573861adb475e42cccfc35f8e5ba9b7e4eecb6fbaf40b'
                '5a75cf79d099d5c1b5f9b2ca81b292a417e7f26c23fe0bd9f7749429d1c8692a8dbcf9e4cb18a9b3eedb35f291f0fcac'
                '8b469b04049200f4c7dc6d3eb0b8085940662a29425a34c3a9c961478aae1b94891c3bed9aeda997045e6e1cbc592f6f'
                'fb33295fabf0c9c877137b9dfb831481549c35efb84bf72069833dc01ca80522784b9a62643195c11fd8f94ff720a1cf'
                'fae5127510194e132d1c2c97ef9a6388d05d941e4157372588ff29b85897478d41d4283090a3dc2b7d44590ea60b2ca8'
                '1878b1e3b92ffe20ffcdf27e5766838bee126c1fb4fbcc3c5dfd2bad293a04cf74430aae54ccfebffd7afb578b5e0c5d'
                'e66c712344bd6e526614a55bd820e3efd403cefcf23a12d265d6a7e32302e8e1a4fa5d2e76916fd7537c3995e5a0384c'
                '8334f8488263fe3d9d5995f256828e3b44684780f3d35da6b4e9987cfab3e17b000405222b445b616774758392a2adc1'
                'c3d6f5ff000c318796a5adb1cfe4fd09182f464f63658cc0d4dbe8ff021b213c5e65797d8894a2acbbd0ea0000000000'
                '00000000000000000000000000000000141f2c3b',
        },
        {
            'ps': 44,
            'src': 'sigGen tgId 19 tcId 271',
            'mu':
                '1d24714c69dbf0c970d540cb572020257499d927cf3b7c99dbf0ebe667faac0fa3abcb36b2af351c8d013fb4e708b101'
                '667847ee18782ce95a23fb9ef77dcaaf',
            'rnd': '288f870ff69e89d6ced754ab158c3a9b42653103384e2cc0167f104c4209d580',
            'sk':
                '2a85d5d03cac6c8977eaf1c19847f8ba8d53e5d1c4a9ca2d02c2c4a7e9838bbae95fc78db5a422e1f747ee3cc59290b0'
                '84383c52bc03906295cdcfd8d5fad5507813fae6b7dd5f3289528af354abb98056a8c233f49ec8653d02ded6cbb7b43d'
                'ced8921ea9f2a03a0ec1b1d409ca80a0cf4825f804ced52e3445a56e3235adbb0c276d03450e42842998126d08983053'
                '484cd4906cc1160104196909804854122962362e88868dc284099b046a1bc65002b91043a06d4824480013265340289b'
                '1090ca34120aa441d1a690c8302e01122d21860004b4900b050d4b32841ab5258c344a8202429c088519936542c68d1b'
                '19444a08260c2660802806d1000e08236843984403341202290494368e94368c44a640233792db1871e4b27119238201'
                'b68408986881984863280209266c4c201193c41093c2659c944801486658862c0cb42d0180441b498699346c13994c00'
                '454c9b428ecc186e00849123044de2042692a020db002d202140028929c80082c0340448246c5c026a04164a22116a84'
                '846151166641328811a165da006964120ce0406c13312e8b048941a269003785042189d49660c02662ca206103a22542'
                '861113c469d2b089dba8501ab48dcca6885c12420437452101904a048d19a70440982913414951a610c9024491288d63'
                '328604448e9a047149b8648a127298840519b66dd01252e2822cc8464a23913089262ecba08951042003490d21458a63'
                '202400410561c088a324908b1646d48668032492d000290428269a088c8cb409c80808a0068193c00d02c6891401520b'
                'c849c4b84124b851ca420958a851042841d144229908500b214214300c08989118076dc9080ed4a0711cc649a4c62d0b'
                '336603262de4340e1187840800621a427040b26194169144b82c010142598640d330240c487019491121966cc2002884'
                '862c843240121548d236006300861c3888142922944820d00221e0320604108209b08c031541902020e4b845913021c0'
                '228a5aa22589346a1c14105826810ba61148263222b86858483162a6851196290131219ca63001188d90007209b44d13'
                '202504c76c89b461014089134125c8c40188c800021465dbc0604b82016084008c48298240728b88718ac48500254424'
                '146c61c41109388ec148851b1752d4144a8022222392491b36420492711ac3410c0129a11270da0411e330925a2290c0'
                '042d1a928512459060242d8824061041405bc42484c4906122885bb828431621475d2170672cee466d30ff84a2a6d043'
                'aa46635a5516f1c0ac3fff2aadff5c05a1a164cb409a1ad5f417e49bb01c94f5168d8136edb7cbe1c61e5c19ed45cb0d'
                'c45b1d0c2c98a9c05033c374269453bfc458847bc9f3ee88bcba992d46f5abb7f05a8a3e924424899c3808c05007d64f'
                'ea4d8dfb3cca275e7cd3830e225f3f4d8f162ca01618840aaef7346204775e6ebed692939618da470a7b9ff793e08b04'
                '589f8d6310ac73a30baf9b786d798151462422010861e0af7e2219ebc08be234fb05f80ae6a04edfe89bd59469ddccc2'
                '1e2e4cd3f72951c17a6f178a33368de11bf1bdb1ec6acbd73bdd8e058b8e0be35ff72502858ea819bfb6541e6550b5b3'
                '05c73b90b83c83ea143e9e871775e449a39929e2cccbc71f867d4d0022606d778f32c437a649d9cdec131f2a8b06fdbc'
                'dc8e7326a5ff973aa60e4e6beab5033f37481ef4adef1a86aa3f8519b541561d7473b5aab33224e9a7f1685843a80718'
                'c5a6e6d810fd695f07f36eb725fca7aad654668089d0a77db39f841f8d24474e17b28718ee1fbb1c6ddde71bd8e68124'
                '63cf91542ea42b70c0ce545ab2b9d693cdf1726278f5df850085802f16f7a6dc0cc694ad07bddc90bfa4b1e429161d66'
                '7896b51014439643d689cfb93f7201cf676b792cb18d023cda85a7cd5f6dc4497e834d4b5d416a6d55e56b844d33732f'
                'edc6efbe9f92ca0c73d6be804128601413ddd55ea965f9828ef7ac40a1f94b96b0620c57added7fcbc0a2ee199b69b0c'
                '6f2e458eee4912cbfc9346051596d67f4a7667c879c990eb205e087b3ec30152b196959d3aaacb7af8f41a03786c3a5e'
                'e7dc0605b232b84329cb85c2563fedefdf894d78267a7cede96ea9fc19eddb6a3336b9f355eadf9f37521da91d214fc2'
                '12afa67dee0fcf4b16be5847981c1a72531f4c5122841f877e8b182c9ebde70bd60ae59f977552686dad425c9534c8b8'
                'f358a5aedfe3447bdea63ed18705c73df335a1ab5f0b2f0ceb8da38f7cd93f346af92400665f7d0553fb322f4a5e3552'
                '1d69fe425e434546301943621000972b3e4fcfff86c2175ac509d123239caa9fee418a8e375f2bb92dceec5c8055e338'
                '20ffbf4d3f5e67260e4c6eb761dbe22a97255b66f6c31de9e77d8b0671cf3573b1f644b7adc8a4387ee2564d634a7d74'
                '8b25eea78d1c60d606b47450bb0478323d471003dcc5b12effd72b30a5eb21f600dbbe672d377ec64c942dc5e9b41609'
                '67560f7c0dd5931bbf876ab1e596c97fde14f2e1d86f8ffb54fc65cb1afa5c92344f1cacab1a7662728e813546188a3e'
                '0efac48e60cfc55418481f88221a371fd66b41cbd2b901153136a007c7d55dd25a73ac5b5393027117cdf37d380dea39'
                '4754e9a4c10fbf43466fb892d3c119e9d486be7453e963fddc069790a6fe5230d91e28a9dd420f9f8b6eb112e15ffffe'
                'a67d8c3dd133017d08a48c24d426673d8fb445000c8a2e9a015aab250f1d7aaa6c7b34e7871fbd01416238c417b097f7'
                'bd7c9359a5544cd68537c231f3c49ee996fe0e45a76e1705b041805415d3f73919901bf7055053f91f5b446c49254f3a'
                'c5616fd695e661ec73c70916efa75e1c23eb94c5db4692cbb2be32244a79204e935d526dfc13652f3b7f7b01f0b6e845'
                '8aac49927502e8388e5ee5369fa238a5cceeee70b6e6d446fcfe6016620dac08a69f97ef8784afff9f28f0f68024f366'
                'f38a395b0639a959164d3cfabc1f720b8a259bf98a41e8e548ba7f5892619304e7c78643251176226ac8b598a248cfbe'
                '8bad6aa9e6606c52c2919860323d2a7cde1b9673801575f6bee95a1e05952aa9d4664b74bb8ab9a1b11aa71b19442e99'
                '97ce05b2b840c26fb85116597f47bd03dd1dfa08560d37ccd6b5dee4e351c683b0d1c42be627dd7027a5922185aecaca'
                '3131fa98be62a2636485a66e45fc09a04aec79f88bfb8caf25f564fc47893eaab3bfa8f5bdf24ce293484bbdc8822588'
                '458a26fcc3594b539cf6d547016f564d3ebaa0fcea8ca431d438c5e3d99b66b4148c9a8a194fbdb2d6521f9075c658ab'
                'c50564f0039d3c779cb89fe7c197d1ca07e74dc3741d02c5dd8f0a7618a9ef8b2385192720979ac0023d75322f7b899b'
                '6c7302c8802822ecbb488eab2d8ab0987b7666484dac4944e980644024e03c1736622099a0f1785c5df972c3e97390dd'
                'e0480a17be2501115df0a656ed9fcbebdbffd88e9bc5e1e9d4e369a4a67c4d9399fa011accb8d90b07b80e3262f9e06d'
                '3a9c3cb1bb09a8c11426548115cf5abe4191c2d28a4566690bef7fd8417bb1f6510c7f5b12abd396e40336e7cbd0a96f'
                'eacb960a38babcd0b2fbfa7810cf5743',
            'sig':
                '5c04a9fd9bd3757969f5099d5627d3b0a1f2ca39dd4ed72ee355e568ee8cea68b91ef0ac2e0003c8b84f03fa40e5c2d7'
                '4287d7cedb6c2e14787c6e1e6006915753f9f3795533053e50cd771b689caa446f96c3a53265568320921690848ad3ec'
                '7209b2b05545ad470e49b8c226abe1e8dfe4d5d55ddeb72bd2871580c9802145e13358ae3e5a4df855e26c5fee86c41e'
                '032325138bccc1e58911988f5c4ae8149ff0c1ec880567c475a445c5802763e0d770877f4195475d3a34fd39b95735ba'
                '6f71b2d4da59999ebdfa0df2d989c8afe7404d0c82dec7643c6e0faecb0d7fb5d44cfba0da77bea14279623424cb9b3d'
                'd41823b02383e0c7394169b562c012b28c5382ebe4ead06a1dca7cf5e2eb816e33129736ce65255eb4ee02028835e4c8'
                'c3f626d3fb1c97f05a7e65c71471188f59c4684f768a9e6c7fb31dcd7726f301e4695d06d52d5d91c80471150117ab5e'
                '4688ea333d44d3d440e60d580830812e69716b5ad30ca8d2f0c7a8502b7068008917039b930767aa9a4a54b59e24b6cc'
                '89854ef9f430a3ea6ec8ffd9d3a14171011aa8ca53c77293ec81ede75de60fb193b427b2dc67f095496391e31cc0d75d'
                '53818df88a5a10edff994aba36f4d6922ef185c543fbede5fbb445bf84dd2d99d6cc8c845f390872ee5a6ec08359ff38'
                'd41e0017a8ff20c720bfa1697435c5ed16a852c77150ddd9333dd5d99c53ed91d1e3dfd4e1f5f1977678c83bd0c17411'
                '09500c71fc29b97ade88dd1a2e95c15cbb10748504f1d54abde13fdfb39eddf4cfa9ece08fdb9a0d54c2fcee36d50676'
                '8414d393ad6a4106916b213dcf71a028da5fd43b6f115acc6f46d406f9ac36c305617e76e22225b6e79a1b1ec82005f4'
                '92d08692a127eb77cf798dbdbc93068e70e128baaac1129bd69736b88d55361fbc4daac8a8192b59199f802f8b80f2c2'
                '875e88777a823682255730c0e0d3260a1f6779b17c806eb17594a19fc681c8ceec7e71eb3a4fb3d276a988fbe0563bc0'
                'e10d34ae24fa0c17cbe6b3a2833e02e44e56be07ec592e8bb24f3843d8176320391e13f1be33f810ccc6fa486d3340f9'
                '8940b89e1dbb3bb8c3eb360d450aca8c5d2e097e86a3820e8a9722e9aa65cce411e879be9fb25006ae83cfabb4b9317d'
                '99d76937f15c45ac2143bb3797f14678d60e4df904852a06fd9b1979504db89fdebcc9484d1723814854856b2599de24'
                'd9478fe6e43e2c023f982709a8850059bdf05f0e716fd368edf0a85151f932e4bed7d4e0687a852dff40b116f0164c03'
                '593b09ae2f1f069fabe592f2dc41b19f579b20cdb22527147a6097206c7c76e1dedd595b7e1f0f94cfdb4f55a5654e4d'
                '544946843bc5eee859a4f2eca0c765d0992c6a8d7cbd7b63556d7dd7d18cc067eee0d50d1f7acab5e8588e1efd785db0'
                '2f8473d9712c86a4768b8472dd31a8a0f5ef15e63c8222bbd79570fff5941df891548c397404a60c6ccac68a9ecfaa98'
                'bfb2d5c84fa806f76baae8918a64c9b0c042294ebc7ab28f5a395ae7d359db23fafdad37e0dca95d609636b2f3bc1a05'
                '643251ee389e40403fc75e5657515c1741da629f68307bc1ad220e69ef62aa8114cdd633cb33479af35a671015ed0649'
                '6271578d6d67bfeaec7b3850e3472de32d086e2fba936f7cfbd24603c2b4734ca228c9b60f46bdff9a58f8404d66a12d'
                '2a69d24924d93aac8e802ed5da9fe14dbfe1480d72198da4dde65ad9559259016fde9c3b16a11edd8cb0758bdf2f969e'
                '3445a651796f259d0a66a4d732363f381a691f1e2444acac20ab0e0b96c4618fee33b7117b43cfbac0247072105f34e7'
                '6ca3c34ec4614f08b18437ee01835295a627bdc1f9650cb3ab394d47928af3b8e5aa9e574d1f27a47fd1bdebd49fbc5d'
                'a8ee6b9c897dd23834c82a039f48ebcef771c18301c789073c457af59fb5d5200d0ef62eb055c6c08de0df25b2e34abe'
                '200f3d6c9b1977a89a671668ab4b10ace8e78a10379fbbbbc19364ad7ec795ae26c207329b7c4d0233132d21679fdea7'
                '7f275b0cacf1eb6d6ffe2d42aa0d8a750ca441731d812bcf098032c83a0b5fefa7e86b10205ba254e1b789b59d98cec2'
                '72a179a695ea3948b1597bcf2beb653332fcb5554671efc0375cd907d281f03108bd52add05db18561b6ae5a30859bbd'
                'a23329be4bacf3de9b0891412d85aed9d2983cb0d434bb6be70b43f139be09a02a7ae3461179d19200fa016fb9396199'
                'c181bb3d947f2bca6e2adc899ec2add4faa68acfc400338ef7a3edb8451f0d9d55b8875488eb940fb897c5ea9f42a833'
                'de2bc2592f0a2a4976a55debdc3c7516195d54a0e9035a97b54b6b45ccaff2a32546a394499c7b42bfffd7bb84ea7262'
                'ac8b86951c75009146546f4e4320bac89fe08195b14ad089a6b396a46cc5adc509aef6df3b83194689258c66c18d27dc'
                '006f1adc1c74f47575f64c92d1c772402548a130250bf68f0cd669de41a8218de7d7a31fcf69d3d4365b150c86694112'
                '8204bb92e03be1e98fa1c4e9d2a57ece743ed18c04987d62ef3d1e7f5de6e8d2896f17d204bec7cf2ab6a1645b8b8912'
                'cb085347f9a104c105f76d83da9b24a8382a28403d3eb9c81102e11ffb94d478c4e9598371add165181a9ce70483d912'
                '356aa062b8c0a3cea544d12aac653bd0c797ea23beb8b035c78a708539f1694e72b2f7a4b3ad60f14a4fbfeb118ffbfd'
                'c8f53657c06007cef8a64aa1deccff14c64d1807141850354998cee19758f0c7e386e5f9649d8d6c964a329281b8348e'
                '9d7a59c2546f95f91820ea619da1700de87b9ffffa959a94d7f9f298ddcea6d48d0159f9a6be63d84cbf04551d0dedde'
                '5f3a6b662f586de92d2b6368e96c9311205c5b33c6eb1ac5f49d3a90a0361feac68de73d32be91dd33f00133680a1ce1'
                'f36d73f0fa4eea975e4078ed4c6e6e6e81be55c5da1dea6de0d81dc8024d3c74508f8e64e97834bf6d3d98b5a1f64f18'
                'f38be13feb356785e37fd3e8d1e25b51cb69b1066e6a76296fc1b070694012b4c513eb88fad48e0dd28c384639e73894'
                'af1d0ee58dd2184860cea9579fc8d5e7ac69a8cf85656bd08999c7fac4e6ce811f2f96222d9c45c91df101417e2fe0b5'
                'c84acfbd14ca27109ccfb5ccb4e5aa0f5d93b077bb46221af87550b9c3c53cb43ad525d0939fb950b9973a3c452c4295'
                '2ec4fdda481210f26cbc61b314c41e6ec23f8693440470a1c6e88c479c32158a415ac6e8c21b8c12a146d8977acd7ef1'
                '480248d5fe3c58511cf6bd53e045e313c3dd0367e082b14b6189fdc46334fdd2082548497b95a1bcbfc5dbf8fa112034'
                '4858596f7280939fdce1e9f0262a44464b4e545658606d708890a3a6b1bccd124f6685888f9bb6b9d4eaebf700000000'
                '000000000000000000000000000000000d1c2f3c',
        },
        {
            'ps': 44,
            'src': 'sigGen tgId 19 tcId 272',
            'mu':
                '6cc8d04329178606013ceb48b452c5e1fa48b03fd114fe57afcc79e98c1d982bccb010b7ed9e902e394bb9d8059e3eb7'
                '73f18e1909b8507d80bde1ba46bf51ba',
            'rnd': '866ba26162861c5b3f84fcbef20ba3477df979a4daaeef723d8a647181deeb9f',
            'sk':
                'cc05d76200e3fbbc838e43a160cec8f15f77d0d0b9e5ef1cb235b01e1f18a41accb2d728a560b749cf353a0378c7fc94'
                '195aff90d12bf5a142d275addad8a34853098bc70d223ab23c810c0b54a76d5886509420c6e9b8ac160103e203c862e4'
                '5deb4d5f6b02f8bf6f04089894b23d07d72ee657d21eb7c6179e24ac2655f5724800500c222cd4284e082200090222d2'
                '16508cc6241a1992d4341018216023882de0a891d200491b234c449811184164934682614031c1c68411380a13358a1c'
                'b860893672081511a3a0050983848834468c14499a9049d8b02521168c0c2972d0c40c0b80842447881a114d12956c13'
                '142ee400244236009ab64154886850104a5996451b30701934805c364c23184908a0050a1806e320900c1202021641d1'
                'c00c894050413228a4b60012172610946823848561244013820958002d9c4024248211044492d99640d814261b308618'
                'b84518480524064e08066992a845caa67000c429591652134528c41480c8c280cb940dc9c489032008a4442159a02c21'
                'b88ce2108941286eca060a8c860562b864d94822d82672d08844cb144a0b438909055119b4311a084ee4185093b22949'
                '4260dbc84c40908dd1922843048243b6290aa409d8c6854486708c40904b14618c3251108600183831e2b0659b2692c8'
                '34666214060a084de1380110158c11226691228c0997045a262918384d02056a0a9221cb022620a664cb042ce2245203'
                '3244d12624c9124a99923104232918c60019c565123824810402c41670013630a11805510211a218682437451ac78542'
                'a86024104203c12883444203c784000669c4082e18b63121c26191a48da244508304850228305a242e5bb2445042120a'
                '477050346410958dd91029900004640060d4482983844822427209040c8c080510c8094aa66012111118269208900948'
                '90905c18700c4402c1980c19a1111b936554c064194649c042909ba0254b428e600622a110440cc9901b10265b924d11'
                '37410c080aa4242812932009c0009a32461a836403c9404c2882c41230d4429120242523215008c720518650243110cb'
                '308e11456218998c8810504390691a343020a82518a82d42004502254409c6908a042e10b62420b311a028448ab660e0'
                'b21093440a44429164202e9cc2909c266899166114b3510026261a84815b06421194002286711997848a222961b46408'
                '916c2185015942400c11289b26861ac64d19054d628600224711839264c43092ac4803dbde7c472a7cfebf3f32dac699'
                '3639604c386b5590a1256fcc6310dc76566d3bea16559469e589dce941cbfa6eef9cffe0476da25d01c19d2def283f4c'
                '663773b5b74c1eabce10edd3762dfbb6f029d936204ad35e76c37524b890deed07102fb9559ea091af95a45b67a79f63'
                '15c6901cab98c0738bdc7be09241e3b859499304567ee04555512c97119350c3cb8bb6a9bd19100581b47dc8b444890f'
                'c4776272d945ab6c8701da05a35de116b1c0f1de18b87df0974a2c290432e51a536915ad9070628f33bb403f191cc682'
                'fa664d19cff9283571d08c0ca6f869f85bb5c8ce41e75d8c8bde69d41de7975256aa9216769403d36c1b854a05b99075'
                '8e82f21c2594d2af61517322e6144dee30f995a75300c7bba6cb28f462af34f1eab1e4bbcacb938cdde06bcf80c89d00'
                '488760f0c21a801be0cdfd8c12e2c080cbc631af82768fcf355ff0bdfe040f2d6a37f75bf9b103c708f4fb147a14578b'
                '22429f5643a79227f2c34147bdadfa672c797a5921640da583f53754a4d464f0ad760fe02da5b8dfc283ac1fda36d2cf'
                '6a94e31ae7d5cc3354af4441ab504afab328452e43d7e22f6f5fdf5cc2f8447da68be4f3cdb76963b838cab3ff924f17'
                'ea1837141214c3484abcfac06f8c5fdc76243df37c21fcfaa87fae7647399def9013999d7d2860ceaf0b131d319c23ff'
                '4cf1f01279fd9f278ce9b53989479adfdef1382f3e6451ccd2c8982e3a7dbee656748a9112dea9bbd29461c6187f2c85'
                '6a4d10e537e2e9308c8f2c2fc8541a14977f7d3b344dfd461ed92c31c620633799c316b92bb740cac7d9a9b4e6e9abae'
                'e45ae33d8f4e92fbcf0034d60d0be9b2ae3c6bb82d53cec2f6c6789f93093e3a54081ae5850823d4e259326ac7850a08'
                '7f93af527ae2d6f157f2b72127735d43aca1ffcd7b78b3457092aae53262b5d987a9c9e520922d6c70e5d6b8b76c74fe'
                'f176d4b9e6387e16a0769ec5ad418280e9000c998b6c75797ae9e931fe151e712810d9f951019f88b0716f51c32b140a'
                'ba5557779345a6952f428ba0c696854818d50717d5ab42c3e6988fa781f48de7db7385e490f3987df505fdc9080084f0'
                '09edd6c520bd54963d879e1ec88dddbd06885fd396ff7c0301c2c60a80d4e23da63dfca9958d3ee96bcbba117960e870'
                'ffb7da2326aed883d2ed1e711311ced85a0f6d5e2157365baa3ba0500f775997b904af1f1824f985c58dd2c56ba38099'
                '4145e57e68fbf88d196d364769668190fb70dfc6599f6ca5da69fa101fd44ecce9ff24f1f972cc63d9941d9006c0ba9d'
                '88a1abe362f9f115fb13b6575d8a15f3cfeb97936aa1e6e8a72725d7e1bf6c6d740e86723ee60743e91e647814b257b8'
                'c557e6579d4794def69f312d60dc018e7bcf866d3caadf0c3227b74296d287fb835657a3af3a0b4901c70faf907ba45a'
                'e66ab46836470244c43f43c338d1fd614380aada83cf003445a0bdfaa9a8f385a21b608d68a8df85f39682596bbb8e85'
                'ee73d705f80f50329a5012f292711262c56856eba018053c88b33791a59be97acfbad4369c354dc71a6a7c8ec6a6b11b'
                '3e15aa011e3c1be5e471a01b6969568d1e603eb0744886d972c216b421f9917af8f4b3b2831484458c1c07d4db260d24'
                '16112198dada08d3e773716bb08050591c37f589a8f06a8a0740b6a87db3e6f0a365f73706096697cea2c4e401518a77'
                'b01c6029c78413ccc69f1a4a907d9f5e520dd29b084e344e33abbef891b9f8970d2853ad43e763c63a8d20bad0551f74'
                '8b202388645d06bc4c59cb5879cf82770dc0c3a34f0907fcc6ffdf883ed4a2068a2c18f07d92c7b36f5e3b3a497e583a'
                '126a9e87986ecb7b3cb7ba0a9cd2bb1c1d7690ac38ea44a7f7118cfa6dce2c266a810907678193b66ae15075cf3e7743'
                '2e20c8f6ce22eb7c296ff881e7e1b00cd47bb65fbf647741514ef13e5a9beb3b92c0bd39878de364f2503c13dedc1d87'
                '8ced365b2870e4a8105c261339832085b9e4aad9f7275b604040e88157c4ca59e2d6c089ff873a22b08457210736b357'
                '9aba698c1ade09ec5dd9d2e2b67d437ecd52bd5f96db2ba75047ff640f7408ceda1dcc21be08212334320d78a26fd215'
                '1405dcd73c5b018fbb01757616575cfb68cf0ab500de66bc473670aca3f995fa5be3b37bbd214eb72d5b7288a8bd7c89'
                '83c180ebd652e84bd84eb164d805cfb6087c410c8d08c29aa5a2e62983b04c187e2f9497f4ba5a5664da46fad5a4bac6'
                'e37823816c16f4d43526bb8a63f71c6ab177cdb393aa660e27d748f8fcc94774eac40276759cd46301360b4157837756'
                '84dcf6369deeae2a99031811ea1748d0',
            'sig':
                'c05f75c68c398846399b95c6d902bfab8c39ab5598e7698f20d11d8b5dbfd702ad86e65c37c33b64ce7db45be6400af8'
                'dbbcc5cc85b4657090c1802e78bb8cadf9b4cf2cb5861e96de592ec8cd971d3b11d7aeb4a80de1812b55395a67842ed6'
                '56899719de2d05a19487be25801173b3c42e11a3847ab85f7a6e2485a4355e7696daf015defdc08c46b32edc1f25ac15'
                'b25728059b652f8d14a458328ae02071741dd65497380dffec09f87b6a5bdb681c709f453b750ab1efedddd6b7f9d9f4'
                'c5b4eaf618c8c5b611a94c88855bb60af9fd7196d2fad199871d8f67ce83c91968e3040d73611af3b33c8f86b2e31797'
                'c8edf5b94f3f17d5cf9cd56681eec5fc6dfad5e5faf0d86e944a59dc18e3088bddd68ade5072ef8c75ab8d1d4ad0bd05'
                '2a7944462b40ccee9f68a19a3d61e38d60473e6f0dd038fb3c543bc939d0e728d5b7e5f7e94e6503af480badee6492c9'
                'cb9dc7da5dbbac8421bb3135973c134221d12e7319f558adc129732cec2cc03583f68db2e7272459a83705b8536c9a31'
                '6fc11fce07a0811bba9f5a1789d5e406860a972594c8ce5cfd051cb7e0983a36dac662d096bfdd64cf7a8c18f5416d3f'
                '2eda1bf67d7b303401764a37226b314d8c4056e3a7f0cfd5eb8f77edd16a2e0a2399e2b472ae3aad844e872fe87d9596'
                '5445672b43bc9538ce0325229e4b51abd99148ec9f2af38d13ca008873f0638bd16852fa321c576491fb4c02543a394e'
                '915acb9628dff994148c8309df97267f57a10365f8bfe6ad9ccf775a6466b5c216b8775b9617b610674ba689c9624df5'
                'dd8f55f70a2fd4cafde27521bce745917171d8a245d798032f858585f9787c165c3048aec67306ba9fb3b0a8320bb302'
                '964c95a4b0f1b3b6e8f49d9f02ee52c712eddfb76b93241a09a63354e95b934b211f8212ebaac263a73b8e5e9281caf8'
                '3f512cf933c568908b4e7094bba68eab9b0ce2e5fd8ba622f7748ae3a6bb52233eaba9d9d93017d6859b1ee3c88db2ef'
                '7fe3de74dcf5bd2c0ae1793804d634caeb01edf71e2ecf952c294fe88c2b2fe7c0c77d001553fcbfa5746d58586c72c3'
                '92f64cafc24e32dd99551f5fa025ac145835532de62b6205d6bfca12a253f3719a9c7f2a4f74b76ff5f2556df2c06ea5'
                '0ee7e322423cd928c9472c80e0fafa16365a3209dbb7cf5c666f4e2890788783406efd34a275eb6298dde9f2a03c40bc'
                '2ce109198ae2d15089c4325234da368f574d28a3f4640aca92b2590065c0ca539d929ff084d89111a8c3f05a519af07a'
                'a1a0839b08d1e5421c99c828fe4112160f1f17cfbfdb70af0a858845def235780fb66f38798484dfd940276b40df9d18'
                '136560796cd4513a3ca7576b7b5f78418f31205c0b765f2f57e21c1a78992dddd797fb1e9ff7cb21a447d28d55474bf3'
                'b8c96dccb1ce62b365315c6e0baacaa92630ffa423cb5d8579c7299b86bee57067cc0a1a498e23199178a4e5376973cd'
                '35031418ace628f969a1c63bfc6f982740e2e04091a1a576c5b4a5250bcc87f305fcb05416276043cdf1c7598b3d1c5e'
                'e8a08fe593be01d5c2394522c47144c6889ce812d98cc8f9cb556796d43549b92f771cdc38e6e31d7cdde2ffc9c0acc9'
                'ea0fc226af954bef828f0d8ca7c3f0e28f0a625dcd48954c86befa18e78d54d7e9c64341656ac87bba5df73c30407808'
                '9f79dcb1b334cddd3fe5e0543763c31f85a431fb59f2603e044a91b5e2b2e3d87db155993fbe47d69888616c7c0eb4cb'
                'dbd3f0c89009a999a3a2c476eed80d32f555d4ec7bcd5c4086495fc53b18769f010e828ba9b657768fac535571688dc4'
                '3bc64ac67d064c58fc6ec29b6443fd7bb11d43c4fdf6812c7d7f4bd26b78eab84a320623dc0ac2281f7cb7a12a24a033'
                'e502739324c9e716bbc3264a92dc4a089580a5baf4c7c7c045b7f9478428659908cf7d78401f1f2b66925b6525e1a65a'
                '43c7c2e3b5db24a79cedeb4376821338c0be45620bf622e9d80fd94a6158415dab94dcab443b6630bf6cdfd875caafd4'
                'b3da282b2dfb7e4968491fa4a1cbb45b0e565811f69119c7bcd9ea617ace01a4848434a8b10babc8234bbceb951afc2a'
                '5d0c7c41d633e6cbc915e4d09c99209e67790867bb746dda9272fa571d7c5a3ab9dc420b52fdc5406c3655b7ac283a44'
                '0983b92583ba24da3c66389607e3f201d2f5a93e6db48d12d0be790add350fb2aa432037a7af0e4eb3a69dd7859e6fb0'
                '986ead0e8134e7773d3da06f045c6e50f00bd4f49369c95293c7572c3ee50a5d6a8d478a35aa5e457b39427ab5b87565'
                '72b7880a8548e3d3106c2e2c9fe8e8aaafb69e582b76fe1eb39e386cbeeb274feeafaaef3b984394652c2f8808275b2f'
                '7f8bc20a535c05ae48e486eba23af871e3201c2d2692dc598c120d0c91dd4ef7ed685434083065a2bc6879336f49432e'
                '8abee5fbb8a4cb3f0331fb1afc7aa43d1f58248cc6e2b13cf79b0599764507c515c019aa969515ee231d52781613f8a6'
                '5c5613292cae74ae1fd05727d867a048e824282543c90c426285904d0ef3b13bb6278e6453cbecea872f79e1201a9df0'
                '16b5736df37ba49fe636fd97d3d5ac781385b70f392eeb104d518e52d2c59963ebd66cba3e0714f9ab14ce43855ec71f'
                'd8e2f1345eec037d9b7cb9caf3e32aab23c54a5908dce514967d3c15999bcc8617856377736c36a012760a93a6e919b0'
                '7fd9221cc26336d7085a5ecd1d3ea6b90a0aa24c35fdee9cdcf501d9db78b073804e244ebe3af7cdfc2cbf47c64edd21'
                '1fdffe1070270c6087d3ea263481030774469be13371eca6feb53f4d7448e0bb5fcf58e1ddf63f5f0921940d6558afd6'
                '591a18ae6ce360b1430b7fea3fa389785bed37d950ec875c4f8ed8523a6f24b9628ba8f3376df6bff98b71eba9780a99'
                'b0858aa08b765adc6622880f0426ebc10388171338b34bdb13caf061ff3e07a11c2773f419948531a8f7ef9c8223eade'
                'b97ecfc118dc2359064d0a5872d839f29b51fec9265a21f9cd7fc07ce29aa758849a948426fd196040c7b1cf04766c75'
                '0eabc8d755d083fa3f9899859721294141eadde96fb43889d7b3ca0d9c83245102c2837f9c34f646b6713bffd616cb8a'
                '1283be2c8f7369129fd714389658748030d03e054917bdd147edd9836c09ecc8efc15ae0ff04c06fb22c00164c7727d8'
                'ddecfeb159eceefa7be140565f2fb7abd00c1cd04be40ee4965e92329ba40164797b160fe9d43febe5a2126c830bfd3c'
                '52474e98c960e27c0cf02064e7d5767f0045304d45663688003a6daeddcdf88f1e363a6c89909aa5bac0e6f42e35363f'
                '417478919fb5bcc5dce20115163c72758991989ba0b9d6dee4e8f305154a4b4c7276889ab8c7d5e6ebeff8f9fc000000'
                '000000000000000000000000000000000c1a2b3d',
        },
    ],
    'sigGenCtx': [
        {
            'ps': 44,
            'src': 'sigGen tgId 1 tcId 1',
            'msg':
                '636c19a0652537f75e3931f27c7cf6025d78cc759b8af4595563a320cef0fd67fea0883a4564a78d0c9401014ba1dc69'
                '124b77c5636eddeba65f050db3438c603a7d9359e6094ed43d30e378759bb85a7156635a5137e492f96e439339e5bef0'
                '0d779c03fc4dc076a6c8fc4700d659eaf33ef2713399d7d6808fa6a680f49d3a77e44fcf85ab9964c797f4280e6421a0'
                '14c388d61f36d45c4722af95b1870d9af10aac22766eae7b1512a708f61ff82f25582e8d8e8e442406c53e3426af766f'
                '9fea47079447f843511665645adb228557d54428f6ad85391140696fb100927a7601e319a44f056a81253b14c7566470'
                '35f035b829ed708204ec5699b17a688d2b2dbabe4b58768c8e6e156730892668da1be91a8ebda730c02e711bdc94d896'
                '8d6b9eeebe3e8b1f0ac376d11e31b17607332d8911f5f9c91b79fdd677804f053f3398e1002d9b07a4fa0f8786c2aabd'
                '05e89c2b9918ca254d9e1b5a46301a1a4afd94c8efb75ea35fc6a2db1b466736d44407919b9a02d4fc87985ed1fbce47'
                'd62bcdeef97e020c7a37c69becc7ade6fded561577f04517eb8e47f1c3d9db25628fa2c82c64242a597e82e1b1ed6243'
                '795c38ad2031d679f3f9521ea85b8afc1877884f0a2642359a76464d6a39113dacef4d4ed5f49deadeadef6f99bfa0a0'
                'cbed1ac32b0f33c6aa0da1bd1bb426e368ecdd49fb56e9333bb35f3deced433b346202911c7a2a8a3948a4bf27d89e3d'
                'eadc5cddfad502cd7e373e55996c0f4fcdc896baf211bfc5c9d81ffe24686a7909f8aafb3c1004ca1cf4a3db3ff46258'
                '47c9279252a73694d799edffa01fc222137e49fbc55619f45ae86128a6965eb7d7bf1de78a7df752f46f5256055fb37e'
                '1d4a729eab3a1865b0b1104afa2a0429eff35e539de06c861cf535ddbbc9a66a325b53abc04dab3612bbc7f60414472a'
                '4d0d1faccae5da71f533ec56702a2078a8145e415452370e9f2839785161b9094ca608dc414f7f919da8fef75c4a5e4b'
                '341958bd1e94d056e961fb49777819f32b49a1cf76549100d27cd625a820709b71b0f16b55e552ed757f30d34f510e74'
                'cda618cce5d0fc2584ada3708246d51a344a9a86ece79a4415879f737916ae75ed586c7d3ba5e60c36dd52ef29687515'
                'f2aae9fdc6fbcc39245471ccdc3302d69dcdd8f75cc7c51e486181b820be9887537ca77cec4b42c64fc84500c32e6db8'
                '9672aec2f0c9929927d64809c11c02695435fa49ec99494b8fc8c1ee61ecf5916a43d42328edbd4ec693153696d28f11'
                'b7a7ecb9c0d7fc6b95d6afad18582d3d0ddfdb502db91141efbb21e904df223e76d9478f290271469402dc392eac09e8'
                '7d1a15b91105eafe3616bc311e916d7210dd5a2141ab572399ec5618b74757abec407b7151331cd1fb883a81260a33eb'
                '1a94818658f628f88c67ec2ed7e6877097e23c517d87069164b31869a3e38a851b2efe3fb8ef8e2891f8f957c4818413'
                'f1dd65b08f4e1918d33975e61eb9f185bfb1af5cfa794efd93cba097a0d9cbd99a372395694936ca8af8b806ec21f431'
                '909931905a1e4a1573cefac618a4118b40620813eb811ef0410a7b448ec1cb8e92b83bb1640b3ca24a0f16873a78d405'
                '3d46c8b8af87eacc4a959b97c195248955353fedaa4ed2081ab79ad64d6886dca13cdab24b21c3d1a6e6ff3713575ae5'
                'e564f0c055764218f914d9725991b249ccafee1b7b0aee46f59463ec66cc1cf42af46700b2538b905756bc3967b86509'
                'd36603304b84d94d64a313e1069a6eb64d412bbf9a85b0d0df3aa0555752e909756987d5826a3556b3028563236bcaf8'
                'ab148c51c2db735a3b859a81da8c50ea06364cd0921acbda93ed9a0ee0eb557abb7ae2a83cf040c13a19ef4d44c9434d'
                '11664e79e585728ebcc942029cae742ad3df4a1eda625055b0325605a887a4d5f037bd551629590599bc0a8d45f0f391'
                '1f97d5e89e3384cebb65a23f8b0c4ac65688f2904094c2a9c8e9525f310bba5271e211f34efa5de2c8fde9d9d222efec'
                '1c3b9900426574318a24e3fc164dcca43e75627bf86702f08835f6b5c54dcdace569acfdb0f9c7d45d0a5a50eae618be'
                'b2ae26a0cfd455c8394afa0a39d23be575cee22e0b7f536516314f4e303b3a824030870132437bc798b87d045fdd05ad'
                '588a8c256958ef3ab059e44a9ced81b64e59e83f80946f01f34b87fbba04bffa7cec3bb1f189dc296f0796a2456f131f'
                'b337091ed88199943b7dae45825f4246fc29b9b00d35ee5777c0c11929ab7fa290095afc4abb23359c49e6dfe153ea31'
                '21bf4ec411a4290e3453d9fbb736de225d8f986c9063054aedca54374322ab51bc785007cedd312975eb6050051100f0'
                '812a028ca4a6a971c71ca142cd9ff994a3df0cb7265f4c601b3d123ad5cd668f0d21d73db64f30c83076671a3d4d6688'
                '25351d6ca00d125867b9dbd56fdae82f36de8f33281fcac14cacc539b7b319f7128114befc9d6e9d55ff5c81107d75f6'
                'af1fce5644790a3af4190a0eab6757c33aeb53e4d0984e0535d4ac3259beda56bb70a00f7753e36566e5564aa2a37102'
                '31b53fead43067502e45aa27df701f4a64adb21c69887879d6271538e87d4adffc8ca278083f046e8d0a98efcdb98d7c'
                '1d3fc7ed836d8ed42e4829d89ff45bc63577e16cec3d892b9b3689f85da6c20000b42d44437f57ddf88fb6926a9fa416'
                '03f5968fba8d304a830b6ddb4b8664e4da9478430b5ebccb079cf91d880d370812d47fc18b9d9578f838a2004b5f7af2'
                'ad3e9fa2a8b6eb82b7212c50062883250bb93bc57911237a3720faf7e073ed34ec00460c3243c14d9af8d3ae17cc99f2'
                '308274389466f2f34bd2e56a04867a8ad0441c9f1bb3a87ff1cf2c6b056e4d1c8bfe7d5bfebd79099f61c0dac3b31cc7'
                '64d81d64e924f0aedd72f60d7091550bada81d204dde63eda906c30b6285f2e8dc9dfd5a79fac5a81ecb3962ab221063'
                '6d2260b59bf9646133975faecd0f7917d5a12f80f5c22d0e5eb919b140978508b5911adb9dc78a0c1df21da708246238'
                '7c7af9302bc5f487fefe7d25058254513e68d32f47f691ced25b46e94a2b0cdcdf1f3394e8c37188c162d22f965c6764'
                'dc68d215004157b00fe1f49c4eb5ead02d13826ce631b9117dd3719fa7a1afc6f7949f34fc3af0618b1ac6a1d4ee5c32'
                '0279d045235ef87c9ccf50f1a3e3cad582c98baae8ec4afe59a5cbdfad56e0cec415837176328f833e872146394a0756'
                'f973f7b5bd204885eb4778b3e13703be15893bab3ac4497a7e48ca30723545d158ad16b114f657ffc0bd35bfac0ecb09'
                'b8947c7e1b60030f250bab14200843210624c1ad40bc529107560b3ed36e862a5ceb39b6564cf61a5a566d67875f56cc'
                'fb092d323928f4f24ad2cb127b5e669272337377d53f2b3457fad634ae9c64d269869c3a01f85ed0620ef582814e1531'
                '8b1c04ec32c05398432f2b97f8560040554c619090f1af7620a53728d86e638392cf8bafddb91fcb172c2bb06f7e7599'
                '37cdf1e4d2a70016cbe1a6518b6ac56fdf9b166ef0380d4631333790087b57c6f6c2939dde431fa83e7be7eaff50fe4f'
                'bd342bc7456c5cca6bcf28f14f3e92b3cba6a18ab983a40b635bdb4c027915592587cf9b2e236d984c4d21834e830419'
                'c8ea6415aa24d78dd05aebb205a9178d53777454585b9d30bc4bae901075654f0ee1f61a0669d19adb28f7cc5429e4fb'
                'dd32f8b4d212fabe046b7f7bbeb2b5c7263fdbe9a4f5bf4b2b4767531aa29b3bc76c43c63d8b8feacb9a0fc6b5fde142'
                '7b116eef64ab6721f8354061fdc659143134789ff531d9942f40950c17b8816ca8641974b6cc6f3f0c39f81620be2a60'
                'a7277e366989a7958624bcd3eb735bf04c601f2826003bb06ae1299dc760b8eb13808073a9ceccc88c4074f17cda2135'
                'd7bf76d8a93ee1279a2705355134d6fb1539ad0ca933b0c338c9660727d5d86f177ad19d5bce24c18d29a659920591f3'
                '489cc6554a38b0a85cd2a7ce006e504081973be3271e98dc8ef84559dc0d95e098667678165906525ef8bcf3aab3b9d2'
                '82826727e52959be15ddae518b0ea119c55181ba40d3c3e8be200c81ddadb93d49d0677d265b311920b64bd942c5736a'
                '7999a064f003a2ea008d8317437a7561b6f116fe781ab266b671bde3bdc37642374ffb520e702e60cfe098d9c1e88bde'
                '9a099db807abba75ecafd41e6372cb986644ffcf590f6a54a91eaa33909f158b902055895cdc86371e556279c4d77f79'
                '142878d6731cfeef93f9958ee2d9ca4e2899f6e2ebdfc1df1b72eb57fffd4d3fad8c0d5aee3d24860241681dbba1aa0a'
                'ac627712162c062183661497a20131fb1751308ce377b09fab0d0ff10145452f0a8e5930f96590de19f1d29fddd09312'
                '33696301d1b49806927177a70b1f125605f167361364657a5202407c7d431022b41a11139b4b2072c46d955fdfe3e05a'
                '6d4fe2eef2482c447dff4cf2265d7327d0578aeb797fa5e8df5a7f40a8e37a9ff467d9f06be17a3f058a93413300cc44'
                'ad3d435a83d4c146404ecf6c8832ce104180f2f3a1206514b10ec03bc6e636afc7087277f4bb1fe75a7a11d1f52b4dc6'
                'c559286aaf944c20b43715a3bc1cc1521fc598d6f8946a69eaa287ee411a4bc6b17c57873956745fde6b0b5e240a89e2'
                '6953eb41f1ff421ce161c124f42a8bc09639ae46fe2aa50b0689d53bb04bcbacc67c19cddae1005fc256b2de617be9b3'
                'a7bcaaefb7505e8220c622f15e05729340229fddde337c402965975dacc6d1297b334123df0bce665af70057212ac459'
                'b35fa533a465e7e8e089fb85b7b879211d441b225f26f2e5554442c61b5dc925ea4e1626e7ef6d9756a04ad1f124aa9c'
                'be1cb4eb4fafa8c9858c2212fc3d892a5becaa6255383dd22f6bd107f0787278563f03a587241295b06b5e25c19d0227'
                'a83a4a649c01dcc1c13c0f61445835e4b1e4afff653164a551476332faff0e3fcc1660255c245c063e69d6ecca63dc13'
                '9d5824d0dccf3d095fa788f8071b2b9828d9c4206cd33dd6b48ccea33ac44cd9406a4d259737189037cdf89afa10920d'
                '0c11b1163c1c7eea7dbb08f56074d658418309992837aadaf0013deabdba92bc812e18101c8e5d4904755c4111099274'
                'b7b6548ccd143b2422cea59a668260d9fd19fef2e98d0e9610d7ae635bcca8959ba36c1e948fd68021019e2b246d21b2'
                'd9b70eba9e2e1724d4e91ca4945c25c1fac907873439910bd49d2000b2e3802d7b42c0808ea25fa32ba157269bab1d41'
                '01510ea49a9cf599389c5dfed142c62c10b84fb19e2713096ea2242ad3caa8319bf243790f90e5caf45fa8a1abce454f'
                'cc2af044dcb93445ca1e358067eaf8e13d08cc1792925701fc2b6bd26cde27a4228c14cbabe63a6809d50c6791e2f65f'
                '31157fd37268dbe1f69c2a17213e1ad685c7625e4a2af6bddc3f806e744e9d27438c1087b4ad6b85ea5ef6a1a316a78a'
                '4380b52f0a39eb429c3480deeec640ed3ece2ec8c85e573af76d98366d92f15d1d6e34b43bdbf67154d9e60ce862f283'
                '9463349574c4f87834f00b00ab401c82406941e049d5517264a28dc1d78b2b026e4376891532c65e4f7e898c4e5b14e2'
                '9abd97146560c70bed49c83b2348f7bd7d595cbf22b63fd77da64111e03ebb2cddb109ce48a85bca039940540a440591'
                '8f69ca0988f293a48be0bdc12bcaa52d9ed27f29d986274863e4b1b65bcab83a676cdb856c59ff5ddae25570f1bfafb5'
                '4f9b1fc27f6dfd6bef3763874f6e86e050ae80da80f5c9bd95ff96d7f2177fc76c0124e1ab08e8e8475c7b3517945c71'
                'b9478770861bb7747dcacb685545c86a6c7b1cacdf4028d71e06f6376947886067ec1cba82ec4289ad0422d3e007ef3d'
                '94e57c9ff5c45dd602095cc8a46579a09eab6f44835c50e91a11703c172ae07acf9b9ce2e7260cd7309f16d2d55d9a1e'
                '4139fdc182bed930c864c6019b8e7618db31253f83bada9b6df2035c8c184de1130bca8d43bcacf5da1f9dc1c279c934'
                'fca3ea223ead290cc7407d2fb4b3506525887b64c272bcc55464edacc6a1dcea21b710dd7d736a8e6f8dffff810159c8'
                'cc63639e64eaeb0c806796a83c9999c740ff300d7c1dc98827df4fae7e3c2deb0c294660681ce951c58cfa46fc916dbe'
                '3b7e3bafec66f213c4cbbb4e3cb1987bae923aaa58d5457bae1d736e308d54e32d8b5f17b7dc7d47d49f35ae98986f38'
                'fb2bd451759b4a9b96f38b6aadc6b2f97954e6abe994a682e3af45a370db6f39872034e387ce37143749ab5e5f61f619'
                '42a68908d2f659300e5b1facaf81e44151eacba3dff5a0035cb8a243c4b4de035bf424551dc12452c414d828d293ccd9'
                '8c70133d64520e67fca7c9f7491e45e683f23f7c5b71b265282ff6ee5c9dab26b0eb61099b62f59b7180c7cf264d82ba'
                '0334c57db97cc5ee79afa059ed7fe7c477f044cbd9481b4970f9f920602b14c889e36d44612216f4b63a51b7ac65956a'
                'a028fb3b160b9e707927a0d0717c29cb674cbf83e988ec732b5ad777b9957010c96a9c8af77b15496757cd4d95424e8e'
                'b20a4c1d765ed43db2f3b62b5405c846753612bf0adcd5b36935e1bec69e66e1862c7d81dbe646db2aa666cd2f7f7e48'
                '1693ecfc24d4ba2f8c2803bd3affe418c0e5abd34eded961323694c40c61db6df31cbdaab726c731ffcb5fb4477912be'
                '6b722e0bec7165d33ea422eb06bafbebdc4b364cbe508beff09845b4b2170555219b7e074db8b829697bfb4315b8c945'
                '8012cc4dce345aea7a7cc3a59bcf4f39e738a3d0ff7bfea9980581183a066bb43de1830151ed8dc56b7e834b62512fea'
                '933549816c072703141d3a5cf9c568fec825f6cbb9e36e31b910d7267f12c7d3627bdda20534da33ac3de5bf1e47d643'
                'a5035e2924916571d84fb5473ad340f9dd59a3d0080d02274f1a5c1f5546806f5812fac00ba52c054be6b0075b294e09'
                '5c3a069fb62e559fc36ace5197b1588856117188dd9d33e4f85aff5dadc5911d6cf4d0adcfd780c99ad75d3f89255f4b'
                '445dccec47bafd2de7d57637f8ef7720a95777f7fc9ce623fdb942dbca1bb96f91f74d24e63a75e3ebcd49b5fa7e82dd'
                'b3285a4395f1429282b227bd9de9fa318a71b57acd2a48049b0ce83e2e68d62576e0c4c54c44e046721b4f2e3f10efd4'
                '0c781ed0a3f8bd78eda7877637b4add2e166ce8dbe06aaa84259738ba236ac238220f3dc3bb88b446d82ccf7ed239fe5'
                'a6f265eb3372f4ff5559882e3d2bfbb99e7599d79a54c4465102ffb206ff02cb87b1b69def4a981bf88d3000fedc476d'
                '35d2f6efee27975c905436cc8eed8d8559870b8598318c956587ff31b0549b87ce8ea094855b5293364ece7ce0fda3f8'
                'bfe1559a6415fbd6667b4b41bbcdab5fd116c932e54c67ae226f9b9407f311b0c8bbfe5bb46d9d98c086e0ec0a7503d1'
                'e2d66ff1ae6cb3be3c090702aebc5c476855b6be9f8d354107789e990aa3b72a724950643a79067f799ee9e9aea5105f'
                '1feb90c19f751b333aaa6bb4eb2d5c26f2b5a7bf1b7c32f8175633bac16feb722c8ac667caa9df19096ce06d721dd5ad'
                '59ab5999183de9e5525a6b7f8f249f1a18ddd1c1dab5d14b4fbffc0462855382d5c2df618a0450fe4ca01c9bf52fd905'
                '7042f3c69fab70380ce39e683b35866ff660ae682a105d0ba3716c4aeedd2fed28383ae8f44ae3842b0971e810f36fb8'
                'eb0b79241d013eab2be710832f9c427eccae5cabee727a7085cb6a68bb89f3b3f49ce7315cfb9c84e3285b6eba685096'
                '722d7103a76454d23cd520b98621d48655caec7f32b5ab3db2030f4345b646a585f18a900f497ee01b19e607384e88f3'
                '6ca024000ed587fcbe814c254570ec22dd59070e1540277acafa55bab169befe2955b331d824fe8cff9fd137c349db70'
                'd49771f74db24820d2fc240c62879c8fb8106e21e1c0b94f5054c05e60f977ef07b7414df8770f987694f292734fe1c0'
                'fd31303a38e22815e56a6f5c4bbfb5c48e985c444799c0e94ba70309d69fbac0b10c1d16be068763fb89e7b9605a407a'
                '9ec9312d0f92cc1a47ef40bf46239ecc24d0b78b39538dc0c66cd614b408d88c664a2d756cde90689756694cc64dd0d2'
                '9d9bc239e6a6c5cb3e9e0c9ffb6371b13b070c16f63c68e7099d32fe1fcc5ed20bd17725ba1493736123b1d5c59906c9'
                '5588192520dba415c17d4d7a1a26eff073d239012dc73a542c2df29a512a6457184c250ebdd1a545d3a5edf468bfa054'
                'be03ff2af01e167a97d6f6c52177baae71b63abb7aadf472fd2a204341d12a23f313120cd9d50d5207a0bbb144a26ff3'
                'e82fc593e39368d00fd800fe701d1a52873b68906aa3dd374a1d4ee27d034bfd2890615c24b25e5ba47cafb70d576f56'
                '8339b5909f9884498bea4641ef0c4dbf8f0d56e0749d8c3dcb0828eeec6921905e3eefcac3db0a7f70d5fab0ef2964cd'
                '6b9c202ee8ce947204786baa17f51e869a366b53dab95bb03c3fae081090b536b240e40bf0bbc6ca91c9831e8c46be1f'
                'dd0b40a560160d4fa710eaaf98263c8796f7f0d514fc91dbdbcc6ae70802c126ee462e4c184c2ea316f8078197a296fb'
                'b18c204e6dac650c5758f18fb92448af9281512e21ed14b7465e827909e934cd5b230c51b154a84074503a2c04740199'
                '72106bcb6ff21fbdddd2a216edda5d9285f604bbbdbac0fd4cc12041abf28ae8747054667bb9c360dfc90b7252f50295'
                '92e51f8e5d7509c677e6853352fe87e945f40bef6fef78a5846230c68137e4d2f5734032dbcfdc7f60c456f35e48c20f'
                '908ca936c7f708d218fa5e3af5698acddae47b150e1776ee2ad3e777c290a0e39c25300c05bfb671884e4951be075347'
                '3c1984ff2c5e35c099aff57d689021624c1d4148b1c7e65fe3a87343d80f9d20514f08e4f2ec01dd6ee1d3ec1e9919fc'
                '9222615c28a49744fd77eb2d3ca3a26c9b1416818cb484ae7a6aed480be4d6cfd5b0e77b7b393568d19599769b7b485b'
                '2aded0f568efac7a9ddc955e0c68d996ee87a984ffcd4b6b097f70392f218b10c8f9b1e57bc4567f35e748c6a43fe742'
                'cec898268b1055dbc44cb9be6ee262e5a33a9df3aaa85e86ad359554a90fb7c33ddf1b91072e4a66ed5b8dda4b03b5cb'
                '3cf1d55c032521ea599f54d6774337512605c223ad9ed77997a119cc92b826020c0d97e060dec9ff02c92fdfa7e20706'
                '281f927105c1d8d4d2363bcc2424b3887efcb97e495f71b877c7e58672aab0d26d3df04540a5fec58be140d29640c7e7'
                '4fa18957b575441865d317048764b61309d20cec0c',
            'ctx':
                '8c1f0f14834390d53e370f974037a24dcc7752b210a6387513ef685897e846e14ed2e6f0548224497cb32ec2cd4a6cd1'
                'fef802e81768b7730f6396a88c0d886df9dde1ac09a146ce5f691bc71947d8aa97f565205540bf307ef0919a5084b298',
            'sk':
                'd10a7daadc675bffe61da485642da00930ca6206c420755a687f6f9afdf547d19dd48d7f417e56ed9a333584e14284d4'
                'b7b354a4a9162f6bd09664115f9bf3649a997870e0609aec65f23fdd5884926e5914fc9a03a0d2081d9234c5a230f2a7'
                '67a0be128f439deb23341d1a67ffed52e6146464c19e662c1c8e770744d8ffc612114d1c1222222664d3102aa23092db'
                'c4305c202619a690dcb26c13040c0a2126c9382e1a0330012685229585cc226ed3844dd12012c224712242691a294922'
                'c428094988422268dc8065c4122e18a14060444c9946285c904dc3c2701403315ac64cd2148da0064a9c3441db288ce1'
                'a24588268448b42051440cc318051ab890193351a3c484609630999230e1246c01879058c82c14108c0ba44023282824'
                '880103117260c220a2c685d8442cc304324ab420800222da8621c328261a054009480c42c60591182242962949482009'
                '266504a52980b42023a44823444d242081a292241017800b930418036ac0286910c9490c220414460512024958406099'
                'b610134004da8045d13660a1266689022400054012a95084344a08b4294b222062802c1cb08419846504220059366501'
                '153161068619b02c1c3904c8a028d4340a8340400316860494000a164c20b1294a188c51a49023212e4b3644d2b80821'
                'c5640b194162026992802012b66011990d400201531472a290246030691b342264964800b62019080952008c53820802'
                '0384c9b28460a86802263122b621a186898302066310250c132ca242728ab20c224671e1264451a82d230321a2202ccc'
                'a8611c498c514661e3900581c01159306e0244601117004bb2404430709348024444611a922d194781c4a0906346920a'
                '304e19280e244842e1308ec2c04c0c974808088283006d082631d090050841419b308ec9c4315416300b875082c2850b'
                'a909d9364d9918666146701928890b1391939089da060823898d5c8444209980d88625002266232048e0960441926161'
                '002d8b986888c26011a1289192445a101064361018380921076580481212b68c084924583009232691c29450a1168419'
                '286c9c82491318240837842292811a304621b820114142e1c4109ba02450a4650129411319915c806d94387062102109'
                '3411013429811084529830c3446413098a0ca30849262909b69184280c11158a08c90ccaa490d8b84d22c38521392ec4'
                'a86d1c1826c11070434208589201c4c2498044655a22685102924934040380013e561e982b8ca565aea3ef00d4e294f5'
                'e7478bf127a82e36cf32813d6a2abf054b56e3d0b1b52e45e11f2b1ead362995c40675ae48304c1bb2534a1ba1949045'
                'fcb52c3e6a41faf37fdf22104f68c09436a0cee08a42faec891a417e0dcbf284172ac4f94f2890dc1d66fdf1ce8246b2'
                'c237153020b445f7f6b34651b3f380d1dcedc4c7182962748c24e2280618cc7d98d45b57af73241235a3c9492eb0b9f4'
                '293948ff40bab03533ccf612023410fc19c3b33986e5c5b4892a657e32f79544aa1fa18271f4b6a92b888c968fa4b451'
                '96f0ccf15c4779e41573f2984cc5c34b57f9d3c758544a9163b9023ad4279dba755b8092f311c4662f33dc7b14f903b2'
                'ab102e4f21d59637d192cb8dd60a650edfe248d4452662ce148a5eaea25664d5fd90b03a41df219633e83c614d354dd5'
                '09190a547e90e9c648902e64aad4e086a9c7b29090658c1524bff42aefd64dd571dfdd2285fe62d9876fa77d885db1a9'
                'd4d0622abc73ba4b929d6e2fc98334ea4d4b2c190c7376f6aac912a38e9241f7d08f4058161d8ffea1970a53e2fa135a'
                'ebdd221470d36225a2a23c1e8922951cab2a0e0a2628991ef72044a5eb715b3c7538655f34fd0f03002b9c15079cc9f8'
                'bf1e17531105e6e8387b70c14e3ad6c9f1d83354903f564e53e888dc152165c6c684868c150fdff73bc39e65350b09d5'
                '4de51fcfa9d43e1a36fd0420642a78c628ed92d0734c30c2a544aeafa81344aee122b2d57987f244ba36c33890234bea'
                'a43dfeaffc8de0edb74393c458c775991d0c120ca1790df28168e3f607c4cee3359014800d8eb6df570d591c9fe5d3e3'
                'b5eed9ac196bc61696926ab48b7f61a41d1d236517b01638508db17ed4834f3eabaedc5b0e31270119f6319670de5715'
                'b99129efcd92c83206c8086459452bcdb9808c114038510055494cfb652526b6763bd58b932e3b5a1fd24ae3f26e15f4'
                '4b609cf97a204feb07ef9af3519795508424a1ecb061a3dffb121bdad5cd44b519fb7c49e9fb234ad76ef3ceb54edfb1'
                '3d1e7ff9db99261bb39513ee6138fd5527ce67a56f2f688aa0437f1c4fc50670fb49268e48360538c0c21454f7966675'
                '1887c5f98c495adefa4089e33fa1806019dcc25f6a20bec3a95ac2525bc5a424dcd0d0ddcf88a59536889d836d2397e9'
                'b72a9df58356567c87059b8fbb830bc490215f3b7fd7f01576f09a815db55b527a9668ed2ff0ac4aa6d4fcee920f953d'
                '292538014dbc57da9b01f3e522f228e6a200e22a31e28db9ccd5e672abc99edc5950909a02fdea10b92c3a1d4383e492'
                'a731b1e9defe6e1dca4625387e96bafe38a02a3ed15b1637a3f72beef52afd2ad74386d7797657c450d36842cca8f3e3'
                '00ba699c5c8ae0f067d584b9ca4ae44af156b3f4df7c409c6a1ff20008b95cb4d20d505a722299a5f96f0857b435602f'
                '166ae8c51adb1b0b65c115193fd66d51b7b4e94fa659d78468fde4c4bda59dd5b7a45d9bd178d7bb3acff94cecfeacb3'
                'cbcc93bcd0c44e064ac885a604f6192030192bcc7ce7bbf8b221dc377f2548e4ef2f86e5762b92c619c63f575ad547cf'
                '9e32e8fb145ad80cde6fa28473635681c97bdccb85d6f15ff0c567df09b5a2e2683ca3fc8096bd1fb6e36df32b4caa02'
                '270ab35d1bb2dbaa7970a6273e2bb4fab09aeb66d40baa51d1146b206be11598053e379424a64dd7ef818dc7a4894b6b'
                '12dccda271a269748e062674b50f762b4401fd54288e46952adef25d30bedff1c8fb153a55a98c83e12fe0876c4f52d5'
                'e9b2cd986b71c67f46e05ab0201fe635582909730dec0dd2a4b1fda1bf6bd7fb118e5490ba54fd01d394e1e1b80b4287'
                'b785c9226190198d8becb7296d85422632716c5e7384213dbc3c27a8305b80f5b3e91874020a24123253e3014f4333a2'
                '96a2f61c859d34e980b0960e4628d2d1b1da13f603eadaa5a6901bfde1f8d1cb92dc0df91a8d6fc7a65736516a3e2fb0'
                '41b535b095df6278a39db66ccf0b365ece9c9317cb05899b90f7e4696564a627cc9d025eda8c54df41cdca82f95e247a'
                'd577db90c50f579ea555c9a4f7f538526925b30fd876e85660c669ff4771a8748fd6b9ad434e19f10dc6e28c3902ba2c'
                'f5516c7870dd03f83d1098142af43e29c6ca8c6e945d3af983ee7c15c3c87044691be225aa422ee600d06f18a6fd3943'
                '17ff10c391cba1789202e4d6853cc27518b849f5ff16aebe26df3f85a005f2a77001a925d1c67825cc64fe0092d90c2b'
                '28541f9e43871f77055bb2fdf0130c5254b03912bcb937e1e0bf2180d0f48a84a2cf093d5270edfed0ab141a608c8a52'
                'bc6c4ba34128ff377a4bb046d90cf79b',
            'sig':
                '1951500245bac3685e1c31ee20418604a0b693fc396f47eba26d6a241493285f9d96a8a0972e031c07b4d56df2ccbb68'
                '8a1733e5882dcb8092eab8055b8f0fcd8becd771b1a95201ff9a8eee6a14298e4165cc0523e9fe223022e92bdd480429'
                'a46d7e0d9e82bc200e8060c9260c05847f5b9e738193749053ca4cd71bba1d11a2ccd3d3f857fb830836bcf0b09f2f8c'
                '4be2e86c73f8353f65c2504a5a6f79e8503c148e17477bc45a3f688ad9bfd7ccb82a1576fd07b715304ce9b5091729be'
                '74f6ec06646fe2e814933b3317d2e299b6b80e8fafbd6cc710e3b4a2e913990b2c7e08c3d300b2c9f62f3ae322f274a8'
                '5e3dc6f2307653a083b3b9134088aeab5a97b5eeb565c12a11b19dbb299dc25a9caf201231bc06492aaf381e49fc840a'
                '3faafa99e4f48ce06c5bcea8d9c069349bb7acb98b74aef15b998994ffb80997b93672cbed2156d6b2dff819d9b58dfa'
                '26d712d09a7dff5006f25e5d1ce889fea8d73b309680c6c473861e9a309a863127eda77f3ab0b8b76afd113555a2cf24'
                '124e1265cea11e4a11e78f58255e3928b12f0223b88202a56ab2174cf0f95c43dca78a99e8571ff088159ce6511278ad'
                'aeb03c7ccf5280099d21555e8d7d96c1cdc9f9cd8c3df20cf5f0757e8a978bada93d336955847f50bcd794cd78472019'
                '6fe51ef4034f59d86b6d64ec977695eed60bec329d236853922f0fb3216a1a5b1c65f27b2111d8da01f2e7ef52f93256'
                '00f7f107b3a78cbcb7922b62681ea86632ec0e249f024d2a91f9c8a004bab1d812ecd1037bed6122ee0989d7011d0039'
                '8a4d9850c5c50f9fa75196dfcd0893cd6eb0c34377dbb83a5186046e803a9546e42785bde21161d2dfa517bf3f6b5394'
                '52848ca071c7ae57f15e7a6e1af7bbf83afd3131594c8829a870e738ec3aab66a1652967b072c2b0917542d8b12fd6ad'
                '86714cb70eaa71f2bd70b3191a13e07ec8c04b8652e3420bfdaa30683efe94d91390653866f4ba0215578fa737cfe070'
                '24aff1c614a31a34398178a2d6d468871cfb0865591d6a919c9af45d7c441651a754016ec3f137240237d0e856a2a883'
                '767f7907425f4b3faccf3d102a728efcebee43c3e995e54c40a2203e3fa0a4567dcbd8172b6bf03f5dedb47658674ad3'
                '39db2249890648aafdbb4f630d23df6bc0ac13c7b8f206accfb40dbddb8a350572402b62c81b1d7a01ae847aa9017828'
                'a64662c81a6b140b0390f2be3e53592c051f268e842b2a467ee380f3e79951cf8ee23e54f40aa90cb2f18eb3b763f968'
                'a5453c65b85c07fab395b002f16c785419732ddc8b00b720c776d3cdb890a1919adf11adbe680fcc1d8fd4f5308f8dfb'
                'f173fd44bd68052021c8ce8bed130f0132e1ae2aa6d9444c53fe676f85d4818f39707208300cc51343d0173bc100a388'
                'fa6233123d89d3dfe6d469110eed0bc3c9af89e8fd59736a18f69743cc120e4471210e4b2f9d1e4a1b94bbe6d5fa9c3a'
                '4980739a22ebdd0f1838a3ba4137e1c344a887f70b44302a85afa432bedb6c6b24b9e6339ad83a0948a7625ce4be6a0c'
                'a40685dc7ea673e404793f75fa440b8defe7c5784b21c814be5cbd0e0cd5b84f5246133bdc18ed711e88fc7f18a7526a'
                '9ba62670c90fe9fec6f293c6f62deba57f1ab6c6d07fe55334f0250b11624139567ef451c36a1c26691c8856b39387dc'
                '2ab4c8af32ded57beb84bfda47b06503f9d34c9b36fa4521ead4253a7bfce0b7e96928f78f3f089c374b8735eee30784'
                'eb1c47242c447802de5c8d55efa727787493641cd0aa169b18aac14b2121595003ab3213c02903dfc36be579af3dd54e'
                '6f7a8651950f35034fc5c36941f5157508062c72ab95609478196f0cdd23c4364492000581ec91ccabeb2638e3d2b487'
                '7315b1c46d92bcfbd6c6c875708da86a7c41311ccce6a394f771f5e3a1486d5d0797b09ec838ccb0006bbde6f3e0692c'
                'ab845f95e5cd341904dda7f072c510c5c850ed1929594eed2b3427f67f4565ee030176c57371d4624ffe3096f82a83b7'
                'd8a5263dc697a6330061f4c56f99aac21fa126846a24f09e50116ad3e622c1f36cf384cdbf49cf5ebcec5c773cc6fc62'
                'c0cd65ac9320416319c1f718c3a67285d4ad40510c63e3f6c511a1b19647925c2d383eb4a774afd80cd12c5698c6a1aa'
                '0a6158d888da7ff26ae4e70743802232ba6d6477f952aa97f65b16c0f5b7fac66eab502dddf4b4e0836f11a7521e3e3d'
                '8f273459b6afc42e2835249b6ff6b7665a07120ec588114deccc758c2b75321190309881c343600d0d9528b03e004471'
                '2a9f94e6ae6400373f6923238dc8038dc4a1d1c397d211361fe683c96de856a8c9cd0f7135e8a217ef1cc498a0b3d24e'
                '946fc2f464e0e5352bb7f26347f10d72a2970de8d77d99be62aeee801a10af431cfe6a69faf6bf7f0f400c598ff2865e'
                '22c2c3085d65c19c8dc1c09c2565f567e7b76eda51ad53753e23483585153aba59625bff7e1425d9dc87cf7f6bba1c74'
                '79249c187d855b4deebf106c6e00ef40b09bcc578ea9ba1ecc467e49ce6425973079941a380bb8bb3d1e3d734e7282e0'
                '3b88a1febe0712cea5625147fbaeb433e804be741641a313e47fe64d07fee0a7ff75e4e2da7203b95e0d11f4f04cf2d1'
                'f13afc248ec4e068f5d926148e624bd335c825acef5153d95865933eeeeb49c1b82681197f1a3da24a6471543f0ab1e5'
                'c63afe1244cc19222cef14524cd982983391e8ee8cdd42c99e8d5cfb9e47447c5d048ed3e82ac3042d96ed7aa98c51eb'
                'f4507382cb111acecb11d67d58d3f7ecbd1562eae432d5d48eaeef572391026506db7cd46855b36a76018bcf970358ff'
                '392a0300fa38f543123112444fcaa445f17604f23db8753bfcb2414e93390881527834fb303471e38bf6fe6ab773c4b2'
                'f60e2ff286f24d339a07373ef2a19e70c20fe5c305bcd167491bca15fc934041263a62f4d4534d44ec7bab6a79128556'
                'ec475ee99beae8d147b77640447142f59bbb53830b0229a22daedcac05e29c9ef793bffe6aed1b80340be5b01e3f973e'
                '19a9309f68b1f30a7be4364f5ba7e4aa21af8dbecdb125fcaa2dcad014a09a9087b6d0d728225e3ca08844b7dd62389b'
                'bc791d9412f3a520632326a9135dfd84a38491904430d0ecb147f1ff259ceb69263365a9d19f104c2d38ccb8b793f36e'
                '4ac9826baa2b4e5dc604225e3c1f217bab088df18b043102965142cf2df7b69d066774a91d628b0dcd7ae88aae3a0f81'
                '43e77e2623c0abd54a78db5db61e45b05e23f60abffda34e6544d307a0c95773232a324d54656d8c90a7acb5b9bbd0d3'
                'dadbe8f7fa2022393a3c45476c6e829dbdc5c6cdd1e0e4fafe0c2a2d5d60849cacafb2d4d6e3ef0517182b2c3f54577c'
                '839ea2a7dfe1e5eef6fe0000000000001529374a',
        },
        {
            'ps': 44,
            'src': 'sigGen tgId 1 tcId 2',
            'msg':
                '63d8840eef07a7685719883fedf2cfb490783183db2812a5509b6d9cb5bb79a0f65a3e975526829cd80996a0a7adaa86'
                'dc975f6f72ee90a26fda3571a38071edb930ec9778ab4cf0e8a4726cca827f850d101c26a932d1e2f2b743a1176a404a'
                '7560222732b797f9be08a243d18359b37b4cdce3cae64edc571f4f0fa40af98be743ef2436fad2eaf4e70df70f280142'
                'c6e8ab10f6278e6484582105a28be0cc00b16bd3c5209b265cd20b594bd3357924f19b85d6f93c5317b444d1212fbc00'
                '4159ca44a12633616d8209327aa619c92a43345e8b2225caf60df9f98209a8660586ff649c60bc585026a7fcc4336010'
                'adc6dbca95c28641be67a55e7e8488157ecd66dbb6c68f050dc9211263e3319b6b787d0b1e27346c61b62b2c66c92272'
                '390be0f6cfcc892bd1faf1ca2ee8f8e9930b28a1f6c2205fc335a840f26100fe944ffa5bcdc5a6941974cd3f86f8a10a'
                'f71e8d66c8b6c13366adbb7560a3a09e3978c2d0f2ef082071f057b8f6870d7fab09e393ff3976561fed4bd5e6188471'
                '2dc3c693774c13dbb18da03f0ce120b183a18ee515ce61000c391c05cab9ae1230649a16',
            'ctx': '2a3cc9c6c9a2127bd490d48f7338cda8870ac989a853e11a',
            'sk':
                'b35d32a609feaddf9076c887d3371f22ad1a3e6484cb2ad6167ca69830971a893982cfdb5528c70176a4f2d2e858709d'
                '14e25cfa5f9ccc5f8156db3fccb3533f18d203c2e29bd07491c70d99ee60f458bf135b79262f7ab68087bff7df7553b7'
                'da7f582579d9f77fb99cdfbf762b9d2d0c3bf76cea10c3a62e6c82eca5fa04f094968d03400a53426689c645dab82913'
                '882024c191213891c3280c82460009972c19b00c59c83150920953888d64a24509306c21a94d1a4448db0840904480e3'
                'b28dc09425040391c3a0719ac6300c860c98b048e22868d4b631c4b8500a36104932220c380aa00269d4c28d2081099b'
                'c6295bb44c62407101388e49906062a62504132914222e4c086540482113a660094926db942c4a1041a3966062462849'
                'c84d243044a082085c264acb26414bb881e404669148465b0211d290688294002098291ac041522862d8c00d58066de4'
                'c069e4260591020d93246100138a1190654410921a244d0b28701a35725930704b0280a1224c0ac34124916cc4320208'
                '12489010421a13221a08499148066220652208281c199218297254c20821188d8b326a40088e522288db16514b924103'
                '10250b2352614421234281621424009025a3448e009830d8b8088a3481d1b449582664d0064a119080219705e48271c4'
                'c261ca04655038455200218104500131820c06412093442022851b278e21266419294cdc208acb1861641480cbc84991'
                '9070a2c271c42030cbb884c496450216620a992c00076ce2284ad8b8694c48660419014ba6601b384ad13252d02626c4'
                'b00c0b244a19140552000c0c20815b042954006c11a389002571ca1051180612c1382a58120250b240483440518630cb'
                '4209483270c3228dc11662da4668a1284d03491110b22d5b968848120d911469c40484cab080dab64159188202c52d94'
                '2686648409e31889c2086d4c060dc3c64824c78114a6281c04500845688a2660032231c30671e1289123387019397010'
                'b10d0bb3209b860949422d44c420d02602e4c64d21242adcc25104a6080c3364d49491c9280602918110438824c571d3'
                'a88c60103080c6914bb0801a1610012730501889003949132720623226212164134300d0c02513126422422600340984'
                'b4808a90689c947109c004dac000d9b205c9c8045aa4088c288621c22409b3010389059a988440a80840128a2280484b'
                '422dc12645a030421215455a1884a28845cc06706434301a0020e41080d0308ee4aadc7cd6ab0fea695973864ae9afee'
                '72c7061fa99a5fd409594a5810b351c2af4e9d43052815c3b8cd87a36544a83a81e9af4899eaa43e6961b56a0fd35a0c'
                '308d27c2cbf2ed98db9f7c94562a36de5b970ccd9fa39c6eebebf19db6e6a2940dbbc599707ac0b76a5e311e5d317d0e'
                '49ffad2803e395ef1080ca5f64274eb4cb34e3df824f67bf8fb71ce399368bbb4e8a5e7160bf9e2525e5aa49390e49bf'
                '5b3a136fbd612631a39e775a26e5e352a71e8c1c41fd97ee31e532c14ed26a2443977a69a77aafde4ea9c12a5bb85713'
                'b0dd7028d0e42cdd191db83e26e08da4d300b3c6d6da769a307fbf886ecccb27e604faec1b4fc65cb3a35aed20bc7c69'
                '8e87fba7a6e2e55e3a8206e6492723fb02194c36b916605d5a9d3c4c08b293961f007098ab1243e6db412fed62268cf2'
                '79a56339b7c379bbc6d912363d2e147b63f2b2236e0bdb9795e30591f4f90aae12a1fb27061ee2a2ee1011bb29f74c72'
                '29cedde41e6d77e935ee564ef514fac796cbc56b899a4c2a6f2e701b82fecb6f1b8b5e247d100374e433bdb0ebb36262'
                '82ab13ec41d8002042d3a4cd414c546b1c7727aea1a8979bc5285d892772c5d90215072833ed88cbd64d2c2df24caa46'
                'e024f501be08dc7e0e9e2c6476fed80daa995e902a2065e96b0024219e48f38d3052456dfbe70eecec035af62ddc9637'
                '4cc5b4713d1467200fc80dbe07fb0171c9e5eee44ea1b607579ec66407734c062135da09189d62dd4939a62f684e7928'
                'bc02be2b576b33947622a43aaa5fdda39c3c08a585b73b2d80e9ac56615c4179301d74217655cf93714e09c42bce7989'
                '324aa27142c0e3208be23e0cb56d7f7e820ba0c1056195ee02c311d5cbd6df98482b6cbbe64397e69ff9ea8e98cba79a'
                'd86a3ec7714d7fb6b167a70c89baca27951e29317ce995d3a679e344e850a564fae312cd4319608457fb464bdc558510'
                '2caa1cf605e54b0e36bfea7f06bd4f63ec6b14c521ad2f48c168d1aa37fbf59b1e7e315a603b9787b708fd56a8905f98'
                '8eec74ac03fd2fddf5ea3a554414209b38d546aa5b1821185b92ef7fe2eed71ab624d41654ec25abd68712057cd45a31'
                '50e7be58df42e9a84ed819459de00c3b9c21646253d1c9cdcc9a39cb09f4ee65ff22684753b950b9cb8667818e19ed15'
                'c58f0a88b3c3e19fae6280e6e8b81b609b4e5475f0cd2b13448787dc5c116025e1167f5ff8a4a3a3911e00f160848d35'
                '418b5fb5d45dfd4ed18d934eed50a788a33b84218cf262078336d91283f10ecf6d21958bc3ec260dd995f86c583b0e99'
                'bb74e78ff942f40f414da1730ae9eef6efd1424c1039dd6ff24785d94b08cff79c859d914c2b1f21450124c58642193c'
                'e9aff384d8ebeb93b3ee4e9f0c27719e60de27c7698f5c4f75db82b72045676844d5dd9b34442cf9be56a0990230e37d'
                'a1c4c18ec65db8f825158ad6524e49f75347c8c6771685a8aebf12996fc9098972604a41498f0b60b4f2899c611526e3'
                'd806df385e7687e914fa647896f7e139ba36198c50bfda6976c89a0919c0f191f85f85efa40716b14de4c9fc07cb014d'
                '9f68c2cd21beca579641fc3372c4651137da6161b90926a8e7221d34153886280588557febc8ee8a74de11fcdd98c108'
                '63c6bbc20c6d31fffd535a884cd960625139a16b083b61ab164aba22c26fcd2fd3eede6906a14ed1f0572bff6c821523'
                '33295952bf7b26d0154e5a5ac18816a7dd215b57060124858ad42b2e4b82857c29de8fb5489529b738bfe2123af63b10'
                'ef550bbe922d18409d354a292ea03c6ae6163fd9da7424e316b706a69a0e722a83c5fad43cf1c004b04fb10430f30380'
                '635eb3c08a4fbd57ef67fbd8fb7e1cc47012465969b46a89ac1f8a99864e8a34add10e68f5cf5accf4f26e1743babf03'
                'a67ac9474bab1eedcc41daabfacb267a212b80918b2cf101cacc5ef79fd0bab083f2070d255a5d9e51b1f9d6ec5186ac'
                'b724d07189bbfa789a576ea370494bc51c1cd301aa819985db7340a2f9ef929b6f6f54002d152e64420ca066ef084a64'
                '8abf5c581a94f3d1b92e50aa350ab605587a7997b16e50ed6ad0ad0156ecc9adb982a454c63a0b7f130188faa4874780'
                'ccc6fa0eda99d0366a7743d11a1efae67e2ac01f7eed01ee4fa0cdad9cff296dfbaf32b80ad42ab76bc27c70ccb0ed00'
                '69155a7b741473479af3c8a4fcffd41af74a5d7d6977ddcb335ad355f51586818453f84389f84652e717a4d0ff2c9332'
                'a522456d9889079a99f2b7f6935d61808d7ae45f37208677d0934de2b7a5f5275dd0b65b4397dfbfcab31e80e681dc97'
                'c1529a83dde72059186984544ce5eb34',
            'sig':
                '8964cb35b1d94508472da9e4bf9f77d685f2dd1f4af5c660a1f4423d7b5939e6db3952707d576978f1fdfca4d9b0ceda'
                '12e5ce422632d310c277806533422e6cb209d387ee930edc4b4065f215f309b92d14ce443044c04d3e7ca92077e9aa94'
                'cdbf91e1059d620198f5f3fc7207fea671b155b2c5f9f3bc0c5e098a8923c0c0740c504b36cd4d417e63c0b0d1e8c885'
                'e1cc18f88568700a8fb1b51f700e612cb7a995c59c035e36252d85a5c35d4976b744770246a935220405706532f0479d'
                '202d069d00491a3e2f9c387d35eaca833ffde59917f3345eba3aa289f703d8c2267251f73d47f790e7db0137e0f2caa3'
                '42d3328ce1a74ad87ec38dd94387467cc98e2635d2205b6702834eb21d6cee7fb21564e473d471e26a3b08865aeba53a'
                '13d6ddf77b2aca8131ed4e87a4e7305097df08fb11c5cfc5e32a1c23375381ba42392aa890180cf74118370202223fae'
                '33822acca68877e0af11a48e9db4344876143f825d5fe6c1a8b82659e61c2468079b0847e796a5e8615ad487c7ab016d'
                '6b19608b71fafc5d3c2b7fc598b018b1ffca8eea79b8c45fb3bcd17a4cabe6b808100f35795f2fb1bde3eed9f076e469'
                '6e9eb3fd860cadf905deb1bbce5682ed1e0efdce27a404bb851b014a27864f648656fd341db80491c5b3ee4aab4fa3f9'
                '5a6f1cbc9491fcf06e95494f320d92270ba4e25443804c170237e559592c625c6f8aab0a5c75536fd7c4482633700ab0'
                'cdcaa5924ac101a831d3006d5b13d8ed0bbd2f81beca17fbea8c30c3cae338d7b4c16789f1756a21596638a0703811fb'
                '1ab35aae7d12477459d7bab1cd795f96df2203b0ea7bbcd9aabbdcdaa324c437facb7a03fd029f86bac43e700f071bd3'
                'a3131f5fd9336703e8a9115d65b734b0e934b586d6cd7e0066d07f0671d5422078f784d3f1367bc5cbcd178d952d3a5e'
                '6cfa871f0dd856d1098d75b43da36c380b2f9fcde0438c1856dd6d9317c5be4c487a6d82419a6b6304d6e14cad5263ab'
                '9c20a6ef47814b572f4a3bd6b6f3fa6e058e42cb9c6dd31e13e7e618a40fca59fa786ead95b8dd878b4507f9216f67e3'
                '0a932668d15eee35e9052acb1929c8a9a2734076059dd9ec59f13faa33fe80860ea066644abb2b3cad3c8ee2d00ffa20'
                '620e44c2802f72b47d7c9fa2f81407d66cd370f7bd15ea76e3aa99953f8d424b2c41ccd7e9ed4cc7d4d23ca888011363'
                'a2467f59bdaea553818c63a97ba19469c33f8fc9a6e9070f08821dea17be91260776a562f7c1793610339dfa6a7b49fe'
                '04dee09876749cae185af8c2c6ef805f8795560bfa0dd7b901ba214c856c72348ae0230befbb2527c9eb44b918d0b8a2'
                '2383281aaaee6612fb7aeba6d39719e78ffe8fff90a0b40a0028b132028d7de8d837cf08527e93c103b526f386ef0c42'
                '307ba2c87d9fb8a4847c96696dbcd2606cb00822f7a85df2894fa6134a2209d0bca9f071149a478ee3e6c44052b3b8e6'
                '9726b8338279c7dfa7f21620fed7112e49d40de1aa987622ae4ffc3ee4f19d0f08ddc4c0f1951c62e316c74b0c97f0bc'
                'e0aa715a877871784ecb8f9220f61894d3ac8e5615d64570025e95810c733386efc2a921d12be29defda0c91c6943b3f'
                '6a963754a37a374dd181dce5c3fe84e33f0474c64c9797ce11d66372cb73c563244e1f991d8924c6017f2d3f0b1d9519'
                'd8b330546c266f822c8e65e9421a09c3ea3aa5c3e44dc3b44d7623dca8fd6ca68f246036bdcef5951401394a482991c2'
                '41ffa9737470630ad0a35498ec8a9024cc06f45f4b7fc2a5722897969ffb9ea7f16ae2a10df25d1add6a302a1f7dc569'
                '5551151039ab74c643f046bd0fe961c6ef3f0c0f461120b80ae3ff911f0d3a03b2bbfda58ac27cef537af49f590e2acf'
                '1b1b2baf9ed3c6ef5def1e47d3b036326ac39be7205482bea276b87e793616373136fc48a0cf502b4471b70dce1b9449'
                'e8a4695e09258b170f4ed61e5fe03e24e5f1e293df563baa905df4814296747f74df25ee2653079844ae8110f16af18b'
                'e4f2650a5382af464904368a593b6da6a3670719ffc22d003da41cf3d054bd4dc965b680efba53d9ceac676f050e7c07'
                'a355743d4a27bed6e59344c35dbf428e8bcf9bba25da5f7042b819ac80cbb89e6d9eaf49df5f66458e6e882b477ad391'
                'c0b1057730d3b385f8d439c8c69d62182c4f55800b7d730e957efdd31a945ad0ec101bf01778f504eea311e4d1fd8416'
                '2e4c2edf60e3a40087d47410c0999da0da90b7f12fb497c0218a89b9295a79e7d0e2203adf92f60b59a56fc51befb3ab'
                '90823ecbbb886ea923be654d9474f1082aec108703735a9dc8578046e496e498664c58618bb02ff184c3f232f3aa2d6d'
                'd7db6aed57c7ab4a6f0829015c34e97a227e083b894b1e17741c297cda4c6b1cc3803c3ac0626eebeeaf1737b1cd9ef0'
                '50668c928b4e17fa53f97e3ee0e568254897fddefb4935c052d5259850f013282ae60dfbd52504092d3473682b8d2021'
                'bc4d022c4ca4d04d18b0e7f54d79f186c1f8ef31e73cb268f74c3e78485f31ef829cf7111fd0315ea174d1b78374fe7c'
                '60434a8bb2d12a6e9ed6042f3b27a3d62f387ad25fce5f1848a09f5cbff90021b93f8bc38b014337830a002f5a65aeea'
                '3ed65bc4e621580556836f055a4f5d5342476414e89aebb0851867008c1e194285b4e4c172baf5846e3ed49cb81bbb94'
                'a7436379250520f9f6213fe6e0c1a9568ad271b9754cf87363df469dbb25a3f56fd697ef9d578d108fe21e7216f0bc7c'
                'fc7d54027fbdc03cd40cd0f683a757250fdff5d70c1d444c4905b473ad5d45eae31c7cfa83615611b9505582b5418717'
                'b25b43a4a353deffeb7e3c9bcdf84eb799ac6c8b557d04119f33176ed4b8da2593b4874c35f09fdfa4ee304002f9886b'
                '53bf7bbd8498b04eff38b8c296f2f2f01a501679ef27baca9ef9218a1d13863a163e815f0012ebb89b5b4adb6bdd5986'
                '46d90e133ba41a2e17eed94042ea81a78bb8982bcff0f68daede2743a7bf5e1e68c9f4f18294407566de327b4724623e'
                '5f0ba026ac19cf8cd93d876676104aa4e99f29c945f600bef682d132baf3b6b813e43dffa4029268ab36fcfeaa39481a'
                '53aab1f57317ca6f5e5e7634795939f11a00c611f524b71a2728277a89827499524d81179e4d20bfff6f15d625c6a210'
                '67082c839f48bb5dec44e310a558d132159d0d73dd475f3c18b77c7cc2a24e5a0e342635f5ca5ec1d4dee496a7182065'
                '24835f7729700c279a9df5d9167e68dd6a83e052eea7b6f4ed46a21ed365bfdd0001555d7b8998a5b3d0d7e9fa050616'
                '202341446a86a6b6bfcde0e6001a2e454a4d5f6872969ab5b6c6dbf3131618283e51595a71cfe6ef0000000000000000'
                '000000000000000000000000000000000d1c2c38',
        },
    ],
    'sigVerMu': [
        {
            'ps': 44,
            'src': 'sigVer tgId 7 tcId 91',
            'pk':
                'e1b71cdbe81759a71fb5c07eea2d8747c39c11a3c827c0462129375e1bd28655647223f5ea75ed03344595005e132120'
                '257ff6fc08e5c0523552c17af360bf3196cafb1835b2598c4ec206a48248f678dd819b5229d7003f2df3935ff912acce'
                'd1c0bf5e4c7495245a162516b2a56193569e48e2cd361173814869742f5be497f901903828a4b5cf106424cfbfb6edca'
                'b10c3987157e81fb560ebab8808379da0be272fbfdea639a7fbb3b3ca6ed6e68fc2532774a543a4de2f8a4b7f3af9c9a'
                '2489bb9d31b871ae2975abff7c9a0347295c5b429b59d4bcf129501bed874b0d148143f22b16d391c81a8bcd4c01a210'
                'c955f5aaa094a89caf194a06bad0a19076de270a0ac6e2ad4e8d0e029ff11e712c8f11081f6bdac2589b198360a2dda8'
                '66a8535526481493399dbfdde4c371599ab48cbc889c03b4d238fde70d0d641f68ff2c142cbfeb446b5649aebab05308'
                '5bd85c00f0897af9f6d39e2a7c0e0862c1ee866354a873a0e753f0adb915c1deede3fa8d631596d3a6e03b2d00629a5b'
                '91b33128a4dc9f6f9ce6caa1f7066e9f554be6c44b7b047e6e0d5bcbf34d1e06b659db474cc0075d96319b087ce2294b'
                '53696036dc97a507111266cf0a207e55c3e03214296764b8345add55f975ffa369638db8348c139f1f6a95d0a43cd452'
                'd43019bd3ce4d4af1716165b50757a39c9a08b564d2b26b482efad6eff862c7a84bc916192a6295ee1716df9bc242272'
                '84b1f3de686f4e00a70d4b18301301a3a39e01c37e41b39ac5cfa4ed5586b6c527c2ea6d3517e49021ab22c361e5b7bf'
                '4085a9720326b145c4ffeff3d9455acdb62eaf1dda219ab1e1f71f3ccbdee8003d324645dfba332edec68e58aedcbbf2'
                '87eaaa280ff80e42953b62ab5898486c0bb079d3b09584bb5c30a91c005e5c06a29a96a55aa5c878956898a52cf54670'
                '9c7876013347cca8351ea84800dff10b95369a8640b183986a16da95645dbc62b63acdd735ba6368b0004695d79fab02'
                'b76f6f285c5b3ea930b3ae339e296bbb39e0381f18d2b3c61d2f0093c6d2cceb2c8c150ba00efdd4a7b2af94a0405e99'
                '278d4bb8cf5dba3e5faf1a9fd057966c57a2274353bcb09f66f6ac1f4e5047a3dc73eb43a25dbf919a7240648ed86d30'
                '8cf4d75ee94e6bfc90fe048ad1c88088f014491060f38709e0af3c04796d9aa114c7664bf63ae210546a49f0b998b744'
                'f0f5f72869f397f21aab3313db8780fea7ded484f902f8dffdfab6b7c9609286a8db63a6df152c64f38ab5112bb37e2a'
                '6be94f6b1d3f22a891e980f2fd75674cd9e5f1ddab038233b02e6fbd4e46c3bf26b5b2b8b7d3bd143161813e5fc63ec9'
                'd82b600e451f7766e07df8179d8e3c5073ac3629a4033b4a327040902e52acc60885eb50321c6caaf7fe0ebb6ed9bccc'
                '9a11807f03b768c03a329f1918cb9ce626d6b5ffbc0c64aa57cb4b1d4525d14505941186f1588d528a5b13ab7c1c9bea'
                'e7cec24089d7e5a4caa637e3e51f2c3dda32a2bb036a20c0e7fb482cde98c924812cb3491958f400c53c7587743356dd'
                '14acf2c14d6f8f7d7ae9b37f08c18a9d97de14613e4ae42147ae8f01c0c05c18538b9b081ecaf32a8477742d1e86bab8'
                'db30697280e5671cb9e52c6bfa3c7db585785801a3b1ae88d97f9087b2e64d70056005b855d4f41a0eadfb5615189ebf'
                'd7249674758ca2a5c2872af466bea800685f4deae06b2e92ddfd37293122e8ae314ec5f4c5b9e395dd0f9fc73430d0d0'
                '75aafcedc63088890fb81ba9ec8131706b28e1976d51f3bf72c546dce2aeb84627eff6923998d4304d58f720b365120e'
                '5521afea0fe06b994aa80b16a2a88835',
            'mu':
                '05c1c1aec158f8d500689056909d08cc28a4702d2988052cdf9bfa60770fe6d700ac21564ef95e73fd0fc4f1bd41955e'
                'bafd73e327c5d6271710a720cbf5e4c4',
            'sig':
                '999eb21f38ca9c1f650ab3fe7875386bceff90f4ad0d20ce1cd6356a3c43440648201495551937bc7c5700c3b2bb1249'
                '3f3b2f1f8671713b10db1cd1abf8e876f81799244b18efbaddfcf1ce52dbca9004348100c70e8c58a9def02c8f4972c7'
                '6be6f18edbc5db2d3f7442eeb83c842fbcdfa69b967a5e838587afce78dab5cebb40014b1645ef9cb44e82cfb1b3c328'
                '2ffb69f480f340bbb0d83b687e4f15b98a446c363a13ec9ba7fa2b50d374b0befeb25c4dcc0438dbf37c7cc5412ddc75'
                '678f402ee564968eba16236940b17e547b264ec611659beab8f5ff21a9081dd8b845e4d257fc7dc767911bb110b74b58'
                '77276fda9ca4f8bdba0058a7d6b1a1661d80fe005e3cbb9d8f7deb00e4efc25b431b074cce982234d67136672980cd77'
                '835928fb72adcd045f2594bd4c725863439f26ba0a8898bc1e7a3a1f7b7916de1c4c2e4b987a2c5169c6d0ebb511953a'
                '6a6cc1d835b1134bee4c8eedcc87fed8151ff70fd38c7d2e8233789c52aeb582cb3d65998b098b83165eb6077cdb0b03'
                'bd445d991cb5e2a77a161e9a3a9e5f302d7b7f8cde1fdbc73a492030cf736b8ba0f9e9b77c81a34a4de22a803cdda184'
                'd812a698d628f15e8e409ba7a3d2acea6fa5c782bc8c71e54909a4f4d6d2919da45826f7a38d84b2a0ffe1370d36c729'
                'fdf46bc21268d178ebdbd7fa3aac05c015cc960a86aec608116c05efa6aa99b74f8ca5ef23e2f8ba209b5559889cf0cd'
                '65fdf9ccd1b105bc4f171eceaade17fe0b78f574642da87d79d264c6b7a4bbd34af4a4fe6994692469ab5bed4f030c50'
                'ea1fcdf6d12370c801840a0fc3c8865e5d067fdc2ab11eb563d5d705f157213ac65644145155fb3593a758633eed234f'
                '4cab9fc60f03dcff390d6513702fde5e82aa0b285a6a72ae0413e2b2ffbf53a353f26b390cae0fba85ee5bd9161db054'
                '532d4d231661cf0bae8af019be6b9071911210c1512d92f141fb19ee7d0a5c103fa706e2e3a861ec8c9355d1b85ae60f'
                'dafb2a982ceff9a0bbdd85d75d852a5b6d3fa76678e6f8d2f9d4b530f1815ef3d67801a28fa59721a24d8d04edfb22d6'
                'b001ecb12fa8c94a644b0b72d4421dc37b51f5c8d1b4122ba1e3ced6faa448f3b4fa0649ded7ad0b03fef980c8bf5e0e'
                'eba678b18f65c60fb5d0b0891521ce6dd961373b4008e1214797cbc2a256faafad3cd0a9d9c1f2bff574565f186ff18f'
                '70839bb6c142400443a2a971020b833d1ff838708aab5395becee2fd66b79792587efb66a1d41adfec249ba6cf5a34b7'
                'bbadb39427972ce1872d0c7040daae0c145011389193cae88f97c962caae46900964559c2545ada7734fe389396ffd19'
                '182b671836e268bb878bbe2be51ad8c8aaab9c7a4a407412c7327f63a44018b0a7a14609ad461f4982ef94c4b4ce0eef'
                '8939ac67be74f8cecfa06d11f3379fdd61ec930c58f23e6a936c7c6c38bb15fc89287ac7301a219c7fe57fb3dd369242'
                '49eb80cb88d444c8dc1e162b9fcabbacb3535fa79a5016feb01d95f20094250ed45e2b4014f3b188eb4b4f35733d3301'
                '72d482b17a679d71fde79f4580c372e684571a8592916656a2d9ddfd3a1d001395cb34304aef9a8a5bbb36e268247d71'
                '95d09f81f62c5836500db68d074aab82acedd1dc11fb2e50a4e66f8d4ab3adb3258de70dc09bca5d165184f557749344'
                '7ef0e9ebd5b5748f21cfa7d718a5b8d9105d0a427a92756495d013f2009fc12e3f204ee9b0558a980ba3e8d169cef533'
                '3070cd2307cc8c6a3202d5c4165117a2a71086eaa715d476a1caa7e4a5483c386bfd451f0cb0b4c2dd0c12b3bac8674e'
                '8141bf198eac51e948a2434d4903d412ab7f8d961b840aeba8a1feb2aa35630499a21c301e41b91f642914647386290f'
                '53a8c1e038d8bb1584c3c9c9b593823c4373c995d81332227f3c45ad1688599be4a512deafcdc6efbb7910197d6e78ca'
                'b5185915848fb47c7925194c4fc3f2d6535dc6ccef34eb8a5c044524da88e9f5ce5cf821093dda4d4ddb12ea07cc672e'
                'abedc6765776e0300cf58ed432b52971e09c51f245931daccadd6b4d6a592a3360fac29665af73dac3a851ff896cb77a'
                '55ce0b8156b1acc3d6778d56930b297cb33d88253b66fb38a2dcb7def245c6b60d672bef5d1f7154de17019f263fedf2'
                'fb7ab96c65252723498a1485772258d92eebbae6ab7072b7ac6054b48d2c19809446a121250012da3ed3001c5b59ed69'
                '4d56f0e028e69ef364bad768202fb776b913f708b2cee46e1264564416f0e0fb91f847252eed516e1d344431e0b18683'
                '4c82320da007ba1b4ac47fc92094554fdcc566efc1718345b36ec637bba3077062fc302992a41e3edd51ecd58cf53577'
                'accdff3a700d7c2a94ab0ba085e090b1320726c2331a8ea336ca030355e2f71d2fd70e6958d888c5d0c076ca99d20d0f'
                'da811e70b74a5d2c90becc7f33c608911ea2ed065f8aa505d40293373aefa5c2f4fda651d516cf2db1a3863969246fc0'
                '21b6c415ee357bb4ff2fa7095519c5c54dc68753919b6ee3ff8ad15f3470fcb6d7f833eb660d2925deabe63458ddded5'
                '71ab8d3c5f6f02eb4d1b6507a386f8c9ab95c80400aadd86e2fba51ee1e0778e26d9107374121a987aa66d0f7386a5dc'
                'd5efaadff571885006ad86a8a7a4fb36b8fcbf0a293d3c440458fcfc9856cd46113eb56a3a76b11b9d24d905b91ee70a'
                '1795249e98dc7be34640ed702601288ab659359ddc922ddebff00a90db2f49b6c467f5daf6c244e5fca190bd37ebc368'
                '6b314b627438285817541010003f63660fbaaa94629f47bbaca616f426228d480325caa4fb4f1d4c9a8890b059c393e5'
                'f9b3ca5216145208916b671a7c100b0d836cc4f2f70acf12e4bfcd8d96f74867d2e33a2342b3ae822350d8fdd13da259'
                '81ec3233207ec3cd63041570e9409d6f406f394dd02db30aa6e6234018bd490f0b7dfb8dad948706b2ffdce2493ec86e'
                '90ee02d3f192e855cfdb724ee4c58364288d8d5273b680968201b7722be753e2b4f46c3d24251aa62f3080a6c85711e2'
                '2c459282f83beece9fdabf98e80ae9da66f8327155ab4a7c9afcff53246f5668f6ee9504781d9eda124cb2b75a4d7031'
                '32eec444af66269a81854ffe401111dda644bbe30a708824191e2973111221ac0d3789d5c2b1255447090d5c328c0e13'
                '4ce95b57ddc843c97ba4a05fe6c378fd7abaaf1bc83fb0d451ab9d92237fdff3e12d1315c87f9be545ad21d4e2ba444f'
                '12bd87eb90ac29ea2e580731790f398d11453a4c622fe423d236ad6fcf08f3c4000d195b5c5d6a848d8fb2c0c8ced2e4'
                '090d132b2d2f717378b5dde0f20e12144c58606a6f858c8d92a3a5a6c4f0030b0f122e2f333a425c66789395a6a7aaad'
                'afb1bcbee3f0f7fd0000000000000000101d2e48',
            'pass': True,
            'reason': 'valid signature and message - signature should verify successfully',
        },
        {
            'ps': 44,
            'src': 'sigVer tgId 7 tcId 92',
            'pk':
                '9a2334020aa332d36620d0be264cf0b59324672c0bd6fbcc62e5a0bcb43a096e9cd1c94eff1a2ba847d2dd322472a3e3'
                'd1334c1e645813ad1797683f92e0519b36146c2f424a19cac6db808f50c10e79ef4aecaa52931145720cb592480f1181'
                '671a627413de3e3997b37b05495cfda0652debe2b680113640a0549217be5363ed354bb80fca6ffaac28540637f336bb'
                'df36a8f9d538478e3ecf8c9e41eb5f612f766b0c04fd32c34bb4661cdef281be8a9014867a558d352965e38f8c3dddc4'
                'f7476ab24cc7f206a3baf8e097c88d81f23356ed3e484893c62db0916cd6db8b20a560550ddc64945089ac2237ba6c76'
                '4d32499f5904528b5b983ffe3d351f4be028864df428535ebb5843bb7434a88beb482976e3a4e11c83c7e538bc058659'
                '5706d7be84c1516ab9d87aceee989ddae7279240d6539dd232ca2bfe0ef9498084056189fdeebb79005a757bf81d9b6f'
                '407d358b73c624f9d1fe58ab72e516cc79777820d54b4691893798c01889eafa1174774af9092b080bbfebfec3e626a5'
                'b5dd1ef35b4ccccbe877cc3bee115fde493ac5c0ab2deedc53ff141518b89a9332264984321d6c79e02647b3196178ef'
                '12cc764ed3c2de45f57813cbdd8bf3e54702ba8fb69ad42b62ad3953f09ee796ad8044536e0b3cf5ff7f9ba89f07c6a1'
                '36658ee48e618b1699afb995e3ba50cc472f3603d2a05c0fce3e803b3dc1a83a81b7e8303765ee243555f1a5f2e38a44'
                '9b04b36a79a7f3463dc56026feb771c55b13d5fc7b94be361a4480bc094487a27bb8e0b7a531ea7ba9c6be88906a770d'
                '691da4336ffff28031b4b62ae6c6dea2c044ad8596dd9fc5959b71ba022fe301099d7659a7bc97419ea866431093ea80'
                '3add2ec15d95097b71639a29c2afc6b8c8c417ffef9984558abe8360ff7cf6878f025bb94a1759d569c8dde78a6c3291'
                '7e39d262d4a55eabd38aab85cf946822ecbf6dfb8515ec9272837fa2148a62dce9764f95baf65a591d02965c5ba540cd'
                'aa1a97bf17fe6980764ab0b88829b26d6b10fd049eb79c96bdb2800a99308648377abc8f15727260f50fc09135e490c3'
                '774e86eb41338a5126f4e76f1b01d35e2bda4b0654f0627c28ad586a49af6fa96c5d007158648900c16942a962cfa3eb'
                '5567bfc80c37eab96d49a4ffcd9f311dae0e4e87a7692e157add8b1ca6e2ef567c2d0671a4629cd01b38ffb40338b711'
                'd93381a3dfd84cca98ffe9bae04996e9fd49432ab3cc82e070d6758eaf70db160426631ccdf14511d218fd48ed8aa814'
                '469ce7092e448695825f69a0eac50950c4ff6aba18df592204de37c30487be03815a0212b8828bea37487997dec182af'
                '5a430b5372343e6163f3c08121a216f85dbe5f97e3b743c87554c9f1d7be9fb1deeb18e1071fcc27b6f9a133a9601b8f'
                '8f9afc393e6b861864709bb8e07cd514771cf7c870c3300a7b299a5582edce8cc5ec6991016b4a5822507f13efb36980'
                'b9a225cdfd41f64b65e1fcb3cf2fd4c740152465d93fdd148f302f1bfdb1d64188c7e311c93f6515d09ac0d6fbe969bf'
                '474ede272c6070ca22655557f0b12c002667b03a79cd9cbb0d93ebcedd6d43e9240cf7c1e08d7a40be10e3747057f2c9'
                '608a594a9fdfd479a091457110029923cd90c0e65487ac7973daf84bc15857c90ec1aca8e151fa46cd2cd896f7e81d5a'
                '35134f9801699cb173e6cce9aa7dad9dd3788841f794d796d96857dd3cb289d20c19b2322ae083760adeb359468ddcf2'
                '4c6c787533b88bd69c075870b87f0929ad70985586106bfea769a8703f49a585c352f9db25737f1ecd3fbff1a41706ce'
                'cda842a5b4539d6f8c0e8d9e485c7215',
            'mu':
                'b020b8ed9be2002da798ec857e2229284b7c95196517e52491ebcd47063993658a0ba5f3925a2f6fbbe603e65e8cc01f'
                'e7a14acb38e75455144b48ca52bc14ab',
            'sig':
                '5f017e3d156802cb51c588eec2189ce5137ceb4440fcf6e363fd890b685f8e89bb1513a837e4780b78c0c63ee7f1bf7a'
                '4b1f071a71ff917887c723fb3b7733e47c27c898840454c31a9602e7fba44758a201220b3523d622cce3eef9b5e1eb19'
                '598b4f7db16d184d177e1f2144e3df50ad8407e2cff505d5ff9193e3b7796981adc235fe406e28b541eb239264579227'
                '62c3d0c3c6837b249d4ebb927f38b061e6300d5b1f472fb8a84c34664d759f16e67ca659958033900c96dc7f8c34457b'
                '21b9cae471b4f0bc2c2fbe063c18e7bdde7e228386a033f87abc7a07c6c57b42b4f114cba79d503caed714acdbff906e'
                '90efbf5f833de5b9e224c0c1a8154ce06a680466eb17d80f13a0a30e3ed58f60c7d7bb4b3fff19ee76293d8efdedeb43'
                'ad71d0fe00834a8dc7b95c8bab52f78c0d215bad850342cf2e0b780e10d0a8831e5e856610409a71c698139a7bb206fc'
                '5e4b1503664e6f0c393e6c63c7e6d2e43bdb5330ffe17acb45e764a5942ac46e5da7e6d25c8caf33bbbbdd40d244f814'
                '13a57f9532706b3dc8b157053afae6cdaa2ac943e1edbdba7ed9944bd263573f3b74ccceb68149de857ca6c85ef7aa23'
                '094f9f7a4783d65dbe480bdd848c0bfb6beaa43ebca538d8ca91e64931e5b6df25c45fec6bd8e5d1351b7f7d7dd8c283'
                'e53667f3daadff77ae1cb694c0c61911c681633965f735e8c1573b2c854a076e8a4afec051c5ce6759b52cb11eb3d58a'
                'e05553d666feccca4d320c39bf38300ce88065c026f0127c3c97de156b791522354aff6808e494093815c5b23a0e3287'
                '50859a41f38037f65054ce70f5c829f115ef86f1439a3424457e2f7d64d6f967f7a3b6aaa3d34fe58b8d55db2d141771'
                '0fa0d543f7c4cb3ad7d5b07ab458e98d7773e7238225a4e3c4e0727a8019b9e55852dc3688e90c41b63de2f8e07cbb05'
                '8ac388af5bf25b7c3c0493f59253ba667da19642b1bcc056e2569f987dfc8fc21c282c6bedd49f17da9dc9e072de4656'
                'd0d7862b9cb0a5a3771ce6b13340f391b408977efc3dd8385f4902812785cbcdfe5b1ab87c34eed20895ee91905afc15'
                '64e84ec5a3ab0e08a3ef68bc8b1604d833d1939181c8048125fda65c59cbb620221bd602e883c1025531e5562bc14430'
                '2c25bcf11ab59b590d488fca6870148299c7713d552989c183606f40728602b475ec253ba028b5bcd638851ab65057de'
                'ecb64994810578ae9337cb97dfdbe45374d4e9641cc93d6e8e4ac3afb180589cdb864052a7368baad542b2eb414e7c71'
                '350d742a1f06f523c0a8ce87d31f3112b1e69d8d4bf93cbe2b2567cc7f1eda67a4faad117f1a738640e4142b62fa36e1'
                '4881e58a6aa952b503b9b945035f580bf5e37fdcf52e8ade9c3446285b40cb92c6c02e088b317b0a81510feacddc4d99'
                '02ba64b50f17fc9cf1a788b90b05ed795a23e5a49854640f4dfa79b2dd9be51905e2afe9450d55d8a9fdda2050f9cd90'
                '102b5457a0f08cb4b771735e52c5b9115b44f91e084276baae9370d2de95e8482f9c9be2c647d44c0c28dae7bd508c41'
                '29b912d72bf70688bccc8d6140e4d2589bc019fe5373efb7370e0f62879707bc1d7c458aa3195b737510a48285f7c575'
                '043bbea93835f8c84c1be0d098cdf6dc3e740a0ef47df6e6fc8c66def97f46f2a945af241ce327babe4478ecfdcd4bd8'
                '837340f87cef5eb51af66607240883bc2f9fec2a853dae6bac3c1739d5bbcd164d0be34666bffc18eb46602ecbc4c493'
                'dd83d56fb2ec332ed179ac3bc97ed5ac7ce59b00d5ee7854ccab657bac4b37584e33154260da2c7e9266bf6aad5a2544'
                '8b10cbdcfadee33620c8d6485029483e4a99a70e8cbd1d257618bbbab3619e325a7c43726009ad9c54e587cb4201f71c'
                'c92606cf2426e5359ba9229855e0429fcea716527f26a8bbbe47e4163d156a170204c22c8d74ed1f84e6fbc841ff0755'
                '972a53041c5dec286deb8138be0da123d56d10a9dcd140cc22aefe8ec181bdb9b7bbf093ac32ae9dee1690e773cf8b94'
                '1287e1e6784bb452a0e08efa4c59bb3308e9f43e4b28402abb696f3ca9b2774f92ae2632d29ad797605724f1f5ef9a5c'
                '5f934f373e397779cdd020a0742fa5c5db69af964406d5d58c999a6570d20418a860135dde1e46f5b1c5f2479bce3c6e'
                'edf83bd9eb2e5c0fb84acec8047aa392f75f17d983bb1da5ec7ffa4a79f11ca5947c47d846f486522b94c631db454a40'
                'aebb4d67e3189082df15bb5ce683bacf3c4865ad062c4b81cd176305a7ebbc3744a2a6f425802addbf52258b322cf63f'
                'd27a8a3576903fe4b2f208ff1b5037b0921bc2c80553f176ac4aef0f8152993bee7fd8039e1963603ff96f6aa1253cd6'
                '76ba10c7fa688ed1a7db23413f0e1fa7d4823ea1b6f9409ac54c17e6c8b52c8cde14941255494fc91f93162b4e6cbb83'
                '6773ee690ab7df186a047e2750402fe5c4dada62a65ceb90ece79a264f882511df8b6c0c4b0b2ad0c143d2f2c29639bb'
                '6c8dc8b35b1ca0169cb6aa0945236df4ee22c42bcc4ac296265dd596038cb249e3f9cd13668996d2b0de70d0b69844a9'
                '3097c3d8f70950a08292d636c968816c920f812f1f9a4d09f6c8a2d6adbd5e211012db827ae4614ff65eab717c3036f1'
                '0409a370b4ce712f9a1d2d9033ee798a922eebc18fc7eebf87a43a95f9943db71771dccfa2051a0da99a90aaaeaf1d3e'
                '4083f91c5aebc99053aa77dc69e81b07896183c9ac505d17dc1d6e1a0f197db2f67774fe2bf2bece7786b136e8a8f095'
                'c75a3468f6282038af346cec5e22aee6859aa060044f62e6820605c46347c34b08a21fcabfcb0111eb163df4838cb02f'
                'ca780dc777ccd4b2c02a3742d2e5171481eff530bb641f156176b48943c0a3fbe2358d24cb192fc6497fdca4d7c228d6'
                '514cc443524580aa0078c020c9bace98beb422ef17f6191ee3145639b96f68b2e5504003103d5623a0006ae91863b64b'
                '0df5fd8e979c55c2034b139ada7fd65680e42ddbaaaae1ff47348643e1c50c09703d12312b4e09d1a75365c77adfa6f8'
                'cb8c1dd3670589433a91014f0c9ad340e5bc57358a36133093baee4aa0903add517458aba962a877ed611c0f7947b332'
                '9cd9332bbbee38c9d61f505cec330145ddfe61014da2c196600a30c9a2b73e95a975f563234122e57c8ba0d024ee1ddd'
                '3f7158add323351b24d86990f415000acb6b3405026a5e5b86fc83c0d6fd28374760fed62008b6a78ff082505e167d2b'
                '8185d833ca06ace0cf5ddffe3283979b03d9660d72d1fe5c10b1d0edcabd4f852e38626d738a95a9b0bac5ccd2e41017'
                '34737899c2ccd2d6f4fbfd01050b16181d26414a4b525c678db2bfcfe3e7edfe05193050768196b4c7ccd0e500000000'
                '000000000000000000000000000000000e1b303c',
            'pass': False,
            'reason': 'modified signature - z',
        },
        {
            'ps': 44,
            'src': 'sigVer tgId 7 tcId 93',
            'pk':
                'b68a50569552dd33af9e4e1899d13cc931027982c5e659b546920fba248fbf18c810e4ed05dc2100254b08a2ca81c9ab'
                'c7931ff077c117709c897f8dc5e2d2a1fa7951c64ba867758d8dac47e22b686437111dc79a3b0a0c0e4950653afc6453'
                'b701aee13147c4580f1139fdc432001eee1cc73a2355030e6563687b19a2c69374d8ac490b60658fb22e0c1ab7ed44d4'
                'a944a44adb1e71028d988e30d37780c999c8f0f178844d7a2b7f01d20012fa10a8bcbf291b2af8fef3e2f831bd5e9998'
                '278c2f5aaecb09b7cf729ccd1462a454e5891cbd29678897930b2fd5432f60b0ea34869284cecfde5a678005a56092ac'
                'de579dd173c43057d829ee6ea5a15af12a33202423b03abed6a67eda53f6135a718c3e0421f06bd8922fb60ad10d8834'
                '910b3643f9ed954782fa6cb5bd7cabe7c4039b49c6a200887d70d0f3914ac7f795f0255398ebf148f657215095213691'
                '590df67d5dcfb01229cc385113d68f308e49aa20d48e9a39deef7fbaef1871f36cad444e989dc8b4463118e26f4c8e86'
                '26f36fd2f984e59baf6c37e6b15642f6e66592aed272d8cc4c584e702a66569dc0e93eb5f49a701dc6131e0e1c8f9a1c'
                'ccd01375d54551c0228a0f231e411ebc70e2178dbbcece18695ff8edce73bea307b77dc072ec81fd865b94ce14ede7bf'
                '11b4aafba6f636a6303de17720f6ca49f6025f8346808427b5432a077562d66226ceb6454c06257cdf2477251e64150b'
                '55030647131c0219121a4ab3601bb11b5d9c4ae9250913f77a147a427266ebfedf98466d115376616571797a84bf9479'
                'f1ec79de4742187673420a0b2e540fbed149c29cb2fb0c7044ed14186519a58e8d340f26b26cd57184d0d17e81fd45ae'
                'da14928c170656e0020995e1ceb02872f9ebdfeea0ef03b48ae1e4f63debe62e880dc2333a7eb3eb8fa2c4abcf3b454d'
                '2b35f1c4c8f4f7b07885fa81b1f48ee6b0196129057111f5253dc32780231f21e663a01581aa0530aa2ab90eca52b287'
                'b4529a99b6f4288760551520f97204ca386f9b83b234ed634cf9f896929973e580234aebdac48f475d7fd54f175e09e9'
                'fbcce7d7bc39f1c885eeba3f00de1b019fd96226dfa6fcdf67a2417732350ee555d85dff3b7bc2d0cbb859f3d8d23576'
                '9b21ae2b0b61fbe94d6cbe94d971a5402dcd975af6114130e8727e176d547eea2ed5dfccb85ec44ce37b1d25666f588c'
                '1205e59102e357a4b45a5fa07aca0f744bbe8134778f2f9c0519f021c0fd65cb0fde9e308d1b3253407311f5a0e2937a'
                '10a5b1cafeb8dfc4ab1b7ad2637f3ab8921faa23ab1cf4cf688ac94edb5cdcb3a44483c0b3f620fe01bd347c339c4a43'
                'd2ede0ed1b55e7b169d5d1a413b4587bdbaa2a2daad1c183dad6f8f8a9a55892f36e232d86bf0ea5a149eb8d11fad310'
                '4303add787f67accf559219272f2a1acf8411155d0e4a17587b7291e6c9ee7820e5214cc5d7091e0a66913b8a84d1ff2'
                '6420545c5d084683c6ff1a53a408ae4365bfebd9a015e3a6c49cb0cd31e1ee7fa05a4e9d7b5747862e22015208d6f0b4'
                '7d3791ab8f06e7dc110fa6ad21220701e0261769504f81c5b4bb69d5462f87364c95c39fa069bdbb2ff4dbffcb51da14'
                '34ec588e0ae690155d389d7365d7f71abceefe192cf4891479325f9f4125fec03108f16747c9106b0547a10d218b3057'
                '9eefdde95c5e861491e3cf612a9b46e2b90a9dabb56f933ca9397504ab43955e4bd6b1199789a16efbb30723366d69f3'
                '5b6b933a264858aa3362d9f5c31edd0c5abeeb61c0526620ff4296c37dcc17fa8a4e473a842ae074639ed7f372beebcd'
                '87bee40391dd38eb9dd2ddf525325d6b',
            'mu':
                '6d47a528544c07c68a9ef89b068fd4378476c071ef5bde9aa37c72b4c5ce2d9299062c3973f3315457ba54c01f624aa5'
                'b900fba6bae0ff9981181c85a05e81df',
            'sig':
                '8b5aed5e24d84d28e06e5decb6097b7a81cbda42f8505fc79c6e0335416f92199a8f0874947e936fb0f15fa4542a5fa4'
                '6c48ff5ac334eb2d0f3d7b5315d69c1b87d6a9fccfd94473f4f885724887694112e0bcda59e5d44e5b82abe27b84b640'
                '1e1362a93d6c50c6705bf44b537f957f4d3ff29a870e6143b3062050bcadc10d0249ee31cc46facf89d62e4706d4fc42'
                '54f4c9641df5597bd10215bacf52851ebc3375dd42509cb6595fa72c19a8a36a56a2c20965cc081bd0834874c18aeacc'
                '5f37ad4d7dec97fbb5794649022da69eecf2e9c33581d45fdf0a77895d6b9f380e8a3416edd0d95d70b5a1510ab7b33f'
                'f3040f8853d4f429f495ec9ac79e73bde9276d8641979ebd43b391f5ec1dc88cb65824783433c4e9ec2262803c5a7fd6'
                '68ffa66532a88e52001e24e741276ed77f3d56d68b289b5a0d5b260d492647731e73f353227b57229d97f2d7648c5b14'
                'c3171ef23f4b4488508b910f0a9aa27f6863d543f26910c81d0bde567b18b58d94fd14dc9cad926a8d0e71ced0b538c0'
                '377ba5f9c1ebc10b1209b43a0a0211e34cc331d907654d8b325bc9309a4a57ce8c417c65cd25e0337a69ac59ff39ca58'
                '183f7592b0d45f08929f265cd312e06b0b25a5cd956df4fa6e83785bf5e59d8fd55920b078ba5da68487210bde7fa124'
                '3b2b5c2db60fdc31085f3e784100c4979305135576165ce2d72bf84c5058c89a50a29a828ec4201a110f534f35bf4e7a'
                '5804593e046a681e64b75d4f83a0321ffb432a818c5386f0ac5717e3461c7f2db8801995b4e4abe202d91ed0205860a3'
                '04aaca7971e0121e4967bcbc4d88e8cd305cc55adaed5509e4d567e5e777949d92022b24f0fc9ca20712b139c3b52633'
                '246d90ea5a0868a3e4162051672fbeb77baf4ed069812497075cea56af43cdae3389ac5e3cecbfd7ae263ebfb1336f2a'
                'dd0589009a6d9cf35c78c3c56933e456d297f12b316f5163736e5fdbe8dcfbb64a8b40275094514eec3fb1a23a4e1a60'
                'ceb5124709a0cba05140d2541578566fd141b57795b504d9e6dcaecb6a9a705140abcc055f434e5bbbc45c0f9fae0dfa'
                '9e7459f0a8f05a97437047a651a7999cb6998524370811624943d86f864528e2984ec13e6964d1fc0e56b8693353e5ee'
                'a151d130e9cb742a2215f39d95d62b404ff4a70fc81f5208365568761abeafd9905905a92f6b65b61393cb5a803313a3'
                'ec920412af1d694debcbbc6e744294f3ee38a1cf64fdd8c9472b5eaa538dec95493d8bf11480ceafcb3e453bf9c46db8'
                'f054ec54fc52778198a7b5a5f93030a386fd140c6e84c4903aea2504083febddfc108c86363c90d3d606a8985357991e'
                '6cff1bcb30df8212db2461cbe60b8baa05c6e85d85d0018c47102fb02494ad3de13f6106d82e64a81be9f6062b8825f7'
                '464e80353642bd51a7e367ff9c0fff17935d50ad4eaff6b0f28bdcbbfdee8c4bbda939962da673069beab7e03ec10363'
                '730e36a8524779829a620cf82883084c6f8c59b63ff9cd177f96b643efa3a693691cd45d784e400bf3c802fb449b8447'
                '674fe7f72ad84a02f53843a9fb6619a885caa3b0140231056a48fb0295bdec9030ab1d18e3bcd42aaf8912cc8ea1d74a'
                '26dd87dadc08417b6285930875f079f88576cfc5bd7444ecbcdfac9c9e68e01b1f84ea54871be64d2827f5740538c376'
                '40ae938ab13cab5b26813666abe0456e4eb267cb368b6019bc01f0e5d072911fe1fab77bd64766dc91d5afad1ba2e2ae'
                'db4d220d0f5ef5124af9c0b043a97548a8fc96cc7ea03384d9670937783e84f8ff5162d3ca028bbf62e535190fa405b4'
                '0184d88d3bdebaf259a54f525929d9cc891bde2aac9ba079da69c1a4df495b3fd3afa99853d825f7d4db13af678deefa'
                '058c9c8e50ec6c2592e4c840ddaeecacf7e95625dae538849a2ecdc6599b7d2d9f359d0b35efa0ad1b01e46f09faa2b5'
                'e580446801a95c1447a14c3d1db9e2cd24a65fb18e8e2ca29f54dc8eb729d0432563631c1c557dc2daea99b34eeec585'
                '83acf4e6803899b7695d52cae447b41008a7f14c2aeb350ca450ab53884e5364749035c5998a3450eba813eb5cea5cf3'
                '675d3d6b981a6e3e73cb9adb73ff90dc5d166480c267abd82e9e123163fcebfa194948b74015edd343d6defa7cb3a49d'
                '6e579f3f836e365a76953a564f698ba3c7cc4188103e5d00d15142545bb55551dc6a5aa3c0af265e6106aef780b24f6d'
                'a116a3b11410f24f3216c74118c404d64b5cd9918fffefc8967bb84ea92fa7e92046bc6bf3f035721d4e7b4e7966216f'
                '7b2b1bd0c0fa46c96c60dec2f08cd466c57fd995dea71be60d0da7f46b786bcc3fdd3c82fd7b741396d179c494ecabe8'
                '3f32ce1f6dbbaee8140a8ce1545d5f4f212c8493be5ac4288344a12af78c1d94923c2cd7c5a08b763aa972a77dd6cc4a'
                '524b630105cc34370d72e33eacd4b38b5a0d7d17e2b5bc88acb335ca7cab65972c4c397d2344b55705359efebbe2595a'
                'e8acaa5663addad532d1a7f6b2d9604684d1027bd156485e8732d6831391e6eefa79ae4077953482dd708bf16c410a3a'
                'eec0dc429eedd3c1faad1fcafa2404c05bf60a7294fc6a6995c58427105acac20554198a5619c320b500f8f4af45fa08'
                '49e49c5b3f100ebfcf5c9b6a7535173bbdf26c767e5afc70ceff68f2b90c051a559d91a86b1abbfc68da33126e50fdf9'
                '28e1a6a0563baf12c50c6d1afc494a529f3e0abc20b8cd1f409978a14f45d9c3420f35d64945b7d723ecdddcb332d955'
                'b9cc0e783d38a938493b6861f3439b575c1e5cb575940c1a3a035ae89bd5aeab6a8cf0124add8bf7096935c246246f76'
                'adca5fe6ee2f506fa53ff65b239aea0d5cf41da6434ca78ea0788d753f4ebcb9e9a90ee827ab85a8de2765e38ced4631'
                'd5470ab29446dfaefb4e462d3c177596835cd1bb5fde1d69de1738c9195279b16fdd33e864700c8823bb679c6e4f03cc'
                'f246beb6c0c0486a4ff6b6e3d78154345168411c5171855b70fd5fee639a1190e9f6433717b465477b727824f7662edf'
                'f6b13c26c6be7f38e944f638992abfb86fcb61dd03e5a8a7326269f5b2cb9134dd4685a467103765cb5c9650a07c0499'
                '5321da8a904f6c2198c436f1743cec18d1f27c7eeb98582d5031ce46c821b106e97ec86a9c95cc55a2178a8860bf8ae2'
                '8b06a0e3858edb22136b4a08e37943438537791ac3ae61b1549e1b52a3af850a81b42a51c62e2cf33ee74062cde13121'
                '822a6f599bb40c0b531e5110fba6415ad1d9ad589a9d8a27ad7537fde55b956d002025262f3940415f739aa5abc1c5ce'
                'eefb002d313d53636a7bafb2b6c9cff1f2f508393c577074aeb5c4c8dde7f7f9fb1b565d81828f969da7b1bcbfe8f4ff'
                '0000000000000000000000000000000012223140',
            'pass': False,
            'reason': 'modified signature - commitment',
        },
        {
            'ps': 44,
            'src': 'sigVer tgId 7 tcId 94',
            'pk':
                'd59ec99b96dc790db8120cedfeca1bad408cce8f33d5a643ab1ba4d14ad78bd34826b833470ed23640e475f9d20b0863'
                '0b92c2a9cd8a7fe21dbef134f2a71b37adac2152361c068f16c3b3ed7395d51bed37d604ee18916a0c0183ddf191d9b2'
                '6fc3e2c6aedc4a3f9031bca997b88cf496cd1d028bdbd5a95f2d2b030734138fc336fb821a7c8f27aae5fd79f2e2aeb8'
                '895f62c5a74d0001ef059b4682dae17535e60223232dc7cf73b2c4aa22f83d644e44bb39fe07335ed7f5dab2db75b997'
                'e21c793fc0433fc948925fddd6fa7d528dd3543ba63b786e9628a0c60c3078bdb3a7165b557f4d8b4fb094baa9a63bce'
                '4e3ae8c44a29cf7cfc81aa047dcf77d39564dafe0bc88bc4cb0ac46d610b57ef926015c4f399f436e3376466f7ed4f01'
                '71e4b68c83368298a9e99bc068ee7010e37d2284e2c6e77f5f13c5401e4ecfd9318ad1feb17417e5cb0a0fd0d3bb135c'
                'eb9daf38cc2751bb656734108cf9cd43562808764d2cca48879ed57dde79b03d6dbda91dfa945020ae988270d1bb0ea4'
                '0d36560b66dfccbdbadc8ca195bca02498e7c9c4c6c67233c64a8ec1b34b7b7ce2eef3af947735f9512416afd299c98d'
                'd889dd652cfefa80bf7c11cec956d8fcd8046ca5f82ae1278c44f45ed6f394d5fbe711d2aa304a945523de180e1f283c'
                'b5a90a17c0df59fdfe65b72f46a2930eb7ea13f2199809040e5e65dfab14a0d970c8d8fb434947d320752ec10bb1b9da'
                'c934588afc37f130d5735fac919e9ee969be18199c8ecfcb2d843abd02acee547c413282164cb2837befbfc9260816b7'
                '90002a3bd05d176fd768c08947cb39b7e98365ba22ddddd1f1aea7d2978e2ff97e9e6758f251fffaaf207ae07965d6a7'
                'c074bcbf116cf0d548a4469d48965fb24efa49794edaceffe82c1174c3014bfed430f5c6abfa33a7b269f35817580a5c'
                'eb99d2596c46b8bbf29f769a99ee1b82270a2bd28055de1409c3e6455dfaf75383662d3afd51ba66769fc9d6168d582b'
                '700e1456bbdfc5fc9cfccbd067dd94a4f41065eace7580da2c6d8b0d093c5c1e156eaaf5b9a24885bcdedc4e0ab6f8b3'
                '432ab95cb233129ec903852f22cd71b343f1b80d16f5fde6dc08a6f998b5622f09bcfa20186eddad0e077ca128554075'
                '7615b578537e5af73705553eda2059eb56a3ed7e10147b793404012de973553058941c930c82f56a9bbf3c122f9ac6f6'
                '9b9785974000676e5821a590c47470cc353f9b7c12570b06e254c492e70b8f836fee4997ad659f0d5d3d7cb74381f839'
                'ed02828351691b79bf1e1b36a450afc1a2561e99a5cbf27a95833a9fa8046f929bbde35174c8b1748adfa1e2e914e656'
                'fbc28b97e71942f8a281053390601810eef804d5fc631d204353a9d1a2ea0ed8d8afbaeb01d150c14e1883e236b9a38a'
                'c192307aaf3d57dad1d8e4991cbd44189f0ceddb327a34ccca731858c7630edd662939c658be01ee2b021ae843c4b721'
                '2ff8aef7587a384cdf86be263e177cea58bdbf91e51707374239a532f6bbc42ba274c530cc14a1b2eba2101098b78965'
                'c74b9af9ec71c931d4720703f294cc9d89fe5280049b5a6cfce7a7fa8df8259d1ecd821b47c5d93ff992e8db4c464cba'
                'b5a830a5ab2ca9e4cc6d001b483c6633552f64bfbf8d017952801ebdd8c1393a56fc1848481687f17fd735f7bf15a804'
                '044ddec4a0f54802a5ab201ee5613d2a6671ab0f409f148e4c5dd6a93122c58e52a2a0ee457ed40c32cda8e794dace36'
                '73aac47e56dfaea0ef11621609e471f28f65855ef36c71512d0dacf3ca837f12915ec741803519f138bc46f22afeb8e1'
                '48523a5e7ec2723f355bc00a714b9733',
            'mu':
                '962a4a0e5578c2f9ceddabca895e89ff91ac444d481d47c92a474f41adddca0e0c5a53baa05e08fd97d16cac688fd500'
                '0304c3e0d6494be9e4eb6d5d765aca3b',
            'sig':
                'cf8493d25ddda0e3e4a25e0faa78d725c6d90260fb60c70bf8435d4efd13f275cf0e7f4c86b80936206e1d805d8e33c2'
                '610019c115e6a44562b299b659b670cd7f479ee21d8bb0198f181d30cc5e436fae464acae62b0e8f0d47cdf85270250e'
                '9770b7936d5046457dfd6f5bfe4cc2712839df4434720d3bfb14f5a03eb27d6f1f78e150c63b1de62d78a5985a6a414f'
                'cf8e7a28e49d7b192355b73bc51f4c3d1a336384a555d4c260a50c699c3f98638c3cdceaf16b75875bf1fefbcd1dfb37'
                '58f263dcf338c1c4c9f3df381e1f33c1ae4ffd875aba0b994787c71256235976664faae09e23f4b821bc705998e2012b'
                '77193dbf39b6e1385d6e68159a40f0bf67cf910aeab3a43a08bc71c5965a582bde480026399c427fc696d2c9ed5154f2'
                'a8ecbdd858d4734986e83b8d535ecc3c077bd2095b0ad087ff2991e8c72468868a0b34929b2749253de349eb880e797d'
                'f78eb77b9ed17daa779ed6bc60c24c8c0e21eff991de0fbc2a2d701daadb576af633900f370aac6feac955ddd10bc609'
                '815892820887d49a0f0bd778e686a842de0e04e30de623dc8ab0871f6bb087028817c89d7de1340edc52957de3783804'
                '11efec8fd525b8ee0f747e07fde7bc0189edb14f9e2daa786bb098f8d17a5af3529131f187ca30d0b0e5ea385f6c512e'
                'dc71054e189ddaad09975a2949d52dd9f45d2ccbadadcb47180dee4e28291b9c6498ea78d9aa0591132ee437d49971fc'
                '847642e3683f07a8be89639eb726b4125fad561e25b1b5eaaa674bd0e14f6ea638ce7c90164a67b5f1cb168b6c148d9f'
                '15cff12ec3b473d007843cb7a689061e865bc715d3ae7339b6d5b0f88f382ebad6e008c678dc68c1de77d013cf227ad5'
                '531860d93c69996b4fe52d8441522e0ae86e8bae4913579d77c08e27d5e16f4e66b426fb97a6fcfa085458ee092d566d'
                '9588561daa10108ae74069812db4238724c4862718ceaea42071479685c6b2d1c2eb611218750e859104ff0e499ade9f'
                '5310bb2a228f6b049d87840cf37379ff54c27b209e199aae390f84529b96d76340ee29ea266b72648c7e2c053acd8a8e'
                '72a23e2aaa3f6e8ffe953ec4bdc82bd8b3551739109b138f364b1665f988f9d8d9074817d248be164d710d5eb663e356'
                '639b8812fe0a399f255971fabb52ed67a6fb366fdef2df4f04dcd47bb988801a74d3abe1fd764f014d99218a28311925'
                '537c07fac5f4ad50e55dca398e8529718e1ad140eadac8d8df4d4adb879d95146c7a03d37c3ee38a299d20ade966842f'
                '8d053cd254fe539ed54cddbc9b439d4bf13b4e9c79c0b1eab0c7f20259010e67bfb352437ff2185c27aef77235d0d7d9'
                '4aa5b3696e339b8f796aa05273aaa5bac69f60fc46852566b0c6db5a494224f0677d36d6b4179dca7eed8e8536c74c69'
                '79c01f37f00251ff9cd3c83f9a6cb06b1e5cac739a3790692edba6ecb8eb3c3beba16fe261a872913c383ec52da80b9b'
                '63d311f56e11cb069d46a14bf2f8438d3292f861210976d44f44a5b490109e7e384c6e4af1e83a2df7c452d2e844ace1'
                '5d3c32baa347686400358d30e3c3e20e7bdba821f2e608dcb9cae3c606b47b543696178459be0c59f7ab19faf04cfef4'
                '005052ac63ed94837568be89f06b746a6bca5a3d0047a8bc4f93a74a08d264a6eaabe2367a07d92cb05a2646104b8176'
                '97b1a3e21e8968f825440d22ca65db30c7347f38355ae3092c5f02700709b2fd936bd39e86a6c48edd614e565f189eed'
                '999dabcae0e8f78d7b45efad45afcef180788f92324eed66ee4d507d1af2ddb4dcc4956e80e2a19a6a3bd67a9abce3fa'
                'e71140bd244f4a9bbcc00d876a04e6e8f38f418264fbb04c6737681447e271861e8f1e75edfa32e4aa04101629a4325d'
                '69d0fe3c82ef19377dc2d7e9d771581323d1fbd4b2605df67c49effba7ad15110ea32e32dca301d975437602ffc1fef0'
                'd463184d49bf7f13a46308fb6146f4f238253db1fecd3497940c8368712c46545c2c1b95d9c11f4d7fa01a0567c92fd8'
                '5ab1fd196a65da85c2e54390ca3869762865ba4b90a77722df1642f452785652867e6f4db65a4eb885dc5cd58c76ed72'
                '61035a6074a025c6f8c41e6b600b95bc09008a27824c4040c8f3d25307c1baf68859365d9de36678c7ec83ee50359387'
                'c477ebc7f761e52d51160d3a5633041175ce84f87dd05133aaa6827a370a87c8292ed39003da65872995a2b73f42b31b'
                '024bf84a804e983c023e2fad796283b8cad1934f60a933eb7d1b8835634079bcb64890afbde3284405014a6c85514fb5'
                'cdb1b4e350201968b835cbd5a21bd2f13f2cf0ddc0fc64ac64296a992e7ad229d60c9c2df5bf98ebcae51667d25f3db5'
                '0d9865847476e8728b90fa951396b2f245d53e2f5c4cce27448d66978857f592e593b48e521357d74f8b50c4e2a4163c'
                'c375885f06a3114639f2dfffc77e2fed16790c9d8a9986ae90c283cb83fc620418d576cf0690e2d6080e395a7a90a830'
                '8edb51d02f32a72ee2213c289ef4627ea048d054c89a936134963fe365aeadb54bf2c540c3b53f052e7fe5537221b697'
                'c63474c369083df789d868a49aedbed74a5393ac381b0ca7e15b43ce90067b8755a8e1043b15036fa62907fbd1a6067f'
                'd91bd49f3cfc66e3435b38b839737c85cd3093f65a6f897ca4f55b96f9ffb5a0546a9e79a9a5da39f6b9d59815097bbf'
                '6863ccd25abbd1cba04405b161193194c94097f4a176d3aa8532666312562ee6f6b0f187d64a338e21ee8af5e5f69265'
                'f31880f935072ef31087a2f94484f89f16694c9c4abd163bf2e5e042bda7fa0e9ee88f4c32bb5e8a79478c450be1f97d'
                'fc070270697f50b2e7fd428516892988be3668748680e0d8345df1f83d599c37840b8cf0f174a05d972034918d6b0b83'
                'ca99863d4ffda0ca578d27924497234b51336a97ee5f64019af6dd7d48059d554732082b525aa9703f3f87796d2225a5'
                '78e57e269133ab62c87f8f56c009f64295f55aa1531f450dafda386639a0bd2b4c5ebae76c9fcabb0829503accce9e33'
                'ded645b5ccadf78864af5762f612319555a39bb4c84997fa39836c64c75b9db1e3897b52bfa3e5c7c5ff9711d606d798'
                '3ee8ed3d982575e1ff7bdb29dbe8eed5d346ecc9bcb9f5cc00bcd0ccd2929cff58712358f7bfc2906defd36aac5e1bf7'
                '34dc12ff1ca564c0badb063c35b456c53a13aadca507532a19302d380fdb6cdfffe8cefa5b3514a10e135bc38873d727'
                'b5843010e0af546cd261edf9282ba2898ac302f574742478f36c566ba96bfeb41519485d66848a8c9798a5f1f5feff1c'
                '1e2d404e51636a93acb2b5e408132d36383e4356636573959aeaf217192329455f61848792bbbdc4cdd8f0fcff000000'
                '000000000000000000000000000000000f1c2b3c',
            'pass': False,
            'reason': 'modified signature - hint',
        },
        {
            'ps': 44,
            'src': 'sigVer tgId 7 tcId 95',
            'pk':
                'a00123e39f54f539f8226901defaab28300ef8be125011ead22b1459f5fa26e6bdf0feee9ee6bc97a02ca984a4e08cb3'
                'd9e6f20d794bcc7a4141a9a3a5e9adccd940421bd221a9adc0389b4090eee8b634d0a84d79d02a73dd2d15d4ac0ba157'
                'e23d5ba0076972279fc772785a78ee6bcb37b39f28debb27bc66a3f5097f109c4ad1dfc14224c2cae4709cdb39965655'
                'bc37d3214c5f470848db265fb9e7ea111317c4d58e09cc977a7a71d253882789ad175ca818414463e7a9c0c50ca30d37'
                'e8d1a4cd134390496f37e507e04484935d9628de0aa51dd5d95ebd0876307f815aab11dca193ad4f54f16fa8d1fcb1d4'
                'cee6f131e71f5aeb7a4188ff135109a61f4a6406eb3742c3b56c1efaf070cfef833839f6f39241cefee55b6c9b6cf35c'
                'abd292e8bc84c2cceb90ccc23ef9f65cfbaf23b3f7e5608fd886bb560d0a5f84e34ded2d1720f8e320a9425fcbd42a89'
                'c7746b44f8d9d7e0339196382f572aa5270301456cb5d1f6567eb384d39ed6bda460ca6b45deeb33c8bb9ff7da837dc1'
                '207ac841e4b6c3358f3e03bccb64fa284e71e10e4da766beee1d82ebdeb18d84b980a91c5b7971cb5c5f3b99d739a02c'
                'ea1a9600ce102dcbe6e9a075a37bb88a09500469c08e333711173583b5c60fe71835d9167e22a236da9f2dde18befa9c'
                '6799b750a4a42f7b3117209b5696efc4351a841f896ffb19d2d23ad72194ba4ace7217b82d467181492b1e5dcf96ec8d'
                'ad6a79b94ec5836e0ed0d7d44604c57258784a193a7fdaece12edd5ce101fc4dfc041901dd714b14a9d19de2e874c374'
                'fc34b129295ebc1f7d964848c77821f64481cffb7471287e64b89aa02bec7b21b35ea2a2a0db34d00158b0a49c59f304'
                'a55f43f7e32be8ebdd1c6ef661e7c5f9247927a3e2f1d42b12d37940d3c2b97b0c9c3dd7c8b7ce534f76c48806540d78'
                'c53c079dd2944f6182442eeda4560354e2dd3ebc0def33c08a68b75c56e3c5247026d1d3e09681835cce2361b3e2686c'
                '31b6f4bd88c31a9d878a09ab66b8b81307f96719870ae11131c022512194b6b9cf8368e553de2a6b6876212492980e63'
                '6e2223594b57a74c8befa0314be28733562958ab82e291786f093906700f271641fddd1ffda7d4f8b43ee2f4d154be60'
                '9df149afa918f8eb227eb31112144e5e8422d6390da1c47f3e7d1d3fb5989713ee80ac3ed77c6b1aa3aae0b8eef6b27d'
                'a30e9fd51c3f88c8223ce858bdf65a12218015daa66bf9d9fb6951abcf582194fc534a77dfe624181a44d1e7275b36f4'
                '29eaafc2c97ae5c8f5ada8fa39448a2525750ffaf9b5d11f073112b14cce8a2ee028be354b399ebc0cf1cebff7889e86'
                'd5270c1e06d2b23db838a7aebd761c39d470cff5d933f3a96faf525a7dbe511edb84555c5b84989865d7d7249691969b'
                '3f919d06795639ab9bf19cee5dc43cf9b2f167051dcfce974d8ff6d59a568b796f967046d0c8bda9e2417bbb409bd218'
                'a3219b31684ffa0b5fea14569abc8f3e2e9d08a0e1bca25d2a98ca19baec5bc342ec456cf7e390a21b19a1bed24e53df'
                'b80b48605f66f028c0d926dcf71c94073c44bd852cb06bedd229c5859f740a12922301d1b433b57964e16943a3f7c92a'
                '5173d495c7ba28b0647cc92fab292d853e431e054fec8c43be2eccf45fb115ae0a4ce11c211dbab76173d0493007ef13'
                '38477a1fbc68540007bac9ca498236e74ad42159ba0d41caeeb54e6a19b1e2272b3827a5e12afceca4950926f547e4f5'
                'ad9ef8b436011d583eb7a2fdb983e63f8123358313b0507729e16b943627a087ed53dbdd2a818d369f714869f7876906'
                '9c136214356bfe03f44b05046ac7c027',
            'mu':
                '0b2ca1cd4d77c5b24863a8dd967063c1871a97d56b57573a204c3e7083bae95aaa299b501dfd649ea368db4683c7f422'
                'c532e5ba6caee3a67dbecbb216681b25',
            'sig':
                '0c4d957e08ce9be2777b18c9d41f46b5926ce4a9438c8fbc1c92c668badd54078c310a1725e9348569295e4fa0656d60'
                '3c097d3af24c2756f3c7aeaad0f2a6ec19c214e90c4881a6ba84c516ab923a755500c562ad86b162d37a7ac432efcbe3'
                'aef26ac04d4db85bd7413367e6970fc2a3b3f2f00d7d4d7fd06a7381cf93ec14fb68b5d59385336b1721595154640ff2'
                'af23a18344d8d50c8beb1196844fd90994806d8edbd61d6f1742694300ac000b34c35f9e41a8c6fda896bd4e2fc2d121'
                '94fdd06cddd98abb226732a223a25d59688f8f23c17703d16e46f46e16f0599c0068e939d28e0e6621b17a845aeba431'
                'c87245e39a5ae663b2d697162d21b4e14940b8c0cf8cf01b31173c907506cd2294c3edd38dc756c4e3e4797d80fa8d84'
                '611d0769cbc05612d271f82a5420e006aa615ec99bb1eee04dd1e639b8d12299eafd014eaf71f9bd3cc0a0233d4daa7b'
                'dcf13cfc31e193a4a10999491f96d59d647d29ac2d35eff0f6f0c760653dee4ac260a8caa38bb34d06645bc64a61b289'
                'cbf6597904d9f510654d43cb24ee113e8fd24a4d2e068f05672a90cd1fa720aae7b6762c09baa8ead9eb210e12570fa7'
                '77348693e07b5463c70ede77722b720544b7666f8e294365da0eb801c1d750b93d1b6b9fa05c7cc79c7fec4d24a2d8de'
                'f90849e58f1f5b99b21e33116d8a8c87c19fc2bdbb87e9d703e519005d60a6733489e24c352f393626a1b4d0b4b63cce'
                '279f6e51f2eac2574b8cc301daf7731b9bb1b16bc41ab6a480fab7efd5768b4116c2f94e7a4f0c624f2fd6489145cb94'
                '0b7e4b1f4b091d7a0de62c629ac2258244f58d594b66e174b7915b926898a50ea119b615ede57c1be222af64637e955b'
                '56e2274a3d017af0d12d3c9b60be50b232a4739e3737d2551a5d94882b7b242649c772c9ee7a4dc83fb20e2ab8e33216'
                '32497875a47e36ecff35d8992c814acbf4e73460965527c44106e7691e0c32e00149f3d74c14a512bb27002b9d7f66b3'
                'acc19dec907519b3b50b132b8d680f8b0bf60bb61cc137f9bf7cd43bde24a64ed784ddd8bc024d6bf7ca28f118d913e9'
                'be2fe12e7e0f07cf728e7843ba851a33fbcf2d2fd6981a9c3e0e9620b2b0f7e52325b9dd00e20852ae2f529d95aaab73'
                'fdecc058c806c2567d32bcb9227f6d6608fc4e98cbfc4b755b609f63d2028457a0d40065b9641c879b72608888b2f231'
                'e20452d47c0ab0f0fd8f961e321e5dcfff2c02f779fffc491aff75b85ed8f6871f4dd0935d7430b84be686cf99848bdd'
                '04d054780afcef5b3e17ba7ebd92a02aba63d907ec48800b1860de1c423f2c0901f7b18c71ff1963c30b33050f1cb9f1'
                '556d1c339df3d7d0573fff88d4793df6da273ee3c48ba40c8519d68fddb6766c0dd8a6187e083628ca529dbf6ee74db5'
                'a058ae549e400fcf7e54ca74decc3b70c8f9e947e6cd8a3e442e5866db91b8d221b4aeb518bf858e14d6a640f4283f50'
                'ee223ff167ccfca17d2d3a1f07e2344ff231366c146e7eadb3f291d19c831803d5c7686df6bb9459b8438184f12848d6'
                '3093d0a4cf636cdcecfbf29139f8ab2eabff53aa7dabcf19a42dcd73720cae0e3634270c1ef0e4cc2d0842be08ab8eb4'
                'da0f166057939e49c91a2132a0c9c4dd98a248787ffeecb01c501403a212a642ddc36db7e29fb91416b53dcab940f9cf'
                'c617045fcf5380149e7df205a666d022215abfee04638c3794f2c5a84e56c934faef236312dda4a01346c790f6e6eb9e'
                '444fd131cab006e57e11afc32b037ceaa24eb8c3d9e45d2e1a858fdb84078da9670e80b2254420ecde0fcfa03a34af72'
                '2ec42bd06c786ac2f3575a5e3a2ecb66aa1ab7ff6cc42681b3a2a9392034c05f9ec5e74e8710d5ac80773ef7982aa960'
                'edbd5be637ddcf3fef0be30ca45bde80d247cf27eea0c4974a9d60206627e82037af5e329387931214b3c437e60660d8'
                '3200aad4fb6c04b88f9962cc25eb0dda16bd073808a90484f8e88843ca6d634ea57cbf62d587f0325ad56dfa5291b3e8'
                '3921733769bae2efdc2c77dd6102edc497a64a73e3274ec1263f46928d38cfb16f1d20e09a8c68a07f1d23f73b1616f5'
                '891991b192beb2e9c442fc9990e5bae283e6cdc789f28e45e888109ba12c4f961403dc85d9e1a98813748926714eddb7'
                'bae1401ba233bc9683e5cef5f80ce47ef158b8fe50decf2811de54df2f59fac0e799e860ec24e4617c84d5fba5e4186e'
                'baae332b62ce9141324fc5d04c86471d36c0fa852185ffade2210e90bc4e82b515772cf0f650b64b9ae71f221e0814c9'
                '3bd0ae007347fd422475577cae422502f2cd17bfb309f81405516d3e343540dc2c5332fb1e74f3fd3bcfa4b7de2f80f0'
                '08d832ab60e36a7780faa074b403f837d61f1b7d8b03a9d03caf956b64e4a6423eef3160d7843e5ed697f8b3270b11f1'
                '185906bf2f18e337a225514e973bd66ce6a6d4fc99280d6116ec9c43a5d7655f73b3dcbfbd5c0ee542982ff323a3610a'
                '8400f1b1f54723db4c51b6313e280ab93e4889d5bdd3b37df63e69a4752d31d380818fe00e25d1d49963af36d63a40fe'
                '1eedb20b092eb736d71a9e93decd1a04378c9892be36050ccd8ca7d468cff65e62fcc980ee2b7c9ff556727837214b5f'
                '49fec7dccd2544015050974b44778c5f6899f2f5d6401480c4d8ef9419de9cb2a9dd81fcd8b524fc063dd8c190c1f23c'
                '9e2f0c1b9315b95852929c9666992d8162c0d9de117e2de2b04458fd5cb08292d755eda4b8bace9a872eb631ff03103c'
                '68353b94b134b3f69aee47698aab1cd844deb9fdff947e94ce4a857877a0a4da5c1f490d1183da973fc88fac32838635'
                '1e434550b8a155ad47637133bb8d10d134a848125de511186b591b8ea986bb6c06727829a28cd2a4e5e0e0190333545c'
                'bd169155eb47fe7f7559f29158511d02d0111a651e9625cebaf73cbb7b0b0def0a58b3b18f0fb892c106ac464c9285e1'
                '2809f1f2bbfa360daec9432cff86bdc69bcb2f41ebaa71fd88025997f3cc4d437b194ec283e9c775ebd892e9b911b282'
                'af0558919c4088846f1511385d889b936522799b6e326ff198c9c35c684b8fc69702f658b2c0e71cdb949196f295a1c8'
                '90019e193928ae70787bd6b046283f0f1a995af4edb78f0b88f955ca58f828be8fa6167bb00b263dd3c67347bc4dda70'
                '17c47aafbc27b54959bf3d85a6157a1c8c526045249aa5902ddb48e820c81465c3d2f791d4878b4dcf3c1b16d9c0264d'
                'b4ed07b75973e0b52076cf20da620dfaf2251bd8de9cee82d53fbe1a17e18eb1010f13232534595b6276797d7f8e909b'
                '9da3bbc2ced5daedfb1e303235525ba1bfcbccd4deed1d326b6f8b969798b5b9deedf0121926323d5a63797b7e9ba6f5'
                'fb00000000000000000000000000000019263341',
            'pass': False,
            'reason': 'modified message',
        },
    ],
}

if __name__ == '__main__':
    sys.exit(main())
