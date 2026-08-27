#!/usr/bin/env python3
"""Known-Answer Tests for the ACE ML-KEM algorithm (src/ace-ISA-algorithms.adoc,
anchor [[ACE-PQC-ML-KEM]]) against FIPS 203.

What this harness validates
---------------------------
1.  *Standards conformance of what the spec delegates.*  kat/fips203.py is a real,
    complete FIPS 203 implementation (K-PKE with NTT over Z_3329, ExpandA via
    SHAKE128, CBD sampling, Compress/Decompress, ByteEncode/ByteDecode, and the
    derandomized ML-KEM.KeyGen_internal / Encaps_internal / Decaps_internal).  It
    is anchored here, byte for byte, against official NIST ACVP vectors for all
    three parameter sets.

2.  *The ACE specification text itself*: the size table <<ACE-ML-KEM-sizes>>, the
    state machine (Ready / GenerateKeyPair / Encapsulate / Decapsulate /
    *_Input / *_Output), the `process_VLI`-based field loading with the transfer
    counter kept in the MDH _AlgorithmUse_ field, the unconditional Decaps with
    implicit rejection indistinguishable to the caller, and the `ace.derive`
    Form 01 flow that moves `sharedkey` into a secret field of a separately
    provisioned CC, whose _UsagePolicy_ / _Locality_ must satisfy the
    requirement recorded in this CC's _AuxInfo_ (review finding M5).

3.  *Review finding M12, since FIXED*: <<ACE-PQC-ML-KEM>> now requires the
    FIPS 203 section 7.2 / 7.3 input checks and splits their outcome by kind --
    a KEY check failure is a configuration error (Error State Invalid), a
    CIPHERTEXT check failure is a data error (State Failure, a valid state).
    The misnaming of `ace_state_failure` as an "Error State" is also gone.
    The pre-fix behaviour (no checks at all) is retained as a labelled
    regression case.

Vector provenance
-----------------
    usnistgov/ACVP-Server, gen-val/json-files/ML-KEM-keyGen-FIPS203/
        internalProjection.json          (tcId 1, 26, 51)
    usnistgov/ACVP-Server, gen-val/json-files/ML-KEM-encapDecap-FIPS203/
        internalProjection.json          (encapsulation tcId 1, 26, 51;
                                          decapsulation tcId 76, 86, 88, 96;
                                          encapsulationKeyCheck tcId 116, 117, 137;
                                          decapsulationKeyCheck tcId 128)
    fetched 2026-08-26; the exact case identifiers are carried in each record.

Negative control (KAT-EXPECT-FAIL): decapsulation with the implicit-rejection
branch disabled must fail the "modified ciphertext" vector.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fips203 as K
from common import sl, bin_

# ---------------------------------------------------------------- reporting

_results = []

def chk(name, ok, note=''):
    _results.append(bool(ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{note}]" if note else ''))
    return ok

# ================================================================ ACE model
#
# MDH field positions, src/ace-ISA-unpriv.adoc <<ACE-metadata-header>>.
F_ALGORITHM     = (11, 0)
F_ALGPOLICY     = (13, 12)
F_STATE         = (25, 21)
F_STATEEXT      = (29, 26)
F_AUXINFO       = (61, 46)
F_USAGEPOLICY   = (68, 64)
F_LOCALITY      = (77, 69)
F_RES7978       = (79, 78)
F_ALGORITHMUSE  = (95, 80)

def mdh_get(mdh, fld):
    hi, lo = fld
    return sl(mdh, hi, lo)

def mdh_set(mdh, fld, val):
    hi, lo = fld
    m = ((1 << (hi - lo + 1)) - 1) << lo
    return (mdh & ~m) | ((val << lo) & m)

# State numbers: global ones from <<ACE-states-valid>> / <<ACE-states-error>>,
# algorithm-specific ones from the ML-KEM state list in [[ACE-PQC-ML-KEM]].
S_READY, S_GENKEYPAIR, S_ENCAPSULATE, S_DECAPSULATE = 1, 2, 3, 4
S_EK_IN, S_DK_IN, S_EK_OUT, S_CT_IN, S_CT_OUT = 5, 6, 7, 8, 9
S_SUCCESS, S_FAILURE, S_INVALID = 22, 23, 25

IN_STATES  = {S_EK_IN: 'encapsk', S_DK_IN: 'decapsk', S_CT_IN: 'ciphertext'}
OUT_STATES = {S_EK_OUT: 'encapsk', S_CT_OUT: 'ciphertext'}


class Invalidated(Exception):
    """The CR transitioned to Error State _Invalid_ (ace_state_invalid, 25)."""


class MLKEMContext:
    """Model of an ACE Cryptographic Context running an ML-KEM algorithm.

    Only the architecturally visible behaviour of [[ACE-PQC-ML-KEM]] is modelled:
    the MDH, the four state fields, and the state machine.  Cryptography is
    delegated to kat/fips203.py, exactly as the spec delegates it to FIPS 203.
    """

    def __init__(self, pset, auxinfo=0, validate=True):
        self.pset = pset
        self.ek_len, self.dk_len, self.ct_len, self.ss_len = K.sizes(pset)
        # Provisioning Input is the 128-bit MDH alone (no key material).
        self.mdh = mdh_set(0, F_AUXINFO, auxinfo)
        self.mdh = mdh_set(self.mdh, F_STATE, S_READY)
        # `validate` selects the FIPS 203 7.2/7.3 checks that <<ACE-PQC-ML-KEM>> now requires.
        self.validate = validate
        self._clear_all()

    # -- fields ---------------------------------------------------------
    def _clear_all(self):
        self.encapsk = b''
        self.decapsk = b''
        self.ciphertext = b''
        self.sharedkey = b''

    def field(self, name):
        return getattr(self, name)

    def field_bits(self, name):
        return {'encapsk': self.ek_len, 'decapsk': self.dk_len,
                'ciphertext': self.ct_len}[name] * 8

    @property
    def state(self):
        return mdh_get(self.mdh, F_STATE)

    @property
    def alguse(self):
        return mdh_get(self.mdh, F_ALGORITHMUSE)

    @alguse.setter
    def alguse(self, v):
        self.mdh = mdh_set(self.mdh, F_ALGORITHMUSE, v)

    # -- instructions ---------------------------------------------------
    def setst(self, state):
        """Form A `ace.setst`.  ML-KEM: "All uses of ace.setst do not require an
        auxiliary parameter." """
        self.mdh = mdh_set(self.mdh, F_STATE, state)
        if state == S_READY:
            # "Upon transitioning to Ready, the fields encapsk, decapsk,
            #  ciphertext and sharedkey are cleared."
            self._clear_all()
        if state in IN_STATES or state in OUT_STATES:
            # "Upon entering an *_Input_ or *_Output_ state by using ace.setst,
            #  the AlgorithmUse field is zeroed."
            self.alguse = 0

    def exec_input(self, data):
        """Form B `ace.exec ..., INPUT` in an _*_Input_ state: process_VLI with
        block = state = F, b = n = len, cumul_len = AlgorithmUse (block_base and
        input_base internal and unaliased, per <<ACE-process-VLI>>),
        process_block = finalize = None."""
        name = IN_STATES[self.state]
        n = self.field_bits(name)
        cum = self.alguse
        if cum >= n:                       # process_VLI step 1
            self.mdh = mdh_set(self.mdh, F_STATE, S_INVALID)
            raise Invalidated(f'{name}_Input past end (AlgorithmUse={cum} >= n={n})')
        amount = min(len(data) * 8, n - cum)      # bits in excess are ignored
        buf = bytearray(self.field(name).ljust(n // 8, b'\0'))
        buf[cum // 8: cum // 8 + amount // 8] = data[:amount // 8]
        setattr(self, name, bytes(buf))
        self.alguse = cum + amount
        return amount

    def input_complete(self, name):
        return self.alguse >= self.field_bits(name)

    def exec_output(self, nbytes):
        """Form C `ace.exec` in an _*_Output_ state."""
        name = OUT_STATES[self.state]
        n = self.field_bits(name)
        cum = self.alguse
        if cum >= n:
            self.mdh = mdh_set(self.mdh, F_STATE, S_INVALID)
            raise Invalidated(f'{name}_Output past end')
        amount = min(nbytes * 8, n - cum)
        out = self.field(name)[cum // 8: cum // 8 + amount // 8]
        self.alguse = cum + amount
        return out

    def exec_d(self, rng_d=None, rng_z=None, rng_m=None,
               disable_implicit_rejection=False):
        """Form D `ace.exec Kn|K{Xn}` in GenerateKeyPair / Encapsulate / Decapsulate.

        The seeds that the spec draws from the RBG are injected here so that the
        model can be run against derandomized official vectors.
        """
        st = self.state
        if st == S_READY:
            # "In State Ready, no ace.exec instruction is allowed."
            self.mdh = mdh_set(self.mdh, F_STATE, S_INVALID)
            raise Invalidated('ace.exec in state Ready')

        if st == S_GENKEYPAIR:
            self.encapsk, self.decapsk = K.keygen_internal(rng_d, rng_z, self.pset)
            self.mdh = mdh_set(self.mdh, F_STATE, S_SUCCESS)
            return

        if st == S_ENCAPSULATE:
            if self.validate and not K.check_encaps_input(self.encapsk, self.pset):
                # FIPS 203 7.2 encapsulation key check.  A key check failure is a
                # CONFIGURATION error -> Error State Invalid (<<ACE-PQC-ML-KEM>>).
                self.mdh = mdh_set(self.mdh, F_STATE, S_INVALID)
                return
            self.sharedkey, self.ciphertext = K.encaps_internal(
                self.encapsk, rng_m, self.pset)
            self.mdh = mdh_set(self.mdh, F_STATE, S_CT_OUT)
            self.alguse = 0
            return

        if st == S_DECAPSULATE:
            if self.validate and not K.check_decaps_key(self.decapsk, self.pset):
                # FIPS 203 7.3 decapsulation KEY check: configuration error.
                self.mdh = mdh_set(self.mdh, F_STATE, S_INVALID)
                return
            if self.validate and not K.check_ciphertext(self.ciphertext, self.pset):
                # FIPS 203 7.3 CIPHERTEXT type check: data error -> State Failure,
                # a valid state; the caller may supply another ciphertext.
                self.mdh = mdh_set(self.mdh, F_STATE, S_FAILURE)
                return
            # "ML-KEM.Decaps is executed unconditionally. ... The caller cannot
            #  distinguish the two cases."  Hence: always State Success.
            self.sharedkey = K.decaps_internal(
                self.decapsk, self.ciphertext, self.pset,
                disable_implicit_rejection=disable_implicit_rejection)
            self.mdh = mdh_set(self.mdh, F_STATE, S_SUCCESS)
            return

        raise AssertionError(f'no Form D ace.exec defined in state {st}')

    def derive(self, dest_mdh, length_bytes):
        """`ace.derive` Form 01 (<<ACE-instruction-derive>>): the output of this
        CC's ace.exec -- the shared key -- into a secret field of a second CR.

        The destination CC is provisioned separately, so this models only the
        transfer and the _AuxInfo_ policy requirement.  Returns the bytes written
        into the destination secret field.

        `length_bytes` is the `length` operand: a number of BYTES.  It is
        ceil(m/8) for a destination algorithm whose key is m bits.
        """
        if length_bytes > len(self.sharedkey):
            raise Invalidated('length exceeds the shared key')
        # <<ACE-PQC-ML-KEM>>: _AuxInfo_ is a REQUIREMENT on the destination CC,
        # not a value copied into it.  Bits [79:64]: UsagePolicy [4:0],
        # Locality [13:5], Reserved [15:14].
        aux = mdh_get(self.mdh, F_AUXINFO)
        req_usage, req_loc = aux & 0x1F, (aux >> 5) & 0x1FF
        got_usage = mdh_get(dest_mdh, F_USAGEPOLICY)
        got_loc = mdh_get(dest_mdh, F_LOCALITY)
        # "at least as restrictive": every UsagePolicy bit required must be set,
        # and the required Locality bits must all be present.
        if (got_usage & req_usage) != req_usage or (got_loc & req_loc) != req_loc:
            raise Invalidated('destination policies less restrictive than _AuxInfo_')
        return self.sharedkey[:length_bytes]

# ================================================================ tests

def _raises(fn):
    try:
        fn()
        return False
    except Invalidated:
        return True


def t_sizes():
    print('\n-- Size table <<ACE-ML-KEM-sizes>> vs FIPS 203 --')
    table = {512: (800, 1632, 768, 32),
             768: (1184, 2400, 1088, 32),
             1024: (1568, 3168, 1568, 32)}
    for ps, want in table.items():
        chk(f'ML-KEM-{ps} (encapsk, decapsk, ciphertext, sharedkey)',
            K.sizes(ps) == want, str(want))
    # Serialized Context sizes claimed by the spec: 2448 / 3536 / 4784 bytes.
    for ps, want in ((512, 2448), (768, 3536), (1024, 4784)):
        ek, dk, ct, ss = K.sizes(ps)
        got = 16 + dk + ct + ss
        chk(f'ML-KEM-{ps} Serialized Context = MDH + decapsk + ciphertext + sharedkey',
            got == want and got % 16 == 0, f'{got} B = {got // 16} blocks')
    # "decapsk contains encapsk"
    for ps in (512, 768, 1024):
        ek, dk = K.keygen_internal(bytes(32), bytes(32), ps)
        chk(f'ML-KEM-{ps} decapsk embeds encapsk', dk[384 * K.PARAMS[ps][0]:
                                                     768 * K.PARAMS[ps][0] + 32] == ek)


def t_keygen():
    print('\n-- ML-KEM.KeyGen (FIPS 203 Alg. 19/16) vs ACVP vectors --')
    for v in VECTORS['keyGen']:
        ek, dk = K.keygen_internal(bytes.fromhex(v['d']), bytes.fromhex(v['z']),
                                   v['pset'])
        chk(f"KeyGen ML-KEM-{v['pset']}  {v['src']}",
            ek.hex() == v['ek'] and dk.hex() == v['dk'])


def t_encaps():
    print('\n-- ML-KEM.Encaps (FIPS 203 Alg. 20/17) vs ACVP vectors --')
    for v in VECTORS['encaps']:
        Kk, c = K.encaps_internal(bytes.fromhex(v['ek']), bytes.fromhex(v['m']),
                                  v['pset'])
        chk(f"Encaps ML-KEM-{v['pset']}  {v['src']}",
            c.hex() == v['c'] and Kk.hex() == v['k'])


def t_decaps():
    print('\n-- ML-KEM.Decaps (FIPS 203 Alg. 21/18) vs ACVP vectors --')
    for v in VECTORS['decaps']:
        Kk = K.decaps_internal(bytes.fromhex(v['dk']), bytes.fromhex(v['c']),
                               v['pset'])
        chk(f"Decaps ML-KEM-{v['pset']}  {v['src']}  ({v['reason']})",
            Kk.hex() == v['k'])
    # implicit rejection really is the z-derived K-bar
    for v in VECTORS['decaps']:
        if 'modified' not in v['reason']:
            continue
        dk = bytes.fromhex(v['dk'])
        z = dk[-32:]
        chk(f"Decaps ML-KEM-{v['pset']} {v['src']} K = J(z || c) on rejection",
            K.J(z + bytes.fromhex(v['c'])).hex() == v['k'])
        break


def t_input_validation():
    print('\n-- FIPS 203 7.2/7.3 input validation (<<ACE-PQC-ML-KEM>>; M12 fixed) --')
    for v in VECTORS['ekCheck']:
        got = K.check_encaps_input(bytes.fromhex(v['ek']), v['pset'])
        chk(f"encapsk check per FIPS 203 7.2 (<<ACE-PQC-ML-KEM>>)  {v['src']}  ({v['reason']})",
            got == v['pass'], 'accepted' if got else 'REJECTED')
    for v in VECTORS['dkCheck']:
        ct = bytes(K.sizes(v['pset'])[2])
        got = K.check_decaps_input(bytes.fromhex(v['dk']), ct, v['pset'])
        chk(f"decapsk check per FIPS 203 7.3 (<<ACE-PQC-ML-KEM>>)  {v['src']}  ({v['reason']})",
            got == v['pass'], 'accepted' if got else 'REJECTED')

    # A hand-made malformed encapsk: one coefficient re-encoded as q (>= q).
    ps = 768
    ek, _ = K.keygen_internal(bytes(32), bytes(32), ps)
    t0 = K.byte_decode(12, ek[:384])
    bad = bytearray(ek)
    bad[:384] = K.byte_encode(12, [K.Q] + t0[1:])          # coefficient == q
    chk('malformed encapsk (coefficient == q) rejected per FIPS 203 7.2',
        K.check_encaps_input(bytes(bad), ps) is False)
    chk('the same encapsk is well-formed once the coefficient is reduced',
        K.check_encaps_input(ek, ps) is True)

    # M12, now FIXED: the key check is required, and a KEY failure is a
    # configuration error -> Error State Invalid.
    cc = MLKEMContext(ps, validate=True)
    cc.setst(S_EK_IN); cc.exec_input(bytes(bad))
    cc.setst(S_ENCAPSULATE); cc.exec_d(rng_m=bytes(32))
    chk('malformed encapsk -> Error State Invalid (25), a key check being a '
        'configuration error', cc.state == S_INVALID)
    # A CIPHERTEXT of the wrong length is a data error -> State Failure (23),
    # a VALID state, and the caller may retry with another ciphertext.
    ek, dk = K.keygen_internal(bytes(32), bytes(32), ps)
    cc = MLKEMContext(ps, validate=True)
    cc.setst(S_DK_IN); cc.exec_input(dk)
    cc.setst(S_CT_IN); cc.exec_input(bytes(K.sizes(ps)[2]))
    # An _*_Input_ state zero-pads to the field width, so a wrong-length
    # ciphertext cannot arrive through it; set the field directly to model one
    # that reached the CC by import of a malformed SCC.
    cc.ciphertext = cc.ciphertext[:-1]
    cc.setst(S_DECAPSULATE); cc.exec_d()
    chk('short ciphertext -> State Failure (23, a VALID state), not Invalid',
        cc.state == S_FAILURE)
    # The pre-fix behaviour, kept as a regression check: with no checks at all a
    # malformed encapsk was simply used and Encaps ran to completion.
    cc = MLKEMContext(ps, validate=False)
    cc.setst(S_EK_IN); cc.exec_input(bytes(bad))
    cc.setst(S_ENCAPSULATE); cc.exec_d(rng_m=bytes(32))
    chk('pre-fix behaviour (no checks): malformed encapsk was accepted and '
        'Encaps proceeded -- what M12 reported',
        cc.state == S_CT_OUT and len(cc.ciphertext) == K.sizes(ps)[2])


def t_state_machine():
    print('\n-- ACE state machine and process_VLI accounting --')
    ps = 768
    v = VECTORS['encaps'][1]
    assert v['pset'] == ps
    ek = bytes.fromhex(v['ek'])

    # chunked _encapsk_Input_ through the AlgorithmUse counter
    cc = MLKEMContext(ps)
    cc.setst(S_EK_IN)
    chk('setst(_encapsk_Input_) zeroes _AlgorithmUse_', cc.alguse == 0)
    chunks = [128, 512, 400, 144]            # 1184 bytes, uneven transfers
    off = 0
    ok = True
    for i, n in enumerate(chunks):
        cc.exec_input(ek[off:off + n]); off += n
        ok &= cc.alguse == off * 8
    chk('chunked _encapsk_Input_: _AlgorithmUse_ tracks bits loaded',
        ok and cc.alguse == 1184 * 8, f'{cc.alguse} bits')
    chk('encapsk loaded byte-exactly by process_VLI', cc.encapsk == ek)

    # last transfer over-long: "the bits in excess are ignored"
    cc2 = MLKEMContext(ps)
    cc2.setst(S_EK_IN)
    cc2.exec_input(ek[:1024])
    took = cc2.exec_input(ek[1024:] + b'\xAA' * 64)      # 224 bytes offered
    chk('excess bits of the last transfer are ignored',
        took == 160 * 8 and cc2.alguse == 1184 * 8 and cc2.encapsk == ek)

    # a further ace.exec past completion -> Error State Invalid
    try:
        cc2.exec_input(b'\x00' * 16)
        chk('ace.exec with _AlgorithmUse_ >= n transitions to Error State _Invalid_',
            False)
    except Invalidated:
        chk('ace.exec with _AlgorithmUse_ >= n transitions to Error State _Invalid_',
            cc2.state == S_INVALID)

    # no ace.exec allowed in State Ready
    cc3 = MLKEMContext(ps)
    try:
        cc3.exec_d()
        chk('no ace.exec allowed in State _Ready_', False)
    except Invalidated:
        chk('no ace.exec allowed in State _Ready_', cc3.state == S_INVALID)

    # Ready clears the four state fields
    cc.setst(S_READY)
    chk('transition to _Ready_ clears encapsk/decapsk/ciphertext/sharedkey',
        (cc.encapsk, cc.decapsk, cc.ciphertext, cc.sharedkey) == (b'', b'', b'', b''))

    # full Encapsulate flow ending in _ciphertext_Output_, anchored to the vector
    cc = MLKEMContext(ps)
    cc.setst(S_EK_IN); cc.exec_input(ek)
    cc.setst(S_ENCAPSULATE); cc.exec_d(rng_m=bytes.fromhex(v['m']))
    chk('Encaps success -> State _ciphertext_Output_ (3 -> 9)', cc.state == S_CT_OUT)
    out, want = b'', bytes.fromhex(v['c'])
    for n in (512, 512, 64):
        out += cc.exec_output(n)
    chk('_ciphertext_Output_ streams the ACVP ciphertext, _AlgorithmUse_ complete',
        out == want and cc.alguse == len(want) * 8, v['src'])
    try:
        cc.exec_output(16)
        chk('_ciphertext_Output_ past the end -> Error State _Invalid_', False)
    except Invalidated:
        chk('_ciphertext_Output_ past the end -> Error State _Invalid_',
            cc.state == S_INVALID)

    # GenerateKeyPair -> encapsk_Output, anchored to the keygen vector
    kv = [x for x in VECTORS['keyGen'] if x['pset'] == ps][0]
    cc = MLKEMContext(ps)
    cc.setst(S_GENKEYPAIR)
    cc.exec_d(rng_d=bytes.fromhex(kv['d']), rng_z=bytes.fromhex(kv['z']))
    chk('GenerateKeyPair success -> State _Success_ (22)', cc.state == S_SUCCESS)
    cc.setst(S_EK_OUT)
    outek = b''
    while cc.alguse < 1184 * 8:
        outek += cc.exec_output(300)
    chk('_encapsk_Output_ returns the ACVP encapsulation key', outek.hex() == kv['ek'],
        kv['src'])

    # full Decapsulate flow: unconditional, always State Success, both branches
    dv = [x for x in VECTORS['decaps'] if x['pset'] == ps]
    states = set()
    for x in dv:
        cc = MLKEMContext(ps)
        cc.setst(S_DK_IN); cc.exec_input(bytes.fromhex(x['dk']))
        cc.setst(S_CT_IN); cc.exec_input(bytes.fromhex(x['c']))
        cc.setst(S_DECAPSULATE); cc.exec_d()
        states.add(cc.state)
        chk(f"Decapsulate flow ML-KEM-{ps} {x['src']} ({x['reason']}) "
            f"-> sharedkey matches the vector",
            cc.sharedkey.hex() == x['k'] and cc.state == S_SUCCESS)
    chk('Decaps is unconditional: valid and implicitly-rejected cases are '
        'indistinguishable (both -> State _Success_)', states == {S_SUCCESS},
        f'states seen: {sorted(states)}')


def t_derive():
    print('\n-- ace.derive Form 01: sharedkey -> secret field of a provisioned CC --')
    ps = 768
    v = VECTORS['encaps'][1]
    # _AuxInfo_ states the policies the destination CC is REQUIRED to carry, in
    # the format of MDH[79:64]: UsagePolicy [4:0], Locality [13:5], Reserved [15:14].
    usage, locality, reserved = 0b01011, 0b000101010, 0b10
    aux = usage | (locality << 5) | (reserved << 14)
    cc = MLKEMContext(ps, auxinfo=aux)
    cc.setst(S_EK_IN); cc.exec_input(bytes.fromhex(v['ek']))
    cc.setst(S_ENCAPSULATE); cc.exec_d(rng_m=bytes.fromhex(v['m']))
    chk('sharedkey held in the CC equals the ACVP shared secret',
        cc.sharedkey.hex() == v['k'], v['src'])

    # A destination CC provisioned separately, carrying the required policies.
    dest = mdh_set(mdh_set(0, F_USAGEPOLICY, usage), F_LOCALITY, locality)
    for m in (128, 192, 256):
        key = cc.derive(dest, m // 8)
        chk(f'ace.derive: length = {m // 8} B transfers the {m} least significant '
            'bits of sharedkey',
            key == cc.sharedkey[:m // 8] and len(key) == m // 8)
    chk('ace.derive: a 256-bit key is the whole sharedkey',
        cc.derive(dest, 32) == cc.sharedkey)
    chk('ace.derive: length beyond the shared key is rejected',
        _raises(lambda: cc.derive(dest, 33)))

    # _AuxInfo_ is a requirement on the destination, not a value copied into it.
    weak = mdh_set(mdh_set(0, F_USAGEPOLICY, usage & ~1), F_LOCALITY, locality)
    chk('ace.derive: destination whose _UsagePolicy_ is less restrictive than '
        '_AuxInfo_ -> Error State Invalid, no key transferred',
        _raises(lambda: cc.derive(weak, 16)))
    weak2 = mdh_set(mdh_set(0, F_USAGEPOLICY, usage), F_LOCALITY, locality & ~2)
    chk('ace.derive: destination whose _Locality_ is less restrictive than '
        '_AuxInfo_ -> Error State Invalid',
        _raises(lambda: cc.derive(weak2, 16)))
    stricter = mdh_set(mdh_set(0, F_USAGEPOLICY, usage | 0b10000), F_LOCALITY, locality)
    chk('ace.derive: a destination stricter than _AuxInfo_ is accepted',
        cc.derive(stricter, 16) == cc.sharedkey[:16])

    # the same sharedkey obtained by Decapsulate transfers the same bytes
    dv = [x for x in VECTORS['decaps'] if x['reason'].startswith('valid')][0]
    cd = MLKEMContext(dv['pset'], auxinfo=aux)
    cd.setst(S_DK_IN); cd.exec_input(bytes.fromhex(dv['dk']))
    cd.setst(S_CT_IN); cd.exec_input(bytes.fromhex(dv['c']))
    cd.setst(S_DECAPSULATE); cd.exec_d()
    chk('ace.derive after _Decapsulate_ uses the decapsulated sharedkey',
        cd.derive(dest, 16) == bytes.fromhex(dv['k'])[:16], dv['src'])


def t_negative_control():
    print('\n-- negative control --')
    print('KAT-EXPECT-FAIL: implicit rejection disabled')
    v = [x for x in VECTORS['decaps'] if 'modified' in x['reason']][0]
    Kk = K.decaps_internal(bytes.fromhex(v['dk']), bytes.fromhex(v['c']),
                           v['pset'], disable_implicit_rejection=True)
    chk(f"implicit rejection disabled -> {v['src']} must not reproduce K-bar",
        Kk.hex() == v['k'])
    return _results.pop()          # this FAIL is the expected one


def main():
    print('ACE ML-KEM known-answer tests (FIPS 203, [[ACE-PQC-ML-KEM]])')
    t_sizes()
    t_keygen()
    t_encaps()
    t_decaps()
    t_input_validation()
    t_state_machine()
    t_derive()
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
            'pset': 512,
            'src': 'keyGen tcId 1',
            'd': '47b893474672ba92e4b12ee44fb32953af8e8503b5fb471d1614fb8a021a660a',
            'z': '1f8cb39e9e30bc458a0dc5408884b1187fb217018df760fa57317703b844a0a9',
            'ek':
                '28266a088b3482439bca01afb7ca5c6136a979b5159985a9484b36b679a5f7b9819eb63577891f7bb9cb98413ccc434a'
                'dc79a16d6ab3076569ce6291c59b5d64612a7fb0c15013200bc8bebb03a570174b5e4363aed86eb02a220d281fb5457f'
                '0a549fc5051d49a6b2015259a2c3084f405e1769952260675586a584904059275a265234ef3abf88c171a80898fc7833'
                '58bbc9803c8789027d917c9ebacbc568cc18de84c85454b94249586c0c6e2b8a16fa789c51212dd1728ee9b8c6c40528'
                'bf93826fa82368419623032af27b5694305816811d3ca85805100e9c1a9621e5089e54cb47f5a8fea0b49ef81c6b5187'
                'f48924c7947d6b61697a4a8a18452ef803336ad4be503275bcacc03c181405f7b1dc9b47fb169eb37bbe27e29c763a4e'
                '52b9a42520388cf09b8edbcdf41ccf6537190e6156c37cc1aac63c0f90ce78d0b9b190c548d71b6f26cc8f585ea14004'
                'b5b30aaa100b2adc1263828833b24e46163b41446f98c882092a39941867b80632e2097674a793935227db0b8577e03a'
                '69c50a514c7473c892e3fba7c4316bdabc952a70644176687d4191323bad93d85a3ca250868c0747e6c44f6126c874af'
                'bec0bdd4503cb2c59a69816e7d4109941467579a1ffe6a4f50fa379051729dab6e2f61432f15be67d667c7cc1054742b'
                '2b953078a5cf88d9133087309d88c61da240d99c59137329907b47865321ecd5564e987333b4cb607b0afca86769dc95'
                'b2f921357213fcb80c3b152918e9bab2228c0a1b77897ac68ce55088165f87f397da9790873b62c5383c0ccc370f0267'
                'cbe195651ccf336182c22ac3924b76c9e779b7a271d166b6d24b84242b7e73cc723f764039f6c851744034c3304db0c0'
                '91a5764fdc9d593556ff734b82a87ccbc38ca99564d988bbd2d1bf071bb160722d365104fb27610651a8ed817f2742a6'
                'b5a1273a61acaf4460b0ab1456a9922351400a1c7d95d856d6e3370622c9c4164bc6b401435624a98b95caeb274f34ce'
                '92038d785068cdd8cf44c38d84acb2c466a2756c870ee78c26e738cc451002304eb8c90ab24b6463eb124d779f937a2e'
                '3692611d2e34d57b36cc4b2cd3b31ff485c6684d408b972e0d5ca7d2224aae4e',
            'dk':
                '89c31d05611aaab258f78bc2de0a80d5914bf80c376a990d33cb97f4f2077ce12d2dac559de3400b0622754a2e814730'
                'bb7c2b401a076cec9524654ddac661b2f2123ea64d3bd727ca42c8d2725475bc0ad4b698e61001d031105897ca746249'
                'd24538cd63849e874eb9449fbae979ca2a3f357b7d87f112fb16ab8ba20bdd315688231b21a4083277663113bc70a806'
                'e772917fa95743a01f138bc7bd5cb3b21cbf8ee301eb0bce71a4baac3907b469cbede767a55aa194930b4a2b227e633c'
                'f33a3fc715454a32873b717fe6a21c01989133e42113d985f46807a26b0de105cd9a897334d9816075c3149a1919cc2d'
                'bed56a23f3192cdb68f6e305852b8b864bacb5349cfd98419ffc9486c6b07f788cbc79b7680441b0db1dbd92aedff49d'
                'b6f2ae52b95fa9b966c6cc08714a131770903859b823d2cf9731a36d8795b60585f8f1bf1a2c4e544407d5c1359810bf'
                '99a7374511a663ec1b192b83e27c4f4b6c3387692e4d756a235c14d151056e829fb79936a0c8a52ee128f0f369f8eb73'
                '90783788037ce32b021e57c45eb968cd5b9a04b02f89149778653f208c14c2e786d4544749572bf0d9a31b13bbad60b6'
                '756b9379fc2e1660c58ed373c957309ea213213a5988cc59b1c37153811f7271bc1e729ab1629714d1955f7067965562'
                '13b08e3f766867d1cc02648be0574bb8818d0978578c562ffb6795dc065037129c5e4738b5960fe7e2a22570c36571a4'
                'a7a0a5187609f8d27714ca299309509c7c8ac2776e6814a262359b971b1a153cab81858d96350f9f2ccc9884c8f5509e'
                '237655b4b2b22e75c6919a82eb56b095e3c52b55583f6855e186cb75da3a20640762922062721d5c1ac51b87b10633bf'
                '43860814c89ce16bbf66667c2101bd27ba80969c78dc487678989ef5ab22d9b42679590e1855c94a9a90b4e021333a45'
                '32c7ae238358646094b598aa431486d0b7bbd82c5c4ebb6195680c3e5aa806b155af7004318867fe55b1996353495034'
                'df459624f4b04b51167a5148499846a36c605ad85b997674df241d8ec59e56e22ccdb342f535292aa444b69c3e7a2521'
                '28266a088b3482439bca01afb7ca5c6136a979b5159985a9484b36b679a5f7b9819eb63577891f7bb9cb98413ccc434a'
                'dc79a16d6ab3076569ce6291c59b5d64612a7fb0c15013200bc8bebb03a570174b5e4363aed86eb02a220d281fb5457f'
                '0a549fc5051d49a6b2015259a2c3084f405e1769952260675586a584904059275a265234ef3abf88c171a80898fc7833'
                '58bbc9803c8789027d917c9ebacbc568cc18de84c85454b94249586c0c6e2b8a16fa789c51212dd1728ee9b8c6c40528'
                'bf93826fa82368419623032af27b5694305816811d3ca85805100e9c1a9621e5089e54cb47f5a8fea0b49ef81c6b5187'
                'f48924c7947d6b61697a4a8a18452ef803336ad4be503275bcacc03c181405f7b1dc9b47fb169eb37bbe27e29c763a4e'
                '52b9a42520388cf09b8edbcdf41ccf6537190e6156c37cc1aac63c0f90ce78d0b9b190c548d71b6f26cc8f585ea14004'
                'b5b30aaa100b2adc1263828833b24e46163b41446f98c882092a39941867b80632e2097674a793935227db0b8577e03a'
                '69c50a514c7473c892e3fba7c4316bdabc952a70644176687d4191323bad93d85a3ca250868c0747e6c44f6126c874af'
                'bec0bdd4503cb2c59a69816e7d4109941467579a1ffe6a4f50fa379051729dab6e2f61432f15be67d667c7cc1054742b'
                '2b953078a5cf88d9133087309d88c61da240d99c59137329907b47865321ecd5564e987333b4cb607b0afca86769dc95'
                'b2f921357213fcb80c3b152918e9bab2228c0a1b77897ac68ce55088165f87f397da9790873b62c5383c0ccc370f0267'
                'cbe195651ccf336182c22ac3924b76c9e779b7a271d166b6d24b84242b7e73cc723f764039f6c851744034c3304db0c0'
                '91a5764fdc9d593556ff734b82a87ccbc38ca99564d988bbd2d1bf071bb160722d365104fb27610651a8ed817f2742a6'
                'b5a1273a61acaf4460b0ab1456a9922351400a1c7d95d856d6e3370622c9c4164bc6b401435624a98b95caeb274f34ce'
                '92038d785068cdd8cf44c38d84acb2c466a2756c870ee78c26e738cc451002304eb8c90ab24b6463eb124d779f937a2e'
                '3692611d2e34d57b36cc4b2cd3b31ff485c6684d408b972e0d5ca7d2224aae4e3a389831056ed8fd8147686924578268'
                '9c84b3ce90fe6a9e78d0a380fd6a15731f8cb39e9e30bc458a0dc5408884b1187fb217018df760fa57317703b844a0a9',
        },
        {
            'pset': 768,
            'src': 'keyGen tcId 26',
            'd': 'e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0',
            'z': '1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0',
            'ek':
                '28c793778741b80b02b4339f2aa4347255b099f17264e1b8cc0a2c7c2a1a79f7997b907fd0496c6e6c8ad7714f5f339d'
                '75f11f625591a869be1175ae47f05fd4313468232ba6957d7807b824f445ac99a0d568ab1ad54dca8249d1482e61275f'
                '52248c77f61a4248753188cd1794cd0a465ec0dc4b025985c461b74e76286e4c37e77405695cc9fd0654374b427a2034'
                '3aec0ff1a187768273bfc4905472a1da387f14559d6ce87313f6a5b6138434539f9a13684055b177e543f8b40f432abd'
                '7cc49989a50a9084c660913f45a8593b17499bc4cf936c2bc1851421cb986808a0ef30afe97aab5b8b8eb3f0b3506a95'
                'b91563a0e57db7231044987ef141bdab3537c316ad16f17805a81f29329879a94e96157e4b7447f7d59603b21bd896cc'
                '47b7cd4e232322eb9c5d2215696bcffca3a04efcc4c5d9cc39ac9a6e8700d38c244b0169e7fa1fe81b4b10365e74e6a1'
                'f7f756d11acdc84043f81006d62995376c22535958feb53f78117ee0f61c4c862640d06dc57a2b8be62a41a642af3bc6'
                '3f6bac98bbbbff70570f37b8f8d9572f2735657a6c98f96caf57a849868720b2640b8bb2732237a1f984c18872d10289'
                'ce43c952c9257e06529aeb76afd127b17596fd25c5216c9cabd9b18efc50e87bbb04568bb7d5c4e9288c006483af5912'
                'e19108573700bd10cd77224b80659ea75aa74270b33ac4008b738bfee271e78658c8742ff13c96ad0781a03c7576ca26'
                'dd58b52980ba58c0505e446afa140cdcea0490db1f9b18815d4314b2459cacc562441c91f4084e5426c88e632cf7482e'
                '79907911d06473260835d7b85e7856a829aea0381707b939ce86882cc09c4448c6ae94a9c303107c5667eefb8df7763c'
                'c21189a3c590c40aa51f491503a7935ec08f4fc300cbe607ed8c9100c29fbf45584b13c8d780069337aec76c36ceb703'
                '73e2ab6e7b934b466f53fb32eaf040055496b8540e23a2a277e534468608d5ec0f8d38cea5bbb806c1bf4f164f6ac826'
                'fe733f95461e29dcc11200c0aada1b8332023eab329718ce25cc0a09555903f3578bbc863b1752ca94365da556df54c3'
                'b7e05cbb7115fbc1b6c57a172c31b9906560c8fb54f3c563a2256cc073243b8179b4a28d60e086cf51082ee429272996'
                'f0aabe03ba0eafd3c8e7d954bd0933e2f60ed0c32cede7b820a28e48f3ca3c40913cccae2337abfc59843f08c9863325'
                'd65a4e9e15c1f46172b118b2b5eb0f1d5158a00134f27b085488c3a0621fe4e5678698250fb74ee5152e3e35a66544a0'
                '5d279ea99131fbc15165060b90f88eeb7b20892a4de4cb1683495bd7da037966b47cc040f1764c5deb06b5499d426739'
                '1cebbb47f734d8539e39528436a1858182854bf20b1f93279afb706464c65ccc5ae099b37cc03556c26abf4c3f8b9ba3'
                'a936707211a49a59b268f5284f7970c77612719450377417428c4ba47c9ca115cf95304c4759c5d8859b44985c06a6c9'
                '24689237ba320d610960d61c53e85431789e67a40113f167ff93429c264f6cabc95448c903437d39a6577be0cf001285'
                '2aa476351a9046a110a1a625a3d74c910b78bce9cfca735e4f91b8a4c57dbe489e849446098aacf73070aee638fcc889'
                '6473d3c159d3afb4b687b40dfbf371a9c2644b605187b71a14bc4c8678fe8247',
            'dk':
                '3808b98d9a093c7853b0b814d1ca5f392677d3d0a38f81c852f95b9a69b374a24588c0add5b510be567c5a24688ec91e'
                'd0f28bb4c86978c09793795c36b94e5dd8498eb4353ff40ea87b17e921b5b4cba08e5b7be5a9c8bc69ac5ac3075dd947'
                'd04b8695097ac39790a0c8abe11200c9f136ed7b0c10077e36111c1f139d9bd27142993f5883925c4918413cb8043962'
                'a28567397a1c7e003bac30644055155ce9464e623fc5e2160cd1143fd2c90c03a08d0b333fbb40a308cacd81618674b4'
                '06809790b2538d30431f064f65ebba7c41b2a53146a3abca66754cae591534045c1d640d6308472ebca660a8a7d37247'
                '0d3869115b8860b577311980b2c66b8352229abc17b0c31f58e5a5ebdbca6e3b157d9ca79ee890778a4cf28429c2a82c'
                '80dc9c524b0864e385e355bd4e65732d395e464070f61828e57c3e1be2a50052c4ff1951f5d0c89720987d8941f08587'
                '1113a91f518fc79b7189056990b2447bf54fc170c932e0a4e0f7a262542f56d1b49eebc392106d93c77de9186dfbb824'
                'e73b2f7fc796b312875b43414877afb356214492c19c748dd381bc7a9237bf097cc606a03119a240a5536ac7844f6a79'
                'd0e2b821b68d96542450179bcca231f2da68c5eb6d118b99a1b66eaa566c78a9009008b0d66155ba4839f8e518c65017'
                '7dec170eb09e8bf6a89905320590c642b801cf5b5151c2af3e7271cb9961c65a5bd17479429a31be9081f2767d94816c'
                '16d1b04772012382b689ab2d3fb9bdc66547bfeb23052600bb369771494d9c914ec93a066abc9611940b947310da0419'
                '7312425d736a1933b785c95dc430791e42cd691c79ba63be06ec80765c9c07053eac706697f21720c672b9803df99355'
                '32197b0485bbe42b0dd16561ac0605e9da73c189c9e29aba3aeca19c21621b209326418543c44b88843eb3720a2cec3d'
                'b52c59d6507ee5cb03c268b31fc4bf115695eb0b8ad3f11fedea1a5d0724a5d5284d0c10e9844d0d32bb5735448421bc'
                '5317650beac4829b234b787339812f2316ace8c22c42d6346214934fc0b49eccbdf8da19aee64de9628c4f7ab3e512a3'
                '99b0c227b677ac4a69891a6874f6641d2cc95460b751e17e434c924b2947d806856665696e3cc4db9553b81606c31c38'
                '00b48756a073bf685eea20899c176769e902db971827d153b9c33516e959c6b469841946c0d921a371a5de9740c6ab9c'
                'a272b5850ba8753ca023a460ebf7bd573c0745f40b90f105ee17c19b6832e019b80f8858bb515f7c709e68f29c1375b2'
                '2567afe7b528f4431a94b553df825cdeb84b4ea9296eab9ad66271eec5aef6f79509a20a182279fdf92f87fb6e750996'
                '8d22ca750b5056974841b9654e5716bdc33a2c6a116a4117fa757a1d22710668412b8878e134b70fe32158a2317fbc62'
                'f01371296aa42e33c903e0c439f19684b11e2f911f7fb79860c8800f9ca146eabe29db07237aabb503a9be2aa7263a06'
                '26c162a27537775792b2e7b0fd347929934ad8f521d4159059f611312ab903879490059be8b38920e2cb4a256b8b3578'
                '3e909346d13e9888beb9350369f7c1a8501331110c651621a616b365a026d1cc47df440c9e650dd0c0bfc82954391145'
                '28c793778741b80b02b4339f2aa4347255b099f17264e1b8cc0a2c7c2a1a79f7997b907fd0496c6e6c8ad7714f5f339d'
                '75f11f625591a869be1175ae47f05fd4313468232ba6957d7807b824f445ac99a0d568ab1ad54dca8249d1482e61275f'
                '52248c77f61a4248753188cd1794cd0a465ec0dc4b025985c461b74e76286e4c37e77405695cc9fd0654374b427a2034'
                '3aec0ff1a187768273bfc4905472a1da387f14559d6ce87313f6a5b6138434539f9a13684055b177e543f8b40f432abd'
                '7cc49989a50a9084c660913f45a8593b17499bc4cf936c2bc1851421cb986808a0ef30afe97aab5b8b8eb3f0b3506a95'
                'b91563a0e57db7231044987ef141bdab3537c316ad16f17805a81f29329879a94e96157e4b7447f7d59603b21bd896cc'
                '47b7cd4e232322eb9c5d2215696bcffca3a04efcc4c5d9cc39ac9a6e8700d38c244b0169e7fa1fe81b4b10365e74e6a1'
                'f7f756d11acdc84043f81006d62995376c22535958feb53f78117ee0f61c4c862640d06dc57a2b8be62a41a642af3bc6'
                '3f6bac98bbbbff70570f37b8f8d9572f2735657a6c98f96caf57a849868720b2640b8bb2732237a1f984c18872d10289'
                'ce43c952c9257e06529aeb76afd127b17596fd25c5216c9cabd9b18efc50e87bbb04568bb7d5c4e9288c006483af5912'
                'e19108573700bd10cd77224b80659ea75aa74270b33ac4008b738bfee271e78658c8742ff13c96ad0781a03c7576ca26'
                'dd58b52980ba58c0505e446afa140cdcea0490db1f9b18815d4314b2459cacc562441c91f4084e5426c88e632cf7482e'
                '79907911d06473260835d7b85e7856a829aea0381707b939ce86882cc09c4448c6ae94a9c303107c5667eefb8df7763c'
                'c21189a3c590c40aa51f491503a7935ec08f4fc300cbe607ed8c9100c29fbf45584b13c8d780069337aec76c36ceb703'
                '73e2ab6e7b934b466f53fb32eaf040055496b8540e23a2a277e534468608d5ec0f8d38cea5bbb806c1bf4f164f6ac826'
                'fe733f95461e29dcc11200c0aada1b8332023eab329718ce25cc0a09555903f3578bbc863b1752ca94365da556df54c3'
                'b7e05cbb7115fbc1b6c57a172c31b9906560c8fb54f3c563a2256cc073243b8179b4a28d60e086cf51082ee429272996'
                'f0aabe03ba0eafd3c8e7d954bd0933e2f60ed0c32cede7b820a28e48f3ca3c40913cccae2337abfc59843f08c9863325'
                'd65a4e9e15c1f46172b118b2b5eb0f1d5158a00134f27b085488c3a0621fe4e5678698250fb74ee5152e3e35a66544a0'
                '5d279ea99131fbc15165060b90f88eeb7b20892a4de4cb1683495bd7da037966b47cc040f1764c5deb06b5499d426739'
                '1cebbb47f734d8539e39528436a1858182854bf20b1f93279afb706464c65ccc5ae099b37cc03556c26abf4c3f8b9ba3'
                'a936707211a49a59b268f5284f7970c77612719450377417428c4ba47c9ca115cf95304c4759c5d8859b44985c06a6c9'
                '24689237ba320d610960d61c53e85431789e67a40113f167ff93429c264f6cabc95448c903437d39a6577be0cf001285'
                '2aa476351a9046a110a1a625a3d74c910b78bce9cfca735e4f91b8a4c57dbe489e849446098aacf73070aee638fcc889'
                '6473d3c159d3afb4b687b40dfbf371a9c2644b605187b71a14bc4c8678fe824781e66ef5a7a221619f6a64039cc36984'
                '3e10df5c859f6959cc3fd8e5272330fd1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0',
        },
        {
            'pset': 1024,
            'src': 'keyGen tcId 51',
            'd': 'f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009',
            'z': '35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275',
            'ek':
                '8d0923ca8a2da2b4146ec25321122b8a5aa8afe0c03415273008a46ee83031e98aaaa125abc75d3b30322560c197e75d'
                'd0e48a348099f7b2144d7b8a8660a4a97bcf19c0583bd9bb2123033cd7bb5a14b08b817831a673a28170f5f6443c0551'
                '913a327cba18c3a053c4040250403b70ab9588832403aa0fc37665e04980fe1602e7d2715d9cbc00515df432a4f5b32b'
                '3bc92ae3f31700166d498123e94576509b712b18491b1435ee7ab7aeb1ad30d72348c3cc083abe24a8b12097bf32f792'
                '476288eecc3bf630adcdac6aca7950d9839501a448500742bae37f109203a809b2b960a307e25347a32c3eab79288173'
                'a878789b296e9e8c1c28c5bb3ac472601c9765f7b77225a810c7b85370bef4a5b079d2015ada54236b8f33840675f9b2'
                'eb427a1b5974cd5c61b24010886c5a7bda5bbed974af7217f3338ad719cb308a8bcb1b6d6ed2a1643736c29095e8a845'
                '2a3a36c7bb5ae58cbfdc61529466a90f454ed6895b0861083dd1371999b2f559a3a487cf59a074fb49215ea6a6be656f'
                '9af17b121a2447cb7985590e9738842b899ba57ac311810ae2d9794f37483dd6bccb64af6d56588ae94665961c025c3a'
                'a2861974c236bca4bd8ff5509f7ab774593e7c5549e57c2f18d15c0515094ad9a0dfaa0601e524f8231156b627bb25a0'
                'dae04dacd0a66c041cef400583fc13bae640291a39a5c5ca8bca1ad5c683cdd8290891a76940817dd8c9f52678780548'
                'e37a05806600801426dbb950c3b2ba34e24cc77864dd91b39f1408c716a69df63342854e50a245fb50977b9410ded2c9'
                '3f86b1f9d5a78b87bf81e51ca620a7e8566b19ab700964a40e3266415228d432156e5cbdf52364a90483a55c39b3fb16'
                'fc7465a3f8ac801b70b9fb28b583444ba5c1a73722d417a9d6d9b7deb08bc6b330ff27cf61ab8831e27758c64af3b121'
                '50cb7b33abc29858106d63686d8762459abf9413850ae53ed6313f76f83d0fb8ab34374e7df693e4a1b3e5a8ad0ce820'
                'afe1cf401acde650a8101b0946022d52178e19613c42b88b07cc04eaa81dfb28ac9dc076236b67219a30f8f945dd57bd'
                '2f335c52d59372308d38993467db53da3382b74867b616481bd0091a2232c1116dc88a589db9107224a681008c67c589'
                '186a6929549beef92253db02b0c8aa9f9c875a670266c72bcbdb4f5625043703c1a0457395832e4c335180462ed2220c'
                '59e7361903c107d85457f6cd82eb820d0855d97675c2e0151cdb73c2885ddb7849d74541580124e890116a65bc068093'
                'b57914e20c937c60a3eb25576f1a976a9583839b672144cd4a45c3477a45c29b4e0bc2bdbd206585c9b7a7741c8b6b57'
                '93a92797a15ae7a5b73a74b2971463634ba52aa792af05530730b6d0a89a346156b733677932bd36593a7496130cc458'
                'dcc5ca987c21960604ec8a8c5396056680cbf3f1aac4f401aa5029fb2150434bb4706c31a2d54e4297939fa7c9c6f857'
                '00613ceb65c7f03ac56eb86e2d27ccc6dcb7b9394dcdb942ff222d86958a996c0cb6a8a44f97a70441c95fa71250116e'
                'ec20863c0b5a643458788ab001f8869d909922f51ee547a1e889255b3a0599c65842e5ab8d73872f053bc62392ea5389'
                '6d328102d460bf1609583c22c3b43780ec6dad0319eb4a5a65b4756c3cb40eaa935183bf8bd46abe76ba46e199103a53'
                '13c3235f49c915e097bca804de680781d8365731beac6789a9203fb8787c4c070e00a13a6722a66a28236db179825653'
                'd33ccf898b72c6b8450d97afd3276bb13340519cbeda708d12a858f54c49f4547195b7788a9150b2649e36aa39412192'
                '6d568a488b16d3557b2a32af57d11fc3373f80a28c0723273d362502e7c428ab44d3cbabf9ea585fd1bd0c9846556a1e'
                '196b78cf951592984a0a8487a78c2317d7aca4118e1049750a0788f0d66ad9e48e34731130aba0b427360a856d96d80b'
                '3f028fdd3aba9035c10106ba1c0934bed36c6d7c7434249654ea89fc22137f4ab903653b75fb25b6f01635e6cc7d39cf'
                '1508690562826b49b6ffc59e0dd35022e541f8ba0d304aa5b4e20606907c424395666c54abc2b8fb009847c863176850'
                '00c231215c8c15945860f6a85ddb98a8c3a527f2749d3c027e694e8f0b0f0fa454913aadb635aadd452f7128bf775256'
                '9669a8b93290eb92e78f6adff23e89f57f3890753b51f12f3f3a8a654e677847',
            'dk':
                '6cbbb491d7b3a3439f53c9027bd727a0e1c78004b4cdb66760e50f1bf97fff0139f82862f1f3178a077b6af77735cb80'
                '2e91316bc207b9f1485ff7a868891e003bb9c6558be6052c0826af1cb5836b94c7d5d714eefc7cfd983e9884b7134849'
                '9dca05def33b49d1c14bbbb95ab195bd72219b18bd0c704275cc94ab06653bbb9e0eec74181903a0081aae068b81ebae'
                '8925335b8134b1480a60f758282c2f011b909641266774513a19090bc672eb3a0708cb577f134151c155c1e560d9b335'
                'a35a4d75f223502752cd250c9a7778efc76a52709813a24679b987a6172f1714641ea6902d364f96357e92b44275ebcc'
                'e7f6207bb0a215e98b3aa92daa46a39ad9132f3874c6239391e716ba600e42bc7084425051f865756a89dab46a76104e'
                '183a12031b99be86257b583c2e88104fec3bfcaa50f238beec20abf31219685885f2c3ce2f80c09b874e73a8712d35b8'
                'ee819d84b1c59a37947c0b9e25f066ee030ed28172fd5914b562408ba9b9de9bab2b95a4f30c22ece458e133371a693d'
                '9458058265a75ad6ca5707617b38a1b6f396fb199cc1c77100741de37500f1bbb10b9204eeb7c3f5b91a1cc91b6d4072'
                'af410957358acb0625488b9f6a9915758b7cc9b4afe7d5ad6a95231a7a711b3a8996e23afb3695b45b6d919c771d7685'
                'd90a7550a9b5b1e7538a365451a5a815009e49326c6541caf0ba685056bf82ea4ab504161b555568583802800554a948'
                '0602437b0b9677fac638a2508154a658e0623c62666e078d21a5a545a818d66c9547b9749458b735a4ad51812950e8a6'
                '25a1b2a753abbba16415006300ad32d34c8b0b3b2af4d1cfbde08b4f06c70de4ba28fb3763745cce133dd2e488f89a51'
                'e7a586a86ac928867b0541438af5645de3211aa94aca4a1095896ebc363c374a85565c1eba030b5ea21b9b8a140e131e'
                'd07580d5b8590446988da65939a823a84661b26ca12461afe373519f43c13987a96a9069cd6b9177b205b25b5197dbcd'
                'e66c6457892c1df96fe50ab7ef3b3dab0a87436b3451476c44aa22aef918ae5a1a8ae46920263032e3bc5debcfee43b8'
                'aa290cedf06966939ee6cc7c6af83cb9d90cc889ab8b5a3d4c224e73916ae057bf5455528cacbed31b554043c6b0ea19'
                '6854461d2644461470efc55080e326fed49d62b5a4bb06b14f505eb4486c9a1b033b927836da656c2475e5b8b823986d'
                'ca99b298512d94b77fe0588dbb96ba53a67369b82c2beab2ccc0103e549317a99dd97b598fa0a506184eb55c96b17302'
                '533c7ec3334e3cec2bbb22be0f89442840884fab4a766a41bc8061d4abcac5190c729309ac6151bd434b818bc1e7d0cd'
                '435c9ca6dc7182228ff93867134a5cc65c6167c4a8bb830e7feb863c15bf87b259eb0518ff5248792a625f37c5895897'
                '99746d36197dc63aabd134a00ef1b49c79a2df67b28e6b6e989cc9d0577ea5aa1b2fe64b322c7a8b241d503523d875cc'
                'dc479d28e3c01bd8383dcb2b684281e6949171f518ea97009237b5cd42ac8fc8a571716eb784b336529db67728499988'
                'b73b80ef5c6d33f3b42ada7a0a36a7c6a8a0dfb804b3d7bb05803957b913827a16f52acdd7650ee2971a85dc21f6a94a'
                '5b31988e4438a9c1733ab8c48c32653fe800bf81ba66658cd2001acf3a83e3a0426ab6c3b2600a53621277a43d723ab9'
                '6758b120f120248c15edf4294fc38f96ec490bd52094655841d9355038a379d8b666875171f39218e21d37023f5108b6'
                'd15389f07c1241e15071c43cd7d160eb5341b719c2055424ef6cbf66815f84943c9481cd1de685a74c5b9db37a071395'
                '2fd4a67bec8ca7496f6c9c5fb84a8eafe68d54654c6bac9c3ab712c2bc32c0cab072c18de3cabbd9224dfaa305dfdb3f'
                '85019d7b988577b40f27514822db42d87489502c53cce6a095b486d9143d6d160b1c7313bf288913657698117eb145c0'
                'c9c55d66c15bf1a2b268f6a5fa259139551abfe3468f1cc49c01b4232543def0bf9ae503b998536310751a8bc302b4b4'
                '440b835233797c967e7f9308155b27ba63c65e08bdd1946828196b30c042cda0b56e4008215ac51f373604f5930bb662'
                '97c32be41a162ca21471cc86657b5cb5307d89091da9a5137f1c1433ab8ac1d59de421c7c17a883eab99ba4714f84199'
                '8d0923ca8a2da2b4146ec25321122b8a5aa8afe0c03415273008a46ee83031e98aaaa125abc75d3b30322560c197e75d'
                'd0e48a348099f7b2144d7b8a8660a4a97bcf19c0583bd9bb2123033cd7bb5a14b08b817831a673a28170f5f6443c0551'
                '913a327cba18c3a053c4040250403b70ab9588832403aa0fc37665e04980fe1602e7d2715d9cbc00515df432a4f5b32b'
                '3bc92ae3f31700166d498123e94576509b712b18491b1435ee7ab7aeb1ad30d72348c3cc083abe24a8b12097bf32f792'
                '476288eecc3bf630adcdac6aca7950d9839501a448500742bae37f109203a809b2b960a307e25347a32c3eab79288173'
                'a878789b296e9e8c1c28c5bb3ac472601c9765f7b77225a810c7b85370bef4a5b079d2015ada54236b8f33840675f9b2'
                'eb427a1b5974cd5c61b24010886c5a7bda5bbed974af7217f3338ad719cb308a8bcb1b6d6ed2a1643736c29095e8a845'
                '2a3a36c7bb5ae58cbfdc61529466a90f454ed6895b0861083dd1371999b2f559a3a487cf59a074fb49215ea6a6be656f'
                '9af17b121a2447cb7985590e9738842b899ba57ac311810ae2d9794f37483dd6bccb64af6d56588ae94665961c025c3a'
                'a2861974c236bca4bd8ff5509f7ab774593e7c5549e57c2f18d15c0515094ad9a0dfaa0601e524f8231156b627bb25a0'
                'dae04dacd0a66c041cef400583fc13bae640291a39a5c5ca8bca1ad5c683cdd8290891a76940817dd8c9f52678780548'
                'e37a05806600801426dbb950c3b2ba34e24cc77864dd91b39f1408c716a69df63342854e50a245fb50977b9410ded2c9'
                '3f86b1f9d5a78b87bf81e51ca620a7e8566b19ab700964a40e3266415228d432156e5cbdf52364a90483a55c39b3fb16'
                'fc7465a3f8ac801b70b9fb28b583444ba5c1a73722d417a9d6d9b7deb08bc6b330ff27cf61ab8831e27758c64af3b121'
                '50cb7b33abc29858106d63686d8762459abf9413850ae53ed6313f76f83d0fb8ab34374e7df693e4a1b3e5a8ad0ce820'
                'afe1cf401acde650a8101b0946022d52178e19613c42b88b07cc04eaa81dfb28ac9dc076236b67219a30f8f945dd57bd'
                '2f335c52d59372308d38993467db53da3382b74867b616481bd0091a2232c1116dc88a589db9107224a681008c67c589'
                '186a6929549beef92253db02b0c8aa9f9c875a670266c72bcbdb4f5625043703c1a0457395832e4c335180462ed2220c'
                '59e7361903c107d85457f6cd82eb820d0855d97675c2e0151cdb73c2885ddb7849d74541580124e890116a65bc068093'
                'b57914e20c937c60a3eb25576f1a976a9583839b672144cd4a45c3477a45c29b4e0bc2bdbd206585c9b7a7741c8b6b57'
                '93a92797a15ae7a5b73a74b2971463634ba52aa792af05530730b6d0a89a346156b733677932bd36593a7496130cc458'
                'dcc5ca987c21960604ec8a8c5396056680cbf3f1aac4f401aa5029fb2150434bb4706c31a2d54e4297939fa7c9c6f857'
                '00613ceb65c7f03ac56eb86e2d27ccc6dcb7b9394dcdb942ff222d86958a996c0cb6a8a44f97a70441c95fa71250116e'
                'ec20863c0b5a643458788ab001f8869d909922f51ee547a1e889255b3a0599c65842e5ab8d73872f053bc62392ea5389'
                '6d328102d460bf1609583c22c3b43780ec6dad0319eb4a5a65b4756c3cb40eaa935183bf8bd46abe76ba46e199103a53'
                '13c3235f49c915e097bca804de680781d8365731beac6789a9203fb8787c4c070e00a13a6722a66a28236db179825653'
                'd33ccf898b72c6b8450d97afd3276bb13340519cbeda708d12a858f54c49f4547195b7788a9150b2649e36aa39412192'
                '6d568a488b16d3557b2a32af57d11fc3373f80a28c0723273d362502e7c428ab44d3cbabf9ea585fd1bd0c9846556a1e'
                '196b78cf951592984a0a8487a78c2317d7aca4118e1049750a0788f0d66ad9e48e34731130aba0b427360a856d96d80b'
                '3f028fdd3aba9035c10106ba1c0934bed36c6d7c7434249654ea89fc22137f4ab903653b75fb25b6f01635e6cc7d39cf'
                '1508690562826b49b6ffc59e0dd35022e541f8ba0d304aa5b4e20606907c424395666c54abc2b8fb009847c863176850'
                '00c231215c8c15945860f6a85ddb98a8c3a527f2749d3c027e694e8f0b0f0fa454913aadb635aadd452f7128bf775256'
                '9669a8b93290eb92e78f6adff23e89f57f3890753b51f12f3f3a8a654e6778479370fe5b05ddc92c939f62cbde4c0fea'
                '36f45cd20c5748cf3ac891a4c260449635d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275',
        },
    ],
    'encaps': [
        {
            'pset': 512,
            'src': 'encapDecap encapsulation tcId 1',
            'ek':
                '17e5129b2029f3281987d6624725b64c51cf8dca3562372bacb7ae15fa9f2ff6ab47659b7d305b61f55f571315ff69aa'
                '49e1388100319a650e86c59ba3024c3dec83d4aaab661c452f6cb6a8d2638c133c599045329ccc8f677d24683df1146e'
                'e1c7318c3763a47acff81a03927b9bac5a49dc285c4ee204c4d72dbb1c97fe53c622e621338669fcfac1e30a36f0a976'
                '9bbb2ba408787ee629cec383f29aaaabd46e22133f339c08e29b82c4faaf0f676e1c2b04377975dc3a3b246488edd163'
                '6c58abcd65b8198b6fa8a8475ef541daf34b5adb9db0589d8958b62a88930eeb1c0c352b1e57bc7882c89efa31845781'
                '3f2b55b96881e7f75c3dc97357681e54553ae099095ac38b34c00199952602c481c0f1cf74b550ce7c4f6c5876aff076'
                'dd921942db377e1749f0306f77443a2f058d785854c7e32b67f49bcb99a5e18aab607c649b892b4da7cc7af31557149f'
                '02b19460fb49e5051a7251ade0083cdc1b0b0ca9633220c2b3c532fa2cbc0dc6cffcd4455e0005d06cafc727c778375c'
                'b67ac461b3627a653c843baeaef866c7f67746262ff6d76536255c89045a172cbfaa123d6eca3e56fc922f437a14f78d'
                '1adb54b3e54e8dd530450b8500e15a54c97471cb26ab437394480282ba6b7a786c28857baf387725bb4342b4c3abe4cb'
                'f90612b04c8bdc1599c2d4c66b80b1a1941440040a42aabe03e1ccb0b4190780b6603bb69ec199b063826beaa5447c88'
                '427c6bd7a06e4164a490b955152979b8f5bc9417598af01bcc371577189e1775165b9610b9f75aeea277018b1c2c0439'
                '1115b6f353afeecbaa18aa4001db94fcdc5f46ea520e9836bc5a4576b58c59fc3f75634946d8cc1b1081ce93aba85663'
                '04169332fa316d4ba675a086ad87937963511e4a1845ea38689b564e11295672098cf01d5d4bab0338121128a682b048'
                'e6aa31b83c65ff861e123010433a3c7607ae5e90c438067f637b44adf8798cd0980ec83bdaeb4d427a8f8d88c519e525'
                '42f07734a645a2a5bd4d6521a4b64a96a10f35002780169b35e35f01ca74fe6207b8b475ebc079647cc10aec3c29683e'
                '071d87b82abbdd6d369e326e475325ed5ae7ed232b37f49388c06a740d421204',
            'm': 'dcacfe4de1c115da106acd1eefeafdc7f0f4e5707453ee2d6b0d69d34cc0ef4a',
            'c':
                '1c3204a5a2c031077459e24a179fc80f8833e19f36e7ac0d3071bfbd2d48fcf1352b96efd0fa3195b44a27ec575b2794'
                '909e4089421e56409ad00cf472680f438e0a6d39e88fe6b938ef722c7b7f75f714264c8f22c528a63985c75d2412278b'
                '137acd29003cad1711a2637c630164507b7d3c0acd1dd3ba6e689411df6d3eee410ec8c93ef27bc82019c3943b85e645'
                '519bec1105d4738388c7a5452a67880de88d65c1626a55a4565b5c26b20bbfc33f2dcecf938149d8b58b19dfb5f451c3'
                'a9fb5ab3dc486c435f5397b6e32416a9306d9869b91231adfcc9a4ad3d956ec49832c3ef2a6ed50638f6633d5a8fa7bb'
                '7b04ef45ff9b57d6ea7b771d57c3e5b9bf96e03abd601bb46e5ce3e104233e7be642b082a610fcebea684c516aa39a05'
                '1ddb87025ca849816e177c17c10115939b98b5d9f95323328cb5250c4e38b7e932481d20bcbc66b0becb3dc1aa196f5f'
                'e207b28f36344a3c00f2fbe179878d6c7981467fc2df70d079088f09b4d2cb56d5dede593a77b31930e8f6138dfc7f9a'
                '7295fb372c1a33713610b2be51f311e7ce6050ec276e5c3a50790ee4cb81511052ab659dd54f4baf211eacdc2a4e987c'
                '7e2eb8b384f06813c2542bf765c3e6b142968bf3c66414d01a205964e743777040a6a9879c84681b6f6b3f2f2b0b0455'
                '952a99a21cd609c1fd7be71ba6a1c9589445dc69cf1d4937763ac640df853fd3e6dc9143467e473ff4b89975f24cca51'
                '506830c279ad8bf806611e836f405e8c1fc36208e99acb764316bd7c42d2e248b1dc3d5c551ab77fc168296853129c31'
                'f5722707791fd5f9aaabc4fd4c82a99970a93f274fd0d6252edcaedc076bf5984e6e28056bb831ff289cb0f6ee87bc48'
                '16712da0f322a51765f5f230d0de72cbb4714c9cfe56c1bd727dd7d3f7c1b5b83029c81a22b8fd430b137003b63f29b7'
                '10a1a2c549f9ab0b5ac8a123935a1a3bf627690252aef65f20681e2e9a664321cdf5fde1943c196ba2f04e42e35f62ce'
                '77198f01a747a14d57d7ed46259189a6aa3363fc178a8cc5499f033f9b8d90d327aafab7de16831e8325d337ab3dcdf1',
            'k': '2d74374b55d29aa585e144a29ba4f0a96537a73b4f176c5527075f66e38e8858',
        },
        {
            'pset': 768,
            'src': 'encapDecap encapsulation tcId 26',
            'ek':
                '9c6839354086919bc7b8a547ff18b523075fd1706856400952489e4cd13ed8b17a817a3076e0947b860ec9558bd9d3c9'
                '4df5418a7a7301763999c09996715ce32aacfef767a44969925949cc9b8120cb78953bcf6fb8282427cb3f4cbbc50ab2'
                '3274493a8ba7e5c09088160fda731b55980867912bac53125b27073bb502afac5e74973e0f3601dc50ce08cc7f3fa44c'
                'e331a43f9673be745295e693077264a8e238f0a912c0a59c44d561e2a8bd831541fe869b3110b051100db3517f87510e'
                'cad8651ce4998bb648002ba41a5351fa2a4ed94a58cb707214a59f8876176cf82fceb99364971c7c0896e8b62c054446'
                '3ff101983c2045981ccd9173eb33ba18483ed915bd11ea950db3a8787c105263242e3a64c748b8b1a5947880c5bf3896'
                'e08b4b9916a39fd70c2ff8bd041a2b18e251d16a276e38100a613ea96a86cb3652dcc83f2d31cd9f8b79e42541a66752'
                'd191436cf5b5d8350ee7835cdb122855392c1da5c33fda12ad1028f2806861a2ab9c63785fd11e220346322c250936ab'
                '819254734a8dc9241971ac90cda6696adb90d1e327dc977841aba38324c8fb2092784942003a0808e5546d034592f03b'
                'acc19e3138c9070ccea80a933d536c49e4771091af8a70207d474574c64b9f1c8e47224174061117e98c18897a7b1b3c'
                '4478c6558c321a89a84b6c508947cb61c89204fbca43bcaa1d688f768b02e50babebf0c5fb8962b2355973c4193fa92e'
                '0ce4b9f8473e154828c986bf63e1cd985c6f0462c9b4374594d226c5e99b8a844978db8dd2839e27138aacf75e917635'
                'cec4b407a54f184c22f62981b9f4552fb334ff2b7ff68b470fd61b993c32581cc0f39881a5a6a769a60297f4b0579acb'
                'f52a8abb143885886245ca2636e20498959e4f2857ab96706e6409c4164ba88c7193e568e4446120215a6d8499c6b4bc'
                '559628a9f481c7db51e2e10df1f4339a647b4ccc0405b79f70a90ca9a8ad07789222ba6e66c3aff42b61baa637af1512'
                '6c88b2e210a7cad9cb08cbb5123a7f9bb4ad63daaea6b43f9aaba561212823cb898a676c967b2d64f4b6333439f8993b'
                'd7b19687248926e077a9700431a59157b9668ee022b6d31343f15c08f14488877dfb30a552c06f96a16f354b9a3f1909'
                '0b32a043b43256ba5b1088b56a4125588c8746d4099ea21c4f33ad8c5c7c32286dee2ca76fc2651d57aee9d847824ac6'
                '09b5bfd5c87316c2afe0e153d6326af89987ecb70cf0a0a77fa000e0e0acc2685e2317429c3a7513f42873cb98f66970'
                '3ae9146919226db58d6c2b93b6f50c7cdab677b505945a0f2523886c1b82a6a7cc7eba9251096d88360d7ef6473acbcd'
                '359a0d20414b95c209b2413b1483a3a061386377b28e3896bcd8c5e2692681cc803e1694efb6ce353082ffca4079ea9b'
                'b7b2025bcb68990466ed2803ab11516d80325dc4cde3da9e020653e084c45f837c88711df3aa6075741c1283121c8b1c'
                '691013969a62b2563e556206cf0810848691c7c408d018617a7300ad943e189a9b44512ef13b669831392f1329e2ac7c'
                '623aa044223079139b7f1c213e93682ed86165468377d40884310163a5539f27745e667adf506896ba933b002e4d50b2'
                '497ecff09d0bbca4f7e6f9db9e10c643d23701bd6385e163cf71c1e919a6e20a',
            'm': '4e77596168711e913965d8175ac3bd76aab08b7f9385a02ae883cf6c6e17dd81',
            'c':
                '0385e8044d17e2b96b3f50ed28c2502216322ac33f69d2ce34f0a11e9b3de339aebe98283a6010a34bdc98b0e5bbe142'
                'a38575da305066331d8d11d161f512b4b56b60fd049dfee3771473253a0310cd842c71cb7734474bfbdbbadd2b9b87c3'
                '7804d8558b00d77b1f79f0fd2c94552a8d3b19fdd6a5511c4ebeea40aa839a489aec636b510bf51bf3782f24f53f752e'
                'e2db9fb4964e8379d0fa70603cb8c2c7293bc35a56b818257b65fbe6b2c98178b61d7ceb58c7e1a9100650a945c739e3'
                '603c188ba3c179823950c6d874d7fc8f8ddb7a9ee941f4a78a0f8a1eae080d4d77893aaefb0db452659b0275d1717363'
                '90a1b23661c69058869a8c4d0bb46d1655858162012a057c7c067fd035d47d5d627e3cd27cd3ca021a34f8db6695c7e5'
                '81ece67d898482d509e4df61dce5bbdfaac89465a9209c547b4263e9155940f8fcb1da3a4a7d25df2969f31644741a8c'
                '6fe8065d5f176214a4db8fe76bf41869b0f22e1f5cf5c34a5067b1d9f39f3ab4b0b9f6330d7cf6ec7477b53d9223fa70'
                'e4c680d49b32883d92b50c53cf9e61915437cf57eca49d6bbc88c64ccb222d4f20227cccd4f7e7c21f95ce74d6ab5dec'
                'e17f600ad1715248648e4d1af6fe41a02023eb5cff871ec654756b7d156e601e82827e17dd0fe4f5357136120a810506'
                'a40f28a0b860c3ce75bf7796653327939b507043ab8be0175a9b312319818063ac40302eb42452da0b1cb9e3c2e43c49'
                'd740a03ac1b9057fb44eff830d548d12585f50dbaf7404c2dfa7f4403db8b7cee65df528f575c7f552d0632553fc6c90'
                'a3b09c1114492392c165e9b1b0a10e9556c72cde2bb23df6da784521249eec542012ec33599b97b95ff5234158a6d553'
                'b3bbae9704e630d64a66d658f74f27c8c30237e87686fb04551bb128d917305173e2788883352a0216fd8d0035d748c9'
                'b42a600073adba73f851bb5eca287ad325a3a3561769868c56e6d84fb661ed5a41649342ea342f82be528fd9bb4f4924'
                '52c0a9426ed8677113ec6f1cac51233f0520425c3b27acfaa0d25a07bc2ca01115c90432ed14a1f4dda693c6e704a16b'
                'ece8972d8218b62cec4f255058988b224d86f2bde4b221a3c672cb744ca8f9158a4e5c97d0c56af5dfc1c5f0191f64cb'
                '6d7ab86b14432eceb5a3ed77a8d3ea651a07c9a0cf95e631f41c2ab29191f66dd9a73271f47a455999c5fc8391550bbb'
                '346ca1bcad598a32a50cb52281156874f36de9d8ea5860d99703ea3f4907c640b47a75a285b4347845cd6c94407995f5'
                '69fd8a4b12461d8236e4015ae000e2acaf2bd9f8d28377ec0d9e4cae714c481c5abae37448b3f84a291b84b4213c8fe1'
                'f6e0fdfa1a6d1a52c974f795c5947f667a8dbe162983ec0c71c0f0237e6ed8bcb7ac9e4c73b5a1ed85fd5e0fa2810c84'
                '2d484d6f9dfcc8472f05683d9d1144ef6c36294bd06a019efec202fc46288eba2ade82aa3363faf32b9b027c75a7d615'
                '845cf2ec538141f1746009737600f697cc8d90c80c1e19f1ab2c08646c0e3958',
            'k': '79d74f6c6c2d916bec47bd828fd9b67295a37f54927fab1263c0d122f1c6f1ed',
        },
        {
            'pset': 1024,
            'src': 'encapDecap encapsulation tcId 51',
            'ek':
                '2191abb6d6beee29c5780758a970349879b61a028deea5404731292346c81eeb1d17766afbcaa68c867d91132f34a494'
                'e28caa767241b50902f4825771865fc8d633736248963a253dd52c1a07c7177cb6df74c43c3c74d7133da9dc915fe14b'
                '5bc30b86153e7b86be04189f4ce8ceb6e5cb69808d35640ac50335b1633162e28260300646153be7b26a84c1c565956f'
                '8577c95cfa80b68978cd7a79e49c7e808b21cdb460ed8388c4859670333b69980b2f9a0f78d7a5b9d8554893a0b5c524'
                '47b15318828989816f43406abfa4950607a5a57cba62f5c4340ac3d294191687c7d2b60ef2d83f6bec15b1618129b785'
                '77447bd1e36a87142b9c552c8cd2304f35b81b3bc5196c3840c0346d513ec8862ba14a172c051402f7398707a6133c8e'
                '88e5b57f9b9eec18aed1404ea1c47be5169e5d558e262a231a75925d25c499650c8ac031be580cfb185a0e0362ce2194'
                'c53713a630cb59600c1942908ff5142b02364b74b3f5474301ab2da4188dca640961142f28584ebe810683c046b59cc2'
                'cc07025da63a5e8c5e99e24fbae183329886279c2d58d0b8cac1c7b3033f05e765c75414748687ff03c00b36709d41c5'
                '968528f178cd03b813b69054d3e20fb6a04a713b1b169ab5f0369810fc5cd967a866b70a2d87514605794930be9b7b5d'
                '49d08f5cb08d84fc5beecb994dd2a5fc10aeeb4cce1ed251fd4815a9d06eea6a77f18c56acabb1f7c478dd52218b7bbf'
                '9770a51c3ac96402548a1bb22dd0c29f422330057179ec2d91e1aee27bbcb1eb4671324265e28676090896e332535ba2'
                'e9169c54113f19a45229c2448078ae08f7213f347244527ef726855ca054ab7a1ed1a40a285a60d04c00ccfa8fd318cf'
                '182705ddb888df652669b3224cf54ed6d00db5121331b40c7e35b1945925e5ac1503a999899317a2370020d818733303'
                '27db7cc1d430e32c6570fccffeea90a871a4b04ca9a8065ab20a6459f1806221a5482802f14a68893b111607c4e085a5'
                'a6410c027c1bf5fa33adeccea576211f272cc942acacc879de398477780a26e7545ed693edd66ad24772b0c0c4b033a7'
                '3ed94e1d02c384d1a288a78f5d8838b5ac0b37855dc59b987ec9b0f5c6868b0319f3372024fc15b247144f925d3edc45'
                '3fb8551ec1ca734a37a3972b8cc9b84a217a4d0bc0d08c815359aba59a07eed998133587e062cf735a8521a18ac2059e'
                '3f142f12ccc5ae024ca33b8e4a285be5a3ced460c2c3675b956294ef2c61c96a88441665d56b2029688efe4540dc35ab'
                'f5957bf9477f58277851719547510f22d01a13d0047c5b88372a654c732aff395dbf825829a06e6ae6923296218ab9ad'
                '33d0b07a0b6a3f3b3dd8428a1f82b72a921853d94c5d400494494f0d168148b5392f386b16c6056d6b8d767b7f4d918a'
                '9384c855c8b4de8450eb6ccc2df18528cba0a3552d5704683aa3aaf52751fd5a17801a76a58a75038533c1576e8668b5'
                'd290ceb20cb1ff91317d9b418311c11e617d10b4b0e9055aef5cc6ebf8b91f0244ed9854fde463e55112a238038750cd'
                '016735613b9c461996b90a3b4d4b0d8b8825ec087fb138ab868a04cb3c9249b5b118f81ed06b99e6b521f206a32a4013'
                'e876c6c80b36af39ac197a21b78b5f2713aa45c74335f32676c2ac2902710ec42af5984687a672e0466831c7b436300b'
                '30351795b22b3a939347a7b744831bafe78c3bf09a8224a958568f75d71f822941dfd64d8969ada5b73c847272b59144'
                '91bbce5f0c09ef501babd95190f93201ab413e833f7924b696d5c2b62272245932a6d9c35e1670aa3bc57cd41b8d61a5'
                '2aaa6d80bb774f922ecb41cd58469c4dcac698f6730890237602064b148650c17e6edcb3713382fe755e46f3abe0c6c4'
                '5184ae5c5c861e35a0e2bab2b4e8a4775584351170152512c7e99e96f285b916605b53b91d6c501f51a93129483046cb'
                '2dfa16d4a540ed2b6ab18bbdfba2b201baa20297ab1fe7133757c07dc041971aa4219157d77628f31aaf520650a2250a'
                'dad1524e58268d21cc62e2469c8425e86359dbcaa066acb466e06947a1c144e53ee0dc930432c806c493b2bb25757b1e'
                '2c775a27a896ec25b58e8a78d4dac91815a1f3d90635ea25ae13cefa77877dc0c2f0678ade307243b438c54aa69dda53'
                '9b8a41c1b3c98c77fceb2c0bc2025a272d927943ea338cdf32a0dec8b187df5c',
            'm': '2f1e2ca7bd72af847cac38cdefc4d345909d7517543edf32e2fc491ba05eb5c3',
            'c':
                'd892e0948544d020ece56f00c6495b9bd1c469ac0f134002c864d10cf61c6c7887890276a7546310ea077741d83428f2'
                '2b60e2a40ed8bbf5d9227893bb0b7417df4380323426ebc9744ef35a1bb6dab1181ff0b677e8c9b6574360994f96eb87'
                'c3524e15e468283169d90d8a994bed0da9cd778ca239ca6c225390221fd408a3eae541a032d714f3d078dd1ec722ca83'
                'fffc92a416f46fc1e8710c3f8e9cd452c016f483985a5c1d951fe2b03c4ac2c9a0ba71f6ffa4b29ede76df69cad594d1'
                '0618b94e783fddaf11cc801ed5036feb4a70d071079944b7d9f1ffbb98f123dc34a52a40de57e079a1f8b180da9e6eca'
                'a47a111f3c054dd9563d7e74b95ac65ab453afe0bf0dcec5578fe6fbc2d9eb91932799ea64b2dfa95b2c9c6e931ffb0a'
                '5a499ddc42c6d6b563d5a6c1f34dbcb36f57e6c10c69feadc70a3d01f5f3715f6bea0d3e2e7ac2b04e01ca80a2e187bb'
                '7d9efa5ee257b9c3caea3947d785ca56a76d0b6692a69418935dfc36fd9b26758f5e1043d5c2a6d5cc1556aed592bbcd'
                '652f4024bf324910f8caa2415171f3ec8b1cc494f2b519cbd2b13d317672de60f0a3d400e6079f85c3cdad0da5a17f2e'
                'faccec03d3c2e85b063ac3cb29f2fc4850705b8d472e35dc12d06a7d021db302ca883dc7d4a57b7a9e1d023960d4ea5e'
                '39c9d5bf328b8e4ac0afc3a6c990f598f373059ad28edbeb90412472c637877ea82e7105caf467a15ce961695f2ff04c'
                '750e277e78c1ce9e490a5c45168936bcf79261b95fb20afccdce790e0aedde204da4f6734700fc1ce05239f4ead0a496'
                'fd8f733049ef9b6ecc54d5c635b56d6fcac7aba1ba32d707d888b820ce3e794c2562798210d726c6c5db3d22a214f3f2'
                'a1f2477fcb77377af41d0f3f0ac635e7bf0674cebb672ea93b9504efa8c5aafb7458e41a1d85c28841877ff2f444005c'
                'd1c1e4227573e8151184786489c7cc39549f8a29b9c4d68be38f24081fe239c5d0e14ad5e361720836a72a99ce88e47b'
                'f3e6a1a9eb57cdc3724cb4789fb88c135ca9ccd94ccc9bd73ee8a796bfea36e894ed27b0791e8ad23fcda5ae7c167d57'
                '74aa00468d97bd0fd2b9bd78d01e1e39a66994a369212d95d7886be00f2b7a1f187c85b873f33cb7d3e4c23993f7bc9f'
                'f7abbc6fd9d5c54f06e5f31b79da992bc0f2aa79a36bd00483ca0add2dcb2be36c27dc913668f030128e82281e5e66e8'
                '7c75dce3fc60431ce6a19c6c45e19a2d84430e945034b7da6c506ef009493af22f701088e01c20acb21972ff28d284d2'
                'a57a69d108161938f028011ba985e2b925532b52eed878646579183eb0ef3fb57be1e05c1bd2b68d0e4a9ce104e0ecdf'
                'b30268e6c007812fd88498d97795447e7f88ce8a3bcd161b1e34dcf77413b778f88a3ad66f247f7664d0f6af31ec1dad'
                'c00fec09d6ac63fc8a802c3752484b5b43555381043fdd30ef5d7dcf4f5b68eb89f08a0fe5ecb65d6d9418ca5283ca39'
                '8d3129cd3b44edf5e3568c953ce2b66a28b473cab0c43918a05c5a4358d1392604495d06b395187caa6b36050b436b21'
                '8485466cb6643eda7ac66aaeea758715a22a8849066879cc966da7e0f7e843a1e234920aecf2a4fed2f78c69a6c103a5'
                'a535d77976b1e40bb0d75d6e370212017734f2b0be9f3f87c5583634ea6a998d8fe9ce5e5905f2a6abb9d635425d0673'
                '1c1227eb634a3603d081cb1a7c2b0c1685942efd6f65992dd39aa67cd954fa0310a0f5866ac6121e27e349d5c2adf37a'
                '672c1dfb021a855000f0c0c29489926b997930b20df641120ef8605cfd9482eea9344918aec689f580a94508f318e63e'
                'adc3eb7486b9fcd7a92ba16f5e02cf78ef73f528fae3a43d451c58261a82b3735e09d4f4679ce112803505006cbae6ea'
                'f641a6f66b0c51ee90095735d87ad88c3d19cd7888248fcc3872939605f205976ef6c6aa52f8316e9def841594373fcd'
                '177f0e24d8975653a29f738fa8f0d457f2d72b7c00a4b7a66fb080f705a8bd599314354e65842af598b8a2a40f6cb320'
                '8762ac6cd467d06a2e987a7af72e355bea297da87bc9250ebe8d8f85cf292200a21d93475ba46be78c17c1605c10b976'
                '59859f08f980114955e68361e180c98015aa46a776070c4f2b328a903a70ad226742f0022279179fd2530390f190e300'
                '8f7202c83a6a15866df848c8a150d12287451dec8ee7f04c1c3121e4bba687d7',
            'k': '5087e3b0c90bf601dd6501e071270eff8683621e9f5d67a7a668e50c4f460a75',
        },
    ],
    'decaps': [
        {
            'pset': 512,
            'src': 'encapDecap decapsulation tcId 76',
            'dk':
                'b5589fad1b1ed2ea0f5869628f8777567062e7c4a06c619635b90c44bc3b0b19aba7d01a90594cfb8aafd823329d502a'
                '08a5cb10a7827d6b9687634bb1e3805ab22370683871e78a2d5ac9ca582c7b01c1306309beb9c2f9761552265d6eb67d'
                'c635b9025acf510c6ce8d1801cb81e47434ade02c00318c4bbe349f751c75a80225f807c7fb976f5bb5478f805677379'
                '5db90f8a762edbcb1cd2fa53f69a5c44b726e5b5926f92366351adcbfacf4cd9492b216638f4959e3635a3918bcd9aa5'
                '9242667dd886ba9b53061421ac3206a68349357a0db7b1b40c2b6bb41676faa77e05b3b8c57c549caa2ba36b6540aa06'
                '0129b7f5a7c59db17e5a9708d6c88ac4b3c8b6db1234a75319931ad3b6608031ba1a45772dba8c39c13c24cba719382c'
                'f6231ae064c127b782c5781aeb16cb7c7767ee608d37986cef629ff5796f9ecab3a0ccc8f4e0687f32be1426a198b00c'
                'bbd2a99616268b5a3b700a1990a75158b668ee9637f3f7032da19b7f7185b5b70da163792a79238f8ab3755ab4a387cd'
                'b6a7905c17cbc259aef9b534d03860cdfcb8c4349465b8847c741b0d522af5d976e2d70cb7350a150a1217481c73cc5c'
                'dd6393aac9bb6c68770819001af7455ea2687c637ac43ab3812981a511bacbf23dccd3252d1860a143b4939523c92c94'
                'a213bced384d79555fece80176f739c955c8283668cc1208b8b08fca3027bb7494bffa6b2df317bd36408fa0580d010d'
                'd4376ee6d91a0bfb70ad3c086d24a9991a53c5fcabf04647a7d777ee428f749c309782c2b83049b0961889012478981f'
                '16f83b6048c0e2b1c67f739b4d48256ac23341984ec19b7286cc301a7c205af19b4dd5c3ff59a00c75048992bba53936'
                '9295bbb4fc5245f2598b25b935a445eb6cb9305408fec37bbf8c3e74baa1bed452a4d77607ba45dec85f93a30a4e3396'
                '0893ae6165955141284c335d90c4799e279e1a997a8c93b3696377f0941382b41104b84a0c95882b006435272609023e'
                '705415b697b2ad9ac5c16ab5cc343eb293334a298cdce4bf4e680d92e3cbf9e38684522cd496a237ca72f453af6ca07e'
                'c754a67b21437be714f2361291b7b76fcc0b740acb3c1c71ea20149fe5c27948a09852c2a3ea773fa41fa70804ae74a3'
                '44e7474bcc909a2893a97a89a9d755e7495a9df0b292259b5b904ffd8249aa5590027b91dea4209a156994a4af3f6143'
                'fa599869c2c293c9446a431c439a92a94cc1c5977232a47edaf110202ccb5c881ab81c29d30cba381c316ea8016cd912'
                'fe7c8a3515cc6c6223bd988768d562fe72578c26896d5b03e1d920b574295e88bc3df657ee000d53b58a28773264730e'
                'c50a70ebcc42506939f185b566700cb8d01253f52287ccc02036008f43cae36bb71aca892690a548f832314cba13b118'
                'e6608ce584932b58284ef38970589508da06079679697b8bd8b2345b332ca0115edfab5a7f9a0356a3c3f102092f705f'
                'bd69016ff9a13b0ca21854a0abc53d00189fc57b2494e7977beb352b24bb8f338fd30a4e70c4379851a295a16d8ad010'
                '0db46ed772a99799198d9739e1f543f140324243767d71070ba303177498b029608f894160787f3de62ce65b74278b5f'
                'fa24a65b89a59097a1ff437eca2c431cc70ca0418141c36574d730cb64a234db88f826112f694ffcabad91a93dcf9bbc'
                'bd6071ee0c6a500bb6c78a1d5d362a45046700c09cde0360c9a9754c4b5c26fabb0f420aba265460f7729b625c5b6b7a'
                'cf97766b9032f4a429cc76c8b03c7168f7037e8101830c8b838b5350d2a9cc575aa88c3a673a81fee3ca79436d2499c2'
                '80c1a52e0c5086b5c3c209410214ad4315704545b74b98c13ac3131234212ff344c3514c876a96006d5dfa01bed741bd'
                'd76260c026c29e78138851319bc71f12a66b2d362066a1c4b2028303b91445aab80426ae9465aa25859b28f1402179ca'
                '3d1c073ce876aef5b25f964149506c15cab4698c91ac94abfbe69dacf06323e9a6e151ca6c019f49078e60c41837b176'
                '3bd87ebce040a2d7a3d4964839e4ab07d121ed3a2e23f75ab6086161603c20b7bfc063cbd00a7392e26d7f697c17ba0c'
                '62231a3e34a72c0bc958093c62471b7d1a8b2f7520a0581e809048b4798c0f1a0a2083306d6c42233202f2101c1db61a'
                '58086b24558b17d5befc7542572b81e9880d3f164d708bc3c357546dddc39c71c3ceeeab482ed67e61cfdefaaedd3027'
                'b700de0c72dd84d43f2b81f309ec9d9e0069dfb3705c76b01e9a8db4b66437487dcae2e3319165983c937cd3e95c39a9',
            'c':
                '5eb39c88db720b7c6b1dbe08047717f870671db16328ef96f8ee9827ad694cc9bc662e697d2d30103851239332ce9b2a'
                '3653bd98c3faab41dc5445fa844e05e4d189d4b8e6e3feca09a81975aa0585e1b179808678f22944108af19fcfbf1c58'
                'ba76fda508449ea6b3312f8184d1e568c1a4b1c188b04e654978ee9e7a10299c45eeebad0a24884e12bbb05f0b9575ed'
                '5c8bacdec1ab16a59ebbe2b7a677559140c9cb00e18b4b5a0c51a4a92a61537daa2360525d699de4f30db0b4d841b708'
                'b92e38e1e07f3a2ec124e6c82df062b110f48262ba95a50956b7430eed0041b295fb84c38bb2b96cf1c85e88d3bd4dd5'
                'af8e1aba963fcb9d9004f5ccb7fa15f2d8781be9cc19b77ea6f397372f9b6c9b375342530f4fd4e3b934e52b60c20fab'
                '1dafed0e6c72fad8783b62852000a24bb81273bbf1c25edd879058c5eef67e3a0da14e937564a508e9475ff3b25b5687'
                '046684760dec75132d14fa471d54f4be9ace2ae9088678f44104230582ed466fbd8ba53150ebdaf126f417183689a245'
                '39358b00c4eabfccec170c87975b3dfb9ff6267e81b44c93cc9451a3f9f7b913afde043748c5f7f36fab63c801b0bc50'
                '42c3d44d836770e9058e04f3571b04c0c87d38b17dd1f7eceda701b0532cf35a096f8237083834aed2b2aba4df1cfdca'
                'eaabe69dbcfb9b4838c8ea1a9a3ca8ffc75ad9b9c0366517d782f412946539cdf0d02304ad60beabff9d9be1f75ed39b'
                'bf2f10ffe061f2828dbce798de6685a3f3f52477b361b1a42db1c0922e8d2d545a6ad54f0cac86f6afaf7b381dbca543'
                '30f13bc19f7b698603f844170b90658a9a82ac7d582ae798db6eda9087e1e7eff6cb903558a289f988d5cb5d2c52db0e'
                'ca5898e3ac15b136640a38acc68f1a7be53c54f0e1ee66556663e204ba8399633348ef38c7b1ff500ac53958d103b984'
                'e540732459e860ba5f065b466faed85da80716fff2f57371d9f9d09ebfe3a088b4c2c44e1f03c73a97830269a41419d2'
                'bfa48fcc16523745e67c38e4be7344c4aaefe9bd667cf4741e5f16607680378df0d2eb60db6db6aa66a53b63a03e52ca',
            'k': '1eb644ebfd75877d0ca481e1a3b95e7c461b81e0e3df5a42699775c7bda3b004',
            'reason': 'modified ciphertext',
        },
        {
            'pset': 768,
            'src': 'encapDecap decapsulation tcId 86',
            'dk':
                '859384dfc0c207a6466ccbbc507c26dfeca413e06e46e30cf18528577b76c108c31e1b6efa8b41044a4fb2152d3ff391'
                'bc6443b57060ae655b0efcbabc889032ecc986d2a144153c8189505c37c6bb1471e5ea8c1521770d732e88a1a3b0624e'
                '5a2a42661c1743677591296b81447169635160f80d61f31c420a5d35f5adfea37e4254be39741e197056082c1bd9390a'
                '030b2a63fc37dfa561ae091dd9da11649bb7406464838bc23c872423b7515e3444fb862ba7d51becabcf9b458f302905'
                'cff983d00578ad89686721432221782ba7a134e052bba7879a36654c081e4c3b615a1c764c128afbd79ef0d816c7e5af'
                '135a51448c14cf3c6172e022741b889da485c208899190bb2cb8090bd2b7f8213213e090b27a9c3c56bf87024bd2e300'
                '1cea031be20e959bc1a75281b8a3639f487c12f40786e5458b14747d965e0e294947d6a487d44938d50829d0723a9108'
                '06b9376e76480141960757cf37e2ac03b4a6767a68381a69f6b45c274c62b800403c1c992d0b84d336560d6b4bfed4a3'
                '8edcca3c61699d31cb6bb88c10909cc6081d1bc9a549f604373576f2b5b14d453eec5c7673b5a39ffa8b6a223972019f'
                '0ee7300bc82da77414e4413648b68fc8e7b51dc6cbf083098c1a2f2cc680e52a9e7a8964eacb2df18b8da1d603317298'
                'b797bc17524ea03376ba3b410ff1b1b23526d3eb7a8255380793c5d938861e4983d4d23cad3a34bb256434dcc315c40c'
                '8d0a9d2132a595b78dfbb655f9f2361a379047706400e5cfa1654ac779841c0767ac8c1dd27254599137d9f3355328cd'
                '34e581e1e1bdd64c082eaa29a7f71610b65766882ca804106ce0bc5e20630a44bc5ff87db491c2cf7746b3150ba03abd'
                '907096d8004fa20384fb154f553659bbc451c09c0d42a43035994cc24b4f798bc7c961c6c64c92f2c63e87149d89e982'
                '21a9337f0a973226557056952bbc05abba46c7ec6ce1b2721a0487687c16cff6b50cd5bd59443ca765353848aa42323e'
                'bed3776c014d60d8a6b6d6b31de26f11c15822991249f76c3130735d2c22d5d4b4550a3428004349073e3f296a286c3a'
                '0d6572c383b3fd277439c85a03b42b584c97b5779a2d675b6de024949438aa8700aeebc9ffca10c8b327ca6b917b899d'
                '3ed817c4543cdf288b489c2ef3aa2f95f310b0688e3e81aa83005571812a5267781ac21c92f7c41f359de74877c19124'
                'fa462b3a181bd885a3c3534f16d99afea4bb6a434ce177c99020c880eb368fd211261172f0bb7ae4270fc9aa6dfdb598'
                '5a1c069f1815e9277bee24cdb1ecba0cf2c3c48100f540a24e4050f9b376868098805136e673150c957b73ea3e7bbab0'
                '76b459d2157e9e501734500bd2b574b9c563a7ca8ad83b6cfbec76727b1d3c61c289958fc8805ae6e4455a5257e89038'
                '54e35112b7cd46185ea16339dc0838e118971cba5a78025f86749433a38ab79b58e6e6885003470e208735177f82d738'
                'c3f7a52d848b742a75d115a528f4915078632fbb639145668b504c30abb96929a75fec5deae90973b2431d685f74c98d'
                '36db263bbb6c73d71974993e13b50242167110262a8eb406c987481eaacd44069d53c2b967003dd2dcb979d81a97f623'
                '51344bc40a6b203083918c40aa459ea2e20892514749556294534cb3e3b948f1c0f7a941fde49874c609973a4e845b11'
                '2456974b3aaf9877b3159b7ed0c4c423889c8a8b1c5b33409a8c6b26f573a6668a5fe0c74ad0ca28304d1c7a498a93bc'
                '08921d3943042f986438abcc61a358c6482839a524845b04ffca16cb741f7db5b0afd7b9874b6b53d156b3e036b3d41e'
                '963b27ac0c87b411436471591001635e6440903a0b38302a92c8777f264de5290dd1e511bc7c0a68e3266882cedd30ac'
                'a8928596b7affb28b94d8711e31a8c9e5ac2a9567b55630d5ff8627e52386408a1bb3bc2d6b90a7c33c04aaa60e9046e'
                '10d89b41fbb8e3e26cbc27c1c062411436cc22d637dd021cb93b6972cb7aee5c98ad64006b0cd070b0ad99d467158c85'
                '852b88666ba1de29cfa3047396a5bddc76b1afaba62d622e17f846e17487a167ca9b45070309526ee08791647cee81b7'
                'aff21ca97c7d09a7b0a2880db0110461f168a8f5bafa045864373217b05ed1223fd0b00a1d7810e341c15ce69567e826'
                '5110918b857f2546beb5761de3849fde971e2cc649c363c0ef296e2dc94b07499869851ba3032248e4a628294d626c6f'
                '38c42530a07952d6b44b650112f77c8df5c5939102090c8188db61f3713e93c4a22a61c91fea79ea06bb1344a5ccd638'
                '12f540a8907ffcf62fbdd7344a744095bc5df65047dcf8362a38bff92b5b6098893ae96286f4199f857dc5351b962204'
                '807b9421602a0f00222a82b6f4785daf303354f9c097cb74a0723cbfda0553c4b0b4454e1ed11c6926396be9ad5cd160'
                '11d333a1a880e123934243542776a0848b0ccc442bcb117c24982c42d10510683e7d534ac47c6631acb187039d098b7d'
                'e551b868a28ffc42112253aef0f86f4c358c778017b30c0c3510254e6abf50664fb54c197bacbb790c32a935783093c8'
                '8927b65c5c696c695cab4a845b262219c639c4f07dcf663914094b1db58dd04105d7c6bc32b6392d481bf954abacac75'
                '70cb30bdf265e955ac1df3a356ab59c89b0cc6db7ecf4185f81ba9af7ba8ca47bf69a278681c1c8216cabb4887a36620'
                '4118764669209d502be63bc8f21429e7434b381b55c95c53da864e333c13e7818644788a381215a4954cf3a038dae27c'
                'a4684b130268436cc22fa100ebd843d6d9a20dd0b8c4bc8d56899fd3e4272ca1301ac9429986977a9a4910a785990629'
                'dffc7ef2093aaa646741825e53ac6c43b962b5624a4d31a5e054436a2b7b880460a52062e4c5c9b2e72225dc2355d44d'
                'd6b22a18ca6a05094bf8d3b2a0c58c13777bbe448fd0182b876a596e595ad4e79db6f0c1b4e1435507802e2b539edc25'
                '820b23e7127655e11b34a5aaff25c11a7b617ed7083650c9030462a79ab77be63780a45f8ca96dcb15358e56aedc3136'
                '0b2030010282ca67cde5169993fa808ee475bda0af49c216af9506330c9b0384bd2c3c51b814cff09b3c530ca754e679'
                '66c22e44f68650b7117f78235d8425929816526b0a46f647a85a7929b49d677a38418368091590fd1276ee9629e63944'
                'db4770b7c22e30b2cffba5b6d46a9a1217b7fa44b54b8266f07554b3ea970cc30d1e92c03f41ce2a2093f58a831a4353'
                'e02393cb8969a582d55545ec39a61104ba2e5bf082d0d9573988cc26089b222718d29bcfb365365bd9529c55aaba5635'
                '850809b305614091247e8bb47315503a07337ed40ca79d3c8b8d240d3af38c8a7a65ed18047b92600ff09eb509820f0e',
            'c':
                'f8ffae03ca26e156af3aa562e6f84159596d3a985ae42da4e45171ba7c8a1cfee2549efddc414b27ff697920bfc8a006'
                'be1651b0ecd18f91c91f1df9e6332178c3ba45407099c0c5c223e9c88d4bed9742d8a3e1251c6af4b03cf79f2671d874'
                '6e7c86eb270f0c54b3362f691387539f5e7b16680ab51c1f93d098d40cb8698827ae9eb1a85f52199589d561a0fb1140'
                'fad888ab0b03fce03a9d1d1069f0ffe274362f3f1b656e402e3075efc29cfdcd3d3a4163f74ce6b1566cf4626d14544a'
                '2a33ddf5860612af5d337c6b55a7eae01422ca01882baa591f9edda6976e2bfdf945277b4c145cdbea5f22b636dd9761'
                'f8edc518c33223fd46d771e39756b26dfd35798d3aa071f90d2250220d4869c59b3cad020b1e786eb8c856d2ab33ffa1'
                '605fb61cb91c64de695fcc1d61ba06941b5336cb67e648b4197af2b297f4eed2df996e213d63e0bfb54a86c47b286a9d'
                '5059580dad4007e4dc6fb944a53717f325d94eb6a514c13efc445f8e4ebffde3d7b00b955aebce826e4e9568c5e4eb69'
                'e0f3be52c7b441cb7f09ee441bc01058183accde0a9473881bf09c992a86c6511319ee5af76fa80079de11ea7c8b9d09'
                '47c308345a6586a8eda5d00aa7a26346c3e2c90c1709e52ee7ca292e89e1c22b5447449ae508ba0fe2c801e3a0f6d12e'
                '22c93bd98d19ce199aa055d209431fddc46beab5db20fad6b53b93e1e723785ebc29d486fb240d6a4813683e2e71ff05'
                'b4f53eb57c068c2c35f0b0ddabd8e17b48f8477747d1d97aff5434d1f09ce1dd325dc2bb5f79523dd4185dd38d3629b6'
                'e83f76257bbbdcd6963b1edffbdf4456c6a6d2641f035d08a7ee3a7f1c046cd3be550ab93853fc689913e0e136a83ba1'
                '5f948d8f229cfd6e12d19c2fddc9f17dfde4b28a7eac09043f1d4f37ddd4923151e837d7c9c9fc4dc9de1576686b50f6'
                '934474402d53439d45a015ba6558c3032571e1b3263bc7e6cad549d1050fdd49f9b5cb2024cf543b6fb706b636106b54'
                'e938f8ea664d9cbd75ff7042ed9d81546bda255d177d7335a7df06b5d0edc98c6678318f7131ed7564d5344df5480224'
                '1144502eedcb057be3ca1d3ff8c65fa7487521dc9d4db49265dff8158b4ce2a1893399bcb4bbfcd2c3f7d9c2286eedcd'
                '76518026d6586f10a79e02477efd8ff93931b01210c6ad0f75d23a62f68044200597dd277cebab9b5c21c74c5cd74b63'
                'a8b6d59789f5c50cace6676c93990db2f7b4f39e00f455ac002c12367d7bfd0cb0327ef077c45382f0454255b2e11a94'
                '2254608bc41b890172be38e3edd20ed028c37006aa6ed5907c78614748e53b7ee3242a7c1000552eddb67a5436fe8808'
                'd53699e9bb3c190f5b966a1fdbb1da68e8fc630d841c63f5fbe7161baa0670bf970c3e617aaac12c83ff3c1d19761b74'
                '21685f1f6c9c93eb35900e54f10744d90f4d444e06c45e2a9faef1a96f0b752d4df1df86a9503d8d99cdf8a62622184a'
                '919e19df8230e7017d5f411a89da304b67e63cc3e3d901f998f563ca9bd4c9be',
            'k': '34cfae7f2ca3b0b9c3e06afeed554c053f6e51d875d3bd3ff0eda2086ee79f3a',
            'reason': 'valid decapsulation',
        },
        {
            'pset': 768,
            'src': 'encapDecap decapsulation tcId 88',
            'dk':
                '5de17b5a596d15390d5695541cb03fae4073e601c7557894ab341fc31982bba0c92e04badd2a826fdc166e72af283870'
                '3fe94f87bab64cd971879b6bb8c84a52c318834c46ae1028cb839fd912773714c651dbadd69a7323e1193059bd4799b1'
                '4f5cc2ca92219780b3befab65c91b637023b4baa4a63a37d83240393442bb9386b625a977a5388abb435fb3453e34633'
                'a0b803ec28be691c258fe610364b89557c7809357a4c691925ac7d4bd2621f76a07a4b26b3b45a109957d6e236e83592'
                '71f8b4fc054af05158ed6026140543f2d905cc144c3436c966e92e89aa24885c044eca3610921cb1a508e71b2a3f979e'
                '0a33c1edb61c2303057842c937453904c80f4542bf5db886636c8bc392cba8b74afd210b3d3400b7257ea2c2ab03d577'
                'c95170d5c7771c54b63f9c6030cb6f02f9516502c478002af1bac2e11b58ec2009fb085aa8b48c51d4b13375679e7742'
                'cb97548b1b8861216e3b739146487405466ccbe1a3ebeb9c6553013cc86ea0fb2cdfe8bb93e38e66b762af97a98ad17b'
                '6f6b1afa935a50bc3e7154229904578fb90d07030ea8716a1af9c787f789d4b2174673131021092a84145d183421ecca'
                '36142f4316614c2001bb33ce044c257eb592b3c57fa7cb7a3e1ac24da08c15a5a0af31900fb2147bd83da4d58b6aa5a1'
                '09608d53b0a86aa13147435a6fdbad926bb65b83b0df6c432af258f2ac57abb63dd5e6c272c50e5d6ac34fba51573245'
                'd3a06a1d593fae29240883883a5c5b25058b99f49ca6894e9ac225bf44213537204e824c46f9704b89c3c16a52bb1337'
                '81583317968010c86758c5bf7c190c34b8b7331b8242c84cc96278ae586f8472225e795663b379a93c4696407c00504c'
                '810c5fc499a98ba67c0ad6718ba32d4049713b65147ab1192fb46a2ea7023423aeb6526a80585f551610abd45726864e'
                '0af9482f498822778471cb895d1cb1aaa144409873b1eccaecf65a5f5298cab685caa0a193584943dcbaa84c255df35c'
                'e752630a110a988536c8e02ff0554b5725221ef98614e1bdab923bf222567882869bc819ad470145589d3d749372333b'
                'a5977e2664c56c729e7005b4500544184652d2e1653f813c4829c8787a6e63aab5ee171c18ba4b0c5b3994da4af6c539'
                '9c71c910811bdbf48d0267737cf6a7917b80d6c76aea1c091c943d1dfb1b6f280414d93898e759717509770b215aeb81'
                '9dd4b1c425cde0259791129f090ab15d81488adc92bd8707edf3c1ebe228cc01c8d2dbc7c7024b96b2125b965af626aa'
                'abfcb7ec2c1a33487c8bd3745fe49c7869172e1b6a8d92632d712b56886732e480d4100a36d8b8b56107a26c8cf6f5a0'
                '7d51b9ba54a52c9a40ad4c31eb687acd445d580107b6948119e555c0c357a8e0bbb8c62404c46d3b232c8f0a40af3b7a'
                '05b8bb71f04ed5eabec380b75bbb4d262ba1da07c11a958f04cb6483b4737462c2a9a346761c22888a99233511c31a0f'
                'b1cb7c97d6a3fbe78addb6c8df1575d7293e98d3cba1dab3d393a55f3c73a38b8ccd6bcc42b31274cbb7c46acc8c56a8'
                '5e58bd5f49b736423bf9a050f4e5cb6d395f499624046011c3b02e7b98a02e9b6fb561298da8883ec2b2de4a2db0aa93'
                '8c6a9c67a137342bba5a1a7191c17411a649e9b9b47f0c3522264c38f66437438c7b75588787bb03b1c073d668b35523'
                '9e7502840a7183e9c9e49270a1339941e17733792d4beabe4dc50a2351a3f1aa11323490511bb00371ad9ae72f4589bd'
                '5da732ea52892d8a6f98386e67d3b8cc97af61ca9c15c23a97725ba5c820452786cccc34751ccf13f72d2af1a0b7f81f'
                '698b5b8ff9a2cd5b076d23a6219ca9457338236c743360cf9e8a19dc83cea7f5be17d084835b8ed700cb0a1c9d7cdcc4'
                'f5526b63c34d623749c9992a19957aa5c0894a623821acc3cca0b9410c0f8cd59757c53899c1a0d327733c0b7f1961b0'
                'c74b9ddbac662c166c5f787141f81d19b907e8a042fd2b01794b8968486e69fa02fd136ded53c6a633899a368442acca'
                '49f66eb4766a16247128c38b7e0287d3bbb1594324d6b1c9c80a368c5903a0080ebdf6c72a27aa10286859382349d39f'
                '9c91acb06800152b9edc9cb965a5ac9e7c8a6f1439b18b2fe1942c9b9943ee830a7adb5eec6501f593361e0c95625b74'
                '97a02a30173faf47c74dcc4e99a436864a5110130b2b6c8007015d1ebb15c232bf91ab19dca7711ed97d98637e051a1e'
                '686b21f9eaac8652129b69102eb4a4ca0906ec9489daea054dbb7afbcca5c4c8c511b753e8847224f95a3fc8b12a6561'
                '4c8c04ef58a56ebc1170a48886f04e24976411e88e44220f1ce13bba414775e463e9826572b6a879625b348aabc7a644'
                '5e95052c77b13db39f1c719ff597b688a73a23d7912c3ac06b6b8324153e3b2b4c63b361be77267573c5f2a88477a259'
                '71778151a96b1c8c3033d0a43c7378736a2caf73143e3cc348fa239f74a3ddd51cf10acfd78735f1136576c97718d782'
                '2635b2bdb159ca2701493489f4fc8ba27a5c891abf9d73316c7583248956bffcbb790c3519b010018887fc891d98b33a'
                'a62582f0d9cd790626afe183269834c742589497155c5545706c0e397b25909b18ec3c734b824a6095c2b0843a0a165a'
                '88729dfc1bc0319797946ba4e3d85e3d20b1e0cb1eab0547ea30c41056835d3c78a7487f6cb774b9d68f7e613f566871'
                '7bf81498617fcbc730f93377656c9a6033347a4ac0749374ba8807e2440758788cf7056f9480936524608704281499a7'
                'b04a46fb595c7bd274568b2c7007442059bff1851795739568334b2dd3517092632d839961f7a2b23b33cc3831217ab6'
                'ded0a413118f369b859507ad1eea019d0c82b1341146b58da521535e55904ac7145bdc7174c82e5bc877dafa993049ce'
                'b9d3ac2a81955c5508cedc1331a28bce2827d127a0109a8512fb78bbac2cfeb31a997a091af60414e637597a38246842'
                '13588386055e64a515da5a5c670a81ac972b2f6cc6e82abff1150bf5901fb0f0186f4ab76ee22a3638a0018c8dfa0477'
                '7357cdc5c667f0f81e1b6a833e67529c71854bb32d206b39ab3247db61ac2874344d82a8b818178c8589e5419d558414'
                'f3fc53b72823357b0b50138d4c80864db3685944732793467f5989f283589178994aa63b01a68d2ac8cad2f3b3b62c6f'
                '5aa7ad4bc2cabaf306dc37cf46428855f23e6988bd2b21349bc1223a819b54473f397c60f6d4777dd1775e3685ead34b'
                '9a162c0625e876dd243debe6b4d6e1a2829abdf70d120c02c34ce876bec17a724317826d17b0b62b5fd188ab789f3e51'
                '172428146a05978d22a98642c3ae4003571a76168392f72fdfb415510f1125c8bf5f5474a27277b71147c9eba71cab9a',
            'c':
                'c4ff0334ee9e01b04014ca57fd3c1f02f6b4fa91490864fe7be3f3601a0ba87791c73ac5a54097fbf4c21a8c5051a5ea'
                '8a32150ac7f4dda59280afcf938b6b5e7a023235c2aa330cdc0a976c5387bf1e92ae9c9d195436904cc9a4f9d7f2fc90'
                '317957b9744a6f4278bc48094bfe26c9aa09cafe0d7d8e1fc04416ad27c37e950dbcfb696a6f9bb96325f99d7143770e'
                '9f45c1e011bf6b9e550f28e8dc151d561a0b3048b1fcc07b2ebe0790a589a16c7bc75fff4cdc90dfb571bcd0dce00dca'
                'e5495b54f66881548a0fdbd1b90e529ad7fa2921874088c96af8fb99c7f621560ecc6691c69a8d02322d671f67d67c66'
                '3bba9b0ba451798eefb2c148324961c145737325731fd6b8383137400409478737e792f072a0ed2e7f43768cd132eccd'
                'bbb393ac435934d1fb8adc17551d3c2a1d9db4c205888f58b630c80f2c98eda00b7e6f2e3e0c6d4124866964c98bd086'
                'daa126215a98293957c6ad68724b2bd0e4cf55a45fec8c03622b3b358d3fb45b619d3286e5d7bc429d9e06342b384857'
                '67bca1898691208b4786a3258be2e9a6bb5ab2ec7b8cf3752bdc0e4e6767f5e46d7221bc8e8bd69f36f1b14c6f4b1527'
                '2b780c18fa118aac52a390a28e8862773789113371cdcefdc4b45547be5f26a9bc3151fcb87fd9c50a99cf4338562023'
                'a15b13860aff9daac05a2409834c0b68ee3a635261053546407e8cfa75046f55978ad9b2afecc8a79d35b8349e0a33f9'
                '0f23ad6648761f400228d83fa22366f0d2613814b505c29069fa8f3cb0b6143de9baf4e9dfdaf2b606cc577d06d2b327'
                '94c41199f06517a475313fc9f9d433099fc7b310c99fbaa132082b05c332b00cb3871d2dcc60fa33f8956074b87a2c1e'
                '4ea6609670f0e81dfd75ad8b68ddc91217127930659c6a29e07a9e5102908e218f101d5feec11f9c3e759e381e74379f'
                '648c29f7033bb58afca6590f0f84fee54510a78ed12528c960a93a691ff1667e319d641f97c16cf1d45399daa03bd5ea'
                '15c806f19d4e759d641fe1071449cf4e13c70d1c58d2265d53eb07a5cbe012cf9fd6768221d27e69d727af657e215159'
                '3207909d1ca11a8c96e2ccca095c3bb811c87ebe14e995ffb7f763b47ed0eeb604a0cccd74ab0c29dfcfe3b4620f5e8e'
                'b3ffd74ae9bc7a6b48ae4651d430871d4651e64c2b2fbe5701e2c64e20f5279157b55e3e9d166caf03fbaef2472e960d'
                '1a0160a92f42d1834b5d493e52e9d0897dbfaa373208eadc16fcff3ce8ae40226a469abc60b9a1b67244c5aeebf1abae'
                'cfe9dd9f9c1183f125d3b6172afb2c6cc29125a9f8c3a8b31fa880fc447719c5e58c50c4199e17ef9a061eab483bbfe3'
                '70f277b9ca09b3e3e6ff39e97ae392c0ef0b623f9be056db4d21e7704b5127d42f7fea27fea8f9186044e49d2c2d5175'
                '8329c8cab35b00df58c91a5e2f6fc6faafcd2037ba982052f02f204508c9b2c7d6ef53955372010fb3505c8c8e27677e'
                'f37ef07bd619342aa3fa6de31eb7e6089ef5f0bf9c4aeb024f9161897906c643',
            'k': '2cfb695710a6c4377f46c20c13480aef7ac56030d47a0ab5af07ddd6062c28f4',
            'reason': 'modified ciphertext',
        },
        {
            'pset': 1024,
            'src': 'encapDecap decapsulation tcId 96',
            'dk':
                '36bb5d4b256dcfcb14028b1efd5a74e5606617950da40b2408cb2c0462a222d4373a7a290fcb2997daacae414dd8c3aa'
                '7b38773c79c949059cf15b12fa8c522c538fdde905e798a3e7d5a6f27c93330b8243a12983e5c83880971827b01c2a03'
                'b4fabe4b15071ad124a5a00c69d98afd6bc63f305693b50040595995e99ad375bbd58989cdd2aa92e95532ea88336c5d'
                'd9f6c4a1b254fbcc4921b96de593c3134a2219b7a192e87309bbc6ef95499d594b30a4661f809d03297b6bcb2ea894b7'
                '24083115b0c6e6c2af2d239ab69574ea95a746cb23a0dc429ef42a79234cad8b9e85597beec196e85870ca1415cac402'
                '13b64ca34a8247595c89fbc19ad73b715ab3990b7e9691c9e5c767d0780e4e3026dc172494bb4ed87311d20896571608'
                'b065224b2c08d3b754837c0b8ad8cdac7775a8158a0fa93872c972f4048de1e9c9a8e33d59397e8de188251a6286ba2c'
                'e6f258d1f8a99e78c464f576fce80a999c6475ec03bc597014da6084f2c97eb88795f28cdb27437fb11f67977be1f865'
                '722b85c3371d4534cddd396bd6b12298f4287a7caa87542afadcc70a222fc1830182831bd1319d980ba03937b2cee6c2'
                '417a766e841609d8417e9c9d8dfcbc956217a5ec02deba6ba6717a0c71009aa663dd4cafd5fb5142ea14fb52c72fab33'
                'b0070fb38c9c9670323dec00d9eb9f02f64bf4e65d86c2c216799093040f6ffb80fdf6bdcc649f1f39bcd2c613221b52'
                '8803a75e16bb5b8b067eba7765738af0647da1026dea6717cbe4116bb28dff91c224243c1a72350165c30184ad901a94'
                '25538d255b72fd834c8e0090cb0289c2f79ef7997cc2aa5928d453198bc392f6524a88b5ae67b96a1c1782267f044a0a'
                'a0d8a011332cb8d34e1c6cc149a4a6a3b99621a308818322fd336edfb867e4495ec9d92b4bc70f7b170a0d28b3ec365e'
                '5da02c7e50373b3059248a439e0a7a0b3a656863785ca749e7419a9b1595ee28b7df838f1f2baf02a065b1242c17da79'
                '74c5332bd7724c77644e88549fb572ba8964979979b5a7901cf05823b4b985e4b3d531c21620689f036646d528dbccb4'
                '645b72ec920fd0f5426614bc469664a48a9ee0b5c7d9a52164e3163c299441e11dd246731180c9bd70219171712c7bb3'
                '71b213fc976236043f9367569561cc00f033d473809b3c49fa3725f111907015c6214c63347c4b8672980dd856e30b55'
                'bdb7b3d22554242393ab54314715cebb43ab224a911b090df1cc5e6950504ed063bab0a0d72a5c0fa8a1824962de9cb6'
                '85745659ecadbdc3b335627ddb5959fed1b66108af4f5548f151acbb3336a94c59a0a6b28d94b9359ac7c766cd7b9015'
                'c3b99ef45280470c37e985cce280acabe67afc54151239125845b94fa26656c4cad63b0494416464f4c7fe5936bc284e'
                '9ae388fa844ef71227d1aa0e872bc6fde92f894c26e885087523cfb56c7440222150a62bb27c067173025ba2953999bb'
                '3746094d546a6ae03baf8630fb3bc6f57239e7a35c20691fbe1611e6c46efc25b77029abaa947d81c286c4816e24f35d'
                '883b4d315a529a593421bcc5765b34ef6c4d416c3cd95443f9ba2fa248659ee77aa201987f6a5ebda78d307559a87496'
                '3b1927198b3524518acd6618f2d25afa4b11c4b396c9111a19398d55079ef62054a812c37fe81db4565f67038b9eda7a'
                '4b63b640252701844917e8cc7b3b1ede433d0356a2c0ea7e2df3c237498231a65e8e87874bd78487ebc1ce800c7d1b56'
                '476c220a8bcfba568ba20b773c993a98302c084b2ba25297049841355a16ff098c420a2220837ba6c89b44356b810576'
                '760316254646b0a5a41754a18af17d998541400cac0dc830ad9616f4f17840a9ce2d69b3bbe8cf9d60b01b00ac7ec8b1'
                'e08b3d886a804b4a4f2fe30cee898e42109f3a16c91fca5d1c328b90f00da0996f2365be54927d93f83f8f319d8ffc37'
                '5a5126356a94c6b6c3dec98cc9f2cf0089b3a6b878c73bbef04a4442b1b0fbe273a994bfb6e88ef627b6fae415c37691'
                'c9d30e10b45a83e02ac3f16a5b1249e8b15c0304ab6f3482477c44a6fa8b5db797fcba271fc1544ca333a6144e72b02e'
                '929cab8fb6011eb66399b8af76cb188aac3ee43b992482c4585934a5075428fb9966aba67b414114e379a05c7f81c351'
                'f6e18eeb8c3042e4a8dad0ced9a28cc492a2573590b15a914cd100ba119939610c6cd77d73fcb5bbbc50609152b3946e'
                '2d5969bda6586a7b26bd4284f41269dec3c124fc3c73a0a369818d9a491931607afbc85b54410444f9a426c9491099cb'
                '4ad40edcab36f6924764403ade37288feac93c2544f16acb41f0355e2491fd948fb8774a62c0ab9fd3bdf48948c94206'
                'e386bdf8d463fae547b580b1d9531d48e11d1df6539a7911b5577f7d8b55b17547306ccdf4224950776a2c90adce2673'
                '983c3ff286260fc6b08138cdc93ca3297873aa9443c7165021d767d3c132b1a66b413b8bd3849e8f6547665601c776a5'
                '58209ffcfc84ef1415dcd6091f12c790f1cfa2c5cc9c170bb7d0072ae997ff443d853b021b1999e1686ac6580ea6a0a9'
                '46a2b417c17eef967a51cbcab67992a16a8c12623ca327ac7fac5e4b616844e28f43ba45ad9252c695c4ee6707d60c10'
                '085917a3d5ce9d46cc9ea52a7759827fd64571b7b4630554946796b308ab65680fb23091515683d1cb815221b294fa40'
                '3d79124a9989eb7402f9990712e91d78c89ae45b33647a8fc11c5770ab738a3573e2c32e485a07dd0a009df27b445683'
                '4776ade5c454e5c70d00cc455115169e8c5d9ac35844e5126e784596b191cacc1c8ff6c2c0e371a81726930808caf368'
                '0ca194d0156bb1662be1928d3b3a432f102ee9c8ba950c3cd05b394320c568474d78dc7e75862a155cc73cf2a093c87a'
                '96653fc1b1288fb130caa41500541e34725e612c475740079bea8ef227bf1269b9f0f86e2ca929c3d611ce52552859c7'
                'cfca9bb0f125e2ca1bc1cc67eff49e27ea6b087700b8723c9dc0175a424d1578458d0bce007c5858361279b0c76e62a0'
                '3e1977b880552396320976040d9155dbe7a4ae2aae1a312b010cc430b310cda08ebbe690e0a102d24bc508b2a31f6117'
                '1efc3c80e0038c20469436776c65656f189a972544529ccce3d917eeec4912f779e3435a890000042468f93a3d1f1047'
                '80d26ffaab53aa33bea1a3103c3a51a86c6a7e178bb65c8145f6a41efb6dca856fe4847ac574476dd768271031e2e8a7'
                '0220caaca92ec136120de09ffa31c034c0a243eb48762286b1b2218ed2b34c551572b6bf741a9d0d8a31bc1678067a3f'
                'd13995cb559325b29c39a78c7798c3806682d3b0c810f5740d438a1861c8b5f11343b9b21a11694bb1049dcc0c872b25'
                '75911de0e8997bd19f2dd7b7d2ac501098cc54444abcf1c266721122a6acac20b17dc5ca3f9b5089136e6edb6061382e'
                '96d08b27d869003b8794ba83a50b1e2e72910699bf02513b35a1630f0bc2e8a666087787dd3b0b10529af8499f631403'
                '9b827786b71ca5dc706dd0610dd220eaf024d577ce14f80649b86ef5f839ecf23f5c595223a294dd9bc0cb7bb59f0390'
                '82e68b57fbb325911c2d8cac1c694cdce01d9e890561b43fea7bb5e2e00c6d3a650d9838801810bdf5013a8b95e9d76b'
                '329c1f2a0a40c4964fc52823e55b2af6412136314937f98150ca4a2679444773b66cc679519815746b74728a0c9b8346'
                '187106aa2185669023a1983a38580505d04e4847b2aa2a4127125013db519f141b5fe640b06935c2b673819a665d9039'
                '848803128204c4b223533c9a3f12c9553c8a4161490fcc5b51ca2b6a81385169c38c78ada8ba7c42877138a50fbfc586'
                '3e4967de01593597cfc7110a0b9c82506c9fdc7bc4d4d6b245751ccee2119be688ea0985c5647294a3b9abd07296473b'
                '70578fbdb0c4c5f16ebe034375818a63e408141b57129093fad761c54a99133111707656811a2351319c04b99259946f'
                'e197b7e89283659623ba26185f887680943c1cb88341420c6c32ce2b5b6304fa99bd35a2d7cab3e39060056bb4d756a7'
                '8050835f301ac355ba7a412227027dfd2c681440af9c81664a9c4dc5955f4bbc2479888a7536a9199199ac6710b49594'
                '9ca82bb9b1a2b06823bb1a79c6162cfb6a8b8a8893152928a169b9801765deb2ab890ba2d32c5c4409912c86c12c0897'
                '2cb3a042bba1b76675987279067c288fab89ddd93a75368888a40c2c9a20b60a0fcee8495dabb859b797c7b763cdb9ce'
                'b405213b7bb45f134cb6cb106cd7252ea069feb250138018fc4a5071473ca81c6a495a46aef27210d556fabc5d12281c'
                'a6d03bec1e62e762b589499cc3deb96e2a1119663db91a6a308e2360a02413ccf01948541c54d5589829053e8513a916'
                'f58e7318073cc06a308a53fcba7d197e3a2ded7516d56c84ba0b51b7ffa0e5d77342681eb856686b73d7942c37d8e2c8',
            'c':
                '4f18ed0d9ff40079ec3a6d67f903adee4d5caf5b4194d969ca222537eecd10abff3ce7cda292b2f632f65a1c73e8ce44'
                'b6d7890e123987a8c08ff23f7345313294fb6b3e8e382eafb352958637a6a01e0839dd1218f1bca9167894383be7f651'
                'ab0c0e74ca9b19dfa157db8656e5c4367ded62f7b4432f43f5ba02f394271d79f1ac3dc4b1caed50723730b337ec5030'
                '3182ed297aa3908cc28eea64e80819cb1509fe54302e3e03ebc39bdf0c00a755650af3610af7834ffffef5e6a2f7b66d'
                '68634e5b1b76f2482652b785dc8051494bce4f41867baa07ee88c9680e19139eb9bc5128fd5a348e01ee2a7178b3b29b'
                'd0c6d6096a7dc3059da039e2aeb64d5dde1154bfdfcfaee6cb6ccdda5039c64ec3ed3a2cd58fc4f7a4228995cb240b1b'
                'a31cbea59bf6483e100c3816badae7414f0e744451ff1fa0912d5c0a2472b1b7c0abdfb175424db48ab6f7be4db87178'
                '8af54960d244035d0e3ffa2fdbcf143c22001d4d7d3ce3ba848562c9ceb024d5dfb8f07689e72b0f2ad31d05890bf96f'
                '46002e204eda434511daa17385b81e0c513cc36f9d53a6adb36c1b23c2e37cac31e5997e1ac3102d4fc2c3a5b3ba3c97'
                '72541fcfff57ae162f5f55fe21dc47a66da2ab98233de8ee3058635fe5f3315e7bfba87e8dd2280930240945e972cc29'
                'cca19060439d317c146dff758fb183d66542ed00f2841c203095e9020d0f10f416c0b7e641f4b02a9f71f599e42678c8'
                '5ceace3ef586ec1b4c4c62d21f2cc75cfa7f58a525cb6a55868eaa31043596e2985d52f32938b304678a89c72d3b91ae'
                'b6943a4b34541da42e1060f6dc03ab7d6aa90b2ec7a4d8b2e1fce969a8614765f8212a08bceafff50a48c2a522e1a41f'
                'c2c2cc89827830d34ad556dbcab5e69121c22dd035437fc6ad0dd95c0e22916d5284e833cb84286ddfc47dcbe9758b98'
                '0d78e4dc294a3ce5a1175f7ecbe2d103801089ca744f2bbcee7212f64b0ccff10d4e9643027b942134ff2b50db9084d6'
                '6857c4df62b2c6919d9de84d51170efc7942b3871fd536d26310ff39ae099e0fa562fb13b0418ffdfd398657259a822a'
                '458e3688b42d492117f16e291f913566cfd6ccb097c0c45c2e5416b7d3707e93fec60037937b3930d1bb6a6cca5418c1'
                'd26083b3286d00eb0aed6c2b7e77028fc70896789ab29f424d91d393f1f63ed8e0d02d3a19f16b80481cad1809bf92db'
                '925d11651e7dc1b0499e1853865b708d79446166a1c25ede6ffcd277689b298da836bf52d4a885c6e8f4320ad031ffbd'
                '676378093c0f854236733b002e55636d44a5db9ecd7358ca24a3ef7638ef03b4b5d8e79def61221fde892987860dfced'
                '702d4ca1536348fccd99fa58c1031d934cde4593538474b2ebc8248bd4c4792b2b63b16a152970007574969f34cacb80'
                'dc978240c9755903e9f7951aca608b682fa60a90a8282b3e54862b60cec8eeb737fbc31b6511052856083cad928d2e41'
                'f226c89a3de0fc36797714471216ea0ff8a3dc1eee64e24afc46a16a818b4fb212410975034f5486a4e84078f59dad65'
                'e5d1ebd37021eede2b459041d4250468459d535ca974683cd4584b62b45756ef0d2c0e0f2af7b946597dcb8612927907'
                '8c4fea6563ef1e378bef179d65b1c8b0432660af5afb461478b9a9cba980925e8035cafe83c3dbad397f2bdfaaa08ba0'
                '5c623115cdea9a62129d271f237d33cf1266b38f122cd7a365956b9a08d611646cbda81ad64cf096344f9b905386e7a2'
                '31526d4c5de966263b7c8299fc7ac8dae2cc188ac205f60a14aa108c394260a4630fccd65aa9f56fb26425b02c6319c3'
                '05b042eb9e10dba41221299bd6dd4e02ce5e4085db6439ef118bb45b6d4c086af359a3c4b79e9b8bcb93cab682eb050c'
                '745380b65e8775acdd27f97e934a059b3d663e35bedc977fbcbbecb3d10c2d8ae2cd8b1940968ff7ce054ea7eebd0e81'
                'e65a372ccd133e098867ede82de7c58d99e908b416584645710e2b013a849fc15c209931918cbfb0fcc35d87ca633157'
                '19cf8de8025682f123b6a4288ec654438c6d75522a7e0b80f59bbb44ab8dfcb5372597590ab7644dd1ed74162f5ff389'
                'b417981fe46b27396508b28965bc564f8b45d68ddeed1cbb0b3a50ead14087f3b9e5d8abd007bc38258d127ec34413df'
                'c4f41ee0b549e106f77c1696dbf04f31a2dca4691e71d8bdecf4f2721d98e1c8',
            'k': '5d1350c0937b6222662f3d0a6194b8f1b60d4aeaf94fb8426c91078b6c12041d',
            'reason': 'modified ciphertext',
        },
    ],
    'ekCheck': [
        {
            'pset': 512,
            'src': 'encapDecap encapsulationKeyCheck tcId 116',
            'ek':
                '8b0c8f08a734cf1801a9cb0bf1538ea8ab5754d3a618d4531ae041fb054aa46a1e70db84d63b722bc69cb4785cebd791'
                '745b6c85367289447e3d266374f30f517b5512c02ffda63b519cb361f1bff4738a38a0ab824a232cf332d717169a947f'
                'fda532dbe9bdfb0372146056b97a066568c5af83554bd818bb6c206695c3adf29950023321a215dc98a531bc310bd39c'
                '22a56ecb047b53e62d6ea837deb77974492ccd2314b6b21b11e170c4583992a3974a921420b9a033b953c69b651e46a3'
                '10813891fab0d420b147e7933c316defb8bbd3a9ba3883182b4827721644ca969d5563372de3c5b9224ebde4344ba714'
                '6198489dc20b6c079036da8c1020918bf293b3ac0ea9f646b8003d516c394f36a6ecfc92027a92f7eb6369c280d284ba'
                'aca3838c03840cb1befeacce0f04454959ce459c62e9790bcab7cdeb37644841ae66186e9d415ffc548a34e61b75e2a2'
                '04204803159ac57a50ae209a513337a7420dfac60d47655fcf239fcb3c9111c6552c273e42e39c8cc180a14927697a36'
                '73687556a9a4640aca90c4c66f00654a13ac7a5c25deb2427b651b4376c6dd506258e255c7bb8d8b312eaf8552c74598'
                'd7d4b7fe388fee92a12e3381450b948babb0d8c351538188e7acacddfa38a26205c71c4cf72c06a50c83cea12918e03e'
                '95781d03033c22717898c63bfd8a9ba3ac312e61799ae30211777d3ffc33a06aceaa171180580be8458a1de556d8f027'
                'd4f95867d6c151404269c215e8c0a42d3a2829a92bf737785b6bc1620578be53803d8b2db2a626335561120339761214'
                'fe90267cf803c63c27350561e785cc02990b3fd7abe193b3f1037fed871929f649bcf40d3b0c4161499deb8324a9375d'
                '9a262d65617868d73f519cb59be36b1b24b14c31bcbf08571a777224c45bc0b73279aa9b6b740a351845d86676c0b333'
                'fda586bc89895db9113ecb58fbd73540a6a8dd14978915a1d7a3164a378512dbc0b5535152cc0bc5d667470bc6946250'
                'e07162135555f0298eab570188c1c1857a55499807fd53191775bfbb9acfd38563fdfc2d64666569f94dc2b1bad1d828'
                '24729c8d16292176e97ae6d8e30fe1bf83f44762d689613d105183ee6aa7933b',
            'pass': True,
            'reason': 'valid encapsulation key',
        },
        {
            'pset': 512,
            'src': 'encapDecap encapsulationKeyCheck tcId 117',
            'ek':
                '024dc3a47081953a8c5691a1fad560c7653820b4413b266882f6a2d7229765b2972347330112bf65e82f4a8c7837272b'
                '426a4e3305a8774621872b50b270c9c2314a631144e851a410e083f843575469899d102bd911108b90c475210d9ec35c'
                '86502f47d97bb0f65dd2ec0482d5000bc462c32c1b3ba769c6d407e8739850f9814035a8114aa405c086fc738eda7a8b'
                '63cac736e1b88c0a8f42a6a4f795a628c339c6902c73f6359952bdc3344ad8633c3bc7be540cbaa2753ef10301acc805'
                '9739649a7a6a23db341845878243137b2b7db13b5f866544bae8c22b972ab812624e4b0648201aafcb4652197891086c'
                '7cb0b99be95d488ac0f74274ed63870b405a64c338400810c324536b9ca3689a81f9a553ba1450e0c10e3503935a7616'
                'd07ba9c87aa269f8526ddc41f732119fa941064c55ac7319a514be51a587dba0a5256a53a4868b34b80426a8a8316928'
                'a6a57ee7ea2b706c5e5ed37ef7b68d5be75726480ea9a01c5fd8439949b85ae374486472c9a7970a84b08e997440613e'
                'b2e3aef03b400ab06db0b27d019576af6984724479e78a79bbf14494016308d1713dfa9677f94c562c684ecc7cb9137d'
                '24f0ae06fa563be66bfb648fb3aab64203bb12ca3fbe0ac8a2272c6b26b9378b7a1693a4bfeba351d18cbe3a838e299e'
                '0bb6c77dd13ca9791de2d989fc61b6a0e99733c72a18575555fc7f99221127bc8272505e5b489fab663e1a848c497bc3'
                'c6ebc8d5c23e2aa45dff832f75894aea99135efc65fe5b2a1fcbc291a39040f00f01569780f2435028114c5996490324'
                '7421b3cb72c85484340fcc404aa368f405cf7ab9913f81073b585793a1ab1dea39f452bfad241dc808367c2607540934'
                '3b6c8feb08a9bdd83fad348fad5b4a1e7b7ef87376db7076992c481b0bb6ccc63c2e82cf65701503bc3b22b4bcc1f186'
                '909140b1cb19ccb863253bc2a9ba9567f53cb4f7a8a4406cc7176cc68a334ba892f816be2df672e4cb6628da62f96139'
                '6a1b3f50c42f764c33109a34d2e94dbd1cc43a8284afaa79199334e54080e238a333d307655a91c07252a8224f1e4572'
                '98e15ee0966b5c7c6c4824a02f117e6807b25f4f4d993f9b45b086b3d43ae092',
            'pass': False,
            'reason': 'noisy linear system values too large',
        },
        {
            'pset': 768,
            'src': 'encapDecap encapsulationKeyCheck tcId 137',
            'ek':
                '026dbca9319a20dcbd8aa0ae721344710493091c20de43273a821043b0ca062a37af3a4dbe33b503d01375ba11f06a4f'
                '10c7a961746f68456b013449f3e416d0e63a40740a1123c5c1051ffdc8ac8bf9c5ea1246ca16a9f7fc1c8e750cd0c40f'
                '18584a473a0719591f1040c2d7db72add962ac278a96b4836c1b6f2c33b6acc30e4865487b1cb2ea609cef60cd771571'
                '5ecc1d0a541a7286962c26adbad87f216c5c6073c579153371a767172784f5eabae70773102b0728d422b1a8b51e09ac'
                '56f8a11f4b40f70b9d7e7380130c977563c6f50ba07641c3633363d102a11d3956cb363ecdfac9e82467715319de73bd'
                '82931803b09b9e52315f3b9e90d634e7b43a097b020f20613fe42ad941a88e7461d831cce093cdb88331e8283cc0e18b'
                'e0c40f89523ebf09ad35c5c4c44708d4e028e6269bbd7721c8f5c2dfc5570f6cb9721b6d9bc303d7c525646539a80920'
                '0bf3cc30f902eac04471fb79744cb82beacc31d97eec934caa13bd607717c811241e4379762464713630d4fcadc9e890'
                'a6a96450a786b5849108602951960ac9da84f10a97b04b66e7304cf234804edaab8c9355bf05af2c6346a694c87a9001'
                '3779904e183d8cf7bda6950b58fa4a78195bcc7659bb040e6a642741b90e4e27292340a7224b2cd6d53f21311a497516'
                '030606eb206ee9625fb0db621ba10efc604f2f696d11e667efb24319193e16c45e317ba0e7120a0012cdd33a62356135'
                'f3e18af837ca868294e7a92f2670492c0996538360b375294e47313af78418aa262c96cc2986332f7107afd50c53443c'
                '97161858363bb821625ba209dd40aac3bc48f4c8069a2535040436f799421da205f5b729f31a7e1469883d07bac1b62a'
                '6cbc7811646b51134cf27b307fa3a61cf9cc0b6393c0859f91abc734ec9aa573375674134de65bfedb39f5e546cbf0cd'
                '98fc5c16b36408ec058a5142035abae46594bb2a5fb1bacfb648515b6672ad04a88239bcfe4c4dcab768ab9294cda377'
                '16e62fc08c4e0c1aba58565919e19b17b795f3a37a3475a499131fee57b7aaf8b7fae64207d4b2e32632e4632920278e'
                'db864d61d4b1e8c62a2bd42dc980475e1ccf9061c64b573bad7ba2f799c5a37054ef3586be94056a49712ce94743c323'
                '6937053974c9b8e274f6d7a0b0d427f565a37c9aacb0242e7c2c86d01630c8627373ea951325476c1a617a845749582e'
                '93c724b4c032b8106fe4f101d99baa5e4b9f3dfa8205279c2927834b6412b73c84e9f3a5e398aa5f0456de89a10f381d'
                '840c19ef92b4ffd96da90566c51ab5e8eb7adc5444a76b59a61cbfde1b889e744d1e389b90eb5bf1888e7c42accf28c5'
                'c34a63e0e36e64e99636b07ae6255f1bf980a887cd65f2467eab30071533f4d0b1f454811c3303176a9e8d4140f57b53'
                '8d89b794d7c069050637f9a7ed6badb2a910064b21cdda813fd4cf2cdccdf58cbad33c3777a930eb9aa4a2bb1cd22c7b'
                '3ba17b6905a8fe96875de00c34757202581823250133915acc659559215e5490263975225f29ac8aca24cc6888a4d779'
                '27687a69344a57ac819e7780a7aba782ba0af0886826d20040b537719c87d99aa4b4601acfa7cfa61bba07ecc9c3a75c'
                'e3b01e0a163f1b8ed4d9ad2ae714111a25290cdd167d42f6f56b767583f78cac',
            'pass': False,
            'reason': 'noisy linear system values too large',
        },
    ],
    'dkCheck': [
        {
            'pset': 768,
            'src': 'encapDecap decapsulationKeyCheck tcId 128',
            'dk':
                '43a825cec4a9fad91be6f1a402a2c6ae197595064374c62b7beb6d8dc9c9b69c386afc6d1615bd7f9461d7c8516b5248'
                'f7fbc8ff153eba1a938c2ca4526a4b98a3c267d758dbeaba0741b42908149148bc442c8096bb12064b031089c5516036'
                '04298dd786529843a098a67fd2b4315f265f794a2508984538c319f5e7afb83cb69da043d2031bd2dc2d940c899a1089'
                '7033587746933d5c312a171da98bcbcb777a22f300333a2a61535b40819706240173941bdaa3866dc03c3238465505a7'
                'c57caa5a1685656265ec2b1de6946c4a8b299a77511d5a1ff2475349fc2df4e6765939b7258c2ca2c7213ac357a9e72f'
                '7e50032ac59621c10945e1b04376c5a46b84b2e7c838b20b0b3324072b0780c3814e59af30bc9c22121f7519ae9bb2b8'
                '820602953a61ff3111151143d37c640e020549985ed863b202d7c0c7d067b5c184960574e7c8991832539bd34a68a816'
                'e2e8ae8f8bb596bcbc7b044d6ef16d05915af12bbabaa069ec177174333780140d8949ad85b0c6cad7679421a146f601'
                'f9a5aa56212a6b97ae81264cb8b167277347c6619b89360ce6297f5c938afe702aa1097a70267057c69aa2f666247344'
                '7112a9ad22b15b5c6a90d28754434a07f16b79eabd129298aaa5af6f913effabcf2e1886433357939053377c0de4fa16'
                '7468ce7aa7cd4700c2bee14744a432fec92a6d84304a78c697e1660a848d00b722eb202eb0e623b17c68e797b732c491'
                '800bc78d126efe34207a9251d6b6316a457c1bf55aa0cc78b9d30c0c4382d901881e7c52b7e85d12830971848d95c36d'
                '9db18fadb0c8946051c12ba02cbcc557170531f99fdda5b7199b41d3074746b968ebec9f2dc07d1e3b9adf6b050f148d'
                '19030c04705d999130a9f36b8e5c4b66aca585c052b21396e0c03d49a7a661a8c77a29508bd32d4a515d9c515dc259b5'
                'd965349608a1dd942837c09677d055160c6e3c8b700bf8155fe22186730e6a8aa97a7788da5523a98c8283c61331052e'
                '6d80660e8821c8c4c19a7888c37663413c05b9b11c63455e8ae51deca93710040001475e1168ca63434451a46dd946cc'
                'd8589fdc4a5ca161064435528bfa2617a8669cd9c2f393b26cda492b1337b90484b1610a6e3cace044106cbc5c5798b7'
                '178cc3d62b166d6722f6ac9720e918d0e0275a63172bc76adac957896653d7bb3380ac0ef99786478cb457fc80a28c86'
                '56691d92a3ac68f721182ca376e5b471b1c9d6667ee6470721940e63e49c0f41216702b3327924e70a03bfb5b278b067'
                '5dec9057577581d8b0a2a2379c9861c59578f3969152d689e9ab3673f66f1e38ce6ea938d59c405b5c6a330589d65590'
                '22d373e9284f57a727749a44b1277f7fe45200cd0b31843b16d759b997973a8aa603dc61d3c62850c78ea40c1fa3dccd'
                '6c84915fa987dbe838d5ec018ec5b527fc2adac0753453ca90b62e91071bc5026751718253b0bc84d3c74fbc71012224'
                'a59776dadb39e3a12d0dfb2f83d125aa0754990790bef598caec547b845e16779399e827fc6b1756c29f29e91e572a3f'
                '05f53a81314c77bca26c042350f75b42b9a629c1c45328be769a50851a8eb2263a1425c11e59ada0472f345266960538'
                '43bca6288a9c9afacc9225a08fe598c1ca31c7c7b5b3c04d8f562263666b723ab1b47927cdb7afc704b422911952f480'
                '69f04adbac60867a0a8c683f5aa30d7d7cad28a845811552e17c34bd297f19b9baad72a45858924eb95f3d29cd95269c'
                '55d7560a41b85a1204681049cad04f08025c5dbc2d9d72725d67cc99413a898751011287f2c74485a6a7159878f66040'
                'cf859babd901a21a57d4fb865be940f75295cbe3283906c45c2c388b3a5c47bc56c7d56c4db6adfe8065ec7ac6781cbd'
                'a9bb1a89d211c6c68b9a4202033b109fc99b3df191ebb523acb34247379b5935ce4a8a56961149b7c918c2cb801b1488'
                '17151a317370a7809a33068c89b4b1ac831103391af0ba3463d2a45ee35abe4a06753c8d2b862ed1b04047a21f882942'
                '1ae773edfa753032271be67dc4fcc8ec73338f295c8a67c3d5b2a5a36c6e1f65386341cb7042b504eb3b957944438a05'
                'a36ca9a1e40c0d4600f5543a15b99dba91222fe5769f07318315b58b5cb1db6596d93c8b6b704b12c1bbbae6145329b9'
                '2e3a966b2c7c38643a0a2c38d4824642ab90c654c57cfa96819b3af81034f9cc6582f477e8a58342a36a6ac776fff183'
                'feb03d6b34cee9211f96a77e05fcbaa0783e2f95301ab99d8356411cb6196ba2bfe6476b7719b50f2ab2bc3c92e4fa0a'
                '77121d3967cfaf9542084249557399a8eb8e7d79315f82788a614e59807c5bc1a3dd8c09980c2fb33295a31b4728ea21'
                '8c3929347b73c35a5a2686b4584715017cabd0e5a35c8c87d5332c937583f4242a385a7fb67aaa77815137ac991b4656'
                'd8d93619071b57836a928326144027483799396238984c73d966055861ae19f76424999e213885d9d967c0cc828a3073'
                '76f41de38b7b57da66355677d0fcbc4bb15e35413d7c3c35b1a9a389cbc4120415014135b135641f060b14c8946456a6'
                '03181227121c5925c3a0c70210fb03fdaca7dbb73af14ab794800a7d2bb27d8b2dcb9cb9c356a0c4e38b815ca3910036'
                'dc9748045b403968486eba5fc2a67947b92d4f247d6dc686dc28c2e76648bd89201e273121c6b286c9b3b686406eb69f'
                'c5c458e8c7afdb00c873e4aedd307904600ea46981816c5b87b10260e165358147b3827c380a8aa849310b9389caf914'
                '5711bc22e74baf280d56991d346a1645a12e37facc66c12700dc39cb8621b6c5c001a6181b42b2527173ffd0a91cd157'
                '19839f2703a68dc82a7ba083a051834d393f18f01c897248c1649897bba2beb8b0dee66a39ab4164483041b7333efc9d'
                '54352bb4659cce581d447c77263c5e4df74f5727b8392abf2503739c5c98cd5c3cc1e562f41a1fe0664e07c17a263695'
                '9a51b17eb1919d1942cfcaa3a32a554d499b1205a60676033bcbca8056978f98293a683e80e06d6e261f6185c8861312'
                'c642c04bd93962912eaf56672a019163dc91f0d844adf88212f51f43601eb99b043baaa31a9279489bb0b629a1371873'
                '17802f571391c88b2e5e757a17d63eb0374f40b9a918d742a9851420b65355e3c441e048a9d51857b64e411aa217575e'
                'd8957a9f0247a7f071289bbaedc70d6cc24e1f273646c0b9832b6dc4861638cca434d6341c8645f5e561187ab9a478b6'
                '5bf5a3ee96d7846d34ac145db03b70bef620d782aef1a9d2983b3bb086d37a486c5c020b73c2544b1ea91ce5cd5aa223'
                '48dccaf9b62f405960918cb2c22edf7df58216fd7f1903aeb2b10cfeffe0ed3ef73b980e6d0c500e9898103bde8c9d5b',
            'pass': False,
            'reason': 'modified H',
        },
        {
            'pset': 768,
            'src': 'encapDecap decapsulationKeyCheck tcId 126',
            'dk':
                'f629720f4168eebc9772e040cf5885df694edff1a2291133470163774bb709d93331139a60a812c70338c74970b90c38'
                'd5c16ca25245ba0847be1ccfb6f97907971ef3da8188ea5b765a8f6da13ce85cb6183cc4c9a9c39ea1085d69c88afb2c'
                'd4011114c47c67ccb73d863fc1c45d0dac2cc48142f595578bb99d4881587a31c2ff03613ac97f76a90abee451c4a471'
                'e9e5820bb9a340e378ac3b8084c00bfd309befe14279da8c38f540f94431175aaaa1671e29a0ca7b491db6db7a72933f'
                '921019cf5b8d0ed64a0803c264eab0224362f32b4c0b12451919c1c95378bda6b55225abfa6c43da0978cb830978226e'
                '68375d40ba94da10302f888fde8173ce21b080a86028007d2db743fb4773abe679515221c48a78b73014baf538460142'
                '5e165680979c65871c7d3b3a78478e1c772a792c1f1891700068bf50c000ab1804d3d76619f600b24770ee356a807a2a'
                'cc07004ec9428443ab3345b7c2e36aa134533a727272b097f21caf2619cd569c3bd5b431282b7ed2874feac4b5853264'
                '21bc12b8623d724a7f9516a4217458f3e365ec42cd772a0534158fd5247f1bc92685b9ad60b9672f07005769ce4a6177'
                '3293bd48298ce54397c2435e0dea4df39b9aadebc98437617c0b8664dc87748170e240188068b765e3b9693caab1500a'
                'ee64baa023701d5c647a844e1477a665514047537f9741b270bb46914534f84303acac915434c4e7b6921d6071875b35'
                '8d56babd49501766b863f929d045a71a168b9de16f23996ca1c1ca630cb59b692de30a0b1e975429ab136eb020437b93'
                '00e696ad868f5a92092278606c31168cf21c549033c1445996887306934eba76519d021c67d2b893734a873403e9b4a9'
                '1c7839c5320fbb6babf551c0b410b8f84cce1d0c0411b6a9765662e7cb4e5f9378d8e4515d847a950a551422a6779529'
                '436c49c97b6a703b9582c06a6b31387a94ba568a31bf6268e4134d1671c42a03949ef10a6380b07a60556343cb61087d'
                'bc5505fd9512a814334d46915db7b858b51f2ef80de446c5e2eba473967aba6627c3f066f3353b7ddbbe955354684940'
                '0c63bd3bf7a515700ddc874629525da56a25355352117b8e25494f62383cd8a5aea34522917a62e4b04a128a7234a330'
                '94448ad99782367810d8b7758e3985e0e3bc62203e367726337a9da1909c4f1690634ac199407b65b9cd2f83c71b688f'
                'f3242929a107fa1383f141569a32c631c097d459381ad730258474cbd87889280daf5a6e9cf45ed2e78e85b052551745'
                '085a02664046ed87667331c2fcbb474cb6289bc85a3e0aad72a949c9458ae2b9586880bdca52306ca483b3e711fb3409'
                'd4aa7cfceb7ca212191b378865aa7360c629c7e375689ba16e70176189a3b0120eda33617ee83c65c2347d8b6696ea3b'
                '93c49470570e6fc3275a59a58221753eeaab3de687a395c7f68824ceb61cbd2c9c1d641113574258a6c5a37babb039c1'
                'c3042fc1796593e43f19948ecb8abbf6d56de00b18ff1b94e3ab9ab560ac5f96a7fbf267cf8b64a6b87dff8409b6ac26'
                'fa06718a302ba81504329a3975e456fa86bca8ba665be899c8261cd7094904d97f77b8bbfb63becfe38f582842d1c304'
                'd2094601901ec45b32ab391e263282a6c86802e1bde88c2624823202460ef0e94f782c9ca4542248540217b462cc4671'
                'c6793db3b83d225791ba89700152b34833969701814e502a206c9230740aa1b35b6dbc9132bcba84eb7ab9ab06ff0512'
                'ecf87821a68c4a2cc3936ba945d6848f685ecd718222bca9bd4b2754d1ab00b70e7ecb4f6e18c38d214f8fcc28e37984'
                '6ff268be758558cb56fdd9a2c3a64af5b1accafc1e3fc09c1f259e00d36f1f4a8c0b473fae069aa6dccd54e5503ec792'
                '78d8aa28a43262d80c34f6087790250b471eca8a31f59b2d5ff59699a41ce8a72ba59368473b9a94b4078c178b0a3001'
                '8036b4235b2737217d18cbc76ac99f62db8141888c7393c608015dd9249f82b119eff1545f355c028cac0d04b60bd702'
                '079151150125fd68439c599f61b1a2ea75733733334ba15e6554a7d68ca83c122c4ae999264296eb60047f481ac84a1d'
                '6d128cd9b607bcf3a0ffacc78f7b889b73c6bd186ce776408df89c2aaa6f78929ec378cc2b5c6d40773afa21bc45db2e'
                'ed041ee0c6849ab677a8c6beb3806b52c527a13b7d065c82f9d02fb861802b36bd3ae11b6298b5a197b3f5f85a5bcc55'
                'fb398de11165b8cacee26608e17c538a6bc40742cb2141cc1e15527afc54aa4b16854a7057f1cc54cc0eb795a110fc59'
                'b5c53ab6638c999234d3e113b5d83efde9164ae604fa97869f5335eab2288bc650ecf99a16c461f9146a5d047d41c762'
                '86b91dbed5ba6f63b036ea6b6f23c5b0ec193f32869307193590281fc39d6112bd41ca5372847efca3c47808c249cc9f'
                'a6e062362aad8d2861b2f72509d827239b1966e7011aea546537c27ec86390b4a126389b7f556fff575433b70ed7f57e'
                'bacb079bf16d46e42492d98c56c7466184b22879a1bc0714b37a3ca7439948ba920b9ca0d5f8cf62fa0827d3055817be'
                '0317b4f7a29925137268002ae577c6c8c15415f22b2e43c4345121f76c01fb9c159e623fb766ad2591412d9a2880a75d'
                '8f356904044e066c4a39381462a2a6a1ac8c4ae6b7942b413730bd32344971928de4c634ce262c77983722aa03a15308'
                'd042a3f4a824b48710d511070331a7cc1517c6024b22a35c2103928ee2aaee7238f123177647bb5cbb708927cd01e52a'
                '21b282cea82f161520ac8697d637491a48236df100efc7a86e41b518b0b8f306b8b82581259b3e4966625c499b25498a'
                '1f546a64d286bc1bc88200a9f2241fb907c4cc962844347e58533171a090ac7c86a2d48e908c75ce0a25a28b81c9bb54'
                '23390ac9a1447fdb6cf4d68cf7fab10f416ba3823141a088d0c8adf928984dd0a5d495a96d51a2925c09b02b9da2959b'
                'cbcb3c629b177a382c75f3a1d6d0a50220b82df815af75c9ce4a875e723c0931908c639e5892c06c4526a2103a9ef569'
                'b2250608624a8758cfe8d3a3f2da6b64759f279750c7f199a2303f684a826b72bcbb9a8cc78280d93ac1009b58413085'
                '104156d2da65aa8b669e6466e3f4cdb907bf75761417411268e4ad94610abcea560e564d65509b48945cae43333c4b08'
                '363c22da8477510a895b5b0443f839c67b4220a3c080e29052d8be57c31858da73a281508f6615bfca2aa591a6db2905'
                '62ffa88ef2ad586f6fe0ba6643106cc1090ec080571f6aa33f728780246bfe2e3074bad30297d6125220ff1e66c62998'
                '6ea940bee294b4ffc62908f6cae073f555df3658e58eaf77ac1d1737b49be4b697e88f76d4326179bcc5120fe458c51c',
            'pass': True,
            'reason': 'valid decapsulation key',
        },
    ],
}

if __name__ == '__main__':
    sys.exit(main())
