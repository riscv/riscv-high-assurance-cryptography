#!/usr/bin/env python3
"""CMAC known-answer test: the KLEE specification text against SP 800-38B / RFC 4493.

Two independent implementations are checked against the published vectors:

  REF   SP 800-38B / RFC 4493 written directly on byte strings, with the
        subkey doubling over the big-endian string view as the standard
        specifies.
  KLEE  the Machine of <<KLEE-CMAC-mode>> (modules/ROOT/pages/Zkl-ISA-machines.adoc),
        implemented formula-by-formula in the KLEE value model of
        modules/ROOT/pages/Zkl-notation.adoc (byte i of a string lives at bits [8i+7:8i];
        the left operand of @ is more significant).  gen_subkeys uses
        `double`, the OCB3 doubling of <<KLEE-OCB-mode>>.  The model is a CL
        driven by kl.setst / kl.exec Forms and KLLEN, so it also applies the
        General Rules for Machines (<<KLEE-Machines-other-rules>>: MGR1-MGR6)
        and the State rules of the Instructions chapter (<<KLEE-State-field>>: SGR2, SGR4-SGR6,
        SGR8, SGR10, SGR16) where CMAC relies on them, and it exports and
        imports the Serialized Content of <<KLEE-CMAC-mode>> (the plaintext of
        `Content1`, <<KLEE-SCC>>; the sealing itself is covered by scc-kat.py).

Vectors and provenance
  * RFC 4493 section 4 (identical to SP 800-38B Appendix D.1), AES-128:
    subkey generation anchors (AES-128(K,0), K1, K2) and examples 1-4 with
    Mlen = 0, 16, 40, 64 bytes.
  * NIST "CMAC Mode for Authentication" example file (the SP 800-38B
    example set, csrc.nist.gov .../examples/AES_CMAC.pdf), CMAC-AES192 and
    CMAC-AES256 examples 1-4 with Mlen = 0, 16, 20, 64 bytes, including
    their published L, K1 and K2 values.
    The AES-128 Mlen = 20 example from the same file is included too, so
    every key size exercises a partial final block.

Checks performed
  * REF vs published tag, and KLEE vs published tag, for all 13 examples,
    the KLEE model being driven two ways: one block per kl.exec with the last
    block passed at its exact length, and every full block in a single
    multi-block kl.exec (MGR3) with the last block passed in a 256-bit
    operand with filler above it, which the Machine must ignore.
  * The published subkey anchors (L, K1, K2) against KLEE gen_subkeys, for
    all three key sizes.
  * Every path of _Hash_Absorb_Last_Block_ is covered:
      Xs = 0     empty message           (K2, all-padding block)
      Xs = b     full final block        (K1 path)
      0 < Xs < b partial final block     (K2, ocb-style padded block)
  * Both _Hash_Output_ options: the Form C `kl.exec` emit, and the Form C
    `kl.setst #kl_state_hash_verify` comparison (Success on the right tag,
    Failure on a tampered one and on a truncated one).
  * The `Xs` validity rules of the Form B setst: Xs > b, Xs not a multiple
    of 8, and block_base != 0 must drive the CL to Error State _Invalid_.
  * The Serialized Content: the CL is exported and re-imported after every
    instruction of every example; every admissible field value fits its row;
    the sizes are reported.
  * State machine: instructions and Forms not allowed in the current State
    (<<KLEE-MGR-not-allowed-instructions>>, <<KLEE-SGR-no-exec-in-ready>>,
    <<KLEE-SGR-success-failure>>), the KLIOBUF substitutions of
    <<KLEE-usage-input-output>>, KLLEN not a multiple of b in _Hash_Absorb_
    (MGR2), one block whatever KLLEN in the last-block and output States
    (MGR3) with OUTPUT cleared beyond bit b-1, and a return to _Ready_ (SGR8).
  * <<KLEE-derive-endpoints>>: `key` (j = 1) is the only importable field and
    is written with the CL in State Ready; CMAC has no exportable field.
  * Negative controls (must NOT reproduce the standard):
      NC-K2full     : take the K2 path for a full final block instead of K1.
      NC-lemask     : derive the subkeys with the little-endian update_mask
                      instead of double() = bswap(update_mask(bswap(S))).
      NC-blockorder : a multi-block kl.exec taking its blocks from the most
                      significant position downwards, contrary to MGR3.
      NC-scc-drop   : the Serialized Content without its `hash` row.

Review finding m6 is fixed in the spec: <<KLEE-CMAC-mode>> now states that with
last_blk_len = 0 "INPUT is not read and the padded value is zeros(b-8) @
0b10000000", so the undefined slice INPUT[-1:0] is gone.  The harness checks
that reading directly, by feeding a nonzero dummy INPUT in the empty-message
case and requiring the published tag.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (b2v, v2b, sl, cat, aes_encrypt, update_mask,
                    double_ocb, bxor, MASK128)

B = 128                      # block size (spec parameter b)

# _State_ values: <<KLEE-states-valid>>, <<KLEE-states-error>>, and the symmetric
# constants of <<KLEE-state-constants-symmetric>>.
S_READY = 1
S_HASH_ABSORB = 2            # kl_state_hash_absorb
S_HASH_LAST = 3              # kl_state_hash_last_block
S_HASH_VERIFY = 5            # kl_state_hash_verify
S_HASH_OUTPUT = 6            # kl_state_hash_output
S_SUCCESS = 46
S_FAILURE = 47
S_INVALID = 49               # kl_state_invalid

# filler placed above the bits that carry data; the Machine must ignore it
JUNK = int.from_bytes(bytes([0x5A, 0xC3]) * 32, 'little')

def junk_above(nbits, width=B):
    return (JUNK << nbits) & ((1 << width) - 1)

# ====================================================================== REF
# SP 800-38B section 6.1-6.2 / RFC 4493 section 2, on byte strings.

def _ref_double(S):
    """L << 1 over the big-endian string, xor R_128 = 0x87 if the first bit was 1."""
    n = int.from_bytes(S, 'big')
    r = ((n << 1) & MASK128) ^ (0x87 if n >> 127 else 0)
    return r.to_bytes(16, 'big')

def ref_subkeys(K):
    L = aes_encrypt(K, bytes(16))
    K1 = _ref_double(L)
    K2 = _ref_double(K1)
    return L, K1, K2

def ref_cmac(K, M):
    _, K1, K2 = ref_subkeys(K)
    if len(M) and len(M) % 16 == 0:
        blocks = [M[i:i + 16] for i in range(0, len(M), 16)]
        last = bxor(blocks.pop(), K1)                      # complete final block
    else:
        n = len(M) // 16
        blocks = [M[i * 16:(i + 1) * 16] for i in range(n)]
        tail = M[n * 16:]
        last = bxor(tail + b'\x80' + bytes(15 - len(tail)), K2)
    X = bytes(16)
    for blk in blocks:
        X = aes_encrypt(K, bxor(X, blk))
    return aes_encrypt(K, bxor(X, last))

# ====================================================================== KLEE
# The Machine of <<KLEE-CMAC-mode>>, transcribed step by step.

class Invalid(Exception):
    """The CL transitioned to Error State _Invalid_.  `output` is the OUTPUT
    operand as the instruction leaves it (<<KLEE-SGR-usage-cr-error-state>>)."""
    def __init__(self, why, output=0):
        super().__init__(why)
        self.output = output


SKS = {}                     # System Key Store: SKID -> key bytes (MGR8)


def cmac_layout(key_bits, b=B):
    """<<KLEE-CMAC-mode>> Serialized Content, rows i-iv: (field, size in bits).
    The MDH is not part of it; it is implicitly zero-padded to a multiple of
    128 bits (the Machines chapter, "Definition of a Machine in KLEE")."""
    return [('key', key_bits),         # i    `key` or System Key Identifier
            ('hash', b),               # ii
            ('last_blk_len', 32),      # iii
            ('block_base', 32)]        # iv


def pack(fields):
    """Fields in table order from bit 0 upwards (the lowest address first,
    <<KLEE-Notation>>), then zero padding to a multiple of 128 bits."""
    v = pos = 0
    for val, w in fields:
        if not 0 <= val < (1 << w):
            raise OverflowError(f'{val} does not fit in {w} bits')
        v |= val << pos
        pos += w
    return v2b(v, -(-pos // B) * 16)


def unpack(data, layout):
    v, pos, out = b2v(data), 0, {}
    for f, w in layout:
        out[f] = sl(v, pos + w - 1, pos)
        pos += w
    assert v >> pos == 0 and len(data) * 8 == -(-pos // B) * B
    return out


class KleeCmac:
    """A CL holding a CMAC CC.  kl.setst and kl.exec are issued through
    setst(immed, form, aux) and exec(form, INPUT, klen), with KLLEN = klen
    bits; exec returns OUTPUT as a klen-bit value (0 for Forms B and D)."""

    def __init__(self, key, skid=None, double_fn=double_ocb, force_k2=False,
                 msb_first=False):
        self.keyb = key                   # `key`, k bits
        self.skid = skid                  # System Key Identifier, if any
        if skid is not None:
            SKS[skid] = key
        self.model = dict(double_fn=double_fn, force_k2=force_k2,
                          msb_first=msb_first)
        self.double = double_fn           # NC-lemask
        self.force_k2 = force_k2          # NC-K2full
        self.msb_first = msb_first        # NC-blockorder
        self.state = S_READY              # the kl.mgmt completing provisioning
        self._ready()

    # -- Machine-Specific Functions -------------------------------------
    def enc(self, v):
        return b2v(aes_encrypt(self.keyb, v2b(v, 16)))

    def gen_subkeys(self):
        # L <- enc_blk(K, zeros(b)); K1 <- double(L); K2 <- double(K1)
        # (L is returned as well, so that the published anchor can be checked.)
        L = self.enc(0)
        K1 = self.double(L)
        K2 = self.double(K1)
        return L, K1, K2

    # -- State handling -------------------------------------------------
    def _ready(self):                     # In State _Ready_
        self.last_blk_len = 0
        self.block_base = 0
        self.hash = 0                     # zeros(b)

    def _invalid(self, why, output=0):
        # <<KLEE-SGR-clear-cr-content-error-state>>: Content beyond the MDH cleared
        self.state = S_INVALID
        self.keyb, self.skid = None, None
        self.hash = self.last_blk_len = self.block_base = 0
        raise Invalid(why, output)

    def setst(self, immed, form='A', aux=None):
        """kl.setst Kd, #immed; Form B carries Xs in aux, Form C an INPUT."""
        s = self.state
        if s == S_INVALID:                        # <<KLEE-SGR-usage-cr-error-state>>
            return
        if immed == S_READY:                      # from any valid state (SGR8)
            self.state = S_READY
            self._ready()
            return
        if s in (S_SUCCESS, S_FAILURE):           # <<KLEE-SGR-setst-in-success-failure>>
            self._invalid(f'kl.setst #{immed} in State {s}')
        if immed == S_HASH_VERIFY and form == 'A':
            form = 'C'                            # KLIOBUF substitution (the Instructions chapter)
        # Allowed State Transitions; SGR4 admits the immediate of the current State
        if immed == S_HASH_ABSORB and form == 'A' and s in (S_READY, S_HASH_ABSORB):
            pass                                  # no operation is specified
        elif immed == S_HASH_LAST and form == 'B' and s in (S_HASH_ABSORB, S_HASH_LAST):
            if self.block_base != 0:
                self._invalid('the previous block is not complete')
            if aux > B or aux % 8:
                self._invalid('Xs > b, or Xs not a multiple of 8')
            self.last_blk_len = aux
        elif immed == S_HASH_OUTPUT and form == 'A' and s == S_HASH_OUTPUT:
            pass                                  # SGR4, nothing to perform
        elif immed == S_HASH_VERIFY and form == 'C' and s == S_HASH_OUTPUT:
            # the b least significant bits of INPUT are compared with hash
            match = sl(aux, B - 1, 0) == self.hash
            self.state = S_SUCCESS if match else S_FAILURE
            return
        else:
            self._invalid(f'kl.setst Form {form} #{immed} not allowed in State {s}')
        self.state = immed

    def exec(self, form, INPUT=0, klen=B):
        """kl.exec in Form A-D with KLLEN = klen."""
        s = self.state
        if s == S_INVALID:                        # no operation, OUTPUT zeroed
            return 0
        want = {S_HASH_ABSORB: 'B', S_HASH_LAST: 'B', S_HASH_OUTPUT: 'C'}.get(s)
        # a Form D kl.exec substitutes Form A, B or C (<<KLEE-usage-input-output>>)
        if want is None or form not in (want, 'D'):
            self._invalid(f'kl.exec Form {form} not allowed in State {s}')
        if s == S_HASH_ABSORB:
            if klen % B:                          # MGR2: no operation, Invalid
                self._invalid('KLLEN not a multiple of b')
            order = range(0, klen, B)             # MGR3: i = 0, b, ..., KLLEN - b
            for i in (reversed(order) if self.msb_first else order):
                # hash <- enc_blk(key, hash xor INPUT)
                self.hash = self.enc(self.hash ^ sl(INPUT, i + B - 1, i))
            return 0
        if s == S_HASH_OUTPUT:
            out = self.hash                       # OUTPUT <- hash
            self.state = S_SUCCESS
            return out & ((1 << klen) - 1)        # bits beyond the b-th cleared
        # _Hash_Absorb_Last_Block_: a single kl.exec, exactly one block (MGR3)
        n = self.last_blk_len
        if klen < n:
            self._invalid('KLLEN < last_blk_len')
        INPUT = sl(INPUT, B - 1, 0)               # KLLEN > b: only the low b bits
        _, K1, K2 = self.gen_subkeys()
        if n == B:
            # NC-K2full applies the wrong subkey on the full-block path.  The K2
            # branch cannot be taken here at all: its padding zeros(b-8-n) is
            # undefined for n = b, which is why the spec splits the two cases.
            tmp = self.hash ^ INPUT ^ (K2 if self.force_k2 else K1)
        else:
            # zeros(b - 8 - n) @ 0b10000000 @ INPUT[n-1:0]; for n = 0 INPUT is
            # not read and the padded value is zeros(b-8) @ 0b10000000.
            body = (cat((0, B - 8 - n), (0x80, 8), (sl(INPUT, n - 1, 0), n)) if n
                    else cat((0, B - 8), (0x80, 8)))
            tmp = self.hash ^ body ^ K2
        self.hash = self.enc(tmp)
        self.state = S_HASH_OUTPUT
        return 0

    # -- <<KLEE-derive-endpoints>> -----------------------------------------
    def derive_into(self, j, src, length):
        """This CL as the destination of a kl.derive (<<KLEE-instruction-derive>>)."""
        if self.state == S_INVALID:
            return
        if j != 1:
            self._invalid(f'j = {j} is not an importable field of CMAC')
        if self.skid is not None:
            self._invalid('a field configured by a SKID is never importable')
        if self.state != S_READY:
            self._invalid('a destination whose key is written must be in Ready')
        k = len(self.keyb)                        # dest_length, bytes
        eff = min(length, k)                      # <<KLEE-derive-rule-both-fixed-size>>
        self.keyb = src[:eff] + bytes(k - eff)

    def derive_from(self, i):
        """This CL as the source of a kl.derive: CMAC has no exportable field."""
        self._invalid(f'i = {i} is not an exportable field of CMAC')

    # -- Serialized Content --------------------------------------------------
    def key_bits(self):
        return 64 if self.skid is not None else 8 * len(self.keyb)

    def export(self, layout=None):
        layout = layout or cmac_layout(self.key_bits())
        vals = {'key': self.skid if self.skid is not None else b2v(self.keyb),
                'hash': self.hash, 'last_blk_len': self.last_blk_len,
                'block_base': self.block_base}
        return pack([(vals[f], w) for f, w in layout])

    def imported(self, content1, layout=None):
        """A fresh CL of the same implementation, loaded with `content1` and the
        MDH of this CL (_State_, _KeyType_)."""
        layout = layout or cmac_layout(self.key_bits())
        f = unpack(content1, layout)
        key = SKS[f['key']] if self.skid is not None else v2b(f['key'], len(self.keyb))
        new = KleeCmac(key, self.skid, **self.model)
        new.state = self.state
        new.hash = f.get('hash', 0)
        new.last_blk_len, new.block_base = f['last_blk_len'], f['block_base']
        return new


def _chunks(data, per_exec):
    """The full blocks of `data` as kl.exec operands of per_exec blocks each
    (0: all of them in one kl.exec); a list of (INPUT, KLLEN)."""
    n = len(data) // 16
    step = per_exec or max(n, 1)
    return [(b2v(data[16 * a:16 * min(n, a + step)]), 8 * 16 * (min(n, a + step) - a))
            for a in range(0, n, step)]


def kl_cmac(K, M, per_exec=1, junk=False, hop=False, layout=None, subst=False,
            dummy_empty_input=0, cl=None, skid=None, **model):
    """Drive the Machine as <<KLEE-pseudocode-CMAC>> does, leaving the CL in
    State _Hash_Output_.  hop: export and re-import the CL after every
    instruction; cl: an existing CL in State Ready to use instead of a new one."""
    fB = 'D' if subst else 'B'
    cl = cl or KleeCmac(K, skid=skid, **model)
    nxt = (lambda c: c.imported(c.export(layout), layout)) if hop else (lambda c: c)
    cl.setst(S_HASH_ABSORB, 'A'); cl = nxt(cl)
    if len(M) and len(M) % 16 == 0:
        full, tail = M[:-16], M[-16:]             # the last full block is the last block
    else:
        full, tail = M[:len(M) // 16 * 16], M[len(M) // 16 * 16:]
    for INPUT, klen in _chunks(full, per_exec):
        cl.exec(fB, INPUT, klen); cl = nxt(cl)
    cl.setst(S_HASH_LAST, 'B', 8 * len(tail)); cl = nxt(cl)
    if junk:                                      # KLLEN > b, filler above the data
        INPUT, klen = b2v(tail) | junk_above(8 * len(tail), 2 * B), 2 * B
    elif tail:
        INPUT, klen = b2v(tail), 8 * len(tail)    # exactly the last block
    else:
        INPUT, klen = dummy_empty_input, B        # dummy input for the empty message
    cl.exec(fB, INPUT, klen); cl = nxt(cl)
    return cl


# ================================================================== vectors
# RFC 4493 section 4 / SP 800-38B D.1 (AES-128), and the NIST CMAC example
# file for AES-192 (D.2) and AES-256 (D.3).
MSG = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710")

K128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
K192 = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e5"
                     "62f8ead2522c6b7b")
K256 = bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                     "1f352c073b6108d72d9810a30914dff4")

# (label, key, published L, published K1, published K2)
SUBKEYS = [
    ("AES-128", K128, "7DF76B0C1AB899B33E42F047B91B546F",
                      "FBEED618357133667C85E08F7236A8DE",
                      "F7DDAC306AE266CCF90BC11EE46D513B"),
    ("AES-192", K192, "22452D8E49A8A5939F7321CEEA6D514B",
                      "448A5B1C93514B273EE6439DD4DAA296",
                      "8914B63926A2964E7DCC873BA9B5452C"),
    ("AES-256", K256, "E568F68194CF76D6174D4CC04310A854",
                      "CAD1ED03299EEDAC2E9A99808621502F",
                      "95A3DA06533DDB585D3533010C42A0D9"),
]

# (label, key, Mlen in bytes, expected tag)
VECTORS = [
    ("AES-128 ex1", K128,  0, "BB1D6929E95937287FA37D129B756746"),
    ("AES-128 ex2", K128, 16, "070A16B46B4D4144F79BDD9DD04A287C"),
    ("AES-128 ex3", K128, 20, "7D85449EA6EA19C823A7BF78837DFADE"),
    ("AES-128 ex4", K128, 40, "DFA66747DE9AE63030CA32611497C827"),
    ("AES-128 ex5", K128, 64, "51F0BEBF7E3B9D92FC49741779363CFE"),
    ("AES-192 ex1", K192,  0, "D17DDF46ADAACDE531CAC483DE7A9367"),
    ("AES-192 ex2", K192, 16, "9E99A7BF31E710900662F65E617C5184"),
    ("AES-192 ex3", K192, 20, "3D75C194ED96070444A9FA7EC740ECF8"),
    ("AES-192 ex4", K192, 64, "A1D5DF0EED790F794D77589659F39A11"),
    ("AES-256 ex1", K256,  0, "028962F61B7BF89EFC6B551F4667D983"),
    ("AES-256 ex2", K256, 16, "28A7023F452E8F82BD4BF28D8C37C35C"),
    ("AES-256 ex3", K256, 20, "156727DC0878944A023C1FE03BAD6D93"),
    ("AES-256 ex4", K256, 64, "E1992190549F6ED5696A2C056C315410"),
]

def path_of(n):
    if n == 0:
        return "Xs=0 empty"
    if n % 16 == 0:
        return "Xs=b   K1"
    return "0<Xs<b K2"

# ==================================================================== run
def main():
    ok = True
    def chk(cond):
        nonlocal ok
        ok = ok and bool(cond)
        return 'PASS' if cond else 'FAIL'
    def line(text, cond):
        print(f"  {text:<66} {chk(cond)}")
    def invalid(fn):
        """fn() must raise Invalid; returns the exception, or None."""
        try:
            fn()
        except Invalid as e:
            return e
        return None
    def info(text):
        print(f"INFO  {text}")
    def spec_note(text):
        print(f"SPEC-NOTE  {text}")

    print("gen_subkeys vs the published L / K1 / K2 anchors "
          "(RFC 4493 section 4; NIST CMAC example file):")
    print(f"{'key':10} {'L':6} {'K1':6} {'K2':6}")
    for label, K, wl, w1, w2 in SUBKEYS:
        L, K1, K2 = KleeCmac(K).gen_subkeys()
        rl, r1, r2 = ref_subkeys(K)
        good = (v2b(L, 16).hex().upper() == wl and rl.hex().upper() == wl)
        g1 = (v2b(K1, 16).hex().upper() == w1 and r1.hex().upper() == w1)
        g2 = (v2b(K2, 16).hex().upper() == w2 and r2.hex().upper() == w2)
        print(f"{label:10} {chk(good):6} {chk(g1):6} {chk(g2):6}")

    print("\nCMAC vectors (REF = SP 800-38B on byte strings; "
          "KLEE = the Machine of <<KLEE-CMAC-mode>>)\n"
          "  1blk  : one block per kl.exec, last block at its exact length\n"
          "  multi : all full blocks in one kl.exec (MGR3), KLLEN = 2b with "
          "filler above the last block\n"
          "  SCC   : export/import after every instruction")
    print(f"{'case':14} {'Mlen':>5}  {'last-block path':16} "
          f"{'REF':6} {'1blk':6} {'multi':6} {'verify':7} {'tamper':7} {'SCC':6}")
    for label, K, n, want in VECTORS:
        M = MSG[:n]
        W = bytes.fromhex(want)
        r = ref_cmac(K, M)
        emitted = v2b(kl_cmac(K, M).exec('C'), 16)
        cm = kl_cmac(K, M, per_exec=0, junk=True)
        wide = cm.exec('C', klen=2 * B)           # KLLEN = 2b: one block, rest zero
        clj = kl_cmac(K, M)                       # filler above bit b-1 is ignored
        clj.setst(S_HASH_VERIFY, 'C', b2v(W) | junk_above(B, 2 * B))
        good_verify = clj.state == S_SUCCESS
        cl = kl_cmac(K, M)
        cl.setst(S_HASH_VERIFY, 'C', b2v(W))
        verified = cl.state == S_SUCCESS
        bad = bytearray(W); bad[0] ^= 0x80
        evil = kl_cmac(K, M)
        evil.setst(S_HASH_VERIFY, 'C', b2v(bytes(bad)))
        clh = kl_cmac(K, M, hop=True)
        hop_tag = v2b(clh.exec('C'), 16)
        print(f"{label:14} {n:>5}  {path_of(n):16} "
              f"{chk(r == W):6} {chk(emitted == W):6} "
              f"{chk(v2b(wide, 32) == W + bytes(16)):6} "
              f"{chk(verified and good_verify):7} "
              f"{chk(evil.state == S_FAILURE):7} {chk(hop_tag == W):6}")

    print("\nempty message (<<KLEE-CMAC-mode>>: with last_blk_len = 0 INPUT is "
          "not read), review m6:")
    for label, K, want in (("AES-128", K128, "BB1D6929E95937287FA37D129B756746"),
                           ("AES-192", K192, "D17DDF46ADAACDE531CAC483DE7A9367"),
                           ("AES-256", K256, "028962F61B7BF89EFC6B551F4667D983")):
        t0 = v2b(kl_cmac(K, b'', dummy_empty_input=0).exec('C'), 16)
        t1 = v2b(kl_cmac(K, b'', dummy_empty_input=MASK128).exec('C'), 16)
        agree = t0 == t1 == bytes.fromhex(want)
        print(f"  {label}: INPUT = 0 and INPUT = ones(128) both give the "
              f"published tag: {chk(agree)}")

    print("\nForm B kl.setst #kl_state_hash_last_block, Xs:")
    def at_absorb(K=K128, **kw):
        cl = KleeCmac(K, **kw)
        cl.setst(S_HASH_ABSORB, 'A')
        return cl
    for Xs, why in ((136, "Xs > b"), (129, "Xs > b"), (4, "not a multiple of 8"),
                    (12, "not a multiple of 8"), (127, "not a multiple of 8")):
        print(f"  Xs = {Xs:3} ({why:19}) -> Invalid : "
              f"{chk(invalid(lambda: at_absorb().setst(S_HASH_LAST, 'B', Xs)))}")
    for Xs in (0, 8, 64, 120, 128):
        cl = at_absorb()
        accepted = (invalid(lambda: cl.setst(S_HASH_LAST, 'B', Xs)) is None
                    and cl.state == S_HASH_LAST and cl.last_blk_len == Xs)
        print(f"  Xs = {Xs:3} ({'admissible':19})            : {chk(accepted)}")
    cl = at_absorb()
    f = unpack(cl.export(), cmac_layout(128))
    f['block_base'] = 8                           # a CC whose block is incomplete
    cl = cl.imported(pack([(f[n], w) for n, w in cmac_layout(128)]))
    line("block_base != 0 -> Invalid", invalid(lambda: cl.setst(S_HASH_LAST, 'B', 64)))
    info("no State of <<KLEE-CMAC-mode>> can make block_base non-zero: "
         "_Hash_Absorb_ consumes whole blocks only (Granularity: b, MGR2) and "
         "CMAC has no kl.exec derive endpoint, so the check above can be reached "
         "only through an imported CC, as here.")

    # ---------------------------------------------- Serialized Content
    print("\nSerialized Content of <<KLEE-CMAC-mode>> (plaintext of Content1; "
          "the MDH is not part of it):")
    info("the table gives the order and size of the fields only; they are packed "
         "here from bit 0 upwards (lowest address first, <<KLEE-Notation>>), then "
         "zero-padded to a multiple of 128 bits.")
    for label, kb in (("SKID", 64), ("k = 128", 128), ("k = 192", 192), ("k = 256", 256)):
        bits = sum(w for _, w in cmac_layout(kb))
        blocks = -(-bits // B)
        info(f"{label:8}: fields {bits} bits + {blocks * B - bits} padding = "
             f"{blocks} blocks; SCC = MDH + SIV + Content1 = {blocks + 2} blocks")
    fits = True
    for hv, lbl, bb in ((MASK128, B, 0), (0, 0, B - 8), (1, 8, 0)):
        cl = KleeCmac(K128)
        cl.hash, cl.last_blk_len, cl.block_base = hv, lbl, bb
        try:
            back = cl.imported(cl.export())
            fits &= (back.hash, back.last_blk_len, back.block_base) == (hv, lbl, bb)
        except OverflowError:
            fits = False
    line("every admissible value fits its row (hash, last_blk_len, block_base)", fits)
    cl = kl_cmac(K128, MSG[:40], hop=True, skid=0x0123456789ABCDEF)
    line("export/import after every instruction, key as a 64-bit SKID: ex4",
         v2b(cl.exec('C'), 16) == bytes.fromhex(VECTORS[3][3]))

    # ------------------------------------------------ State machine
    print("\nState machine (MGR1-MGR6 of <<KLEE-Machines-other-rules>>, SGR rules "
          "of the Instructions chapter):")
    W4 = bytes.fromhex(VECTORS[3][3])             # AES-128, Mlen = 40
    cl = KleeCmac(K128)
    line("kl.exec in Ready -> Invalid (SGR2)",
         invalid(lambda: cl.exec('B', 0)) and cl.state == S_INVALID)
    line("the Content is cleared on entering the Error State (SGR10)",
         cl.keyb is None and cl.hash == 0)
    line("later kl.exec: no operation, OUTPUT zero, State unchanged (SGR16)",
         invalid(lambda: cl.exec('C')) is None and cl.exec('C') == 0
         and cl.state == S_INVALID)
    line("kl.setst #hash_last_block from Ready (Hash_Absorb skipped) -> Invalid",
         invalid(lambda: KleeCmac(K128).setst(S_HASH_LAST, 'B', 0)))
    line("kl.setst #hash_verify from Hash_Absorb -> Invalid",
         invalid(lambda: at_absorb().setst(S_HASH_VERIFY, 'C', 0)))
    line("kl.exec Form A in Hash_Absorb -> Invalid (Form B expected)",
         invalid(lambda: at_absorb().exec('A', 0)))
    line("kl.exec Form C in Hash_Absorb -> Invalid (Form B expected)",
         invalid(lambda: at_absorb().exec('C')))
    for klen in (64, 136, 200):
        cl = at_absorb()
        line(f"KLLEN = {klen} in Hash_Absorb -> no operation, Invalid (MGR2)",
             invalid(lambda: cl.exec('B', 0, klen)) and cl.state == S_INVALID)
    cl = at_absorb()
    cl.setst(S_HASH_LAST, 'B', 64)
    line("kl.exec with KLLEN = 56 < last_blk_len = 64 -> Invalid (INFO below)",
         invalid(lambda: cl.exec('B', 0, 56)))
    info("<<KLEE-truncation-vs-length>> gives KLLEN >= last_blk_len as the only "
         "restriction on a last block without stating the consequence; the "
         "harness applies MGR2 (no operation, Error State _Invalid_).")
    cl = kl_cmac(K128, MSG[:40])                  # in _Hash_Output_ after one exec
    line("the kl.exec of Hash_Absorb_Last_Block moves the CL to Hash_Output, so "
         "a second one -> Invalid", cl.state == S_HASH_OUTPUT
         and invalid(lambda: cl.exec('B', 0, 64)))
    cl = kl_cmac(K128, MSG[:40])
    cl.exec('C')
    line("a second tag kl.exec, in State Success -> Invalid (SGR5)",
         cl.state == S_SUCCESS and invalid(lambda: cl.exec('C')))
    try:
        subst_ok = all(v2b(kl_cmac(K, MSG[:n], subst=True).exec('D'), 16)
                       == bytes.fromhex(w) for _, K, n, w in VECTORS)
        cl = kl_cmac(K128, MSG[:40], subst=True)
        cl.setst(S_HASH_VERIFY, 'A', b2v(W4))     # Form A substitutes Form C
        subst_ok = subst_ok and cl.state == S_SUCCESS
    except Invalid:
        subst_ok = False
    line("Form D kl.exec and Form A kl.setst #hash_verify (KLIOBUF substitutions) "
         "reproduce all 13 vectors", subst_ok)
    cl = kl_cmac(K128, MSG[:40])
    trunc = b2v(W4[:8])                           # the 64 most significant bits zero
    cl.setst(S_HASH_VERIFY, 'C', trunc)
    line("a truncated (64-bit) tag -> Failure: all b bits are compared",
         cl.state == S_FAILURE)
    info("<<KLEE-CMAC-mode>>: \"Verification of a truncated CMAC is instead "
         "performed in software, after emitting the tag\".")
    for state, text in ((S_SUCCESS, 'Success'), (S_FAILURE, 'Failure'),
                        (S_HASH_ABSORB, 'Hash_Absorb')):
        cl = kl_cmac(K128, MSG[:40])
        if state == S_SUCCESS:
            cl.exec('C')
        elif state == S_FAILURE:
            cl.setst(S_HASH_VERIFY, 'C', 0)
        else:
            cl = at_absorb()
            cl.exec('B', b2v(MSG[:16]))
        got = cl.state == state
        cl.setst(S_READY)                         # SGR8 / "From any valid state"
        line(f"kl.setst #ready from {text}, then ex4 on the same CL (SGR8)",
             got and v2b(kl_cmac(None, MSG[:40], cl=cl).exec('C'), 16) == W4)
    for st, text in ((S_SUCCESS, 'Success'), (S_FAILURE, 'Failure')):
        cl = kl_cmac(K128, MSG[:40])
        if st == S_SUCCESS:
            cl.exec('C')
        else:
            cl.setst(S_HASH_VERIFY, 'C', 0)
        line(f"kl.setst #hash_absorb in State {text} -> Invalid (SGR6)",
             invalid(lambda: cl.setst(S_HASH_ABSORB, 'A')))
    info("the text names no kl.setst Form for the transition _Ready_ -> "
         "_Hash_Absorb_; the harness uses Form A, as <<KLEE-pseudocode-CMAC>> does.")
    spec_note("the Machines chapter, \"Definition of a Machine in KLEE\" (Zkl-ISA-machines.adoc:341), "
              "says an operation may instead use \"Form D kl.exec or Form C "
              "kl.setst\"; <<KLEE-usage-input-output>> makes Form A kl.setst the "
              "substitute of Form C, which is what this harness applies.")
    info("MGR10 (<<KLEE-MGR-progress-discard>>) does not apply: CMAC designates no "
         "progress field and none of its States has an interruptible "
         "long-running instruction.")

    # ------------------------------------------------ derive endpoints
    print("\n<<KLEE-derive-endpoints>> (provisional in the spec): CMAC imports "
          "`key` (j = 1) and exports nothing")
    src = K128 + bytes(range(0xF0, 0x100))        # e.g. a 256-bit shared secret
    for length in (16, 32):
        cl = KleeCmac(bytes(16))
        cl.derive_into(1, src, length)
        line(f"key derived in Ready (length = {length} bytes), then ex4",
             v2b(kl_cmac(None, MSG[:40], cl=cl).exec('C'), 16) == W4)
    line("kl.derive into `key` of a CL in Hash_Absorb -> Invalid",
         invalid(lambda: at_absorb().derive_into(1, src, 16)))
    line("kl.derive into a key configured by a SKID -> Invalid",
         invalid(lambda: KleeCmac(K128, skid=7).derive_into(1, src, 16)))
    for j in (0, 2):
        line(f"kl.derive into endpoint j = {j} (not importable) -> Invalid",
             invalid(lambda: KleeCmac(K128).derive_into(j, src, 16)))
    line("CMAC as a kl.derive source (no exportable field) -> Invalid",
         invalid(lambda: kl_cmac(K128, MSG[:40]).derive_from(1)))

    # ------------------------------------------------------ negative controls
    print("\nnegative controls (wrong formulations must NOT reproduce the standard):")
    print("KAT-EXPECT-FAIL: NC-K2full")
    print("KAT-EXPECT-FAIL: NC-lemask")
    print("KAT-EXPECT-FAIL: NC-blockorder")
    print("KAT-EXPECT-FAIL: NC-scc-drop")
    fired = []
    def nc(label, text, differs):
        fired.append(differs)
        print(f"  {label:14}({text}): "
              f"{'FAIL as expected' if differs else 'MATCHED (control did not fire)'}")
    # NC-K2full: only meaningful where the final block is full (Mlen = 16, 64).
    nc("NC-K2full", "K2 used for a full final block, not K1",
       all(v2b(kl_cmac(K, MSG[:n], force_k2=True).exec('C'), 16) != bytes.fromhex(w)
           for _, K, n, w in VECTORS if n and n % 16 == 0))
    nc("NC-lemask", "subkeys via little-endian update_mask",
       any(v2b(kl_cmac(K, MSG[:n], double_fn=update_mask).exec('C'), 16)
           != bytes.fromhex(w) for _, K, n, w in VECTORS))
    # NC-blockorder: needs at least two full blocks in one kl.exec (Mlen = 40, 64).
    nc("NC-blockorder", "multi-block kl.exec, most significant block first",
       all(v2b(kl_cmac(K, MSG[:n], per_exec=0, msb_first=True).exec('C'), 16)
           != bytes.fromhex(w) for _, K, n, w in VECTORS if n >= 40))
    nc("NC-scc-drop", "Serialized Content without its hash row",
       all(v2b(kl_cmac(K, MSG[:n], hop=True,
                       layout=[r for r in cmac_layout(8 * len(K)) if r[0] != 'hash']
                       ).exec('C'), 16) != bytes.fromhex(w)
           for _, K, n, w in VECTORS if n >= 16))
    ok = ok and all(fired)

    print(f"\nKAT-RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
