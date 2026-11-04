#!/usr/bin/env python3
"""Execute the SCC Sail listings and compare them with fixed vectors and the Python core."""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / 'modules/ROOT/pages/Zkl-ISA-unpriv.adoc'
VECTORS = Path(__file__).with_suffix('.json')
sys.path.insert(0, str(ROOT / 'src/kat'))
import common
import scc_core as core


def literal(value, bits=128):
    return f'0x{value:0{bits // 4}x}'


def extract_listings():
    section = PAGE.read_text().split('[[KLE-SCC-export-import]]', 1)[1]
    section = section.split('[[KLE-SCC-export]]', 1)[0]
    listings = re.findall(r'\[source,sail\]\n----\n(.*?)\n----', section, re.S)
    if not listings:
        raise ValueError('No SCC Sail listings found')
    return '\n\n'.join(listings).replace(
        'default Order dec', 'default Order dec\n$include <prelude.sail>', 1)


def build_harness(listings, vectors):
    aes_calls, mont_calls = {}, {}
    original_aes, original_mont = core.aes_enc, common.montmul

    # Supply the omitted primitives for the inputs exercised by the Python core.
    # Unexpected primitive inputs abort the Sail run rather than returning a guess.
    def aes(key, block):
        result = original_aes(key, block)
        aes_calls[(common.b2v(key), common.b2v(block))] = common.b2v(result)
        return result

    def mont(a, b):
        result = original_mont(a, b)
        mont_calls[(a, b)] = result
        return result

    lines, assertions = [], 0

    def vector(name, values):
        binding = 'var' if values else 'let'
        lines.append(f'  {binding} {name} = vector_init({len(values)}, sail_zeros(128));')
        for i, value in enumerate(values):
            lines.append(f'  {name}[{i}] = {literal(value)};')

    def check(condition, label):
        nonlocal assertions
        assertions += 1
        lines.append(f'  assert({condition}, {json.dumps(label)});')

    def check_blocks(name, values, label):
        for i, value in enumerate(values):
            check(f'{name}[{i}] == {literal(value)}', f'{label}, block {i}')

    core.aes_enc, common.montmul = aes, mont
    try:
        common.section('Existing SCC core and independent RFC model vs Sail-derived vectors')
        for t, record in enumerate(vectors):
            key = common.b2v(bytes.fromhex(record['key']))
            sep = record['sep']
            ad = [common.b2v(bytes.fromhex(x)) for x in record['ad']]
            pt = [common.b2v(bytes.fromhex(x)) for x in record['plaintext']]
            siv = common.b2v(bytes.fromhex(record['siv']))
            ct = [common.b2v(bytes.fromhex(x)) for x in record['ciphertext']]
            label = record['name']
            common.check(f'{label}: Python encryption', core.scc_encrypt(ad, sep, pt, key) == (siv, ct))
            ad_auth = list(ad)
            if sep == 0:
                ad_auth[0] &= ~(1 << 47)
            rct, rtag = core.scc_rfc_seal(bytes.fromhex(record['key']), bytes(12),
                b''.join(common.v2b(x, 16) for x in ad_auth),
                b''.join(common.v2b(x, 16) for x in pt), lenblock=False, sep=sep)
            common.check(f'{label}: independent RFC construction',
                         rct.hex() == ''.join(record['ciphertext']) and rtag.hex() == record['siv'])
            vector(f'ad{t}', ad)
            vector(f'p{t}', pt)
            lines.append(f'  let (tag{t}, ct{t}) = SCC_Encrypt(ad{t}, 0b{sep}, p{t}, '
                         f'{literal(key, 256)}, {len(ad)}, {len(pt)});')
            check(f'tag{t} == {literal(siv)}', f'{label}: SIV')
            check_blocks(f'ct{t}', ct, f'{label}: ciphertext')
            check_blocks(f'ad{t}', ad, f'{label}: encryption preserves AD')
            check_blocks(f'p{t}', pt, f'{label}: encryption preserves plaintext')

            zeros = [0] * len(pt)
            cases = [
                ('valid', ad, sep, siv, ct, key, True, pt),
                ('ADSDropped', [ad[0] ^ (1 << 47)] + ad[1:], sep, siv, ct, key,
                 sep == 0, pt if sep == 0 else zeros),
                ('wrong segment', ad, sep ^ 1, siv, ct, key, False, zeros),
                ('wrong key', ad, sep, siv, ct, key ^ 1, False, zeros),
                ('changed AD', [ad[0] ^ 1] + ad[1:], sep, siv, ct, key, False, zeros),
            ]
            for bit in (0, 126, 127):
                cases.append((f'tag bit {bit}', ad, sep, siv ^ (1 << bit), ct, key, False, zeros))
            for i in range(len(ct)):
                changed = list(ct)
                changed[i] ^= 1 << 127
                cases.append((f'ciphertext block {i}', ad, sep, siv, changed, key, False, zeros))
            for j, (name, a, domain, tag, c, k, correct, plaintext) in enumerate(cases):
                case = f'{label}: {name}'
                common.check(f'{case}: Python decryption',
                             core.scc_decrypt(a, domain, tag, c, k) == (correct, plaintext))
                vector(f'ad{t}_{j}', a)
                vector(f'c{t}_{j}', c)
                lines.append(f'  let (ok{t}_{j}, out{t}_{j}) = SCC_Decrypt(ad{t}_{j}, 0b{domain}, '
                             f'{literal(tag)}, c{t}_{j}, {literal(k, 256)}, {len(a)}, {len(c)});')
                check(f'ok{t}_{j} == {str(correct).lower()}', f'{case}: authentication')
                check_blocks(f'out{t}_{j}', plaintext, f'{case}: plaintext')
                check_blocks(f'ad{t}_{j}', a, f'{case}: decryption preserves AD')
                check_blocks(f'c{t}_{j}', c, f'{case}: decryption preserves ciphertext')

        # RFC 8452 Appendix A, plus POLYVAL's empty-input identity.
        h = common.b2v(bytes.fromhex('25629347589242761d31f826ba4b757b'))
        data = [common.b2v(bytes.fromhex(x)) for x in
                ('4f4f95668c83dfb6401762bb2d01a262', 'd1a24ddd2721d006bbe45f20d3c9f362')]
        want = common.b2v(bytes.fromhex('f7a3b47b846119fae5b7866cf5e5b77e'))
        common.check('RFC 8452 POLYVAL anchor', common.polyval(h, data) == want)
        vector('rfc', data)
        vector('empty', [])
        check(f'POLYVAL({literal(h)}, rfc, 2) == {literal(want)}', 'RFC POLYVAL')
        check(f'POLYVAL({literal(h)}, empty, 0) == {literal(0)}', 'Empty POLYVAL')

        key_bytes = bytes.fromhex('01' + '00' * 31)
        auth, enc = core.scc_rfc_keys(key_bytes, bytes(12))
        key = common.b2v(key_bytes)
        common.check('Key derivation vs RFC with zero nonce',
                     core.scc_keyderiv(key) == (common.b2v(enc), common.b2v(auth)))
        lines.append(f'  let (enc, auth) = SCC_KeyDeriv({literal(key, 256)});')
        check(f'enc == {literal(common.b2v(enc), 256)}', 'Derived encryption key')
        check(f'auth == {literal(common.b2v(auth))}', 'Derived authentication key')

        # Force low-word wrap; an SCC tag is unlikely to reach this boundary in a small KAT.
        for sep in (0, 1):
            tag = (0x0123456789abcdef01234567 << 32) | 0xfffffffe
            data = [0, 1, 1 << 127, (1 << 128) - 1]
            want = [x ^ core._E(key, core._ctr(sep, tag, i)) for i, x in enumerate(data)]
            vector(f'wrap{sep}', data)
            lines.append(f'  let wrapped{sep} = SCC_CTR({literal(key, 256)}, 0b{sep}, '
                         f'{literal(tag)}, wrap{sep}, 4);')
            check_blocks(f'wrapped{sep}', want, f'Segment {sep}: counter wrap')
    finally:
        core.aes_enc, common.montmul = original_aes, original_mont

    helpers = '''
function concat_blocks(A, B) = {
  let a = length(A);
  let b = length(B);
  var output = vector_init(a + b, sail_zeros(128));
  foreach (i from 0 to a - 1) { output[i] = A[i] };
  foreach (i from 0 to b - 1) { output[a + i] = B[i] };
  output
}
'''
    for name, calls, bits in [('AESE256', aes_calls, 256), ('Montmul', mont_calls, 128)]:
        helpers += f'\nfunction {name}(a, b) = match (a, b) {{\n'
        for (a, b), result in calls.items():
            helpers += f'  ({literal(a, bits)}, {literal(b)}) => {literal(result)},\n'
        helpers += f'  _ => {{ assert(false, "Unexpected {name} input"); sail_zeros(128) }}\n}}\n'
    main = '\nfunction main() -> unit = {\n' + '\n'.join(lines)
    main += '\n  print("SCC-SAIL-RESULT: PASS\\n")\n}\n'
    return listings + helpers + main, assertions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sail', default='sail', help='Sail executable (default: sail on PATH)')
    args = parser.parse_args()
    sail = shutil.which(args.sail)
    if sail is None:
        parser.error(f'Sail executable not found: {args.sail}; use --sail /path/to/sail')
    harness, assertions = build_harness(extract_listings(), json.loads(VECTORS.read_text()))
    common.section('Sail listings vs fixed vectors and the existing SCC core')
    with tempfile.TemporaryDirectory(prefix='scc-sail-kat-') as temporary:
        directory = Path(temporary)
        model, commands = directory / 'scc.sail', directory / 'run.commands'
        model.write_text(harness)
        commands.write_text('main()\n:run\n:quit\n')
        environment = dict(os.environ)
        environment['PATH'] = str(Path(sail).parent) + os.pathsep + environment.get('PATH', '')
        result = subprocess.run([sail, '--no-color', '-i', '--is', str(commands), str(model)],
                                cwd=directory, env=environment, capture_output=True, text=True, timeout=300)
    output = result.stdout + result.stderr
    passed = result.returncode == 0 and re.search(r'^SCC-SAIL-RESULT: PASS$', output, re.M)
    if not passed:
        print(output)
    common.check(f'{assertions} Sail assertions', bool(passed))
    common.done()


if __name__ == '__main__':
    main()
