#!/usr/bin/env python3
"""Run every *-kat.py in this directory and fail if any check fails.

Two reporting conventions are honoured, in this order of preference.

1.  A script may print a single verdict line

        KAT-RESULT: PASS            (or FAIL)

    which the runner uses directly.  This is unambiguous and is what new scripts
    should do.

2.  Otherwise the runner inspects the output for the word FAIL.  Several scripts
    deliberately evaluate a *wrong* formulation alongside the correct one, so that the
    test is demonstrably able to fail; those FAILs are expected.  Such a script declares
    them by printing, anywhere in its output,

        KAT-EXPECT-FAIL: <label>

    where <label> is either a column heading of a results table or a substring of the
    line that carries the expected FAIL.  For a column heading the runner works out the
    column's span from the header row and only excuses FAILs falling inside it, so a
    genuine failure in a neighbouring column on the same row is still caught.

    A script that declares a negative control and then does not produce the expected
    FAIL is reported as failed: it means the test has lost its power to discriminate.
"""
import os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
# The harnesses live in the kat/ subdirectory next to this runner; the shared
# modules they import (common.py, fips203.py, fips204.py, ecc_curves.py) sit
# beside them, which is what lets each one add its own directory to sys.path.
KATDIR = os.path.join(HERE, 'kat')
SCRIPTS = (sorted(f for f in os.listdir(KATDIR) if f.endswith('-kat.py'))
           if os.path.isdir(KATDIR) else [])
TIMEOUT = 900


def run(script):
    p = subprocess.run([sys.executable, os.path.join(KATDIR, script)],
                       capture_output=True, text=True, timeout=TIMEOUT)
    return p.returncode, p.stdout + p.stderr


def column_spans(lines, labels):
    """Map each label that names a table column to the [start, end) span it occupies.

    A label counts as a column heading only if it occurs in a line that carries no
    verdict of its own; a label occurring in a line that already says PASS or FAIL is a
    marker for that whole line instead, and is returned in the second list.
    """
    spans, line_labels = [], []
    for lab in labels:
        placed = False
        for line in lines:
            if line.startswith('KAT-EXPECT-FAIL:') or lab not in line:
                continue
            if 'PASS' in line or 'FAIL' in line:
                continue                      # not a header: treat as a line marker
            i = line.find(lab)
            # the column ends where the next field begins
            m = re.search(r'\s{2,}\S', line[i + len(lab):])
            end = i + len(lab) + (m.start() + len(m.group(0)) - 1 if m else len(line))
            spans.append((lab, i, end))
            placed = True
            break
        if not placed:
            line_labels.append(lab)
    return spans, line_labels


def classify(out):
    """(real_failures, expected_failures, declared_labels) for heuristic mode."""
    labels = [m.group(1).strip()
              for m in re.finditer(r'^KAT-EXPECT-FAIL:\s*(.+)$', out, re.M)]
    lines = out.splitlines()
    spans, line_labels = column_spans(lines, labels)
    real = exp = 0
    for line in lines:
        if line.startswith('KAT-EXPECT-FAIL:'):
            continue
        whole_line = any(lab in line for lab in line_labels)
        for m in re.finditer('FAIL', line):
            i = m.start()
            excused = whole_line or any(s <= i < e for _, s, e in spans)
            exp += excused
            real += not excused
    return real, exp, labels


def verdict(script):
    """Return (ok, note, output)."""
    try:
        rc, out = run(script)
    except subprocess.TimeoutExpired:
        return False, f'timed out after {TIMEOUT}s', '(timeout)'
    if rc != 0:
        return False, f'exit status {rc}', out
    m = re.search(r'^KAT-RESULT:\s*(PASS|FAIL)\s*$', out, re.M)
    if m:
        return m.group(1) == 'PASS', 'declared KAT-RESULT', out
    real, exp, labels = classify(out)
    if labels and exp == 0:
        return False, 'negative control did not fire', out
    note = f'{exp} expected-fail' if exp else ''
    return real == 0, note, out


def main():
    if not SCRIPTS:
        print('no *-kat.py found in ' + KATDIR, file=sys.stderr)
        return 1
    w = max(len(s) for s in SCRIPTS)
    bad, logs = [], {}
    print(f'running {len(SCRIPTS)} known-answer tests from {KATDIR}\n')
    for s in SCRIPTS:
        ok, note, out = verdict(s)
        logs[s] = out
        print(f'  {s:<{w}}  {"ok" if ok else "FAILED":6}  {note}')
        if not ok:
            bad.append(s)
    print()
    for s in bad:
        print(f'===== {s} ' + '=' * max(0, 64 - len(s)))
        print(logs[s].rstrip() + '\n')
    if bad:
        print(f'{len(bad)} of {len(SCRIPTS)} known-answer tests FAILED')
        return 1
    print(f'all {len(SCRIPTS)} known-answer tests passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
