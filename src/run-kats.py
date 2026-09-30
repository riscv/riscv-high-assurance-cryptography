#!/usr/bin/env python3
"""Run every kat/*-kat.py; each must exit 0 and print `KAT-RESULT: PASS`."""
import os, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

KATDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kat')
TIMEOUT = 900


def verdict(script):
    try:
        p = subprocess.run([sys.executable, os.path.join(KATDIR, script)],
                           capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f'timed out after {TIMEOUT}s', ''
    out = p.stdout + p.stderr
    if p.returncode:
        return False, f'exit status {p.returncode}', out
    if not re.search(r'^KAT-RESULT: PASS\s*$', out, re.M):
        return False, 'no KAT-RESULT: PASS', out
    return True, '', out


def main():
    scripts = sorted(f for f in os.listdir(KATDIR) if f.endswith('-kat.py'))
    if not scripts:
        print(f'no *-kat.py in {KATDIR}', file=sys.stderr)
        return 1
    with ThreadPoolExecutor() as ex:
        results = dict(zip(scripts, ex.map(verdict, scripts)))
    w = max(map(len, scripts))
    for s, (ok, note, _) in results.items():
        print(f'  {s:<{w}}  {"ok" if ok else "FAILED":6}  {note}')
    bad = [s for s, (ok, _, _) in results.items() if not ok]
    for s in bad:
        print(f'\n===== {s} ' + '=' * max(0, 64 - len(s)) + '\n' + results[s][2].rstrip())
    print(f'\n{len(bad)} of {len(scripts)} known-answer tests FAILED' if bad
          else f'\nall {len(scripts)} known-answer tests passed')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
