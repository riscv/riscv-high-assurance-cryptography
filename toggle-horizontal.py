#!/usr/bin/env python3
"""Switch the [horizontal] layout of the Rules on or off.

  ./toggle-horizontal.py on       uncomment every // [horizontal]
  ./toggle-horizontal.py off      comment out every [horizontal]
  ./toggle-horizontal.py status   count both kinds (default)

Covers modules/ROOT/pages/*.adoc. A [horizontal] whose next non-blank line
is a Principle (anchor label P<n>) is never touched.
"""
import pathlib, re, sys

PAGES = pathlib.Path(__file__).resolve().parent / "modules/ROOT/pages"
ON, OFF = "[horizontal]", "// [horizontal]"
PRINCIPLE = re.compile(r"^\[\[[^\]]*,P\d+\]\]")

def is_principle(lines, i):
    for l in lines[i + 1:]:
        if l.strip():
            return bool(PRINCIPLE.match(l))
    return False

def main(mode):
    tot = {ON: 0, OFF: 0, "changed": 0}
    for f in sorted(PAGES.glob("*.adoc")):
        lines = f.read_text().split("\n")
        changed = 0
        for i, l in enumerate(lines):
            s = l.strip()
            if s not in (ON, OFF) or is_principle(lines, i):
                continue
            tot[s] += 1
            want = {"on": ON, "off": OFF}.get(mode, s)
            if s != want:
                lines[i] = want
                changed += 1
        if changed:
            f.write_text("\n".join(lines))
            print(f"{f.name}: {changed} changed")
        tot["changed"] += changed
    print(f"before: {tot[ON]} on, {tot[OFF]} off (Principles excluded); {tot['changed']} changed")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "status"
    if mode not in ("on", "off", "status"):
        sys.exit(__doc__)
    main(mode)
