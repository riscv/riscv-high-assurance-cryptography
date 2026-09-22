#!/usr/bin/env python3
"""Check cross-references between the chapter pages in modules/ROOT/pages/.

Each chapter is a separate page on the website, so a link to an anchor in
another chapter must name that chapter's file:

    <<Zkl-notation.adoc#KLEE-Notation>>        not   <<KLEE-Notation>>

The PDF renders both forms the same ("Section 1"), but on the site the short
form is a broken link. Links within the same page stay <<id>>.

Reports, as file:line:
  - <<id>> / <<id,text>> whose anchor is defined on another page
  - <<Page.adoc#id>> whose page or anchor does not exist

Usage:
    scripts/check-cross-page-refs.py          # check; exit 1 on problems
    scripts/check-cross-page-refs.py --fix    # also rewrite <<id>> links

Comments and verbatim blocks (listing, literal, passthrough, comment) are
skipped, as they do not render as links.
"""
import re
import sys
from pathlib import Path

PAGES = Path(__file__).resolve().parent.parent / 'modules' / 'ROOT' / 'pages'

ANCHOR = re.compile(r'\[\[([\w:.-]+)(?:,[^\]]*)?\]\]|\[#([\w:.-]+)[\],.%]|anchor:([\w:.-]+)\[')
LOCAL_REF = re.compile(r'<<([\w:.-]+)(,[^>]*)?>>')
PAGE_REF = re.compile(r'<<([\w.-]+\.adoc)#([\w:.-]+)(,[^>]*)?>>')
VERBATIM = re.compile(r'^(-{4,}|\.{4,}|\+{4,}|/{4,}|`{3,}.*)$')


def text_lines(lines):
    """Yield (index, line) for lines outside comments and verbatim blocks."""
    fence = None
    for i, line in enumerate(lines):
        stripped = line.rstrip()
        if fence:
            if stripped == fence:
                fence = None
            continue
        if VERBATIM.match(stripped):
            fence = stripped
            continue
        if line.startswith('//'):
            continue
        yield i, line


def main():
    fix = '--fix' in sys.argv[1:]
    files = sorted(PAGES.glob('*.adoc'))
    anchors = {}  # id -> set of page names defining it
    for f in files:
        for m in ANCHOR.finditer(f.read_text()):
            anchors.setdefault(next(g for g in m.groups() if g), set()).add(f.name)

    problems = fixed = 0
    for f in files:
        lines = f.read_text().split('\n')
        changed = False
        for i, line in text_lines(lines):
            where = f'{f.relative_to(PAGES.parent.parent.parent)}:{i + 1}'
            for m in PAGE_REF.finditer(line):
                page, anchor = m.group(1), m.group(2)
                if not (PAGES / page).is_file():
                    problems += 1
                    print(f'{where}: {m.group(0)}: no page {page}')
                elif page not in anchors.get(anchor, ()):
                    problems += 1
                    print(f'{where}: {m.group(0)}: no anchor #{anchor} in {page}')

            def other_page(m):
                owners = anchors.get(m.group(1), set())
                return None if not owners or f.name in owners else sorted(owners)

            for m in LOCAL_REF.finditer(line):
                owners = other_page(m)
                if not owners:
                    continue
                target = f'<<{owners[0]}#{m.group(1)}{m.group(2) or ""}>>'
                if len(owners) > 1:
                    problems += 1
                    print(f'{where}: {m.group(0)}: anchor is defined in several pages: {", ".join(owners)}')
                elif fix:
                    fixed += 1
                else:
                    problems += 1
                    print(f'{where}: {m.group(0)} points to {owners[0]}; write {target}')
            if fix:
                new = LOCAL_REF.sub(
                    lambda m: (lambda o: f'<<{o[0]}#{m.group(1)}{m.group(2) or ""}>>'
                               if o and len(o) == 1 else m.group(0))(other_page(m)),
                    line)
                if new != line:
                    lines[i] = new
                    changed = True
        if changed:
            f.write_text('\n'.join(lines))

    if fixed:
        print(f'Rewrote {fixed} link(s) to name their page.')
    if problems:
        if not fix:
            print(f'\n{problems} problem(s). Run scripts/check-cross-page-refs.py --fix '
                  'to rewrite <<id>> links that point to another page.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
