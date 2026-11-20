#!/usr/bin/env python3
"""Copy scripts/ci/gate.sh into the Tekton Task and the GitLab template, which run inside the kube-noob image
and so cannot call the file the way action.yml does.

Each wrapper's script has a preamble of its own (where its outputs go: Tekton result paths, the GitLab dotenv
file) and then a marker line; everything after the marker is the body of scripts/ci/gate.sh (the file minus its
`#!/bin/sh` line), re-indented for the YAML block scalar. The shell the three wrappers run is therefore one
script, tested once in tests/test_ci_wrappers.py with a stub kube-noob for every exit code (G291).

Usage:
  python scripts/ci_wrappers.py           write the copies
  python scripts/ci_wrappers.py --check   exit 1 if a copy is stale (CI)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path("scripts/ci/gate.sh")
MARKER = "# -- scripts/ci/gate.sh follows; written by scripts/ci_wrappers.py, so edit the script, not this file --"
WRAPPERS = (Path("deploy/tekton/kube-noob-gate.yaml"), Path("deploy/gitlab/kube-noob-gate.gitlab-ci.yml"))


def body(root: Path) -> list[str]:
    lines = (root / SCRIPT).read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "#!/bin/sh":
        raise SystemExit(f"{SCRIPT}: the first line must be #!/bin/sh")
    for n, line in enumerate(lines, 1):
        if "\t" in line or line != line.rstrip():
            raise SystemExit(f"{SCRIPT}:{n}: tabs and trailing spaces do not survive a YAML block scalar")
    return lines[1:]


def render(text: str, script: list[str], name: str) -> str:
    """The wrapper with everything after its marker replaced by the script, at the marker's indentation."""
    lines = text.splitlines()
    hits = [i for i, line in enumerate(lines) if line.strip() == MARKER]
    if len(hits) != 1:
        raise SystemExit(f"{name}: expected exactly one marker line, found {len(hits)}: {MARKER!r}")
    at = hits[0]
    indent = lines[at][: len(lines[at]) - len(lines[at].lstrip())]
    end = at + 1
    while end < len(lines) and (not lines[end].strip() or lines[end].startswith(indent)):
        end += 1
    copied = [(indent + line) if line else "" for line in script]
    return "\n".join([*lines[: at + 1], *copied, *lines[end:]]) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if a wrapper's copy is stale")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    script = body(a.root)
    stale = []
    for rel in WRAPPERS:
        path = a.root / rel
        current = path.read_text(encoding="utf-8")
        wanted = render(current, script, str(rel))
        if current == wanted:
            continue
        if a.check:
            stale.append(str(rel))
        else:
            path.write_text(wanted, encoding="utf-8")
            print(f"wrote {rel}")
    if stale:
        print(f"stale: {', '.join(stale)} do not carry {SCRIPT}; run: python scripts/ci_wrappers.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
