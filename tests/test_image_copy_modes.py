"""A `COPY --chmod` must not be the thing that creates its destination directory.

When a `COPY`'s destination directory does not already exist, the builder creates it -- and a newer BuildKit
applies the `--chmod` to that created directory as well as to the files. A mode without an execute bit (`0444`,
`0400`, `0644`) then leaves a directory nothing non-root can traverse, and the only symptom is a message about
the FILE:

    cp: cannot stat '/kube-noob-db/kube-noob-db.tgz': Permission denied
    cp: cannot stat '/seed/jira-snapshot.tgz.enc': Permission denied

Root is unaffected (`DAC_OVERRIDE`), so it survives every build and every local run done as root, and only bites
the non-root user the image declares. It cost two red CI jobs on main and on every branch: `db-image` (G319) and
`e2e-kind (OpenShift 4.22)`, which were the same defect in two Containerfiles, found three days apart because
fixing the first one did not look for its sibling.

So the rule is structural, not per-file: every `COPY --chmod` whose mode lacks an execute bit must be preceded by
an explicit `RUN mkdir` that makes its destination directory traversable.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

COPY = re.compile(r"^COPY\s+(?P<flags>(?:--\S+\s+)*)(?P<rest>\S.*)$")
CHMOD = re.compile(r"--chmod=(?P<mode>[0-7]{3,4})")


def _containerfiles() -> list[Path]:
    found = [p for p in ROOT.glob("Containerfile*") if p.is_file()]
    found += [p for p in ROOT.glob("Dockerfile*") if p.is_file()]
    assert found, "no Containerfile found; this guard would pass vacuously"
    return sorted(found)


def _destination_dir(rest: str) -> str:
    """The directory the COPY writes into: the destination with a trailing slash is itself a directory,
    otherwise it is the destination's parent."""
    dest = rest.rsplit(maxsplit=1)[-1]
    return dest if dest.endswith("/") else dest.rsplit("/", 1)[0] + "/"


def test_every_chmod_copy_has_a_traversable_destination_directory() -> None:
    bad: list[str] = []
    for cf in _containerfiles():
        lines = cf.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines, 1):
            m = COPY.match(line.strip())
            if not m:
                continue
            mode = CHMOD.search(m.group("flags"))
            if not mode:
                continue
            # An execute bit on the owner triad is enough to traverse as that owner; these copies are all
            # `--chown=0:0`, so what matters is whether ANY triad can enter. A mode with no execute bit at all
            # cannot be a usable directory for anyone but root.
            if any(int(d) & 1 for d in mode.group("mode")[-3:]):
                continue
            dest = _destination_dir(m.group("rest"))
            if dest in ("/", ""):
                continue
            made = any(
                re.search(r"^RUN\b.*\bmkdir\b.*" + re.escape(dest.rstrip("/")) + r"\b", earlier.strip())
                for earlier in lines[: n - 1]
            )
            if not made:
                bad.append(
                    f"{cf.name}:{n} copies with {mode.group(0)} into {dest} without an earlier "
                    f"`RUN mkdir -p {dest.rstrip('/')} && chmod 0755 {dest.rstrip('/')}`; "
                    f"the builder creates that directory with the same mode and nothing non-root can enter it"
                )
    assert not bad, "\n".join(bad)


def test_the_documented_snippet_does_not_hand_a_user_the_same_defect() -> None:
    """`docs/use-cases.md` tells a reader to build a seed image with a printf'd Containerfile. It carried the
    same `COPY --chmod=0444 ... /seed/...` with no mkdir, so anyone following it built an image whose own user
    could not read the file."""
    text = (ROOT / "docs" / "use-cases.md").read_text(encoding="utf-8")
    for snippet in re.findall(r"printf '([^']*Containerfile[^']*)'", text) + re.findall(r"printf '(FROM [^']*)'", text):
        if "--chmod=0444" in snippet and "/seed/" in snippet:
            assert "mkdir -p /seed" in snippet, (
                "the documented seed Containerfile copies into /seed with a mode that has no execute bit and "
                "never creates /seed, so the image's own user cannot read what it holds"
            )
