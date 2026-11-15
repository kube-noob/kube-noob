#!/usr/bin/env python3
"""Refresh the bundled index of reported OpenShift issues (src/kube_noob/data/known_issues/) from the release notes.

Usage: python scripts/vendor_known_issues.py [--minors 4.20,4.21,4.22] [--workdir DIR]
       python scripts/vendor_known_issues.py --check     exit 1 if a part is over the size limit or unreadable,
                                                         a record has a field the loader does not know (a component
                                                         or operator version would change what operators issues can
                                                         join on), a record the loader would reject, or an operator
                                                         alias name no record uses; prints how many records each
                                                         alias term hits and which records two packages share

Parses github.com/openshift/openshift-docs (branches enterprise-<minor>, Apache-2.0) with
kube_noob.sources.release_notes and writes one JSON file per minor release and kind, split into parts under
PART_LIMIT bytes so every file stays readable text under the Claude plugin directory's 256 KiB limit. Needs git and
the network.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "kube_noob" / "data" / "known_issues"
PART_LIMIT = 200_000
sys.path.insert(0, str(ROOT / "src"))


def compact(record: dict, commit: str) -> dict:
    prefix = f"https://github.com/openshift/openshift-docs/blob/{commit}/"
    r = {k: v for k, v in record.items() if k not in {"summary", "workaround", "url", "product"} and v is not None}
    r["source"] = record["source"].removeprefix(prefix)
    if r.get("ids") == [r["id"]]:
        del r["ids"]
    return r


def write_parts(records: list[dict], meta: dict) -> list[Path]:
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.json"):
        old.unlink()
    written: list[Path] = []
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in records:
        groups.setdefault((r["minor"], r["kind"]), []).append(r)
    for (minor, kind), recs in sorted(groups.items()):
        part: list[dict] = []
        n = 1

        def flush(part: list[dict], n: int, minor: str = minor, kind: str = kind) -> None:
            path = OUT / f"openshift-{minor}-{kind}-{n}.json"
            body = ",\n".join(json.dumps(x, ensure_ascii=False, separators=(",", ":")) for x in part)
            head = json.dumps(meta, ensure_ascii=False, separators=(",", ":"))[:-1]
            path.write_text(f'{head},"records":[\n{body}\n]}}\n', encoding="utf-8")
            written.append(path)

        size = 0
        for r in recs:
            line = len(json.dumps(r, ensure_ascii=False, separators=(",", ":")).encode()) + 2
            if part and size + line > PART_LIMIT - 4000:
                flush(part, n)
                part, size, n = [], 0, n + 1
            part.append(r)
            size += line
        if part:
            flush(part, n)
    return written


#: The fields a record has. kube_noob.operator_issues joins by name BECAUSE no record has a component, a package or
#: an operator version (G278); a regeneration that adds one must change that join, not be ignored by it.
RECORD_FIELDS = frozenset({"id", "ids", "kind", "minor", "version", "text", "source", "issued", "fixedIn"})


def check() -> int:
    bad = []
    for f in sorted(OUT.glob("*.json")):
        raw = f.read_bytes()
        if len(raw) >= 256 * 1024:
            bad.append(f"{f.name}: {len(raw)} bytes")
        json.loads(raw.decode("utf-8"))
    # The operator alias table (kube_noob.operator_issues.ALIASES) names products as the release notes write them. A
    # regenerated corpus that no longer uses a name would leave that operator matched against nothing while it reads
    # as "named in none", so a dead or ambiguous name fails here, next to the data that killed it.
    from kube_noob import known_issues, operator_issues

    for f in sorted(OUT.glob("*.json")):
        for n, r in enumerate(json.loads(f.read_text(encoding="utf-8")).get("records", []), start=1):
            extra = sorted(set(r) - RECORD_FIELDS) if isinstance(r, dict) else ["<not an object>"]
            if extra:
                bad.append(f"{f.name} record {n}: fields the loader does not know: {', '.join(extra)}")
    issues, meta = known_issues._read_parts(sorted(OUT.glob("*.json")))
    bad += [f"rejected by the loader: {r}" for r in meta.get("_rejected", [])]
    bad += [f"operator alias: {p}" for p in operator_issues.alias_problems(issues)]
    for line in operator_issues.alias_report(issues):
        print(line)
    if bad:
        print("\n".join(bad))
        return 1
    print(
        f"{len(list(OUT.glob('*.json')))} known-issue files, each under 256 KiB and valid JSON; every operator alias "
        "name is used by them"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--minors", default="4.20,4.21,4.22")
    ap.add_argument("--workdir", type=Path)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.check:
        return check()
    from kube_noob.sources.release_notes import fetch, snapshot

    minors = [m.strip() for m in a.minors.split(",") if m.strip()]
    with tempfile.TemporaryDirectory(prefix="kube-noob-rn-") as tmp:
        records, commits = fetch(minors, a.workdir or Path(tmp))
    snap = snapshot(records, commits)
    meta = {k: v for k, v in snap.items() if k != "records"}
    compacted = [compact(r, commits[r["minor"]]) for r in records]
    files = write_parts(compacted, meta)
    print(f"{len(records)} issues from OpenShift {', '.join(minors)} -> {len(files)} files in {OUT}")
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
