"""Generate docs/stig.md: what kube-noob's rules judge of each rule in the DISA Kubernetes STIG.

Two data files, both under ``src/kube_noob/data/stig/``, and one generated document:

* ``kubernetes-stig.yaml`` -- the pinned rule list: Group/Vuln id, rule id, STIG id, severity, title, and one
  line in kube-noob's own words on what the check reads. DISA's check and fix text is not shipped.
* ``crosswalk.yaml`` -- one row per rule, hand-written, with exactly one of four statuses.
* ``docs/stig.md`` -- written from the two, never by hand.

The script validates before it renders, and refuses rather than writing a table it cannot stand behind: a row for
an id the snapshot does not have is an invented control, a snapshot id with no row is a control the page would
silently not list, and a status outside the four is a claim nobody defined. ``tests/test_stig_crosswalk.py`` then
runs every ``covered`` and ``partly`` row on a fixture, so the sentences here are measurements.

    python scripts/stig_crosswalk.py            write docs/stig.md
    python scripts/stig_crosswalk.py --check    exit 1 when the data is invalid or the document is stale
    python scripts/stig_crosswalk.py --verify-source CLUSTER_DIR NODE_DIR
        compare the snapshot with checkouts of mitre/k8s-cluster-stig-baseline and mitre/k8s-node-stig-baseline
        (the mirror it was parsed from): ids, rule ids, STIG ids, severities, titles, and the recorded hash

Everything but ``--verify-source`` is offline, and that one reads two local directories.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SNAPSHOT = ROOT / "src" / "kube_noob" / "data" / "stig" / "kubernetes-stig.yaml"
CROSSWALK = ROOT / "src" / "kube_noob" / "data" / "stig" / "crosswalk.yaml"
DOC = ROOT / "docs" / "stig.md"

COVERED, PARTLY, NOT_DETERMINABLE, NOT_COVERED = (
    "covered",
    "partly",
    "not determinable from manifests",
    "not covered",
)
#: The only statuses, in the order the document counts them.
STATUSES = (COVERED, PARTLY, NOT_DETERMINABLE, NOT_COVERED)
STATUS_MEANS = {
    COVERED: "a kube-noob rule judges this check from a manifest. The row says how, and where the rule is stricter.",
    PARTLY: "a rule judges part of the check. The row names the part it does not judge.",
    NOT_DETERMINABLE: "the check reads something no manifest holds. The row names the evidence it needs.",
    NOT_COVERED: "a manifest could decide it, and no kube-noob rule reads it yet. These rows are the rule backlog.",
}
#: What a check reads, and how the document names it.
READS = {
    "static-pod-manifest": "control plane static pod manifest",
    "kubelet": "kubelet process and configuration file",
    "node-files": "file ownership and mode on a node",
    "node-state": "node or cluster state",
    "cluster-objects": "objects in the cluster",
    "documentation": "PPSM list and system documentation",
}
#: Checks that read one of these are in no manifest, so their rows can only be NOT_DETERMINABLE.
_OFF_MANIFEST = frozenset({"kubelet", "node-files", "node-state", "documentation"})
CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}

NOT_AN_ASSESSMENT = (
    "**This page is not a STIG assessment and not an ATO artifact.** It says which of DISA's checks a kube-noob "
    "rule reads, and nothing about any cluster. kube-noob reads the manifests it is given; a STIG is assessed "
    "against a running system by a person who signs for the result. A finding from a mapped rule is evidence an "
    "assessor can use, and a clean run of a mapped rule is not a `Not a Finding`. Every row marked "
    f"`{NOT_DETERMINABLE}` needs cluster or node evidence, which the row names, and kube-noob has no opinion on "
    "it at all. Nothing here is a statement by or on behalf of DISA."
)
MANAGED_CONTROL_PLANE = (
    "**A managed control plane has no static pod manifest to give.** On EKS, AKS, GKE and ROSA with hosted "
    "control planes the API server, controller manager, scheduler and etcd run outside the cluster, so every "
    "row that reads a control plane static pod manifest is not determinable there, whatever its status says "
    "below: the status describes the rule, and the rule has nothing to read. KN-S038 and KN-S039 decline when "
    "no kube-apiserver or etcd container is in the input, and a declined rule is never counted as clean. The "
    "same holds for an application bundle audited on its own. On OpenShift, where operators write the control "
    "plane's arguments, KN-S038 declines a kube-apiserver manifest with that reason, and this STIG is not the "
    "one that applies."
)

_V_ID = re.compile(r"\AV-\d{6}\Z")
_RULE_ID = re.compile(r"\ASV-(\d{6})r\d+_rule\Z")
_STIG_ID = re.compile(r"\ACNTR-K8-\d{6}\Z")
_RULE_FIELDS = frozenset({"id", "rule_id", "stig_id", "severity", "title", "check", "profiles"})
_ROW_FIELDS = frozenset({"status", "reads", "rules", "judged", "not_judged", "evidence", "backlog", "note"})


class CrosswalkError(Exception):
    """The snapshot or the crosswalk does not say what it must; nothing is rendered from it."""


def canonical(rules: list[dict[str, Any]]) -> str:
    """The text ``source.rules_sha256`` is the hash of."""
    return json.dumps(rules, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _read(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CrosswalkError(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CrosswalkError(f"{path} is not a mapping")
    return data


def load_snapshot(path: Path | None = None) -> dict[str, Any]:
    """The pinned rule list, or a CrosswalkError naming what is wrong with it."""
    path = path or SNAPSHOT
    data = _read(path)
    src, rules = data.get("source"), data.get("rules")
    if not isinstance(src, dict) or not isinstance(rules, list) or not rules:
        raise CrosswalkError(f"{path} needs a `source` mapping and a non-empty `rules` list")
    for key in ("stig_version", "stig_release", "published", "checklist", "parsed_from", "parsed_sha256", "retrieved"):
        if not src.get(key):
            raise CrosswalkError(f"{path}: source.{key} is missing")
    if hashlib.sha256(canonical(rules).encode()).hexdigest() != src.get("rules_sha256"):
        raise CrosswalkError(f"{path}: the rules list does not hash to the rules_sha256 it records")
    if src.get("rule_count") != len(rules):
        raise CrosswalkError(f"{path}: source.rule_count is {src.get('rule_count')} and there are {len(rules)} rules")
    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != _RULE_FIELDS:
            raise CrosswalkError(f"{path}: a rule does not have exactly the fields {sorted(_RULE_FIELDS)}: {rule!r}")
        vid = str(rule["id"])
        m = _RULE_ID.match(str(rule["rule_id"]))
        if not _V_ID.match(vid) or not m or m.group(1) != vid[2:] or not _STIG_ID.match(str(rule["stig_id"])):
            raise CrosswalkError(f"{path}: {vid} / {rule['rule_id']} / {rule['stig_id']} is not a well-formed rule")
        if vid in seen:
            raise CrosswalkError(f"{path}: {vid} is listed twice")
        seen.add(vid)
        if rule["severity"] not in CAT:
            raise CrosswalkError(f"{path}: {vid} has severity {rule['severity']!r}")
        if "\n" in str(rule["check"]) or not str(rule["check"]).strip() or not str(rule["title"]).strip():
            raise CrosswalkError(f"{path}: {vid} needs a title and a one-line check summary")
        if not rule["profiles"] or not set(rule["profiles"]) <= set(src["parsed_from"]):
            raise CrosswalkError(f"{path}: {vid} names a profile that source.parsed_from does not")
    if [r["id"] for r in rules] != sorted(seen):
        raise CrosswalkError(f"{path}: the rules are not sorted by id")
    return data


def _catalogue() -> dict[str, str]:
    from kube_noob.audit.rules import RULES

    return {r.rule_id: r.title for r in (RULES.values() if isinstance(RULES, dict) else RULES)}


def load_crosswalk(snapshot: dict[str, Any], path: Path | None = None) -> dict[str, dict[str, Any]]:
    """The rows, keyed by V-ID, or a CrosswalkError naming the row that does not hold."""
    path = path or CROSSWALK
    rows = _read(path).get("rows")
    if not isinstance(rows, dict):
        raise CrosswalkError(f"{path} needs a `rows` mapping")
    ids = {r["id"] for r in snapshot["rules"]}
    invented = sorted(set(rows) - ids)
    if invented:
        raise CrosswalkError(f"{path}: {', '.join(invented)} is not in the snapshot; a row may not invent a control")
    missing = sorted(ids - set(rows))
    if missing:
        raise CrosswalkError(f"{path}: no row for {', '.join(missing)}; every rule in the snapshot is listed")
    known = _catalogue()
    for vid, row in rows.items():

        def bad(why: str, vid: str = vid) -> CrosswalkError:
            return CrosswalkError(f"{path}: {vid} {why}")

        if not isinstance(row, dict) or not set(row) <= _ROW_FIELDS:
            raise bad(f"has a field outside {sorted(_ROW_FIELDS)}")
        status, reads, rules = row.get("status"), row.get("reads"), row.get("rules")
        if status not in STATUSES:
            raise bad(f"has status {status!r}; the only statuses are {', '.join(STATUSES)}")
        if reads not in READS:
            raise bad(f"reads {reads!r}, which is not one of {', '.join(READS)}")
        if not isinstance(rules, list):
            raise bad("needs a `rules` list, empty when no rule judges it")
        unknown = [r for r in rules if r not in known]
        if unknown:
            raise bad(f"names {', '.join(map(str, unknown))}, which is not in kube-noob's rule catalogue")

        def said(key: str, row: dict[str, Any] = row) -> bool:
            return isinstance(row.get(key), str) and bool(row[key].strip())

        if status in {COVERED, PARTLY}:
            if not rules or not said("judged"):
                raise bad(f"is {status} and must name the rules and say what they judge")
            if (status == PARTLY) != said("not_judged"):
                raise bad("must name the part not judged if it is partly covered, and only then")
            if reads in _OFF_MANIFEST:
                raise bad(f"reads {reads}, which no manifest holds, and cannot be {status}")
        else:
            if rules or "judged" in row or "not_judged" in row:
                raise bad(f"is {status} and names a rule: a rule id on a row reads as coverage, so put it in `note`")
            if status == NOT_DETERMINABLE and (not said("evidence") or reads == "cluster-objects"):
                raise bad("must say what evidence would decide it, and cannot be a check on cluster objects")
            if status == NOT_COVERED and (not said("backlog") or reads in _OFF_MANIFEST):
                raise bad("must describe the rule that would cover it, and must read something a manifest holds")
    return {vid: rows[vid] for vid in sorted(rows)}


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _source_url(snapshot: dict[str, Any], rule: dict[str, Any]) -> str:
    """The control file this rule was parsed from, at the pinned commit."""
    tree = str(snapshot["source"]["parsed_from"][rule["profiles"][0]])
    return f"{tree.replace('/tree/', '/blob/', 1)}/S{rule['id']}.rb"


def render(snapshot: dict[str, Any], rows: dict[str, dict[str, Any]]) -> str:
    src = snapshot["source"]
    rules = snapshot["rules"]
    titles = _catalogue()
    cat = {r["id"]: CAT[r["severity"]] for r in rules}
    cross = Counter((rows[r["id"]]["status"], cat[r["id"]]) for r in rules)
    by_status = Counter(row["status"] for row in rows.values())
    by_cat = Counter(cat.values())
    cats = ("CAT I", "CAT II", "CAT III")
    judging = sorted({r for row in rows.values() for r in row["rules"]})
    out = [
        "# DISA Kubernetes STIG: what kube-noob's rules judge, and what no manifest can show",
        "",
        "<!-- Generated by scripts/stig_crosswalk.py. Do not edit: run the script. -->",
        "",
        f"Benchmark: **{src['benchmark']}**, **Version {src['stig_version']}, Release {src['stig_release']}**, "
        f"published {src['published']}, **{len(rules)} rules** ({by_cat['CAT I']} CAT I, {by_cat['CAT II']} CAT II, "
        f"{by_cat['CAT III']} CAT III). NIST's National Checklist Program lists it at "
        f"[{src['checklist'].removeprefix('https://')}]({src['checklist']}).",
        "",
        NOT_AN_ASSESSMENT,
        "",
        MANAGED_CONTROL_PLANE,
        "",
        "## Where the rule list came from",
        "",
        "The authoritative source is DISA's XCCDF. Neither ncp.nist.gov nor public.cyber.mil could be read when "
        f"the list was pinned ({src['retrieved']}), so the ids, rule ids, severities and titles were parsed from "
        "MITRE SAF's two InSpec profiles for this release, which carry DISA's metadata as tags: "
        + " and ".join(f"[{name}]({url})" for name, url in sorted(src["parsed_from"].items()))
        + f". The sha256 over the control files parsed is `{src['parsed_sha256']}`. Every id, rule id and severity "
        "was then compared with "
        + " and ".join(f"<{u}>" for u in src["cross_checked"])
        + f", which agreed on all {len(rules)}. The pinned list is `src/kube_noob/data/stig/kubernetes-stig.yaml`; "
        f"its sha256 is `{src['rules_sha256']}`, recomputed by `scripts/stig_crosswalk.py --check` and "
        "`tests/test_stig_crosswalk.py`. It carries DISA's rule titles and one line per check in kube-noob's own "
        "words; DISA's check, fix and discussion text is not reproduced here. Read the rule itself before you "
        "rely on a row.",
        "",
        "## Counts",
        "",
        "No status on this page is a pass. `covered` says a rule reads what the check reads; whether a cluster "
        "meets the check is a different question, answered by running the rule on that cluster's manifests and "
        "then by an assessor.",
        "",
        "| Status | CAT I | CAT II | CAT III | All |",
        "|---|---|---|---|---|",
    ]
    out += [f"| {s} | " + " | ".join(str(cross[s, c]) for c in cats) + f" | {by_status[s]} |" for s in STATUSES]
    out += [
        "| **All** | " + " | ".join(str(by_cat[c]) for c in cats) + f" | {len(rules)} |",
        "",
    ]
    out += [f"- `{s}`: {STATUS_MEANS[s]}" for s in STATUSES]
    out += [
        "",
        f"{by_status[COVERED] + by_status[PARTLY]} of the {len(rules)} rules have a kube-noob rule behind them, "
        f"through {len(judging)} rules: " + ", ".join(f"`{r}`" for r in judging) + ".",
        "",
        "What each check reads decides most of this, so here it is by source:",
        "",
        "| The check reads | Rules | " + " | ".join(STATUSES) + " |",
        "|---|---|" + "---|" * len(STATUSES),
    ]
    reads = Counter(row["reads"] for row in rows.values())
    reads_status = Counter((row["reads"], row["status"]) for row in rows.values())
    out += [
        f"| {READS[k]} | {reads[k]} | " + " | ".join(str(reads_status[k, s]) for s in STATUSES) + " |" for k in READS
    ]
    high = [r for r in rules if r["severity"] == "high"]
    out += [
        "",
        f"## The {len(high)} CAT I rules",
        "",
        "| Rule | Title | Status | kube-noob rules |",
        "|---|---|---|---|",
    ]
    out += [
        f"| {r['id']} | {_cell(r['title'])} | {rows[r['id']]['status']} | "
        f"{', '.join(f'`{x}`' for x in rows[r['id']]['rules']) or '—'} |"
        for r in high
    ]
    judged = [r for r in rules if rows[r["id"]]["status"] in {COVERED, PARTLY}]
    out += [
        "",
        f"## The {len(judged)} rules a kube-noob rule judges",
        "",
        "Each of these is run on a fixture by `tests/test_stig_crosswalk.py`: the manifest the rule reports, the "
        "one it does not, and for a `partly` row the manifest that is a finding to DISA and clean to kube-noob.",
        "",
    ]
    for r in judged:
        row = rows[r["id"]]
        out += [
            f"### {r['id']} — {r['title']} ({cat[r['id']]}, {row['status']})",
            "",
            f"- **The check:** {r['check']}",
            f"- **Judged:** {row['judged']}",
        ]
        if row["status"] == PARTLY:
            out.append(f"- **Not judged:** {row['not_judged']}")
        if row.get("note"):
            out.append(f"- **Note:** {row['note']}")
        out.append("- **Rules:** " + "; ".join(f"`{x}` ({titles[x]})" for x in row["rules"]))
        out.append("")
    backlog = [r for r in rules if rows[r["id"]]["status"] == NOT_COVERED]
    out += [
        f"## The {len(backlog)} rules not covered: the backlog",
        "",
        "A manifest could decide each of these, and no kube-noob rule reads it. Most are one flag in a control "
        "plane static pod manifest. A row leaves this list only with a rule and a fixture.",
        "",
        "| Rule | CAT | What a rule would read | Note |",
        "|---|---|---|---|",
    ]
    out += [
        f"| {r['id']} | {cat[r['id']]} | {_cell(rows[r['id']]['backlog'])} | {_cell(rows[r['id']].get('note', ''))} |"
        for r in backlog
    ]
    out += [
        "",
        f"## Every rule: all {len(rules)}",
        "",
        "The V-ID links to the control file the row's id, rule id and severity were parsed from, at the pinned "
        "commit. The last column is what the row's status rests on: what a rule judges and does not, the "
        "evidence a check needs, or the rule that would cover it.",
        "",
        "| Rule | STIG ID | CAT | Title | The check reads | Status | kube-noob rules | Why |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rules:
        row = rows[r["id"]]
        if row["status"] == NOT_DETERMINABLE:
            why = f"Needs: {row['evidence']}"
        elif row["status"] == NOT_COVERED:
            why = f"Backlog: {row['backlog']}"
        elif row["status"] == PARTLY:
            why = f"Not judged: {row['not_judged']}"
        else:
            why = f"Judged: {row['judged']}"
        out.append(
            f"| [{r['id']}]({_source_url(snapshot, r)}) | {r['stig_id']} | {cat[r['id']]} | {_cell(r['title'])} | "
            f"{READS[row['reads']]} | {row['status']} | {', '.join(f'`{x}`' for x in row['rules']) or '—'} | "
            f"{_cell(why)} |"
        )
    out.append("")
    return "\n".join(out)


# -- the mirror the snapshot was parsed from -------------------------------------------------------------------------


def _ruby_string(text: str, start: int) -> str:
    """The Ruby string literal at ``start``: ``'...'``, ``"..."`` or ``%q(...)`` with balanced parentheses."""
    out: list[str] = []
    if text.startswith("%q(", start):
        i, depth = start + 3, 1
        while True:
            ch = text[i]
            if ch == "\\":
                out.append(text[i + 1])
                i += 2
                continue
            depth += (ch == "(") - (ch == ")")
            if depth == 0:
                return "".join(out)
            out.append(ch)
            i += 1
    quote = text[start]
    if quote not in "'\"":
        raise CrosswalkError(f"not a string literal: {text[start : start + 40]!r}")
    i = start + 1
    while text[i] != quote:
        if text[i] == "\\":
            out.append(text[i + 1])
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def parse_profiles(dirs: dict[str, Path]) -> tuple[dict[str, dict[str, Any]], str]:
    """(rule metadata by V-ID, the sha256 over the control files) from checkouts of the two InSpec profiles."""
    digest = hashlib.sha256()
    found: dict[str, dict[str, Any]] = {}
    for profile in sorted(dirs):
        for path in sorted((dirs[profile] / "controls").glob("SV-*.rb")):
            raw = path.read_bytes()
            digest.update(f"{profile}/controls/{path.name}\n".encode())
            digest.update(raw)
            text = raw.decode("utf-8")

            def tag(name: str, text: str = text, path: Path = path) -> str:
                m = re.search(rf"tag {name}: '([^']*)'", text)
                if not m:
                    raise CrosswalkError(f"{path} has no {name} tag")
                return m.group(1)

            title_at = re.search(r"^  title ", text, re.MULTILINE)
            if not title_at:
                raise CrosswalkError(f"{path} has no title")
            meta = {
                "rule_id": tag("rid"),
                "stig_id": tag("stig_id"),
                "severity": tag("severity"),
                "title": re.sub(r"\s+", " ", _ruby_string(text, title_at.end())),
            }
            vid = tag("gid")
            if vid in found and {k: found[vid][k] for k in meta} != meta:
                raise CrosswalkError(f"{vid} differs between the two profiles")
            found.setdefault(vid, {**meta, "profiles": []})["profiles"].append(profile)
    return found, digest.hexdigest()


def verify_source(snapshot: dict[str, Any], cluster: Path, node: Path) -> list[str]:
    """Every way the snapshot differs from the two profile checkouts; empty when it matches."""
    found, digest = parse_profiles({"cluster": cluster, "node": node})
    problems: list[str] = []
    pinned = {r["id"]: r for r in snapshot["rules"]}
    for vid in sorted(set(found) - set(pinned)):
        problems.append(f"{vid} is in the profiles and not in the snapshot")
    for vid in sorted(set(pinned) - set(found)):
        problems.append(f"{vid} is in the snapshot and not in the profiles")
    for vid in sorted(set(found) & set(pinned)):
        for key, value in found[vid].items():
            if pinned[vid][key] != value:
                problems.append(f"{vid} {key}: snapshot {pinned[vid][key]!r}, profiles {value!r}")
    if digest != snapshot["source"]["parsed_sha256"]:
        problems.append(
            f"the control files hash to {digest}, not the recorded {snapshot['source']['parsed_sha256']}: these "
            "checkouts are not at the commits in source.parsed_from"
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    ap.add_argument("--check", action="store_true", help="exit 1 when the data is invalid or docs/stig.md is stale")
    ap.add_argument(
        "--verify-source",
        nargs=2,
        type=Path,
        metavar=("CLUSTER_DIR", "NODE_DIR"),
        help="compare the snapshot with checkouts of the two MITRE InSpec profiles it was parsed from",
    )
    try:
        a = ap.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        snapshot = load_snapshot()
        if a.verify_source:
            problems = verify_source(snapshot, *a.verify_source)
            for line in problems:
                print(line, file=sys.stderr)
            if not problems:
                print(f"the snapshot matches the profiles ({len(snapshot['rules'])} rules)")
            return 1 if problems else 0
        rows = load_crosswalk(snapshot)
        text = render(snapshot, rows)
    except CrosswalkError as exc:
        print(f"stig_crosswalk: {exc}", file=sys.stderr)
        return 1
    if a.check:
        if not DOC.is_file() or DOC.read_text(encoding="utf-8") != text:
            print(f"{DOC.name} is stale: run python scripts/stig_crosswalk.py", file=sys.stderr)
            return 1
        src = snapshot["source"]
        counts = Counter(row["status"] for row in rows.values())
        print(
            f"STIG crosswalk is current (Kubernetes STIG V{src['stig_version']}R{src['stig_release']}, "
            f"{len(rows)} rules: " + ", ".join(f"{counts[s]} {s}" for s in STATUSES) + ")"
        )
        return 0
    DOC.write_text(text, encoding="utf-8")
    print(f"wrote {DOC.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
