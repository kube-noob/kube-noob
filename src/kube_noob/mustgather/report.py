"""Must-gather report and support-case draft (backlog G3).

``build`` joins what ingest read (``Bundle``) and what the analysers found (``Analysis``) with what kube-noob knows:
known issues from the bundled OpenShift release notes (and the local Jira cache when there is one) matched to each
finding for the detected version, and approved entries from the team's memory repositories. ``markdown`` and
``case_draft`` render it. Everything is offline.

Rules: nothing is invented. The case draft carries only what the must-gather and the indexes say; everything a person
must supply (what users see, when it started, impact, what was tried) is a ``[FILL IN: ...]`` placeholder. Every
string passes ``redact_text`` once more on the way out; the must-gather's own path is reduced to its file name.
"""

from __future__ import annotations

import posixpath
from collections.abc import Callable
from pathlib import Path
from typing import Any

from kube_noob import __version__
from kube_noob.debug.cluster import redact_text
from kube_noob.mustgather.analyse import SEVERITIES, Analysis, has_clusterversion
from kube_noob.mustgather.ingest import GATHER_DIRS, Bundle
from kube_noob.operator_issues import Surface

MAX_MATCHED_FINDINGS = 20  # findings sent to known-issue and memory matching (the most severe first)
MAX_NEXT_STEPS = 15
FILL = "[FILL IN: {}]"

MatchKnown = Callable[[str, str, str | None], dict[str, Any]]
MatchMemory = Callable[[str, str | None, str | None, list[str]], dict[str, Any]]


def _known(text: str, platform: str, version: str | None, data_dir: Path | None = None) -> dict[str, Any]:
    from kube_noob import known_issues

    return known_issues.match(text, platform, version, 3, data_dir)


def _nd_ops(o: dict[str, Any]) -> str:
    from kube_noob.mustgather.analyse import OPERATOR_ND, not_determined_text

    return not_determined_text(o, OPERATOR_ND)


def okd_of(cluster: dict[str, Any]) -> str | None:
    """The OKD version the analysers' ClusterVersion holds, through the same reading ``operators issues
    --must-gather`` uses (``operator_issues.must_gather_release``), else None."""
    from kube_noob import operator_issues

    return operator_issues.okd_version(operator_issues.must_gather_release(cluster))


def okd_note(version: str) -> str:
    from kube_noob import operator_issues

    return operator_issues.okd_note(version)


def _query(f: dict[str, Any]) -> str:
    """The text a finding is matched by: its words and the names of its signals (alert names are words the
    catalogue and the release notes share)."""
    parts = [f["title"], f.get("reason", ""), f.get("message", ""), f.get("detail", {}).get("logHint", "")]
    parts += [s.split(":", 1)[1] for s in f.get("signals", [])]
    return ". ".join(p for p in parts if p)


def build(
    bundle: Bundle,
    analysis: Analysis,
    *,
    data_dir: Path | None = None,
    memory_dirs: list[Path] | None = None,
    match_known: MatchKnown | None = None,
    match_memory: MatchMemory | None = None,
    generated_by: str = f"kube-noob {__version__}",
    surface: Surface = "must-gather",
    inventory: dict[str, Any] | None = None,
    operator_issues: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The report as a dict (``report.json``).

    The operator inventory and the operator release-note lookup are computed here when not given, because
    ``completeness`` is the fold of every leg (G285) and the report has to carry the legs it folds; ``surface`` words
    their hints for where they are read (``operator_issues.Surface``)."""
    a = analysis.as_dict()
    cluster = a["cluster"]
    version = cluster.get("version") or None
    okd = okd_of(cluster)
    # a ClusterVersion makes it OpenShift even when none is named version or none holds a readable version; an OKD
    # one makes it OKD, decided as `operators issues --must-gather` decides it
    platform = "okd" if okd else "openshift" if cluster.get("version") or has_clusterversion(cluster) else "kubernetes"
    note: str | None
    if okd:
        verdict, note = "not-determined", f"{okd_note(okd)}, so no finding was matched against them"
    elif platform == "kubernetes":
        verdict, note = (
            "not-applicable",
            "the index holds OpenShift release-note issues; they do not apply to plain Kubernetes",
        )
    else:
        # The one coverage verdict the gate uses (G284): a release the index does not cover is not-evaluated,
        # never looked-up by default (round 1, 2). Mid-update, the running release is what is searched and the
        # note says the target was not, which the completeness leg reads as partial.
        from kube_noob.known_issues import release_coverage

        verdict, note, _minor = release_coverage(
            "openshift", version, data_dir, hint="the must-gather's ClusterVersion names none; the newest indexed is"
        )
        desired = cluster.get("desiredVersion")
        if verdict == "looked-up" and desired and version and desired != version:
            note = f"{note}; the running release {version} was searched and the update target {desired} was not"
    operators = [o["name"] for o in cluster.get("operators", [])]
    roots = bundle.as_dict()["gatherRoots"]
    findings = [{"rank": n, **f} for n, f in enumerate(a["findings"], start=1)]

    def known(text: str) -> dict[str, Any]:
        if okd or verdict == "not-evaluated":
            # the notes do not describe OKD's builds, or the release is outside the index: what the index is, but
            # nothing matched against it (a match across every release would be a search of the wrong release)
            return {"knowledge": _known("", "openshift", None, data_dir)["knowledge"] if match_known is None else {}}
        if match_known is not None:
            return match_known(text, platform, version)
        return _known(text, platform, version, data_dir)

    issues: dict[str, dict[str, Any]] = {}
    knowledge: dict[str, Any] = {}
    memory: dict[str, dict[str, Any]] = {}
    memory_notes: list[str] = []
    for f in [x for x in findings if x["severity"] in {"critical", "high", "medium"}][:MAX_MATCHED_FINDINGS]:
        q = _query(f)
        found = known(q)
        knowledge = knowledge or found.get("knowledge", {})
        for m in found.get("matches", []):
            entry = issues.setdefault(m["id"], {**{k: m[k] for k in _ISSUE_KEYS if k in m}, "findings": []})
            entry["findings"].append(f["rank"])
            f.setdefault("knownIssues", []).append(m["id"])
        if memory_dirs or match_memory is not None:
            got = (
                match_memory(q, version, platform, operators)
                if match_memory is not None
                else _memory(memory_dirs or [], q, version, platform)
            )
            memory_notes += got.get("notes", [])
            for m in got.get("matches", []):
                entry = memory.setdefault(m["id"], {**m, "findings": []})
                entry["findings"].append(f["rank"])
                f.setdefault("memory", []).append(m["id"])
    if not knowledge:
        knowledge = known("")["knowledge"] if match_known is None else {}
    steps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        for c in f["next"]:
            if c not in seen and len(steps) < MAX_NEXT_STEPS:
                seen.add(c)
                steps.append({"command": c, "label": "read-only", "for": f["rank"]})
    if inventory is None or operator_issues is None:
        from kube_noob import operator_issues as op_issues_mod
        from kube_noob import operators as ops_mod
        from kube_noob.mustgather import operators as mg_operators

        olm = mg_operators.collect(bundle)
        if inventory is None:
            inventory = ops_mod.inventory(olm)
        if operator_issues is None:
            operator_issues = op_issues_mod.for_must_gather(olm, cluster, surface=surface, data_dir=data_dir)
    from kube_noob.mustgather import completeness as mg_completeness

    head: dict[str, Any] = {
        "knownIssuesVerdict": verdict,
        "knownIssuesNote": note,
        "cluster": cluster,
    }
    return {
        "generatedBy": generated_by,
        "source": posixpath.basename(bundle.source.rstrip("/")) or "must-gather",
        "collected": next((r["timestamp"] for r in roots if r["timestamp"]), ""),
        "gatherImages": [r["version"] or "no version file" for r in roots],
        "platform": platform,
        "cluster": cluster,
        "counts": a["counts"],
        "findings": findings,
        "knownIssues": sorted(issues.values(), key=lambda m: (min(m["findings"]), m["id"])),
        "knownIssuesVerdict": verdict,
        "knownIssuesNote": note,
        "memory": sorted(memory.values(), key=lambda m: (min(m["findings"]), m["id"])),
        "memoryNotes": list(dict.fromkeys(memory_notes)),
        "nextSteps": steps,
        "coverage": a["coverage"],
        "completeness": mg_completeness.fold(analysis, bundle, inventory, operator_issues, head),
        "unparsed": a["unparsed"],
        "conflicts": a["conflicts"],
        "duplicates": a["duplicates"],
        "skipped": bundle.as_dict()["skipped"],
        "signals": a["signals"],
        "knowledge": knowledge,
        "operatorInventory": inventory,
        "operatorKnownIssues": operator_issues,
    }


_ISSUE_KEYS = ("id", "url", "kind", "foundIn", "fixedIn", "status", "summary", "workaround", "source", "ticket")


def _memory(dirs: list[Path], text: str, version: str | None, platform: str | None) -> dict[str, Any]:
    from kube_noob.memory.match import for_answers

    return for_answers(dirs, text, version, platform)


# --------------------------------------------------------------------------------------------------- rendering ----


def _md(text: Any) -> str:
    """A value for one Markdown line or cell: redacted, no line breaks, pipes and backticks escaped."""
    s = redact_text(" ".join(str(text if text is not None else "").split()))
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def _short(path: str) -> str:
    """A must-gather path from its gather root down (``cluster-scoped-resources/...``, ``namespaces/...``): the
    ``must-gather.local.*`` and image directories above it are the same for every file."""
    parts = path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part in GATHER_DIRS:
            return "/".join(parts[i:])
    return path


def _environment(r: dict[str, Any]) -> list[str]:
    c = r["cluster"]
    out = []
    if c.get("version"):
        update = ""
        if c.get("desiredVersion") and c["desiredVersion"] != c["version"]:
            state = next((h["state"] for h in c.get("history", []) if h["version"] == c["desiredVersion"]), "")
            update = f"; update to {_md(c['desiredVersion'])}" + (f" ({_md(state)})" if state else "")
        channel = f" (channel {_md(c['channel'])})" if c.get("channel") else ""
        product = "OKD" if r.get("platform") == "okd" else "OpenShift Container Platform"
        out.append(f"- {product} {_md(c['version'])}{channel}{update}")
    elif c.get("clusterVersionNote"):
        out.append(f"- Version: not determined: {_md(c['clusterVersionNote'])}")
    elif r.get("platform") == "openshift":
        out.append("- Version: not determined: the ClusterVersion named version holds no version this reads")
    else:
        out.append("- Version: not in this must-gather (no ClusterVersion collected)")
    if c.get("platform"):
        topo = f", control plane topology {_md(c['controlPlaneTopology'])}" if c.get("controlPlaneTopology") else ""
        out.append(f"- Platform: {_md(c['platform'])}{topo}")
    n = c.get("nodes")
    if n:
        from kube_noob.mustgather.analyse import NODE_ND, not_determined_text

        control = f"{n.get('controlPlane', 0)} control plane"
        if n.get("controlPlaneNotDetermined"):
            control += f", {n['controlPlaneNotDetermined']} control plane not determined"
        out.append(
            f"- Nodes: {n['total']} ({control}), {n.get('ready', 0)} Ready" + not_determined_text(n, NODE_ND[:1])
        )
    o = c.get("clusterOperators")
    if o:
        out.append(
            f"- Cluster operators: {o['total']}, {o.get('available', 0)} Available, {o.get('degraded', 0)} Degraded"
            + _nd_ops(o)
        )
    ops = c.get("operators")
    if ops:
        shown = ", ".join(f"{_md(x['name'])} ({_md(x['phase'] or 'no phase')})" for x in ops[:20])
        more = f" and {len(ops) - 20} more" if len(ops) > 20 else ""
        out.append(f"- Operators installed with OLM: {shown}{more}")
    out.append(f"- Must-gather `{_md(r['source'])}`, collected {_md(r['collected']) or 'at an unknown time'}")
    if r["gatherImages"]:
        out.append(f"- Gather images: {', '.join(_md(g) for g in r['gatherImages'])}")
    return out


def _knowledge_line(r: dict[str, Any]) -> str:
    k = r["knowledge"]
    if not k.get("knownIssuesAsOf"):
        return "Known issues: no index available."
    releases = ", ".join(k.get("openshiftReleases", []))
    jira = " and the local Jira cache" if k.get("jiraTickets") else ""
    line = f"Known issues from the OpenShift {releases} release notes{jira}, as of {_md(k['knownIssuesAsOf'])}."
    if k.get("recordsRejected"):
        line += f" {k['recordsRejected']} record(s) of the index were unusable and left out."
    if k.get("localCopyNote"):
        line += f" {_md(str(k['localCopyNote']))}."
    return line


def markdown(r: dict[str, Any]) -> str:
    c, counts = r["cluster"], r["counts"]
    if c.get("version"):
        title = f"{'OKD' if r.get('platform') == 'okd' else 'OpenShift'} {c['version']}"
    elif r.get("platform") == "openshift":
        title = "an OpenShift cluster (version not determined)"
    else:
        title = "a Kubernetes cluster"
    if c.get("platform"):
        title += f" on {c['platform']}"
    lines = [
        f"# Must-gather report: {_md(title)}",
        "",
        f"Written offline by {_md(r['generatedBy'])} from `{_md(r['source'])}`. {_knowledge_line(r)}",
        "",
        "## Summary",
        "",
        *_environment(r),
        "- Findings: " + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES),
    ]
    top = [f for f in r["findings"] if f["severity"] in {"critical", "high"}][:5]
    if top:
        lines += ["", "Most severe:", ""]
        lines += [f"{f['rank']}. {f['severity'].upper()}: {_md(f['title'])}" for f in top]
    lines += ["", "## Findings", "", "| # | Severity | Area | Finding | Known issues |", "|---|---|---|---|---|"]
    for f in r["findings"]:
        ki = ", ".join(f.get("knownIssues", [])) or ""
        lines.append(f"| {f['rank']} | {f['severity']} | {f['analyser']} | {_md(f['title'])} | {ki} |")
    for f in r["findings"]:
        lines += ["", f"### {f['rank']}. {_md(f['title'])}", ""]
        lines.append(f"- Severity: {f['severity']} ({f['analyser']}{', platform' if f.get('platform') else ''})")
        if f.get("reason"):
            lines.append(f"- Reason: {_md(f['reason'])}")
        if f.get("message"):
            lines.append(f"- Message: {_md(f['message'])}")
        hint = f.get("detail", {}).get("logHint")
        if hint:
            lines.append(f"- Last error in the log: {_md(hint)}")
        if f["signals"]:
            lines.append(f"- Signals: {', '.join(_md(s) for s in f['signals'])}")
        if f.get("memory"):
            lines.append(f"- Team memory: {', '.join(f'[mem:{_md(m)}]' for m in f['memory'])}")
        lines.append(f"- Evidence: {', '.join(f'`{_md(_short(e))}`' for e in f['evidence'])}")
        if f["next"]:
            lines += ["", "```bash", *f["next"], "```"]
    lines += ["", "## Known issues that match", ""]
    if r["knownIssues"]:
        version = c.get("version") or "this version"
        lines += [f"| Issue | Status for {_md(version)} | Fixed in | Findings | Summary |", "|---|---|---|---|---|"]
        for m in r["knownIssues"]:
            ref = f"[{_md(m['id'])}]({m['url']})" if m.get("url") else _md(m["id"])
            found = ", ".join(str(n) for n in m["findings"])
            lines.append(
                f"| {ref} | {_md(m.get('status') or '')} | {_md(m.get('fixedIn') or 'not yet')} | {found} | "
                f"{_md(m.get('summary') or '')} |"
            )
    elif r.get("knownIssuesVerdict") == "not-determined":
        lines.append(f"Not determined: {_md(r['knownIssuesNote'])}. {_knowledge_line(r)}")
    else:
        lines.append(f"None of the findings matches a known issue. {_knowledge_line(r)}")
    if r["memory"] or r["memoryNotes"]:
        lines += ["", "## From your team's memory", ""]
        for m in r["memory"]:
            found = ", ".join(str(n) for n in m["findings"])
            lines.append(f"- [mem:{_md(m['id'])}] {_md(m.get('symptom', ''))} (findings {found})")
        lines += [f"- Note: {_md(n)}" for n in r["memoryNotes"]]
    if r["nextSteps"]:
        lines += ["", "## Read-only next steps", "", "Run these on the live cluster to confirm, most severe first:", ""]
        lines += ["```bash", *(s["command"] for s in r["nextSteps"]), "```"]
    lines += ["", "## What was read", "", "| Area | Files | Objects | Findings | Note |", "|---|---|---|---|---|"]
    for cov in r["coverage"]:
        note = cov.get("note", "") + (f" ({cov['notShown']} more not shown)" if cov.get("notShown") else "")
        lines.append(f"| {cov['analyser']} | {cov['files']} | {cov['objects']} | {cov['findings']} | {_md(note)} |")
    extra = [f"- Skipped {s['count']}: {_md(s['reason'])}" for s in r["skipped"]]
    extra += [f"- Not read: `{_md(u['path'])}` ({_md(u['reason'])})" for u in r["unparsed"][:20]]
    for c in (r.get("conflicts") or [])[:20]:
        where = ", ".join(f"`{_md(p)}`" for p in c["paths"][:3])
        differs = _md(", ".join(c["differs"][:4]) or "content")
        extra.append(
            f"- Conflict: {_md(c['object'])} was collected twice with different content ({where}; differs: "
            f"{differs}): those fields are not determined, the rest are read"
        )
    if r.get("duplicates"):
        extra.append(
            f"- Duplicates: {len(r['duplicates'])} object(s) collected twice with identical content, read once"
        )
    c = r.get("completeness") or {}
    if c.get("legs"):
        # One line, every leg: the table above is the analysers' view only, and "complete" has to mean every leg
        # (the operator inventory, the release-note lookups and the skipped files included), as the exit code does.
        partial = [leg for leg in c["legs"] if leg["state"] == "partial"]
        if partial:
            extra.append(
                "- Evidence is partial: " + "; ".join(f"{_md(leg['leg'])}: {_md(leg['why'])}" for leg in partial)
            )
        else:
            read = [leg["leg"] for leg in c["legs"] if leg["state"] == "complete"]
            apart = [leg["leg"] for leg in c["legs"] if leg["state"] == "not-applicable"]
            line = (
                "- Evidence is complete: every leg read what it set out to read ("
                + ", ".join(_md(x) for x in read)
                + ")"
            )
            if apart:
                line += "; not applicable here: " + ", ".join(_md(x) for x in apart)
            extra.append(line)
    if extra:
        lines += ["", *extra]
    if r["signals"]:
        lines += ["", "## Signals", "", ", ".join(f"{_md(s['kind'])}:{_md(s['name'])}" for s in r["signals"])]
    return "\n".join(lines) + "\n"


def case_draft(r: dict[str, Any]) -> str:
    """A support case draft: the facts the must-gather holds, and placeholders for everything it cannot know."""
    c = r["cluster"]
    lines = [
        "# Support case draft",
        "",
        "> Written by kube-noob from a must-gather. Replace every [FILL IN: ...] before you submit. Everything else "
        "comes from the must-gather or the bundled indexes; check it.",
        "",
        "## Problem statement",
        "",
        FILL.format("what is not working, as your users see it, in one or two sentences"),
        "",
        "What the must-gather shows:",
        "",
    ]
    top = [f for f in r["findings"] if f["severity"] != "info"][:5]
    lines += [f"- {f['severity'].upper()}: {_md(f['title'])}" for f in top] or ["- No problem found by kube-noob."]
    lines += ["", "## Environment", "", *_environment(r), "", "## Timeline", ""]
    lines += [
        f"- {FILL.format('when it started (date, time and time zone)')}",
        f"- {FILL.format('what changed before it started: an update, a configuration change, a new workload')}",
    ]
    for h in c.get("history", [])[:3]:
        started = f", started {_md(h['startedTime'])}" if h.get("startedTime") else ""
        done = f", completed {_md(h['completionTime'])}" if h.get("completionTime") else ""
        lines.append(f"- Update to {_md(h['version'])}: {_md(h['state'])}{started}{done} (ClusterVersion history)")
    lines.append(f"- Must-gather collected: {_md(r['collected']) or FILL.format('when it was collected')}")
    lines += ["", "## Frequency", "", FILL.format("constant, intermittent or once; how often and since when"), ""]
    worst = next((f["severity"] for f in r["findings"] if f["severity"] != "info"), "")
    lines += ["## Business impact", "", FILL.format("who is affected, production or not, any workaround in place")]
    if worst:
        lines.append(f"\nThe most severe finding is {worst}; {FILL.format('the case severity you choose, and why')}")
    lines += ["", "## Evidence", "", f"- The must-gather: `{_md(r['source'])}` (attach it to the case)"]
    for f in r["findings"][:15]:
        files = ", ".join(f"`{_md(_short(e))}`" for e in f["evidence"][:2])
        lines.append(f"- {f['rank']}. {f['severity']}: {_md(f['title'])}: {files}")
    # The draft says what the evidence could not settle, as the report does (round 1, 13): a conflict or a partial
    # leg copied into a case without this line reads as a complete read of the cluster.
    for c in (r.get("conflicts") or [])[:10]:
        lines.append(
            f"- Conflict: {_md(c['object'])} was collected twice with different content (differs: "
            f"{_md(', '.join(c.get('differs') or []) or 'content')}); those fields are not determined"
        )
    comp = r.get("completeness") or {}
    partial_legs = [leg for leg in comp.get("legs") or [] if leg.get("state") == "partial"]
    if partial_legs:
        lines.append(
            "- Evidence is partial: " + "; ".join(f"{_md(leg['leg'])}: {_md(leg['why'])}" for leg in partial_legs)
        )
    lines += ["", "## Matched known issues and bugs", ""]
    if r["knownIssues"]:
        for m in r["knownIssues"]:
            fixed = f", fixed in {_md(m['fixedIn'])}" if m.get("fixedIn") else ""
            lines.append(
                f"- {_md(m['id'])}: {_md(m.get('summary') or '')} ({_md(m.get('status') or '')}{fixed}; matches "
                f"finding {', '.join(str(n) for n in m['findings'])})"
            )
    elif r.get("knownIssuesVerdict") == "not-determined":
        lines.append(f"- Not determined: {_md(r['knownIssuesNote'])}. {_knowledge_line(r)}")
    else:
        lines.append(f"- None matched. {_knowledge_line(r)}")
    lines += ["", "## Steps already taken", "", FILL.format("what you tried and what happened"), ""]
    if r["nextSteps"]:
        lines += ["Read-only checks kube-noob suggests running first (paste their output into the case):", ""]
        lines += ["```bash", *(s["command"] for s in r["nextSteps"][:10]), "```"]
    return "\n".join(lines) + "\n"


def write(r: dict[str, Any], out_dir: Path, *, draft: bool) -> list[Path]:
    """``report.md`` and ``report.json`` (and ``case-draft.md``) in ``out_dir``; returns the files written."""
    import json

    if out_dir.exists() and not out_dir.is_dir():
        raise ValueError(f"{out_dir}: exists and is not a directory")
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {"report.md": markdown(r), "report.json": json.dumps(r, indent=1, ensure_ascii=False) + "\n"}
    if draft:
        files["case-draft.md"] = case_draft(r)
    written = []
    for name, text in files.items():
        path = out_dir / name
        if path.is_symlink():
            raise ValueError(f"{path}: a symbolic link; not written")
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written
