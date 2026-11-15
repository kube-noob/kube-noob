"""Code findings joined with the images that ship them and the workloads that run them (requirements R4.5-R4.7).

score = base x exposure x privileges, as for image vulnerabilities (``kube_noob.vuln.rank``):

- base: the tool's ``security-severity`` score, else by severity (critical 9.5, high 8.0, medium 5.5, low 2.5,
  info 0.5);
- exposure and privileges: the widest exposure and the largest blast radius among the workloads that run an image
  shipping the file (``kube_noob.attack_paths``); 1 and 1 when no workload in the input runs it.

A file no image ships (tests, docs, tools; or left out by ``.dockerignore``) is listed as not shipped and not ranked:
it is still a finding to fix, but nothing runs it. Without Containerfiles nothing is known about shipping and every
finding is ranked by its base score. A workload runs an image built from a Containerfile when one of its
containers names the same registry and repository (any tag or digest: the code is the same source).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from kube_noob.attack_paths import Reach, Step, ambiguous_notes
from kube_noob.code import deps, ship
from kube_noob.code.sarif import SEVERITY_RANK, CodeFinding, SarifReport
from kube_noob.sanitize import visible
from kube_noob.vuln import reports as vr
from kube_noob.vuln.rank import parse_ref

SEVERITY_BASE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0.5}
FORMULA = "base x exposure x privileges (see kube_noob.code.assess)"


@dataclass
class _Placement:
    reach: Reach
    exposure_kind: str
    exposure: float
    capability: str
    scope: str
    privileges: float


def _place(r: Reach) -> _Placement:
    exp = r.exposure
    caps = r.capabilities
    cap = caps[0] if caps else None
    return _Placement(
        r,
        exp.exposure if exp else "pod network only (no Route, Ingress, NodePort or load balancer selects it)",
        float(exp.weight) if exp else 1.0,
        cap.name if cap else "none found",
        cap.scope if cap else "",
        1.0 + (cap.weight / 10.0 if cap else 0.0),
    )


def same_repository(image: str, container_image: str) -> bool:
    a, b = parse_ref(image), parse_ref(container_image)
    return bool(a.repository) and (a.registry, a.repository) == (b.registry, b.repository)


def _path(f: CodeFinding, image: str, p: _Placement | None) -> dict[str, Any]:
    weakness = f"{', '.join(f'CWE-{c}' for c in f.cwe) or f.rule_id} in {f.location.path}:{f.location.line or '?'}"
    if p is None:
        return {"summary": f"{image} [{weakness}] (not placed: no workload in the input runs this image)", "steps": []}
    r = p.reach
    steps: list[Step] = r.entry_steps() or [
        Step("pod network", r.ref, "reaches", "any pod can connect unless a NetworkPolicy stops it")
    ]
    steps.append(Step(r.ref, f"code execution in {r.ref}", "exploit", f"{weakness} (image {image})"))
    caps = r.capabilities
    if caps:
        cap = caps[0]
        tail = next((t for c, t in r.api if c is cap), None)
        steps.extend(tail if tail is not None else [Step(r.ref, "node", "runs on", cap.evidence)])
    names = [steps[0].source, *(s.target for s in steps)]
    return {"summary": " -> ".join(names), "steps": [s.as_dict() for s in steps]}


def _placements(image: str, reach: dict[str, Reach] | None) -> list[_Placement]:
    out = [_place(r) for r in (reach or {}).values() if any(same_repository(image, c) for c in r.images)]
    out.sort(key=lambda p: (-(p.exposure * p.privileges), p.reach.ref))
    return out


def _rank_row(f: CodeFinding, shipped: list[ship.Shipped], reach: dict[str, Reach] | None) -> dict[str, Any]:
    base = f.score if f.score is not None else SEVERITY_BASE[f.severity]
    best: tuple[_Placement, str] | None = None
    workloads: list[str] = []
    for s in shipped:
        for cand in _placements(s.image, reach):
            workloads.append(cand.reach.ref)
            if best is None or cand.exposure * cand.privileges > best[0].exposure * best[0].privileges:
                best = (cand, s.image)
    image = best[1] if best else (shipped[0].image if shipped else "")
    p = best[0] if best else None
    exposure = p.exposure if p else 1.0
    privileges = p.privileges if p else 1.0
    return {
        "score": round(base * exposure * privileges, 2),
        "finding": f.as_dict(),
        "image": image or None,
        "factors": {
            "base": {"value": base, "from": f.severity_from if f.score is not None else f"severity {f.severity}"},
            "exposure": {"value": exposure, "kind": p.exposure_kind if p else "unknown (not placed)"},
            "privileges": {"value": round(privileges, 2), "capability": p.capability if p else "none found"},
        },
        "workloads": sorted(set(workloads))[:20],
        "workloadsTotal": len(set(workloads)),
        "attackPath": _path(f, image or "no image", p),
    }


def _sca(
    scans: list[vr.ScanReport], builds: list[ship.Build], files: dict[str, str] | None
) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    notes: list[str] = []
    per_image: dict[str, list[vr.Finding]] = {}
    labels: dict[str, vr.ImageInfo] = {}
    for scan in scans:
        label = scan.image.label
        labels.setdefault(label, scan.image)
        per_image.setdefault(label, []).extend(f for f in scan.findings if f.package.ecosystem in deps.MANIFESTS)
    for label, found in per_image.items():
        info = labels[label]
        build = next((b for b in builds if b.image and any(same_repository(b.image, n) for n in info.names)), None)
        for f in vr.merge(found):
            copied: list[tuple[str, int]] = []
            if build is not None:
                for path in f.paths:
                    for repo_path, line in ship.source_of(build, path):
                        if files is None or repo_path in files:
                            copied.append((repo_path, line))
            declared = deps.find(files, f.package.ecosystem, f.package.name, [c for c, _ in copied]) if files else []
            gate = vr.gating_severity(f.severity, f.cvss, f.known_exploited)
            target = next((d for d in declared if d.kind == "manifest"), declared[0] if declared else None)
            action = f"update {f.package.name} from {f.package.version}" + (
                f" to {f.fix_version}" if f.fix_versions else " (no fixed version yet)"
            )
            if target:
                action += f" in {target.file}:{target.line}"
            rows.append(
                {
                    "cve": f.cve,
                    "package": f.package.as_dict(),
                    "fixVersion": f.fix_version or None,
                    "severity": f.severity,
                    "gatingSeverity": gate,
                    "knownExploited": f.known_exploited,
                    "image": label,
                    "imagePaths": list(f.paths[:5]),
                    "copiedFrom": [{"file": c, "line": line} for c, line in dict.fromkeys(copied)],
                    "declaredIn": [d.as_dict() for d in declared],
                    "action": action,
                    "sources": sorted(set(f.sources)),
                }
            )
        if build is None and found:
            notes.append(
                f"{label}: no Containerfile names this image (-c Containerfile=<image>), so lockfiles in the image "
                "are matched to the repository by package name only"
            )
    rows.sort(
        key=lambda r: (
            -int(r["knownExploited"]),
            -vr.SEVERITY_RANK[r["gatingSeverity"]],
            r["fixVersion"] is None,
            r["package"]["name"],
            r["cve"],
        )
    )
    if files is None and rows:
        notes.append("no dependency files given (--context, or dependencyFiles): declarations not looked up")
    return rows, notes


def assess(
    sarifs: list[SarifReport],
    builds: list[ship.Build] | None = None,
    reach: dict[str, Reach] | None = None,
    scans: list[vr.ScanReport] | None = None,
    files: dict[str, str] | None = None,
    top: int = 20,
    include_quality: bool = False,
    exists: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """``exists``: whether a repository-relative path is a file of the repository. With Containerfiles, a finding
    whose path is outside the source root or no repository file has unknown shipping: it is ranked and gated like
    shipped code (fail closed), never filed as "not shipped"."""
    from kube_noob.code.sarif import merge

    builds = builds or []
    raw = [f for s in sarifs for f in s.findings]
    findings = merge(raw)
    excluded = [e for s in sarifs for e in s.excluded]
    quality = [f for s in sarifs for f in s.quality]
    notes = [n for s in sarifs for n in s.notes]
    shipped_rows: list[dict[str, Any]] = []
    not_shipped: list[dict[str, Any]] = []
    unknown = 0
    for f in findings:
        why = ""
        if builds and not f.location.resolved:
            why = "the path is outside the source root (pass --source-root with the directory the scanner ran in)"
        elif builds and exists is not None and not exists(f.location.path):
            why = "no such file in the repository (scan from the repository root, or pass --source-root)"
        shipped = ship.where(builds, f.location.path) if builds and not why else []
        if builds and not shipped and not why:
            not_shipped.append({**f.as_dict(), "shipped": "no image ships this file"})
            continue
        unknown += int(bool(why))
        row = _rank_row(f, shipped, reach)
        if why:
            row["shipped"] = f"unknown: {why}"
        else:
            row["shipped"] = [s.as_dict() for s in shipped] if builds else "unknown (no Containerfiles given)"
        shipped_rows.append(row)
    shipped_rows.sort(
        key=lambda r: (
            -r["score"],
            -SEVERITY_RANK[r["finding"]["severity"]],
            r["finding"]["location"]["path"],
            r["finding"]["location"].get("line", 0),
        )
    )
    for i, r in enumerate(shipped_rows, start=1):
        r["rank"] = i
    sca, sca_notes = _sca(scans or [], builds, files) if scans else ([], [])
    notes += sca_notes
    if builds and not reach:
        notes.append("no manifests given (-m): exposure and privileges are 1; pass the YAML that runs the images")
    images = []
    for b in builds:
        places = _placements(b.image, reach) if b.image else []
        images.append(
            {
                "image": b.label,
                "containerfile": b.containerfile,
                "context": b.context or ".",
                "workloads": [p.reach.ref for p in places][:20],
            }
        )
        if not b.image:
            notes.append(f"{b.containerfile}: no image name given (-c {b.containerfile}=<image>), so it is not placed")
    by_tool: dict[str, int] = {}
    for f in quality:
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
    out: dict[str, Any] = {
        "tools": sorted({t for s in sarifs for t in s.tools}),
        "counts": {
            "results": len(raw) + len(excluded) + len(quality),
            "findings": len(findings),
            "mergedAcrossTools": len(raw) - len(findings),
            "excluded": len(excluded),
            "quality": len(quality),
            "shipped": len(shipped_rows) if builds else None,
            "notShipped": len(not_shipped) if builds else None,
            "shippingUnknown": unknown if builds else None,
            "sca": len(sca),
        },
        "ranking": {
            "formula": FORMULA,
            # A name two different objects carry: each copy is placed with its own images and rights (G273).
            "ambiguous": ambiguous_notes(reach or {}),
            "ranked": shipped_rows[:top],
            "total": len(shipped_rows),
            "bySeverity": {
                sev: sum(1 for r in shipped_rows if r["finding"]["severity"] == sev) for sev in SEVERITY_RANK
            },
        },
        "notShipped": not_shipped,
        "excluded": excluded[:200],
        "quality": {"count": len(quality), "byTool": by_tool},
        "sca": sca,
        "images": images,
        "notes": list(dict.fromkeys(notes)),
    }
    if include_quality:
        out["quality"]["findings"] = [f.as_dict() for f in quality[:500]]
    return out


def failing(out: dict[str, Any], fail_on: str) -> list[str]:
    """Why ``--fail-on`` fails: shipped (or, without Containerfiles, any) security findings at or above it, and
    language-package vulnerabilities that are fixable or known exploited at or above it."""
    if fail_on == "never":
        return []
    floor = SEVERITY_RANK[fail_on]
    code = sum(n for sev, n in out["ranking"]["bySeverity"].items() if SEVERITY_RANK[sev] >= floor)
    sca = [
        r
        for r in out["sca"]
        if vr.SEVERITY_RANK[r["gatingSeverity"]] >= vr.SEVERITY_RANK[fail_on]
        and (r["fixVersion"] or r["knownExploited"])
    ]
    why = []
    if code:
        where = (
            (
                "in shipped code or code whose shipping is not known"
                if out["counts"].get("shippingUnknown")
                else "in shipped code"
            )
            if out["counts"]["shipped"] is not None
            else "(no -c: shipping not known)"
        )
        why.append(f"{code} code finding{'' if code == 1 else 's'} at {fail_on} or above {where}")
    if sca:
        n = len(sca)
        why.append(
            f"{n} dependency vulnerabilit{'y' if n == 1 else 'ies'} at {fail_on} or above that "
            f"{'is' if n == 1 else 'are'} fixable or known exploited"
        )
    return why


def render_text(out: dict[str, Any], top: int = 20) -> str:
    c = out["counts"]
    lines = [
        f"{c['results']} results from {', '.join(out['tools']) or 'no tool'}: {c['findings']} security findings "
        f"({c['mergedAcrossTools']} merged across tools), {c['excluded']} excluded, {c['quality']} lint or quality",
    ]
    if c["shipped"] is not None:
        unknown = f", {c['shippingUnknown']} whose shipping is not known" if c.get("shippingUnknown") else ""
        lines.append(f"{c['shipped']} in shipped code, {c['notShipped']} in files no image ships{unknown}")
    for img in out["images"]:
        where = ", ".join(img["workloads"]) or "no workload in the input"
        lines.append(f"  {img['image']} ({img['containerfile']}, context {img['context']}): runs in {where}")
    lines.extend(f"note: {visible(n)}" for n in out["ranking"].get("ambiguous") or [])
    ranked = out["ranking"]["ranked"][:top]
    if ranked:
        lines.append(f"top {len(ranked)} by reachability ({out['ranking']['formula']}):")
    for r in ranked:
        f = r["finding"]
        loc = f["location"]
        lines.append(
            f"  {r['rank']}. {r['score']} {', '.join(f['cwe']) or f['sources'][0]['ruleId']} "
            f"{loc['path']}:{loc.get('line', '?')} ({f['severity']}; {', '.join(f['tools'])}) {f['title'][:80]}"
        )
        lines.append(f"     path: {r['attackPath']['summary']}")
    if out["notShipped"]:
        lines.append(f"not shipped ({len(out['notShipped'])}): " + ", ".join(x["id"] for x in out["notShipped"][:10]))
    if out["sca"]:
        lines.append(f"dependencies ({len(out['sca'])}):")
        for r in out["sca"][:top]:
            lines.append(f"  {r['cve']} {r['package']['name']} ({r['gatingSeverity']}): {r['action']}")
    for e in out["excluded"][:10]:
        lines.append(f"  excluded {e['finding']['id']}: {e['reason']}")
    lines += [f"note: {n}" for n in out["notes"]]
    return "\n".join(lines)
