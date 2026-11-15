"""One vulnerability assessment from scanner reports and SBOMs: normalise (R5.1), apply VEX (R5.2), rank by
reachability (R5.3).

Reports about the same image (the same digest or image id, or ``--image`` for all of them) are assessed together:
findings from scanner reports are merged, and package facts from every report of the image (an SBOM's source RPM
names, Trivy's ``--list-all-pkgs`` packages) fill in what a scanner report left out. An image with only SBOMs gets
its findings by matching its packages against VEX.
"""

from __future__ import annotations

import dataclasses
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from kube_noob.sanitize import visible
from kube_noob.vuln import rank as ranking
from kube_noob.vuln import vex as vexmod
from kube_noob.vuln.kev import Kev
from kube_noob.vuln.reports import SEVERITIES, Finding, ImageInfo, Package, ScanReport, merge
from kube_noob.vuln.vex import VexIndex

MAX_REPORTS = 50


class AssessError(ValueError):
    """Inputs that cannot be assessed together."""


@dataclass
class _Image:
    info: ImageInfo
    reports: list[ScanReport] = field(default_factory=list)


def _identities(info: ImageInfo, n: int) -> set[str]:
    """What names one image: a manifest digest, an image id, or registry/repository:tag when a tag is written. A
    reference by digest alone says nothing about tags, and an unnamed report is an image of its own."""
    from kube_noob.vuln.rank import parse_ref

    out = {"digest:" + d.rpartition("@")[2] for d in info.digests if "sha256:" in d}
    if info.image_id:
        out.add("id:" + info.image_id)
    for name in info.names:
        r = parse_ref(name)
        if r.digest:
            out.add("digest:" + r.digest)
        elif r.repository and r.tag:
            out.add(f"name:{r.registry}/{r.repository}:{r.tag}")
    return out or {f"report:{n}"}


def _compatible(a: tuple[str, str] | None, b: tuple[str, str] | None) -> bool:
    """Two reports describe one image only if they agree on its distro release (or one does not say)."""
    if a is None or b is None:
        return True
    return a[0] == b[0] and a[1].split(".")[0] == b[1].split(".")[0]


def _group(reports: list[ScanReport], image: str | None) -> list[_Image]:
    """Reports about the same image together: the same digest, image id or registry/repository:tag, and the same
    distro release (or all of them when ``image`` names it)."""
    groups: list[tuple[set[str], _Image]] = []
    for n, r in enumerate(reports):
        if image:
            info = ImageInfo(
                names=[image.split("@")[0]] if not image.startswith("sha256:") else [],
                digests=[image] if "sha256:" in image else [],
            )
            ids = {"forced"}
        else:
            info, ids = r.image, _identities(r.image, n)
        hits = [g for g in groups if g[0] & ids and _compatible(g[1].info.distro, r.image.distro)]
        if hits:
            target = hits[0]
            for other in hits[1:]:  # this report links two groups: join them when they agree on the distro
                if not _compatible(target[1].info.distro, other[1].info.distro):
                    continue
                target[0].update(other[0])
                target[1].reports.extend(other[1].reports)
                _absorb(target[1].info, other[1].info)
                groups.remove(other)
            target[0].update(ids)
        else:
            target = (set(ids), _Image(dataclasses.replace(info, names=list(info.names), digests=list(info.digests))))
            groups.append(target)
        _absorb(target[1].info, r.image)
        target[1].reports.append(r)
    return [g[1] for g in groups]


def _absorb(into: ImageInfo, other: ImageInfo) -> None:
    for n in other.names:
        if n not in into.names:
            into.names.append(n)
    for d in other.digests:
        if d not in into.digests:
            into.digests.append(d)
    into.image_id = into.image_id or other.image_id
    into.distro = into.distro or other.distro


def _with_sources(findings: list[Finding], packages: list[Package]) -> list[Finding]:
    sources = {p.key: p.source for p in packages if p.source}
    out: list[Finding] = []
    for f in findings:
        src = sources.get(f.package.key)
        if src and not f.package.source:
            out.append(dataclasses.replace(f, package=dataclasses.replace(f.package, source=src)))
        else:
            out.append(f)
    return out


def assess(
    reports: list[ScanReport],
    *,
    vex: VexIndex | None = None,
    kev: Kev | None = None,
    reach: dict[str, Any] | None = None,
    products: tuple[str, ...] = (),
    image: str | None = None,
    top: int = 50,
    trust_report_vex: bool = False,
) -> dict[str, Any]:
    """``trust_report_vex``: honour a CycloneDX report's own analysis (not_affected, resolved, false_positive); by
    default those findings stay, with the report's claim in their notes."""
    if not reports:
        raise AssessError("give at least one scanner report or SBOM")
    if len(reports) > MAX_REPORTS:
        raise AssessError(f"more than {MAX_REPORTS} reports")
    try:
        products = vexmod.validate_products(products)
    except vexmod.VexError as exc:
        raise AssessError(str(exc)) from exc
    index = vex or VexIndex()
    images_out: list[dict[str, Any]] = []
    all_kept: list[tuple[ImageInfo, list[Finding]]] = []
    excluded: list[dict[str, Any]] = []
    notes: list[str] = []
    reported = 0
    for img in _group(reports, image):
        packages = [p for r in img.reports for p in r.packages]
        scanner = [f for r in img.reports if not r.sbom for f in r.findings]
        prefixes = products or vexmod.rhel_products(img.info.distro)
        own = [x for r in img.reports for x in r.own_vex]
        own_excluded: list[dict[str, Any]] = []
        if trust_report_vex and own:
            drop = {tuple(x["key"]) for x in own}
            scanner = [f for f in scanner if f.key not in drop]
            own_excluded = [{k: v for k, v in x.items() if k != "key"} for x in own]
        if any(not r.sbom for r in img.reports):
            findings = merge(_with_sources(scanner, packages))
            applied = vexmod.apply(findings, index, prefixes) if index.by_cve else None
            if applied is None:
                kept, img_excluded = findings, []
                img_notes = ["no VEX statements loaded (run kube-noob corpus advisories, or pass --vex)"]
                outside = unmatched = 0
            else:
                kept, img_excluded = applied.kept, applied.excluded
                img_notes, outside, unmatched = applied.notes, applied.outside, applied.unmatched
            if any(r.sbom for r in img.reports):
                img_notes.append("scanner findings used; the SBOMs added package facts only")
        else:
            if not index.by_cve:
                raise AssessError(
                    f"{img.info.label}: an SBOM has packages, not findings; matching them needs Red Hat VEX "
                    "statements (kube-noob corpus advisories, or --vex)"
                )
            applied = vexmod.match_packages(packages, index, prefixes)
            kept, img_excluded = merge(applied.kept), applied.excluded
            img_notes, outside, unmatched = applied.notes, applied.outside, 0
            if outside:
                img_notes.append(
                    f"{outside} packages are not Red Hat RPMs: SBOM matching reads Red Hat VEX only, so they were not "
                    "checked (give a scanner report for language packages)"
                )
        if own and not trust_report_vex:
            img_notes.append(
                f"{len(own)} findings the report's own analysis marks not affected or resolved are kept: pass "
                "--trust-report-vex to accept the report's VEX"
            )
        n_reported = len(kept) + len(img_excluded) + len(own_excluded)
        reported += n_reported
        img_excluded = [*own_excluded, *img_excluded]
        for x in img_excluded:
            x["image"] = img.info.label
        excluded.extend(img_excluded)
        all_kept.append((img.info, kept))
        images_out.append(
            {
                "image": img.info.as_dict(),
                "formats": sorted({r.format for r in img.reports}),
                "vexProducts": list(prefixes),
                "reported": n_reported,
                "findings": len(kept),
                "excludedByVex": len(img_excluded),
                "outsideVex": outside,
                "noStatement": unmatched,
                "notes": sorted(set(img_notes + [n for r in img.reports for n in r.notes])),
            }
        )
    kev_hits = 0
    rows: list[dict[str, Any]] = []
    for info, kept in all_kept:
        for f in kept:
            if kev is not None and kev.get(f.cve) is not None:
                f.known_exploited = True
                kev_hits += 1
            rows.append({**f.as_dict(), "image": info.label})
    ranked = ranking.rank(all_kept, reach, kev, top=top)
    by_sev = Counter(r["severity"] for r in rows)
    return {
        "images": images_out,
        "counts": {
            "reported": reported,
            "findings": len(rows),
            "excludedByVex": len(excluded),
            "bySeverity": {s: by_sev.get(s, 0) for s in SEVERITIES},
            "fixable": sum(1 for r in rows if r["fixVersion"]),
            "knownExploited": sum(1 for r in rows if r["knownExploited"]),
        },
        "findings": rows,
        "excluded": excluded,
        "vex": {"sources": index.origins, "documents": index.documents, "cves": len(index.by_cve)},
        "kev": {"catalog": kev.describe() if kev else "no KEV catalog given (--kev)", "matched": kev_hits},
        "ranking": ranked,
        "notes": notes,
    }


def summary_for_workloads(out: dict[str, Any]) -> dict[str, str]:
    """Per workload ref: a one-line summary of its fixable critical or high findings and exploited ones, or "" when
    there are none (the threat model's TM-E01 status)."""
    result: dict[str, str] = {}
    for ref, c in out["ranking"]["workloads"].items():
        n = c["fixableHighOrExploited"]
        result[ref] = f"{n} fixable critical/high or exploited finding(s) in its images" if n else ""
    return result


def render_text(out: dict[str, Any], top: int = 10) -> str:
    c = out["counts"]
    lines = [
        f"{c['reported']} reported, {c['excludedByVex']} excluded by VEX, {c['findings']} findings "
        f"({', '.join(f'{v} {k}' for k, v in c['bySeverity'].items() if v)}); {c['fixable']} fixable, "
        f"{c['knownExploited']} known exploited",
    ]
    for img in out["images"]:
        lines.append(
            f"  {img['image']['name']} [{', '.join(img['formats'])}]: {img['findings']} findings, "
            f"{img['excludedByVex']} excluded by VEX, {img['outsideVex']} outside VEX"
        )
        lines.extend(f"    note: {n}" for n in img["notes"])
    lines.append(f"VEX: {'; '.join(out['vex']['sources']) or 'none loaded'}. KEV: {out['kev']['catalog']}.")
    lines.extend(f"note: {visible(n)}" for n in out["ranking"].get("ambiguous") or [])
    ranked = out["ranking"]["ranked"][:top]
    if ranked:
        lines.append(f"top {len(ranked)} by reachability ({out['ranking']['formula']}):")
    for r in ranked:
        f = r["finding"]
        fx = r["factors"]
        lines.append(
            f"  {r['rank']}. {r['score']:.1f} {f['cve']} {f['package']['name']} {f['package']['version']} "
            f"-> {f['fixVersion'] or 'no fix'} ({f['severity']}; base {fx['base']['value']} x exposure "
            f"{fx['exposure']['value']:g} x privileges {fx['privileges']['value']:g} x exploited "
            f"{fx['exploited']['value']:g})"
        )
        lines.append(f"     path: {r['attackPath']['summary']}")
    for x in out["excluded"][:top]:
        f = x["finding"]
        lines.append(f"  excluded: {f['cve']} {f['package']['name']} {f['package']['version']}: {x['reason']}")
    if len(out["excluded"]) > top:
        lines.append(f"  ... and {len(out['excluded']) - top} more excluded (see --format json)")
    return "\n".join(lines) + "\n"
