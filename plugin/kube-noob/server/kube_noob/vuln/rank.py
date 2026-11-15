"""Rank findings by reachability (requirements R5.3): exposure, privileges and RBAC reach from the attack-path model,
and known exploitation, multiply the base score. Each ranked finding shows its attack path.

score = base x exposure x privileges x exploited, where

- base: the report's CVSS base score, else by severity (critical 9.5, high 8.0, medium 5.5, low 2.5, negligible 0.5,
  unknown 5.0);
- exposure: the widest exposure that selects a workload running the image (``kube_noob.attack_paths``): internet
  (Route, Ingress, public load balancer) 3, node network or a load balancer limited by source ranges 2, internal
  only 1;
- privileges: 1 + the largest blast radius (1-10) of what code in that workload's pods can do, on the node or
  through its ServiceAccount's RBAC, divided by 10 (1.0-2.0);
- exploited: 2 when the CVE is in the CISA KEV catalog or a report marks it as exploited (Grype's known-exploited,
  RHACS's CISA KEV flag), else 1.

Without manifests the exposure and privileges factors are 1 and the output says the image was not placed. An image
runs in a workload when one of its containers references it by digest, or by registry, repository and tag (Docker
Hub names normalised: ``nginx`` is ``docker.io/library/nginx:latest``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from kube_noob.attack_paths import Capability, Reach, Step, ambiguous_notes
from kube_noob.vuln.kev import Kev
from kube_noob.vuln.reports import Finding, ImageInfo, gating_severity

SEVERITY_BASE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "negligible": 0.5, "unknown": 5.0}
KEV_FACTOR = 2.0
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ImageRef:
    registry: str
    repository: str
    tag: str
    digest: str


def parse_ref(text: str) -> ImageRef:
    """``[registry/]repository[:tag][@sha256:...]``; a bare digest has no repository."""
    ref = text.strip()
    if _DIGEST.match(ref):
        return ImageRef("", "", "", ref)
    name, _, digest = ref.partition("@")
    digest = digest if _DIGEST.match(digest) else ""
    tag = ""
    slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > slash:
        name, tag = name[:colon], name[colon + 1 :]
    parts = name.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", name
    if registry in {"docker.io", "index.docker.io", "registry-1.docker.io"}:
        registry = "docker.io"
        if "/" not in repo:
            repo = f"library/{repo}"
    return ImageRef(registry.lower(), repo, tag, digest)


def same_image(image: ImageInfo, container_image: str) -> bool:
    c = parse_ref(container_image)
    for d in image.digests:
        r = parse_ref(d)
        if c.digest and r.digest == c.digest and (not r.repository or r.repository == c.repository):
            return True
    if c.digest:
        return False
    for n in image.names:
        r = parse_ref(n)
        if r.repository and (r.registry, r.repository, r.tag or "latest") == (
            c.registry,
            c.repository,
            c.tag or "latest",
        ):
            return True
    return False


@dataclass
class Placement:
    reach: Reach
    exposure_kind: str
    exposure_factor: float
    capability: Capability | None
    privileges_factor: float

    @property
    def factor(self) -> float:
        return self.exposure_factor * self.privileges_factor


def _placement(r: Reach) -> Placement:
    exp = r.exposure
    caps = r.capabilities
    cap = caps[0] if caps else None
    return Placement(
        r,
        exp.exposure if exp else "pod network only (no Route, Ingress, NodePort or load balancer selects it)",
        float(exp.weight) if exp else 1.0,
        cap,
        1.0 + (cap.weight / 10.0 if cap else 0.0),
    )


def _path(f: Finding, image: ImageInfo, p: Placement | None) -> dict[str, Any]:
    exploit = f"{f.cve} in {f.package.name} {f.package.version}"
    if p is None:
        return {
            "summary": f"{image.label} [{exploit}] (not placed: no workload in the input runs this image)",
            "steps": [],
        }
    r = p.reach
    steps: list[Step] = r.entry_steps() or [
        Step("pod network", r.ref, "reaches", "any pod can connect unless a NetworkPolicy stops it")
    ]
    steps.append(Step(r.ref, f"code execution in {r.ref}", "exploit", f"{exploit} (image {image.label})"))
    if p.capability is not None:
        cap = p.capability
        api = next((tail for c, tail in r.api if c is cap), None)
        if api is not None:
            steps.extend(api)
        else:
            steps.append(Step(r.ref, "node", "runs on", cap.evidence))
    names = [steps[0].source, *(s.target for s in steps)]
    return {"summary": " -> ".join(names), "steps": [s.as_dict() for s in steps]}


def rank(
    per_image: list[tuple[ImageInfo, list[Finding]]],
    reach: dict[str, Reach] | None,
    kev: Kev | None,
    top: int = 50,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    per_workload: dict[str, dict[str, int]] = {}
    placed_images = 0
    for image, findings in per_image:
        placements = [_placement(r) for r in (reach or {}).values() if any(same_image(image, c) for c in r.images)]
        placements.sort(key=lambda p: (-p.factor, p.reach.ref))
        if placements:
            placed_images += 1
        best = placements[0] if placements else None
        for f in findings:
            entry = kev.get(f.cve) if kev else None
            exploited = f.known_exploited or entry is not None
            base = f.cvss if f.cvss is not None else SEVERITY_BASE.get(f.severity, 5.0)
            exposure = best.exposure_factor if best else 1.0
            privileges = best.privileges_factor if best else 1.0
            kev_factor = KEV_FACTOR if exploited else 1.0
            score = round(base * exposure * privileges * kev_factor, 2)
            rows.append(
                {
                    "score": score,
                    "finding": f.as_dict(),
                    "image": image.label,
                    "factors": {
                        "base": {"value": base, "from": "cvss" if f.cvss is not None else f"severity {f.severity}"},
                        "exposure": {
                            "value": exposure,
                            "kind": best.exposure_kind if best else "unknown (image not placed)",
                        },
                        "privileges": {
                            "value": round(privileges, 2),
                            "capability": best.capability.name if best and best.capability else "none found",
                            "scope": best.capability.scope if best and best.capability else "",
                        },
                        "exploited": {
                            "value": kev_factor,
                            **({"kev": entry.as_dict()} if entry else {}),
                            **({"reportedBy": "scanner"} if f.known_exploited and not entry else {}),
                        },
                    },
                    "workloads": [p.reach.ref for p in placements][:20],
                    "workloadsTotal": len(placements),
                    "attackPath": _path(f, image, best),
                }
            )
            gate = gating_severity(f.severity, f.cvss, exploited)
            bad = exploited or (bool(f.fix_versions) and gate in {"critical", "high"})
            for p in placements:  # every workload, not only the 20 shown
                cur = per_workload.setdefault(p.reach.ref, {"findings": 0, "fixableHighOrExploited": 0})
                cur["findings"] += 1
                cur["fixableHighOrExploited"] += int(bad)
    rows.sort(
        key=lambda r: (
            -r["score"],
            -r["factors"]["exploited"]["value"],
            -(r["finding"]["cvss"] or 0.0),
            r["finding"]["cve"],
            r["finding"]["package"]["name"],
        )
    )
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return {
        "workloads": dict(sorted(per_workload.items())),
        "ranked": rows[:top],
        "total": len(rows),
        "imagesPlaced": placed_images,
        "images": len(per_image),
        "formula": "base x exposure x privileges x exploited (see kube_noob.vuln.rank)",
        # A name two different objects carry: each copy is placed with its own images and rights (G273).
        "ambiguous": ambiguous_notes(reach or {}),
    }
