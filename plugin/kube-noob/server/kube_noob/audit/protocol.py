"""The mandatory 7-step engineering protocol: Clarify, Validate, Research, Audit, Calibrate, Generate, Red Team.

Deterministic orchestration of the engine; an LLM (agent or MCP client) adds reasoning on top, but every step here is
reproducible and its outputs are checkable.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from kube_noob.audit.engine import analyze
from kube_noob.audit.fixer import fix_manifests
from kube_noob.audit.model import Report, Severity, Stage
from kube_noob.catalog import OPENSHIFT_FAMILY, k8s_version_for
from kube_noob.errors import ClarificationNeeded
from kube_noob.generate.blueprint import Blueprint, clarify
from kube_noob.generate.manifests import generate
from kube_noob.knowledge.store import KnowledgeStore
from kube_noob.yamlio import load_documents

_PLATFORM_HINTS: tuple[tuple[str, str], ...] = (
    (r"\brosa[- ]?(with )?hcp\b|\bhosted control plane|\bhypershift\b", "rosa-hcp"),
    (r"\brosa\b(?![- ]?hcp)", "rosa-classic"),
    (r"\bopenshift\b|\bocp\b|\bokd\b", "openshift"),
    (r"\bkubernetes\b|\beks\b|\baks\b|\bgke\b|\bkind\b|\bk3s\b", "kubernetes"),
)


# "OpenShift 4.21", "ROSA HCP 4.20", "OCP 4.22" or "Kubernetes 1.33" written in the request itself.
_VERSION_IN_REQUEST = re.compile(
    r"(?i)\b(?:openshift|ocp|rosa(?:\s+(?:hcp|classic))?)\s*v?(?P<ocp>4\.\d{1,2})\b"
    r"|\b(?:kubernetes|k8s)\s*v?(?P<k8s>1\.\d{2})\b"
)


def infer_platform(request: str, manifests: str | None) -> tuple[str | None, str]:
    text = request.lower()
    for pat, plat in _PLATFORM_HINTS:
        if re.search(pat, text):
            return plat, f"platform inferred from request text ('{plat}')"
    if manifests and re.search(r"apiVersion:\s*(route|security|apps)\.openshift\.io", manifests):
        return "openshift", "platform inferred from OpenShift API groups in the manifests"
    return None, ""


def _commands(platform: str) -> list[str]:
    cli = "oc" if platform in OPENSHIFT_FAMILY else "kubectl"
    return [
        f"kube-noob audit -f manifest.yaml --platform {platform}",
        f"{cli} apply --dry-run=server -f manifest.yaml",
        f"{cli} diff -f manifest.yaml",
        f"{cli} apply -f manifest.yaml && {cli} rollout status -f manifest.yaml --timeout=180s",
    ]


def _summ(report: Report, stage: Stage) -> list[dict[str, Any]]:
    return [f.as_dict() for f in report.findings if f.stage is stage and f.severity >= Severity.LOW]


def run_protocol(
    request: str,
    *,
    manifests: str | None = None,
    blueprint: dict[str, Any] | None = None,
    platform: str | None = None,
    version: str | None = None,
    apply_fixes: bool = True,
    store: KnowledgeStore | None = None,
) -> dict[str, Any]:
    steps: dict[str, Any] = {}
    assumptions: list[str] = []
    questions: list[str] = []

    # 1. Clarify ------------------------------------------------------------------------------------------
    if platform is None and blueprint is not None and blueprint.get("platform"):
        platform = str(blueprint["platform"])
        assumptions.append(f"platform taken from the blueprint ('{platform}')")
    if version is None and blueprint is not None:
        bp_version = blueprint.get("platformVersion") or blueprint.get("platform_version")
        if bp_version:
            version = str(bp_version)
            assumptions.append(f"version taken from the blueprint ('{version}')")
    if platform is None:
        inferred, why = infer_platform(request, manifests)
        if inferred:
            platform = inferred
            assumptions.append(why)
        else:
            platform = "kubernetes"
            questions.append(
                "Which platform is the target: vanilla Kubernetes, OpenShift (on-prem IPI/UPI), "
                "ROSA Classic or ROSA with HCP? Defaulted to vanilla Kubernetes."
            )
    if version is None:
        named = _VERSION_IN_REQUEST.search(request or "")
        if named and (named.group("ocp") or named.group("k8s")):
            if named.group("ocp") and platform in {"openshift", "rosa-classic", "rosa-hcp"}:
                version = named.group("ocp")
            elif named.group("k8s") and platform == "kubernetes":
                version = named.group("k8s")
            if version:
                assumptions.append(f"version taken from the request ('{version}')")
    if version is None:
        assumptions.append(f"No version given; assuming Kubernetes {k8s_version_for(platform, None)} semantics.")
    bp: Blueprint | None = None
    if blueprint is not None:
        try:
            bp = Blueprint.model_validate({**blueprint, "platform": blueprint.get("platform", platform)})
            q, a = clarify(bp)
            questions.extend(q)
            assumptions.extend(a)
        except ValidationError as exc:
            questions.extend(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
    if manifests is None and bp is None:
        questions.append(
            "Provide manifests to review or a blueprint (name, namespace, image, exposure, storage) to generate from."
        )
    steps["clarify"] = {"questions": questions, "assumptions": assumptions, "platform": platform}
    blocking = bool(questions) and bp is None and manifests is None
    if blocking or (bp is not None and questions):
        return {"status": "needs-clarification", "steps": steps, "questions": questions, "assumptions": assumptions}

    # 6 (early): Generate when a blueprint was given, so 2-5 run on the produced manifests -----------------
    generated_notes: list[str] = []
    source_label = "input"
    if bp is not None:
        try:
            gen = generate(bp)
        except ClarificationNeeded as exc:
            return {
                "status": "needs-clarification",
                "steps": steps,
                "questions": exc.questions,
                "assumptions": assumptions,
            }
        manifests = gen.yaml()
        generated_notes = gen.prerequisites
        source_label = "generated"
    assert manifests is not None  # noqa: S101

    # 2. Validate -----------------------------------------------------------------------------------------
    docs = load_documents(manifests)
    initial = analyze(docs, platform=platform, version=version)
    steps["validate"] = {"findings": _summ(initial, Stage.VALIDATE), "notes": initial.assumptions}

    # 3. Research -----------------------------------------------------------------------------------------
    citations: list[dict[str, Any]] = []
    if store is not None:
        kinds = sorted({d.kind for d in docs if d.kind})
        topics = [request] + [f"{f.title} {f.rule_id}" for f in initial.findings if f.severity >= Severity.HIGH][:4]
        topics.append(f"{platform} {' '.join(kinds)} best practices")
        seen: set[str] = set()
        for t in topics:
            for h in store.search(t, limit=3):
                if h.chunk.chunk_id not in seen:
                    seen.add(h.chunk.chunk_id)
                    citations.append(h.as_dict(max_chars=400))
        citations = citations[:8]
    rule_cites = {c.source_id: c.as_dict() for f in initial.findings for c in f.citation_objects()}
    steps["research"] = {"knowledge": citations, "ruleSources": list(rule_cites.values())}

    # 4. Audit / 5. Calibrate -----------------------------------------------------------------------------
    steps["audit"] = {"findings": _summ(initial, Stage.AUDIT)}
    steps["calibrate"] = {"findings": _summ(initial, Stage.CALIBRATE)}

    # 6. Generate (fix) -----------------------------------------------------------------------------------
    final_yaml = manifests
    changes: list[dict[str, Any]] = []
    manual: list[str] = []
    if source_label == "input" and apply_fixes:
        fx = fix_manifests(manifests, platform=platform, k8s_version=initial.kubernetes_version)
        final_yaml = fx.yaml()
        changes = [c.as_dict() for c in fx.changes]
        manual = fx.manual
    final = analyze(final_yaml, platform=platform, version=version)
    steps["generate"] = {
        "source": source_label,
        "changes": changes,
        "manualFollowUps": manual,
        "prerequisites": generated_notes,
    }

    # 7. Red Team -----------------------------------------------------------------------------------------
    exposed = [s.as_dict() for s in final.scenarios if s.verdict == "exposed"]
    blockers = [f.as_dict() for f in final.findings if f.severity >= Severity.HIGH]
    steps["redTeam"] = {"scenarios": [s.as_dict() for s in final.scenarios], "remainingBlockers": blockers}

    # "ready" from an absence of HIGH findings is only honest if the audit read everything it was given. With no
    # documents no rule ran, so there were no blockers and the run reported ready. The same holds for an object
    # the rules did not read: `Report.undetermined()` is the one predicate every renderer of this report reads,
    # and this one did not, so the privileged container that is `blocked` in a Deployment was `ready` in an Argo
    # Rollout, with `remainingBlockers: []` and `kubectl apply` printed beneath it (G339). A blocker stays a
    # blocker -- a finding is a finding -- and the reason is carried either way, because "this has problems" and
    # "part of it was never read" are independent.
    undetermined = final.undetermined() if docs else "no document was given, so no rule ran"
    undecided = [s.as_dict() for s in final.scenarios if s.verdict == "undecided"]
    if blockers:
        status = "blocked"
    elif undetermined is not None:
        status = "undetermined"
    else:
        status = "ready"
    brief = {
        "platform": platform,
        "platformVersion": final.platform_version,
        "kubernetesVersion": final.kubernetes_version,
        "resources": final.resources,
        "before": initial.as_dict()["summary"],
        "after": final.as_dict()["summary"],
        "assumptions": assumptions + [a for a in final.assumptions if a not in assumptions],
        "openQuestions": questions,
    }
    return {
        "status": status,
        # Beside the status and ahead of the long fields: a client that truncates a tool result keeps the first
        # bytes, and the reason a verdict was withheld is the part that must survive that (G330).
        **({"statusReason": undetermined} if undetermined is not None else {}),
        "auditValidationBrief": brief,
        "productionManifest": final_yaml,
        "redTeamFindingsAndSafeguards": {
            "exposedScenarios": exposed,
            "undecidedScenarios": undecided,
            "remainingBlockers": blockers,
            "manualFollowUps": manual,
            "prerequisites": generated_notes,
        },
        "validationCommands": _commands(platform),
        "steps": steps,
    }
