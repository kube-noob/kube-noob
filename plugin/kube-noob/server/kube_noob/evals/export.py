"""Training dataset export ("train later"): deterministic, license-aware, provenance-tagged.

Produces chat-format SFT records (``{"messages": [...], "metadata": {...}}``) and a GRPO prompt set
(``{"prompt": ..., "task_id": ...}`` for use with ``kube_noob.evals.reward.trl_reward``).

Sources, in order:
  1. Curriculum exercises with ``reference`` blueprints -> generator output (audited, our own output).
  2. Synthetic blueprint grid (platform x exposure x storage x workload) -> generator output.
  3. Debug playbooks -> symptom/diagnosis pairs.
  4. Knowledge QA from redistributable chunks (built-in docs; corpus chunks only if redistributable).
No LLM-generated labels are included unless ``allow_llm_labels`` is set by the operator.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from kube_noob import __version__
from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity
from kube_noob.debug.playbooks import PLAYBOOKS
from kube_noob.debug.steps import split_comment
from kube_noob.evals.reward import benchmark
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.manifests import generate
from kube_noob.knowledge.store import KnowledgeStore
from kube_noob.learn.tutor import exercises

SYSTEM = (
    "You are an SRE assistant for Kubernetes, OpenShift, ROSA HCP, Helm and RHACS. Answer with "
    "validated YAML and cite local knowledge as [kn:<doc>#<n>]."
)


def _rec(user: str, assistant: str, meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": {
            **meta,
            "generator": f"kube-noob {__version__}",
            "labelSource": meta.get("labelSource", "deterministic"),
        },
    }


def _manifest_answer(bp: Blueprint) -> str | None:
    g = generate(bp)
    r = analyze(g.yaml(), bp.platform, bp.platform_version)
    if any(f.severity >= Severity.HIGH for f in r.findings):
        return None  # never train on outputs that fail our own audit
    notes = "\n".join(f"- {a}" for a in g.assumptions + g.prerequisites)
    return f"```yaml\n{g.yaml()}```\n\nAssumptions and prerequisites:\n{notes}\n"


def _describe(bp: Blueprint) -> str:
    parts = [
        f"Deploy '{bp.name}' in namespace '{bp.namespace}' on {bp.platform} using image '{bp.image}' with "
        f"{bp.replicas} replica(s) on port {bp.port}"
    ]
    if bp.workload == "statefulset":
        parts.append("as a StatefulSet")
    if bp.storage:
        parts.append(f"with {bp.storage.size} {bp.storage.access_mode} storage at {bp.storage.mount_path}")
    if bp.exposure.type != "none":
        host = f" on host {bp.exposure.host}" if bp.exposure.host else ""
        parts.append(f"exposed via {bp.exposure.type}{host}")
    return ", ".join(parts) + ". Produce production-grade, hardened manifests."


def exercise_records() -> Iterator[dict[str, Any]]:
    for ex in exercises().values():
        ref = ex.get("reference")
        if not ref:
            continue
        bp = Blueprint.model_validate(ref)
        ans = _manifest_answer(bp)
        if ans:
            yield _rec(ex["prompt"], ans, {"source": "curriculum", "id": ex["id"], "license": "Apache-2.0"})


def synthetic_records(limit: int | None = None) -> Iterator[dict[str, Any]]:
    platforms = ["kubernetes", "openshift", "rosa-hcp", "rosa-classic"]
    exposures = ["none", "route", "ingress"]
    storages: list[dict[str, Any] | None] = [
        None,
        {"size": "10Gi", "accessMode": "ReadWriteMany"},
        {"size": "20Gi", "accessMode": "ReadWriteOnce"},
    ]
    workloads = ["deployment", "statefulset"]
    n = 0
    for plat, exp, st, wl in itertools.product(platforms, exposures, storages, workloads):
        if exp == "route" and plat == "kubernetes":
            continue
        if st and st["accessMode"] == "ReadWriteOnce" and wl == "deployment":
            continue
        storage = st
        if st and st["accessMode"] == "ReadWriteMany" and plat == "kubernetes":
            storage = {**st, "storageClass": "nfs-csi"}
        name = f"svc-{hashlib.sha256(f'{plat}{exp}{storage}{wl}'.encode()).hexdigest()[:6]}"
        raw: dict[str, Any] = {
            "name": name,
            "namespace": "team-apps",
            "image": f"quay.io/example/{name}:1.0.0",
            "platform": plat,
            "workload": wl,
            "replicas": 3,
        }
        if exp != "none":
            raw["exposure"] = {"type": exp, "host": f"{name}.apps.example.com"}
        if storage:
            raw["storage"] = storage
        bp = Blueprint.model_validate(raw)
        ans = _manifest_answer(bp)
        if ans:
            yield _rec(_describe(bp), ans, {"source": "synthetic-blueprint", "id": name, "license": "Apache-2.0"})
            n += 1
            if limit is not None and n >= limit:
                return


def playbook_records() -> Iterator[dict[str, Any]]:
    for p in PLAYBOOKS:
        symptom = p.signals[0].replace("\\", "").replace("(", "").replace(")", "").replace("?", "")
        answer = (
            f"**{p.title}**\n\nLikely causes:\n"
            + "\n".join(f"- {c}" for c in p.root_causes)
            + "\n\nRead-only checks:\n"
            + "\n".join(_check_line(c) for c in p.checks)
            + "\n\nFixes:\n"
            + "\n".join(f"- {f}" for f in p.fixes)
            + ("\n\nSee: " + ", ".join(f"[kn:{k}#0]" for k in p.knowledge) if p.knowledge else "")
        )
        yield _rec(
            f"I'm seeing `{symptom}` on {p.platforms[0]}. What's wrong and how do I fix it?",
            answer,
            {"source": "playbook", "id": p.pid, "license": "Apache-2.0"},
        )


def _check_line(check: str) -> str:
    cmd, why = split_comment(check)
    return f"- `{cmd}`" + (f": {why}" if why else "")


def knowledge_records(store: KnowledgeStore, include_restricted: bool) -> Iterator[dict[str, Any]]:
    for c in store.chunks:
        if c.origin == "local":  # the user's own notes are never training data, whatever the flags say
            continue
        if not c.redistributable and not include_restricted:
            continue
        if len(c.text) < 200 or not c.heading:
            continue
        q = f"Explain: {c.heading} ({c.title})"
        a = f"{c.text}\n\nSource: [{c.chunk_id}]" + (f" ({c.url}, {c.license})" if c.url else "")
        yield _rec(
            q, a, {"source": c.source_id, "id": c.chunk_id, "license": c.license, "redistributable": c.redistributable}
        )


def export_sft(
    out: Path, store: KnowledgeStore, include_restricted: bool = False, synthetic_limit: int | None = None
) -> dict[str, Any]:
    out.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    seen: set[str] = set()
    holdout = {t["prompt"].strip() for t in benchmark().values()}
    with out.open("w", encoding="utf-8") as fh:
        for gen in (
            exercise_records(),
            synthetic_records(synthetic_limit),
            playbook_records(),
            knowledge_records(store, include_restricted),
        ):
            for rec in gen:
                user = rec["messages"][1]["content"]
                if user.strip() in holdout:
                    continue  # never leak benchmark prompts into training data
                key = hashlib.sha256(json.dumps(rec["messages"], sort_keys=True).encode()).hexdigest()
                if key in seen:
                    continue
                seen.add(key)
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                counts[rec["metadata"]["source"].split(":")[0]] = (
                    counts.get(rec["metadata"]["source"].split(":")[0], 0) + 1
                )
    return {
        "file": str(out),
        "records": sum(counts.values()),
        "bySource": counts,
        "includesRestricted": include_restricted,
        "labelSources": ["deterministic"],
    }


def export_grpo(out: Path) -> dict[str, Any]:
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out.open("w", encoding="utf-8") as fh:
        for tid, task in benchmark().items():
            fh.write(
                json.dumps(
                    {
                        "prompt": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task["prompt"]}],
                        "task_id": tid,
                    }
                )
                + "\n"
            )
            n += 1
    return {
        "file": str(out),
        "records": n,
        "rewardFunction": "kube_noob.evals.reward:trl_reward (pass the 'task_id' column)",
    }
