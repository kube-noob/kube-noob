"""`kube-noob selftest`: prove, in the user's own environment, that kube-noob answers the questions it claims to.

Offline by construction: it only calls the local search index, the diagnosis playbooks, the audit engine and the
protocol on bundled examples. Web and cluster access are never used.
"""

from __future__ import annotations

from collections import defaultdict
from importlib import resources
from typing import Any

import yaml

from kube_noob.config import Settings


class SelfTestSpecError(ValueError):
    """A self-test case cannot be judged as written."""


def validate_case(case: dict[str, Any]) -> None:
    """Refuse a case that asserts nothing.

    `audit` built `missing = [r for r in case["expect"] if r not in fired]` and returned `not missing`, so a case
    with `expect: []` passed whatever the audit found -- and `search` returns `any(d in case["expect"] ...)`,
    which is False on an empty expectation and so fails for the opposite reason. Either way the case is not
    saying what it means, and the self-test is the thing a user runs to decide whether to trust the tool.
    """
    expect = case.get("expect")
    if expect is None or (isinstance(expect, list | tuple | set | str) and not expect):
        raise SelfTestSpecError(
            f"self-test case {case.get('id')!r} ({case.get('kind')}) has an empty `expect`, so it asserts "
            "nothing; give it what it should find, or remove the case"
        )


def cases() -> list[dict[str, Any]]:
    raw = resources.files("kube_noob").joinpath("data", "evals", "selftest.yaml").read_text(encoding="utf-8")
    out = list(yaml.safe_load(raw)["cases"])
    for case in out:
        validate_case(case)
    return out


def _check(kit: Any, case: dict[str, Any]) -> tuple[bool, str]:
    from kube_noob import toolkit as tk
    from kube_noob.demo import examples_dir

    kind = case["kind"]
    if kind == "search":
        hits = kit.search(tk.SearchIn(query=case["query"], limit=3))["results"]
        docs = [h["chunkId"].split("#", 1)[0].removeprefix("kn:") for h in hits]
        return any(d in case["expect"] for d in docs), f"top 3: {', '.join(docs) or 'none'}"
    if kind == "diagnose":
        out = kit.diagnose(tk.DiagnoseIn(text=case["text"], limit=3))
        ids = [d["id"] for d in out["diagnoses"][:2]]
        return case["expect"] in ids, f"top 2: {', '.join(ids) or 'none'}"
    manifests = (examples_dir() / case["example"]).read_text(encoding="utf-8")
    if kind == "audit":
        rep = kit.audit(tk.AuditIn(manifests=manifests, platform=case.get("platform"), version=case.get("version")))
        fired = {f["ruleId"] for f in rep["findings"]}
        missing = [r for r in case["expect"] if r not in fired]
        return not missing, f"missing: {', '.join(missing)}" if missing else f"{len(fired)} rules fired"
    if kind == "protocol":
        out = kit.run_protocol(
            tk.ProtocolIn(request=case.get("request", "deploy this"), blueprint=yaml.safe_load(manifests))
        )
        return out["status"] == case["expect"], f"status {out['status']}"
    raise ValueError(f"unknown self-test kind {kind!r}")


def run(settings: Settings, category: str | None = None) -> dict[str, Any]:
    from kube_noob import toolkit as tk

    safe = settings.model_copy(
        update={"web_enabled": False, "cluster": settings.cluster.model_copy(update={"enabled": False})}
    )
    kit = tk.Toolkit(safe)
    selected = [c for c in cases() if category in (None, c["category"])]
    if not selected:
        raise KeyError(f"no self-test cases in category {category!r}")
    by_cat: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    failures = []
    for case in selected:
        ok, detail = _check(kit, case)
        by_cat[case["category"]][1] += 1
        if ok:
            by_cat[case["category"]][0] += 1
        else:
            failures.append({"id": case["id"], "category": case["category"], "kind": case["kind"], "detail": detail})
    passed = sum(p for p, _ in by_cat.values())
    return {
        "passed": passed,
        "total": len(selected),
        "score": round(passed / len(selected), 3),
        "byCategory": {k: {"passed": p, "total": t} for k, (p, t) in sorted(by_cat.items())},
        "failures": failures,
    }
