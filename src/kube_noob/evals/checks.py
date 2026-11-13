"""Deterministic check DSL shared by learning exercises, the eval benchmark and the training reward.

A check spec is a mapping (YAML/JSON):

    platform: openshift          # target used for the audit
    version: "4.20"              # optional platform version
    kinds: [Deployment, Service] # kinds that must be present
    schemaValid: true            # no KN-V007 findings
    maxSeverity: medium          # no finding above this severity
    forbidRules: [KN-S001]       # these rule ids must not fire (INFO-level advisories are ignored)
    minScore: 80                 # audit posture score threshold (0-100)
    assertions:                  # field assertions (see _assert for every operator)
      - {kind: Deployment, path: spec.replicas, gte: 2}
      - {kind: Route, path: spec.tls.termination, in: [edge, reencrypt]}
      - {kind: PodDisruptionBudget, exists: true}
      - {kind: EgressFirewall, path: "spec.egress[-1]", equals: {type: Deny, to: {cidrSelector: 0.0.0.0/0}}}
      - {kind: EgressFirewall, path: spec.egress, containsItem: {type: Allow, to: {dnsName: s3.amazonaws.com}}}
      - {kind: ClusterRole, all: true, path: "rules[*].verbs", subsetOf: [get, list, watch]}

Paths: dotted keys, ``[n]`` indexes (negative allowed), ``[*]`` fans out over a list. By default an assertion passes if
the first object of the kind that has the path satisfies it; ``all: true`` requires every object of the kind and every
value the path fans out to (a missing path then fails).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report, Severity
from kube_noob.errors import ManifestError
from kube_noob.yamlio import Document, load_documents

_FENCE = re.compile(r"```(?:ya?ml|yml)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_PATH_TOKEN = re.compile(r"([^.\[\]]+)|\[(-?\d+|\*)\]")
_MISSING = object()


GATE_CAP = 0.4


@dataclass
class CheckOutcome:
    name: str
    passed: bool
    detail: str
    weight: float = 1.0
    gating: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "weight": self.weight,
            "gating": self.gating,
        }


@dataclass
class Evaluation:
    outcomes: list[CheckOutcome]
    report: Report | None
    parsed: bool

    @property
    def score(self) -> float:
        """Weighted share of passed checks. Gating checks (field assertions and forbidden rules encode the task's
        intent) cap the score at GATE_CAP when any of them fails, so a valid-but-wrong answer cannot score high."""
        total = sum(o.weight for o in self.outcomes)
        raw = 0.0 if total == 0 else sum(o.weight for o in self.outcomes if o.passed) / total
        if any(o.gating and not o.passed for o in self.outcomes):
            return min(raw, GATE_CAP)
        return raw

    @property
    def passed(self) -> bool:
        # `all([])` is True, so an evaluation with no outcomes used to report passed while `score()` returned
        # 0.0 -- two fields of the same result disagreeing. Nothing checked is not everything passing.
        return self.parsed and bool(self.outcomes) and all(o.passed for o in self.outcomes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "score": round(self.score, 4),
            "checks": [o.as_dict() for o in self.outcomes],
            "audit": self.report.as_dict()["summary"] if self.report else None,
            "findings": [f.as_dict() for f in self.report.findings if f.severity >= Severity.MEDIUM][:25]
            if self.report
            else [],
        }


def extract_yaml(answer: str) -> str:
    """Accept raw YAML or Markdown with fenced YAML blocks (model completions)."""
    blocks = _FENCE.findall(answer)
    if blocks:
        return "\n---\n".join(b.strip() for b in blocks)
    return answer


def get_values(obj: Any, path: str) -> list[Any]:
    """All values at ``path``; ``[*]`` fans out, negative indexes count from the end. Missing branches are dropped."""
    current: list[Any] = [obj]
    for m in _PATH_TOKEN.finditer(path):
        key, idx = m.group(1), m.group(2)
        nxt: list[Any] = []
        for cur in current:
            if idx == "*":
                if isinstance(cur, list):
                    nxt.extend(cur)
            elif idx is not None:
                i = int(idx)
                if isinstance(cur, list) and -len(cur) <= i < len(cur):
                    nxt.append(cur[i])
            elif isinstance(cur, dict) and key in cur:
                nxt.append(cur[key])
        current = nxt
    return current


def _subset_match(item: Any, pattern: Any) -> bool:
    """``pattern`` is a partial description of ``item`` (dict keys recursively, scalars by equality)."""
    if isinstance(pattern, dict):
        return isinstance(item, dict) and all(k in item and _subset_match(item[k], v) for k, v in pattern.items())
    return bool(item == pattern)


def _flatten(values: list[Any]) -> list[Any]:
    out: list[Any] = []
    for v in values:
        out.extend(v if isinstance(v, list) else [v])
    return out


class CheckSpecError(ValueError):
    """An assertion in a task spec cannot be evaluated as written."""


# Every comparison `_check_value` understands, plus the two `_assert` handles itself. A key outside this set is a
# typo, and a typo used to pass: `_check_value` returned None for an unrecognised operator and `_assert` turned
# that None into a pass -- on a gating, weight-2.0 assertion, which also disengaged the GATE_CAP clamp, so a
# wrong answer scored high instead of being capped.
OPERATORS = frozenset(
    {
        "equals",
        "notEquals",
        "in",
        "gte",
        "lte",
        "contains",
        "notContains",
        "containsItem",
        "notContainsItem",
        "subsetOf",
        "lenLte",
        "lenGte",
        "matches",
        "exists",
    }
)
_ASSERTION_KEYS = OPERATORS | {"kind", "path", "all", "name"}


def validate_assertion(a: dict[str, Any]) -> None:
    """Refuse an assertion that names no operator this module can evaluate.

    `exists: true` is an operator, so a bare presence check is legitimate; what is refused is a key nothing
    recognises, which previously read as "present" and passed.
    """
    if not isinstance(a, dict):
        raise CheckSpecError(f"an assertion must be a mapping, not {type(a).__name__}")
    unknown = sorted(set(a) - _ASSERTION_KEYS)
    if unknown:
        raise CheckSpecError(
            f"assertion on {a.get('kind')}.{a.get('path')}: {unknown} is not an operator this module can "
            f"evaluate, so the assertion would pass whatever the answer is. Use one of "
            f"{', '.join(sorted(OPERATORS))}"
        )
    if not set(a) & OPERATORS:
        raise CheckSpecError(
            f"assertion on {a.get('kind')}.{a.get('path')} names no operator, so it would pass whatever the "
            f"answer is; use one of {', '.join(sorted(OPERATORS))}"
        )


def _check_value(a: dict[str, Any], val: Any) -> tuple[bool, str] | None:
    """Evaluate one operator against one value. None means no operator was given."""
    if "equals" in a:
        return val == a["equals"], f"== {a['equals']!r}"
    if "notEquals" in a:
        return val != a["notEquals"], f"!= {a['notEquals']!r}"
    if "in" in a:
        return val in a["in"], f"in {a['in']!r}"
    if "gte" in a:
        return isinstance(val, int | float) and not isinstance(val, bool) and val >= a["gte"], f">= {a['gte']}"
    if "lte" in a:
        return isinstance(val, int | float) and not isinstance(val, bool) and val <= a["lte"], f"<= {a['lte']}"
    if "contains" in a:
        return isinstance(val, list | str) and a["contains"] in val, f"contains {a['contains']!r}"
    if "notContains" in a:
        return not (isinstance(val, list | str) and a["notContains"] in val), f"does not contain {a['notContains']!r}"
    if "containsItem" in a:
        ok = isinstance(val, list) and any(_subset_match(x, a["containsItem"]) for x in val)
        return ok, f"has item {a['containsItem']!r}"
    if "notContainsItem" in a:
        ok = not (isinstance(val, list) and any(_subset_match(x, a["notContainsItem"]) for x in val))
        return ok, f"has no item {a['notContainsItem']!r}"
    if "subsetOf" in a:
        items = val if isinstance(val, list) else [val]
        extra = [x for x in items if x not in a["subsetOf"]]
        return not extra, f"subset of {a['subsetOf']!r}" + (f" (extra: {extra!r})" if extra else "")
    if "lenLte" in a:
        return isinstance(val, list | str | dict) and len(val) <= a["lenLte"], f"len <= {a['lenLte']}"
    if "lenGte" in a:
        return isinstance(val, list | str | dict) and len(val) >= a["lenGte"], f"len >= {a['lenGte']}"
    if "matches" in a:
        return isinstance(val, str) and re.search(str(a["matches"]), val) is not None, f"matches {a['matches']!r}"
    return None


def _assert(docs: list[Document], a: dict[str, Any]) -> CheckOutcome:
    kind = a.get("kind")
    path = a.get("path")
    every = bool(a.get("all"))
    name = f"{'all ' if every else ''}{kind}{('.' + path) if path else ''}"
    cands = [d for d in docs if d.kind == kind]
    if not cands:
        return CheckOutcome(f"assert {name}", False, f"no {kind} object found")
    if not path:
        return CheckOutcome(f"assert {name}", bool(a.get("exists", True)), f"{kind} present")
    per_doc = [get_values(d.data, path) for d in cands]
    if "exists" in a:
        want = bool(a["exists"])
        found = [bool(v) for v in per_doc]
        ok = all(f == want for f in found) if every else (any(found) == want)
        return CheckOutcome(f"assert {name} exists={want}", ok, f"found={found if every else any(found)}")
    if every:
        if not all(per_doc):
            return CheckOutcome(f"assert {name}", False, f"{path} not set on every {kind}")
        values = [v for vs in per_doc for v in vs]
        # subsetOf over fanned-out lists judges the union of all items
        if "subsetOf" in a:
            res = _check_value(a, _flatten(values))
            assert res is not None  # noqa: S101
            return CheckOutcome(f"assert {name} {res[1]}", res[0], f"got {_flatten(values)!r}"[:300])
        results = [(v, _check_value(a, v)) for v in values]
        if results and results[0][1] is None:
            return CheckOutcome(f"assert {name}", True, "present")
        bad = [v for v, r in results if r is not None and not r[0]]
        label = results[0][1][1] if results and results[0][1] else ""
        return CheckOutcome(f"assert {name} {label}", not bad, f"failing values {bad!r}"[:300] if bad else "ok")
    vals = next((v for v in per_doc if v), None)
    if vals is None:
        return CheckOutcome(f"assert {name}", False, f"{path} not set")
    target: Any = _flatten(vals) if "[*]" in path else vals[0]
    res = _check_value(a, target)
    if res is None:
        return CheckOutcome(f"assert {name}", True, "present")
    return CheckOutcome(f"assert {name} {res[1]}", res[0], f"got {target!r}"[:300])


def evaluate(answer: str, spec: dict[str, Any]) -> Evaluation:
    text = extract_yaml(answer)
    try:
        docs = load_documents(text)
    except ManifestError as exc:
        return Evaluation([CheckOutcome("parse", False, str(exc), weight=2.0)], None, parsed=False)
    docs = [d for d in docs if isinstance(d.data, dict)]
    if not docs:
        return Evaluation([CheckOutcome("parse", False, "no Kubernetes objects found", weight=2.0)], None, False)
    report = analyze(docs, platform=spec.get("platform", "kubernetes"), version=spec.get("version"))
    outcomes: list[CheckOutcome] = [CheckOutcome("parse", True, f"{len(docs)} object(s)", weight=1.0)]
    present = {d.kind for d in docs}
    for k in spec.get("kinds") or []:
        outcomes.append(CheckOutcome(f"kind {k}", k in present, "present" if k in present else "missing"))
    if spec.get("schemaValid"):
        errs = [f for f in report.findings if f.rule_id in {"KN-V007", "KN-V001", "KN-V002", "KN-V010", "KN-V018"}]
        outcomes.append(
            CheckOutcome("schema valid", not errs, "; ".join(f.message for f in errs[:3]) or "ok", weight=2.0)
        )
    if spec.get("maxSeverity"):
        limit = Severity.parse(spec["maxSeverity"])
        over = [f for f in report.findings if f.severity > limit]
        outcomes.append(
            CheckOutcome(
                f"no findings above {limit.name.lower()}",
                not over,
                "; ".join(f"{f.rule_id} {f.message}" for f in over[:4]) or "ok",
                weight=2.0,
            )
        )
    for rid in spec.get("forbidRules") or []:
        hits = [f for f in report.findings if f.rule_id == rid and f.severity >= Severity.LOW]
        outcomes.append(
            CheckOutcome(
                f"rule {rid} not triggered", not hits, hits[0].message if hits else "ok", weight=1.5, gating=True
            )
        )
    if "minScore" in spec:
        # The one consumer that read `score()` by name: a report whose score the product withholds (a rule
        # declined on an object, a pod spec not read) passed `minScore: 80` at "score 100" while `audit` printed
        # "not determined" for the same input (G272, sixth review). Withheld is not a pass.
        withheld = report.score_withheld()
        outcomes.append(
            CheckOutcome(
                f"posture score >= {spec['minScore']}",
                withheld is None and report.score() >= float(spec["minScore"]),
                f"score not determined ({withheld})" if withheld else f"score {report.score():.0f}",
                weight=1.5,
            )
        )
    for a in spec.get("assertions") or []:
        # Refuse a spec whose assertion names no operator rather than scoring it as a pass. These are gating and
        # weight 2.0, so a typo used to hand out free marks and disengage the GATE_CAP clamp at the same time.
        validate_assertion(a)
        outcome = _assert(docs, a)
        outcome.weight, outcome.gating = 2.0, True
        outcomes.append(outcome)
    return Evaluation(outcomes, report, parsed=True)
