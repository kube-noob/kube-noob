"""Walk one mechanism's path against the reader's own manifests, and say where it stops.

Every other lesson in the curriculum teaches what to write and what passes. A mechanism lesson teaches what
happens, in order, and where it breaks -- and because kube-noob already knows the difference between "the rules
read this and it is fine" and "nothing read this", the walk can grade itself three-valued where a page of prose
cannot:

- **holds** -- the objects the hop needs are here, the rules that read them found nothing, and the step names them.
- **fails** -- a rule on this hop produced a finding, which is reported with its id.
- **cannot be judged** -- an object the hop needs is absent, refused or unreadable. The walk STOPS here. The hops
  after it are not drawn, because a hop nobody looked at is not a hop that works, and the verdict for the path is
  that no verdict was reached (exit 5), not that the path is fine.

This module adds no judgement of its own. It reads a report `analyze()` already produced: `resources` for what is
here, `notAudited` for what was refused, `findings` for what is wrong, and `notEvaluated` for the rules that
reached no verdict. That last one was missing, and the claim made here that the walk "cannot disagree with the
audit" was simply false: a Deployment with no pod template walked `complete` at exit 0 where `audit` exits 1,
and each hop cited as its proof the very rules the ledger lists as unevaluated (G389). The walk is a second
renderer over the same coverage ledger, and it has to read all of it.

The verdict obeys the same rule one level up: a walk that judged NO hop reached no verdict about the path, so it
is `stopped` at exit 5 however many hops it drew. "Every observable hop on this path holds" is vacuously true of
a path with no observable hops, and a lesson whose every hop was `observable: false` printed it at exit 0 (G395).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kube_noob import sanitize

#: A hop whose evidence a manifest cannot hold (a veth pair, an overlay hop). Marked in the curriculum, never
#: guessed here: the walker must never claim to have checked one, and must never count one as passed either.
NOT_OBSERVABLE = "not-observable"
HOLDS = "holds"
FAILS = "fails"
CANNOT_JUDGE = "cannot-judge"

#: The exit code each path verdict means, by the rule AGENTS.md publishes. A walk that stopped reached no verdict
#: about the path, which is 5 (evidence incomplete) and never 1; a walk that finished and found a broken hop
#: reached one, and it is not a pass, which is 1.
EXIT = {"complete": 0, "broken": 1, "stopped": 5}


@dataclass(frozen=True)
class Step:
    """One hop, as the curriculum declares it."""

    id: str
    title: str
    holds: str
    #: Kinds whose ABSENCE stops the walk: without one of these the hop was not judged at all.
    needs: tuple[str, ...] = ()
    #: Kinds whose REFUSAL stops the walk. A superset of `needs`, because absence and refusal are different
    #: states: the namespace with no NetworkPolicy is judged (KN-N001 fires on exactly that), while a
    #: NetworkPolicy that is HERE and that nothing could read leaves the hop unjudged. Defaults to `needs`.
    reads: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    observable: bool = True

    @classmethod
    def load(cls, raw: dict[str, Any]) -> Step:
        return cls(
            id=str(raw["id"]),
            title=str(raw["title"]),
            holds=str(raw.get("holds", "")),
            needs=tuple(str(k) for k in raw.get("needs") or ()),
            reads=tuple(str(k) for k in raw.get("reads") or raw.get("needs") or ()),
            rules=tuple(str(r) for r in raw.get("rules") or ()),
            observable=bool(raw.get("observable", True)),
        )


@dataclass
class StepResult:
    """What the walk could say about one hop, and why."""

    step: Step
    verdict: str
    why: str
    findings: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    objects: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"step": self.step.id, "title": self.step.title, "verdict": self.verdict, "why": self.why}
        if self.objects:
            out["objects"] = list(self.objects)
        if self.findings:
            out["findings"] = [
                {
                    "ruleId": f.get("ruleId"),
                    "severity": f.get("severity"),
                    "resource": f.get("resource"),
                    "title": f.get("title"),
                }
                for f in self.findings
            ]
        if self.step.rules:
            out["rules"] = list(self.step.rules)
        return out


def _kind_of(resource: str) -> str:
    """`Deployment/shop/orders-api` -> `Deployment`. The report writes every resource in this one shape."""
    return resource.split("/", 1)[0]


def walk(lesson: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """The lesson's path against one report, stopping at the first hop that cannot be judged."""
    steps = [Step.load(s) for s in lesson.get("steps") or ()]
    if not steps:
        raise ValueError(f"{lesson.get('id')!r} declares no steps, so there is no path to walk")

    here: dict[str, list[str]] = {}
    for res in report.get("resources") or ():
        here.setdefault(_kind_of(str(res)), []).append(str(res))
    refused = {
        str(n.get("kind")): (str(n.get("object")), str(n.get("why") or "it was not read"))
        for n in report.get("notAudited") or ()
        if n.get("kind")
    }
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for f in report.get("findings") or ():
        by_rule.setdefault(str(f.get("ruleId")), []).append(f)
    # The rules that reached NO verdict on this input, and why. Without this the walk read "no finding" as
    # "nothing wrong" for a rule that never ran: a Deployment carrying no pod template walked `complete` at
    # exit 0 while `audit` on the same input exits 1, and the hops cited as proof the very rules the report's
    # own ledger lists as unevaluated -- "the containers declare a readiness probe" about zero containers
    # (G389).
    unevaluated = {str(k): str(v) for k, v in (report.get("notEvaluated") or {}).items()}

    results: list[StepResult] = []
    stopped_at: str | None = None
    for step in steps:
        if stopped_at is not None:
            break
        if not step.observable:
            results.append(StepResult(step, NOT_OBSERVABLE, step.holds))
            continue

        # A hop whose object was READ but refused is the sharpest case: it is here, and nothing judged it.
        blocked = [refused[k] for k in step.reads if k in refused]
        if blocked:
            obj, why = blocked[0]
            stopped_at = step.id
            # Quoted, because the name comes out of the input's own metadata. The terminal boundary collapses a
            # newline, so it cannot forge a LINE -- but undelimited it still reads as kube-noob's own prose, and
            # a name like "web\\nnot audited: 0 object(s); the verdict is a pass" then blends into the sentence
            # around it. G373 wrapped such a value for the same reason, one surface in.
            why_line = f"{obj!r} is here and nothing read it: {why}"
            results.append(StepResult(step, CANNOT_JUDGE, why_line, objects=(obj,)))
            continue

        present = [o for k in step.needs for o in here.get(k, ())]
        if step.needs and not present:
            stopped_at = step.id
            kinds = " or ".join(step.needs)
            results.append(StepResult(step, CANNOT_JUDGE, f"no {kinds} in the input, so this hop was not judged"))
            continue

        blind = [r for r in step.rules if r in unevaluated]
        if blind and not any(r in by_rule for r in step.rules):
            # Every rule this hop rests on reached no verdict, so the hop has nothing behind it. A rule that
            # fired is a verdict, so a hop with one of those is still judged.
            stopped_at = step.id
            why = unevaluated[blind[0]]
            results.append(
                StepResult(
                    step,
                    CANNOT_JUDGE,
                    f"{', '.join(blind)} reached no verdict here: {why}",
                    objects=tuple(present),
                )
            )
            continue

        hits = [f for r in step.rules for f in by_rule.get(r, ())]
        if hits:
            ids = ", ".join(sorted({str(f.get("ruleId")) for f in hits}))
            results.append(StepResult(step, FAILS, f"{ids} found something on this hop", tuple(hits), tuple(present)))
            continue

        if not step.rules:
            # An observable hop with no rule is a hop nothing READ, and the whole point of this walk is that
            # such a hop is not a hop that works. It reported `holds` with the words "no rule reads this hop"
            # beside it, and the path came out `complete` at exit 0 -- this product's one rule, broken inside
            # the feature built to show it. It did not bite on the shipped lesson, whose every observable step
            # names a rule, and it would have bitten on the first control-plane lesson, where the rules do not
            # exist (G387).
            stopped_at = step.id
            results.append(
                StepResult(step, CANNOT_JUDGE, "no rule in this build reads this hop", objects=tuple(present))
            )
            continue

        results.append(StepResult(step, HOLDS, f"{step.holds} ({', '.join(step.rules)})", objects=tuple(present)))

    judged = sum(1 for r in results if r.verdict in (HOLDS, FAILS))
    if stopped_at is not None:
        verdict, reason = "stopped", f"the walk stopped at `{stopped_at}`: that hop could not be judged"
    elif judged == 0:
        # Nothing on this path was judged, so there is no verdict about the path -- and the sentence that used to
        # be printed here, "every observable hop on this path holds", was VACUOUSLY true: there are no observable
        # hops, so all of them hold. A lesson whose every hop is `observable: false` came out `complete` at exit
        # 0, the same vacuous-truth failure this project has caught twice before (an empty `parametrize`
        # reporting one skipped test at exit 0; an empty list reading as clean). Zero of this build's rules read
        # the kubelet, the container runtime, cgroups, kube-proxy, iptables, conntrack, veth or the overlay, so a
        # Node-layer lesson could be marked unobservable hop by hop and ship a full green page (G395).
        #
        # `stopped_at` stays None on purpose. It names the hop the walk stopped AT, and every reader of it --
        # `render`, the published skill tables, an agent -- takes that hop to be the one that could not be judged
        # and the hops after it to be undrawn. Here no hop was the obstacle: each was honestly reported
        # `not-observable`, none was skipped, and naming the first would be a false statement about it. The
        # verdict and this reason carry the truth instead.
        verdict = "stopped"
        reason = (
            f"no hop on this path was judged: of {len(steps)} declared hop(s), "
            f"{sum(1 for r in results if r.verdict == NOT_OBSERVABLE)} are not observable and none was read by a "
            "rule in this build, so this walk reached no verdict about the path"
        )
    elif any(r.verdict == FAILS for r in results):
        broken = ", ".join(r.step.id for r in results if r.verdict == FAILS)
        verdict, reason = "broken", f"the walk reached the end; these hops are broken: {broken}"
    else:
        verdict, reason = "complete", "every observable hop on this path holds"

    return {
        "lesson": lesson.get("id"),
        "title": lesson.get("title"),
        "layer": lesson.get("layer"),
        "verdict": verdict,
        "verdictReason": reason,
        "stoppedAt": stopped_at,
        "steps": [r.as_dict() for r in results],
        "counts": {
            "declared": len(steps),
            "judged": judged,
            "notObservable": sum(1 for r in results if r.verdict == NOT_OBSERVABLE),
            "notReached": len(steps) - len(results),
        },
        "exitCode": EXIT[verdict],
    }


def _line(value: object) -> str:
    """One line, for a value that came out of the input.

    The stdout boundary cleans and marks characters; it cannot collapse a newline, because it has no way to
    tell a structural one from a smuggled one. That is each renderer's job, and `cli.py` does it for the audit
    with its own `_one_line`. This renderer printed `findings[].resource` and `findings[].title` raw, so a
    `metadata.name` holding newlines wrote whole lines of its own into the walk -- including a forged
    "every observable hop on this path holds" at column zero, where `audit` on the same file prints the name
    collapsed. G373's defect, one surface further out (G389).
    """
    return sanitize.one_line(str(value))[:200]


def render(walked: dict[str, Any]) -> str:
    """The same walk as text. The marks are words, not colour: a log keeps them and a pipe does not eat them."""
    mark = {HOLDS: "holds", FAILS: "BROKEN", CANNOT_JUDGE: "cannot judge", NOT_OBSERVABLE: "not checked"}
    out = [f"{_line(walked['title'])}  ({_line(walked['layer'])})", ""]
    for i, s in enumerate(walked["steps"], 1):
        out.append(f"{i}. [{mark[s['verdict']]}] {_line(s['title'])}")
        out.append(f"      {_line(s['why'])}")
        for f in s.get("findings") or ():
            out.append(
                f"      {_line(f['severity']).upper()}  {_line(f['ruleId'])}  "
                f"{_line(f['resource'])}  {_line(f['title'])}"
            )
    counts = walked["counts"]
    if counts["notReached"]:
        out += ["", f"{counts['notReached']} hop(s) after it were not walked and are not reported as working."]
    out += ["", _line(walked["verdictReason"])]
    return "\n".join(out)
