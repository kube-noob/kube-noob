"""Walk one mechanism's path against the reader's own manifests, and say where it stops.

Every other lesson in the curriculum teaches what to write and what passes. A mechanism lesson teaches what
happens, in order, and where it breaks -- and because kube-noob already knows the difference between "the rules
read this and it is fine" and "nothing read this", the walk can grade itself three-valued where a page of prose
cannot:

- **holds** -- the objects the hop needs are here, the rules that read them found nothing, and the step names them.
- **fails** -- a rule on this hop produced a finding, which is reported with its id.
- **cannot be judged** -- an object the hop needs is absent, refused or unreadable. The walk STOPS here. The hops
  after it are not drawn, because a hop nobody looked at is not a hop that works, and the verdict for the path is
  that no verdict was reached (exit 5), not that the path is fine -- unless a hop before it was already broken.
  Then the path's verdict was reached before the stop, and it is `broken` (exit 1) with the stop named beside it
  (G400).

This module adds no judgement of its own. It reads a report `analyze()` already produced: `resources` for what is
here, `notAudited` for what was refused, `findings` for what is wrong, and `notEvaluated` for the rules that
reached no verdict. That last one was missing, and the claim made here that the walk "cannot disagree with the
audit" was simply false: a Deployment with no pod template walked `complete` at exit 0 where `audit` exits 1,
and each hop cited as its proof the very rules the ledger lists as unevaluated (G389). The walk is a second
renderer over the same coverage ledger, and it has to read all of it.

**Which namespace a walk judges (G404).** One. A path runs inside a namespace -- an Ingress routes to a Service
of its own namespace, a Service selects pods of its own, a NetworkPolicy and a PodDisruptionBudget govern pods of
theirs -- and a hop used to look only for "an object of this KIND, anywhere in the report". So an Ingress and a
Service in `shop` beside a Deployment and a NetworkPolicy in `other` walked `complete` at exit 0, every hop
holding on objects the hop before it cannot reach. The walk now collects the namespace of every object of a kind
any observable hop names (`needs` or `reads`), reports them as `namespaces`, and prints them. Exactly one: that
is the namespace judged, and every hop's objects are in it by construction. More than one: the first hop says
`cannot judge`, names the namespaces, and the walk stops at exit 5 -- it does not pick one, because nothing in
the input says which the reader meant, and it does not judge each, because a hop's rules answer for the whole
report and not for one namespace of it. An object that states no namespace is counted as its own
(`(none stated)`), exactly as the rules count it: `kubectl apply -n` decides where it lands, and no manifest
records that.

**Where the walk and the audit may not disagree (G406).** "Cannot disagree with the audit" was restored by G389
for one shape and was false again in three more, each walking `complete` at exit 0 over bytes whose audit exits
1: a Deployment with no pod template BESIDE a healthy one (KN-V007 on an object two hops said they held on), a
duplicate `selector` key on the Service the Service hop held on (KN-V018, critical), and a single-replica Argo
Rollout that the audit names under `notAudited` and no hop looked at, because `Rollout` is in no hop's `reads`.
A hop read only the rules it lists; a rule outside the list, and an object of a kind outside the list, did not
exist for it. The claim is now exactly these three rules, and no wider:

1. **A hop does not hold on an object the validation stage calls malformed.** A finding whose `stage` is
   `validate` and whose `category` is `schema` -- a required field missing, a duplicate key, a duplicate object,
   an invalid name -- on an object of the hop's kinds, from a rule the hop does not list, makes the hop `cannot
   judge`: the object is not what the API server would accept as written, so what the hop's rules read from it
   is not established. Read from the finding's own fields, never from a list of rule ids kept here.
2. **A hop about workloads does not hold beside a pod spec nobody read.** A `notAudited` row whose reason is one
   of `rules.UNREAD_REASONS` (pods in a kind with no reader, a container where the reader does not look) is a
   workload the hop cannot see, whatever its kind is called, so every hop naming a workload kind is `cannot
   judge` and names the object.
3. **A walk is never `complete` where the audit of the same input is `undetermined`.** Whatever hops 1 and 2 did
   not catch -- an unread object of any other kind, a rule that declined on an object it was given -- is in
   `summary.verdict`, and the walk reads it: `stopped`, exit 5, with `stoppedAt` null because no hop was the
   obstacle. `broken` is unchanged, since a broken hop is a verdict more evidence cannot reverse.

What the walk still may do, on purpose: answer `complete` at 0 where `audit` exits 1 on a finding that is about
something other than this path -- a missing `seccompProfile`, a `latest` tag. The walk answers for one path, and
the audit's exit code answers for `--fail-on`.

**A fragment cannot show that something is missing (G408).** `partial_bundle` says the input is part of a
namespace. Most rules that fire on an ABSENT object decline there themselves (KN-N001, KN-C008), and the hop says
`cannot judge` through their `notEvaluated` entry. Three do not, because for `audit` their finding is a true
sentence about the objects in front of it -- "this Deployment runs 1 replica", "no pod template in this input
matches" -- and silencing them on every single-file audit would cost more than it saves: KN-C007 (excused by an
autoscaler that may be in another file), KN-V011 and KN-N012 (the pod they look for may be in another file). The
walk makes a stronger claim than the audit does -- BROKEN is a verdict about the PATH -- so it does not promote
such a finding to that verdict on a fragment. A lesson names those rules per hop (`absent:`), and on a fragment
a hop whose every finding is from one of them is `cannot judge`, with the findings still listed under it. A
finding from any other rule on the hop is BROKEN as before, fragment or not.

**A hop that names nothing to read holds on nothing (G408).** An observable hop must name at least one kind, in
`needs` or `reads`: a hop with neither could hold against an empty report, where no rule ran and so no rule is
listed as unevaluated. `walk` refuses such a lesson, and independently never holds a hop over a report that
lists no object at all.

The verdict obeys the same rule one level up: a walk that judged NO hop reached no verdict about the path, so it
is `stopped` at exit 5 however many hops it drew. "Every observable hop on this path holds" is vacuously true of
a path with no observable hops, and a lesson whose every hop was `observable: false` printed it at exit 0 (G395).
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field
from typing import Any

from kube_noob import sanitize
from kube_noob.audit.rules import UNREAD_REASONS, WORKLOAD_KINDS

#: A hop whose evidence a manifest cannot hold (a veth pair, an overlay hop). Marked in the curriculum, never
#: guessed here: the walker must never claim to have checked one, and must never count one as passed either.
NOT_OBSERVABLE = "not-observable"
HOLDS = "holds"
FAILS = "fails"
CANNOT_JUDGE = "cannot-judge"

#: The exit code each path verdict means, by the rule AGENTS.md publishes (G272): 1 is "a verdict was reached and it
#: is not a pass", 5 is "no verdict was reached". A broken hop IS a verdict about the path -- no hop after it can
#: make the path work -- so a walk that found one is `broken` at 1 whether or not it later stopped; the stop is
#: named beside it, never instead of it (G400). Only a walk that stopped before finding anything broken reached no
#: verdict, which is 5.
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
    #: The rules among `rules` whose FINDING rests on an object that is not in the input: an autoscaler nobody
    #: passed, a pod template in another file. On a fragment such a finding cannot make the hop BROKEN (G408).
    absent: tuple[str, ...] = ()
    observable: bool = True

    @classmethod
    def load(cls, raw: dict[str, Any]) -> Step:
        absent = tuple(str(r) for r in raw.get("absent") or ())
        stray = sorted(set(absent) - {str(r) for r in raw.get("rules") or ()})
        if stray:
            raise ValueError(f"step {raw.get('id')!r} lists {', '.join(stray)} under `absent` and not under `rules`")
        if raw.get("observable", True) and not (raw.get("needs") or raw.get("reads")):
            # A hop that reads no kind cannot say what it read, and held against an empty report (G408).
            raise ValueError(
                f"step {raw.get('id')!r} is observable and names no kind in `needs` or `reads`, so nothing "
                "would show it was read"
            )
        return cls(
            id=str(raw["id"]),
            title=str(raw["title"]),
            holds=str(raw.get("holds", "")),
            needs=tuple(str(k) for k in raw.get("needs") or ()),
            reads=tuple(str(k) for k in raw.get("reads") or raw.get("needs") or ()),
            rules=tuple(str(r) for r in raw.get("rules") or ()),
            absent=absent,
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


def lessons() -> dict[str, dict[str, Any]]:
    """Every lesson in the curriculum that declares a path, by id: the one lookup the command, the tool and the
    HTML view share, so none of them can walk or draw a lesson the others do not know."""
    from kube_noob.learn.tutor import curriculum

    return {
        str(lsn["id"]): lsn
        for trk in curriculum().get("tracks") or ()
        for lsn in trk.get("lessons") or ()
        if lsn.get("steps")
    }


#: One segment of an example path: what a fixture directory is called, and nothing a path could escape through.
_EXAMPLE_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9-]*\Z")


def examples(lesson: dict[str, Any]) -> tuple[str, ...]:
    """The worked examples a lesson names: directories of manifests, relative to the repository's `tests/fixtures`.

    Optional, and for whoever builds a page about the lesson -- the website listed each lesson's bundles by hand,
    so a new lesson had none until someone remembered. The wheel does not ship `tests/`, so a walk never opens
    these and never prints them; the repository's tests do, and hold each one to a directory that exists and
    walks to a verdict. What is checked here is the shape, as strictly as a step's: a list of distinct relative
    paths made of plain lowercase segments. No `..`, no leading `/`, no backslash, no address -- a value that
    is not such a path raises, because a reader that joins it to a directory would otherwise follow it.
    """
    raw = lesson.get("examples")
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{lesson.get('id')!r}: `examples` is a non-empty list of fixture directories, or is left out")
    for item in raw:
        if not isinstance(item, str) or not all(_EXAMPLE_SEGMENT.match(part) for part in item.split("/")):
            raise ValueError(
                f"{lesson.get('id')!r}: example {item!r} is not a relative path of lowercase segments "
                "(letters, digits and `-`, separated by `/`)"
            )
    if len(set(raw)) != len(raw):
        raise ValueError(f"{lesson.get('id')!r}: `examples` names a directory twice")
    return tuple(raw)


def _kind_of(resource: str) -> str:
    """`Deployment/shop/orders-api` -> `Deployment`. The report writes every resource in this one shape."""
    return resource.split("/", 1)[0]


#: The `stage` and `category` of a finding that says the OBJECT is not what the API server accepts as written.
MALFORMED = ("validate", "schema")

#: How the walk shows an object that states no namespace. Not `default`: the manifest does not say so.
NO_NAMESPACE = "(none stated)"


def _namespace_of(resource: str) -> str:
    """`Deployment/shop/orders-api` -> `shop`; `Deployment/orders-api` -> the object states none.

    The report writes a resource as one string, and a `/` inside a namespace or a name shifts its fields. Neither
    is valid, and neither may make two namespaces read as one. More than three fields means one of them holds a
    `/`, and which one is not recoverable, so everything after the kind is taken whole: it then equals no real
    namespace and no other object's, and the walk stops on more than one namespace instead of merging
    `shop/a` and `shop/b` into `shop`. Exactly three with the `/` in the NAME (and no namespace stated) is
    read as a namespace, and that object carries KN-V009 for its name, on which no hop holds (G406).
    """
    parts = resource.split("/")
    if len(parts) > 3:
        return "/".join(parts[1:])
    return parts[1] if len(parts) == 3 else NO_NAMESPACE


def walk(lesson: dict[str, Any], report: dict[str, Any], partial_bundle: bool = False) -> dict[str, Any]:
    """The lesson's path against one report, stopping at the first hop that cannot be judged.

    ``partial_bundle`` is what the caller told `analyze` about the same input: these documents are part of a
    namespace. It is passed and not read from the report, which records it only as a sentence for a person.
    """
    steps = [Step.load(s) for s in lesson.get("steps") or ()]
    if not steps:
        raise ValueError(f"{lesson.get('id')!r} declares no steps, so there is no path to walk")
    examples(lesson)  # shape only: a lesson whose `examples` is malformed is refused, as a malformed step is

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

    # What the audit says about an OBJECT rather than about a hop, which a hop that reads only its own rule ids
    # never saw (G406): the objects the validation stage calls malformed, and the pod specs nobody read.
    malformed: dict[str, list[dict[str, Any]]] = {}
    for f in report.get("findings") or ():
        if (f.get("stage"), f.get("category")) == MALFORMED:
            malformed.setdefault(str(f.get("resource")), []).append(f)
    unread_pods = [str(n.get("object")) for n in report.get("notAudited") or () if n.get("why") in UNREAD_REASONS]
    summary = report.get("summary") or {}
    undetermined = summary.get("verdict") == "undetermined"

    # The namespaces this path's objects are in: every object of a kind an observable hop names. `resources`
    # lists a refused object too, so one the rules could not read still counts towards where the path is.
    path_kinds = {k for s in steps if s.observable for k in (*s.needs, *s.reads)}
    namespaces = sorted({_namespace_of(o) for k in path_kinds for o in here.get(k, ())})

    results: list[StepResult] = []
    stopped_at: str | None = None
    for step in steps:
        if stopped_at is not None:
            break
        if not step.observable:
            results.append(StepResult(step, NOT_OBSERVABLE, step.holds))
            continue

        if len(namespaces) > 1:
            # Before anything else about the first observable hop, because every later question -- is the
            # object here, did a rule read it -- is asked of the whole report, and the whole report is more
            # than one path. Quoted for the reason given below: a namespace is the input's own text.
            stopped_at = step.id
            named = ", ".join(repr(n) for n in namespaces)
            scattered = tuple(o for k in dict.fromkeys((*step.needs, *step.reads)) for o in here.get(k, ()))
            results.append(
                StepResult(
                    step,
                    CANNOT_JUDGE,
                    f"the objects this path reads are in {len(namespaces)} namespaces ({named}); a path runs in "
                    "one and a walk judges one, so no hop was judged -- pass the manifests of one namespace",
                    objects=scattered,
                )
            )
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

        if unread_pods and any(k in WORKLOAD_KINDS for k in (*step.needs, *step.reads)):
            # A workload this hop is about may be exactly the one nobody read: an Argo Rollout at one replica
            # is the workload a lost node takes down, and "no replicated workload here is left at a single
            # replica" was printed beside it because `Rollout` is in no hop's `reads`.
            stopped_at = step.id
            shown = ", ".join(repr(o) for o in unread_pods[:3])
            more = f" and {len(unread_pods) - 3} more" if len(unread_pods) > 3 else ""
            results.append(
                StepResult(
                    step,
                    CANNOT_JUDGE,
                    f"{shown}{more} holds pods nothing read, and may be the workload this hop is about",
                    objects=tuple(unread_pods),
                )
            )
            continue

        present = [o for k in step.needs for o in here.get(k, ())]
        if step.needs and not present:
            stopped_at = step.id
            kinds = " or ".join(step.needs)
            results.append(StepResult(step, CANNOT_JUDGE, f"no {kinds} in the input, so this hop was not judged"))
            continue

        if not here:
            # No object at all: `analyze` returns before any rule runs, so `notEvaluated` is empty too and
            # every rule would read as silent. A hop with no `needs` reached `holds` from here (G408).
            stopped_at = step.id
            results.append(StepResult(step, CANNOT_JUDGE, "the input holds no object, so no rule read anything"))
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
        if hits and partial_bundle and all(str(f.get("ruleId")) in step.absent for f in hits):
            # Every finding on this hop is from a rule that fires on what is NOT in the input, and the input is
            # a fragment: the autoscaler, or the pod the Service selects, may be in the file nobody pasted. The
            # findings are shown, and the hop is not called BROKEN on evidence that cannot say so (G408).
            stopped_at = step.id
            ids = ", ".join(sorted({str(f.get("ruleId")) for f in hits}))
            results.append(
                StepResult(
                    step,
                    CANNOT_JUDGE,
                    f"{ids} found something, and it rests on an object that is not in this input; part of a "
                    "namespace was passed, so the input cannot show that object is missing -- pass the whole "
                    "namespace (a directory, or partial_bundle=false) for a verdict on this hop",
                    tuple(hits),
                    tuple(present),
                )
            )
            continue
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

        # Last, after the hop's own rules have spoken: a finding of theirs is a verdict and stays BROKEN.
        read_here = [o for k in dict.fromkeys((*step.needs, *step.reads)) for o in here.get(k, ())]
        odd = [f for o in read_here for f in malformed.get(o, ()) if str(f.get("ruleId")) not in step.rules]
        if odd:
            stopped_at = step.id
            ids = ", ".join(sorted({str(f.get("ruleId")) for f in odd}))
            results.append(
                StepResult(
                    step,
                    CANNOT_JUDGE,
                    f"{ids} says an object this hop reads is not what the API server accepts as written, so what "
                    "the hop's rules read from it is not established",
                    tuple(odd),
                    tuple(present),
                )
            )
            continue

        results.append(StepResult(step, HOLDS, f"{step.holds} ({', '.join(step.rules)})", objects=tuple(present)))

    judged = sum(1 for r in results if r.verdict in (HOLDS, FAILS))
    broken = ", ".join(r.step.id for r in results if r.verdict == FAILS)
    if broken and stopped_at is not None:
        # A broken hop followed by one nothing could judge. This was `stopped` at exit 5 with a reason naming only
        # the stop, so the one thing the walk had established -- this path does not work -- was in neither the
        # verdict, the exit code nor the sentence a reader acts on. Measured on the node-dark lesson against the
        # shipped fixtures: KN-C010 BROKEN at hop 2, KN-C009 unable to judge hop 3, and the walk said only that it
        # stopped. No hop after a broken one can make the path work, so the path verdict is reached and it is
        # `broken`; the stop still names its hop in `stoppedAt` and the hops after it are still not walked (G400).
        verdict = "broken"
        reason = (
            f"these hops are broken: {broken}; the walk then stopped at `{stopped_at}`: that hop could not be "
            f"judged, so {len(steps) - len(results)} hop(s) after it were not walked"
        )
    elif stopped_at is not None:
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
    elif broken:
        verdict, reason = "broken", f"the walk reached the end; these hops are broken: {broken}"
    elif undetermined:
        # Every hop that was read holds, and the audit of these same bytes reached no verdict: an object was not
        # read, or a rule declined on one it was given. The hops are true as far as they go, and the path is not
        # shown to be whole, so this is not `complete` (G406). `stopped_at` stays None for G395's reason: no hop
        # was the obstacle, and naming one would be a false statement about it. Objects are quoted and bounded;
        # the audit's own `verdictReason` is not repeated here, because it is built for the audit's renderer.
        unaudited = [str(n.get("object")) for n in report.get("notAudited") or () if not n.get("acceptedBy")]
        named = ", ".join(repr(o) for o in unaudited[:3])
        more = f" and {len(unaudited) - 3} more" if len(unaudited) > 3 else ""
        what = (
            f"{len(unaudited)} object(s) in it were not audited ({named}{more})"
            if unaudited
            else "a rule declined on an object it was given"
        )
        verdict = "stopped"
        reason = (
            f"every hop this walk read holds, but the audit of the same input is undetermined: {what}. A walk "
            "does not call a path complete over an input the audit could not decide; run `kube-noob audit` on it"
        )
    else:
        verdict, reason = "complete", "every observable hop on this path holds"

    return {
        "lesson": lesson.get("id"),
        "title": lesson.get("title"),
        "layer": lesson.get("layer"),
        "verdict": verdict,
        "verdictReason": reason,
        "stoppedAt": stopped_at,
        # Every namespace holding an object this path reads. One entry is the namespace that was judged; more
        # than one is why nothing was (G404). Empty when the input holds no object of the path at all.
        "namespaces": namespaces,
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


def _wrapped(value: object, indent: str = "      ", width: int = 116, limit: int = 4000) -> list[str]:
    """A hop's explanation, wrapped instead of cut.

    `_line` cut every value at 200 characters with no mark, and a hop's `why` is mostly the curriculum's own
    `holds` sentence -- whose last clause is where each hop states its limit ("KN-S014 does not read a projected
    serviceAccountToken volume", "a role of the same reach under another name is not what KN-S016 reads"). Cut
    there, the hold read stronger than the lesson wrote it, and nothing said a word was missing: six of the RBAC
    lesson's seven hops and one node-dark hop lost their caveat (G411). The text is wrapped onto indented lines,
    so it still cannot reach column zero, and a value longer than `limit` -- only input can be that long -- says
    how much was cut.
    """
    text = sanitize.one_line(str(value))
    if len(text) > limit:
        text = f"{text[:limit]} [cut: {len(text) - limit} more characters]"
    return textwrap.wrap(
        text, width=width, initial_indent=indent, subsequent_indent=indent, break_on_hyphens=False
    ) or [indent.rstrip()]


def render(walked: dict[str, Any]) -> str:
    """The same walk as text. The marks are words, not colour: a log keeps them and a pipe does not eat them."""
    mark = {HOLDS: "holds", FAILS: "BROKEN", CANNOT_JUDGE: "cannot judge", NOT_OBSERVABLE: "not checked"}
    out = [f"{_line(walked['title'])}  ({_line(walked['layer'])})"]
    spaces = walked.get("namespaces") or ()
    if spaces:
        # Which namespace the hops below are about, in the reader's first three lines and not only in JSON.
        word = "namespace judged" if len(spaces) == 1 else "namespaces in the input (none judged)"
        out.append(f"{word}: {_line(', '.join(repr(n) for n in spaces))}")
    out.append("")
    for i, s in enumerate(walked["steps"], 1):
        out.append(f"{i}. [{mark[s['verdict']]}] {_line(s['title'])}")
        out.extend(_wrapped(s["why"]))
        for f in s.get("findings") or ():
            out.append(
                f"      {_line(f['severity']).upper()}  {_line(f['ruleId'])}  "
                f"{_line(f['resource'])}  {_line(f['title'])}"
            )
    counts = walked["counts"]
    if counts["notReached"]:
        out += ["", f"{counts['notReached']} hop(s) after it were not walked and are not reported as working."]
    # The verdict line stays one line, uncut: a reader and a script both take the last line as the answer, and
    # every word of it is built here from the curriculum's own step ids, never from the input.
    out += ["", sanitize.one_line(str(walked["verdictReason"]))]
    return "\n".join(out)
