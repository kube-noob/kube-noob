"""One declaration of what a rule's verdict rests on besides its subject, and one check of it (G369).

Its own module, not part of `rules.py`, for the same reason `cprules.py`, `argv.py` and `cpflags.py` are: the
generated plugin copy of a module may not exceed 256 KiB (`scripts/sync_plugin_server.py`, the plugin
directory's own limit), and `rules.py` was 3.5 KiB under it. Nothing here is new behaviour on its own; it is the
`_PARTNER_KINDS` block moved whole and joined with `context=`.

`rules.py` imports this module at the END of its own body and calls `check_evidence` from `run_rules`. The
import is circular by construction -- the check needs `AuditContext`, `RULES` and `object_unreadable`, which
live there -- and it resolves because `rules.py` is fully built by the time that last line runs. So nothing else
should import this module expecting it to bring the rules: import `kube_noob.audit.rules`.

**The defect this joins.** A rule that reads an object it does not judge declared that dependency TWICE:

- `context=` on eight rules, which drives the "evaluated without X" record (`absent_subjects` ->
  `rulesEvaluatedWithout`), checked by G368 against a refused apiVersion group and nothing else;
- `_PARTNER_KINDS` on ten rules, which drives `partner_unreadable`, checked against `object_unreadable` -- a
  field of the wrong type -- and never against a refusal.

They overlapped in exactly one rule, KN-C008, so which half of one question a rule got asked depended on which
list it happened to be in. Measured on one Deployment in `prod` with three replicas, one readable `policy/v1`
PodDisruptionBudget that permits a disruption and one refused `policy.k8s.io/v1` PodDisruptionBudget whose
`minAvailable: 3` on three replicas is the exact thing KN-C009 exists to catch: KN-C009 was in neither
`rulesNotEvaluated` nor `partlyEvaluatedRules` and produced no finding, which is how the control summary counts a
rule checked-and-clean -- over a bundle whose own `notAudited` block names a PodDisruptionBudget nothing read.
Class 9, two sources of truth for one question, with neither of them whole.

`evidence_kinds` is the one declaration and `AuditContext.cannot_judge_absence` the one check. Both predicates
run there, and each document is explained by the predicate that caught it: `refused_summary` for a refused
apiVersion group, and `partner_unreadable`'s channel -- whose published prose is "a field in the input has the
wrong type for what the rule reads ... Fix the field (the schema findings name it)" -- for a field of the wrong
type, which is what that sentence is about. Letting a refused group borrow it would print a true verdict under a
false explanation, which is the G368 defect one layer down.
"""

from __future__ import annotations

from kube_noob.audit.podspec import EMBEDDED_POD_SPEC_PATHS, POD_SPEC_PATHS
from kube_noob.audit.rules import (
    ANY_OBJECT,
    RULES,
    WORKLOAD_SUBJECT,
    AuditContext,
    object_unreadable,
    refusal,
    refused_summary,
)
from kube_noob.yamlio import Document

_WORKLOAD_KINDS = frozenset(POD_SPEC_PATHS) | frozenset(EMBEDDED_POD_SPEC_PATHS)
# The kinds a rule reads as evidence BESIDE the ones its `context=` declares -- the PDB that selects a workload,
# the HPA that scales it. With `context=`, read through `evidence_kinds`, this is ONE declaration of one question,
# checked in ONE place (`cannot_judge_absence`) against BOTH unreadability predicates (G369). It was two:
# `context=` on eight rules asked only about a refused apiVersion and `_PARTNER_KINDS` on ten only about
# `object_unreadable`, they overlapped in one rule, and which half of the question a rule got asked depended on
# which list it was in -- class 9, with neither list whole. Nothing here repeats a kind a rule declares itself.
_EVIDENCE_KINDS: dict[str, frozenset[str]] = {
    "KN-C009": frozenset({"PodDisruptionBudget"}),
    "KN-C012": frozenset({"HorizontalPodAutoscaler"}),
    "KN-C014": frozenset({"HorizontalPodAutoscaler"}),
    "KN-C013": frozenset({"Secret", "ServiceAccount"}),
    "KN-V011": frozenset({"Service"}),
    "KN-V012": frozenset({"Service"}),
    "KN-V023": frozenset({"Service"}),
    "KN-N012": frozenset({"NetworkPolicy"}),
    "KN-ST002": frozenset({"PersistentVolumeClaim"}),
}
# The rules whose verdict also rests on reading the WORKLOAD they judge: a field of the wrong type in the pod
# template is what a PDB selects and what an HPA targets, so the rule cannot tell "no match" from "a match I
# could not read" (G276). Their own subject, not their evidence -- refusal of a subject is the subject gate's
# answer -- so only the malformed-shape predicate is asked here. KN-C008 declares its PDB in `context=`.
_READS_THE_WORKLOAD_IT_JUDGES: frozenset[str] = frozenset(_EVIDENCE_KINDS) | {"KN-C008"}


def evidence_kinds(rule_id: str) -> frozenset[str]:
    """Every kind ``rule_id`` reads as evidence without judging it: its `context=` and `_EVIDENCE_KINDS`, joined.

    The ONE answer to "what does this rule's verdict rest on besides its subject" (G369). `ANY_OBJECT` and the
    pod-spec subject stand for sets of kinds rather than one, so no refusal of one document explains an absence
    of either and neither is evidence here.
    """
    rule = RULES.get(rule_id)
    declared = frozenset(rule.context) if rule is not None else frozenset()
    return (declared | _EVIDENCE_KINDS.get(rule_id, frozenset())) - {ANY_OBJECT, WORKLOAD_SUBJECT}


def check_evidence(ctx: AuditContext, rule_id: str) -> None:
    """Both unreadability predicates against the ONE declaration of this rule's evidence (G369).

    `cannot_judge_absence` is the check the `context=` loop in `run_rules` calls too, and it is idempotent, so
    a kind declared either way is asked the same question and no object is recorded twice.
    """
    ctx.cannot_judge_absence(rule_id, *evidence_kinds(rule_id))
    if rule_id in _READS_THE_WORKLOAD_IT_JUDGES:
        for d in ctx.docs:
            known = isinstance(d.data, dict) and isinstance(d.data.get("kind"), str)
            if (not known or d.kind in _WORKLOAD_KINDS) and object_unreadable(d.data):
                meta_ok = isinstance(d.data, dict) and object_unreadable({**d.data, "spec": None}) is None
                ctx.partner_unreadable(rule_id, d.ref() if meta_ok else f"document {d.index + 1}")
    refs = ctx.unreadable_partners.get(rule_id)
    if refs:
        names = sorted(refs)
        more = f" and {len(names) - 10} more" if len(names) > 10 else ""
        note = f"an object it depends on could not be read: {', '.join(names[:10])}{more}"
        prior = ctx.unreadable_shapes.get(rule_id)
        ctx.unreadable_shapes[rule_id] = f"{prior}; {note}" if prior else note


def unreadable_evidence(
    ctx: AuditContext, *kinds: str, namespace: str | None = None, name: str | None = None
) -> list[Document]:
    """The objects of these kinds the input HOLDS and nothing read, optionally narrowed to one namespace.

    A rule that reasons from the absence of a kind asks `by_kind` or `has_subject`, and both are
    group-matched (G231, G365): a `projectcalico.org/v3 NetworkPolicy` is correctly not a Kubernetes
    NetworkPolicy, and is therefore indistinguishable there from no NetworkPolicy at all. It is not the
    same thing -- the bundle holds one and the audit refused it, and the report names it under
    `notAudited` -- so the two answers are separated here (G368).

    Matched on the kind NAME, not through a group, because the group is exactly what is wrong. Both
    unreadability predicates count: `refusal` for an apiVersion the rules do not know the kind under, and
    `object_unreadable` for a document whose identity or spec cannot be read at all.

    ``name`` narrows it to the object a finding names, that finding's own granularity (G369). Identity is
    the line: a refused object's name is a fact (`notAudited` prints it) where its spec is not, and an
    unreadable identity matches every name, because the rule cannot then tell it apart.
    """
    out: list[Document] = []
    for d in ctx.docs:
        if not isinstance(d.data, dict) or not isinstance(d.data.get("kind"), str):
            continue
        if d.kind not in kinds:
            continue
        if refusal(d) is None and object_unreadable(d.data) is None:
            continue
        if namespace is not None and ctx.ns(d) != namespace:
            continue
        if name is not None and d.name and d.name != name:
            continue
        out.append(d)
    return out


def cannot_judge_absence(
    ctx: AuditContext,
    rule_id: str,
    *kinds: str,
    namespace: str | None = None,
    name: str | None = None,
    suppresses_finding: bool = False,
) -> bool:
    """Whether ``rule_id`` may state that no object of ``kinds`` is here; records the refusal when it may not.

    True means the input holds such an object and nothing read it, so an absence is not a fact the rule
    has: the rule is undecided, the object is named, and the score is withheld. A namespace narrows it,
    because a refusal in one namespace must not blind the rule in another (G366: the guard has to be at
    the granularity of the thing it guards).

    Through `cannot_decide` with `refused_summary`, NOT through `partner_unreadable`: that path composes
    its reason into `unreadable_shapes`, whose published prose is "a field in the input has the wrong type
    for what the rule reads ... Fix the field (the schema findings name it)". A refused apiVersion group is
    not a field of the wrong type and the fix is not a field, so borrowing that channel would have printed
    a true verdict under a false explanation -- the defect this method exists to remove, one layer down.
    `refused_summary` is the phrase a refused SUBJECT already produces ("1 NetworkPolicy not audited
    (apiVersion names a group ...)"), built from the rule's kinds and the fixed refusal reasons and never
    from the input's own text (class 7).

    A MALFORMED object takes the other channel, and this is the ONE place that chooses (G369): the reason
    follows the DOCUMENT, not the declaration it came from, so each is explained by the predicate that
    caught it and neither borrows the other's words.

    ``suppresses_finding`` is True where a RULE calls this instead of yielding, False where the engine only
    records the gap. It decides whether an acceptance may restore the score (G379).
    """
    blind = ctx.unreadable_evidence(*kinds, namespace=namespace, name=name)
    if blind and suppresses_finding:
        ctx.finding_suppressed.add(rule_id)
    for d in blind:
        if refusal(d) is not None:
            ctx.cannot_decide(rule_id, refused_summary([d]), d.ref())
        else:
            # By position when its own metadata cannot be read, as `check_evidence` does: the same ref,
            # so the two callers cannot record one object twice under two names.
            meta_ok = isinstance(d.data, dict) and object_unreadable({**d.data, "spec": None}) is None
            ctx.partner_unreadable(rule_id, d.ref() if meta_ok else f"document {d.index + 1}")
    return bool(blind)
