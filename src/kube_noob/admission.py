"""``kube-noob-admission``: a validating admission webhook for kube-noob's rules (requirements R3.3, tier A).

It answers ``admission.k8s.io/v1`` AdmissionReview requests (contract read from kubernetes/api
``admission/v1/types.go``): every finding of the admitted object becomes an admission warning ("Limit warnings to 120
characters if possible. Warnings over 256 characters and large numbers of warnings may be truncated."), and a request
is denied only for a rule the operator listed in ``admission.enforce``. It never mutates: no response carries a patch.

- Warn mode (no rule enforced) cannot deny: the only path to ``allowed: false`` needs a finding of an enforced rule.
- On UPDATE, an enforced rule denies only a finding the old object did not have, so turning a rule to enforce never
  freezes the workloads that already break it; they keep getting warnings.
- Skipped: DELETE and CONNECT, subresources (status, scale, exec), objects being deleted (an UPDATE), the system
  namespaces (``kube-system``, ``kube-public``, ``kube-node-lease``; also ``openshift`` and ``openshift-*``, only
  when the platform is in the OpenShift family AND the chart found the OpenShift APIs on the cluster),
  ``admission.excludedNamespaces``, and the Pods, ReplicaSets and Jobs that kube-controller-manager's
  own controllers make from a Deployment, StatefulSet, DaemonSet, CronJob, ReplicaSet or Job (that owner was checked).
- Nothing the requester writes decides whether the webhook looks. ``ownerReferences`` is the requester's to write, so
  it skips nothing by itself: the child is skipped only when ``request.userInfo``, which the API server writes from
  the authenticated identity, is one of ``CONTROLLER_USERS`` (G440).
- Rules about a whole bundle or that the API server already enforces are not evaluated (``SKIPPED_RULES``); rules
  that need other objects of the namespace (``CROSS_OBJECT``) run only with ``admission.lookups`` (a cache of the
  namespace's PodDisruptionBudgets, NetworkPolicies, PersistentVolumeClaims, HorizontalPodAutoscalers and the
  StorageClasses, read through the read-only backend and refreshed in the background with jitter) and can never be
  enforced: whether the other object exists yet depends on the order of a ``kubectl apply``.
- A request the webhook did not evaluate is never answered ``allowed: true`` and nothing else (G441). Not
  evaluated means: larger than ``MAX_BODY``, not an AdmissionReview, an object of more than ``MAX_OBJECT_NODES``
  values, an evaluation that raised, or one that did not finish inside ``Config.deadline`` (three fifths of the
  chart's ``timeoutSeconds``, so the answer leaves before the API server stops waiting). In warn mode, which cannot
  deny, it is admitted with a warning that says it was not judged; with a rule enforced it is denied with the
  reason, because an object nobody judged has not passed. What the webhook cannot answer at all -- it is down, or
  the network is -- is the chart's ``admission.failurePolicy``: ``Ignore`` admits, ``Fail`` refuses.
- Active entries of ``admission.exceptionsFile`` (the same ExceptionList as ``kube-noob audit --exceptions``) hide the
  findings they cover.
"""

from __future__ import annotations

import asyncio
import random
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kube_noob import sanitize
from kube_noob.catalog import OPENSHIFT_FAMILY

API_VERSION = "admission.k8s.io/v1"
MAX_BODY = 4_000_000  # bytes: the API server's object limit plus the review envelope
#: The most values (mappings, lists and scalars, each counted once) an object may hold and still be evaluated.
#: Bytes are the wrong measure: a megabyte of annotation is one value and costs nothing, while a megabyte of
#: containers is 16,000 of them and every container rule visits each. Measured on the build machine after G441,
#: the worst shape found -- a Pod of nothing but privileged containers, nine findings apiece -- costs about 26
#: microseconds a value, so an object at this budget is evaluated in about half a second and an update (the old
#: object is evaluated too) in about one: inside the 1.8 s deadline of the default `timeoutSeconds: 3` with room
#: for a machine three times slower. For scale: a Deployment of twenty containers with a hundred environment
#: variables each is about 6,000 values. The budget is not a claim about bytes; it is the largest object whose
#: answer can be promised in time.
MAX_OBJECT_NODES = 20_000
#: How much of the API server's `timeoutSeconds` the webhook may use before it answers "not evaluated". The rest
#: is the connection, the TLS handshake, the request and the response on the wire, and a queue.
DEADLINE_FRACTION = 0.6
#: Every answer for a request that was not evaluated carries a warning that starts with this.
NOT_EVALUATED = "kube-noob: not evaluated"
WARNING_CHARS = 256
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
#: Reserved on the OpenShift family only, where the platform refuses the name and the prefix to its users (a project
#: request for `openshift-x` is forbidden) and its operators live there. Plain Kubernetes reserves neither, so
#: whoever may create a namespace there could name it `openshift-x` and step outside every enforced rule (G440).
#: "On OpenShift" needs evidence, not the configured platform alone: see `Config.openshift_reserved`.
OPENSHIFT_NAMESPACES = frozenset({"openshift"})
OPENSHIFT_PREFIXES = ("openshift-",)
SKIP_OPERATIONS = frozenset({"DELETE", "CONNECT"})
OWNED_KINDS = frozenset({"Pod", "ReplicaSet", "Job"})
#: Who may be believed about `ownerReferences`: the controllers of kube-controller-manager that make the three
#: kinds above from a workload the webhook is sent -- under their own ServiceAccounts, and under the manager's one
#: identity when it runs without `--use-service-account-credentials`. `request.userInfo` is written by the API
#: server from the authenticated identity; holding one of these means a kube-system ServiceAccount token, the
#: manager's client certificate or the right to impersonate it, each of which already is the cluster. Deliberately
#: absent: `replication-controller` (a ReplicationController is not a kind the webhook is sent, so nothing judged
#: its template) and every operator's ServiceAccount (its custom resource was not judged either: G234).
CONTROLLER_USERS = frozenset(
    {
        "system:kube-controller-manager",
        "system:serviceaccount:kube-system:replicaset-controller",
        "system:serviceaccount:kube-system:statefulset-controller",
        "system:serviceaccount:kube-system:daemon-set-controller",
        "system:serviceaccount:kube-system:job-controller",
        "system:serviceaccount:kube-system:deployment-controller",
        "system:serviceaccount:kube-system:cronjob-controller",
    }
)
#: The owners whose pod template those controllers copy, every one of them a resource in the chart's webhook rules.
CHECKED_OWNERS = frozenset({"ReplicaSet", "StatefulSet", "DaemonSet", "Job", "Deployment", "CronJob"})
OWNER_API_VERSIONS = frozenset({"apps/v1", "batch/v1"})
#: The one subresource worth evaluating. `kubectl debug` adds an ephemeral container through
#: `pods/ephemeralcontainers`, which is a different admission request from the Pod's own creation: a policy that
#: matches `pods` never sees it, so a privileged debug container from an unapproved registry walked past every
#: rule that had just refused the same container in a Deployment (R7, G250). Every other subresource -- status,
#: exec, log, portforward -- is somebody else's business and stays skipped.
SUBRESOURCES = frozenset({"ephemeralcontainers"})
SKIPPED_RULES = frozenset(
    {
        "KN-V001",  # the API server refuses objects without apiVersion, kind or name
        "KN-V002",
        "KN-V003",
        "KN-V005",
        "KN-V006",
        "KN-V009",
        "KN-V010",
        "KN-ST005",
        "KN-C006",
        "KN-V004",  # a fact about the cluster's operators, not one object
        "KN-V011",  # needs pods that are created after the Service
        "KN-N012",  # needs pods that are created after the NetworkPolicy
        "KN-V012",
        "KN-V023",  # same: the containerPorts the Service's pods declare are in other objects
        "KN-V024",  # needs the Service an Ingress names: another object, usually admitted after the Ingress
        "KN-V025",  # the API server refuses a floor above the ceiling itself; the target is another object
        "KN-V026",  # the API server refuses a mount that names no volume of the pod itself
        "KN-V027",  # needs the Service a StatefulSet names: another object, often admitted after it
        "KN-N014",  # needs the cluster's CNI and version, which no admitted object carries
        "KN-V014",  # bundle properties
        "KN-V018",
        "KN-S018",  # every Secret in a cluster holds data: the rule is about Git
        "KN-C013",  # needs Secrets of other namespaces, which kube-noob never reads
        # The context cache fetches PDBs, NetworkPolicies, PVCs, HPAs and StorageClasses and nothing else, so
        # with lookups on this rule warned that a ResourceClaim was missing from a bundle it never looked in --
        # on every correct DRA Pod. Fetching them would need get and list on resourceclaims, a privilege the
        # chart does not grant and should not need for a warning `kube-noob audit` already gives on a directory.
        "KN-C015",
        # The same, for the same reason: the context cache fetches no ConfigMaps, Secrets or
        # ServiceAccounts, so with lookups this rule would warn that a ConfigMap is missing from a bundle
        # it never looked in -- on every correct Pod. Reading them would need get and list on secrets,
        # which the chart must never grant. `kube-noob audit` gives the warning on a directory (G396).
        "KN-C017",
        # The kubelet runs a static Pod from a file on the node and the API server holds only its mirror, which
        # cannot stop it: denying the mirror would leave kube-apiserver or etcd running and the request retried.
        # `kube-noob audit` reads the manifest itself (G272).
        "KN-S038",
        "KN-S039",
    }
)
CROSS_OBJECT = frozenset(
    {"KN-N001", "KN-N013", "KN-C008", "KN-C009", "KN-ST001", "KN-ST002", "KN-C012", "KN-C014", "KN-C016"}
)
CONTEXT_RESOURCES = ("poddisruptionbudgets", "networkpolicies", "persistentvolumeclaims", "horizontalpodautoscalers")
CONTEXT_KINDS = {
    "poddisruptionbudgets": "PodDisruptionBudget",
    "networkpolicies": "NetworkPolicy",
    "persistentvolumeclaims": "PersistentVolumeClaim",
    "horizontalpodautoscalers": "HorizontalPodAutoscaler",
    "storageclasses": "StorageClass",
}


class AdmissionConfigError(ValueError):
    """A configuration the webhook refuses to start with."""


@dataclass(frozen=True)
class Config:
    enforce: frozenset[str] = frozenset()
    excluded: frozenset[str] = frozenset()
    platform: str = "kubernetes"
    version: str | None = None
    max_warnings: int = 10
    exceptions: Any = None  # a reviewed ExceptionList (kube_noob.audit.exceptions.Review)
    lookups: bool = False
    #: `audit.allowedRegistries` from the same configuration file. KN-S036 is the one rule whose answer is a
    #: policy rather than a property of the object, so with no list the rule declines (it reports nothing and is
    #: not recorded as checked) and enforcing it is refused below rather than enforcing nothing (R3c, G243).
    allowed_registries: tuple[str, ...] = ()
    #: The webhook configuration's `timeoutSeconds`: how long the API server waits. The chart writes the same value
    #: into both, so the server knows when its answer stops being read (G441).
    timeout_seconds: float = 3.0
    #: Whether `openshift` and `openshift-*` are namespaces the platform reserves on THIS cluster. `platform` cannot
    #: say: it is a declaration, and the chart's default one, so a default install on plain Kubernetes declared
    #: `openshift` and the prefix was skipped there for whoever could name a namespace. The server cannot find out
    #: either -- it is offline, read-only and holds no credential unless lookups are on -- so it does not guess:
    #: False, which judges those namespaces, unless the chart writes `admission.openshiftNamespacesReserved: true`
    #: from what the cluster served at install (`.Capabilities.APIVersions`). Both are required (G440).
    openshift_reserved: bool = False

    @property
    def deadline(self) -> float:
        """Seconds from a request's arrival after which the answer is "not evaluated" rather than late."""
        return self.timeout_seconds * DEADLINE_FRACTION

    @classmethod
    def build(
        cls,
        *,
        enforce: list[str] | tuple[str, ...] = (),
        excluded: list[str] | tuple[str, ...] = (),
        platform: str = "kubernetes",
        version: str | None = None,
        max_warnings: int = 10,
        exceptions_text: str | None = None,
        lookups: bool = False,
        allowed_registries: list[str] | tuple[str, ...] = (),
        timeout_seconds: float = 3.0,
        openshift_reserved: bool = False,
    ) -> Config:
        from kube_noob.audit.rules import RULES

        unknown = sorted(set(enforce) - set(RULES))
        if unknown:
            raise AdmissionConfigError(f"admission.enforce names unknown rules: {', '.join(unknown)}")
        bad = sorted(set(enforce) & (SKIPPED_RULES | CROSS_OBJECT))
        if bad:
            raise AdmissionConfigError(
                f"admission.enforce cannot enforce {', '.join(bad)}: these rules need other objects or the whole "
                "bundle (they warn with admission.lookups, or kube-noob audit checks them)"
            )
        if "KN-S036" in enforce and not [e for e in allowed_registries if e.strip()]:
            # Fail at startup, not quietly at admission: `enforce: [KN-S036]` with no allowlist would deny
            # nothing while the chart said a registry policy was being enforced (G243).
            raise AdmissionConfigError(
                "admission.enforce includes KN-S036 but audit.allowedRegistries is empty: name the registries "
                "you approve (quay.io, or quay.io/my-org to narrow it to one organisation) or drop the rule"
            )
        if not 1 <= max_warnings <= 50:
            raise AdmissionConfigError("admission.maxWarnings must be 1-50")
        if not 1 <= timeout_seconds <= 30:
            raise AdmissionConfigError("admission.timeoutSeconds must be 1-30 (the API server's own limits)")
        review = None
        if exceptions_text is not None:
            from kube_noob.audit import exceptions as exc

            review = exc.review(exceptions_text)
            refused = [e for e in review.entries if e.status == "refused"]
            if refused:
                raise AdmissionConfigError(
                    f"admission.exceptionsFile has refused entries ({', '.join(e.id for e in refused[:5])}): fix them "
                    "with kube-noob exceptions check"
                )
        return cls(
            frozenset(enforce),
            frozenset(excluded),
            platform,
            version,
            max_warnings,
            review,
            lookups,
            tuple(allowed_registries),
            float(timeout_seconds),
            openshift_reserved is True,
        )


def _response(uid: str, allowed: bool, warnings: list[str], message: str | None = None) -> dict[str, Any]:
    resp: dict[str, Any] = {"uid": uid, "allowed": allowed}
    if warnings:
        resp["warnings"] = warnings
    if not allowed:
        resp["status"] = {"code": 403, "reason": "Forbidden", "message": message or "denied by kube-noob"}
    return {"apiVersion": API_VERSION, "kind": "AdmissionReview", "response": resp}


def _warning(text: str) -> str:
    clean = " ".join(str(text).split())
    return clean if len(clean) <= WARNING_CHARS else clean[: WARNING_CHARS - 3].rstrip() + "..."


#: The clock deadlines are read from. A name of its own so a test can move it.
_now = time.monotonic


def _not_evaluated(uid: str, cfg: Config, why: str) -> dict[str, Any]:
    """The answer for a request that was not judged: a denial when a rule is enforced, a warning when none is.

    Every such path used to end in "...; admitted", whatever was enforced, so anything that kept the webhook from
    reading a request -- a megabyte of containers, a body over the limit, a rule that raised on a shape the
    requester chose -- was a way past `admission.enforce` (G441). Warn mode keeps its promise that it never
    denies. `why` is this module's own wording, never the request's."""
    if not cfg.enforce:
        return _response(
            uid,
            True,
            [_warning(f"{NOT_EVALUATED}, so this is not a clean result: {why}; admitted, no rule is enforced")],
        )
    rules = ", ".join(sorted(cfg.enforce))
    message = (
        f"kube-noob did not evaluate this request ({why}), and an object that was not judged has not passed. "
        f"Denied because rules are enforced here (enforced rules: {rules}). If the object is as intended, an "
        "administrator can exclude its namespace (admission.excludedNamespaces, or the label "
        "kube-noob.io/admission=disabled); kube-noob audit reads an object of any size."
    )
    return _response(uid, False, [_warning(f"{NOT_EVALUATED}: {why}; denied, rules are enforced")], message)


def _over_node_budget(value: Any) -> bool:
    """Whether ``value`` holds more than ``MAX_OBJECT_NODES`` values. Stops counting one past the budget, and
    keeps its own stack, so neither a huge object nor a deep one costs more than the budget to refuse."""
    seen = 0
    stack = [value]
    while stack:
        item = stack.pop()
        seen += 1
        if seen > MAX_OBJECT_NODES:
            return True
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list | tuple):
            stack.extend(item)
    return False


def excluded_namespace(ns: str, cfg: Config) -> bool:
    if ns in SYSTEM_NAMESPACES or ns in cfg.excluded:
        return True
    reserved = cfg.openshift_reserved and cfg.platform in OPENSHIFT_FAMILY
    return reserved and (ns in OPENSHIFT_NAMESPACES or ns.startswith(OPENSHIFT_PREFIXES))


def _controllers_child(request: dict[str, Any], obj: dict[str, Any]) -> bool:
    """Whether a kube-controller-manager controller made this object from an owner the webhook was sent.

    Both halves, and the first is the one that matters: the stanza below is ordinary object content, and before
    G440 it was the whole test, so any Pod that named an owner -- a ReplicaSet that did not exist, a ConfigMap --
    was admitted unjudged with an enforced rule switched on. The chart's `matchConditions` state the same
    condition in CEL (`tests/test_admission_cannot_be_bypassed.py` holds the two equal)."""
    user = request.get("userInfo")
    username = user.get("username") if isinstance(user, dict) else None
    if not isinstance(username, str) or username not in CONTROLLER_USERS:
        return False
    if obj.get("kind") not in OWNED_KINDS:
        return False
    meta = obj.get("metadata")
    refs = meta.get("ownerReferences") if isinstance(meta, dict) else None
    return isinstance(refs, list) and any(
        isinstance(r, dict)
        and r.get("controller") is True
        and r.get("kind") in CHECKED_OWNERS
        and r.get("apiVersion") in OWNER_API_VERSIONS
        for r in refs
    )


def _findings(
    obj: dict[str, Any], namespace: str, cfg: Config, context: list[dict[str, Any]]
) -> tuple[list[tuple[str, str, str, str]], str]:
    """(rule, path, warning text, resource) for the admitted object only."""
    from kube_noob.audit.engine import analyze
    from kube_noob.audit.model import Stage
    from kube_noob.yamlio import documents_from_objects

    obj = dict(obj)
    meta = dict(obj.get("metadata") or {})
    if namespace and not meta.get("namespace"):
        meta["namespace"] = namespace
    if not meta.get("name") and meta.get("generateName"):
        meta["name"] = f"{meta['generateName']}x"
    obj["metadata"] = meta
    # Not `load_documents(json.dumps(obj))`: the object arrived parsed, and writing it out to parse it again with
    # a YAML composer was two thirds of the time a large object took (G441).
    docs = documents_from_objects([obj, *context])
    report = analyze(
        docs,
        platform=cfg.platform,
        version=cfg.version,
        stages={Stage.VALIDATE, Stage.AUDIT, Stage.CALIBRATE},
        schema=False,
        allowed_registries=cfg.allowed_registries,
    )
    # What the audit could not read about THIS object. `report.findings` is only half the answer, and the half
    # that is missing is the one this product exists to report: a Tekton `Task` carrying a privileged
    # `docker:24-dind` step was admitted with no warning of any kind, because no rule reads that kind and the
    # loop below has nothing to iterate. The webhook still ADMITS -- a fail-closed webhook that denies what it
    # cannot read freezes a cluster, including the deploy that would fix it -- but silence is not the same as
    # admitting out loud, and `warnings` is the non-blocking channel the API server already has for this (G337).
    withheld = report.undetermined() or ""
    out: list[tuple[str, str, str, str]] = []
    for f in report.findings:
        if f.doc_index != 0 or f.rule_id in SKIPPED_RULES:
            continue
        if f.rule_id in CROSS_OBJECT and not cfg.lookups:
            continue
        if cfg.exceptions is not None:
            from kube_noob.audit import exceptions as exc

            if exc.match(cfg.exceptions, f.rule_id, f.resource) is not None:
                continue
        text_ = f"[{f.rule_id}] {f.title}: {f.message} Fix: {f.remediation}"
        out.append((f.rule_id, f.path, _warning(text_), f.resource))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev = {f.rule_id: order.get(f.severity.name.lower(), 5) for f in report.findings}
    out.sort(key=lambda x: (x[0] not in cfg.enforce, sev.get(x[0], 5), x[0], x[1]))
    return out, str(withheld)


def review(
    doc: Any,
    cfg: Config,
    context: Callable[[str], list[dict[str, Any]]] | None = None,
    *,
    deadline: float | None = None,
    seen: dict[str, str] | None = None,
) -> dict[str, Any]:
    """An AdmissionReview response for any input. Never raises, and never answers a bare ``allowed: true`` for a
    request it did not evaluate: see ``_not_evaluated``.

    ``deadline`` is a reading of ``_now()`` after which no further evaluation is started; None (the offline
    ``kube-noob admission review``) evaluates however long it takes, so that command's answer does not depend on
    the machine. ``seen`` receives the request's uid as soon as it is known, for a caller that may have to answer
    for this request before this function returns."""
    uid = ""
    try:
        request = doc.get("request") if isinstance(doc, dict) else None
        if not isinstance(request, dict):
            return _not_evaluated("", cfg, "the body is not an AdmissionReview request")
        uid = str(request.get("uid") or "")[:128]
        if seen is not None:
            seen["uid"] = uid
        op = str(request.get("operation") or "")
        ns = str(request.get("namespace") or "")
        obj = request.get("object")
        sub = str(request.get("subResource") or "")
        if op in SKIP_OPERATIONS or (sub and sub not in SUBRESOURCES) or not isinstance(obj, dict):
            return _response(uid, True, [])
        if ns and excluded_namespace(ns, cfg):
            return _response(uid, True, [])
        raw_meta = obj.get("metadata")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        # An object on its way out is skipped so that its finalizers can still be removed -- which is an UPDATE.
        # The API server clears `deletionTimestamp` on every create, so a CREATE carrying one is not a request
        # it sent, and the field is no reason to look away from it (G440).
        if op == "UPDATE" and meta.get("deletionTimestamp"):
            return _response(uid, True, [])
        # The owner check deliberately does NOT apply to a subresource. A Pod owned by a ReplicaSet is skipped
        # because its owner was audited and carries the same spec -- but no owner carries an ephemeral
        # container, which is added straight to the Pod. Skipping it here would have made `kubectl debug` on
        # any managed workload the one request nothing checks (G250).
        if not sub and _controllers_child(request, obj):
            return _response(uid, True, [])
        # Everything above is a request the webhook does not judge, and costs nothing. From here on the object is
        # evaluated, so this is where the budgets are: what cannot be answered in time is answered now (G441).
        old = request.get("oldObject") if op == "UPDATE" else None
        if _over_node_budget(obj) or (isinstance(old, dict) and _over_node_budget(old)):
            return _not_evaluated(
                uid, cfg, f"the object holds more than {MAX_OBJECT_NODES:,} values, the most that is evaluated"
            )
        late = "it could not be evaluated in time for the API server's timeout"
        if deadline is not None and _now() >= deadline:
            return _not_evaluated(uid, cfg, late)
        extra = context(ns) if (cfg.lookups and context is not None and ns) else []
        # A cross-object rule over a list that was never read, or whose last refresh failed, would read "none
        # exist" -- a NetworkPolicy list forbidden from the start made KN-N001 deny a clean Deployment (G279).
        # Those rules are not evaluated, and the response says so instead of warning.
        unread_lists: list[str] = []
        if cfg.lookups and context is not None and ns and hasattr(context, "unread"):
            unread_lists = list(context.unread(ns))
        found, withheld = _findings(obj, ns, cfg, extra)
        if unread_lists:
            found = [f for f in found if f[0] not in CROSS_OBJECT]
        before: set[tuple[str, str]] | None = None
        if isinstance(old, dict):
            if deadline is not None and _now() >= deadline:
                return _not_evaluated(uid, cfg, late)
            before = {(r, p) for r, p, _, _ in _findings(old, ns, cfg, extra)[0]}
        if sub and before is not None:
            # On a subresource the request IS the change, so the Pod's existing findings are not this
            # request's business: they were reported when it was created and repeating them here would bury
            # the one line that matters under the workload's whole report.
            found = [f for f in found if (f[0], f[1]) not in before]
        enforced = [f for f in found if f[0] in cfg.enforce]
        if enforced and before is not None:
            enforced = [f for f in enforced if (f[0], f[1]) not in before]
        statements: list[str] = []
        if unread_lists:
            statements.append(
                "kube-noob: rules that need other objects of the namespace were not evaluated: "
                f"{', '.join(unread_lists)} could not be read"
            )
        if withheld:
            # Said even when there are findings: "this object has three problems" and "part of it was never read"
            # are different statements, and the second does not stop being true because the first is.
            statements.append(f"kube-noob: not fully audited, so this is not a clean result: {withheld}")
        # The response carries at most `max_warnings` + 1 lines, as the configuration documents and the tests and
        # the in-cluster load run assert. The statements used to be ADDED to `max_warnings` findings and the
        # "more findings" line, so an object with ten findings and a rule that declined reached twelve: the load
        # run's fuzz cases 27 and 81 failed on exactly that once G407 made a non-numeric `replicas` a decline
        # (G419). The statements are never dropped -- each says something the findings cannot -- so they take
        # their room from the findings, and "N more findings" counts every finding not shown. With `max_warnings`
        # smaller than the statements, the statements share one line.
        if len(statements) > cfg.max_warnings:
            statements = ["; ".join(statements)]
        room = max(0, cfg.max_warnings - len(statements))
        warnings = [w for _, _, w, _ in found[:room]] + [_warning(t) for t in statements]
        if len(found) > room:
            warnings.append(_warning(f"kube-noob: {len(found) - room} more findings: kube-noob audit"))
        if enforced:
            rules = sorted({r for r, _, _, _ in enforced})
            message = f"kube-noob denied {enforced[0][3]}: " + "; ".join(w for _, _, w, _ in enforced[:3])
            return _response(uid, False, warnings, message[:1000] + f" (enforced rules: {', '.join(rules)})")
        return _response(uid, True, warnings)
    except Exception as exc:  # noqa: BLE001 - never raises; the type is named, the text may be the requester's
        return _not_evaluated(uid, cfg, f"evaluating it raised {type(exc).__name__}")


def _too_large(cfg: Config) -> dict[str, Any]:
    return _not_evaluated("", cfg, f"the request is larger than {MAX_BODY:,} bytes")


def review_bytes(
    body: bytes,
    cfg: Config,
    context: Callable[[str], list[dict[str, Any]]] | None = None,
    *,
    deadline_seconds: float | None = None,
    deadline: float | None = None,
    seen: dict[str, str] | None = None,
) -> dict[str, Any]:
    """``review`` for a request body. ``deadline_seconds`` counts from this call; ``deadline`` is a reading of
    the clock taken earlier (when the request arrived, before it waited for a worker). Neither: no time limit."""
    if deadline is None and deadline_seconds is not None:
        deadline = _now() + deadline_seconds
    if len(body) > MAX_BODY:
        return _too_large(cfg)
    try:
        doc = sanitize.loads_bounded(body)
    except (ValueError, RecursionError):
        return _not_evaluated("", cfg, "the request is not JSON")
    return review(doc, cfg, context, deadline=deadline, seen=seen)


def _uid_of(body: bytes) -> str:
    """The request's uid, for an answer given before the evaluation got as far as reading it."""
    try:
        doc = sanitize.loads_bounded(body)
        return str(doc["request"].get("uid") or "")[:128]
    except Exception:  # noqa: BLE001 - not a request: there is no uid to answer with
        return ""


# -- lookups: the namespace's other objects, cached and refreshed in the background --------------------------------


class Lookups:
    """Cached objects that cross-object rules need, per namespace. A request never waits for the API server: a
    namespace seen for the first time has every list unread, so its cross-object rules are not evaluated (the
    response says so; never a warning, never a denial), and it is read by the background refresher, which re-reads
    the most recent namespaces every ``ttl`` seconds +/- 10% with a random pause between reads. ``unread`` names
    the lists that are not a current, complete read (G279)."""

    def __init__(
        self,
        backend: Any,
        ttl: float = 60.0,
        max_namespaces: int = 200,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self.backend, self.ttl, self.max_namespaces, self.sleep = backend, ttl, max_namespaces, sleep
        self.rng = rng or random.Random()  # noqa: S311 - pacing jitter, not crypto
        self._lock = threading.Lock()
        # per namespace, per resource: the last list that was read whole. A failed refresh of one resource keeps its
        # last good list and marks it stale; a list never read is absent. Either way `unread` names it and `review`
        # does not evaluate a cross-object rule over it -- it is never read as "none exist" (G279).
        self._cache: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self._stale: dict[str, set[str]] = {}
        self._cluster_read = False
        self._cluster_stale = False
        self._cluster: list[dict[str, Any]] = []
        self._wanted: deque[str] = deque(maxlen=max_namespaces)
        self.reads = 0
        self.errors: list[str] = []

    def __call__(self, namespace: str) -> list[dict[str, Any]]:
        with self._lock:
            if namespace not in self._wanted:
                self._wanted.append(namespace)
            cached = self._cache.get(namespace, {})
            return [*(o for r in CONTEXT_RESOURCES for o in cached.get(r, [])), *self._cluster]

    def stale(self, namespace: str) -> list[str]:
        """The resources whose last refresh in ``namespace`` failed, so their objects are the last good copy."""
        with self._lock:
            return sorted(self._stale.get(namespace, set()))

    def unread(self, namespace: str) -> list[str]:
        """Every list a cross-object rule would read for ``namespace`` that is not a current, complete read:
        never read (a namespace seen for the first time, a list forbidden from the start), or stale (its last
        refresh failed). ``review`` does not evaluate a cross-object rule over these: a list that was not read is
        not "none exist" (G279)."""
        with self._lock:
            kept = self._cache.get(namespace, {})
            out = {r for r in CONTEXT_RESOURCES if r not in kept} | self._stale.get(namespace, set())
            if not self._cluster_read or self._cluster_stale:
                out.add("storageclasses")
            return sorted(out)

    def _list(self, resource: str, namespace: str | None) -> list[dict[str, Any]]:
        self.reads += 1
        from kube_noob.debug.cluster import list_items

        # A response that is not a complete list (no items, non-objects, another kind, a partial page) raises, so
        # the refresher records the list as unread or stale instead of storing it as empty (G279)
        items = list_items(self.backend.get(resource, namespace=namespace), resource, namespace)
        kind = CONTEXT_KINDS[resource]
        return [{**i, "kind": kind} for i in items][:500]

    def refresh(self) -> None:
        with self._lock:
            namespaces = list(self._wanted)
        cluster_ok = True
        try:
            cluster = self._list("storageclasses", None)
        except Exception as exc:  # noqa: BLE001 - forbidden or unreachable: keep the old copy, marked stale
            self.errors.append(f"storageclasses: {type(exc).__name__}")
            cluster = self._cluster
            cluster_ok = False
        fresh: dict[str, dict[str, list[dict[str, Any]]]] = {}
        failed: dict[str, set[str]] = {}
        for ns in namespaces:
            fresh[ns], failed[ns] = {}, set()
            for resource in CONTEXT_RESOURCES:
                self.sleep(self.rng.uniform(0.05, 0.2))
                try:
                    fresh[ns][resource] = self._list(resource, ns)
                except Exception as exc:  # noqa: BLE001 - one failed read must not stop the refresher
                    self.errors.append(f"{resource} in {ns}: {type(exc).__name__}")
                    failed[ns].add(resource)
        with self._lock:
            self._cluster = cluster
            self._cluster_read = self._cluster_read or cluster_ok
            self._cluster_stale = not cluster_ok
            for ns, lists in fresh.items():
                kept = self._cache.setdefault(ns, {})
                kept.update(lists)  # resources that failed keep their last good list
                self._stale[ns] = {r for r in failed[ns] if r in kept}
            self.errors = self.errors[-50:]

    def start(self) -> threading.Thread:
        def loop() -> None:
            while True:
                self.sleep(self.ttl * self.rng.uniform(0.9, 1.1))
                self.refresh()

        t = threading.Thread(target=loop, name="kube-noob-admission-lookups", daemon=True)
        t.start()
        return t


# -- metrics -----------------------------------------------------------------------------------------------------

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 3.0)


@dataclass
class Metrics:
    counts: dict[str, int] = field(default_factory=lambda: {"allowed": 0, "warned": 0, "denied": 0})
    not_evaluated: int = 0
    buckets: list[int] = field(default_factory=lambda: [0] * (len(BUCKETS) + 1))
    total_seconds: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def observe(self, response: dict[str, Any], seconds: float) -> None:
        r = response.get("response") or {}
        outcome = "denied" if not r.get("allowed", True) else ("warned" if r.get("warnings") else "allowed")
        unjudged = any(str(w).startswith(NOT_EVALUATED) for w in r.get("warnings") or [])
        with self.lock:
            self.counts[outcome] += 1
            self.not_evaluated += unjudged
            self.total_seconds += seconds
            i = next((n for n, b in enumerate(BUCKETS) if seconds <= b), len(BUCKETS))
            self.buckets[i] += 1

    def text(self) -> str:
        with self.lock:
            lines = ["# TYPE kube_noob_admission_requests_total counter"]
            lines += [f'kube_noob_admission_requests_total{{outcome="{k}"}} {v}' for k, v in self.counts.items()]
            # Requests answered without a verdict: over a budget, late, unreadable, or a rule that raised. In warn
            # mode they are among `warned`, with a rule enforced among `denied`; this is how many of either (G441).
            lines.append("# TYPE kube_noob_admission_not_evaluated_total counter")
            lines.append(f"kube_noob_admission_not_evaluated_total {self.not_evaluated}")
            lines.append("# TYPE kube_noob_admission_duration_seconds histogram")
            running = 0
            for b, n in zip((*BUCKETS, float("inf")), self.buckets, strict=True):
                running += n
                le = "+Inf" if b == float("inf") else f"{b:g}"
                lines.append(f'kube_noob_admission_duration_seconds_bucket{{le="{le}"}} {running}')
            lines.append(f"kube_noob_admission_duration_seconds_sum {self.total_seconds:.6f}")
            lines.append(f"kube_noob_admission_duration_seconds_count {running}")
        return "\n".join(lines) + "\n"


def app(cfg: Config, context: Callable[[str], list[dict[str, Any]]] | None = None) -> Any:
    """The ASGI app: POST /validate, GET /healthz, /readyz and /metrics."""
    from concurrent.futures import ThreadPoolExecutor

    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse, Response
    from starlette.routing import Route

    metrics = Metrics()
    # One worker: requests are evaluated one at a time, as they always were, but no longer ON the event loop --
    # where an evaluation of several seconds also held up the liveness probe and every other connection. The loop
    # stays free to answer at the deadline. A request still queued when its deadline passes is cancelled, or finds
    # its time gone when it starts and evaluates nothing, so a burst cannot build a backlog of late work (G441).
    worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="kube-noob-admission")

    async def validate(request: Request) -> Response:
        start = time.perf_counter()
        deadline = _now() + cfg.deadline
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY:
            out = _too_large(cfg)
        else:
            body = bytearray()
            async for chunk in request.stream():
                body += chunk
                if len(body) > MAX_BODY:
                    break
            raw = bytes(body)
            seen: dict[str, str] = {}
            job = asyncio.get_running_loop().run_in_executor(
                worker, lambda: review_bytes(raw, cfg, context, deadline=deadline, seen=seen)
            )
            try:
                out = await asyncio.wait_for(job, timeout=max(0.0, deadline - _now()))
            except TimeoutError:
                # The evaluation cannot be interrupted; the answer can still leave on time. It carries the
                # request's own uid, because the API server treats any other as a failed call -- which
                # `failurePolicy: Ignore` would turn back into the silent admission this is here to prevent.
                uid = seen.get("uid") or (_uid_of(raw) if len(raw) <= MAX_BODY else "")
                out = _not_evaluated(uid, cfg, "it could not be evaluated in time for the API server's timeout")
        metrics.observe(out, time.perf_counter() - start)
        return JSONResponse(out)

    async def ok(_: Request) -> Response:
        return PlainTextResponse("ok\n")

    async def metrics_page(_: Request) -> Response:
        return PlainTextResponse(metrics.text(), media_type="text/plain; version=0.0.4")

    application = Starlette(
        routes=[
            Route("/validate", validate, methods=["POST"]),
            Route("/healthz", ok, methods=["GET"]),
            Route("/readyz", ok, methods=["GET"]),
            Route("/metrics", metrics_page, methods=["GET"]),
        ]
    )
    application.state.metrics = metrics
    return application


def watch_certificate(paths: list[str], on_change: Callable[[], None], interval: float = 60.0) -> threading.Thread:
    """Call ``on_change`` once when a certificate or key file changes (the service CA or cert-manager rotated it): the
    server then exits and the kubelet restarts it with the new pair."""
    import os

    def stamp() -> tuple[float, ...]:
        return tuple(os.stat(p).st_mtime for p in paths)

    first = stamp()

    def loop() -> None:
        while True:
            time.sleep(interval)
            try:
                now = stamp()
            except OSError:
                continue
            if now != first:
                on_change()
                return

    t = threading.Thread(target=loop, name="kube-noob-admission-certs", daemon=True)
    t.start()
    return t
