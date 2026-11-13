"""``kube-noob-admission``: a validating admission webhook for kube-noob's rules (requirements R3.3, tier A).

It answers ``admission.k8s.io/v1`` AdmissionReview requests (contract read from kubernetes/api
``admission/v1/types.go``): every finding of the admitted object becomes an admission warning ("Limit warnings to 120
characters if possible. Warnings over 256 characters and large numbers of warnings may be truncated."), and a request
is denied only for a rule the operator listed in ``admission.enforce``. It never mutates: no response carries a patch.

- Warn mode (no rule enforced) cannot deny: the only path to ``allowed: false`` needs a finding of an enforced rule.
- On UPDATE, an enforced rule denies only a finding the old object did not have, so turning a rule to enforce never
  freezes the workloads that already break it; they keep getting warnings.
- Skipped: DELETE and CONNECT, subresources (status, scale, exec), objects being deleted, Pods, ReplicaSets and Jobs
  owned by a controller (their Deployment, StatefulSet, DaemonSet, CronJob or Job was checked), the system namespaces
  (``kube-system``, ``kube-public``, ``kube-node-lease``, ``openshift`` and ``openshift-*``) and
  ``admission.excludedNamespaces``.
- Rules about a whole bundle or that the API server already enforces are not evaluated (``SKIPPED_RULES``); rules
  that need other objects of the namespace (``CROSS_OBJECT``) run only with ``admission.lookups`` (a cache of the
  namespace's PodDisruptionBudgets, NetworkPolicies, PersistentVolumeClaims, HorizontalPodAutoscalers and the
  StorageClasses, read through the read-only backend and refreshed in the background with jitter) and can never be
  enforced: whether the other object exists yet depends on the order of a ``kubectl apply``.
- Any error while evaluating admits the object with a warning that says so: the webhook fails open, like its
  ``failurePolicy: Ignore``.
- Active entries of ``admission.exceptionsFile`` (the same ExceptionList as ``kube-noob audit --exceptions``) hide the
  findings they cover.
"""

from __future__ import annotations

import json
import random
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kube_noob import sanitize

API_VERSION = "admission.k8s.io/v1"
MAX_BODY = 4_000_000  # bytes: the API server's object limit plus the review envelope
WARNING_CHARS = 256
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease", "openshift"})
SYSTEM_PREFIXES = ("openshift-",)
SKIP_OPERATIONS = frozenset({"DELETE", "CONNECT"})
OWNED_KINDS = frozenset({"Pod", "ReplicaSet", "Job"})
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


def excluded_namespace(ns: str, cfg: Config) -> bool:
    return ns in SYSTEM_NAMESPACES or ns.startswith(SYSTEM_PREFIXES) or ns in cfg.excluded


def _owned(obj: dict[str, Any]) -> bool:
    refs = (obj.get("metadata") or {}).get("ownerReferences")
    return isinstance(refs, list) and any(isinstance(r, dict) and r.get("controller") is True for r in refs)


def _findings(
    obj: dict[str, Any], namespace: str, cfg: Config, context: list[dict[str, Any]]
) -> list[tuple[str, str, str, str]]:
    """(rule, path, warning text, resource) for the admitted object only."""
    from kube_noob.audit.engine import analyze
    from kube_noob.audit.model import Stage
    from kube_noob.yamlio import load_documents

    obj = dict(obj)
    meta = dict(obj.get("metadata") or {})
    if namespace and not meta.get("namespace"):
        meta["namespace"] = namespace
    if not meta.get("name") and meta.get("generateName"):
        meta["name"] = f"{meta['generateName']}x"
    obj["metadata"] = meta
    text = json.dumps(obj)
    if context:
        text += "\n---\n" + "\n---\n".join(json.dumps(c) for c in context)
    docs = load_documents(text)
    report = analyze(
        docs,
        platform=cfg.platform,
        version=cfg.version,
        stages={Stage.VALIDATE, Stage.AUDIT, Stage.CALIBRATE},
        schema=False,
        allowed_registries=cfg.allowed_registries,
    )
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
    return out


def review(
    doc: Any,
    cfg: Config,
    context: Callable[[str], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """An AdmissionReview response for any input. Never raises: an input it cannot evaluate is admitted."""
    uid = ""
    try:
        request = doc.get("request") if isinstance(doc, dict) else None
        if not isinstance(request, dict):
            return _response("", True, [_warning("kube-noob: not an AdmissionReview request; admitted")])
        uid = str(request.get("uid") or "")[:128]
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
        # The owner check deliberately does NOT apply to a subresource. A Pod owned by a ReplicaSet is skipped
        # because its owner was audited and carries the same spec -- but no owner carries an ephemeral
        # container, which is added straight to the Pod. Skipping it here would have made `kubectl debug` on
        # any managed workload the one request nothing checks (G250).
        if meta.get("deletionTimestamp") or (not sub and obj.get("kind") in OWNED_KINDS and _owned(obj)):
            return _response(uid, True, [])
        extra = context(ns) if (cfg.lookups and context is not None and ns) else []
        found = _findings(obj, ns, cfg, extra)
        before: set[tuple[str, str]] | None = None
        if op == "UPDATE" and isinstance(request.get("oldObject"), dict):
            before = {(r, p) for r, p, _, _ in _findings(request["oldObject"], ns, cfg, extra)}
        if sub and before is not None:
            # On a subresource the request IS the change, so the Pod's existing findings are not this
            # request's business: they were reported when it was created and repeating them here would bury
            # the one line that matters under the workload's whole report.
            found = [f for f in found if (f[0], f[1]) not in before]
        enforced = [f for f in found if f[0] in cfg.enforce]
        if enforced and before is not None:
            enforced = [f for f in enforced if (f[0], f[1]) not in before]
        warnings = [w for _, _, w, _ in found[: cfg.max_warnings]]
        if len(found) > cfg.max_warnings:
            warnings.append(_warning(f"kube-noob: {len(found) - cfg.max_warnings} more findings: kube-noob audit"))
        if enforced:
            rules = sorted({r for r, _, _, _ in enforced})
            message = f"kube-noob denied {enforced[0][3]}: " + "; ".join(w for _, _, w, _ in enforced[:3])
            return _response(uid, False, warnings, message[:1000] + f" (enforced rules: {', '.join(rules)})")
        return _response(uid, True, warnings)
    except Exception as exc:  # noqa: BLE001 - fail open, like failurePolicy: Ignore
        return _response(
            uid, True, [_warning(f"kube-noob could not evaluate this object ({type(exc).__name__}); admitted")]
        )


def review_bytes(
    body: bytes, cfg: Config, context: Callable[[str], list[dict[str, Any]]] | None = None
) -> dict[str, Any]:
    if len(body) > MAX_BODY:
        return _response("", True, [_warning(f"kube-noob: request larger than {MAX_BODY} bytes; admitted")])
    try:
        doc = sanitize.loads_bounded(body)
    except (ValueError, RecursionError):
        return _response("", True, [_warning("kube-noob: the request is not JSON; admitted")])
    return review(doc, cfg, context)


# -- lookups: the namespace's other objects, cached and refreshed in the background --------------------------------


class Lookups:
    """Cached objects that cross-object rules need, per namespace. A request never waits for the API server: a
    namespace seen for the first time gets no context (fewer warnings, never a denial) and is read by the background
    refresher, which re-reads the most recent namespaces every ``ttl`` seconds +/- 10% with a random pause between
    reads."""

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
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self._cluster: list[dict[str, Any]] = []
        self._wanted: deque[str] = deque(maxlen=max_namespaces)
        self.reads = 0
        self.errors: list[str] = []

    def __call__(self, namespace: str) -> list[dict[str, Any]]:
        with self._lock:
            if namespace not in self._wanted:
                self._wanted.append(namespace)
            return [*self._cache.get(namespace, []), *self._cluster]

    def _list(self, resource: str, namespace: str | None) -> list[dict[str, Any]]:
        self.reads += 1
        data = self.backend.get(resource, namespace=namespace)
        items = data.get("items") if isinstance(data, dict) else None
        kind = CONTEXT_KINDS[resource]
        return [{**i, "kind": kind} for i in items or [] if isinstance(i, dict)][:500]

    def refresh(self) -> None:
        with self._lock:
            namespaces = list(self._wanted)
        try:
            cluster = self._list("storageclasses", None)
        except Exception as exc:  # noqa: BLE001 - forbidden or unreachable: keep the old copy
            self.errors.append(f"storageclasses: {type(exc).__name__}")
            cluster = self._cluster
        fresh: dict[str, list[dict[str, Any]]] = {}
        for ns in namespaces:
            items: list[dict[str, Any]] = []
            for resource in CONTEXT_RESOURCES:
                self.sleep(self.rng.uniform(0.05, 0.2))
                try:
                    items.extend(self._list(resource, ns))
                except Exception as exc:  # noqa: BLE001 - one failed read must not stop the refresher
                    self.errors.append(f"{resource} in {ns}: {type(exc).__name__}")
            fresh[ns] = items
        with self._lock:
            self._cluster = cluster
            self._cache.update(fresh)
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
    buckets: list[int] = field(default_factory=lambda: [0] * (len(BUCKETS) + 1))
    total_seconds: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def observe(self, response: dict[str, Any], seconds: float) -> None:
        r = response.get("response") or {}
        outcome = "denied" if not r.get("allowed", True) else ("warned" if r.get("warnings") else "allowed")
        with self.lock:
            self.counts[outcome] += 1
            self.total_seconds += seconds
            i = next((n for n, b in enumerate(BUCKETS) if seconds <= b), len(BUCKETS))
            self.buckets[i] += 1

    def text(self) -> str:
        with self.lock:
            lines = ["# TYPE kube_noob_admission_requests_total counter"]
            lines += [f'kube_noob_admission_requests_total{{outcome="{k}"}} {v}' for k, v in self.counts.items()]
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
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse, Response
    from starlette.routing import Route

    metrics = Metrics()

    async def validate(request: Request) -> Response:
        start = time.perf_counter()
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY:
            out = _response("", True, [_warning(f"kube-noob: request larger than {MAX_BODY} bytes; admitted")])
        else:
            body = bytearray()
            async for chunk in request.stream():
                body += chunk
                if len(body) > MAX_BODY:
                    break
            out = review_bytes(bytes(body), cfg, context)
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
