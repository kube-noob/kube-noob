"""Why was this denied? Read an admission denial and explain it, policy by policy.

Recognises the messages of Kyverno, OPA Gatekeeper, ValidatingAdmissionPolicy, Pod Security Admission, OpenShift
SecurityContextConstraints, RHACS (StackRox) admission control, ResourceQuota, LimitRange and RBAC. For each policy it
returns the engine, the policy and rule names, the failing field, read-only commands with the names filled in, the
kube-noob audit rules that catch the same problem before deploy, and the change that satisfies the policy. Exceptions,
quota increases and new permissions are listed as changes that need the policy owner's approval.

Offline: it reads only the text it is given (after redaction).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from kube_noob import sanitize
from kube_noob.catalog import OPENSHIFT_FAMILY
from kube_noob.debug.cluster import redact_text
from kube_noob.debug.steps import classify_step, split_comment

MAX_INPUT = 200_000

ENGINES = {
    "kyverno": "Kyverno",
    "gatekeeper": "OPA Gatekeeper",
    "validating-admission-policy": "ValidatingAdmissionPolicy",
    "pod-security": "Pod Security Admission",
    "openshift-scc": "OpenShift SecurityContextConstraints",
    "rhacs": "RHACS admission control",
    "resource-quota": "ResourceQuota",
    "limit-range": "LimitRange",
    "rbac": "RBAC",
}

_NAME = r"[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?"  # bounded: no quadratic scans on long words
_RESOURCE_REF = re.compile(r"(?P<kind>[a-z][a-z0-9.]{0,62}) \"(?P<name>[^\"\s]{1,253})\" is (?:forbidden|invalid)")
_NAMESPACE = (
    re.compile(r"(?:-n|--namespace)[ =](" + _NAME + r")"),
    re.compile(r"in the namespace \"(" + _NAME + r")\""),
    re.compile(r"\bNamespace:\s+(" + _NAME + r")"),
    re.compile(r"\"namespace\":\s*\"(" + _NAME + r")\""),
)


@dataclass
class Denial:
    engine: str
    message: str
    policy: str | None = None
    rule: str | None = None
    resource: str | None = None
    namespace: str | None = None
    path: str | None = None
    mode: str = "deny"  # deny | warn
    meaning: str = ""
    checks: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)
    approvals: list[str] = field(default_factory=list)  # exceptions, grants, quota: the policy owner decides
    related_rules: list[str] = field(default_factory=list)
    patch: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "engine": self.engine,
            "engineName": ENGINES[self.engine],
            "mode": self.mode,
            "policy": self.policy,
            "rule": self.rule,
            "resource": self.resource,
            "namespace": self.namespace,
            "path": self.path,
            "message": self.message,
            "meaning": self.meaning,
            "readOnlyNextSteps": [_step(c) for c in self.checks if classify_step(c) == "read"],
            "diagnosticCommands": [
                {**_step(c), "requiresApproval": True} for c in self.checks if classify_step(c) != "read"
            ],
            "proposedChanges": [{"change": f, "requiresApproval": True} for f in self.fixes]
            + [{"change": f, "requiresApproval": True, "needsPolicyOwner": True} for f in self.approvals],
            "relatedRules": list(dict.fromkeys(self.related_rules)),
        }
        if self.patch:
            out["patch"] = self.patch
        if self.details:
            out["details"] = self.details
        return {k: v for k, v in out.items() if v not in (None, [], "")}


def _step(check: str) -> dict[str, str]:
    cmd, why = split_comment(check)
    if re.match(r"^[a-z][\w.-]*\s", cmd + " ") is None:
        return {"instruction": check.strip()}
    return {"command": cmd, **({"why": why} if why else {})}


# --- what a policy message is about: the same problems kube-noob's audit rules catch before deploy ---------------

_TOPICS: tuple[tuple[re.Pattern[str], tuple[str, ...], str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), rules, fix)
    for p, rules, fix in (
        (
            r"privilege escalation|allowprivilegeescalation",
            ("KN-S002",),
            "Set securityContext.allowPrivilegeEscalation: false on every container.",
        ),
        (
            r"\bprivileged\b",
            ("KN-S001",),
            "Remove securityContext.privileged: true; grant only the specific capability the app needs.",
        ),
        (
            r"run(?:ning)? as (?:the )?root|runasnonroot|non ?root|runasuser",
            ("KN-S003",),
            "Set securityContext.runAsNonRoot: true and use an image with a numeric non-root USER.",
        ),
        (
            r"capabilit",
            ("KN-S006", "KN-S005"),
            "Drop all capabilities (securityContext.capabilities.drop: [ALL]) and add back only what the policy "
            "allows (usually just NET_BIND_SERVICE).",
        ),
        (
            r"read ?only root|readonlyrootfilesystem|\bro rootfs\b",
            ("KN-S007",),
            "Set securityContext.readOnlyRootFilesystem: true and mount an emptyDir for the paths the app writes.",
        ),
        (r"seccomp", ("KN-S008",), "Set securityContext.seccompProfile.type: RuntimeDefault."),
        (
            r"host ?(?:network|pid|ipc)|host namespace",
            ("KN-S009",),
            "Remove hostNetwork, hostPID and hostIPC from the pod spec.",
        ),
        (r"host ?path", ("KN-S010",), "Replace the hostPath volume with a PVC, ConfigMap, Secret or emptyDir."),
        (r"host ?ports?", ("KN-S011",), "Remove hostPort; expose the port through a Service."),
        (
            r"\blatest\b|image tag|mutable (?:image )?tag|tag is required|disallowed tag|digest",
            ("KN-S012",),
            "Pin the image to a version tag or, better, a digest (image@sha256:...).",
        ),
        (
            r"registr|image repo|allowed repos",
            (),
            "Use an image from an allowed registry; mirror the image there first.",
        ),
        (
            r"requests?(?: and)? limits|resource limits|limits? (?:are|is) required|has no resource|memory limit|"
            r"cpu limit|resources? (?:are|is) required",
            ("KN-C004", "KN-C005"),
            "Set resources.requests and resources.limits for CPU and memory on every container.",
        ),
        (
            r"probe",
            ("KN-C001", "KN-C002"),
            "Add a readinessProbe and a livenessProbe (and a startupProbe for slow starts).",
        ),
        (
            r"automount|service ?account token",
            ("KN-S014",),
            "Set automountServiceAccountToken: false unless the app calls the Kubernetes API.",
        ),
        (r"replicas", ("KN-C007",), "Set spec.replicas within the range the policy allows."),
    )
)
_LABELS = re.compile(r"\blabels?\b", re.IGNORECASE)


def _topics(*texts: str | None) -> tuple[list[str], list[str]]:
    """Related kube-noob rules and fixes for a policy, from its name, rule name and message."""
    blob = " ".join(t for t in texts if t).replace("-", " ").replace("_", " ")
    rules: list[str] = []
    fixes: list[str] = []
    for pat, rule_ids, fix in _TOPICS:
        if pat.search(blob):
            rules.extend(rule_ids)
            fixes.append(fix)
    if not fixes and _LABELS.search(blob):
        fixes.append(
            "Add the labels the message names (metadata.labels, and spec.template.metadata.labels for workloads)."
        )
    return list(dict.fromkeys(rules)), list(dict.fromkeys(fixes))


def _ref_near(text: str, pos: int) -> str | None:
    """The object named on the same line as a match (``deployments "web" is invalid``), else anywhere in the text."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    m = _RESOURCE_REF.search(text[start : end if end >= 0 else len(text)]) or _RESOURCE_REF.search(text)
    return f"{m['kind']}/{m['name']}" if m else None


def _unquote(msg: str) -> str:
    msg = msg.strip()
    if len(msg) >= 2 and msg[0] == "'" and msg[-1] == "'":
        msg = msg[1:-1].replace("''", "'")
    return re.sub(r"\s+", " ", msg).strip()


def _kubectl(platform: str | None, text: str = "") -> str:
    if platform in OPENSHIFT_FAMILY:
        return "oc"
    if platform is None and re.search(r"security context constraint|openshift\.io|\boc (apply|create)\b", text):
        return "oc"
    return "kubectl"


def _ns(ns: str | None) -> str:
    return ns or "<namespace>"


# --- Kyverno -----------------------------------------------------------------------------------------------------

_KYV_BLOCK = re.compile(
    r"resource (?P<kind>[A-Za-z][\w.]{0,62})/(?P<ns>(?:[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)?)/(?P<name>[^\s]{1,253}) "
    r"was blocked due to the following polic(?:y|ies)"
)
_KYV_POLICY_LINE = re.compile(r"^(?P<policy>" + _NAME + r"):\s*$")
_KYV_RULE_LINE = re.compile(r"^\s+(?P<rule>" + _NAME + r"):\s+(?P<msg>\S.*)$")
_KYV_EVENT = re.compile(
    r"policy (?P<policy>" + _NAME + r")/(?P<rule>" + _NAME + r") (?:fail|failed|error)(?:ed)?:? (?P<msg>[^\n]+)"
)
_KYV_PATH = re.compile(r"failed at path (?P<path>/[^\s']*)")
_KYV_TOKEN = re.compile(r"(?P<name>" + _NAME + r"):\s+(?=(?P<next>'|" + _NAME + r":))")

# --- Kyverno CEL policy types (policies.kyverno.io/v1): ValidatingPolicy, MutatingPolicy, ImageValidatingPolicy ----
#
# Grounded against the Kyverno source (kyverno/kyverno, read-only clone, 2026-10-30): webhook names are
# pkg/config/config.go's *WebhookName constants with a "-fail"/"-ignore" suffix built in
# pkg/controllers/webhook/validating.go; the "Policy %s failed: %s" message is
# pkg/webhooks/resource/vpol/handler.go and pkg/webhooks/resource/ivpol/handler.go (identical format, confirmed by
# pkg/webhooks/resource/ivpol/diagnostics_test.go); MutatingPolicy's distinct "Resource: ns/name, Kind: K,
# Errors: [...]" wrapper is pkg/webhooks/resource/mpol/handler.go's admissionResponse, only raised when a mutate
# rule errors with failurePolicy: Fail (a successful or Ignore-failed mutation never denies). CRD kind/plural names
# are each policy type's config/crds/policies.kyverno.io/policies.kyverno.io_*.yaml. DeletingPolicy is deliberately
# absent here: kyverno.io's own docs ("Unlike admission policies that react to API requests, DeletingPolicy... Runs
# periodically at scheduled times") confirm it has no admission webhook and so never produces a denial to explain.
_CEL_KIND: dict[str, tuple[str, str]] = {  # webhook-name prefix -> (Kind, CRD plural)
    "vpol": ("ValidatingPolicy", "validatingpolicies"),
    "nvpol": ("NamespacedValidatingPolicy", "namespacedvalidatingpolicies"),
    "mpol": ("MutatingPolicy", "mutatingpolicies"),
    "nmpol": ("NamespacedMutatingPolicy", "namespacedmutatingpolicies"),
    "ivpol": ("ImageValidatingPolicy", "imagevalidatingpolicies"),
    "nivpol": ("NamespacedImageValidatingPolicy", "namespacedimagevalidatingpolicies"),
}
_CEL_WEBHOOK = re.compile(
    r'admission webhook "(?P<prefix>n?(?:vpol|ivpol|mpol))\.(?:validate|mutate)\.kyverno\.svc[^"]*" '
    r"denied the request: (?P<rest>.+)",
    re.DOTALL,
)
_CEL_POLICY_ERR = re.compile(r"\bPolicy (?P<policy>" + _NAME + r") (?:failed|error): ")
# MutatingPolicy's own format has no "failed"/"error" word (pkg/webhooks/resource/mpol/handler.go:
# fmt.Sprintf("Policy %s: %s", name, msg)) -- distinct from vpol/ivpol's "Policy %s failed: %s".
_MPOL_POLICY_ERR = re.compile(r"\bPolicy (?P<policy>" + _NAME + r"): ")
_MPOL_WRAP = re.compile(
    r"^Resource: (?P<ns>[^/,]*)/(?P<name>[^,]+), Kind: (?P<kind>[^,]+), Errors: \[(?P<body>.*)\]\.?\s*\Z", re.DOTALL
)
_IMAGE_VERIFY_TOPICS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), fix)
    for p, fix in (
        (
            r"cosign|sigstore|keyless|no matching signatures|signature verification",
            "Sign the image (`cosign sign` for key-based, or `cosign sign --yes` with OIDC for keyless) with the "
            "same key or identity the policy's attestors.signer / attestors.keyless expects, then push the "
            "signature to the registry before retrying.",
        ),
        (
            r"attestor|attestation|in-?toto|sbom|provenance",
            "Produce and attach the missing attestation (`cosign attest` for in-toto/SBOM/provenance), signed by "
            "the identity the policy's attestors entry names, then push it to the registry.",
        ),
    )
)


def _quote_closed(msg: str) -> bool:
    if not msg.startswith("'"):
        return True
    body = msg[1:].replace("''", "")
    return body.endswith("'")


def _kyverno_entries(rest: str) -> list[tuple[str, str, str]]:
    """(policy, rule, message) from the block after 'was blocked due to the following policies'."""
    rows: list[list[str]] = []
    lines = rest.splitlines()
    if len(lines) > 1:
        policy: str | None = None
        current: list[str] | None = None
        for line in lines:
            if current is not None and len(current[2]) < 4000 and not _quote_closed(current[2]):
                current[2] += " " + line.strip()
                continue
            mp = _KYV_POLICY_LINE.match(line)
            if mp:
                policy, current = mp["policy"], None
                continue
            mr = _KYV_RULE_LINE.match(line)
            if policy and mr:
                current = [policy, mr["rule"], mr["msg"].strip()]
                rows.append(current)
                continue
            if current is not None and line.startswith("    ") and line.strip():
                current[2] += " " + line.strip()  # YAML-folded continuation
        if rows:
            return [(p, r, _unquote(m)) for p, r, m in rows]
    # The whole block on one line (pasted from a log or JSON): scan name: name: 'message' tokens.
    out: list[tuple[str, str, str]] = []
    policy = None
    pos = 0
    while True:
        m = _KYV_TOKEN.search(rest, pos)
        if not m:
            break
        if m["next"] == "'":
            end = m.end() + 1
            while True:
                q = rest.find("'", end)
                if q < 0:
                    q = len(rest)
                    break
                if rest[q : q + 2] == "''":
                    end = q + 2
                    continue
                break
            if policy:
                out.append((policy, m["name"], _unquote(rest[m.end() : q + 1])))
            pos = q + 1
        else:
            policy = m["name"]
            pos = m.end()
    return out


def _kyverno_cel(text: str, platform: str | None) -> list[Denial]:
    """Denials from Kyverno's policies.kyverno.io CEL policy types: ValidatingPolicy, MutatingPolicy,
    ImageValidatingPolicy (and their Namespaced variants). See the grounding note above ``_CEL_KIND``.
    """
    m = _CEL_WEBHOOK.search(text)
    if not m:
        return []
    kind, plural = _CEL_KIND[m["prefix"]]
    kc = _kubectl(platform, text)
    rest = m["rest"].strip()
    resource = ns = None
    body = rest
    wrap = _MPOL_WRAP.match(rest)  # MutatingPolicy's distinct "Resource: ns/name, Kind: K, Errors: [...]" shape
    if wrap:
        ns = wrap["ns"].strip() or None
        resource = f"{wrap['kind'].strip()}/{wrap['name'].strip()}"
        body = wrap["body"]
    pieces = list((_MPOL_POLICY_ERR if wrap else _CEL_POLICY_ERR).finditer(body))
    entries: list[tuple[str, str]] = (
        [
            (pm["policy"], body[pm.end() : (pieces[i + 1].start() if i + 1 < len(pieces) else len(body))].strip())
            for i, pm in enumerate(pieces)
        ]
        if pieces
        else [("", body.strip())]
    )
    is_mutating = kind.endswith("MutatingPolicy")
    out: list[Denial] = []
    for policy, raw in entries:
        msg = raw.strip().rstrip(",").strip().rstrip(".") + "."
        rules, fixes = _topics(policy, msg)
        if kind.endswith("ImageValidatingPolicy"):
            fixes += [fix for pat, fix in _IMAGE_VERIFY_TOPICS if pat.search(msg)]
        d = Denial("kyverno", msg, policy=policy or None, resource=resource, namespace=ns, related_rules=rules)
        d.details["policyKind"] = kind
        who = f"Kyverno {kind} {policy}" if policy else f"A Kyverno {kind}"
        d.meaning = f"{who} rejected {resource or 'the request'}: {msg}" + (
            " A MutatingPolicy denial means its own CEL mutate expression failed to evaluate (failurePolicy: Fail), "
            "not necessarily that the object is wrong."
            if is_mutating
            else ""
        )
        if policy:
            d.checks.append(f"{kc} get {plural}.policies.kyverno.io {policy} -o yaml")
        d.checks += [
            f"{kc} get policyreports.wgpolicyk8s.io -n {_ns(ns)}",
            f"{kc} get policyexceptions.policies.kyverno.io -A",
        ]
        d.checks.append("kube-noob audit -f <manifest.yaml>")
        d.fixes = fixes or (
            [
                f"Ask the owner of {policy or 'the policy'} to check why its CEL mutate expression failed on this "
                "object (missing field, type mismatch) and either fix the expression or narrow its matchConditions "
                "to exclude objects like this one."
            ]
            if is_mutating
            else [f"Change {resource or 'the object'} so it satisfies the rule the message describes."]
        )
        d.approvals.append(
            f"If this workload really needs an exception, ask the owner of {policy or 'the policy'} for a "
            f"policies.kyverno.io PolicyException scoped to this workload only, naming the policy in "
            f"spec.policyRefs (kind: {kind}, name: {policy or '<policy>'}) and matching it with a CEL "
            "matchConditions expression; the PolicyReport then shows result: skip."
        )
        out.append(d)
    return out


def _kyverno(text: str, platform: str | None) -> list[Denial]:
    out: list[Denial] = []
    kc = _kubectl(platform, text)
    block = _KYV_BLOCK.search(text)
    entries: list[tuple[str, str, str]] = []
    resource = ns = None
    if block:
        resource = f"{block['kind']}/{block['ns'] + '/' if block['ns'] else ''}{block['name']}"
        ns = block["ns"] or None
        entries = _kyverno_entries(text[block.end() :])
    for m in _KYV_EVENT.finditer(text):
        entries.append((m["policy"], m["rule"], _unquote(m["msg"])))
    if not entries:
        cel = _kyverno_cel(text, platform)
        if cel:
            out.extend(cel)
        elif re.search(r"admission webhook \"[^\"]*kyverno[^\"]*\" denied the request", text):
            msg = (
                text.split("denied the request:", 1)[1].strip().splitlines()[0] if "denied the request:" in text else ""
            )
            pm = re.search(r"\b[Pp]olicy (" + _NAME + r")", msg)  # generic fallback for an unrecognised webhook name
            entries.append((pm.group(1) if pm else "", "", msg or "Kyverno denied the request."))
    seen: set[tuple[str, str]] = set()
    for policy, rule, raw in entries:
        if (policy, rule) in seen:
            continue
        seen.add((policy, rule))
        msg = re.sub(r"^validation error:\s*", "", raw)
        path = _KYV_PATH.search(msg)
        clean = _KYV_PATH.sub("", msg).replace(f"rule {rule} ", "").strip().rstrip(".") + "."
        clean = re.sub(r"\s+\.$", ".", clean)
        rules, fixes = _topics(policy, rule, clean)
        base_rule = re.sub(r"^autogen-(?:cronjob-)?", "", rule) if rule else rule
        d = Denial(
            "kyverno",
            clean,
            policy=policy or None,
            rule=rule or None,
            resource=resource,
            namespace=ns,
            path=path["path"].rstrip("/") if path else None,
            related_rules=rules,
        )
        who = f"Kyverno policy {policy}" + (f" (rule {rule})" if rule else "")
        d.meaning = f"{who} rejected {resource or 'the request'}: {clean}"
        if rule and rule != base_rule:
            d.meaning += (
                f" Kyverno generated rule {rule} from rule {base_rule} so the policy also applies to Deployments, "
                "StatefulSets, Jobs and other Pod controllers."
            )
        if policy:
            d.checks += [
                f"{kc} get clusterpolicies.kyverno.io,policies.kyverno.io -A --field-selector metadata.name={policy}",
                f"{kc} get clusterpolicy {policy} -o yaml",
            ]
        d.checks += [
            f"{kc} get policyreports.wgpolicyk8s.io -n {_ns(ns)}",
            f"{kc} get policyexceptions.kyverno.io -A",
        ]
        d.checks.append("kube-noob audit -f <manifest.yaml>")
        d.fixes = fixes or [f"Change {resource or 'the object'} so it satisfies the rule the message describes."]
        d.approvals.append(
            f"If this workload really needs an exception, ask the owner of {policy or 'the policy'} for a Kyverno "
            "PolicyException scoped to this workload only. PolicyExceptions are off by default: Kyverno must run with "
            "enablePolicyException set to true and exceptionNamespace naming where exceptions may be used. The "
            "exception names the policy in spec.policyRefs (name and kind) and matches the workload with a CEL "
            "matchConditions expression; the PolicyReport then shows result: skip."
        )
        out.append(d)
    return out


# --- OPA Gatekeeper --------------------------------------------------------------------------------------------

_GK_LINE = re.compile(r"^\s*(?:Warning:\s*)?\[(?:denied by )?(?P<constraint>" + _NAME + r")\]\s*(?P<msg>.*)$")


def _gatekeeper(text: str, platform: str | None) -> list[Denial]:
    if not re.search(r"gatekeeper", text, re.IGNORECASE):
        return []
    kc = _kubectl(platform, text)
    items: list[list[str]] = []  # [constraint, message, mode]
    for raw in text.splitlines():
        line = raw
        warn = line.lstrip().startswith("Warning:")
        if "denied the request:" in line:
            line = line.split("denied the request:", 1)[1]
        m = _GK_LINE.match(line)
        if m:
            items.append([m["constraint"], m["msg"].strip(), "warn" if warn else "deny"])
    out: list[Denial] = []
    ref = _ref_near(text, text.find("gatekeeper"))
    for constraint, msg, mode in items:
        rules, fixes = _topics(constraint, msg)
        d = Denial(
            "gatekeeper",
            msg,
            policy=constraint,
            mode=mode,
            resource=ref,
            related_rules=rules,
        )
        if mode == "warn":
            d.meaning = (
                f"Gatekeeper constraint {constraint} runs in warn mode: the object was admitted, but it breaks the "
                f"constraint: {msg}"
            )
        else:
            d.meaning = f"Gatekeeper constraint {constraint} rejected the request: {msg}"
        d.checks = [
            f"{kc} get constraints --field-selector metadata.name={constraint} -o yaml",
            f"{kc} get constrainttemplates",
            f"{kc} get constraints --field-selector metadata.name={constraint} "
            "-o jsonpath='{.items[*].status.violations}'",
        ]
        d.checks.append("kube-noob audit -f <manifest.yaml>")
        d.fixes = fixes or ["Change the object so it satisfies the constraint the message describes."]
        d.approvals.append(
            f"The owner of {constraint} can roll it out without blocking: spec.enforcementAction: dryrun (violations "
            "only in status.violations) or warn (admitted with a warning), instead of the default deny. To exempt a "
            "namespace: spec.match.excludedNamespaces in the constraint, the Gatekeeper Config resource "
            "(excludedNamespaces per process), or --exempt-namespace=<NAMESPACE NAME> plus the "
            "admission.gatekeeper.sh/ignore namespace label (skips the webhook only; audit still reports it)."
        )
        out.append(d)
    return out


# --- ValidatingAdmissionPolicy (Kubernetes 1.30+) --------------------------------------------------------------

_VAP = re.compile(
    r"ValidatingAdmissionPolicy '(?P<policy>" + _NAME + r")' with binding '(?P<binding>" + _NAME + r")' "
    r"denied request: "
    r"(?P<msg>[^\n]{1,4000})"
)
_VAP_WARN = re.compile(
    r"Validation failed for ValidatingAdmissionPolicy '(?P<policy>" + _NAME + r")' with binding "
    r"'(?P<binding>" + _NAME + r")': (?P<msg>[^\n]{1,4000})"
)


def _vap(text: str, platform: str | None) -> list[Denial]:
    kc = _kubectl(platform, text)
    out: list[Denial] = []
    for pat, mode in ((_VAP, "deny"), (_VAP_WARN, "warn")):
        for m in pat.finditer(text):
            msg = m["msg"].strip()
            expr = re.match(r"failed expression: (.+)", msg)
            rules, fixes = _topics(m["policy"], msg)
            d = Denial(
                "validating-admission-policy",
                msg,
                policy=m["policy"],
                rule=m["binding"],
                mode=mode,
                resource=_ref_near(text, m.start()),
                related_rules=rules,
            )
            verb = "rejected the request" if mode == "deny" else "warns about the request (it was admitted)"
            d.meaning = (
                f"The built-in ValidatingAdmissionPolicy {m['policy']} (binding {m['binding']}) {verb}: "
                f"{msg.rstrip('.')}."
            )
            if expr:
                d.details["failedExpression"] = expr.group(1)
                d.meaning += " The CEL expression evaluated to false for this object."
                d.approvals.append(
                    "The denial quotes the CEL expression because the validation has no message or messageExpression. "
                    f"The owner of {m['policy']} can add spec.validations[i].messageExpression (CEL returning a "
                    "string, for example 'object.spec.replicas must be no greater than ' + "
                    "string(params.maxReplicas)) so the denial says what to change."
                )
            d.checks = [
                f"{kc} get validatingadmissionpolicy {m['policy']} -o yaml",
                f"{kc} get validatingadmissionpolicybinding {m['binding']} -o yaml",
            ]
            d.fixes = fixes or ["Change the object so the policy's expression holds (see spec.validations)."]
            d.approvals.append(
                f"If this object must be excluded, the owner of binding {m['binding']} can narrow its matchResources "
                "(for example its namespaceSelector). To report instead of reject while workloads are fixed, the "
                "binding can use validationActions: [Warn, Audit] (Deny and Warn cannot be combined)."
            )
            out.append(d)
    return out


# --- Pod Security Admission ----------------------------------------------------------------------------------

_PSA = re.compile(
    r"(?P<mode>would violate|violates) PodSecurity \"(?P<level>[a-z]{1,20}):(?P<ver>[^\"\n]{1,20})\": "
    r"(?P<list>[^\n]{1,8000})"
)
# An item ends at a comma, at the end, or at a period that ends the message (a pasted question may follow it).
_PSA_ITEM = re.compile(r"(?P<check>[^,()][^()]{0,200}?) \((?P<detail>[^()]{0,2000})\)(?:,\s*|\.?\s*$|\.\s)")
_CONTAINERS = re.compile(r"containers? ((?:\"[^\"]+\"(?:, | and )?)+)")
_POD_FORBIDDEN = re.compile(r"pods \"(?P<pod>[^\"]+)\" is forbidden")
_CREATED = re.compile(r"^(?P<kind>[a-z]+(?:\.[a-z.]+)?)/(?P<name>" + _NAME + r") (?:created|configured)", re.MULTILINE)

# check name pattern -> (rule ids, where the fix goes, securityContext fragment, fix text)
_PSA_CHECKS: tuple[tuple[re.Pattern[str], tuple[str, ...], str | None, dict[str, Any] | None, str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), r, where, frag, fix)
    for p, r, where, frag, fix in (
        (
            r"allowPrivilegeEscalation",
            ("KN-S002",),
            "container",
            {"allowPrivilegeEscalation": False},
            "Set securityContext.allowPrivilegeEscalation: false on {containers}.",
        ),
        (
            r"unrestricted capabilities",
            ("KN-S006",),
            "container",
            {"capabilities": {"drop": ["ALL"]}},
            "Drop all capabilities on {containers} (securityContext.capabilities.drop: [ALL]).",
        ),
        (
            r"non-default capabilities",
            ("KN-S005",),
            None,
            None,
            "Remove the added capabilities from {containers}; the restricted level allows only NET_BIND_SERVICE.",
        ),
        (
            r"runAsNonRoot",
            ("KN-S003",),
            "pod",
            {"runAsNonRoot": True},
            "Set securityContext.runAsNonRoot: true and use an image with a numeric non-root USER.",
        ),
        (r"runAsUser=0", ("KN-S003",), None, None, "Remove runAsUser: 0 from {containers}."),
        (
            r"seccompProfile",
            ("KN-S008",),
            "pod",
            {"seccompProfile": {"type": "RuntimeDefault"}},
            "Set securityContext.seccompProfile.type: RuntimeDefault in the pod spec.",
        ),
        (r"^privileged", ("KN-S001",), None, None, "Remove securityContext.privileged: true from {containers}."),
        (r"host namespaces", ("KN-S009",), None, None, "Remove hostNetwork, hostPID and hostIPC from the pod spec."),
        (
            r"hostPath volumes|restricted volume types",
            ("KN-S010",),
            None,
            None,
            "Replace the hostPath (or other restricted) volume with a PVC, ConfigMap, Secret, emptyDir or projected "
            "volume.",
        ),
        (r"hostPort", ("KN-S011",), None, None, "Remove hostPort from {containers}; use a Service instead."),
        (r"procMount", ("KN-S020",), None, None, "Remove securityContext.procMount: Unmasked."),
        # KEP-4940 (sig-auth, "psa-block-host-field-in-probes"). The check is named `probeHost` in the violation
        # message -- "probeHost (container \"liveness\" uses probeHost 135.45.63.4)" -- and without an entry here
        # it fell through to the generic branch, which echoes the denial back as its own fix and attributes no
        # rule, while `readOnlyNextSteps` still offered `kube-noob fix`, which could do nothing for it. The KEP
        # covers the lifecycle handlers as well as the three probes, so the fix names both. It is enabled by a
        # namespace's `pod-security.kubernetes.io/enforce-version: v1.34` or later, which is why no version is
        # compared here: by the time this message exists, Pod Security has already ruled, and second-guessing it
        # from a cluster version would be the tool overriding the cluster.
        (
            r"^probeHost$",
            ("KN-S029",),
            None,
            None,
            "Remove the host field from the probes and lifecycle handlers of {containers}: "
            "livenessProbe/readinessProbe/startupProbe .httpGet.host and .tcpSocket.host, and "
            "lifecycle.postStart/preStop .httpGet.host. A handler with no host is sent to the pod's own IP, "
            "which is what the check requires; a host pointing anywhere else makes the kubelet probe that "
            "address instead of the container.",
        ),
        (r"seLinuxOptions", (), None, None, "Remove the custom seLinuxOptions type or user."),
        (r"sysctls", (), None, None, "Remove the unsafe sysctls from the pod securityContext."),
        (r"appArmor", (), None, None, "Use the RuntimeDefault AppArmor profile (or remove the override)."),
    )
)


def _merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = v


def _pod_security(text: str, platform: str | None, ns: str | None) -> list[Denial]:
    kc = _kubectl(platform, text)
    out: list[Denial] = []
    seen: set[str] = set()
    for m in _PSA.finditer(text):
        if m["list"] in seen:
            continue
        seen.add(m["list"])
        mode = "warn" if m["mode"] == "would violate" else "deny"
        pod_sc: dict[str, Any] = {}
        container_sc: dict[str, dict[str, Any]] = {}
        violations: list[dict[str, str]] = []
        rules: list[str] = []
        fixes: list[str] = []
        items = [(i["check"].strip(), i["detail"].strip()) for i in _PSA_ITEM.finditer(m["list"])]
        if not items:  # quoted without the details: "violates PodSecurity "restricted:latest": privileged, ..."
            items = [(c.strip()[:200], "") for c in m["list"].split(", ")[:20] if c.strip()]
        for check, detail in items:
            cm = _CONTAINERS.search(detail)
            names = re.findall(r"\"([^\"]+)\"", cm.group(1)) if cm else []
            violations.append({"check": check, "detail": detail})
            for pat, rule_ids, where, frag, fix in _PSA_CHECKS:
                if not pat.search(check):
                    continue
                rules.extend(rule_ids)
                who = ", ".join(f"container {n}" for n in names) or "every container"
                fixes.append(fix.format(containers=who))
                if frag and where == "pod":
                    _merge(pod_sc, frag)
                elif frag and where == "container":
                    for n in names or ["<container>"]:
                        _merge(container_sc.setdefault(n, {}), frag)
                break
            else:
                fixes.append(f"Satisfy the {check} check: {detail}.")
        pod = _POD_FORBIDDEN.search(text)
        created = _CREATED.search(text)
        resource = f"Pod/{pod['pod']}" if pod else (f"{created['kind']}/{created['name']}" if created else None)
        msg = f'{m["mode"]} PodSecurity "{m["level"]}:{m["ver"]}": {m["list"].strip()}'
        d = Denial(
            "pod-security",
            msg,
            policy=f"{m['level']}:{m['ver']}",
            mode=mode,
            resource=resource,
            namespace=ns,
            related_rules=rules,
            fixes=list(dict.fromkeys(fixes)),
        )
        d.details = {"level": m["level"], "version": m["ver"], "violations": violations}
        n = len(violations)
        if mode == "deny":
            d.meaning = (
                f"Namespace {_ns(ns)} enforces the Pod Security '{m['level']}' level ({m['ver']}); the pod spec "
                f"breaks {n} of its checks, so the pod was not created."
            )
        else:
            d.meaning = (
                f"A warning, not a rejection: the pod spec breaks {n} checks of the Pod Security '{m['level']}' level. "
                "Either the namespace only warns or audits at this level, or this is a Deployment, StatefulSet or Job "
                "whose pods will be rejected when its controller creates them (look for FailedCreate events)."
            )
        if pod_sc or container_sc:
            spec: dict[str, Any] = {}
            if pod_sc:
                spec["securityContext"] = pod_sc
            if container_sc:
                spec["containers"] = [{"name": c, "securityContext": sc} for c, sc in container_sc.items()]
            d.patch = yaml.safe_dump({"spec": spec}, sort_keys=False)
            d.fixes.append(
                "Merge the patch into the pod spec (spec.template.spec for a Deployment); `kube-noob fix` applies the "
                "same hardening to a manifest."
            )
        d.checks = [
            f"{kc} get ns {_ns(ns)} --show-labels",
            f"{kc} get events -n {_ns(ns)} --field-selector reason=FailedCreate",
            "kube-noob fix -f <manifest.yaml>",
        ]
        if platform in OPENSHIFT_FAMILY or kc == "oc":
            d.meaning += (
                " On OpenShift the label syncer sets the namespace level from the SCCs its ServiceAccounts may use; "
                "fix the pod spec rather than the label."
            )
        d.approvals.append(
            f"Lowering the namespace's pod-security.kubernetes.io/enforce label changes the policy for every pod in "
            f"{_ns(ns)}; only the namespace owner should decide that."
        )
        out.append(d)
    return out


# --- OpenShift SecurityContextConstraints ------------------------------------------------------------------------

_SCC = re.compile(r"unable to validate against any security context constraint: \[(?P<body>[^\n]{0,20000})\]")
_SCC_PROVIDER = re.compile(r"(?:^|, )provider \"?(" + _NAME + r")\"?: ")
_SCC_ERROR_SPLIT = re.compile(
    r", (?=\.?[A-Za-z]+(?:\[\d+\])?(?:\.[A-Za-z]+(?:\[\d+\])?)*: "
    r"(?:Invalid value|Forbidden|Unsupported value|Required value|Duplicate value|Not found))"
)
_SCC_ERROR = re.compile(
    r"^(?P<field>\.?[A-Za-z][\w.\[\]]*): (?P<kind>Invalid value|Forbidden|Unsupported value|Required value|"
    r"Duplicate value|Not found)(?:: (?P<rest>.*))?$"
)
_SCC_FIELDS: tuple[tuple[re.Pattern[str], tuple[str, ...], str], ...] = tuple(
    (re.compile(p), r, fix)
    for p, r, fix in (
        (
            r"runAsUser",
            ("KN-S004",),
            "Remove the fixed runAsUser; restricted-v2 assigns a UID from the namespace range{range}. Keep "
            "runAsNonRoot: true and make the image work as an arbitrary UID in group 0.",
        ),
        (
            r"fsGroup|supplementalGroups|runAsGroup",
            ("KN-S004",),
            "Remove the fixed fsGroup / runAsGroup / supplementalGroups; restricted-v2 assigns them from the "
            "namespace range.",
        ),
        (r"privileged", ("KN-S001",), "Remove securityContext.privileged: true."),
        (r"capabilities", ("KN-S005",), "Remove the added capability; restricted-v2 allows only NET_BIND_SERVICE."),
        (r"allowPrivilegeEscalation", ("KN-S002",), "Set securityContext.allowPrivilegeEscalation: false."),
        (r"hostPort", ("KN-S011",), "Remove hostPort; expose the port through a Service."),
        (r"hostNetwork|hostPID|hostIPC", ("KN-S009",), "Remove hostNetwork, hostPID and hostIPC."),
        (r"volumes", ("KN-S010",), "Replace the hostPath volume with a PVC, ConfigMap, Secret or emptyDir."),
        (r"seLinux", (), "Remove the custom seLinuxOptions; restricted-v2 assigns the namespace's SELinux level."),
        (r"seccomp", ("KN-S008",), "Use seccompProfile.type: RuntimeDefault."),
    )
)


def _scc(text: str, ns: str | None, sa: str | None) -> list[Denial]:
    out: list[Denial] = []
    seen: set[str] = set()
    for m in _SCC.finditer(text):
        body = m["body"]
        if body in seen:
            continue
        seen.add(body)
        parts = _SCC_PROVIDER.split(body)
        providers: dict[str, list[dict[str, str]]] = {}
        unusable: list[str] = []
        for name, raw in zip(parts[1::2], parts[2::2], strict=False):
            errors: list[dict[str, str]] = []
            for piece in _SCC_ERROR_SPLIT.split(raw.strip().rstrip(",")):
                chunk = piece.strip().rstrip(",")
                if "not usable by user or serviceaccount" in chunk:
                    unusable.append(name)
                    continue
                e = _SCC_ERROR.match(chunk)
                if e:
                    errors.append({"field": e["field"].lstrip("."), "error": e["kind"], "detail": e["rest"] or ""})
                elif chunk:
                    errors.append({"field": "", "error": "", "detail": chunk})
            if errors:
                providers[name] = errors
        rng = re.search(r"must be in the ranges: \[(\d+), (\d+)\]", body)
        uid_range = f" [{rng.group(1)}-{rng.group(2)}]" if rng else ""
        tried = (
            "restricted-v2"
            if "restricted-v2" in providers
            else next(iter(providers), None)  # the SCC the ServiceAccount may use
        )
        rules: list[str] = []
        fixes: list[str] = []
        for err in providers.get(tried or "", []):
            for pat, rule_ids, fix in _SCC_FIELDS:
                if pat.search(err["field"]):
                    rules.extend(rule_ids)
                    fixes.append(fix.format(range=uid_range))
                    break
            else:
                fixes.append(f"Fix {err['field'] or 'the pod spec'}: {err['detail']}")
        pod = _POD_FORBIDDEN.search(text)
        d = Denial(
            "openshift-scc",
            "unable to validate against any security context constraint",
            policy=tried if tried and tried not in unusable else None,
            resource=f"Pod/{pod['pod']}" if pod else None,
            namespace=ns,
            related_rules=rules,
            fixes=list(dict.fromkeys(fixes)),
        )
        d.details = {"triedProviders": providers, "notUsableByServiceAccount": unusable}
        if rng:
            d.details["namespaceUidRange"] = f"{rng.group(1)}-{rng.group(2)}"
        bad = "; ".join(f"{e['field']}: {e['detail']}" for e in providers.get(tried or "", []))
        d.meaning = (
            "OpenShift tried every SCC the requester and the pod's ServiceAccount may use, and none admitted the pod. "
            + (
                f"The SCC it may use, {tried}, rejected: {bad}. "
                if tried and tried not in unusable
                else (f"Field errors reported: {bad}. " if bad else "")
            )
            + (
                f"Not granted to the requester or the ServiceAccount: {', '.join(unusable[:8])}"
                + (f" and {len(unusable) - 8} more." if len(unusable) > 8 else ".")
                if unusable
                else ""
            )
        ).strip()
        account = f"system:serviceaccount:{_ns(ns)}:{sa or 'default'}"
        d.checks = [
            f"oc get events -n {_ns(ns)} --field-selector reason=FailedCreate",
            f"oc get ns {_ns(ns)} -o jsonpath='{{.metadata.annotations.openshift\\.io/sa\\.scc\\.uid-range}}'",
            "oc adm policy scc-subject-review -f <manifest.yaml>",
            f"oc get pods -n {_ns(ns)} -o jsonpath='{{range .items[*]}}{{.metadata.name}} "
            f'{{.metadata.annotations.openshift\\.io/scc}}{{"\\n"}}{{end}}\'',
            f"oc auth can-i use securitycontextconstraints/nonroot-v2 --as={account}",
        ]
        d.checks.append("kube-noob audit --platform openshift -f <manifest.yaml>")
        d.fixes.append("`kube-noob fix --platform openshift -f <manifest.yaml>` removes the fixed IDs from a manifest.")
        d.approvals.append(
            "Only if the workload truly needs it: grant the least permissive SCC that fits to its ServiceAccount "
            "(pods of a Deployment or DaemonSet are admitted with the ServiceAccount's SCCs, not yours), for example "
            f"`oc adm policy add-scc-to-user nonroot-v2 -z {sa or '<serviceaccount>'} -n {_ns(ns)}`. privileged is "
            "for cluster administration components only, never application workloads. Never edit the default SCCs "
            "(upgrades can reset them and platform pods can break); create your own SCC instead."
        )
        out.append(d)
    return out


# --- RHACS (StackRox) admission control --------------------------------------------------------------------------

_ROX_POLICY = re.compile(r"^[ \t]*Policy:[ \t]*(?P<name>[^\n]{1,200}?)[ \t]*$", re.MULTILINE)


def _rhacs(text: str, platform: str | None) -> list[Denial]:
    if not re.search(r"policyeval\.stackrox\.io|violated \d+ enforced polic|Failed currently enforced policies", text):
        return []
    from kube_noob.audit.engine import list_rules

    by_policy: dict[str, list[str]] = {}
    for r in list_rules():
        names: list[str] = list(r.get("stackroxPolicies") or [])  # type: ignore[call-overload]
        for p in names:
            by_policy.setdefault(p.lower(), []).append(str(r["ruleId"]))
    kc = _kubectl(platform, text)
    out: list[Denial] = []
    heads = list(_ROX_POLICY.finditer(text))
    for i, h in enumerate(heads):
        chunk = text[h.end() : heads[i + 1].start() if i + 1 < len(heads) else len(text)]
        rem = re.search(r"Remediation:\s*(?:\n\s*)?(?:↳\s*)?(?P<r>[^\n]+)", chunk)
        viol = re.search(r"Violations:\s*\n(?P<v>(?:\s+-\s+[^\n]+\n?)+)", chunk)
        violations = [v.strip()[1:].strip() for v in viol["v"].splitlines() if v.strip()] if viol else []
        name = h["name"]
        rules = by_policy.get(name.lower(), [])
        more_rules, fixes = _topics(name, " ".join(violations))
        d = Denial(
            "rhacs",
            "; ".join(violations) or f"Violated the enforced policy {name}",
            policy=name,
            related_rules=list(dict.fromkeys(rules + more_rules)),
        )
        d.meaning = f"RHACS enforced the policy '{name}' at deploy time" + (
            f": {'; '.join(violations)}." if violations else "."
        )
        if rem:
            d.fixes.append(rem["r"].strip())
        d.fixes += fixes
        d.checks = [
            "roxctl deployment check --file <manifest.yaml>",
            f"{kc} get securedcluster -A -o jsonpath='{{.items[*].spec.admissionControl}}'",
        ]
        d.approvals.append(
            "The break-glass annotation admission.stackrox.io/break-glass bypasses enforcement for emergencies only; "
            "it raises a violation and needs the security team's approval."
        )
        out.append(d)
    if (
        not out
        and re.search(r"failed calling webhook \"[^\"\n]{0,60}stackrox\.io\"", text)
        and not re.search(r"denied the request|violated \d+ enforced polic|Failed currently enforced policies", text)
    ):
        return []  # the webhook could not be called (timeout, unreachable): no policy was evaluated
    if not out:
        out.append(
            Denial(
                "rhacs",
                "RHACS admission control denied the request.",
                meaning="RHACS enforced a deploy-time policy; the full message lists each policy and its remediation.",
                checks=["roxctl deployment check --file <manifest.yaml>"],
            )
        )
    return out


# --- ResourceQuota and LimitRange ----------------------------------------------------------------------------

_QUOTA = re.compile(
    r"exceeded quota: (?P<quota>" + _NAME + r"), requested: (?P<req>[^\n]{1,500}?), used: (?P<used>[^\n]{1,500}?), "
    r"limited: (?P<lim>[^\s\"]{1,500})"
)
_QUOTA_SPECIFY = re.compile(r"failed quota: (?P<quota>" + _NAME + r"): must specify (?P<what>[^\n\"]{1,500})")
_LIMIT = re.compile(
    r"(?P<bound>maximum|minimum) (?P<res>[\w.-]{1,63}) usage per (?P<scope>Container|Pod|PersistentVolumeClaim) is "
    r"(?P<allowed>[^\s,]{1,30}), but (?P<field>limit|request) is (?P<value>[^\s,\]\"]{1,30})",
    re.IGNORECASE,
)
_RATIO = re.compile(
    r"(?P<res>[\w.-]{1,63}) max limit to request ratio per (?P<scope>Container|Pod) is (?P<allowed>[\d.]{1,20}), "
    r"but provided ratio is (?P<value>[\d.]{1,20})",
    re.IGNORECASE,
)
_SUFFIX = {
    "": 1.0,
    "m": 1e-3,
    "k": 1e3,
    "M": 1e6,
    "G": 1e9,
    "T": 1e12,
    "P": 1e15,
    "E": 1e18,
    "Ki": 2.0**10,
    "Mi": 2.0**20,
    "Gi": 2.0**30,
    "Ti": 2.0**40,
    "Pi": 2.0**50,
    "Ei": 2.0**60,
}


def parse_quantity(q: str) -> tuple[float, str] | None:
    m = re.fullmatch(r"([+-]?\d+(?:\.\d+)?)([a-zA-Z]{0,2})", q.strip())
    if not m or m.group(2) not in _SUFFIX:
        return None
    return float(m.group(1)) * _SUFFIX[m.group(2)], m.group(2)


def _fmt(value: float, unit: str) -> str:
    n = value / _SUFFIX[unit]
    return f"{n:.0f}{unit}" if abs(n - round(n)) < 0.005 else f"{n:.2f}{unit}"


def _pairs(s: str) -> dict[str, str]:
    return dict(p.split("=", 1) for p in s.strip().strip(",").split(",") if "=" in p)


def _quota(text: str, platform: str | None, ns: str | None) -> list[Denial]:
    kc = _kubectl(platform, text)
    out: list[Denial] = []
    for m in _QUOTA.finditer(text):
        req, used, lim = _pairs(m["req"]), _pairs(m["used"]), _pairs(m["lim"])
        lines = []
        for key, want in req.items():
            if key not in lim:
                continue
            w, u, cap = parse_quantity(want), parse_quantity(used.get(key, "0")), parse_quantity(lim[key])
            if w and u and cap:
                left = max(cap[0] - u[0], 0.0)
                lines.append(f"{key}: needs {want}, {_fmt(left, cap[1])} left of {lim[key]} (used {used.get(key)})")
            else:
                lines.append(f"{key}: requested {want}, used {used.get(key)}, limit {lim[key]}")
        d = Denial(
            "resource-quota",
            f"exceeded quota: {m['quota']}",
            policy=m["quota"],
            namespace=ns,
            related_rules=["KN-C004", "KN-C005"],
        )
        d.details = {"requested": req, "used": used, "limit": lim}
        d.meaning = f"ResourceQuota {m['quota']} in {_ns(ns)} has no room for this request: " + "; ".join(lines) + "."
        d.checks = [
            f"{kc} describe resourcequota {m['quota']} -n {_ns(ns)}",
            f"{kc} top pod -n {_ns(ns)}",
            f"{kc} get pods -n {_ns(ns)} --field-selector status.phase!=Running",
        ]
        d.fixes = [
            "Right-size the requests and limits from observed usage, or scale down or remove workloads in the "
            "namespace that no longer need their share.",
            "Completed or failed pods still count against object-count quotas: clean them up.",
        ]
        d.approvals.append(f"Raising {m['quota']} is the platform team's decision (it reserves cluster capacity).")
        out.append(d)
    for m in _QUOTA_SPECIFY.finditer(text):
        d = Denial(
            "resource-quota",
            f"failed quota: {m['quota']}: must specify {m['what'].strip()}",
            policy=m["quota"],
            namespace=ns,
            related_rules=["KN-C004", "KN-C005"],
        )
        d.meaning = (
            f"ResourceQuota {m['quota']} limits {m['what'].strip()}, so every container in {_ns(ns)} must set those "
            "requests and limits; this pod does not."
        )
        d.checks = [
            f"{kc} describe resourcequota {m['quota']} -n {_ns(ns)}",
            f"{kc} get limitrange -n {_ns(ns)} -o yaml",
        ]
        d.fixes = [
            "Set resources.requests and resources.limits for CPU and memory on every container (`kube-noob audit` "
            "flags missing ones as KN-C004 and KN-C005)."
        ]
        d.approvals.append("A LimitRange with defaults fills them in for every pod; the namespace owner decides that.")
        out.append(d)
    limits = list(_LIMIT.finditer(text)) + list(_RATIO.finditer(text))
    if limits:
        parts = []
        for m in limits:
            if "bound" in m.groupdict() and m.groupdict().get("bound"):
                parts.append(
                    f"{m['bound'].lower()} {m['res']} per {m['scope']} is {m['allowed']}, but the {m['field']} is "
                    f"{m['value']}"
                )
            else:
                parts.append(
                    f"{m['res']} limit-to-request ratio per {m['scope']} must be at most {m['allowed']}, "
                    f"but it is {float(m['value']):g}"
                )
        d = Denial("limit-range", "; ".join(parts), namespace=ns, related_rules=["KN-C004", "KN-C005", "KN-C006"])
        d.meaning = f"A LimitRange in {_ns(ns)} bounds per-container resources: " + "; ".join(parts) + "."
        d.checks = [f"{kc} get limitrange -n {_ns(ns)} -o yaml"]
        d.fixes = ["Set requests and limits inside the LimitRange's bounds (and within its limit-to-request ratio)."]
        d.approvals.append("Changing the LimitRange affects every pod in the namespace; the namespace owner decides.")
        out.append(d)
    return out


# --- RBAC ----------------------------------------------------------------------------------------------------

_RBAC = re.compile(
    r"User \"(?P<subject>[^\"\s'`$;&|<>()\\]{1,253})\" cannot (?P<verb>[a-z]+) "
    r"resource \"(?P<resource>[a-z0-9./-]{1,253})\" "
    r"in API group \"(?P<group>[a-z0-9.-]*)\"(?: in the namespace \"(?P<ns>" + _NAME + r")\"| at the cluster scope)?"
)


def _dns(name: str) -> str:
    out = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return out[:63].rstrip("-") or "kube-noob-grant"


def _rbac(text: str, platform: str | None) -> list[Denial]:
    kc = _kubectl(platform, text)
    out: list[Denial] = []
    seen: set[tuple[str, ...]] = set()
    for m in _RBAC.finditer(text):
        key = (m["subject"], m["verb"], m["resource"], m["group"], m["ns"] or "")
        if key in seen:
            continue
        seen.add(key)
        subject, verb, resource, group, ns = key
        base, _, sub = resource.partition("/")
        res_arg = f"{base}.{group}" if group else base
        can_i = f"{kc} auth can-i {verb} {res_arg}" + (f" --subresource={sub}" if sub else "")
        scope = f"-n {ns}" if ns else "--all-namespaces"
        sa = re.fullmatch(r"system:serviceaccount:(" + _NAME + r"):(" + _NAME + r")", subject)
        if sa:
            subj: dict[str, Any] = {"kind": "ServiceAccount", "name": sa.group(2), "namespace": sa.group(1)}
        elif subject.startswith("system:anonymous"):
            subj = {}
        else:
            subj = {"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": subject}
        where = f"in namespace {ns}" if ns else "at the cluster scope"
        d = Denial(
            "rbac",
            f'User "{subject}" cannot {verb} resource "{resource}" in API group "{group}" {where}',
            policy=None,
            namespace=ns or None,
            related_rules=["KN-S015", "KN-S016", "KN-S017"],
        )
        d.details = {"subject": subject, "verb": verb, "resource": resource, "apiGroup": group, "namespace": ns or None}
        d.meaning = f"{subject} has no RBAC permission to {verb} {resource} {where}."
        d.checks = [
            f"{can_i} {scope} --as={subject}",
            f"{kc} auth can-i --list {scope} --as={subject}",
            f"{kc} get rolebindings,clusterrolebindings -A -o wide",
        ]
        if not subj:
            d.meaning += " The request was not authenticated: fix the token or kubeconfig instead of granting access."
            d.fixes = ["Log in again or fix the ServiceAccount token the client sends; never grant system:anonymous."]
            out.append(d)
            continue
        name = _dns(f"{subj['name']}-{verb}-{base}{'-' + sub if sub else ''}")
        kind, binding = ("Role", "RoleBinding") if ns else ("ClusterRole", "ClusterRoleBinding")
        meta: dict[str, Any] = {"name": name, **({"namespace": ns} if ns else {})}
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": kind,
            "metadata": meta,
            "rules": [{"apiGroups": [group], "resources": [resource], "verbs": [verb]}],
        }
        bind = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": binding,
            "metadata": dict(meta),
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": kind, "name": name},
            "subjects": [subj],
        }
        d.patch = yaml.safe_dump_all([role, bind], sort_keys=False)
        d.fixes = [
            f"Grant exactly this verb on this resource with a {kind} and {binding} (the patch); never a wildcard or "
            "cluster-admin."
            + (" For Secrets, also restrict resourceNames to the ones the app reads." if base == "secrets" else ""),
        ]
        d.checks.append("kube-noob audit -f <role.yaml>")
        out.append(d)
    return out


# --- entry point ---------------------------------------------------------------------------------------------


def _namespace(text: str) -> str | None:
    for p in _NAMESPACE:
        m = p.search(text)
        if m:
            return m.group(1)
    return None


def admission_signal(denial: dict[str, Any]) -> str:
    """The signal name of a denial: ``engine``, or ``engine:policy/rule`` (``kube_noob.signals`` kind admission)."""
    parts = [p for p in (denial.get("policy"), denial.get("rule")) if p]
    return f"{denial['engine']}:{'/'.join(parts)}" if parts else str(denial["engine"])


def explain(text: str, platform: str | None = None) -> dict[str, Any]:
    """Every admission denial in ``text``, explained. Returns ``{"denials": [...], "summary": ..., ...}``.

    Names that end up in a command (policy, rule, namespace, subject) must match Kubernetes name syntax, so text
    pasted from a log can never smuggle shell syntax into a copy-paste command; control characters are dropped.
    """
    if len(text) > MAX_INPUT:
        text = text[-MAX_INPUT:]
    # dropped, not spaced, as before -- except inside a name, where it is marked rather than splicing the name;
    # newlines and tabs stay, because the patterns below read lines (G279)
    text = redact_text(sanitize.visible(text, replacement="", keep="\n\t"))
    ns = _namespace(text)
    sa = re.search(r"system:serviceaccount:" + _NAME + r":(" + _NAME + r")", text)
    denials: list[Denial] = []
    denials += _kyverno(text, platform)
    denials += _gatekeeper(text, platform)
    denials += _vap(text, platform)
    denials += _pod_security(text, platform, ns)
    denials += _scc(text, ns, sa.group(1) if sa else None)
    denials += _rhacs(text, platform)
    denials += _quota(text, platform, ns)
    denials += _rbac(text, platform)
    for d in denials:
        d.namespace = d.namespace or ns
    out: dict[str, Any] = {
        "approach": (
            "Read the policy and the object first (read-only). Change the object to satisfy the policy; exceptions, "
            "quota increases and new permissions are the policy owner's decision."
        ),
        "denials": [d.as_dict() for d in denials],
    }
    names = list(dict.fromkeys(admission_signal(d) for d in out["denials"]))
    first = {n: next(i for i, d in enumerate(out["denials"]) if admission_signal(d) == n) for n in names}
    out["signals"] = [{"kind": "admission", "name": n, "source": f"denial[{first[n]}]"} for n in names]
    if denials:
        names = [
            f"{ENGINES[d.engine]} {d.policy}" + (f"/{d.rule}" if d.rule else "") if d.policy else ENGINES[d.engine]
            for d in denials
        ]
        blocked = sum(1 for d in denials if d.mode == "deny")
        out["summary"] = (
            f"{blocked} polic{'y' if blocked == 1 else 'ies'} blocked this"
            + (f", {len(denials) - blocked} warned" if len(denials) > blocked else "")
            + ": "
            + "; ".join(dict.fromkeys(names))
            + "."
        )
    else:
        out["note"] = (
            "No admission denial found. Paste the whole error from `kubectl apply` / `oc apply`, or the FailedCreate "
            "event (`kubectl get events -n <namespace> --field-selector reason=FailedCreate`)."
        )
    return out
