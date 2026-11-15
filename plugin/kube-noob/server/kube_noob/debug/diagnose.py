"""Debugging: match symptoms (events, describe output, logs, CLI errors, status JSON) to playbooks.

Offline by default. ``debug_workload`` additionally collects live, read-only evidence when cluster access is enabled.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kube_noob import sanitize
from kube_noob.debug.cluster import Backend, list_items, redact_text
from kube_noob.debug.playbooks import EXIT_CODES, PLAYBOOKS, Cause, Playbook
from kube_noob.debug.steps import classify_step, split_comment
from kube_noob.errors import ClusterAccessError
from kube_noob.signals import Signal, for_text, playbooks_for
from kube_noob.signals.ceph import advice as ceph_advice

MAX_INPUT = 400_000
SIGNAL_WEIGHT = 1.0  # a playbook that catalogued signals point at gains this much, once: CrashLoopBackOff and
# BackOff name one symptom, so two symptom signals must not outrank the specific cause (OOMKilled) they share
MAX_SIGNALS_SHOWN = 50

_COMPILED: dict[str, list[re.Pattern[str]]] = {
    p.pid: [re.compile(s, re.IGNORECASE) for s in p.signals] for p in PLAYBOOKS
}

# Names come from command- or output-shaped text: a -n flag, a Namespace: field, JSON, 'namespace "shop"' as API
# errors quote it, namespace/shop; an unquoted word after "namespace" in a sentence ("a namespace issue") is English,
# so it needs a hyphen or digit (or is "default") unless it follows "in namespace" ("pods in namespace shop").
_NS_PATTERNS = (
    re.compile(r"(?:^|[\s'\"`(])(?:-n|--namespace)[ =]([a-z0-9][-a-z0-9]{0,62})\b"),
    re.compile(r"\bNamespace:\s+([a-z0-9][-a-z0-9]{0,62})"),
    re.compile(r"\"namespace\":\s*\"([a-z0-9][-a-z0-9]{0,62})\""),
    re.compile(r"\bnamespaces? \"([a-z0-9][-a-z0-9]{0,62})\""),
    re.compile(r"\bnamespaces?/([a-z0-9][-a-z0-9]{0,62})\b"),
    re.compile(r"\b(?:in|from|into|to) (?:the )?namespace ((?=[0-9-]*[a-z])[a-z0-9][-a-z0-9]{0,62})\b"),
    re.compile(r"\bnamespace ((?=[a-z0-9-]*[-0-9])(?=[0-9-]*[a-z])[a-z0-9][-a-z0-9]{0,62}|default)\b"),
)
# "pod/api-1", 'pod "api-1"', or "pod api-7d9f" in a sentence; a bare word after "pod " ("my pod keeps restarting")
# is English, so the unquoted form needs the hyphen or digit generated pod names carry. The name is whole: it ends in
# a letter or digit, and is followed by the kubelet's "_<namespace>" ("in pod web-7d9f-x2lqp_shop"), a sentence's
# full stop or anything a name cannot hold (a word boundary cut it at its last hyphen before "_").
_POD_PATTERNS = (
    re.compile(r"\bpod/\"?([a-z0-9][-a-z0-9.]{0,252})\"?"),
    re.compile(r"\bpod \"([a-z0-9][-a-z0-9.]{0,252})\""),
    re.compile(
        r"\bpod ((?=[a-z0-9.]*[-0-9])[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?)"
        r"(?=_[a-z0-9]|[^-a-z0-9._]|\.(?![a-z0-9])|\Z)"
    ),
    re.compile(r"^Name:\s+([a-z0-9][-a-z0-9.]{0,252})$", re.MULTILINE),
)
# The Service a paste is about: "svc/web", "kubectl get svc web" (a command, not "when I get endpoints for the
# router"), 'no endpoints available for service "web"', or the
# Name of `kubectl describe svc` output (it has Endpoints: or TargetPort: lines).
_SVC_PATTERNS = (
    re.compile(r"\b(?:svc|services?|endpoints|ep|endpointslices?)/\"?([a-z0-9][-a-z0-9]{0,62})\b"),
    re.compile(r"\b(?:kubectl|oc) get (?:svc|services?|endpoints|ep)[ \t]+([a-z0-9][-a-z0-9]{0,62})\b(?![./])"),
    re.compile(r"\b(?:no endpoints available for service|services?) \"([a-z0-9][-a-z0-9]{0,62})\""),
)
_DESCRIBE_SVC = re.compile(r"^(?:Endpoints|TargetPort):", re.MULTILINE)
_DESCRIBE_NAME = re.compile(r"^Name:\s+([a-z0-9][-a-z0-9]{0,62})\s*$", re.MULTILINE)
# A Service's selector: `kubectl describe svc` prints "Selector: app=web,tier=fe"; jsonpath {.spec.selector} prints
# a JSON object on the next line.
_SELECTOR_LINE = re.compile(
    r"^Selector:[ \t]+([\w./-]{1,253}=[\w.-]{0,63}(?:,[\w./-]{1,253}=[\w.-]{0,63}){0,9})[ \t]*$", re.M
)
_SELECTOR_JSON = re.compile(r"\.spec\.selector\b[^\n]{0,200}\n[ \t]*(\{[^\n{}]{1,600}\})")
_LABEL_KEY = re.compile(r"^[A-Za-z0-9][\w./-]{0,252}\Z")
_LABEL_VALUE = re.compile(r"^[A-Za-z0-9._-]{0,63}\Z")
# The same for claims: pvc/data-0, 'pvc "data"', claimName: data, or "pvc data-db-0" (the bare form needs a hyphen
# or digit: "the pvc is pending" names no claim).
_PVC_PATTERNS = (
    re.compile(r"\b(?i:persistentvolumeclaims?|pvc)/\"?([a-z0-9][-a-z0-9.]{0,252})"),
    re.compile(r"\b(?i:persistentvolumeclaims?|pvc) \"([a-z0-9][-a-z0-9.]{0,252})\""),
    re.compile(r"\bclaimName:[ \t]*\"?([a-z0-9][-a-z0-9.]{0,252})"),
    re.compile(r"\b(?i:persistentvolumeclaims?|pvc) ((?=[a-z0-9.]*[-0-9])[a-z0-9][-a-z0-9.]{0,252})\b"),
)
_SA_PATTERN = re.compile(r"system:serviceaccount:(?P<ns>[a-z0-9][-a-z0-9]{0,62}):([a-z0-9][-a-z0-9]{0,62})")
_SA_SPEC = re.compile(r"\bserviceAccountName[=:]\s*\"?([a-z0-9][-a-z0-9.]{0,252})")
_FORBIDDEN = re.compile(
    r"User \"(?P<subject>[A-Za-z0-9@._:/=+#%-]{1,253})\" cannot (?P<verb>[a-z]+) resource "
    r"\"(?P<resource>[a-z0-9./-]{1,253})\""
    r"(?: in API group \"(?P<group>[a-z0-9.-]*)\")?"
)
_EXIT_PATTERN = re.compile(r"(?:exit ?code|exitCode)[\"':\s]+(\d{1,3})", re.IGNORECASE)


@dataclass
class Diagnosis:
    playbook: Playbook
    score: float
    evidence: list[str]
    checks: list[str]
    fixes: list[str] | None = None  # the playbook's fixes with the names from the input filled in
    causes: list[str] | None = None  # the same for its root causes
    likely: tuple[str, list[str]] | None = None  # the cause the input points at and its fixes (cause-linked triage)
    knowledge: list[str] | None = None  # the playbook's reading that fits the platform

    def as_dict(self) -> dict[str, Any]:
        p = self.playbook
        likely = {"likelyCause": self.likely[0], "likelyFixes": self.likely[1]} if self.likely is not None else {}
        return {
            "id": p.pid,
            "title": p.title,
            "confidence": round(min(1.0, self.score / 3.0), 2),
            "evidence": self.evidence,
            **likely,
            "rootCauses": list(p.root_causes if self.causes is None else self.causes),
            # Diagnose before change: read-only evidence first; anything that executes or mutates needs approval.
            "readOnlyNextSteps": [_step(c) for c in self.checks if classify_step(c) == "read"],
            "diagnosticCommands": [
                {**_step(c), "requiresApproval": True} for c in self.checks if classify_step(c) == "exec"
            ],
            "proposedChanges": [
                {"change": f, "requiresApproval": True} for f in (p.fixes if self.fixes is None else self.fixes)
            ],
            "relatedRules": list(p.related_rules),
            "knowledge": list(p.knowledge if self.knowledge is None else self.knowledge),
        }


def _step(check: str) -> dict[str, str]:
    """A copy-paste-safe step: the bare command plus why it helps, or a plain instruction for prose guidance."""
    cmd, why = split_comment(check)
    if re.match(r"^[a-z][\w.-]*\s", cmd + " ") is None:
        return {"instruction": check.strip()}
    return {"command": cmd, **({"why": why} if why else {})}


def _step_line(step: dict[str, str]) -> str:
    if "command" not in step:
        return f"- {step['instruction']}"
    return f"- `{step['command']}`" + (f": {step['why']}" if step.get("why") else "")


@dataclass
class DiagnoseResult:
    diagnoses: list[Diagnosis]
    context: dict[str, str]
    exit_codes: dict[int, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    ceph: dict[str, Any] | None = None  # Ceph health codes and Rook/ODF alerts explained (kube_noob.signals.ceph)

    def as_dict(self) -> dict[str, Any]:
        return {
            "approach": (
                "Run the read-only steps first (get, describe, logs, events). Commands that execute in a container or "
                "change the cluster are listed separately and require explicit approval."
            ),
            "context": self.context,
            "signals": [x.as_dict() for x in self.signals[:MAX_SIGNALS_SHOWN]],
            "exitCodes": {str(k): v for k, v in self.exit_codes.items()},
            **({"cephHealth": self.ceph} if self.ceph else {}),
            "diagnoses": [d.as_dict() for d in self.diagnoses],
            "notes": self.notes,
        }


def _first(patterns: tuple[re.Pattern[str], ...], text: str) -> str | None:
    for p in patterns:
        m = p.search(text)
        if m:
            return m.group(1)
    return None


# English words that follow "namespace" in a sentence ("a different namespace from the pod") and are not its name.
_NOT_A_NAMESPACE = frozenset(
    {
        "a", "an", "and", "another", "are", "as", "at", "but", "by", "different", "does", "for", "from", "has", "in",
        "into", "is", "it", "its", "level", "of", "on", "or", "other", "same", "scoped", "than", "that", "the", "then",
        "this", "to", "was", "which", "while", "with", "without",
        "after", "all", "also", "although", "any", "be", "been", "before", "because", "can", "cannot", "could", "did",
        "do", "each", "even", "every", "here", "if", "isn", "just", "must", "not", "only", "should", "since", "so",
        "still", "there", "though", "unless", "until", "were", "when", "where", "will", "would", "yet",
    }
)  # fmt: skip
# kube-scheduler's Scheduled event: "Successfully assigned <namespace>/<pod> to <node>" (pkg/scheduler/schedule_one.go)
_ASSIGNED = re.compile(r"Successfully assigned ([a-z0-9][-a-z0-9]{0,62})/([a-z0-9][-a-z0-9.]{0,252}) to ")
_PULL_SECRETS = re.compile(r"Unable to retrieve some image pull secrets \(([a-z0-9][-a-z0-9.]{0,252})")


def _namespace(text: str) -> str | None:
    for p in _NS_PATTERNS:
        for m in p.finditer(text):
            if m.group(1) not in _NOT_A_NAMESPACE:
                return m.group(1)
    return None


def extract_context(text: str) -> dict[str, str]:
    ctx: dict[str, str] = {}
    ns = _namespace(text)
    assigned = _ASSIGNED.search(text)
    if ns:
        ctx["ns"] = ns
    elif assigned:
        ctx["ns"] = assigned.group(1)
    m = _PULL_SECRETS.search(text)
    if m:
        ctx["secret"] = m.group(1)
    pod = _first(_POD_PATTERNS, text) or (assigned.group(2) if assigned else None)
    if pod:
        ctx["pod"] = pod
        ctx.setdefault("name", pod)
    pvc = _first(_PVC_PATTERNS, text)
    if pvc:
        ctx["pvc"] = pvc
    svc = _first(_SVC_PATTERNS, text)
    if svc is None and _DESCRIBE_SVC.search(text) and (m := _DESCRIBE_NAME.search(text)):
        svc = m.group(1)
    if svc:
        ctx["svc"] = svc
    selector = _selector(text)
    if selector:
        ctx["selector"] = selector
    m = _SA_PATTERN.search(text)
    if m:
        ctx["sa"], ctx["sa_ns"] = m.group(2), m.group("ns")
    elif m := _SA_SPEC.search(text):
        ctx["sa"] = m.group(1)
    m = _FORBIDDEN.search(text)
    if m:
        ctx["subject"], ctx["verb"] = m.group("subject"), m.group("verb")
        group = m.group("group")
        ctx["resource"] = f"{m.group('resource')}.{group}" if group else m.group("resource")
    return ctx


def _selector(text: str) -> str | None:
    """The Service selector as ``k=v,k=v`` when every key and value is a valid label (anything else stays a
    placeholder)."""
    m = _SELECTOR_LINE.search(text)
    if m:
        return m.group(1)
    m = _SELECTOR_JSON.search(text)
    if not m:
        return None
    try:
        doc = sanitize.loads_bounded(m.group(1))
    except ValueError:
        return None
    if not isinstance(doc, dict) or not doc or len(doc) > 10:
        return None
    pairs = []
    for k, v in doc.items():
        if not (isinstance(v, str) and _LABEL_KEY.match(k) and _LABEL_VALUE.match(v)):
            return None
        pairs.append(f"{k}={v}")
    return ",".join(pairs)


_SAFE_VALUE = re.compile(r"^(?!#)[A-Za-z0-9@._:/=+#%,-]{1,600}\Z")  # nothing a shell treats specially, no spaces


def _fill(cmd: str, ctx: dict[str, str]) -> str:
    """``cmd`` with the names found in the input. A value that could do anything in a shell (quotes, $, `, ;, |, &,
    spaces, newlines...) is never pasted into a command: its placeholder stays, so a copied step only ever reads."""
    ctx = {k: v for k, v in ctx.items() if isinstance(v, str) and _SAFE_VALUE.match(v)}
    out = cmd
    sa_ns = ctx.get("sa_ns") or ctx.get("ns", "<namespace>")
    sa_subject = f"system:serviceaccount:{sa_ns}:{ctx.get('sa', 'default')}"
    defaults = {
        "ns": "<namespace>",
        "pod": "<pod>",
        "name": "<name>",
        "pvc": "<pvc>",
        "svc": "<service>",
        "selector": "<selector>",
        "secret": "<secret>",
        "sa": "default",
        "subject": sa_subject if "sa" in ctx else "<user-or-serviceaccount>",
        "verb": "<verb>",
        "resource": "<resource>",
    }
    for key, default in defaults.items():
        out = out.replace("{" + key + "}", ctx.get(key, default))
    return out.replace("{{", "{").replace("}}", "}")


_OPENSHIFT_ONLY = re.compile(
    r"#\s*\[(OCP|ROSA)\]|\boc (get|describe) (route|scc|securitycontextconstraints)\b|\boc adm (?!top)"
)
_KUBERNETES_ONLY = re.compile(r"#\s*\[K8S\]")  # e.g. kubeadm's static pods in kube-system


_ROSA_STEP = re.compile(r"^rosa\s|#\s*\[ROSA\]")


def _for_platform(cmd: str, platform: str | None, rosa: bool = False) -> str | None:
    """Commands as the user's platform spells them: plain Kubernetes gets kubectl and no OpenShift-only steps;
    OpenShift and ROSA get no steps marked [K8S]. ``platform`` None means no platform was given and the text says
    OpenShift or ROSA, so it is treated as OpenShift. A `rosa` step needs a ROSA platform, or no platform and text
    that says ROSA (``rosa``)."""
    if _ROSA_STEP.search(cmd) and not (platform in ("rosa-classic", "rosa-hcp") or (platform is None and rosa)):
        return None
    if platform != "kubernetes" and _KUBERNETES_ONLY.search(cmd):
        return None
    if platform != "kubernetes" or not cmd.startswith(("oc ", "openssl", "kubectl")):
        return cmd
    if _OPENSHIFT_ONLY.search(cmd):
        return None
    cmd = re.sub(r"^oc adm top ", "kubectl top ", cmd)
    rsh = re.match(r"^oc rsh (-n \S+ )?(\S+) (.+)$", cmd)
    if rsh:
        return f"kubectl exec {rsh.group(1) or ''}{rsh.group(2)} -- {rsh.group(3)}"
    return re.sub(r"^oc ", "kubectl ", cmd)


def _fix_applies(fix: str, platform: str | None) -> bool:
    """Fixes marked [OCP] or [ROSA] are for OpenShift; [K8S] for plain Kubernetes. With no platform, all apply."""
    if platform == "kubernetes":
        return not fix.startswith(("[OCP]", "[ROSA]"))
    if platform:
        return not fix.startswith("[K8S]")
    return True


_ROSA_CONTEXT = re.compile(r"(?i)\b(?:rosa|hypershift|hosted control planes?|hcp)\b")
_TAG = re.compile(r"^(?:\[(OCP|ROSA|K8S)\]|On (OpenShift|ROSA)\b)")
_WHEN: dict[tuple[str, int], tuple[re.Pattern[str], ...]] = {
    (p.pid, c.cause): tuple(re.compile(w, re.IGNORECASE) for w in c.when) for p in PLAYBOOKS for c in p.causes
}


def _tag(text: str) -> str | None:
    m = _TAG.match(text)
    if not m:
        return None
    return (m.group(1) or ("OCP" if m.group(2) == "OpenShift" else "ROSA")).upper()


def _fits(text: str, platform: str | None, openshift: bool, rosa: bool) -> bool:
    """Whether a cause or fix marked [OCP], [ROSA], [K8S] (or "On OpenShift") fits: the platform decides when it is
    given; without one, an OpenShift or ROSA cause needs the text to say so (G83), and a [K8S] one needs it not to."""
    tag = _tag(text)
    if tag is None:
        return True
    if platform == "kubernetes":
        return tag == "K8S"
    if platform:
        return tag != "K8S"
    if tag == "K8S":
        return not (openshift or rosa)
    return rosa if tag == "ROSA" else openshift or rosa


def likely_cause(p: Playbook, text: str, platform: str | None, openshift: bool, rosa: bool) -> Cause | None:
    """The cause ``text`` points at: three points for each of the cause's own patterns it matches, plus the
    rarity-weighted words it shares with the cause and its fixes; the playbook's order breaks ties. When no cause's
    own patterns match, a playbook with a ``default_cause`` shows that one (its most common cause; graders found shared
    words a worse guess there), and otherwise the shared-word guess skips AWS causes for text about another cloud or
    hardware (``_OTHER_INFRA``). A cause that does not fit the platform (``_fits``) is never chosen."""
    if not p.causes:
        return None
    from kube_noob.insight import _playbook_word_counts, _specific_terms

    df = _playbook_word_counts()
    want = _specific_terms(text[:20_000], kubernetes_words=True)
    best: Cause | None = None
    best_score = -1.0
    guess: Cause | None = None  # the best cause by shared words alone that suits the text's infrastructure
    guess_score = -1.0
    default: Cause | None = None
    evidence = False
    elsewhere = bool(_OTHER_INFRA.search(text)) and not _AWS_TEXT.search(text)
    for c in sorted(p.causes, key=lambda c: c.cause):
        cause = p.root_causes[c.cause]
        if not _fits(cause, platform, openshift, rosa):
            continue
        if c.cause == p.default_cause:
            default = c
        hits = sum(1 for w in _WHEN[(p.pid, c.cause)] if w.search(text))
        evidence = evidence or hits > 0
        words = _specific_terms(" ".join([cause, *(p.fixes[i] for i in c.fixes)]), kubernetes_words=True)
        score = 3.0 * hits + sum(1.0 / df.get(t, 1) for t in want & words)
        if score > best_score:
            best, best_score = c, score
        if score > guess_score and not (elsewhere and _AWS_CAUSE.search(cause)):
            guess, guess_score = c, score
    if evidence:
        return best
    return default or guess or best


# Without evidence, a cause about AWS pieces (EFS, EBS, security groups) is no guess for text about another cloud or
# about hardware you run yourself (community graders: EFS advice on GKE and on-prem NFS posts, cloud security groups
# on a bare-metal cluster).
_AWS_CAUSE = re.compile(r"\b(?:EFS|EBS|AWS|security groups?|gp[23](?:-csi)?|VPC)\b|\bcloud\b", re.IGNORECASE)
_AWS_TEXT = re.compile(r"\b(?:aws|amazon|eks|ec2|efs|ebs|rosa|gp[23])\b", re.IGNORECASE)
_OTHER_INFRA = re.compile(
    r"\b(?:azure|aks|gke|gce|google cloud|gcp|vsphere|bare[- ]?metal|on[- ]?prem\w*|openstack|homelab|minikube|"
    r"kind cluster|k3s|microk8s|nutanix|proxmox)\b",
    re.IGNORECASE,
)


# Reading about ROSA or OpenShift is none for plain Kubernetes or for text about another cloud (red team: a GKE
# post cited the ROSA EFS doc).
_PLATFORM_READING = ("rosa-", "ocp-")


# Patterns too common to name an OpenShift playbook when the text does not say it is OpenShift: a bare "Permission
# denied" is a Docker entrypoint without +x as often as an arbitrary UID. The playbook's specific patterns (nginx's
# "mkdir() ... failed (13: Permission denied)") still name it.
_WEAK_WITHOUT_CONTEXT: dict[str, frozenset[str]] = {
    "DBG-ARBITRARY-UID": frozenset({"EACCES", "Permission denied"}),
    "DBG-CLUSTEROPERATOR": frozenset({r"Degraded\s+True", r"Available\s+False"}),
}


#: Names an Alertmanager payload's labels alone may set (``kube_noob.signals.alertmanager.label_context``).
LABEL_ONLY_CONTEXT = ("ns", "pod", "name")


def diagnose(
    text: str,
    platform: str | None = None,
    limit: int = 5,
    signals: list[Signal] | None = None,
    context: dict[str, str] | None = None,
) -> DiagnoseResult:
    """Rank playbooks for ``text``: one point per matching pattern plus ``SIGNAL_WEIGHT`` when catalogued signals point
    at the playbook (``kube_noob.signals``: an alert name, a container or event reason, a phrase such as "leader
    changed"), times the playbook's weight. ``signals`` overrides the signals read from ``text``, e.g. the ones read
    from an Alertmanager payload; ``context`` likewise overrides the names steps are filled with."""
    if len(text) > MAX_INPUT:
        text = text[-MAX_INPUT:]
    text = redact_text(text)
    ctx = extract_context(text)
    if context is not None:
        # An Alertmanager payload: the namespace and the pod, which decide what every step reads, come from its labels
        # and never from its annotations, which are prose that anyone writing the alert rule controls (G274). A service
        # or a claim the labels name wins over the text; one they do not name is still read from the text, and so is
        # every other name (the verb and resource of a "forbidden" message, its user, a pull secret, a selector):
        # labels never carry those, and replacing the whole context with the labels' lost them all.
        for key in LABEL_ONLY_CONTEXT:
            ctx.pop(key, None)
        ctx.update(context)
    if signals is None:
        signals = for_text(text)
    linked = playbooks_for(signals)
    lines = text.splitlines()
    results: list[Diagnosis] = []
    openshift = rosa = False
    if not platform:
        from kube_noob.known_issues import openshift_cluster_context

        openshift = openshift_cluster_context(text)
        rosa = bool(_ROSA_CONTEXT.search(text))
    # Steps as the user's platform spells them; with none given, text that never says OpenShift or ROSA gets kubectl
    # and no OpenShift-only steps (G83).
    steps_platform = platform or (None if openshift or rosa else "kubernetes")
    other_cloud = bool(_OTHER_INFRA.search(text)) and not _AWS_TEXT.search(text)
    for p in PLAYBOOKS:
        if platform and platform not in p.platforms:
            continue
        # No platform given: an OpenShift playbook needs the text to say it is OpenShift (a bare "Permission denied"
        # is not the arbitrary-UID problem on Docker), and a ROSA playbook needs ROSA or hosted control planes.
        weak: frozenset[str] = frozenset()
        if not platform and "kubernetes" not in p.platforms:
            if set(p.platforms) <= {"rosa-hcp", "rosa-classic"} and not rosa:
                continue  # a ROSA playbook needs ROSA or hosted control planes in the text
            if not openshift:
                if p.pid not in _WEAK_WITHOUT_CONTEXT:
                    continue  # an OpenShift playbook needs the text to say it is OpenShift
                weak = _WEAK_WITHOUT_CONTEXT[p.pid]  # without it, only the playbook's specific patterns count
        evidence: list[str] = [f"signal {x.kind} {x.name}" for x in linked.get(p.pid, [])]
        hits = 0
        for pat in _COMPILED[p.pid]:
            if pat.pattern in weak or not pat.search(text):  # one scan; the line is looked up only for matches
                continue
            matched_line = next((ln.strip() for ln in lines if pat.search(ln)), pat.pattern)
            if matched_line is not None:
                hits += 1
                clipped = matched_line[:300]
                if clipped not in evidence:
                    evidence.append(clipped)
        boost = SIGNAL_WEIGHT if p.pid in linked else 0.0
        if hits or boost:
            score = (hits + boost) * p.weight
            cause = likely_cause(p, text, platform, openshift, rosa)
            order = list(range(len(p.checks)))
            if cause is not None:  # the steps that confirm the likely cause first
                order = [*cause.checks, *(i for i in order if i not in cause.checks)]
            checks = [_for_platform(_fill(p.checks[i], ctx), steps_platform, rosa) for i in order]
            fixes = [_fill(f, ctx) for f in p.fixes if _fix_applies(f, platform)]
            reading = [
                k
                for k in p.knowledge
                if not (k.startswith(_PLATFORM_READING) and (steps_platform == "kubernetes" or other_cloud))
            ]
            causes = [_fill(c, ctx) for c in p.root_causes if _fix_applies(c, platform)]
            likely = None
            if cause is not None:
                likely = (
                    _fill(p.root_causes[cause.cause], ctx),
                    [_fill(p.fixes[i], ctx) for i in cause.fixes if _fits(p.fixes[i], platform, openshift, rosa)],
                )
            results.append(Diagnosis(p, score, evidence[:5], [c for c in checks if c], fixes, causes, likely, reading))
    results.sort(key=lambda d: (-d.score, d.playbook.pid))
    codes = {int(c) for c in _EXIT_PATTERN.findall(text)}
    exit_info = {c: EXIT_CODES[c] for c in sorted(codes) if c in EXIT_CODES}
    # Ceph health codes and Rook/ODF alerts: what each means, read-only steps for the platform, and when to stop.
    ceph = ceph_advice(signals, text, platform, openshift or rosa)
    notes: list[str] = []
    if not results and not ceph:
        cli = "kubectl" if steps_platform == "kubernetes" else "oc"
        notes.append(
            f"No playbook matched. Paste `{cli} describe pod`, `{cli} get events --sort-by=.lastTimestamp` and "
            f"`{cli} logs --previous` output for a better diagnosis."
        )
    return DiagnoseResult(results[:limit], ctx, exit_info, notes, signals, ceph)


# --- live collection ---------------------------------------------------------------------------------------

WORKLOAD_RESOURCES = {
    "deployment": "deployments",
    "deployments": "deployments",
    "statefulset": "statefulsets",
    "statefulsets": "statefulsets",
    "daemonset": "daemonsets",
    "daemonsets": "daemonsets",
    "job": "jobs",
    "jobs": "jobs",
    "pod": "pods",
    "pods": "pods",
}


def _selector_string(sel: dict[str, Any]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted((sel.get("matchLabels") or {}).items()))


def _pod_summary(pod: dict[str, Any]) -> list[str]:
    out: list[str] = []
    name = pod.get("metadata", {}).get("name")
    status = pod.get("status", {})
    spec = pod.get("spec") or {}
    out.append(f"pod/{name} phase={status.get('phase')} node={spec.get('nodeName')}")
    pull = [str(s.get("name")) for s in spec.get("imagePullSecrets") or [] if isinstance(s, dict) and s.get("name")]
    if pull or spec.get("serviceAccountName"):  # names only: kube-noob never reads a Secret
        out.append(f"  spec serviceAccountName={spec.get('serviceAccountName') or 'default'} imagePullSecrets={pull}")
    for cond in status.get("conditions") or []:
        if cond.get("status") != "True":
            out.append(
                f"  condition {cond.get('type')}={cond.get('status')} {cond.get('reason', '')} "
                f"{cond.get('message', '')}"
            )
    for cs in (status.get("initContainerStatuses") or []) + (status.get("containerStatuses") or []):
        state, last = cs.get("state") or {}, cs.get("lastState") or {}
        for k, v in state.items():
            if k != "running":
                out.append(
                    f"  container {cs.get('name')} {k}: {v.get('reason', '')} {v.get('message', '')} "
                    f"exitCode: {v.get('exitCode', '')}"
                )
        if "terminated" in last:
            t = last["terminated"]
            out.append(
                f"  container {cs.get('name')} lastState terminated: {t.get('reason')} exitCode: {t.get('exitCode')}"
            )
        out.append(f"  container {cs.get('name')} ready={cs.get('ready')} restartCount: {cs.get('restartCount')}")
    return out


_PULL_REASONS = frozenset({"ErrImagePull", "ImagePullBackOff"})


def _service_account_pull_secrets(backend: Backend, namespace: str, pods: list[dict[str, Any]]) -> list[str]:
    """For pods stuck pulling: the pull secret names their ServiceAccounts link (names only, never a Secret)."""
    accounts: list[str] = []
    for pod in pods:
        statuses = (pod.get("status") or {}).get("containerStatuses") or []
        if any(((cs.get("state") or {}).get("waiting") or {}).get("reason") in _PULL_REASONS for cs in statuses):
            sa = (pod.get("spec") or {}).get("serviceAccountName") or "default"
            if sa not in accounts:
                accounts.append(sa)
    out: list[str] = []
    for sa in accounts[:3]:
        try:
            obj = backend.get("serviceaccounts", name=sa, namespace=namespace)
        except ClusterAccessError:
            continue  # the ServiceAccount is a bonus; the events already name the missing secret
        names = [str(s.get("name")) for s in obj.get("imagePullSecrets") or [] if isinstance(s, dict)]
        out.append(f"serviceaccount/{sa} imagePullSecrets={names}")
    return out


def collect_evidence(backend: Backend, namespace: str, kind: str, name: str, log_lines: int = 100) -> dict[str, Any]:
    resource = WORKLOAD_RESOURCES.get(kind.lower())
    if resource is None:
        raise ClusterAccessError(f"Unsupported workload kind {kind!r}; use one of {sorted(set(WORKLOAD_RESOURCES))}")
    lines: list[str] = []
    obj = backend.get(resource, name=name, namespace=namespace)
    pods: list[dict[str, Any]]
    if resource == "pods":
        pods = [obj]
    else:
        st = obj.get("status") or {}
        lines.append(
            f"{kind}/{name} status: "
            + json.dumps(
                {
                    k: st.get(k)
                    for k in (
                        "replicas",
                        "readyReplicas",
                        "availableReplicas",
                        "updatedReplicas",
                        "unavailableReplicas",
                        "failed",
                        "succeeded",
                    )
                    if k in st
                }
            )
        )
        for cond in st.get("conditions") or []:
            lines.append(
                f"  condition {cond.get('type')}={cond.get('status')} {cond.get('reason', '')}: "
                f"{cond.get('message', '')}"
            )
        sel = (obj.get("spec") or {}).get("selector") or {}
        sel_str = _selector_string(sel) if resource != "jobs" else f"job-name={name}"
        pods = (
            list_items(backend.get("pods", namespace=namespace, selector=sel_str), "pods", namespace) if sel_str else []
        )
    for pod in pods[:10]:
        lines.extend(_pod_summary(pod))
    lines.extend(_service_account_pull_secrets(backend, namespace, pods[:10]))
    # a response without an items list is a failed read, not "no events" (G279)
    events = list_items(backend.get("events", namespace=namespace), "events", namespace)
    names = {name} | {p.get("metadata", {}).get("name") for p in pods}
    rel = [
        e
        for e in events
        if (e.get("involvedObject") or {}).get("name") in names
        or str((e.get("involvedObject") or {}).get("name", "")).startswith(name)
    ]
    rel.sort(key=lambda e: e.get("lastTimestamp") or e.get("eventTime") or "")
    for e in rel[-40:]:
        io = e.get("involvedObject") or {}
        lines.append(f"event {e.get('type')} {e.get('reason')} {io.get('kind')}/{io.get('name')}: {e.get('message')}")
    logs: dict[str, str] = {}
    for pod in pods[:3]:
        pname = pod.get("metadata", {}).get("name")
        for cs in (pod.get("status") or {}).get("containerStatuses") or []:
            crashed = bool((cs.get("lastState") or {}).get("terminated")) or cs.get("restartCount", 0) > 0
            try:
                logs[f"{pname}/{cs.get('name')}"] = backend.logs(
                    namespace, pname, cs.get("name"), log_lines, previous=crashed
                )
            except ClusterAccessError as exc:
                logs[f"{pname}/{cs.get('name')}"] = f"<logs unavailable: {exc}>"
    return {"summary": lines, "logs": logs, "object": obj}


def debug_workload(
    backend: Backend,
    namespace: str,
    kind: str,
    name: str,
    platform: str | None = None,
    log_lines: int = 100,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    from kube_noob.debug.cluster import cluster_info
    from kube_noob.debug.policy import explain as explain_denials
    from kube_noob.known_issues import match as known_issue_match

    ev = collect_evidence(backend, namespace, kind, name, log_lines)
    blob = "\n".join(ev["summary"]) + "\n" + "\n".join(ev["logs"].values())
    blob += f"\nNamespace: {namespace}\n"
    unread: str | None = None
    try:
        info: dict[str, Any] = cluster_info(backend)
    except Exception as exc:  # noqa: BLE001 - the version is a bonus; the diagnosis must not depend on it
        info, unread = {}, str(exc)[:200] or type(exc).__name__
    platform = platform or ("openshift" if info.get("openshift") else None)
    result = diagnose(blob, platform=platform)
    if "pod" not in result.context:
        result.context["name"] = name
    reported = known_issue_match(blob, platform, info.get("openshift"), 3, data_dir)
    if unread is not None and "versionCoverage" in reported:
        # "No version was given" would blame the user for a read that failed (G277).
        reported["versionCoverage"] = {
            "status": "not-narrowed",
            "versionUnreadable": unread,
            "why": f"The cluster's version could not be read ({unread}), so the answer is not narrowed by version: "
            "it covers every indexed release, including issues the cluster may already have the fix for.",
        }
    denials = explain_denials(blob, platform)["denials"]
    return {
        "backend": backend.name,
        "target": f"{kind}/{namespace}/{name}",
        # platformNotRead travels too: without it an unread ClusterVersion showed as `openshift: null` and the
        # known-issue match below silently ran without a platform (G279)
        "cluster": {
            k: info.get(k)
            for k in ("kubernetes", "openshift", "platformNotRead", "newerThanKnowledge", "warnings")
            if k in info
        },
        "evidence": ev["summary"],
        "logs": {k: v[-6000:] for k, v in ev["logs"].items()},
        **result.as_dict(),
        "knownIssues": reported["matches"],
        **({"knownIssuesCoverage": reported["versionCoverage"]} if "versionCoverage" in reported else {}),
        **({"policyDenials": denials} if denials else {}),
    }


def bundle_markdown(result: dict[str, Any]) -> str:
    """Human-readable diagnostic bundle: evidence first, then read-only steps, then gated commands and changes."""
    lines = [
        f"# Diagnostic bundle: {result['target']}",
        "",
        f"Collected read-only via `{result['backend']}`. Secrets were not read; sensitive values are redacted.",
        *(
            ["", f"**Platform not known:** {(result.get('cluster') or {})['platformNotRead']}."]
            if (result.get("cluster") or {}).get("platformNotRead")
            else []
        ),
        "",
        "## Evidence",
        *(f"- {e}" for e in result.get("evidence", [])),
    ]
    if result.get("signals"):
        lines += ["", "## Signals", ""]
        lines += [
            f"- {x['kind']} {x['name']}" + (f" ({x['detail']})" if x.get("detail") else "") for x in result["signals"]
        ]
    ceph = result.get("cephHealth") or {}
    if ceph.get("stop"):
        lines += ["", f"**{ceph['stop']}**"]
    for e in ceph.get("entries", []):
        lines += ["", f"## Ceph {e['code']}" + (f" ({e['severity']})" if e.get("severity") else ""), "", e["meaning"]]
        lines += ["", "Likely causes:", *(f"- {c}" for c in e["likelyCauses"]), "", f"Fix: {e['fix']}"]
        lines += [f"Escalate: {e['escalate']}"] if e.get("escalate") else []
        lines += ["", "Read-only next steps:", *(_step_line(s) for s in e["readOnlyNextSteps"])]
        if e["diagnosticCommands"]:
            lines += ["", "In the Rook toolbox (require approval):", *(_step_line(c) for c in e["diagnosticCommands"])]
    for m in result.get("memory", []):
        state_label = {
            "fix": "fix",
            "runbook": "runbook",
            "retired": "retired",
            "tried, did not work": "tried, did not work",
        }
        lines += ["", f"## Team memory {m['citation']}: {state_label[m['state']]}", "", m["symptom"], ""]
        lines += [f"- Cause: {m['cause']}", f"- Fix: {m['fix']['text']}", f"- {m['outcomes']['summary']}"]
        lines += [f"- Note: {m['note']}"] if m.get("note") else []
    for m in result.get("knownIssues", []):
        lines += ["", f"## Reported issue {m['id']}", "", m["status"], "", m["summary"], "", f"- Issue: {m['url']}"]
        lines += [f"- Workaround: {m['workaround']}"] if m.get("workaround") else []
        lines += [f"- Release notes: {m['source']}"]
    from kube_noob.known_issues import coverage_line

    if limit := coverage_line(result.get("knownIssuesCoverage"), listed=bool(result.get("knownIssues"))):
        lines += ["", f"Reported issues: {limit}"]
    for p in result.get("policyDenials", []):
        title = f"{p['engineName']} {p.get('policy') or ''}".strip() + (f" / {p['rule']}" if p.get("rule") else "")
        lines += ["", f"## Denied by {title}", "", p["meaning"], "", "Read-only next steps:"]
        lines += [_step_line(s) for s in p.get("readOnlyNextSteps", [])]
        lines += ["", "Proposed changes (require approval):"]
        lines += [f"- {c['change']}" for c in p.get("proposedChanges", [])]
        if p.get("patch"):
            lines += ["", "```yaml", p["patch"].rstrip(), "```"]
    for d in result.get("diagnoses", []):
        lines += ["", f"## {d['id']}: {d['title']} (confidence {d['confidence']})", "", "Likely causes:"]
        lines += [f"- {c}" for c in d["rootCauses"]]
        lines += ["", "Read-only next steps:", *(_step_line(s) for s in d["readOnlyNextSteps"])]
        if d["diagnosticCommands"]:
            lines += ["", "Diagnostic commands that execute in a container (require approval):"]
            lines += [_step_line(c) for c in d["diagnosticCommands"]]
        lines += ["", "Proposed changes (require approval):"]
        lines += [f"- {c['change']}" for c in d["proposedChanges"]]
    if result.get("logs"):
        lines += ["", "## Recent logs (redacted)"]
        for name, text in result["logs"].items():
            lines += ["", f"### {name}", "```", text[-3000:], "```"]
    return sanitize.visible_lines("\n".join(lines) + "\n")  # nothing that does not print reaches the file (G279)


# --- text view (`kube-noob diagnose`, the default --format) -------------------------------------------------

# Every top-level field of the diagnose result is either rendered by ``render_text`` or left out for a stated
# reason; tests/test_diagnose_text.py fails on a field that is in neither, so a new caveat cannot be dropped from
# the text view by default (G221, G277).
TEXT_RENDERED = frozenset(
    {
        "input",
        "context",
        "signals",
        "exitCodes",
        "cephHealth",
        "diagnoses",
        "notes",
        "knownIssues",
        "knownIssuesCoverage",
        "memory",
        "memoryNotes",
        "policyDenials",
        "approach",
        "inputTruncated",
        "untrusted",
        "injectionSignals",
        "injectionSignalsTruncated",
    }
)
TEXT_OMITTED = {
    "knowledgeAsOf": "added by the MCP and REST surfaces, not by the CLI; `kube-noob doctor` prints the dates",
}
# One level down: every field of a diagnosis, decided the same way (rendered, or counted with where to see it).
DIAGNOSIS_RENDERED = frozenset(
    {
        "id",
        "title",
        "confidence",
        "evidence",
        "likelyCause",
        "likelyFixes",
        "rootCauses",
        "readOnlyNextSteps",
        "diagnosticCommands",
        "proposedChanges",
        "relatedRules",
        "knowledge",
    }
)
DIAGNOSIS_OMITTED: dict[str, str] = {}
MAX_TEXT_CHANGES = 3  # proposed changes shown for the top diagnosis; --format yaml has every one
MAX_TEXT_EVIDENCE = 3  # evidence lines shown for the top diagnosis; the rest are counted


class _Verbatim(str):
    """A line that is a command: its spacing is part of it, so the final pass makes it visible without collapsing
    its whitespace (a newline in it still becomes a space, so it cannot start a line of its own)."""


def _text_step(s: dict[str, Any], indent: str) -> list[str]:
    out: list[str] = (
        [_Verbatim(f"{indent}{s['command']}")] if s.get("command") else [f"{indent}{s.get('instruction', '')}"]
    )
    return out + ([f"{indent}  why: {s['why']}"] if s.get("why") else [])


def _text_diagnosis(d: dict[str, Any], others: list[dict[str, Any]]) -> list[str]:
    # Fields joined by a separator the final whitespace collapse keeps (two spaces did not survive it).
    lines = [f"{d['id']} \u00b7 {d['title']} \u00b7 confidence {d['confidence']}"]
    evidence = d.get("evidence") or []
    if evidence:
        lines.append("  evidence: " + "; ".join(str(e) for e in evidence[:MAX_TEXT_EVIDENCE]))
        if len(evidence) > MAX_TEXT_EVIDENCE:
            lines[-1] += f" (+{len(evidence) - MAX_TEXT_EVIDENCE} more: --format yaml)"
    causes = list(d.get("rootCauses") or [])
    if d.get("likelyCause"):
        # The input pointed at this cause; the playbook's others are still possible and are counted, not dropped.
        lines.append(f"  likely cause: {d['likelyCause']}")
        rest = [c for c in causes if c != d["likelyCause"]]
        if rest:
            lines.append(f"  other possible causes: {len(rest)} (--format yaml lists them)")
    elif causes:
        # Nothing in the input singled one out: the first cause is the playbook's order, not a finding.
        lines.append(f"  possible causes ({len(causes)}, not narrowed by the input): {causes[0]}")
        if len(causes) > 1:
            lines.append(f"    +{len(causes) - 1} more: --format yaml lists them")
    n = 0
    if d.get("readOnlyNextSteps"):
        n += 1
        lines.append(f"  {n}. read-only first:")
        for s in d["readOnlyNextSteps"]:
            lines += _text_step(s, "     ")
    if d.get("diagnosticCommands"):
        n += 1
        lines.append(f"  {n}. runs in a container (needs approval):")
        for s in d["diagnosticCommands"]:
            lines += _text_step(s, "     ")
    changes = list(d.get("likelyFixes") or []) or [c["change"] for c in d.get("proposedChanges") or []]
    if changes:
        n += 1
        lines.append(f"  {n}. change, only after the evidence (needs approval):")
        lines += [f"     - {c}" for c in changes[:MAX_TEXT_CHANGES]]
        total = len(d.get("proposedChanges") or [])
        if total > min(len(changes), MAX_TEXT_CHANGES):
            lines.append(f"     ({total} proposed changes in all: --format yaml lists every one)")
    if d.get("relatedRules"):
        lines.append(f"  caught before deploy by: {', '.join(d['relatedRules'])} (kube-noob audit)")
    if d.get("knowledge"):
        lines.append(f"  docs: {', '.join(d['knowledge'])} (kube-noob search)")
    if others:
        also = "; ".join(f"{x['id']} {x['title']} ({x['confidence']})" for x in others)
        lines.append(f"also possible: {also}. Their steps: --format yaml")
    return lines


def _text_ceph(ceph: dict[str, Any]) -> list[str]:
    lines = [""] + ([f"STOP: {ceph['stop']}"] if ceph.get("stop") else [])
    for e in ceph.get("entries", []):
        sev = f" ({e['severity']})" if e.get("severity") else ""
        lines.append(f"Ceph {e['code']}{sev}: {e['meaning']}")
        lines += [f"  cause: {c}" for c in e.get("likelyCauses", [])]
        lines.append(f"  fix (needs approval): {e['fix']}")
        if e.get("escalate"):
            lines.append(f"  escalate: {e['escalate']}")
        if e.get("readOnlyNextSteps"):
            lines.append("  read-only first:")
            for s in e["readOnlyNextSteps"]:
                lines += _text_step(s, "    ")
        if e.get("diagnosticCommands"):
            lines.append("  in the toolbox (needs approval):")
            for s in e["diagnosticCommands"]:
                lines += _text_step(s, "    ")
    for a in ceph.get("alerts", []):
        lines.append(f"alert {a['alert']}: {a.get('meaning') or 'no explanation catalogued'}")
    if ceph.get("readOnlyNextSteps"):
        lines.append("Ceph, read-only first:")
        for s in ceph["readOnlyNextSteps"]:
            lines += _text_step(s, "  ")
    if ceph.get("diagnosticCommands"):
        lines.append("Ceph, in the toolbox (needs approval):")
        for s in ceph["diagnosticCommands"]:
            lines += _text_step(s, "  ")
    if ceph.get("notCatalogued"):
        lines.append(f"not catalogued, so not explained: {', '.join(ceph['notCatalogued'])}")
    return [*lines, ceph["note"]]


def _text_denial(p: dict[str, Any]) -> list[str]:
    name = " / ".join(x for x in (p.get("policy"), p.get("rule")) if x)
    head = ("WARN " if p.get("mode") == "warn" else "DENY ") + p["engineName"] + (f"  {name}" if name else "")
    lines = ["", head + (f"  ({p['resource']})" if p.get("resource") else ""), f"  {p['meaning']}"]
    if p.get("readOnlyNextSteps"):
        lines.append("  check (read-only):")
        for s in p["readOnlyNextSteps"]:
            lines += _text_step(s, "    ")
    if p.get("proposedChanges"):
        lines.append("  fix (needs approval):")
        for c in p["proposedChanges"]:
            owner = " (the policy owner decides)" if c.get("needsPolicyOwner") else ""
            lines.append(f"    - {c['change']}{owner}")
    return lines


def _text_reported(result: dict[str, Any]) -> list[str]:
    from kube_noob.known_issues import coverage_line

    known = result.get("knownIssues") or []
    limit = coverage_line(result.get("knownIssuesCoverage"), listed=bool(known))
    lines = [""] if known or limit else []
    for m in known:
        lines += [f"reported issue {m['id']}: {m.get('status') or ''}", f"  {m.get('summary') or m.get('title') or ''}"]
        lines += [f"  workaround: {m['workaround']}"] if m.get("workaround") else []
        lines.append(f"  {m['url']}")
    lines += [limit] if limit else []
    memory = result.get("memory") or []
    if memory or result.get("memoryNotes"):
        lines.append("")
    for m in memory:
        lines += _text_memory(m)
    return lines + [f"team memory not read: {n}" for n in result.get("memoryNotes") or []]


# One level down, as for a diagnosis: every field of a team-memory match is rendered or left out for a reason.
MEMORY_RENDERED = frozenset(
    {"citation", "state", "symptom", "cause", "fix", "versions", "outcomes", "note", "riskAccepted", "file", "owners"}
)
MEMORY_OMITTED = {
    "id": "the citation carries it",
    "status": "only approved entries are attached to an answer",
    "kind": "the state says it (fix, runbook, tried and did not work, retired)",
    "repository": "a local path; the file name is shown",
    "platform": "the entry was matched for this platform",
    "sources": "provenance links, in the entry file",
    "evidence": "counted on the evidence line; listed in the entry file",
    "matchedBy": "why it matched, not what it says; in --format yaml",
}


def _text_memory(m: dict[str, Any]) -> list[str]:
    lines = [f"team memory {m['citation']} ({m['state']}): {m['symptom']}"]
    if m.get("cause"):
        lines.append(f"  cause: {m['cause']}")
    fix = m.get("fix") or {}
    if fix.get("text"):
        lines.append(f"  fix: {fix['text']}")
    for c in fix.get("commands") or []:
        label = "read-only" if c.get("label") == "read-only" else "needs approval"
        lines += [f"  {label}:", _Verbatim(f"    {c.get('command', '')}")]
    if fix.get("patch"):
        lines.append(f"  patch: {len(str(fix['patch']).splitlines())} lines (needs approval; --format yaml shows it)")
    v = m.get("versions") or {}
    if v:
        lines.append("  versions: " + ", ".join(f"{k} {v[k]}" for k in sorted(v)))
    if m.get("outcomes", {}).get("summary"):
        lines.append(f"  {m['outcomes']['summary']}")
    if m.get("riskAccepted"):
        ra = m["riskAccepted"]
        lines.append(f"  risk accepted by {ra.get('owner')}: {ra.get('reason')}")
    if m.get("evidence"):
        lines.append(f"  evidence: {len(m['evidence'])} item(s) in {m.get('file') or 'the entry'}")
    elif m.get("file"):
        lines.append(f"  entry: {m['file']}")
    if m.get("owners"):
        lines.append(f"  owners: {', '.join(m['owners'])}")
    if m.get("note"):
        lines.append(f"  note: {m['note']}")
    return lines


def _text_caveats(result: dict[str, Any]) -> list[str]:
    tail: list[str] = []
    cut = result.get("inputTruncated") or {}
    if cut:
        tail.append(f"input cut: {cut['why']}")
    if result.get("untrusted"):
        kinds = ", ".join(sorted({str(x.get("kind")) for x in result.get("injectionSignals") or []}))
        more = result.get("injectionSignalsTruncated")
        tail.append(
            f"untrusted: text from the input was neutralised ({kinds or 'see injectionSignals'})"
            + (f", {more} more signals not listed" if more else "")
        )
    tail += [f"note: {n}" for n in result.get("notes") or []]
    tail += [f"exit code {code}: {meaning}" for code, meaning in (result.get("exitCodes") or {}).items()]
    payload = result.get("input") or {}
    if payload:
        names = ", ".join(payload.get("alertnames") or [])
        source = f" (from the {payload['versionFrom']})" if payload.get("versionFrom") else ""
        version = f"; version {payload['version']}{source}" if payload.get("version") else "; no version in it"
        tail.append(f"input: {payload.get('kind')}, {payload.get('alerts')} alerts, {payload.get('firing')} firing")
        tail[-1] += f" ({names}){version}"
        if payload.get("payloadVersion") and payload.get("versionFrom") == "argument":
            tail.append(f"the payload says {payload['payloadVersion']} (from the {payload.get('payloadVersionFrom')})")
        if payload.get("versionConflict"):
            tail.append(f"version conflict: {payload['versionConflict']}")
    # An error template's name is a hash that means nothing to a reader; its kind and the line it came from do.
    shown = [f"{x['kind']} {x['name']}" for x in result.get("signals") or [] if x["kind"] != "error_template"]
    tail += ["signals: " + ", ".join(shown)] if shown else []
    ctx = result.get("context") or {}
    tail += ["context: " + ", ".join(f"{k}={v}" for k, v in ctx.items())] if ctx else []
    return ["", *tail] if tail else []


def render_text(result: dict[str, Any]) -> str:
    """The diagnosis as a person reads it: the most likely playbook with its read-only steps first and what needs
    approval labelled as such, then Ceph health, denials, reported issues and team memory, then every caveat the
    structured result carries (notes, a version not covered, memory that could not be read). Same input, same text.
    """
    diagnoses = result.get("diagnoses") or []
    lines = _text_diagnosis(diagnoses[0], diagnoses[1:]) if diagnoses else []
    if result.get("cephHealth"):
        lines += _text_ceph(result["cephHealth"])
    for p in result.get("policyDenials") or []:
        lines += _text_denial(p)
    lines += _text_reported(result) + _text_caveats(result)
    if result.get("approach") and (diagnoses or result.get("cephHealth") or result.get("policyDenials")):
        lines += ["", f"{result['approach']} Here they are marked (needs approval)."]
    while lines and not lines[0]:
        lines.pop(0)

    # Every element is one line: a newline or an invisible character inside a value from the input (a memory
    # symptom, an alert name, a denial message) would otherwise forge a line or hide text in one. ``sanitize``'s
    # one rule (G279) decides what is shown: a removed character inside a name is marked, never spliced out.
    def shown(x: str) -> str:
        indent = x[: len(x) - len(x.lstrip(" "))]
        if isinstance(x, _Verbatim):
            return indent + sanitize.visible(x.lstrip(" ")).replace("\n", " ").replace("\r", " ")
        return indent + sanitize.one_line(x)

    return "\n".join(shown(x) for x in lines)
