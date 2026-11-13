"""A STRIDE threat model per application, from its manifests and the attack-path model (requirements R5.4).

Elements, read from the manifests:

- entry points: Routes, Ingresses, public or node-network Services that select the application's workloads;
- trust boundaries: internet to cluster (each entry point), pod to node (each workload), pod to the Kubernetes API
  (each mounted ServiceAccount token), and the namespace's network (NetworkPolicies);
- data stores: workloads that keep data: a StatefulSet, a PersistentVolumeClaim, or a database, cache or broker
  image or port (PostgreSQL, MySQL/MariaDB, MongoDB, Redis/Valkey, Memcached, Kafka, RabbitMQ, Elasticsearch/
  OpenSearch, Cassandra, etcd);
- identities: the ServiceAccounts whose tokens the pods mount, with the RBAC rights the bundle grants them.

Each threat names the element, the STRIDE category, the kube-noob rules that check its mitigation (and the generated
admission policies and RHACS policies that enforce them), MITRE ATT&CK for Containers technique ids, and a status:

- open: a mitigating rule fails on the element (the evidence lists the findings), or the right exists;
- mitigated: every mitigating rule passes on the element;
- not assessed: the mitigation needs input that was not given (a vulnerability report for public-facing exploits).

An application is the workloads sharing ``app.kubernetes.io/part-of``, else a namespace. The output is
deterministic: the same manifests give the same threats in the same order. Secrets in the input are never read
(``kube_noob.attack_paths`` drops them).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from kube_noob import sanitize
from kube_noob.attack_paths import Inventory, Reach, ambiguous_notes, workload_reach
from kube_noob.sanitize import visible
from kube_noob.vuln import attack

_STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}
_DATA_IMAGES = re.compile(
    r"(?:^|/)(?:postgres(?:ql)?|mysql|mariadb|mongo(?:db)?|redis|valkey|memcached|kafka|rabbitmq|elasticsearch|"
    r"opensearch|cassandra|etcd)(?:[-_][a-z0-9-]*)?(?::|@|$)",
    re.I,
)
_DATA_PORTS = frozenset({5432, 3306, 27017, 6379, 11211, 9092, 5672, 9200, 9042, 2379})
MAX_THREATS = 2000


@dataclass(frozen=True)
class Template:
    tid: str
    category: str
    title: str
    rules: tuple[str, ...]
    techniques: tuple[str, ...]
    mitigation: str


TEMPLATES: dict[str, Template] = {
    t.tid: t
    for t in (
        Template(
            "TM-S01",
            "S",
            "Clients cannot tell the real service from an impostor, and traffic can be read or changed in transit",
            ("KN-N002", "KN-N003", "KN-V016"),
            (),
            "terminate TLS at the Route or Ingress (edge, reencrypt or passthrough) and redirect plain HTTP",
        ),
        Template(
            "TM-S02",
            "S",
            "A token stolen from the pod acts as its ServiceAccount against the Kubernetes API",
            ("KN-S014",),
            ("T1528", "T1550.001"),
            "set automountServiceAccountToken: false where the pod does not call the API",
        ),
        Template(
            "TM-S03",
            "S",
            "Anyone who can create a Service can intercept traffic to the Service's external IP (CVE-2020-8554, "
            "unpatched by design)",
            ("KN-N008",),
            (),
            "no spec.externalIPs (publish through a LoadBalancer Service, a Route or an Ingress) and the "
            "DenyServiceExternalIPs admission controller",
        ),
        Template(
            "TM-T01",
            "T",
            "A different image can run under the same reference",
            ("KN-S012",),
            ("T1525", "T1204.003"),
            "reference images by digest (and admit only signed images)",
        ),
        Template(
            "TM-T02",
            "T",
            "Code in the container can change its own files and binaries at run time",
            ("KN-S007", "KN-S003"),
            ("T1036.005",),
            "readOnlyRootFilesystem: true and a non-root user",
        ),
        Template(
            "TM-R01",
            "R",
            "Commands run through exec in the pods are attributable only through the API server audit log",
            ("KN-S017",),
            ("T1609",),
            "grant pods/exec to no workload identity, and keep pods/exec and pods/attach in the API server audit "
            "policy at Metadata level or above",
        ),
        Template(
            "TM-I01",
            "I",
            "Any pod in the cluster can connect to the data store",
            ("KN-N001", "KN-N007", "KN-N012"),
            ("T1046", "T1613"),
            "a NetworkPolicy that admits only the application's own tiers to the store's port",
        ),
        Template(
            "TM-I02",
            "I",
            "Credentials are written in the manifests, readable by anyone with the repository or the API",
            ("KN-S013", "KN-S018", "KN-S026"),
            ("T1552.001",),
            "move them to Secrets created outside Git (an external secrets operator or sealed secrets)",
        ),
        Template(
            "TM-I03",
            "I",
            "The ServiceAccount can read Secrets: credentials and tokens of other ServiceAccounts",
            ("KN-S015", "KN-S016", "KN-S017"),
            ("T1552.007",),
            "drop get/list/watch on secrets, or name the one Secret it needs in resourceNames",
        ),
        Template(
            "TM-D01",
            "D",
            "One workload can starve its node or be starved: no CPU or memory requests and limits",
            ("KN-C004", "KN-C005"),
            ("T1499", "T1496.001"),
            "set CPU and memory requests and a memory limit",
        ),
        Template(
            "TM-D02",
            "D",
            "A single pod or a voluntary eviction takes the service down",
            ("KN-C007", "KN-C008", "KN-C009"),
            ("T1499",),
            "two or more replicas spread across nodes, and a PodDisruptionBudget that allows one eviction",
        ),
        Template(
            "TM-E01",
            "E",
            "A flaw in the exposed workload gives an attacker code execution in its pods",
            ("KN-S012",),
            ("T1190",),
            "patch fixable vulnerabilities (kube-noob vuln report), and pin the scanned image by digest",
        ),
        Template(
            "TM-E02",
            "E",
            "Code in the pod can escape to the node",
            (
                "KN-S001",
                "KN-S002",
                "KN-S005",
                "KN-S009",
                "KN-S010",
                "KN-S019",
                "KN-S020",
                "KN-S021",
                "KN-S022",
                "KN-S023",
                "KN-S025",
            ),
            ("T1611", "T1068"),
            "no privileged mode, host namespaces or hostPath; drop capabilities; allowPrivilegeEscalation: false; no "
            "gitRepo volume, no '+' or '=' in a sysctl, no workingDir under /proc, no shell characters in a subPath "
            "(published runtime breakouts)",
        ),
        Template(
            "TM-E04",
            "E",
            "An Ingress annotation or path injects configuration into the ingress-nginx controller, which reads every "
            "Secret in the cluster",
            ("KN-N009", "KN-N011"),
            ("T1190", "T1552.007"),
            "no snippet or other Critical- or High-risk ingress-nginx annotation and no ImplementationSpecific path; a "
            "fixed controller release with --enable-annotation-validation; a Gateway API implementation in place of "
            "the retired ingress-nginx",
        ),
        Template(
            "TM-E03",
            "E",
            "The ServiceAccount's RBAC lets code in the pod act beyond the application",
            ("KN-S015", "KN-S016", "KN-S017", "KN-S019"),
            ("T1098.006", "T1609", "T1610"),
            "bind a Role with only the verbs and resources the application calls",
        ),
    )
}
_CAP_TECHNIQUES = {
    "exec into pods": ("T1609",),
    "kubelet API through nodes/proxy": ("T1609",),
    "create or change workloads": ("T1610",),
    "run privileged pods": ("T1610", "T1611"),
    "escalate, bind or impersonate": ("T1098.006",),
    "full control": ("T1098.006", "T1610"),
}


class ThreatError(ValueError):
    """Input the threat model cannot read."""


@dataclass
class Element:
    kind: str  # entry point | workload | data store | identity | network
    ref: str


@dataclass
class Threat:
    template: Template
    element: Element
    status: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    detail: str = ""
    techniques: tuple[str, ...] = ()

    def as_dict(self, policies: set[str], stackrox: dict[str, list[str]]) -> dict[str, Any]:
        t = self.template
        techniques = self.techniques or t.techniques
        return {
            "id": f"{t.tid} {self.element.ref}",
            "threat": t.tid,
            "stride": _STRIDE[t.category],
            "element": {"kind": self.element.kind, "ref": self.element.ref},
            "title": t.title,
            **({"detail": self.detail} if self.detail else {}),
            "status": self.status,
            "evidence": self.evidence,
            "mitigation": t.mitigation,
            "rules": list(t.rules),
            "policies": [f"kube-noob-{r.lower()}" for r in t.rules if r in policies],
            "rhacsPolicies": sorted({p for r in t.rules for p in stackrox.get(r, [])}),
            "attack": [attack.technique(x) for x in techniques],
        }


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    raw = (obj.get("metadata") or {}).get("labels")
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


def _app_of(obj: dict[str, Any]) -> str:
    ns = str((obj.get("metadata") or {}).get("namespace") or "default")
    part = _labels(obj).get("app.kubernetes.io/part-of")
    return f"{ns}/{part}" if part else ns


def _pod_spec(obj: dict[str, Any]) -> dict[str, Any]:
    kind = obj.get("kind")
    spec: Any = obj.get("spec") or {}
    if kind == "CronJob":
        spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    elif kind != "Pod":
        spec = (spec.get("template") or {}).get("spec")
    return spec if isinstance(spec, dict) else {}


def _is_store(obj: dict[str, Any]) -> bool:
    if obj.get("kind") == "StatefulSet" or (obj.get("spec") or {}).get("volumeClaimTemplates"):
        return True
    spec = _pod_spec(obj)
    if any(isinstance(v, dict) and v.get("persistentVolumeClaim") for v in spec.get("volumes") or []):
        return True
    for c in [*(spec.get("containers") or []), *(spec.get("initContainers") or [])]:
        if not isinstance(c, dict):
            continue
        if isinstance(c.get("image"), str) and _DATA_IMAGES.search(c["image"]):
            return True
        for p in c.get("ports") or []:
            if isinstance(p, dict) and p.get("containerPort") in _DATA_PORTS:
                return True
    return False


@dataclass
class _Audit:
    by_resource: dict[str, list[dict[str, Any]]]
    by_namespace: dict[str, list[dict[str, Any]]]


def _audit(docs: list[Any], platform: str, version: str | None) -> _Audit:
    from kube_noob.audit.engine import analyze

    report = analyze(docs, platform=platform, version=version)
    by_resource: dict[str, list[dict[str, Any]]] = {}
    by_namespace: dict[str, list[dict[str, Any]]] = {}
    for f in report.findings:
        item = {"rule": f.rule_id, "resource": f.resource, "path": f.path, "severity": f.severity.name.lower()}
        by_resource.setdefault(f.resource, []).append(item)
        if f.doc_index is not None and 0 <= f.doc_index < len(docs):
            by_namespace.setdefault(docs[f.doc_index].namespace or "default", []).append(item)
    return _Audit(by_resource, by_namespace)


def _sorted(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(items, key=lambda f: (f["rule"], f["resource"], f["path"]))


def _evidence(audit: _Audit, refs: Iterable[str], rules: Iterable[str]) -> list[dict[str, Any]]:
    wanted = set(rules)
    return _sorted(f for ref in dict.fromkeys(refs) for f in audit.by_resource.get(ref, []) if f["rule"] in wanted)


def _generated_policies(platform: str, version: str | None) -> set[str]:
    from kube_noob.generate import policies

    gen = policies.generate(platform=platform, platform_version=version, engines=("vap",))
    return {str(g["ruleId"]) for g in gen.generated if g.get("ruleId")}


def _role_refs(evidence: str) -> list[str]:
    return re.findall(r"\b(?:Cluster)?Role/[A-Za-z0-9._:/-]+", evidence)


def _status(evidence: list[dict[str, Any]]) -> str:
    return "open" if evidence else "mitigated"


def _workload_threats(
    r: Reach, obj: dict[str, Any], audit: _Audit, exposed: bool, store: bool, vulnerable: dict[str, str] | None
) -> list[Threat]:
    el = Element("data store" if store else "workload", r.ref)
    out: list[Threat] = []
    for tid in ("TM-T01", "TM-T02", "TM-D01"):
        ev = _evidence(audit, [r.ref], TEMPLATES[tid].rules)
        out.append(Threat(TEMPLATES[tid], el, _status(ev), ev))
    if exposed or store:
        ev = _evidence(audit, [r.ref], TEMPLATES["TM-D02"].rules)
        out.append(Threat(TEMPLATES["TM-D02"], el, _status(ev), ev))
    ev = _evidence(audit, [r.ref], TEMPLATES["TM-E02"].rules)
    node = sorted({c.name for c in r.node})
    out.append(Threat(TEMPLATES["TM-E02"], el, "open" if ev or node else "mitigated", ev, "; ".join(node)))
    if exposed:
        if vulnerable is None or r.ref not in vulnerable:
            out.append(
                Threat(
                    TEMPLATES["TM-E01"],
                    el,
                    "not assessed",
                    [],
                    "no vulnerability report for this workload's images: run kube-noob vuln report",
                )
            )
        else:
            summary = vulnerable[r.ref]
            out.append(Threat(TEMPLATES["TM-E01"], el, "open" if summary else "mitigated", [], summary))
    if store:
        ev = _sorted(f for f in audit.by_namespace.get(r.namespace, []) if f["rule"] in TEMPLATES["TM-I01"].rules)
        out.append(Threat(TEMPLATES["TM-I01"], el, _status(ev), ev))
    # Every token of every object of this name: two different Deployments of one name are both modelled (G273).
    for sa, how in [t for t in (r.token,) if t is not None]:
        ev = _evidence(audit, [r.ref], TEMPLATES["TM-S02"].rules)
        out.append(
            Threat(TEMPLATES["TM-S02"], Element("identity", sa), "open", ev or [{"token": how}], f"mounted in {r.ref}")
        )
    for cap, tail in sorted(r.api, key=lambda x: (-x[0].weight, x[0].name)):
        sa = tail[0].target
        what = f"{cap.name} ({cap.scope})"
        techniques: tuple[str, ...] = ()
        if cap.name.startswith("read Secrets"):
            tpl = TEMPLATES["TM-I03"]
            what = cap.scope + (" (named objects only)" if "named objects" in cap.name else "")
        else:
            tpl = TEMPLATES["TM-E03"]
            techniques = next((v for k, v in _CAP_TECHNIQUES.items() if cap.name.startswith(k)), ())
        ev = _evidence(audit, _role_refs(cap.evidence), tpl.rules) or [{"grant": cap.evidence}]
        out.append(Threat(tpl, Element("identity", sa), "open", ev, what, techniques))
        if cap.name.startswith(("exec into pods", "kubelet API")):
            out.append(Threat(TEMPLATES["TM-R01"], Element("identity", sa), "open", ev, what))
    return out


def model(
    text: str,
    *,
    platform: str = "kubernetes",
    version: str | None = None,
    vulnerable_images: dict[str, str] | None = None,
    default_namespace: str | None = None,
) -> dict[str, Any]:
    """The threat model of every application in ``text`` (YAML manifests). ``vulnerable_images`` maps a workload ref
    to a one-line vulnerability summary (from ``kube-noob vuln report``), or to ``""`` when its report shows nothing
    fixable at high or above or exploited."""
    from kube_noob.attack_paths import object_ref
    from kube_noob.audit.rules import RULES
    from kube_noob.yamlio import load_documents

    docs = load_documents(text)
    inv = Inventory.from_documents((d.data for d in docs), default_namespace=default_namespace)
    reach = workload_reach(inv)
    audit = _audit(docs, platform, version)
    policies = _generated_policies(platform, version)
    stackrox = {rid: list(r.stackrox_policies) for rid, r in RULES.items()}
    # Looked up by `Reach.object`, the carrying object's own ref, not by the reach key: an embedded component's
    # key is `Kind/ns/name[component]`, and matching that against `object_ref` found nothing, so a Ray head the
    # scan had just called internet-reachable produced zero applications and zero threats here (G231).
    kinds = {r.object.split("/")[0] for r in reach.values() if r.object}
    objects = {object_ref(o): o for kind in kinds for o in inv.of(kind)}
    apps: dict[str, list[str]] = {}
    for ref in sorted(reach):
        obj = objects.get(reach[ref].object)
        if obj is not None:
            apps.setdefault(_app_of(obj), []).append(ref)
    out_apps: list[dict[str, Any]] = []
    total = 0
    for app, refs in sorted(apps.items()):
        threats: list[Threat] = []
        entry_points: dict[str, str] = {}
        exposed: set[str] = set()
        for ref in refs:
            for _, entry, steps in reach[ref].entries:
                first = next((s.target for s in steps if s.source in {"internet", "node network"}), entry.service)
                entry_points.setdefault(first, entry.exposure)
                exposed.add(ref)
        for entry_ref in sorted(entry_points):
            entry_kind = entry_ref.split("/")[0]
            if entry_kind in {"Route", "Ingress"}:
                ev = _evidence(audit, [entry_ref], TEMPLATES["TM-S01"].rules)
                threats.append(Threat(TEMPLATES["TM-S01"], Element("entry point", entry_ref), _status(ev), ev))
            if entry_kind == "Ingress":
                ev = _evidence(audit, [entry_ref], TEMPLATES["TM-E04"].rules)
                threats.append(Threat(TEMPLATES["TM-E04"], Element("entry point", entry_ref), _status(ev), ev))
            if entry_kind == "Service":
                ev = _evidence(audit, [entry_ref], TEMPLATES["TM-S03"].rules)
                threats.append(Threat(TEMPLATES["TM-S03"], Element("entry point", entry_ref), _status(ev), ev))
        stores = [ref for ref in refs if _is_store(objects[reach[ref].object])]
        for ref in refs:
            threats.extend(
                _workload_threats(
                    reach[ref],
                    objects[reach[ref].object],
                    audit,
                    ref in exposed,
                    ref in stores,
                    vulnerable_images,
                )
            )
        namespaces = {reach[ref].namespace for ref in refs}
        app_refs = [ref for ns in sorted(namespaces) for ref in sorted(audit.by_resource) if f"/{ns}/" in ref]
        ev = _evidence(audit, app_refs, TEMPLATES["TM-I02"].rules)
        threats.append(Threat(TEMPLATES["TM-I02"], Element("application", app), _status(ev), ev))
        threats = _dedupe(threats)
        threats.sort(key=lambda t: ("STRIDE".index(t.template.category), t.template.tid, t.element.ref, t.detail))
        total += len(threats)
        if total > MAX_THREATS:
            raise ThreatError(f"more than {MAX_THREATS} threats: model fewer applications at a time")
        rows = [t.as_dict(policies, stackrox) for t in threats]
        out_apps.append(
            {
                "application": app,
                # Each copy of an ambiguous name is its own reach (keyed `ref#2`...); listed by its reference once.
                "workloads": list(dict.fromkeys(reach[ref].ref for ref in refs)),
                "entryPoints": [{"ref": k, "exposure": v} for k, v in sorted(entry_points.items())],
                "dataStores": list(dict.fromkeys(reach[ref].ref for ref in stores)),
                # The one place a union is honest: every identity any copy holds.
                "identities": sorted({tok[0] for ref in refs if (tok := reach[ref].token)}),
                "threats": rows,
                "counts": {s: sum(1 for x in rows if x["status"] == s) for s in ("open", "mitigated", "not assessed")},
            }
        )
    return {
        "platform": platform,
        "version": version,
        "applications": out_apps,
        "attackVersion": attack.VERSION,
        "attribution": attack.ATTRIBUTION,
        "secretsIgnored": inv.dropped_unread,
        # A name carried by different objects: which one runs is not known, so every one is modelled (G273).
        "ambiguous": ambiguous_notes(reach)
        + [
            f"{n} has no namespace: it is modelled in default; pass -n as kubectl apply -n would"
            for n in sorted(inv.unplaced)
        ],
        "statuses": {
            "open": "a mitigating rule fails on the element, or the right exists",
            "mitigated": "every mitigating rule passes on the element",
            "not assessed": "needs input that was not given",
        },
    }


def _dedupe(threats: list[Threat]) -> list[Threat]:
    seen: dict[tuple[str, str, str], Threat] = {}
    for t in threats:
        seen.setdefault((t.template.tid, t.element.ref, t.detail), t)
    return list(seen.values())


def render_markdown(out: dict[str, Any]) -> str:
    lines = [f"# Threat model ({out['platform']}{' ' + out['version'] if out.get('version') else ''})", ""]
    for note in out.get("ambiguous") or []:
        lines += [f"> {visible(note)}", ""]
    for app in out["applications"]:
        c = app["counts"]
        lines += [
            f"## {app['application']}",
            "",
            f"{len(app['workloads'])} workloads, {len(app['entryPoints'])} entry points, "
            f"{len(app['dataStores'])} data stores, {len(app['identities'])} identities. "
            f"Threats: {c['open']} open, {c['mitigated']} mitigated, {c['not assessed']} not assessed.",
            "",
            "| STRIDE | Element | Threat | Status | Mitigated by | ATT&CK |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for t in app["threats"]:
            title = t["title"] + (f" ({t['detail']})" if t.get("detail") else "")
            rules = ", ".join(t["rules"]) + (f"; policies {', '.join(t['policies'])}" if t["policies"] else "")
            techs = ", ".join(a["id"] for a in t["attack"]) or "-"
            cells = [t["stride"], t["element"]["ref"], title.replace("|", "/"), t["status"], rules, techs]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
    lines.append(out["attribution"])
    return sanitize.visible_lines("\n".join(lines) + "\n")  # nothing that does not print reaches the file (G279)
