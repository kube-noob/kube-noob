"""Safe, mechanical remediation.

Only changes that are deterministic and preserve intent are applied automatically. Everything that needs human
judgement (pinning a digest, adding probes, choosing replica counts) is reported, never guessed. Every change is
recorded with the rule it addresses so the user can review the diff.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from kube_noob.audit.podspec import (
    PodTemplate,
    containers,
    pdb_allows_no_disruption,
    pod_template,
    pod_templates,
    replicas,
    selector_matches,
)
from kube_noob.catalog import (
    DEFAULT_STORAGE_CLASS,
    KIND_API_VERSIONS,
    KNOWN_STORAGE_CLASSES,
    OPENSHIFT_FAMILY,
    PROVISIONERS,
    removed_api,
)
from kube_noob.yamlio import Document, dump_documents, fmt_path, load_documents

SIMPLE_RENAMES: dict[tuple[str, str], str] = {
    ("extensions/v1beta1", "Deployment"): "apps/v1",
    ("apps/v1beta1", "Deployment"): "apps/v1",
    ("apps/v1beta2", "Deployment"): "apps/v1",
    ("extensions/v1beta1", "DaemonSet"): "apps/v1",
    ("apps/v1beta2", "DaemonSet"): "apps/v1",
    ("apps/v1beta1", "StatefulSet"): "apps/v1",
    ("apps/v1beta2", "StatefulSet"): "apps/v1",
    ("extensions/v1beta1", "ReplicaSet"): "apps/v1",
    ("apps/v1beta1", "ReplicaSet"): "apps/v1",
    ("apps/v1beta2", "ReplicaSet"): "apps/v1",
    ("extensions/v1beta1", "NetworkPolicy"): "networking.k8s.io/v1",
    ("networking.k8s.io/v1beta1", "IngressClass"): "networking.k8s.io/v1",
    ("rbac.authorization.k8s.io/v1beta1", "Role"): "rbac.authorization.k8s.io/v1",
    ("rbac.authorization.k8s.io/v1beta1", "RoleBinding"): "rbac.authorization.k8s.io/v1",
    ("rbac.authorization.k8s.io/v1beta1", "ClusterRole"): "rbac.authorization.k8s.io/v1",
    ("rbac.authorization.k8s.io/v1beta1", "ClusterRoleBinding"): "rbac.authorization.k8s.io/v1",
    ("scheduling.k8s.io/v1beta1", "PriorityClass"): "scheduling.k8s.io/v1",
    ("storage.k8s.io/v1beta1", "StorageClass"): "storage.k8s.io/v1",
    ("storage.k8s.io/v1beta1", "CSIDriver"): "storage.k8s.io/v1",
    ("batch/v1beta1", "CronJob"): "batch/v1",
    ("policy/v1beta1", "PodDisruptionBudget"): "policy/v1",
    ("autoscaling/v2beta2", "HorizontalPodAutoscaler"): "autoscaling/v2",
    ("node.k8s.io/v1beta1", "RuntimeClass"): "node.k8s.io/v1",
    ("discovery.k8s.io/v1beta1", "EndpointSlice"): "discovery.k8s.io/v1",
    ("coordination.k8s.io/v1beta1", "Lease"): "coordination.k8s.io/v1",
}


@dataclass
class Change:
    rule_id: str
    resource: str
    path: str
    before: Any
    after: Any
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "resource": self.resource,
            "path": self.path,
            "before": self.before,
            "after": self.after,
            "reason": self.reason,
        }


@dataclass
class FixResult:
    documents: list[Any]
    changes: list[Change] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)

    def yaml(self) -> str:
        return dump_documents(self.documents)


class _Fixer:
    def __init__(self, platform: str, k8s_version: str, harden: bool, openshift_ids: bool) -> None:
        self.platform = platform
        self.k8s = k8s_version
        self.harden = harden
        self.openshift_ids = openshift_ids and platform in OPENSHIFT_FAMILY
        self.result = FixResult(documents=[])

    def change(self, rule: str, ref: str, path: tuple[Any, ...], before: Any, after: Any, why: str) -> None:
        self.result.changes.append(Change(rule, ref, fmt_path(path), before, after, why))

    # -- api versions -----------------------------------------------------------------------------------
    def fix_api(self, doc: Document, obj: dict[str, Any]) -> None:
        av, kind = obj.get("apiVersion"), obj.get("kind")
        if not isinstance(av, str) or not isinstance(kind, str):
            return
        key = (av, kind)
        if key in SIMPLE_RENAMES and removed_api(av, kind, "99.0"):
            new = SIMPLE_RENAMES[key]
            obj["apiVersion"] = new
            self.change("KN-V005", doc.ref(), ("apiVersion",), av, new, f"{av} {kind} is removed; mechanical rename.")
            if kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"}:
                self._ensure_selector(doc, obj)
            if key == ("autoscaling/v2beta2", "HorizontalPodAutoscaler"):
                pass  # v2beta2 and v2 share the schema
            return
        if kind == "Ingress" and av in {"extensions/v1beta1", "networking.k8s.io/v1beta1"}:
            self._migrate_ingress(doc, obj)
            return
        if kind == "HorizontalPodAutoscaler" and av == "autoscaling/v2beta1":
            self._migrate_hpa_v2beta1(doc, obj)
            return
        valid = KIND_API_VERSIONS.get(kind)
        if valid and av not in valid and not removed_api(av, kind, "99.0"):
            obj["apiVersion"] = valid[0]
            self.change("KN-V002", doc.ref(), ("apiVersion",), av, valid[0], f"{kind} is served by {valid[0]}.")
        elif removed_api(av, kind, "99.0"):
            rem = removed_api(av, kind, "99.0")
            self.result.manual.append(
                f"{doc.ref()}: {av} {kind} was removed in {rem.removed_in if rem else '?'}; migrate manually "
                f"({rem.notes if rem and rem.notes else 'schema changed'})."
            )

    def _ensure_selector(self, doc: Document, obj: dict[str, Any]) -> None:
        spec = obj.setdefault("spec", {})
        labels = (((spec.get("template") or {}).get("metadata") or {}).get("labels")) or {}
        if not spec.get("selector") and labels:
            spec["selector"] = {"matchLabels": dict(labels)}
            self.change(
                "KN-V010",
                doc.ref(),
                ("spec", "selector"),
                None,
                spec["selector"],
                "apps/v1 requires spec.selector; derived from template labels.",
            )

    def _migrate_ingress(self, doc: Document, obj: dict[str, Any]) -> None:
        before = obj["apiVersion"]
        obj["apiVersion"] = "networking.k8s.io/v1"

        def conv(backend: dict[str, Any]) -> dict[str, Any]:
            if "serviceName" not in backend:
                return backend
            port = backend.get("servicePort")
            port_obj = {"number": port} if isinstance(port, int) else {"name": str(port)}
            return {"service": {"name": backend["serviceName"], "port": port_obj}}

        spec = obj.get("spec") or {}
        if isinstance(spec.get("backend"), dict):
            spec["defaultBackend"] = conv(spec.pop("backend"))
        for rule_ in spec.get("rules") or []:
            for p in ((rule_ or {}).get("http") or {}).get("paths") or []:
                if isinstance(p.get("backend"), dict):
                    p["backend"] = conv(p["backend"])
                p.setdefault("pathType", "ImplementationSpecific")
        self.change(
            "KN-V005",
            doc.ref(),
            ("apiVersion",),
            before,
            "networking.k8s.io/v1",
            "Ingress migrated to networking.k8s.io/v1: serviceName/servicePort -> service.name/port, "
            "pathType ImplementationSpecific (preserves v1beta1 matching semantics).",
        )

    def _migrate_hpa_v2beta1(self, doc: Document, obj: dict[str, Any]) -> None:
        obj["apiVersion"] = "autoscaling/v2"
        for m in (obj.get("spec") or {}).get("metrics") or []:
            res = m.get("resource") if isinstance(m, dict) else None
            if isinstance(res, dict) and "targetAverageUtilization" in res:
                res["target"] = {"type": "Utilization", "averageUtilization": res.pop("targetAverageUtilization")}
            elif isinstance(res, dict) and "targetAverageValue" in res:
                res["target"] = {"type": "AverageValue", "averageValue": res.pop("targetAverageValue")}
        self.change(
            "KN-V005",
            doc.ref(),
            ("apiVersion",),
            "autoscaling/v2beta1",
            "autoscaling/v2",
            "HPA migrated to autoscaling/v2 (targetAverage* -> target{type,...}).",
        )

    # -- security hardening -----------------------------------------------------------------------------
    def harden_pod(self, doc: Document, obj: dict[str, Any]) -> None:
        """Harden every pod spec in the object, not just the one at `spec.template.spec`.

        A KServe predictor or a Ray worker group is a pod spec like any other, and `fix` left them untouched
        while the audit reported findings in them -- so the one command whose job is to close findings could not
        close the findings on an AI workload (G238).
        """
        for pt in pod_templates(Document(index=doc.index, data=obj)):
            self._harden_one(doc, pt)

    def _harden_one(self, doc: Document, pt: PodTemplate) -> None:
        psc = _ensure_dict(pt.spec, "securityContext")
        if self.openshift_ids:
            # SCCs govern runAsUser (MustRunAsRange) and fsGroup (MustRunAs); runAsGroup has no SCC strategy.
            for f in ("runAsUser", "fsGroup"):
                if isinstance(psc.get(f), int) and psc[f] != 0:
                    self.change(
                        "KN-S004",
                        doc.ref(),
                        (*pt.path, "securityContext", f),
                        psc[f],
                        None,
                        "restricted-v2 assigns IDs from the namespace range.",
                    )
                    del psc[f]
        if "seccompProfile" not in psc:
            psc["seccompProfile"] = {"type": "RuntimeDefault"}
            self.change(
                "KN-S008",
                doc.ref(),
                (*pt.path, "securityContext", "seccompProfile"),
                None,
                {"type": "RuntimeDefault"},
                "Pod Security restricted requires RuntimeDefault seccomp.",
            )
        all_containers = list(containers(pt))
        for c in all_containers:
            _ensure_dict(c.container, "securityContext")
        pod_uid = psc.get("runAsUser")
        root_containers = [c for c in all_containers if c.container["securityContext"].get("runAsUser", pod_uid) == 0]
        added_non_root = False
        if psc.get("runAsNonRoot") is None and pod_uid != 0:
            if not root_containers:
                added_non_root = True
                psc["runAsNonRoot"] = True
                self.change(
                    "KN-S003",
                    doc.ref(),
                    (*pt.path, "securityContext", "runAsNonRoot"),
                    None,
                    True,
                    "Refuse to start as root.",
                )
            else:
                # A pod-level runAsNonRoot would make the kubelet refuse the explicit runAsUser: 0 containers
                # (CreateContainerConfigError); harden the other containers individually instead.
                for c in all_containers:
                    csc = c.container["securityContext"]
                    if c in root_containers or csc.get("runAsNonRoot") is not None:
                        continue
                    csc["runAsNonRoot"] = True
                    added_non_root = True
                    self.change(
                        "KN-S003",
                        doc.ref(),
                        (*c.path, "securityContext", "runAsNonRoot"),
                        None,
                        True,
                        "Refuse to start as root (container level: other containers run as UID 0).",
                    )
        if added_non_root:
            self.result.manual.append(
                f"{doc.ref()}: runAsNonRoot: true was added. Images whose USER is root will now fail with "
                "CreateContainerConfigError ('container has runAsNonRoot and image will run as root'); use an "
                "unprivileged image variant or set a numeric non-root USER in the Dockerfile."
            )
        for c in all_containers:
            sc = c.container["securityContext"]
            if self.openshift_ids and isinstance(sc.get("runAsUser"), int) and sc["runAsUser"] != 0:
                self.change(
                    "KN-S004",
                    doc.ref(),
                    (*c.path, "securityContext", "runAsUser"),
                    sc["runAsUser"],
                    None,
                    "restricted-v2 assigns IDs from the namespace range.",
                )
                del sc["runAsUser"]
            if sc.get("runAsUser", pod_uid) == 0:
                self.result.manual.append(
                    f"{doc.ref()} container '{c.name}' runs as UID 0; rebuild the image "
                    "with a non-root USER and remove runAsUser: 0."
                )
            caps = _ensure_dict(sc, "capabilities")
            added = {str(x).upper().removeprefix("CAP_") for x in (caps.get("add") or []) if isinstance(x, str)}
            # The API server rejects allowPrivilegeEscalation: false together with privileged: true or an added
            # CAP_SYS_ADMIN, and a privileged container ignores capability drops: leave those to a manual fix.
            privileged = sc.get("privileged") is True or "SYS_ADMIN" in added
            if "allowPrivilegeEscalation" not in sc and not privileged:
                sc["allowPrivilegeEscalation"] = False
                self.change(
                    "KN-S002",
                    doc.ref(),
                    (*c.path, "securityContext", "allowPrivilegeEscalation"),
                    None,
                    False,
                    "Block setuid privilege escalation.",
                )
            elif sc.get("allowPrivilegeEscalation") is True and not privileged:
                if self.platform in OPENSHIFT_FAMILY:
                    sc["allowPrivilegeEscalation"] = False
                    self.change(
                        "KN-S002",
                        doc.ref(),
                        (*c.path, "securityContext", "allowPrivilegeEscalation"),
                        True,
                        False,
                        "restricted-v2 rejects allowPrivilegeEscalation: true, so the pod could not start anyway.",
                    )
                else:
                    self.result.manual.append(
                        f"{doc.ref()} container '{c.name}' sets allowPrivilegeEscalation: true; set it to false "
                        "unless the app needs setuid binaries (Pod Security 'restricted' rejects true)."
                    )
            if caps.get("drop") is None:
                caps["drop"] = []
            drop = caps["drop"]
            if not privileged and isinstance(drop, list) and not any(str(x).upper() == "ALL" for x in drop):
                drop.append("ALL")
                self.change(
                    "KN-S006",
                    doc.ref(),
                    (*c.path, "securityContext", "capabilities", "drop"),
                    None,
                    ["ALL"],
                    "Drop all Linux capabilities.",
                )
            if not caps.get("drop"):
                caps.pop("drop", None)
            if not caps:
                sc.pop("capabilities", None)
            if sc.get("privileged") is True:
                self.result.manual.append(
                    f"{doc.ref()} container '{c.name}' is privileged; remove it and add only "
                    "the specific capability the workload needs."
                )
            if sc.get("readOnlyRootFilesystem") is not True:
                self.result.manual.append(
                    f"{doc.ref()} container '{c.name}': consider readOnlyRootFilesystem: true "
                    "with emptyDir mounts for writable paths (needs app knowledge)."
                )
            if not c.init and not c.container.get("readinessProbe"):
                self.result.manual.append(
                    f"{doc.ref()} container '{c.name}': add a readinessProbe for the app's health endpoint."
                )

    # -- network / storage / availability ---------------------------------------------------------------
    def fix_route(self, doc: Document, obj: dict[str, Any]) -> None:
        spec = obj.setdefault("spec", {})
        tls = spec.get("tls")
        if not isinstance(tls, dict):
            spec["tls"] = {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}
            self.change(
                "KN-N002",
                doc.ref(),
                ("spec", "tls"),
                None,
                spec["tls"],
                "Terminate TLS at the router and redirect HTTP to HTTPS.",
            )
        elif tls.get("insecureEdgeTerminationPolicy") == "Allow":
            tls["insecureEdgeTerminationPolicy"] = "Redirect"
            self.change(
                "KN-N002",
                doc.ref(),
                ("spec", "tls", "insecureEdgeTerminationPolicy"),
                "Allow",
                "Redirect",
                "Never serve plain HTTP.",
            )

    def fix_pdb(self, doc: Document, obj: dict[str, Any], all_objs: list[dict[str, Any]]) -> None:
        spec = obj.get("spec") or {}
        sel = spec.get("selector")
        for w in all_objs:
            wdoc = Document(index=0, data=w)
            pt = pod_template(wdoc)
            if pt is None or replicas(wdoc) is None:
                continue
            if (w.get("metadata") or {}).get("namespace") != (obj.get("metadata") or {}).get("namespace"):
                continue
            if not selector_matches(sel, pt.labels()):
                continue
            reps = replicas(wdoc) or 1
            ma, mu = spec.get("minAvailable"), spec.get("maxUnavailable")
            if pdb_allows_no_disruption(spec, reps):
                spec.pop("minAvailable", None)
                spec["maxUnavailable"] = 1
                self.change(
                    "KN-C009",
                    doc.ref(),
                    ("spec",),
                    {"minAvailable": ma, "maxUnavailable": mu},
                    {"maxUnavailable": 1},
                    "Allow one voluntary disruption so drains/upgrades can proceed.",
                )
                return

    def fix_egressfirewall(self, doc: Document, obj: dict[str, Any], taken: set[str]) -> None:
        """``taken``: namespaces that already have an EgressFirewall named 'default' in this bundle."""
        meta = _ensure_dict(obj, "metadata")
        ns = str(meta.get("namespace") or "")
        if meta.get("name") != "default" and ns in taken:
            self.result.manual.append(
                f"{doc.ref()}: namespace '{ns or '<unset>'}' already has an EgressFirewall named 'default'. Only one "
                "is allowed per namespace: merge these rules into it (keeping the catch-all Deny last) and delete "
                "this object."
            )
        elif meta.get("name") != "default":
            self.change(
                "KN-V015",
                doc.ref(),
                ("metadata", "name"),
                meta.get("name"),
                "default",
                "OVN-Kubernetes only honours an EgressFirewall named 'default'.",
            )
            meta["name"] = "default"
        if meta.get("name") == "default":
            taken.add(ns)
        egress = (obj.get("spec") or {}).get("egress")
        if isinstance(egress, list):
            catch = [
                e
                for e in egress
                if isinstance(e, dict)
                and (e.get("to") or {}).get("cidrSelector") in {"0.0.0.0/0", "::/0"}
                and not e.get("ports")
            ]
            rest = [e for e in egress if e not in catch]
            reordered = rest + catch
            if reordered != egress:
                obj["spec"]["egress"] = reordered
                self.change(
                    "KN-N006",
                    doc.ref(),
                    ("spec", "egress"),
                    "catch-all rule before specific rules",
                    "catch-all rule(s) moved last",
                    "First match wins; specific rules must come first.",
                )

    def fix_storage(self, doc: Document, obj: dict[str, Any], classes: dict[str, str]) -> None:
        kind = obj.get("kind")
        if kind == "StorageClass":
            p = PROVISIONERS.get(str(obj.get("provisioner")))
            if p and p.zonal and obj.get("volumeBindingMode", "Immediate") == "Immediate":
                obj["volumeBindingMode"] = "WaitForFirstConsumer"
                self.change(
                    "KN-ST003",
                    doc.ref(),
                    ("volumeBindingMode",),
                    "Immediate",
                    "WaitForFirstConsumer",
                    "Provision zonal volumes where the pod lands. StorageClass is immutable: delete and recreate it.",
                )
            return
        specs: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        if kind == "PersistentVolumeClaim" and isinstance(obj.get("spec"), dict):
            specs.append((("spec",), obj["spec"]))
        if kind == "StatefulSet":
            for i, v in enumerate((obj.get("spec") or {}).get("volumeClaimTemplates") or []):
                if isinstance(v, dict) and isinstance(v.get("spec"), dict):
                    specs.append((("spec", "volumeClaimTemplates", i, "spec"), v["spec"]))
        target = DEFAULT_STORAGE_CLASS.get(self.platform, {}).get("ReadWriteMany")
        for path, spec in specs:
            if "ReadWriteMany" not in (spec.get("accessModes") or []):
                continue
            sc = spec.get("storageClassName")
            prov = classes.get(sc) if sc else None
            p = PROVISIONERS.get(prov) if prov else None
            bad = p is not None and not p.rwx_filesystem and not (spec.get("volumeMode") == "Block" and p.rwx_block)
            bad = bad or (sc is None and self.platform in {"rosa-classic", "rosa-hcp"})
            if bad and target:
                spec["storageClassName"] = target
                self.change(
                    "KN-ST001",
                    doc.ref(),
                    (*path, "storageClassName"),
                    sc,
                    target,
                    f"'{sc or '<default>'}' cannot serve ReadWriteMany; '{target}' can. Prerequisite: the "
                    f"'{target}' StorageClass and its CSI driver must exist in the cluster.",
                )
            elif bad:
                self.result.manual.append(
                    f"{doc.ref()}: RWX claim on '{sc}' cannot bind; choose a shared-filesystem "
                    "StorageClass (NFS, CephFS, EFS, Azure Files)."
                )


def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    """``parent[key]`` as a dict; ``null`` or a missing key becomes ``{}`` (YAML ``securityContext:`` with no value)."""
    value = parent.get(key)
    if not isinstance(value, dict):
        value = {}
        parent[key] = value
    return value


def fix_manifests(
    text: str,
    platform: str = "kubernetes",
    k8s_version: str = "1.33",
    harden: bool = True,
    openshift_ids: bool = True,
) -> FixResult:
    docs = load_documents(text)
    fx = _Fixer(platform, k8s_version, harden, openshift_ids)
    objs = [copy.deepcopy(d.data) for d in docs]
    classes = dict(KNOWN_STORAGE_CLASSES)
    for o in objs:
        if isinstance(o, dict) and o.get("kind") == "StorageClass" and o.get("provisioner"):
            classes[str((o.get("metadata") or {}).get("name"))] = str(o["provisioner"])
    firewall_namespaces = {
        str((o.get("metadata") or {}).get("namespace") or "")
        for o in objs
        if isinstance(o, dict)
        and o.get("kind") == "EgressFirewall"
        and isinstance(o.get("metadata"), dict)
        and o["metadata"].get("name") == "default"
    }
    for d, o in zip(docs, objs, strict=True):
        if not isinstance(o, dict):
            continue
        fx.fix_api(d, o)
        kind = o.get("kind")
        if harden:
            fx.harden_pod(d, o)
        if kind == "Route":
            fx.fix_route(d, o)
        elif kind == "PodDisruptionBudget":
            fx.fix_pdb(d, o, [x for x in objs if isinstance(x, dict)])
        elif kind == "EgressFirewall":
            fx.fix_egressfirewall(d, o, firewall_namespaces)
        if kind in {"StorageClass", "PersistentVolumeClaim", "StatefulSet"}:
            fx.fix_storage(d, o, classes)
        image_issue = _image_manual(d, o)
        fx.result.manual.extend(image_issue)
    fx.result.documents = objs
    fx.result.manual = list(dict.fromkeys(fx.result.manual))
    return fx.result


def _image_manual(doc: Document, obj: dict[str, Any]) -> list[str]:

    out: list[str] = []
    # Every template, so a mutable tag in a KServe component or a Ray worker group is listed as manual work
    # rather than passed over (G238).
    for pt in pod_templates(Document(index=0, data=obj)):
        out += _image_manual_for(doc, pt)
    return out


def _image_manual_for(doc: Document, pt: PodTemplate) -> list[str]:
    from kube_noob.audit.rules import image_tag

    out: list[str] = []
    for c in containers(pt):
        img = c.container.get("image")
        if isinstance(img, str):
            tag, digest = image_tag(img)
            if not digest and tag in (None, "latest"):
                out.append(f"{doc.ref()} container '{c.name}': pin image '{img}' to a version tag or digest.")
    return out
