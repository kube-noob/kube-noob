"""Objects that WRITE kube-apiserver's and etcd's flags, and the flags they write (G272).

kubeadm writes a static pod's argv from a ClusterConfiguration's `apiServer.extraArgs` and `etcd.local.extraArgs`
(a mapping before v1beta4, a list of `{name, value}` in v1beta4, where a repeated name becomes a repeated flag),
and the same ClusterConfiguration sits inside Cluster API's KubeadmControlPlane and KubeadmConfig (and their
templates), inside the `kube-system/kubeadm-config` ConfigMap, and inside a kind cluster's `kubeadmConfigPatches`.
k0s writes them from a ClusterConfig's `spec.api.extraArgs` and `spec.storage.etcd.extraArgs`, RKE2 under Rancher
from a provisioning Cluster's `machineGlobalConfig` (`kube-apiserver-arg`, `etcd-arg`, each `key=value`).

This module only EXTRACTS those arguments, as (flag, value, where) triples per component; `KN-S038` and `KN-S039`
decide from the ones that decide on their own (AlwaysAllow, an explicit `anonymous-auth: true`, a plaintext URL
on a network address) and name everything else as seen and not read, because the rest depends on the tool's own
defaults. An object of these kinds is never passed over silently. OpenShift's operator `KubeAPIServer` is named
and not read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kube_noob.audit.argv import _quoted, _shown
from kube_noob.yamlio import Document, PathT

#: How large an embedded YAML string (a ConfigMap value, a kind patch) is parsed; a larger one is not read.
MAX_EMBEDDED_BYTES = 256 * 1024


@dataclass
class ConfigRead:
    """What one configuration object says about one component."""

    #: (flag name with `_` read as `-`, value, the path in the object that holds it)
    pairs: list[tuple[str, str, PathT]] = field(default_factory=list)
    #: What could not be read in it, each a sentence fragment.
    unread: list[str] = field(default_factory=list)
    #: Who writes the flags from it: kubeadm, k0s, RKE2, or the OpenShift operator.
    tool: str = ""


def _group(doc: Document) -> str:
    return doc.api_version.split("/", 1)[0] if "/" in doc.api_version else ""


def _get(data: Any, *path: str | int) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _extra_args(value: Any, path: PathT, out: ConfigRead, what: str) -> None:
    """kubeadm/k0s `extraArgs`: a mapping (v1beta3, k0s) or a list of `{name, value}` (kubeadm v1beta4)."""
    if value is None:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and isinstance(v, (str, int, float, bool)):
                out.pairs.append((k.replace("_", "-"), str(v).lower() if isinstance(v, bool) else str(v), (*path, k)))
            else:
                out.unread.append(f"{what} has an entry {_quoted(k, 60)} that is not a string setting")
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            name, v = (item.get("name"), item.get("value")) if isinstance(item, dict) else (None, None)
            if isinstance(name, str) and isinstance(v, (str, int, float, bool)):
                out.pairs.append((name.replace("_", "-"), str(v), (*path, i, "value")))
            else:
                out.unread.append(f"{what}[{i}] is not a {{name, value}} pair")
        return
    out.unread.append(f"{what} is neither a mapping nor a list")


def _cluster_configuration(cc: Any, path: PathT, component: str, out: ConfigRead, where: str) -> None:
    if not isinstance(cc, dict):
        out.unread.append(f"{where} is not a mapping")
        return
    if component == "kube-apiserver":
        _extra_args(
            _get(cc, "apiServer", "extraArgs"), (*path, "apiServer", "extraArgs"), out, f"{where}.apiServer.extraArgs"
        )
    else:
        if _get(cc, "etcd", "external") is not None:
            out.unread.append(f"{where} names an external etcd, which is not in the input")
        _extra_args(
            _get(cc, "etcd", "local", "extraArgs"),
            (*path, "etcd", "local", "extraArgs"),
            out,
            f"{where}.etcd.local.extraArgs",
        )


def _embedded(text: Any, path: PathT, component: str, out: ConfigRead, where: str) -> None:
    """A ClusterConfiguration inside a YAML string: every document of that kind in it is read, at ``path``."""
    from kube_noob.errors import ManifestError
    from kube_noob.yamlio import load_documents

    if not isinstance(text, str) or len(text.encode("utf-8", errors="replace")) > MAX_EMBEDDED_BYTES:
        out.unread.append(f"{where} is not a YAML string of at most {MAX_EMBEDDED_BYTES} bytes")
        return
    try:
        docs = load_documents(text)
    except ManifestError:
        out.unread.append(f"{where} is not YAML kube-noob can parse")
        return
    for d in docs:
        if isinstance(d.data, dict) and d.data.get("kind") == "ClusterConfiguration":
            before = len(out.pairs)
            _cluster_configuration(d.data, (), component, out, where)
            out.pairs[before:] = [(k, v, path) for k, v, _ in out.pairs[before:]]  # point at the string itself
        elif isinstance(d.data, dict) and d.data.get("kind") not in {
            "InitConfiguration",
            "JoinConfiguration",
            "KubeletConfiguration",
            "KubeProxyConfiguration",
        }:
            out.unread.append(f"{where} holds a {_quoted(d.data.get('kind'), 60)} document that is not read")


def _key_values(value: Any, path: PathT, out: ConfigRead, what: str) -> None:
    """RKE2's `kube-apiserver-arg` / `etcd-arg`: a list of `key=value` strings (or one string)."""
    items = [value] if isinstance(value, str) else value if isinstance(value, list) else None
    if items is None:
        if value is not None:
            out.unread.append(f"{what} is neither a string nor a list")
        return
    for i, item in enumerate(items):
        if isinstance(item, str) and "=" in item:
            k, _, v = item.partition("=")
            out.pairs.append(
                (k.strip().lstrip("-").replace("_", "-"), v, (*path, i) if isinstance(value, list) else path)
            )
        else:
            out.unread.append(f"{what}[{i}] is not a key=value string")


def read_config(doc: Document, component: str) -> ConfigRead | None:
    """The ``component`` (`kube-apiserver` or `etcd`) arguments one configuration object writes, or None when the
    object is not one of the kinds that write them."""
    group, kind, data = _group(doc), doc.kind, doc.data if isinstance(doc.data, dict) else {}
    out = ConfigRead()
    if group == "kubeadm.k8s.io" and kind == "ClusterConfiguration":
        out.tool = "kubeadm"
        _cluster_configuration(data, (), component, out, "ClusterConfiguration")
    elif group == "" and kind == "ConfigMap" and doc.name == "kubeadm-config" and doc.namespace == "kube-system":
        out.tool = "kubeadm"
        _embedded(
            _get(data, "data", "ClusterConfiguration"),
            ("data", "ClusterConfiguration"),
            component,
            out,
            "data.ClusterConfiguration",
        )
    elif group == "controlplane.cluster.x-k8s.io" and kind in {"KubeadmControlPlane", "KubeadmControlPlaneTemplate"}:
        out.tool = "kubeadm (Cluster API)"
        base: PathT = (
            ("spec", "kubeadmConfigSpec")
            if kind == "KubeadmControlPlane"
            else ("spec", "template", "spec", "kubeadmConfigSpec")
        )
        _cluster_configuration(
            _get(data, *base, "clusterConfiguration") or {},
            (*base, "clusterConfiguration"),
            component,
            out,
            ".".join(str(p) for p in (*base, "clusterConfiguration")),
        )
    elif group == "bootstrap.cluster.x-k8s.io" and kind in {"KubeadmConfig", "KubeadmConfigTemplate"}:
        out.tool = "kubeadm (Cluster API)"
        base = ("spec",) if kind == "KubeadmConfig" else ("spec", "template", "spec")
        _cluster_configuration(
            _get(data, *base, "clusterConfiguration") or {},
            (*base, "clusterConfiguration"),
            component,
            out,
            ".".join((*base, "clusterConfiguration")),
        )
    elif group == "kind.x-k8s.io" and kind == "Cluster":
        out.tool = "kind (kubeadm)"
        patches: list[tuple[PathT, Any]] = [(("kubeadmConfigPatches",), data.get("kubeadmConfigPatches"))]
        nodes = data.get("nodes")
        for i, node in enumerate(nodes if isinstance(nodes, list) else []):
            patches.append((("nodes", i, "kubeadmConfigPatches"), _get(node, "kubeadmConfigPatches")))
        for path, value in patches:
            if value is None:
                continue
            if not isinstance(value, list):
                out.unread.append(f"{'.'.join(map(str, path))} is not a list")
                continue
            for j, patch in enumerate(value):
                _embedded(patch, (*path, j), component, out, f"{'.'.join(map(str, path))}[{j}]")
        if data.get("kubeadmConfigPatchesJSON6902"):
            out.unread.append("kubeadmConfigPatchesJSON6902 is not read")
    elif group == "k0s.k0sproject.io" and kind == "ClusterConfig":
        out.tool = "k0s"
        if component == "kube-apiserver":
            _extra_args(_get(data, "spec", "api", "extraArgs"), ("spec", "api", "extraArgs"), out, "spec.api.extraArgs")
        else:
            _extra_args(
                _get(data, "spec", "storage", "etcd", "extraArgs"),
                ("spec", "storage", "etcd", "extraArgs"),
                out,
                "spec.storage.etcd.extraArgs",
            )
    elif group == "provisioning.cattle.io" and kind == "Cluster":
        out.tool = "RKE2 (Rancher)"
        key = "kube-apiserver-arg" if component == "kube-apiserver" else "etcd-arg"
        rke = _get(data, "spec", "rkeConfig") or {}
        _key_values(
            _get(rke, "machineGlobalConfig", key),
            ("spec", "rkeConfig", "machineGlobalConfig", key),
            out,
            f"machineGlobalConfig.{key}",
        )
        selectors = _get(rke, "machineSelectorConfig")
        for i, sel in enumerate(selectors if isinstance(selectors, list) else []):
            _key_values(
                _get(sel, "config", key),
                ("spec", "rkeConfig", "machineSelectorConfig", i, "config", key),
                out,
                f"machineSelectorConfig[{i}].config.{key}",
            )
    elif group == "operator.openshift.io" and kind == "KubeAPIServer" and component == "kube-apiserver":
        out.tool = "the OpenShift operator"
        out.unread.append("its overrides are written by the OpenShift kube-apiserver operator and are not read")
    else:
        return None
    return out


def describe(doc: Document) -> str:
    return _shown(doc.ref(), 160)
