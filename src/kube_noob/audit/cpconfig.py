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

from kube_noob.audit.argv import _quoted, _shown, k3s_pairs, shown_value
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
    #: Every path in the object at which a key was given twice (the loader's duplicate-key records), so a reader
    #: can refuse an entry whose decoder refuses the duplicate.
    dup_paths: set[PathT] = field(default_factory=set)


def _group(doc: Document) -> str:
    return doc.api_version.split("/", 1)[0] if "/" in doc.api_version else ""


def _get(data: Any, *path: str | int) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


#: The kubeadm API versions kube-noob reads: v1beta3 takes `extraArgs` as a mapping, v1beta4 as a list of
#: `{name, value}`. A document in the other form does not decode, so kubeadm writes no static pod from it; a
#: document in any OTHER version (v1beta2, which 1.31 no longer decodes; v1alpha3; v1beta5, which does not exist)
#: is declined rather than read by its shape, because what kubeadm would do with it is not known here (G272).
_KUBEADM_MAP_VERSIONS = frozenset({"kubeadm.k8s.io/v1beta3"})
_KUBEADM_LIST_VERSIONS = frozenset({"kubeadm.k8s.io/v1beta4"})


def _scalar(value: Any) -> str:
    """A YAML scalar as it was written: `true`, not Python's `True`."""
    return str(value).lower() if isinstance(value, bool) else str(value)


#: The first Kubernetes minor whose kubeadm keeps override arguments in their written order (kubernetes master,
#: the 1.36 cycle, `cmd/kubeadm/app/util/arguments.go` fetched 2026-11-13: ArgumentsToCommand sorts the BASE only,
#: and an override that carries no `mergeMethod` goes to the tail as written). Through v1.35.0 every pair is sorted.
KUBEADM_WRITTEN_ORDER_FROM = (1, 36)


def _extra_args(
    value: Any,
    path: PathT,
    out: ConfigRead,
    what: str,
    api_version: str = "",
    strict: bool = False,
    minor: tuple[int, int] = (1, 35),
) -> None:
    """kubeadm/k0s `extraArgs`: a mapping (v1beta3, k0s) or a list of `{name, value}` (kubeadm v1beta4).

    The v1beta4 list keeps every entry, and kubeadm sorts the arguments by (name, value) ON THE RAW NAME before
    it writes them (cmd/kubeadm/app/util/arguments.go ArgumentsToCommand, identical at v1.31.0, v1.32.0, v1.33.0,
    v1.34.0 and v1.35.0: `sort.Slice` on Name then Value), so `anonymous-auth` sorts before `anonymous_auth`;
    only then does kube-apiserver's pflag fold `_` to `-` (WordSepNormalizeFunc) and keep the LAST value. So
    `anonymous_auth: "false"` + `anonymous-auth: "true"` is `--anonymous-auth=true --anonymous_auth=false`, which
    is false. The v1beta3 map is converted to the same Arg list before that sort (v1beta3/conversion.go
    convertToArgs, v1.31.0), so its keys are sorted alike. Folding before sorting put the entries in the wrong
    order (G272, sixth review). From ``minor`` 1.36 (KUBEADM_WRITTEN_ORDER_FROM) kubeadm keeps the overrides in
    their WRITTEN order and an entry with a `mergeMethod` is merged into kubeadm's own default, which is not read,
    so it declines (seventh review).
    With ``api_version`` stated, a form that does not match it is declined: kubeadm cannot decode it, so it
    writes nothing. With ``strict`` (kubeadm), a name or value that is not a string, a missing name, a key the Arg
    type does not have, and an entry with a key twice are declined too: `Arg.Name` and `Arg.Value` and the v1beta3
    map are strings, sigs.k8s.io/yaml refuses a YAML bool or number for a string field and a duplicate key, and
    kubeadm's strict decoding refuses an unknown field, so `kubeadm init` fails on the file and no API server runs
    with it. A missing `value` is the empty string, which kubeadm writes as `--name=` and the flag's own parser
    then reads (pflag refuses it for a boolean).
    """
    if value is None:
        return
    if api_version and api_version not in _KUBEADM_MAP_VERSIONS | _KUBEADM_LIST_VERSIONS:
        out.unread.append(f"{what} is under {api_version}, and kubeadm {api_version} is not one kube-noob reads")
        return
    if api_version in _KUBEADM_MAP_VERSIONS and isinstance(value, list):
        out.unread.append(f"{what} is a list under {api_version}, which takes a mapping: kubeadm cannot decode it")
        return
    if api_version in _KUBEADM_LIST_VERSIONS and isinstance(value, dict):
        out.unread.append(f"{what} is a mapping under {api_version}, which takes a list: kubeadm cannot decode it")
        return
    entries: list[tuple[str, str, PathT]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                out.unread.append(f"{what} has an entry {_quoted(k, 60)} that is not a string setting")
            elif isinstance(v, str):
                entries.append((k, v, (*path, k)))
            elif strict:
                out.unread.append(
                    f"{what}.{_shown(k, 60)} is {_quoted(_scalar(v), 40)}, not a string, which kubeadm's decoder "
                    "refuses"
                )
            elif isinstance(v, (int, float, bool)):
                entries.append((k, str(v).lower() if isinstance(v, bool) else str(v), (*path, k)))
            else:
                out.unread.append(f"{what} has an entry {_quoted(k, 60)} that is not a string setting")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                out.unread.append(f"{what}[{i}] is not a {{name, value}} pair")
                continue
            name, v = item.get("name"), item.get("value")
            twice = sorted(key[-1] for key in out.dup_paths if key[:-1] == (*path, i) and isinstance(key[-1], str))
            if strict and twice:
                out.unread.append(
                    f"{what}[{i}] has the key {_quoted(twice[0], 40)} twice, which kubeadm's decoder refuses"
                )
                continue
            if strict and name is not None and not isinstance(name, str):
                out.unread.append(
                    f"{what}[{i}].name is {_quoted(_scalar(name), 40)}, not a string, which kubeadm's decoder refuses"
                )
                continue
            unknown = sorted(str(k) for k in item if k not in {"name", "value", "mergeMethod"})
            if strict and unknown:
                out.unread.append(
                    f"{what}[{i}] has a field {_quoted(unknown[0], 40)} the kubeadm Arg type does not have, which "
                    "kubeadm's strict decoding refuses"
                )
                continue
            if strict and "mergeMethod" in item:
                if minor < KUBEADM_WRITTEN_ORDER_FROM:
                    out.unread.append(
                        f"{what}[{i}] has a mergeMethod, which kubeadm before "
                        f"{'.'.join(map(str, KUBEADM_WRITTEN_ORDER_FROM))} does not define, so its strict decoding "
                        "refuses the file"
                    )
                else:
                    out.unread.append(
                        f"{what}[{i}] has a mergeMethod, so its value is merged into kubeadm's own default for "
                        f"{_quoted(name, 60)}, which is not read"
                    )
                continue
            if strict and v is None:
                v = ""  # written as `--name=`: the flag's own parser decides what an empty value means
            if isinstance(name, str) and isinstance(v, str):
                entries.append((name, v, (*path, i, "value")))
            elif isinstance(name, str) and strict:
                out.unread.append(
                    f"{what}[{i}].value is {_quoted(_scalar(v), 40)}, not a string, which kubeadm's decoder refuses"
                )
            elif isinstance(name, str) and isinstance(v, (int, float, bool)):
                entries.append((name, str(v), (*path, i, "value")))
            else:
                out.unread.append(f"{what}[{i}] is not a {{name, value}} pair")
    else:
        out.unread.append(f"{what} is neither a mapping nor a list")
        return
    # Sorted on the raw name, as kubeadm writes them through 1.35; in the written order from 1.36; folded for
    # pflag only after.
    if minor < KUBEADM_WRITTEN_ORDER_FROM or isinstance(value, dict):
        entries.sort(key=lambda e: (e[0], e[1]))
    out.pairs.extend((k.replace("_", "-"), v, p) for k, v, p in entries)


def _cluster_configuration(
    cc: Any,
    path: PathT,
    component: str,
    out: ConfigRead,
    where: str,
    api_version: str = "",
    minor: tuple[int, int] = (1, 35),
) -> None:
    if not isinstance(cc, dict):
        out.unread.append(f"{where} is not a mapping")
        return
    section = "apiServer" if component == "kube-apiserver" else "etcd"
    for skipped in ("extraEnvs", "extraVolumes"):
        holder = _get(cc, section) if section == "apiServer" else _get(cc, "etcd", "local")
        if isinstance(holder, dict) and holder.get(skipped) is not None:
            out.unread.append(f"{where}.{section}{'' if section == 'apiServer' else '.local'}.{skipped} is not read")
    if component == "kube-apiserver":
        _extra_args(
            _get(cc, "apiServer", "extraArgs"),
            (*path, "apiServer", "extraArgs"),
            out,
            f"{where}.apiServer.extraArgs",
            api_version,
            strict=True,
            minor=minor,
        )
    else:
        if _get(cc, "etcd", "external") is not None:
            out.unread.append(f"{where} names an external etcd, which is not in the input")
        _extra_args(
            _get(cc, "etcd", "local", "extraArgs"),
            (*path, "etcd", "local", "extraArgs"),
            out,
            f"{where}.etcd.local.extraArgs",
            api_version,
            strict=True,
            minor=minor,
        )


def _kubeadm_config_spec(data: Any, base: PathT, out: ConfigRead) -> None:
    """What a Cluster API KubeadmConfigSpec can do to the control plane besides its `clusterConfiguration`, named
    as unread: `files` written to the node (one may be the static pod manifest itself) and the
    `preKubeadmCommands` / `postKubeadmCommands` scripts, which run as root on the node and may rewrite the
    manifest kubeadm wrote. The fifth review named `files` on KubeadmControlPlane only (G272)."""
    for key, what in (
        ("files", "files written to the node"),
        ("preKubeadmCommands", "scripts that may rewrite the manifest"),
        ("postKubeadmCommands", "scripts that may rewrite the manifest"),
    ):
        if _get(data, *base, key):  # an empty list is nothing to read
            out.unread.append(f"{'.'.join(str(p) for p in (*base, key))} ({what}) is not read")


def _embedded(
    text: Any, path: PathT, component: str, out: ConfigRead, where: str, minor: tuple[int, int] = (1, 35)
) -> None:
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
            outer = out.dup_paths
            out.dup_paths = {key for key, _ in d.duplicate_keys}
            _cluster_configuration(d.data, (), component, out, where, str(d.data.get("apiVersion") or ""), minor)
            out.dup_paths = outer
            out.pairs[before:] = [(k, v, path) for k, v, _ in out.pairs[before:]]  # point at the string itself
        elif isinstance(d.data, dict) and d.data.get("kind") not in {
            "InitConfiguration",
            "JoinConfiguration",
            "KubeletConfiguration",
            "KubeProxyConfiguration",
        }:
            out.unread.append(f"{where} holds a {_quoted(d.data.get('kind'), 60)} document that is not read")


def _key_values(value: Any, path: PathT, out: ConfigRead, what: str) -> None:
    """RKE2's `kube-apiserver-arg` / `etcd-arg`: a list of `key=value` strings (or one string), read exactly as
    k3s's GetArgs reads the argv form and in the order it emits them (`argv.k3s_pairs`: one `--` trimmed, `+=` and
    `-=` are a second flag, a bare key is `key=true`, nothing trimmed, the keys sorted on the cleaned raw name
    before pflag folds `_`), so the two readers of one syntax cannot disagree (G272, sixth and seventh reviews).
    A padded entry is a flag pflag refuses, and the shared decision block says so."""
    items = [value] if isinstance(value, str) else value if isinstance(value, list) else None
    if items is None:
        if value is not None:
            out.unread.append(f"{what} is neither a string nor a list")
        return
    strings: list[str] = []
    for i, item in enumerate(items):
        if isinstance(item, str) and item:
            strings.append(item)
        else:
            out.unread.append(f"{what}[{i}] is not a key=value string")
    indices = [i for i, item in enumerate(items) if isinstance(item, str) and item]
    for flag, v, j in k3s_pairs(strings):
        out.pairs.append((flag, v, (*path, indices[j]) if isinstance(value, list) else path))


def _selector_text(selector: Any) -> str:
    """A selector as YAML on one line, through the output boundary -- never a Python repr (R6, G272)."""
    import yaml

    return _quoted(yaml.safe_dump(selector, default_flow_style=True, width=10_000).strip(), 120)


#: Labels that name a control-plane machine: RKE2's own role label and the upstream node roles.
_CONTROL_PLANE_LABELS = frozenset(
    {"rke.cattle.io/control-plane-role", "node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master"}
)


def _selects_the_control_plane(selector: Any) -> bool:
    """Does this LabelSelector name the control plane: a `matchLabels` entry on a control-plane role label, or a
    `matchExpressions` term with `Exists` or `In` on one? Such a selector's config reaches the API server
    (G272, seventh review). Anything else may not."""
    if not isinstance(selector, dict):
        return False
    labels = selector.get("matchLabels")
    if isinstance(labels, dict) and any(k in _CONTROL_PLANE_LABELS for k in labels):
        return True
    terms = selector.get("matchExpressions")
    return isinstance(terms, list) and any(
        isinstance(t, dict) and t.get("key") in _CONTROL_PLANE_LABELS and t.get("operator") in {"Exists", "In"}
        for t in terms
    )


def _selects_every_machine(selector: Any) -> bool:
    """An absent or empty LabelSelector matches every machine, and `{matchLabels: {}}` is the same empty selector
    spelled out: both put the config on the control plane. Anything with a term, or a key this reader does not
    know, may not (G272, sixth review)."""
    if selector is None or selector == {}:
        return True
    if not isinstance(selector, dict):
        return False
    return all(k in {"matchLabels", "matchExpressions"} and not v for k, v in selector.items())


def read_config(doc: Document, component: str, minor: tuple[int, int] = (1, 35)) -> ConfigRead | None:
    """The ``component`` (`kube-apiserver` or `etcd`) arguments one configuration object writes, or None when the
    object is not one of the kinds that write them. ``minor`` is the target Kubernetes release, which decides
    the order kubeadm writes its arguments in."""
    group, kind, data = _group(doc), doc.kind, doc.data if isinstance(doc.data, dict) else {}
    out = ConfigRead(dup_paths={key for key, _ in doc.duplicate_keys})
    if group == "kubeadm.k8s.io" and kind == "ClusterConfiguration":
        out.tool = "kubeadm"
        _cluster_configuration(data, (), component, out, "ClusterConfiguration", doc.api_version, minor)
    elif group == "" and kind == "ConfigMap" and doc.name == "kubeadm-config" and doc.namespace == "kube-system":
        out.tool = "kubeadm"
        _embedded(
            _get(data, "data", "ClusterConfiguration"),
            ("data", "ClusterConfiguration"),
            component,
            out,
            "data.ClusterConfiguration",
            minor,
        )
    elif group == "controlplane.cluster.x-k8s.io" and kind in {"KubeadmControlPlane", "KubeadmControlPlaneTemplate"}:
        out.tool = "kubeadm (Cluster API)"
        base: PathT = (
            ("spec", "kubeadmConfigSpec")
            if kind == "KubeadmControlPlane"
            else ("spec", "template", "spec", "kubeadmConfigSpec")
        )
        _kubeadm_config_spec(data, base, out)
        _cluster_configuration(
            _get(data, *base, "clusterConfiguration") or {},
            (*base, "clusterConfiguration"),
            component,
            out,
            ".".join(str(p) for p in (*base, "clusterConfiguration")),
            minor=minor,
        )
    elif group == "bootstrap.cluster.x-k8s.io" and kind in {"KubeadmConfig", "KubeadmConfigTemplate"}:
        out.tool = "kubeadm (Cluster API)"
        base = ("spec",) if kind == "KubeadmConfig" else ("spec", "template", "spec")
        _kubeadm_config_spec(data, base, out)
        _cluster_configuration(
            _get(data, *base, "clusterConfiguration") or {},
            (*base, "clusterConfiguration"),
            component,
            out,
            ".".join((*base, "clusterConfiguration")),
            minor=minor,
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
                _embedded(patch, (*path, j), component, out, f"{'.'.join(map(str, path))}[{j}]", minor)
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
        # A mapping is read as the one selector it is; anything else that is not a list is named (G272).
        entries: list[tuple[PathT, str, Any]] = (
            [
                (("spec", "rkeConfig", "machineSelectorConfig", i), f"machineSelectorConfig[{i}]", sel)
                for i, sel in enumerate(selectors)
            ]
            if isinstance(selectors, list)
            else [(("spec", "rkeConfig", "machineSelectorConfig"), "machineSelectorConfig", selectors)]
            if isinstance(selectors, dict)
            else []
        )
        if selectors is not None and not isinstance(selectors, (list, dict)):
            out.unread.append("machineSelectorConfig is neither a list nor a mapping, so it was not read")
        for sel_path, label, sel in entries:
            if not isinstance(sel, dict):
                out.unread.append(f"{label} is not a mapping ({shown_value(sel)}), so it was not read")
                continue
            selector = _get(sel, "machineLabelSelector")
            if not _selects_every_machine(selector) and not _selects_the_control_plane(selector):
                # Which machines the selector picks is not in the object: these arguments may never reach a
                # control-plane node, so they decide nothing (G272).
                out.unread.append(
                    f"{label} applies only to machines matching machineLabelSelector "
                    f"{_selector_text(selector)}, which may not include the control plane, so its {key} is not read"
                )
                continue
            _key_values(_get(sel, "config", key), (*sel_path, "config", key), out, f"{label}.config.{key}")
    elif group == "operator.openshift.io" and kind == "KubeAPIServer" and component == "kube-apiserver":
        out.tool = "the OpenShift operator"
        out.unread.append("its overrides are written by the OpenShift kube-apiserver operator and are not read")
    else:
        return None
    return out


def describe(doc: Document) -> str:
    return _shown(doc.ref(), 160)
