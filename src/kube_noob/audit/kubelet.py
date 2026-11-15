"""Where the kubelet's settings are written, and what an absent one means in each shape (G302).

The kubelet is the component a cluster has most copies of, and it is configured in five shapes a real fleet
produces: a `KubeletConfiguration` object (`kubelet.config.k8s.io/v1beta1`), the same object inside a kubeadm
bundle beside an `InitConfiguration`, a static pod or DaemonSet whose command is the kubelet, OpenShift's
`KubeletConfig` CR (`machineconfiguration.openshift.io/v1`), and a `MachineConfig` whose embedded ignition
carries `/etc/kubernetes/kubelet.conf`. This module reads them all into one record, so `KN-S042`..`KN-S045`
decide once and no shape is read by one rule and skipped by the next (class 25).

**The two default tables are the whole point.** Checked at kubernetes/kubernetes `fba15ecefa95` (master, the 1.38
development branch) and unchanged at v1.20.0, v1.24.0, v1.28.0, v1.31.0, v1.33.0, v1.34.0 and v1.35.0:

* `cmd/kubelet/app/options/options.go`, `applyLegacyDefaults`, is the baseline the COMMAND LINE starts from:
  `--anonymous-auth=true`, `--authentication-token-webhook=false`, `--authorization-mode=AlwaysAllow` and
  `--read-only-port=10255` (`pkg/cluster/ports/ports.go`, `KubeletReadOnlyPort`).
* `pkg/kubelet/apis/config/v1beta1/defaults.go`, `SetDefaults_KubeletConfiguration`, is what a
  `KubeletConfiguration` FILE starts from: `authentication.anonymous.enabled: false`,
  `authentication.webhook.enabled: true`, `authorization.mode: Webhook`, and `readOnlyPort` left at its zero
  value, 0.

So the same absent setting means the opposite thing in the two shapes, and a reader that used one table for both
would report a finding on a file that is safe or pass a command line that is not. Everything else --
`protectKernelDefaults` false, `rotateCertificates` false, `serverTLSBootstrap` false, `tlsCipherSuites` empty --
is the zero value in both, and `makeIPTablesUtilChains` is true and `eventRecordQPS` 50 in both.

`cmd/kubelet/app/server.go`, `kubeletConfigFlagPrecedence`, re-registers the configuration flags against the
config file that was loaded and re-parses argv, so a flag given on the command line wins over the file and a flag
that is absent leaves the file's value. That is why a command line with `--config` DECLINES every setting it does
not itself state -- the file is not in the input -- and why a file DECLINES the settings it does not state, since
the command line that could override them is not in the input either.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from kube_noob.audit.argv import _flag_values, _go_bool, _launch, _quoted, _shown
from kube_noob.yamlio import PathT

if TYPE_CHECKING:
    from collections.abc import Iterator

    from kube_noob.audit.rules import AuditContext
    from kube_noob.yamlio import Document

#: The releases the two default tables above were read at, named in every message that quotes a default.
KUBELET_DEFAULTS_CHECKED = "kubernetes/kubernetes fba15ecefa95 and every release from v1.20.0 to v1.35.0"

#: The group OpenShift's `KubeletConfig` and `MachineConfig` are served in. A kind of either name in any other
#: group is a different resource and not a subject of these rules (class 3).
MACHINE_CONFIG_GROUP = "machineconfiguration.openshift.io"
#: The group a `KubeletConfiguration` is served in.
KUBELET_CONFIG_GROUP = "kubelet.config.k8s.io"
#: The label a MachineConfig carries to say which pool it belongs to, and the prefix a KubeletConfig's pool
#: selector uses. Both are the Machine Config Operator's own spellings.
MACHINE_CONFIG_ROLE_LABEL = "machineconfiguration.openshift.io/role"
POOL_SELECTOR_PREFIX = "pools.operator.machineconfiguration.openshift.io/"
#: The two roles whose ownership differs; any other pool name leaves the role unstated.
NODE_ROLES = ("master", "worker")

#: The file in a MachineConfig's ignition that holds the node's KubeletConfiguration, as the Machine Config
#: Operator writes it. Matched on the whole path, never a substring (class 3).
KUBELET_CONF_PATHS = frozenset({"/etc/kubernetes/kubelet.conf", "/etc/kubernetes/kubelet.conf.d/kubelet.conf"})

#: kube-noob's own name for each setting -> (the kubelet flag that sets it, the path in a KubeletConfiguration).
#: One table, so a flag and a field can never disagree about which setting they are (class 9).
SETTINGS: dict[str, tuple[str, tuple[str, ...]]] = {
    "anonymousAuth": ("anonymous-auth", ("authentication", "anonymous", "enabled")),
    "clientCAFile": ("client-ca-file", ("authentication", "x509", "clientCAFile")),
    "authorizationMode": ("authorization-mode", ("authorization", "mode")),
    "readOnlyPort": ("read-only-port", ("readOnlyPort",)),
    "streamingConnectionIdleTimeout": ("streaming-connection-idle-timeout", ("streamingConnectionIdleTimeout",)),
    "protectKernelDefaults": ("protect-kernel-defaults", ("protectKernelDefaults",)),
    "makeIPTablesUtilChains": ("make-iptables-util-chains", ("makeIPTablesUtilChains",)),
    "eventRecordQPS": ("event-qps", ("eventRecordQPS",)),
    "tlsCipherSuites": ("tls-cipher-suites", ("tlsCipherSuites",)),
    "rotateCertificates": ("rotate-certificates", ("rotateCertificates",)),
    "serverTLSBootstrap": ("rotate-server-certificates", ("serverTLSBootstrap",)),
    "featureGates": ("feature-gates", ("featureGates",)),
}
_BY_FLAG = {flag: name for name, (flag, _) in SETTINGS.items()}

#: `applyLegacyDefaults` (the command line) and `SetDefaults_KubeletConfiguration` (a file), for the three
#: settings where they differ. A setting absent from both tables has the same default in both shapes.
ARGV_DEFAULTS: dict[str, Any] = {"anonymousAuth": True, "authorizationMode": "AlwaysAllow", "readOnlyPort": 10255}
FILE_DEFAULTS: dict[str, Any] = {"anonymousAuth": False, "authorizationMode": "Webhook", "readOnlyPort": 0}
#: Why a setting a configuration FILE does not state is declined rather than taken from FILE_DEFAULTS: the
#: kubelet re-parses argv over the loaded file (`kubeletConfigFlagPrecedence`), so a flag wins, and a command
#: line is not part of a KubeletConfiguration object. A command line, by contrast, is read WHOLE, so a flag that
#: is not in it is genuinely absent and the legacy table decides -- unless it names `--config`.
FILE_HAS_NO_COMMAND_LINE = (
    "the kubelet's command line is not in the input, and a flag given there wins over a KubeletConfiguration "
    "file, so what this object does not state was not read"
)

#: The defaults that are the same in both shapes.
SHARED_DEFAULTS: dict[str, Any] = {
    "clientCAFile": "",
    "streamingConnectionIdleTimeout": "4h0m0s",
    "protectKernelDefaults": False,
    "makeIPTablesUtilChains": True,
    "eventRecordQPS": 50,
    "tlsCipherSuites": [],
    "rotateCertificates": False,
    "serverTLSBootstrap": False,
}

#: The authorization modes the kubelet accepts (`pkg/kubelet/apis/config/v1beta1/types.go`,
#: KubeletAuthorizationModeAlwaysAllow and KubeletAuthorizationModeWebhook). Any other value makes the kubelet
#: refuse to start, so it is declined rather than read as one of these.
KUBELET_AUTHORIZATION_MODES = frozenset({"AlwaysAllow", "Webhook"})

#: Go's own classification, from `crypto/tls.InsecureCipherSuites()` at go1.27.4 -- the Go release
#: kubernetes/kubernetes `fba15ecefa95` names in `.go-version` -- and identical at go1.25.4. Kubernetes accepts
#: exactly these names through `component-base/cli/flag`, whose `InsecureTLSCiphers()` is that list verbatim.
INSECURE_CIPHER_SUITES = frozenset(
    {
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    }
)
#: `crypto/tls.CipherSuites()` at the same releases, plus the two legacy ChaCha20 names `component-base` keeps
#: for backward compatibility. A name in neither set is one the kubelet refuses to start with.
PREFERRED_CIPHER_SUITES = frozenset(
    {
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
    }
)

#: Flags that mark a container with no readable `kubelet` head as the kubelet: the ones only it has.
KUBELET_HINTS = frozenset(
    {
        "kubeconfig",
        "container-runtime-endpoint",
        "pod-manifest-path",
        "register-node",
        "rotate-server-certificates",
        "protect-kernel-defaults",
        "make-iptables-util-chains",
        "bootstrap-kubeconfig",
        "node-labels",
        "pod-infra-container-image",
    }
)
#: Every `fs.BoolVar` `cmd/kubelet/app/options/options.go` registers at `fba15ecefa95`, plus cobra's `--help` and
#: component-base's `--version`, which pflag reads bare as true. A flag this list lacks still declines when given
#: bare before another flag, in both directions (`argv._flag_values`).
KUBELET_BOOLS = frozenset(
    {
        "anonymous-auth",
        "authentication-token-webhook",
        "cgroups-per-qos",
        "contention-profiling",
        "cpu-cfs-quota",
        "enable-controller-attach-detach",
        "enable-debugging-handlers",
        "enable-server",
        "exit-on-lock-contention",
        "experimental-allocatable-ignore-eviction",
        "fail-cgroupv1",
        "fail-swap-on",
        "help",
        "kernel-memcg-notification",
        "local-storage-capacity-isolation",
        "make-iptables-util-chains",
        "protect-kernel-defaults",
        "register-node",
        "rotate-certificates",
        "rotate-server-certificates",
        "runonce",
        "seccomp-default",
        "serialize-image-pulls",
        "version",
    }
)
KUBELET_READ = frozenset({*(flag for flag, _ in SETTINGS.values()), "config", "help", "version"})

#: How large an embedded ignition file is decoded; a larger one is not read.
MAX_IGNITION_BYTES = 256 * 1024
_DATA_URL = re.compile(r"\Adata:(?P<meta>[^,]*),(?P<body>.*)\Z", re.DOTALL)
_GO_DURATION = re.compile(r"\A-?(?:\d+(?:\.\d+)?(?:ns|us|µs|μs|ms|s|m|h))+\Z")


@dataclass
class KubeletSettings:
    """What ONE object says about ONE kubelet, and what it does not say.

    ``values`` holds only the settings the object states, each with the path that holds it, so a rule can tell
    "stated" from "absent" and never defaults a setting from a file it did not read. ``defaults`` names which
    of the two tables fills an absent setting -- ``"argv"``, ``"file"``, or ``""`` when neither does because
    something the input does not carry (a `--config` file, the command line beside a configuration object)
    could set it.
    """

    #: How a message names this object ("Pod kube-system/kubelet container 'kubelet'"), already cleaned.
    where: str
    #: The object reference a decline records, already cleaned.
    ref: str
    #: "argv" for a command line, "file" for a configuration object: which spelling a message uses for a
    #: setting (`--read-only-port` or `readOnlyPort`).
    spelling: str
    values: dict[str, tuple[Any, PathT]] = field(default_factory=dict)
    defaults: str = ""
    #: Why an absent setting cannot be defaulted, as one fixed-phrase fragment; "" when ``defaults`` fills it.
    no_defaults: str = ""
    #: Fixed-phrase fragments for what in this object was not read at all.
    unread: list[str] = field(default_factory=list)
    #: Non-empty when the whole object could not be read, with the reason.
    declined: str = ""
    #: The node role this object configures, when it says: "worker", "master", or "" when nothing states it.
    #: On a managed platform an unstated role is treated as the control plane's, because assuming the worker
    #: role there would read Red Hat's own configuration as the customer's (`audit.ownership`).
    role: str = ""
    #: The document the paths in ``values`` are relative to.
    doc: Document | None = None

    def flag(self, setting: str) -> str:
        """How a message names ``setting`` in this shape."""
        name, path = SETTINGS[setting][0], SETTINGS[setting][1]
        return f"--{name}" if self.spelling == "argv" else ".".join(path)

    def stated(self, setting: str) -> bool:
        return setting in self.values

    def path(self, setting: str) -> PathT:
        value = self.values.get(setting)
        return value[1] if value else ()


def _scalar(value: Any) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value)


# --- the file shapes --------------------------------------------------------------------------------


def _read_fields(data: Any, base: PathT, out: KubeletSettings) -> None:
    """Every setting a KubeletConfiguration mapping states, at ``base``, with the path that holds it."""
    if not isinstance(data, dict):
        out.unread.append("its kubelet configuration is not a mapping, which the kubelet does not decode")
        return
    for setting, (_, path) in SETTINGS.items():
        node: Any = data
        full = base
        for key in path:
            if not isinstance(node, dict):
                node = None
                break
            if key not in node:
                node = None
                break
            node = node[key]
            full = (*full, key)
        if node is None:
            continue
        out.values[setting] = (node, full)


def _ignition_files(data: Any, base: PathT) -> Iterator[tuple[dict[str, Any], PathT]]:
    """Every `storage.files` entry of a MachineConfig's embedded ignition, with the path that holds it."""
    storage = data.get("storage") if isinstance(data, dict) else None
    files = storage.get("files") if isinstance(storage, dict) else None
    if not isinstance(files, list):
        return
    for i, entry in enumerate(files):
        if isinstance(entry, dict):
            yield entry, (*base, "storage", "files", i)


def _decode_ignition(entry: dict[str, Any]) -> tuple[str | None, str]:
    """The file's contents as text, or (None, why kube-noob did not read them) -- a fixed phrase, no input text.

    Only a `data:` URL is decoded: a `source` that fetches over the network is a file this offline tool will not
    read, and a compression this reader does not know is never read as if it were plain (class 4).
    """
    contents = entry.get("contents")
    if not isinstance(contents, dict):
        return None, "an ignition file entry whose contents are not a mapping, which ignition does not decode"
    compression = contents.get("compression")
    if compression not in (None, "", "gzip"):
        return None, "an ignition file compressed in a way kube-noob does not decode"
    source = contents.get("source")
    if contents.get("inline") is not None and source is None:
        source = None  # spec 3.x `inline`, read below as plain text
        inline = contents.get("inline")
        if not isinstance(inline, str):
            return None, "an ignition file whose inline contents are not a string"
        return inline, ""
    if not isinstance(source, str):
        return None, "an ignition file with no source kube-noob can read"
    match = _DATA_URL.match(source)
    if match is None:
        return None, "an ignition file whose source is not a data URL, so its contents are not in the input"
    meta, body = match.group("meta"), match.group("body")
    try:
        if "base64" in meta.lower():
            raw = base64.b64decode(body, validate=True)
        else:
            from urllib.parse import unquote_to_bytes

            raw = unquote_to_bytes(body)
    except (binascii.Error, ValueError):
        return None, "an ignition file whose data URL is not valid base64"
    if compression == "gzip":
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError):
            return None, "an ignition file whose gzip contents kube-noob could not decompress"
    if len(raw) > MAX_IGNITION_BYTES:
        return None, "an ignition file larger than kube-noob decodes"
    try:
        return raw.decode("utf-8"), ""
    except UnicodeDecodeError:
        return None, "an ignition file whose contents are not UTF-8 text"


def _parse_config_text(text: str) -> tuple[Any, str]:
    from kube_noob.yamlio import load_documents

    try:
        docs = load_documents(text)
    except Exception:  # noqa: BLE001 -- any parse failure is the same answer: it was not read
        return None, "an ignition file that is not YAML or JSON kube-noob can parse"
    data = next((d.data for d in docs if isinstance(d.data, dict)), None)
    if data is None:
        return None, "an ignition file that holds no mapping, so it is not a KubeletConfiguration"
    return data, ""


def _file_sources(ctx: AuditContext) -> Iterator[KubeletSettings]:
    """Every object in the input that WRITES the kubelet's configuration, in document order.

    A `KubeletConfiguration` of its own or inside a kubeadm bundle (the same kind either way, so the same
    reader), OpenShift's `KubeletConfig` CR, and a `MachineConfig` whose ignition carries `kubelet.conf`. Each
    is matched on kind AND group, so somebody else's `KubeletConfig` is a different kind (class 3).
    """
    for d in ctx.docs:
        if not isinstance(d.data, dict):
            continue
        group = d.api_version.split("/", 1)[0] if "/" in d.api_version else ""
        ref = _shown(d.ref(), 160)
        if d.kind == "KubeletConfiguration" and group == KUBELET_CONFIG_GROUP:
            out = _file_record(ref, d)
            _read_fields(d.data, (), out)
            yield out
        elif d.kind == "KubeletConfig" and group == MACHINE_CONFIG_GROUP:
            spec = d.data.get("spec")
            out = _file_record(ref, d)
            if not isinstance(spec, dict) or "kubeletConfig" not in spec:
                out.declined = "is a KubeletConfig with no spec.kubeletConfig mapping, so what it sets was not read"
                yield out
                continue
            out.role = _pool_role(spec)
            _read_fields(spec.get("kubeletConfig"), ("spec", "kubeletConfig"), out)
            yield out
        elif d.kind == "MachineConfig" and group == MACHINE_CONFIG_GROUP:
            yield from _machine_config(d, ref)


def _file_record(ref: str, d: Document, role: str = "") -> KubeletSettings:
    """A configuration object's record: it decides what it STATES and declines what it does not."""
    return KubeletSettings(
        where=ref, ref=ref, spelling="file", defaults="", no_defaults=FILE_HAS_NO_COMMAND_LINE, doc=d, role=role
    )


def _pool_role(data: Any) -> str:
    """The node role a KubeletConfig's `spec.machineConfigPoolSelector` names, or "" when it names neither.

    Only the operator's own `pools.operator.machineconfiguration.openshift.io/<role>` label decides. A selector
    written any other way (a custom pool label, `matchExpressions`, or one naming both pools) leaves the role
    unstated rather than being guessed, because a wrong guess reads one owner's configuration as another's.
    """
    selector = data.get("machineConfigPoolSelector") if isinstance(data, dict) else None
    labels = selector.get("matchLabels") if isinstance(selector, dict) else None
    if not isinstance(labels, dict):
        return ""
    named = [
        key[len(POOL_SELECTOR_PREFIX) :]
        for key in labels
        if isinstance(key, str) and key.startswith(POOL_SELECTOR_PREFIX)
    ]
    roles = {r for r in named if r in NODE_ROLES}
    return roles.pop() if len(roles) == 1 and not (set(named) - set(NODE_ROLES)) else ""


def _machine_config_role(d: Document) -> str:
    """The node role a MachineConfig's own role label names, or "" when it carries none kube-noob knows."""
    labels = (d.data.get("metadata") or {}).get("labels") if isinstance(d.data, dict) else None
    role = labels.get(MACHINE_CONFIG_ROLE_LABEL) if isinstance(labels, dict) else None
    return role if role in NODE_ROLES else ""


def _machine_config(d: Document, ref: str) -> Iterator[KubeletSettings]:
    config = d.data.get("spec", {}).get("config") if isinstance(d.data.get("spec"), dict) else None
    role = _machine_config_role(d)
    for entry, path in _ignition_files(config, ("spec", "config")):
        if entry.get("path") not in KUBELET_CONF_PATHS:
            continue
        out = _file_record(ref, d, role)
        text, why = _decode_ignition(entry)
        if text is None:
            out.declined = f"carries {why}"
            yield out
            continue
        data, why = _parse_config_text(text)
        if data is None:
            out.declined = f"carries {why}"
            yield out
            continue
        # The decoded file's own paths are not paths in the MachineConfig, so every value points at the
        # ignition entry that carried it rather than at a path the reader would not find (class 7).
        inner = _file_record(ref, d, role)
        _read_fields(data, (), inner)
        out.values = {name: (value, (*path, "contents", "source")) for name, (value, _) in inner.values.items()}
        out.unread = inner.unread
        yield out


# --- the command line ------------------------------------------------------------------------------


def _argv_sources(ctx: AuditContext) -> Iterator[KubeletSettings]:
    from kube_noob.audit.argv import expand_argv
    from kube_noob.audit.rules import _containers

    for d, _pt, c in _containers(ctx):
        launch = _launch(c.container, "kubelet", KUBELET_HINTS, None)
        if launch is None:
            continue
        ref = _shown(d.ref(), 160)
        where = f"{ref} container {_quoted(c.name, 80)}"
        out = KubeletSettings(where=where, ref=ref, spelling="argv", doc=d)
        runs = "may run" if launch.maybe else "runs"
        if launch.embedded:
            out.declined = (
                f"{runs} the kubelet inside {launch.embedded} server, which sets its flags from the "
                "distribution's own defaults and configuration file, which are not read"
            )
            yield out
            continue
        if launch.declined:
            starts = "may start" if launch.maybe else "starts"
            out.declined = f"{starts} the kubelet {launch.declined}"
            yield out
            continue
        tokens, unexpanded = expand_argv(launch.tokens, c.container)
        if unexpanded is not None:
            out.declined = f"passes an argument to the kubelet through $(VAR) expansion: {unexpanded}"
            yield out
            continue
        flags, problem = _flag_values(tokens, KUBELET_READ, KUBELET_BOOLS, False, pflag=True)
        if problem is not None:
            out.declined = f"{runs} the kubelet and {problem}"
            yield out
            continue
        if flags.get("help") or flags.get("version"):
            continue  # pflag prints and exits: not a running kubelet
        for name, values in flags.items():
            setting = _BY_FLAG.get(name)
            if setting is None or not values:
                continue
            if setting == "tlsCipherSuites":
                joined = ",".join(v for v, _ in values)
                out.values[setting] = ([s for s in joined.split(",") if s], _argv_path(c, launch.skip, values[-1][1]))
            else:
                out.values[setting] = (values[-1][0], _argv_path(c, launch.skip, values[-1][1]))
        if flags.get("config"):
            out.defaults = ""
            out.no_defaults = (
                "it names --config, a KubeletConfiguration file on the node that is not in the input, and the "
                "kubelet re-applies only the flags that are given on top of it"
            )
        else:
            out.defaults = "argv"
        yield out


def _argv_path(c: Any, skip: int, index: int) -> PathT:
    command = c.container["command"]
    absolute = index + skip
    if absolute < len(command):
        return (*c.path, "command", absolute)
    return (*c.path, "args", absolute - len(command))


# --- the one entry point ---------------------------------------------------------------------------


def kubelet_sources(ctx: AuditContext) -> list[KubeletSettings]:
    """Every object in the input that configures a kubelet, file shapes before command lines.

    Sorted by the reference the record names, so the order the documents arrived in does not change the answer
    (class 5).
    """
    sources = [*_file_sources(ctx), *_argv_sources(ctx)]
    return sorted(sources, key=lambda s: (s.spelling, s.where))


def resolve(source: KubeletSettings, setting: str) -> tuple[str, Any]:
    """What ``setting`` is on this kubelet: ("stated", value), ("default", value), or ("unknown", the reason).

    ("unknown", reason) is the honest answer wherever the shape does not state the setting and something not in
    the input could: a `--config` file, or the command line beside a configuration object. It is never filled
    from a default this reader did not read in upstream's own source.
    """
    if setting in source.values:
        return "stated", source.values[setting][0]
    if source.defaults == "argv":
        return "default", SHARED_DEFAULTS[setting] if setting in SHARED_DEFAULTS else ARGV_DEFAULTS[setting]
    return "unknown", source.no_defaults


def read_bool(value: Any) -> bool | None:
    """A kubelet boolean as the shape writes it: a YAML bool in a file, a Go boolean string on the command line."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _go_bool(value)
    return None


def read_int(value: Any) -> int | None:
    """An int32 field as either shape writes it. A YAML bool is not a number, and neither is a float."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text) if text == value and text else None
        except ValueError:
            return None
    return None


def read_duration(value: Any) -> int | None:
    """A Go duration in nanoseconds, or None when `time.ParseDuration` would refuse it.

    A bare `0` is the one unitless value Go accepts (`time.ParseDuration`), and it is the value that turns the
    timeout off, so it is read rather than declined.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value * 1_000_000_000  # a plain number in a metav1.Duration field is seconds in YAML's eyes
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text != value:
        return None
    if text in ("0", "-0", "+0"):
        return 0
    if _GO_DURATION.fullmatch(text) is None:
        return None
    units = {
        "ns": 1,
        "us": 1_000,
        "µs": 1_000,
        "μs": 1_000,
        "ms": 1_000_000,
        "s": 10**9,
        "m": 60 * 10**9,
        "h": 3600 * 10**9,
    }
    total = 0.0
    sign = -1 if text.startswith("-") else 1
    for number, unit in re.findall(r"(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)", text):
        total += float(number) * units[unit]
    return int(sign * total)


def read_strings(value: Any) -> list[str] | None:
    """A string-slice field: a YAML list of strings, or a comma-separated string as pflag reads it."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)] if all(isinstance(v, str) for v in value) else None
    if isinstance(value, str):
        return [v for v in value.split(",") if v]
    return None


def read_gates(value: Any) -> dict[str, bool] | None:
    """`featureGates` as a mapping of name to bool, or `--feature-gates=Name=true,Other=false` as pflag reads it."""
    if isinstance(value, dict):
        if not all(isinstance(k, str) and isinstance(v, bool) for k, v in value.items()):
            return None
        return dict(value)
    if not isinstance(value, str):
        return None
    out: dict[str, bool] = {}
    for item in value.split(","):
        if not item:
            continue
        name, sep, raw = item.partition("=")
        if not sep:
            return None
        flag = _go_bool(raw)
        if flag is None or not name:
            return None
        out[name] = flag
    return out
