"""What kube-apiserver's and etcd's explicit flags decide, for every reader that is not the static pod's argv (G272).

Split out of `rules.py` (as `argv.py` and `cpconfig.py` were) so that file stays under the 256 KiB the Claude
plugin directory reads. Holds the kube-apiserver flag tables and the authorization checks `KN-S038` reads with, the
ONE decision block over explicit flags that kubeadm's ClusterConfiguration, k0s, Rancher's RKE2 config and the
k3s/RKE2 argv all go through, the decline for lists and pod specs the loader could not open, and etcd's URL
helpers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kube_noob.audit.argv import (
    _EMBEDDED_APISERVER_ARG,
    _FLAG_NAME,
    INSECURE_FLAGS,
    _go_bool,
    _Launch,
    _quoted,
    _shown,
    insecure_serving,
    shown_value,
)
from kube_noob.audit.model import Finding, Severity
from kube_noob.audit.podspec import unread_pod_specs
from kube_noob.catalog import parse_minor
from kube_noob.yamlio import Document, PathT

if TYPE_CHECKING:
    from kube_noob.audit.rules import AuditContext, Rule


#: The upstream default of `--anonymous-auth` and of an empty `--authorization-mode`, and the releases they were
#: checked at. Both are the same at every tag from v1.6.0 to v1.37.0 and on master (1.38 development).
ANONYMOUS_AUTH_DEFAULT = "true"
APISERVER_DEFAULTS_CHECKED = "every Kubernetes release from v1.6.0 to v1.37.0 and master at fba15ecefa95"
_APISERVER_DEFAULTS_THROUGH = (1, 38)
_APISERVER_FLAGS = frozenset({"anonymous-auth", "authorization-mode", "authorization-config", "authentication-config"})
#: The flags `--authorization-config` may not be given with (AreLegacyFlagsSet, pkg/kubeapiserver/options/
#: authorization.go at v1.34.0): the API server refuses the combination, even with an empty --authorization-mode.
_AUTHZ_LEGACY_FLAGS = (
    "authorization-mode",
    "authorization-webhook-config-file",
    "authorization-webhook-version",
    "authorization-webhook-cache-authorized-ttl",
    "authorization-webhook-cache-unauthorized-ttl",
)
_APISERVER_READ = _APISERVER_FLAGS | {
    *_AUTHZ_LEGACY_FLAGS,
    "authorization-policy-file",
    "help",
    "version",
    *INSECURE_FLAGS,
}
#: kube-apiserver's boolean flags at v1.34.0 (every BoolVar its option sets register, plus cobra's --help and
#: component-base's --version, which pflag reads bare as true), so a bare one is read as true rather than as a
#: flag that might swallow the next. A flag this list lacks still declines when bare before another flag.
_APISERVER_BOOLS = frozenset(
    {
        "aggregator-reject-forwarding-redirect",
        "allow-privileged",
        "anonymous-auth",
        "audit-log-batch-throttle-enable",
        "audit-log-compress",
        "audit-log-truncate-enabled",
        "audit-webhook-batch-throttle-enable",
        "audit-webhook-truncate-enabled",
        "contention-profiling",
        "disable-http2-serving",
        "emulation-forward-compatible",
        "enable-aggregator-routing",
        "enable-bootstrap-token-auth",
        "enable-garbage-collector",
        "enable-logs-handler",
        "enable-priority-and-fairness",
        "encryption-provider-config-automatic-reload",
        "help",
        "log-json-split-stream",
        "log-text-split-stream",
        "permit-address-sharing",
        "permit-port-sharing",
        "profiling",
        "runtime-config-emulation-forward-compatible",
        "service-account-extend-token-expiration",
        "service-account-lookup",
        "shutdown-send-retry-after",
        "version",
        "watch-cache",
    }
)
#: The authorization modes kube-apiserver accepts (pkg/kubeapiserver/authorizer/modes/modes.go at fba15ecefa95,
#: AuthorizationModeChoices). Any other value, including one with spaces around it, makes it refuse to start.
AUTHORIZATION_MODES = frozenset({"AlwaysAllow", "AlwaysDeny", "ABAC", "Webhook", "RBAC", "Node"})


def _authorization_modes(values: list[str]) -> tuple[list[str], str]:
    """The `--authorization-mode` list as pflag's StringSlice builds it, or why it cannot be read.

    Each occurrence is one CSV record (an empty value is an empty list) appended to the last; a value with a quote
    is CSV quoting, which is not interpreted here; and a mode outside AUTHORIZATION_MODES -- `alwaysallow`, a mode
    with spaces round it, an empty field -- makes the API server refuse to start, so it is declined, not read.
    """
    modes: list[str] = []
    for v in values:
        if not v:
            continue
        if '"' in v:
            return [], f"quotes its --authorization-mode value ({_quoted(v, 80)}), which is CSV quoting not read here"
        modes.extend(v.split(","))
    unknown = [m for m in modes if m not in AUTHORIZATION_MODES]
    if unknown:
        return [], (
            f"names {_quoted(','.join(unknown), 80)} in --authorization-mode, which kube-apiserver does not accept, "
            "so it refuses to start with these arguments"
        )
    return modes, ""


def _last(flags: dict[str, list[tuple[str, int]]], name: str) -> str:
    """The value pflag keeps for a string flag: the last one given ("" when absent)."""
    values = flags.get(name)
    return values[-1][0] if values else ""


def _refused_authorization(flags: dict[str, list[tuple[str, int]]]) -> tuple[list[str], str]:
    """(the authorizer chain, "") -- or ([], why the API server refuses these arguments and does not start).

    BuiltInAuthorizationOptions.Validate (pkg/kubeapiserver/options/authorization.go at v1.34.0), after Complete
    has filled an empty chain with AlwaysAllow: --authorization-config with any legacy flag; a mode it does not
    know; a mode twice; ABAC without --authorization-policy-file or Webhook without
    --authorization-webhook-config-file; either file without its mode. Each of these was read as a decided
    authorizer before the second review (G272); a server that does not start has no authorizer to report.
    """
    refused = "a combination the API server refuses, so it does not start with these arguments"
    if _last(flags, "authorization-config"):
        legacy = next((f for f in _AUTHZ_LEGACY_FLAGS if flags.get(f)), None)
        if legacy:
            return [], f"names --authorization-config together with --{legacy}, {refused}"
        return [], ""
    modes, bad = _authorization_modes([v for v, _ in flags.get("authorization-mode", [])])
    if bad:
        return [], bad
    chain = modes or ["AlwaysAllow"]
    policy, webhook = _last(flags, "authorization-policy-file"), _last(flags, "authorization-webhook-config-file")
    if len(set(chain)) != len(chain):
        return [], f"lists an authorization mode more than once ({_quoted(','.join(chain), 80)}), {refused}"
    if "ABAC" in chain and not policy:
        return [], f"names ABAC in --authorization-mode without --authorization-policy-file, {refused}"
    if "Webhook" in chain and not webhook:
        return [], f"names Webhook in --authorization-mode without --authorization-webhook-config-file, {refused}"
    if policy and "ABAC" not in chain:
        return [], f"names --authorization-policy-file without the ABAC mode, {refused}"
    if webhook and "Webhook" not in chain:
        return [], f"names --authorization-webhook-config-file without the Webhook mode, {refused}"
    return modes, ""


def _embedded_apiserver_args(launch: _Launch) -> list[tuple[str, int]] | None:
    """The `--kube-apiserver-arg` values an embedding server's argv passes on, in argv order, each with the index
    of the token that carries it -- or None when the binary is not one that passes them (k0s)."""
    key = _EMBEDDED_APISERVER_ARG.get(launch.embedded)
    if key is None:
        return None
    values: list[tuple[str, int]] = []
    tokens = launch.tokens
    for i, t in enumerate(tokens):
        if t in (f"--{key}", f"-{key}") and i + 1 < len(tokens):
            values.append((tokens[i + 1], i + 1))
        elif t.startswith((f"--{key}=", f"-{key}=")):
            values.append((t.partition("=")[2], i))
    return values


def _apiserver_explicit(
    ctx: AuditContext,
    r: Rule,
    d: Document,
    pairs: list[tuple[str, str, PathT]],
    passes: str,
    through: str,
) -> tuple[list[Finding], list[str], bool]:
    """What flags an outside writer passes kube-apiserver EXPLICITLY decide, in the order pflag receives them,
    and what they leave undecided: the ONE decision block for every reader that is not the static pod's argv --
    kubeadm's ClusterConfiguration (and the objects that embed it), k0s, Rancher's RKE2 config and the k3s/RKE2
    argv (`--kube-apiserver-arg`). The seventh review found the argv reader deciding AlwaysAllow only, so
    `anonymous-auth=true` on `k3s server` was a MEDIUM finding in the Rancher config and nothing on the argv.

    A flag name no server defines (a padded one, `--123`) means the server does not start, as does an
    authorization chain the API server refuses, so those return no finding and the reason. An explicit
    `--authorization-mode=` replaces the writer's default with nothing, which upstream's Complete() fills with
    AlwaysAllow; AlwaysAllow in the chain is CRITICAL; ABAC and Webhook decline the authorizer; an explicit
    `--anonymous-auth` is read as a Go boolean (MEDIUM when true, declined when neither) unless AlwaysAllow
    already turned it off; the insecure port is read as the static-pod reader reads it. Absent flags are the
    writer's own defaults, which are not read: the caller declines those.
    Returns (findings, the fragments of the decline's reason, whether the whole rule is decided -- only AlwaysAllow
    decides it, because it allows every request and turns anonymous off; an explicit anonymous-auth leaves the
    authorizer to the writer's defaults); the caller adds the writer's defaults line.
    """
    out: list[Finding] = []
    unread: list[str] = []
    flags: dict[str, list[tuple[str, int]]] = {}
    for i, (name, value, _) in enumerate(pairs):
        if _FLAG_NAME.fullmatch(name) is None:
            padded = " with whitespace in its name" if name != name.strip() else ""
            return (
                [],
                [
                    f"passes the flag {_quoted(name, 80)}{padded}: kube-apiserver has no such flag; its flag parser "
                    "refuses it, so this server does not start"
                ],
                False,
            )
        flags.setdefault(name, []).append((value, i))
    if _last(flags, "authorization-config"):
        unread.append("it names --authorization-config, a file that is not in the input")
    modes, refused = _refused_authorization(flags)
    if refused:
        return [], [f"it {refused}"], False
    anon = flags.get("anonymous-auth", [])
    if anon and _go_bool(anon[-1][0]) is None:
        # pflag parses every flag before the server reads any: a value strconv.ParseBool refuses means it does
        # not start, whatever --authorization-mode says (G272, seventh review).
        return (
            [],
            [f"it sets --anonymous-auth={_quoted(anon[-1][0], 60)}, which is not a boolean, so it does not start"],
            False,
        )
    always_allow = False
    given = flags.get("authorization-mode", [])
    if given and not modes and not _last(flags, "authorization-config"):
        always_allow = True
        out.append(
            r.finding(
                d,
                pairs[given[-1][1]][2],
                f"{passes} --authorization-mode= (nothing) {through}, which replaces its own default with an empty "
                f"chain, and names no --authorization-config, so kube-apiserver uses the upstream default, AlwaysAllow "
                f"({APISERVER_DEFAULTS_CHECKED}): every request any authenticated client makes is allowed.",
            )
        )
    elif "AlwaysAllow" in modes:
        always_allow = True
        out.append(
            r.finding(
                d,
                pairs[next(i for v, i in reversed(given) if "AlwaysAllow" in v.split(","))][2],
                f"{passes} AlwaysAllow in --authorization-mode ({_quoted(','.join(modes))}) {through}: any request "
                "no earlier authorizer denies is allowed, so an authenticated client can do anything.",
            )
        )
    elif "ABAC" in modes or "Webhook" in modes:
        which = " and ".join(m for m in ("ABAC", "Webhook") if m in modes)
        unread.append(
            f"it authorizes through {which} in --authorization-mode ({_quoted(','.join(modes))}), which decides from "
            "a policy file or a webhook that is not in the input and can allow every request"
        )
    if anon and not always_allow:
        value, idx = anon[-1]
        if _go_bool(value):
            out.append(
                r.finding(
                    d,
                    pairs[idx][2],
                    f"{passes} --anonymous-auth=true {through}: a request with no credentials is served as "
                    "system:anonymous in group system:unauthenticated.",
                    severity=Severity.MEDIUM,
                )
            )
    minor = parse_minor(ctx.k8s_version)
    target = f"Kubernetes {ctx.k8s_version}" + ("" if ctx.version_stated else ", assumed")
    insecure = insecure_serving(flags, ctx.version_stated, minor, target)
    if insecure is not None and insecure[0] == "decline":
        unread.append(f"it {insecure[1]}")
    elif insecure is not None:
        out.append(
            r.finding(
                d,
                pairs[insecure[2]][2],
                f"{passes} {insecure[1]} {through}: on that port (Kubernetes 1.19 and older) a request is neither "
                "authenticated nor authorized, so anyone who can reach it has the API server as cluster-admin.",
            )
        )
    return out, unread, always_allow


def _unread_lists(ctx: AuditContext, r: Rule) -> bool:
    """What the loader could not open, declined: a list kind still in the input (its `items` is not a list), a
    document that is not a mapping at all (a list item that was a string or null, or a bare scalar document), and
    any document holding a pod spec no reader looks at (`items` under `spec`, `kind: podlist`, a sequence of Pods
    as one item) -- each may hold a pod these rules cannot read. Never the opened part read as the whole (G272)."""
    from kube_noob.yamlio import is_empty_list, is_list_kind

    seen = False
    for d in ctx.docs:
        if is_empty_list(d.data):
            continue  # the record that a list held nothing (`items: []` or `items: null`), not a list to read
        if is_list_kind(d.data) and isinstance(d.data, dict) and not isinstance(d.data.get("items"), list):
            seen = True
            ref = _shown(d.ref(), 160)
            ctx.cannot_decide(
                r.rule_id, f"{ref} is a list whose items are not a list, so what it holds was not read", ref
            )
            continue
        unread = unread_pod_specs(d)
        if unread:
            seen = True
            ref = _shown(d.ref(), 160) if isinstance(d.data, dict) else f"document {d.index + 1} (line {d.start_line})"
            where = (
                "in a kind kube-noob has no reader for" if isinstance(d.data, dict) else "in a sequence, not an object"
            )
            ctx.cannot_decide(
                r.rule_id,
                f"{ref} holds {len(unread)} pod spec(s) {where}, which may run a control-plane binary, so they were "
                "not read",
                ref,
            )
        elif not isinstance(d.data, dict):
            seen = True
            ref = f"document {d.index + 1} (line {d.start_line})"
            ctx.cannot_decide(
                r.rule_id, f"{ref} is not a mapping ({shown_value(d.data)}), so what it is was not read", ref
            )
    return seen


def _config_objects(ctx: AuditContext, r: Rule, component: str) -> tuple[bool, list[Finding]]:
    """Every object in the input that writes ``component``'s flags (`cpconfig.read_config`): the settings that
    decide on their own become findings, and everything else is named as seen and not read (G272).

    kube-apiserver: AlwaysAllow anywhere in the `authorization-mode` values is CRITICAL (a repeated v1beta4 entry
    is a repeated flag, which pflag appends), and an explicit `anonymous-auth: true` is MEDIUM; etcd: a plaintext
    listener or advertised URL on a network address. The rest depends on the tool's own defaults and declines.
    """
    from kube_noob.audit.cpconfig import read_config

    seen = False
    out: list[Finding] = []
    for d in ctx.docs:
        read = read_config(d, component, parse_minor(ctx.k8s_version))
        if read is None:
            continue
        seen = True
        ref = _shown(d.ref(), 160)
        ctx.looked_at(r.rule_id, ref)
        decided = False
        if component == "kube-apiserver":
            found, unread, decided = _apiserver_explicit(
                ctx, r, d, read.pairs, f"{ref} has {read.tool} pass", "to kube-apiserver"
            )
            out.extend(found)
            read.unread.extend(unread)
        else:
            for k, v, path in read.pairs:
                if k not in _ETCD_URL_DEFAULTS:
                    continue
                try:
                    plain, _ = _network_urls(v, k)
                except _Undecidable as why:
                    read.unread.append(str(why))
                    continue
                if plain:
                    decided = True
                    side = "client" if "client" in k else "peer"
                    out.append(
                        r.finding(
                            d,
                            path,
                            f"{ref} has {read.tool} pass --{k}={_quoted(', '.join(plain))} to etcd: plaintext "
                            f"{side} traffic on a network address, where no certificate can be required.",
                            severity=Severity.CRITICAL if side == "client" else Severity.HIGH,
                        )
                    )
        # Declined whenever something was not read, decided or not: the seventh review found a refused entry
        # ("not a {name, value} pair") hidden behind a decided AlwaysAllow beside it (G272).
        if not decided or read.unread:
            rest = "; ".join(read.unread[:3]) or f"the rest of what it sets depends on {read.tool}'s own defaults"
            ctx.cannot_decide(
                r.rule_id,
                f"{ref} writes {component}'s flags through {read.tool}, and is read only for the settings that "
                f"decide on their own: {rest}",
                ref,
            )
    return seen, out


_ETCD_URL_DEFAULTS = {
    "listen-client-urls": "http://localhost:2379",
    "listen-client-http-urls": "",
    "advertise-client-urls": "http://localhost:2379",
    "listen-peer-urls": "http://localhost:2380",
    "initial-advertise-peer-urls": "http://localhost:2380",
}


class _Undecidable(Exception):
    """A setting the manifest does not state, with the reason."""


def _is_loopback(host: str) -> bool:
    import ipaddress

    if host.lower().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _network_urls(value: str, flag: str) -> tuple[list[str], list[str]]:
    """(plaintext URLs on a network address, TLS URLs on a network address) in one URL-list value."""
    from urllib.parse import urlsplit

    plain: list[str] = []
    tls: list[str] = []
    for raw in (u.strip() for u in value.split(",")):
        if not raw:
            continue
        try:
            parts = urlsplit(raw)
            host = parts.hostname or ""
        except ValueError as exc:
            raise _Undecidable(f"--{flag} value {_quoted(raw, 80)} is not a URL") from exc
        scheme = parts.scheme.lower()
        if scheme in {"unix", "unixs"}:
            continue  # a socket on the node, not a network listener
        if scheme not in {"http", "https"}:
            raise _Undecidable(f"--{flag} value {_quoted(raw, 80)} has a scheme etcd's TLS settings do not describe")
        if _is_loopback(host):
            continue
        (plain if scheme == "http" else tls).append(raw)
    return plain, tls
