"""The control plane's own trust boundaries (KN-S037..KN-S041, G272), and the rules that overflow `rules.py`.

Its own module, not part of `rules.py`, for the same reason `argv.py`, `cpflags.py` and `cpconfig.py` are: the
generated plugin copy of a module may not exceed 256 KiB (`scripts/sync_plugin_server.py`, the plugin
directory's own limit), and merging these five rules into the branch that made every rule declare its subject
put `rules.py` at 292 KiB. Nothing in the G272 block is new; it is that block moved whole.

Because this is where that headroom lives, it is also where a NEW rule goes once `rules.py` is close to the
cap: KN-C017 (G396) is here and not beside KN-C015, which it is the sibling of, for no other reason than that
`rules.py` had about 2.9 KiB left and the rule plus the comments that explain it does not fit in 2.9 KiB. A
reader looking for a wiring rule should expect to find one here.

`rules.py` imports this module at the END of its own body, which is what registers these rules in `RULES`. The
import is circular by construction -- the rules need the `@rule` decorator and the context helpers that live
there -- and it resolves because `rules.py` is fully built by the time that last line runs. So nothing else
should import this module: import `kube_noob.audit.rules`, which always brings it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from kube_noob.audit.argv import (
    _EMBEDDED_APISERVER_ARG,
    _exits_at_once,
    _flag_values,
    _go_bool,
    _image_tag,
    _launch,
    _quoted,
    _shown,
    expand_argv,
    insecure_serving,
    k3s_pairs,
)
from kube_noob.audit.cpflags import (
    _APISERVER_BOOLS,
    _APISERVER_DEFAULTS_THROUGH,
    _APISERVER_FLAGS,
    _APISERVER_READ,
    _ETCD_URL_DEFAULTS,
    ANONYMOUS_AUTH_DEFAULT,
    APISERVER_DEFAULTS_CHECKED,
    _apiserver_explicit,
    _config_objects,
    _embedded_apiserver_args,
    _last,
    _network_urls,
    _refused_authorization,
    _Undecidable,
    _unread_lists,
)
from kube_noob.audit.model import Finding, Severity, Stage
from kube_noob.audit.podspec import ContainerRef, PodTemplate, containers
from kube_noob.audit.rules import (
    ANY_OBJECT,
    APISERVICE_GROUP,
    HOSTED_CONTROL_PLANE_PLATFORMS,
    OAUTH_GROUP,
    WORKLOAD_SUBJECT,
    AuditContext,
    Rule,
    _containers,
    _off_openshift,
    _singleton,
    cluster_apiservers,
    rule,
)
from kube_noob.catalog import parse_minor
from kube_noob.yamlio import Document, PathT, get_path

# =====================================================================================================
# AUDIT - the control plane and its trust boundaries (G272)
# =====================================================================================================
# Every fact below was read on 2026-11-11 from the upstream source at the commit named, and the defaults were
# checked at the release tags named, rather than recalled:
#   kubernetes/kubernetes fba15ecefa95 (master, 1.38 development): kube-aggregator apiregistration/v1 types.go,
#     pkg/kubeapiserver/options/authentication.go and authorization.go; the same defaults at v1.6.0 ... v1.37.0.
#   etcd-io/etcd d11eca9a9c16 (main): server/embed/config.go, server/etcdmain/config.go, pkg/flags/flag.go and
#     client/pkg/transport/listener.go; the same defaults at v3.4.0, v3.5.0 and v3.6.0.
#   openshift/api 61403fc4e89f (master): config/v1/types_apiserver.go and types_oauth.go.
#
# Each rule here declines QUIETLY when nothing of its kind is in the input: no APIService, no container that
# runs kube-apiserver or etcd, no OpenShift singleton. "Nothing to look at" is not "looked and found it clean",
# and counting it clean made every application bundle evidence for AC-14 and SC-28(1) (G272).


@rule(
    "KN-S037",
    "APIService does not verify the extension API server it forwards to",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Remove spec.insecureSkipTLSVerify and set spec.caBundle to the CA that signed the extension API server's "
    "serving certificate (on OpenShift, annotate the APIService with service.beta.openshift.io/inject-cabundle: "
    '"true" and let the service CA fill it).',
    "With insecureSkipTLSVerify the aggregation layer sends every request for that API group to whatever answers on "
    "the named Service without checking its certificate. Upstream's own field comment calls this strongly "
    "discouraged. An absent caBundle is not the same thing: the API server then verifies against its system trust "
    "roots.",
    ("k8s-apiservice-types",),
    subjects=("APIService",),
)
def _s037(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """An APIService whose aggregator does not verify the far end.

    `spec.service` nil means the group is served by the API server itself and there is no remote end, so a local
    APIService is out of scope whatever it says. `insecureSkipTLSVerify` is a plain bool in the API type; any
    other value, a spec that is not a mapping and a service that is not one are objects the API server refuses to
    decode, which this rule declines rather than guesses.
    """
    docs = [d for d in ctx.by_kind("APIService") if d.api_version.split("/", 1)[0] == APISERVICE_GROUP]
    if not docs:
        ctx.cannot_decide(r.rule_id, "no config.openshift.io APIServer in the input")
        return
    for d in docs:
        spec = d.data.get("spec") if isinstance(d.data, dict) else None
        ref = _shown(d.ref(), 160)
        if not isinstance(spec, dict):
            ctx.cannot_decide(r.rule_id, f"{ref} has no spec mapping, which the API server does not accept", ref)
            continue
        service = spec.get("service")
        if service is None:
            continue  # served locally: nothing on the other end of a connection to verify
        flag = spec.get("insecureSkipTLSVerify")
        if flag is None or flag is False:
            continue
        if flag is not True or not isinstance(service, dict):
            what = (
                "spec.service is not a mapping"
                if not isinstance(service, dict)
                else f"spec.insecureSkipTLSVerify is {_quoted(flag, 60)}, not a boolean"
            )
            ctx.cannot_decide(r.rule_id, f"{ref}: {what}, which the API server does not accept", ref)
            continue
        target = _shown(f"{service.get('namespace') or '<no namespace>'}/{service.get('name') or '<no name>'}", 160)
        group = _shown(f"{spec.get('group') or '<no group>'}/{spec.get('version') or '<no version>'}", 160)
        yield r.finding(
            d,
            ("spec", "insecureSkipTLSVerify"),
            f"{ref} sets insecureSkipTLSVerify: true, so the API server sends every request for {group} -- "
            f"with the identity of the user who made it -- to whatever answers on Service {target}, without checking "
            "its certificate. Anyone who can take over that Service's endpoints can answer for the whole API group.",
        )


def _argv_path(c: ContainerRef, skip: int, index: int) -> PathT:
    """Where flag token ``index`` sits in the manifest: argv is command + args, and the flags start ``skip`` in."""
    command = c.container["command"]
    absolute = index + skip
    if absolute < len(command):
        return (*c.path, "command", absolute)
    return (*c.path, "args", absolute - len(command))


def _where(d: Document, c: ContainerRef) -> tuple[str, str]:
    """(how a message names this container, the object reference a decline records), both cleaned."""
    ref = _shown(d.ref(), 160)
    return f"{ref} container {_quoted(c.name, 80)}", ref


#: Flags that mark a container with no `command` as an API server: its own, and k3s/rke2's pass-through.
_APISERVER_HINTS = _APISERVER_FLAGS | {
    "etcd-servers",
    "kube-apiserver-arg",
    "service-account-issuer",
    "service-account-signing-key-file",
    "kubelet-client-certificate",
}


@rule(
    "KN-S038",
    "kube-apiserver allows anonymous requests or authorizes every request",
    Stage.AUDIT,
    "security",
    Severity.CRITICAL,
    "Set --authorization-mode=Node,RBAC (or an AuthorizationConfiguration file without AlwaysAllow), and set "
    "--anonymous-auth=false unless something genuinely needs unauthenticated access; if it does, scope it with "
    "an AuthenticationConfiguration anonymous block limited to the health endpoints.",
    "AlwaysAllow authorizes every request any authenticated client makes, and it is what kube-apiserver uses when "
    "--authorization-mode is not given and no --authorization-config is. Anonymous authentication is on unless "
    "--anonymous-auth=false: unauthenticated requests then become system:anonymous, and RBAC bindings to that "
    "user or to system:unauthenticated (KN-S028) decide what they can do.",
    ("k8s-apiserver-authn-options", "k8s-apiserver-authz-options", "rosa-hcp-architecture"),
    subjects=(ANY_OBJECT,),
)
def _s038(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """The two flags that open the API server to everyone, read where kubeadm writes them: the static pod.

    Three things decide whether a flag says anything. An `--authorization-config` file replaces the
    `--authorization-mode` chain entirely, and an `--authentication-config` file can configure the anonymous
    authenticator itself; neither file is in the input, so the half it governs is declined, not passed. An
    absent flag means the upstream default, which this rule names with the releases it was checked at. And
    AlwaysAllow turns anonymous off (ApplyAuthorization resets it with a warning), so that pair is one finding.

    On the OpenShift family the API server is operator-managed and on ROSA with HCP it is not in the cluster at
    all, so a kube-apiserver container here is declined with that reason rather than read as if a person had
    written its arguments. Every launch shape `_launch` does not read directly is declined; `$(VAR)` anywhere in
    argv and any flag that might swallow another are declined; `--version` and `--help` are not servers; and no
    API server in the input at all is a quiet decline, not a clean result (G272).
    """
    minor = parse_minor(ctx.k8s_version)
    beyond = (
        f" (kube-noob checked the default through Kubernetes {_APISERVER_DEFAULTS_THROUGH[0]}."
        f"{_APISERVER_DEFAULTS_THROUGH[1]}; the target is {ctx.k8s_version})"
        if minor > _APISERVER_DEFAULTS_THROUGH
        else ""
    )
    recognised, written = _config_objects(ctx, r, "kube-apiserver")
    recognised = _unread_lists(ctx, r) or recognised
    yield from written
    for d, _pt, c in _containers(ctx):
        launch = _launch(c.container, "kube-apiserver", _APISERVER_HINTS, None)
        if launch is None:
            continue
        flags: dict[str, list[tuple[str, int]]] = {}
        problem: str | None = None
        exits: bool | str = False
        # `$(NAME)` expanded from a literal env value as the kubelet expands it, `$$` read as a literal `$`,
        # and anything else declined with the name (G272, seventh review).
        tokens, unexpanded = ((), None) if launch.declined else expand_argv(launch.tokens, c.container)
        if not launch.declined and not launch.embedded and unexpanded is None:
            # --version and --help are read only where pflag would read them as flags: `--etcd-prefix --version`
            # gives --etcd-prefix the value, and an ambiguous argv is declined below, not taken as a job (G272).
            flags, problem = _flag_values(tokens, _APISERVER_READ, _APISERVER_BOOLS, False, pflag=True)
            if problem is None:
                exits = _exits_at_once(flags, pflag=True)
                if exits is True:
                    continue
        recognised = True
        where, ref = _where(d, c)
        ctx.looked_at(r.rule_id, ref)
        runs = "may run" if launch.maybe else "runs"
        if ctx.is_openshift:
            ctx.cannot_decide(
                r.rule_id,
                f"{where} {runs} kube-apiserver on {ctx.platform}, where the control plane is operator-managed and "
                "is configured through the platform's own configuration rather than by these arguments (on ROSA "
                "with HCP it runs outside the cluster altogether)",
                ref,
            )
            continue
        if launch.declined:
            starts = "may start" if launch.maybe else "starts"
            ctx.cannot_decide(r.rule_id, f"{where} {starts} kube-apiserver {launch.declined}", ref)
            continue
        if unexpanded:
            ctx.cannot_decide(r.rule_id, f"{where} passes an argument through $(VAR) expansion: {unexpanded}", ref)
            continue
        if launch.embedded:
            # The same decision block as the Rancher config and kubeadm, over the `--kube-apiserver-arg` values
            # in the order GetArgs emits them; the distribution's own defaults are not read and are declined.
            given = _embedded_apiserver_args(launch) or []
            pairs = [
                (flag, value, _argv_path(c, launch.skip, given[i][1]))
                for flag, value, i in k3s_pairs([v for v, _ in given])
            ]
            found, unread, decided = _apiserver_explicit(
                ctx,
                r,
                d,
                pairs,
                f"{where} runs kube-apiserver inside {launch.embedded} server and passes it",
                f"through --{_EMBEDDED_APISERVER_ARG.get(launch.embedded, 'its arguments')}",
            )
            yield from found
            if not decided or unread:
                rest = "; ".join(unread[:3])
                ctx.cannot_decide(
                    r.rule_id,
                    f"{where} runs kube-apiserver inside {launch.embedded} server, which sets the API server's other "
                    f"flags from its own defaults and configuration file, which are not read"
                    f"{'; ' + rest if rest else ''}",
                    ref,
                )
            continue
        if problem or isinstance(exits, str):
            ctx.cannot_decide(r.rule_id, f"{where} {problem or exits}", ref)
            continue
        modes, refused = _refused_authorization(flags)
        if refused:
            ctx.cannot_decide(r.rule_id, f"{where} {refused}", ref)
            continue
        given_anon = flags.get("anonymous-auth", [])
        if given_anon and _go_bool(given_anon[-1][0]) is None:
            ctx.cannot_decide(
                r.rule_id,
                f"{where} sets --anonymous-auth={_quoted(given_anon[-1][0], 60)}, which is not a boolean, so it "
                "does not start",
                ref,
            )
            continue
        skip = launch.skip
        # --- the insecure port: a finding up to a stated 1.19, a decline after (argv.insecure_serving) ---
        target = f"Kubernetes {ctx.k8s_version}" + ("" if ctx.version_stated else ", assumed")
        insecure = insecure_serving(flags, ctx.version_stated, minor, target)
        if insecure is not None and insecure[0] == "decline":
            ctx.cannot_decide(r.rule_id, f"{where} {insecure[1]}", ref)
            continue
        if insecure is not None:
            yield r.finding(
                d,
                _argv_path(c, skip, insecure[2]),
                f"{where} {insecure[1]}: on that port (Kubernetes 1.19 and older) a request is neither "
                "authenticated nor authorized, so anyone who can reach it has the API server as cluster-admin.",
            )
        # --- authorization ---
        always_allow = False
        if _last(flags, "authorization-config"):
            ctx.cannot_decide(
                r.rule_id,
                f"{where} names --authorization-config, which replaces --authorization-mode and is a file on the "
                "node that is not in the input",
                ref,
            )
        else:
            given = flags.get("authorization-mode", [])
            if not modes:
                # Absent, or given empty (`--authorization-mode=`): either way the slice is empty, and upstream's
                # Complete() fills an empty slice with AlwaysAllow when there is no --authorization-config.
                always_allow = True
                said = "sets --authorization-mode to nothing" if given else "does not set --authorization-mode"
                yield r.finding(
                    d,
                    _argv_path(c, skip, given[-1][1]) if given else (*c.path, "command", 0),
                    f"{where} {said} and names no --authorization-config, so it uses the upstream default, "
                    f"AlwaysAllow ({APISERVER_DEFAULTS_CHECKED}){beyond}: every request any authenticated client "
                    "makes is allowed.",
                )
            elif "AlwaysAllow" in modes:
                always_allow = True
                yield r.finding(
                    d,
                    _argv_path(c, skip, given[-1][1]),
                    f"{where} has AlwaysAllow in --authorization-mode ({_quoted(','.join(modes))}): any request no "
                    "earlier authorizer denies is allowed, and RBAC and Node only allow or abstain, so an "
                    "authenticated client can do anything.",
                )
            elif "ABAC" in modes or "Webhook" in modes:
                # An ABAC policy file or an authorization webhook decides from something not in the input, and
                # either can allow every request; the authorizer is declined, anonymous is still read (G272).
                which = " and ".join(m for m in ("ABAC", "Webhook") if m in modes)
                ctx.cannot_decide(
                    r.rule_id,
                    f"{where} authorizes through {which} in --authorization-mode ({_quoted(','.join(modes))}), which "
                    "decides from a policy file or a webhook that is not in the input and can allow every request",
                    ref,
                )
        # --- anonymous authentication (off whenever AlwaysAllow is on: upstream resets it) ---
        if always_allow:
            continue
        if given_anon:
            value, idx = given_anon[-1]
            if _go_bool(value):
                yield r.finding(
                    d,
                    _argv_path(c, skip, idx),
                    f"{where} sets --anonymous-auth=true: a request with no credentials is served as "
                    "system:anonymous in group system:unauthenticated, and what it may do is whatever RBAC grants "
                    "those names.",
                    severity=Severity.MEDIUM,
                )
        elif _last(flags, "authentication-config"):
            ctx.cannot_decide(
                r.rule_id,
                f"{where} names --authentication-config without --anonymous-auth: the file, which is not in the "
                "input, may configure the anonymous authenticator",
                ref,
            )
        else:
            yield r.finding(
                d,
                (*c.path, "command", 0),
                f"{where} does not set --anonymous-auth, so the upstream default applies: {ANONYMOUS_AUTH_DEFAULT} "
                f"({APISERVER_DEFAULTS_CHECKED}){beyond}. A request with no credentials is served as "
                "system:anonymous in group system:unauthenticated.",
                severity=Severity.MEDIUM,
            )
    if not recognised:
        ctx.cannot_decide(r.rule_id)


#: etcd's URL flags, which are listeners or the addresses etcd tells others to use, with their defaults.
_ETCD_CLIENT_URLS = ("listen-client-urls", "listen-client-http-urls", "advertise-client-urls")
_ETCD_PEER_URLS = ("listen-peer-urls", "initial-advertise-peer-urls")
#: Per side: the switch, and the CA file that turns client certificates on by itself. etcd's TLSInfo.ServerConfig
#: requires and verifies a client certificate when EITHER is set (client/pkg/transport/listener.go, v3.5.0 and
#: v3.6.0: `if info.TrustedCAFile != "" || info.ClientCertAuth { cfg.ClientAuth = RequireAndVerifyClientCert }`).
#: With the switch and no CA file, Go verifies the certificate against the system roots: a certificate is still
#: required, so that is not "anyone is accepted".
_ETCD_CERT_SETTINGS = (
    ("client", "client-cert-auth", "trusted-ca-file", Severity.CRITICAL),
    ("peer", "peer-client-cert-auth", "peer-trusted-ca-file", Severity.HIGH),
)
#: Per side: the auto-TLS switch and the certificate pair that overrides it. embed.Config ClientSelfCert and
#: PeerSelfCert (server/embed/config.go, release-3.5): with the switch on and NEITHER file given
#: (TLSInfo.Empty), the TLSInfo is replaced by transport.SelfCert's, which sets neither ClientCertAuth nor
#: TrustedCAFile -- so --client-cert-auth and --trusted-ca-file are dropped and ServerConfig leaves
#: tls.NoClientCert. With either file given etcd logs "ignoring ... auto TLS since certs given" (G272).
_ETCD_AUTO_TLS = {
    "client": ("auto-tls", "cert-file", "key-file"),
    "peer": ("peer-auto-tls", "peer-cert-file", "peer-key-file"),
}
_ETCD_BOOLS = frozenset({"client-cert-auth", "peer-client-cert-auth", "auto-tls", "peer-auto-tls"})
_ETCD_FLAGS = frozenset(
    {
        *_ETCD_URL_DEFAULTS,
        *_ETCD_BOOLS,
        "trusted-ca-file",
        "peer-trusted-ca-file",
        "cert-file",
        "key-file",
        "peer-cert-file",
        "peer-key-file",
        "config-file",
    }
)
_ETCD_READ = _ETCD_FLAGS | {"version", "enable-v2"}


def _etcd_release(image: object) -> tuple[int, int]:
    """(major, minor) from the image tag (`3.5.15-0`, `v3.6.4`), or (99, 0) when the tag does not say."""
    m = re.match(r"v?(\d+)\.(\d+)", _image_tag(image))
    return (int(m.group(1)), int(m.group(2))) if m else (99, 0)


#: Every `fs.BoolVar` etcdmain registers in release-3.5 and in v3.6.4 (server/etcdmain/config.go; 3.6 adds the
#: discovery, tracing, mlock and SAN-verification ones and drops --enable-v2, which `_s039` declines on 3.6), and
#: the ignored legacy flags, whose IgnoredFlag type is a boolean (pkg/flags/ignored.go, IsBoolFlag), so a bare one
#: is read as true rather than as a flag that might swallow the next; Go's flag package never gives a boolean the
#: next token. kubeadm v1.34 ships etcd 3.6.4, older releases 3.5.
_ETCD_KNOWN_BOOLS = frozenset(
    {
        "auto-tls",
        "client-cert-auth",
        "enable-grpc-gateway",
        "enable-log-rotation",
        "enable-pprof",
        "enable-v2",
        "experimental-compact-hash-check-enabled",
        "experimental-enable-distributed-tracing",
        "experimental-enable-lease-checkpoint",
        "experimental-enable-lease-checkpoint-persist",
        "experimental-initial-corrupt-check",
        "experimental-memory-mlock",
        "experimental-peer-skip-client-san-verification",
        "experimental-stop-grpc-service-on-defrag",
        "experimental-txn-mode-write-with-shared-buffer",
        "force-new-cluster",
        "initial-election-tick-advance",
        "peer-auto-tls",
        "peer-client-cert-auth",
        "pre-vote",
        "socket-reuse-address",
        "socket-reuse-port",
        "strict-reconfig-check",
        "unsafe-no-fsync",
        "version",
        # etcd 3.6.4
        "discovery-insecure-skip-tls-verify",
        "discovery-insecure-transport",
        "enable-distributed-tracing",
        "memory-mlock",
        "peer-skip-client-san-verification",
        # ignored legacy flags (IgnoredFlag, a boolean), in both releases
        "cluster-active-size",
        "cluster-remove-delay",
        "cluster-sync-interval",
        "config",
        "force",
        "max-result-buffer",
        "max-retry-attempts",
        "peer-heartbeat-interval",
        "peer-election-timeout",
        "retry-interval",
        "snapshot",
        "v",
        "vv",
    }
)
#: Flags only etcd takes, which mark an unread entrypoint as possibly etcd. Not --config-file, --cert-file or
#: --key-file: half the programs in a cluster take those.
_ETCD_HINTS = frozenset(
    {
        *_ETCD_URL_DEFAULTS,
        "client-cert-auth",
        "peer-client-cert-auth",
        "peer-trusted-ca-file",
        "peer-cert-file",
        "peer-key-file",
        "auto-tls",
        "peer-auto-tls",
        "initial-cluster",
        "initial-cluster-state",
        "initial-cluster-token",
        "etcd-arg",
    }
)


def _etcd_env(name: str) -> str:
    return "ETCD_" + name.upper().replace("-", "_")


@rule(
    "KN-S039",
    "etcd serves clients or peers in plaintext, or without client certificates",
    Stage.AUDIT,
    "security",
    Severity.CRITICAL,
    "Serve etcd only on https:// URLs (loopback http is acceptable), with --client-cert-auth=true, "
    "--peer-client-cert-auth=true and --trusted-ca-file / --peer-trusted-ca-file, as kubeadm writes it.",
    "etcd holds every object in the cluster, every Secret included. A plaintext listener on a network address, or a "
    "TLS listener that accepts any client because client certificates are off (etcd's default), lets anyone who "
    "can reach the port read and write the cluster's state.",
    ("etcd-embed-config", "etcd-flags-env"),
    subjects=(ANY_OBJECT,),
)
def _s039(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """etcd's listeners and client-certificate settings, read from its argv and its ETCD_* environment.

    etcd takes each flag from the command line, else from the matching ETCD_* variable, else its default (a flag
    on the command line shadows the variable: pkg/flags SetFlagsFromEnv). A `--config-file` (or ETCD_CONFIG_FILE)
    replaces all of that, and `envFrom` can set any ETCD_* variable this manifest does not show, so both decline
    the container. Loopback and unix-socket listeners are not findings; the defaults are loopback. A trusted CA
    file turns client certificates on as surely as the switch. One undecidable setting declines that setting and
    keeps what was decided beside it (G272).
    """
    recognised, written = _config_objects(ctx, r, "etcd")
    recognised = _unread_lists(ctx, r) or recognised
    yield from written
    for d, _pt, c in _containers(ctx):
        launch = _launch(c.container, "etcd", _ETCD_HINTS, "ETCD_", frozenset({"config-file"}))
        if launch is None:
            continue
        flags: dict[str, list[tuple[str, int]]] = {}
        problem: str | None = None
        exits: bool | str = False
        tokens, unexpanded = ((), None) if launch.declined else expand_argv(launch.tokens, c.container)
        if not launch.declined and unexpanded is None:
            flags, problem = _flag_values(tokens, _ETCD_READ, _ETCD_KNOWN_BOOLS, single_dash=True)
            if problem is None:
                exits = _exits_at_once(flags, pflag=False)
                if exits is True:
                    continue
        recognised = True
        where, ref = _where(d, c)
        ctx.looked_at(r.rule_id, ref)
        if launch.declined:
            starts = "may start" if launch.maybe else "starts"
            ctx.cannot_decide(r.rule_id, f"{where} {starts} etcd {launch.declined}", ref)
            continue
        if launch.embedded:
            ctx.cannot_decide(
                r.rule_id,
                f"{where} may run etcd inside {launch.embedded} server, which configures it through its own flags "
                "and configuration file, which are not read",
                ref,
            )
            continue
        if isinstance(exits, str):
            ctx.cannot_decide(r.rule_id, f"{where} {exits}", ref)
            continue
        if flags.get("enable-v2") and _etcd_release(c.container.get("image")) >= (3, 6):
            ctx.cannot_decide(
                r.rule_id,
                f"{where} passes --enable-v2, which etcd 3.6 no longer defines and refuses to start with; the image "
                "does not say it is etcd 3.5 or older",
                ref,
            )
            continue
        if unexpanded:
            ctx.cannot_decide(r.rule_id, f"{where} passes an argument through $(VAR) expansion: {unexpanded}", ref)
            continue
        findings, reasons = _etcd_findings(r, d, c, where, tokens, launch.skip, flags, problem)
        for why in reasons:
            ctx.cannot_decide(r.rule_id, f"{where}: {why}", ref)
        yield from findings
    if not recognised:
        ctx.cannot_decide(r.rule_id)


def _etcd_findings(
    r: Rule,
    d: Document,
    c: ContainerRef,
    where: str,
    tokens: tuple[str, ...],
    skip: int,
    flags: dict[str, list[tuple[str, int]]],
    problem: str | None,
) -> tuple[list[Finding], list[str]]:
    """What one etcd container decides, and why it could not decide the rest (``flags`` and ``problem`` are
    `_flag_values` over ``tokens``, already read to tell a server from a `--version` job)."""
    if c.container.get("envFrom"):
        return [], ["envFrom can set any ETCD_* variable, ETCD_CONFIG_FILE included, and is not read"]
    if problem:
        return [], [f"it {problem}"]
    env: dict[str, tuple[Any, int]] = {}
    raw_env = c.container.get("env")
    for i, e in enumerate(raw_env if isinstance(raw_env, list) else []):
        if isinstance(e, dict) and isinstance(e.get("name"), str) and e["name"].startswith("ETCD_"):
            env[e["name"]] = (e, i)  # the last entry of a name is the one the container gets

    def setting(name: str) -> tuple[str | None, PathT | None]:
        """(value, where it was set) -- (None, None) for etcd's default.

        An empty `--config-file=` is not a setting: etcdmain's parse() reads ETCD_CONFIG_FILE when the flag left
        the path empty (release-3.5 and v3.6.4), so that one falls through to the variable (G272)."""
        if flags.get(name) and (flags[name][-1][0] or name != "config-file"):
            value, idx = flags[name][-1]
            return value, _argv_path(c, skip, idx)
        entry = env.get(_etcd_env(name))
        if entry is None:
            return None, None
        e, i = entry
        value = e.get("value", "")
        if "valueFrom" in e or not isinstance(value, str) or "$(" in value:
            raise _Undecidable(
                f"{_etcd_env(name)} is not a plain string value (a reference, a $(VAR) expansion or a non-string), "
                "so its value is not read"
            )
        return (value, (*c.path, "env", i, "value")) if value else (None, None)  # etcd ignores an empty variable

    try:
        config, _ = setting("config-file")
    except _Undecidable as why:
        return [], [str(why)]
    if config:
        return [], ["it is configured from a --config-file, which replaces its flags and is not in the input"]
    out: list[Finding] = []
    reasons: list[str] = []
    exposed: dict[str, bool] = {"client": False, "peer": False}
    for side, names, sev in (
        ("client", _ETCD_CLIENT_URLS, Severity.CRITICAL),
        ("peer", _ETCD_PEER_URLS, Severity.HIGH),
    ):
        for name in names:
            try:
                value, path = setting(name)
                plain, tls = _network_urls(value if value is not None else _ETCD_URL_DEFAULTS[name], name)
            except _Undecidable as why:
                reasons.append(str(why))
                continue
            if tls and name.startswith("listen"):
                exposed[side] = True
            if not plain or path is None:
                continue
            urls = _quoted(", ".join(plain))
            if not name.startswith("listen"):
                said = (
                    "tells its clients to connect in plaintext, so what they read and write, Secrets included, "
                    "crosses the network unencrypted"
                    if side == "client"
                    else "tells its peers to connect to it in plaintext, so the cluster's state, Secrets included, "
                    "is replicated unencrypted"
                )
            elif side == "client":
                said = (
                    "accepts plaintext client connections on a network address, where no client certificate can be "
                    "required: anyone who can reach the port reads and writes the cluster's state, Secrets included"
                )
            else:
                said = (
                    "replicates with its peers in plaintext on a network address, where no peer certificate can be "
                    "required: anyone who can reach the port sees the cluster's state, Secrets included"
                )
            out.append(r.finding(d, path, f"{where} --{name} includes {urls}: etcd {said}.", severity=sev))
    for side, switch, ca, sev in _ETCD_CERT_SETTINGS:
        if not exposed[side]:
            continue  # only loopback, a socket, plaintext (already reported) or an undecided listener
        auto_flag, cert_flag, key_flag = _ETCD_AUTO_TLS[side]
        try:
            value, path = setting(switch)
            ca_value, _ = setting(ca)
            auto_value, auto_path = setting(auto_flag)
            cert_value, _ = setting(cert_flag)
            key_value, _ = setting(key_flag)
        except _Undecidable as why:
            reasons.append(str(why))
            continue
        auto = False if auto_value is None else _go_bool(auto_value)
        if auto is None:
            reasons.append(f"--{auto_flag} is {_quoted(auto_value, 60)}, which is not a boolean")
            continue
        if auto and not cert_value and not key_value:
            out.append(
                r.finding(
                    d,
                    auto_path if auto_path is not None else (*c.path, "command", 0),
                    f"{where} turns on --{auto_flag} with no --{cert_flag} or --{key_flag}, so etcd serves its {side} "
                    f"side with a generated self-signed certificate and drops --{switch} and --{ca} with it "
                    "(embed.Config SelfCert): any "
                    f"{side} that can reach the port is accepted without a certificate.",
                    severity=sev,
                )
            )
            continue
        parsed = False if value is None else _go_bool(value)
        if parsed is None:
            reasons.append(f"--{switch} is {_quoted(value, 60)}, which is not a boolean")
            continue
        if parsed or ca_value:
            continue
        said = f"sets --{switch}=false" if value is not None else f"does not set --{switch} (etcd's default is false)"
        out.append(
            r.finding(
                d,
                path if path is not None else (*c.path, "command", 0),
                f"{where} {said} and names no --{ca}, while its {side} side listens with TLS on a network address: "
                f"any {side} that can reach the port is accepted without a certificate.",
                severity=sev,
            )
        )
    return out, reasons


#: The values of `spec.encryption.type` openshift/api defines. `KMS` is behind the KMSEncryption feature gate,
#: and the API server refuses it where the gate is off, so an object that carries it was admitted with the gate on.
ENCRYPTION_ON = frozenset({"aescbc", "aesgcm", "KMS"})
ENCRYPTION_OFF = frozenset({"", "identity"})
#: What openshift/api lists as encrypted once encryption is on: "the current authoritative list".
ENCRYPTED_RESOURCES = "Secrets, ConfigMaps, Routes, OAuth access tokens and OAuth authorize tokens"


@rule(
    "KN-S040",
    "OpenShift API server does not encrypt resources at rest",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Set spec.encryption.type to aescbc or aesgcm (or KMS where the KMSEncryption feature gate is on) on the "
    "APIServer named 'cluster'. Encryption starts with the next write of each object; the operators migrate the "
    "rest.",
    "spec.encryption.type unset means identity: etcd stores Secrets, ConfigMaps, Routes and OAuth tokens as written, "
    "so anyone with a copy of etcd's data or of an etcd backup reads them directly.",
    ("openshift-api-apiserver-types", "hypershift-hostedcluster-types"),
    subjects=("APIServer",),
)
def _s040(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """Encryption at rest, from the same `APIServer` singleton KN-S035 reads.

    Declines rather than passes in four shapes: the singleton is not in the bundle (on OpenShift it always exists,
    so its absence means it was not collected; declined without a sentence, as KN-S035 is), several are and none
    is named `cluster`, the type is a value openshift/api does not define, and a hosted control plane, whose etcd
    encryption is the `HostedCluster`'s `spec.secretEncryption` on the management cluster rather than anything in
    this object.
    """
    docs = cluster_apiservers(ctx)
    if not ctx.is_openshift:
        _off_openshift(ctx, r, docs)
        return
    if not docs:
        # Not collected: declined without a sentence, exactly as KN-S035 declines, so an audit of an application's
        # manifests on OpenShift is not padded with a note about an object nobody passed. `notEvaluatedRules`
        # still names it.
        ctx.cannot_decide(r.rule_id)
        return
    if ctx.platform in HOSTED_CONTROL_PLANE_PLATFORMS:
        ctx.cannot_decide(
            r.rule_id,
            f"on {ctx.platform} the hosted control plane's etcd encryption is set by the HostedCluster's "
            "spec.secretEncryption on the management cluster, not by the APIServer object in this cluster",
        )
        return
    doc, why = _singleton(docs)
    if doc is None:
        ctx.cannot_decide(r.rule_id, why)
        return
    spec = doc.data.get("spec") if isinstance(doc.data, dict) else None
    enc = spec.get("encryption") if isinstance(spec, dict) else None
    if (spec is not None and not isinstance(spec, dict)) or (enc is not None and not isinstance(enc, dict)):
        ctx.cannot_decide(r.rule_id, f"{_shown(doc.ref(), 160)} has a spec or spec.encryption that is not a mapping")
        return
    raw = enc.get("type") if isinstance(enc, dict) else None
    kind = "" if raw is None else raw
    if not isinstance(kind, str) or (kind not in ENCRYPTION_ON and kind not in ENCRYPTION_OFF):
        ctx.cannot_decide(
            r.rule_id,
            f"{_shown(doc.ref(), 160)} sets spec.encryption.type to {_quoted(raw, 60)}, which openshift/api does "
            "not define "
            f"({', '.join(sorted(ENCRYPTION_ON | {'identity'}))})",
        )
        return
    if kind == "KMS" and not (isinstance(enc, dict) and isinstance(enc.get("kms"), dict) and enc["kms"]):
        # openshift/api: "kms config is required when encryption type is KMS" -- an object the API server
        # refuses says nothing about what the cluster encrypts with.
        ctx.cannot_decide(
            r.rule_id,
            f"{_shown(doc.ref(), 160)} sets spec.encryption.type to KMS with no spec.encryption.kms configuration, "
            "which the API server refuses",
        )
        return
    if kind in ENCRYPTION_ON:
        return
    said = "is identity" if kind == "identity" else "is not set, which openshift/api defines as identity"
    yield r.finding(
        doc,
        ("spec", "encryption", "type") if raw is not None else ("spec",) if isinstance(spec, dict) else ("kind",),
        f"spec.encryption.type {said}: etcd stores {ENCRYPTED_RESOURCES} unencrypted, so a copy of etcd's data or "
        "of an etcd backup is a copy of every Secret in the cluster.",
    )


#: The identity provider types openshift/api defines. Of these only LDAP has a switch that turns transport security
#: off (`insecure`); a missing `ca` everywhere else means the system trust roots, which is verification.
IDENTITY_PROVIDER_TYPES = frozenset(
    {"BasicAuth", "GitHub", "GitLab", "Google", "HTPasswd", "Keystone", "LDAP", "OpenID", "RequestHeader"}
)


@rule(
    "KN-S041",
    "OpenShift LDAP identity provider connects without TLS",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Use an ldaps:// URL, or keep ldap:// with insecure: false so the connection is upgraded with StartTLS, and "
    "name the directory's CA in ca.",
    "An LDAP identity provider with insecure: true and an ldap:// URL talks to the directory in plaintext: the bind "
    "password and every user's password at login cross the network unencrypted, and the directory's identity is "
    "never checked.",
    ("openshift-api-oauth-types", "hypershift-hostedcluster-types"),
    subjects=("OAuth",),
)
def _s041(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """The one identity-provider switch openshift/api defines for turning TLS off.

    `insecure` on an LDAP provider: true with ldap:// is plaintext; ldaps:// always uses TLS whatever `insecure`
    says; false with ldap:// is upgraded with StartTLS. Every other type has no such switch, and a missing `ca`
    means the system roots. A type this list does not know is declined by name, not assumed safe. On a hosted
    control plane the OAuth server is configured from `HostedCluster.spec.configuration.oauth`, so this declines.
    """
    docs = [d for d in ctx.by_kind("OAuth") if d.api_version.split("/", 1)[0] == OAUTH_GROUP]
    if not ctx.is_openshift:
        _off_openshift(ctx, r, docs)
        return
    if not docs:
        ctx.cannot_decide(r.rule_id)  # not collected: the singleton exists on every OpenShift cluster (as KN-S040)
        return
    if ctx.platform in HOSTED_CONTROL_PLANE_PLATFORMS:
        ctx.cannot_decide(
            r.rule_id,
            f"on {ctx.platform} the hosted control plane's OAuth server is configured from the HostedCluster's "
            "spec.configuration.oauth on the management cluster, not from the OAuth object in this cluster",
        )
        return
    doc, why = _singleton(docs)
    if doc is None:
        ctx.cannot_decide(r.rule_id, why)
        return
    ref = _shown(doc.ref(), 160)
    spec = doc.data.get("spec") if isinstance(doc.data, dict) else None
    providers = spec.get("identityProviders") if isinstance(spec, dict) else None
    if providers is None:
        return  # no identity provider, so no connection to secure
    if not isinstance(providers, list):
        ctx.cannot_decide(r.rule_id, f"{ref} spec.identityProviders is not a list")
        return
    for i, p in enumerate(providers):
        if not isinstance(p, dict):
            ctx.cannot_decide(r.rule_id, f"{ref} spec.identityProviders[{i}] is not a mapping")
            continue
        name = _shown(p.get("name") or f"identityProviders[{i}]", 80)
        kind = p.get("type")
        if not isinstance(kind, str) or kind not in IDENTITY_PROVIDER_TYPES:
            ctx.cannot_decide(
                r.rule_id,
                f"{ref} identity provider '{name}' has type {_quoted(kind, 60)}, which openshift/api does not define",
            )
            continue
        if kind != "LDAP":
            continue
        ldap = p.get("ldap")
        insecure = ldap.get("insecure", False) if isinstance(ldap, dict) else None
        url = ldap.get("url") if isinstance(ldap, dict) else None
        problem = (
            "has no ldap mapping"
            if not isinstance(ldap, dict)
            else f"sets ldap.insecure to {_quoted(insecure, 60)}, which is not a boolean"
            if not isinstance(insecure, bool)
            else "has no readable ldap.url"
            if not isinstance(url, str)
            else ""
        )
        if problem or not isinstance(url, str):
            ctx.cannot_decide(r.rule_id, f"{ref} LDAP identity provider '{name}' {problem}")
            continue
        if not insecure:
            continue
        scheme = url.split("://", 1)[0].lower() if "://" in url else ""
        if scheme == "ldaps":
            continue  # ldaps:// always uses TLS, whatever insecure says
        if scheme != "ldap":
            ctx.cannot_decide(
                r.rule_id, f"{ref} LDAP identity provider '{name}' has a URL that is not ldap:// or ldaps://"
            )
            continue
        yield r.finding(
            doc,
            ("spec", "identityProviders", i, "ldap", "insecure"),
            f"Identity provider '{name}' is LDAP with insecure: true and an ldap:// URL, so the OAuth server talks to "
            "the directory in plaintext: the bind password and the password of every user who logs in cross the "
            "network unencrypted, and the directory's identity is never checked.",
        )


# =====================================================================================================
# AUDIT - a name with nothing behind it (G396)
# =====================================================================================================
# The defect this answers: a Pod naming five objects that were not in the input -- a ConfigMap volume, a
# Secret volume, a PersistentVolumeClaim, a ServiceAccount and an `envFrom.configMapRef` -- audited at exit
# 0, with one unrelated LOW finding and no word about any of the five. KN-C013 abstained (`no Secret in the
# input`) because it is about a pull secret in the WRONG namespace, and KN-C015 covers only ResourceClaims,
# so no rule decided it and five absences read as a pass.

#: The kinds this rule checks, which are exactly the namespace-scoped ones a pod spec names where the name
#: having nothing behind it stops the Pod from running:
#:
#:   ConfigMap, Secret              an absent one leaves the container in CreateContainerConfigError (env) or
#:                                  the Pod in ContainerCreating for ever (volume), unless `optional: true`.
#:   PersistentVolumeClaim          an absent one leaves the Pod Pending; the scheduler never binds it.
#:   ServiceAccount                 the ServiceAccount admission plugin REFUSES the Pod outright, so it is
#:                                  never created at all.
#:
#: What is deliberately left out, and why:
#:
#: * **Cluster-scoped referents** -- PriorityClass, RuntimeClass, StorageClass, IngressClass. `cli._partial_input`
#:   takes a directory to be the whole NAMESPACE, never the whole cluster, so a directory of a namespace's
#:   manifests is no evidence at all about a cluster-scoped object: it is normal for a namespace's repository
#:   not to carry the cluster's StorageClasses. Flagging those would be exactly the guess this rule exists to
#:   refuse. (KN-ST001 already reads a claim against a StorageClass that IS in the bundle, and declines
#:   otherwise.)
#: * **`imagePullSecrets`** -- an absent pull secret does not stop the Pod: kubelet reports
#:   FailedToRetrieveImagePullSecret and tries the pull anonymously, which succeeds for a public image. It is
#:   also KN-C013's subject, and two rules on one field would be two answers. KN-C013 owns it.
#: * **A Service named by an Ingress backend, a ServiceAccount named by a RoleBinding subject** -- not a pod
#:   spec, so not this rule's subject. KN-V024, at the end of this module, reads the Ingress backend (G405);
#:   this line used to send it to "KN-V011 and KN-N009", neither of which asks. No rule reads the RoleBinding one.
_DANGLE_KINDS: tuple[str, ...] = ("ConfigMap", "PersistentVolumeClaim", "Secret", "ServiceAccount")

#: How a volume names one: the volume key, the kind, and the field inside it that carries the name. `secret`
#: spells it `secretName` and `persistentVolumeClaim` `claimName`, which is why this is a table and not a
#: loop over `"name"`.
_VOLUME_REFS: tuple[tuple[str, str, str], ...] = (
    ("configMap", "ConfigMap", "name"),
    ("secret", "Secret", "secretName"),
    ("persistentVolumeClaim", "PersistentVolumeClaim", "claimName"),
)
#: The same inside one source of a projected volume, where a Secret says `name` rather than `secretName`.
_PROJECTED_REFS: tuple[tuple[str, str, str], ...] = (("configMap", "ConfigMap", "name"), ("secret", "Secret", "name"))
#: How a container names one: `envFrom[].configMapRef` / `secretRef`, then `env[].valueFrom.*KeyRef`.
_ENVFROM_REFS: tuple[tuple[str, str], ...] = (("configMapRef", "ConfigMap"), ("secretRef", "Secret"))
_ENVVAR_REFS: tuple[tuple[str, str], ...] = (("configMapKeyRef", "ConfigMap"), ("secretKeyRef", "Secret"))


def _required_name(src: Any, field: str) -> str | None:
    """The name this reference carries, or None when there is none to check or the manifest opted out.

    `optional: true` is the API's own escape hatch and the whole reason this cannot be a one-line rule:
    kubelet starts the container WITHOUT the ConfigMap or Secret instead of waiting for it, so an absent
    referent is the declared behaviour there and reporting it would be a finding on a correct manifest. It is
    accepted only as the boolean `true`: `optional: false` and an absent key both mean required.
    """
    if not isinstance(src, dict) or src.get("optional") is True:
        return None
    name = src.get(field)
    return name if isinstance(name, str) and name else None


def _dangling_candidates(pt: PodTemplate) -> Iterator[tuple[str, str, PathT]]:
    """Every (kind, name, path) this pod spec names in its own namespace, with the escape hatches already
    taken out. A candidate, not a finding: whether the namespace defines it is the rule's business."""
    spec = pt.spec
    # `serviceAccount` is the pre-1.9 alias the API still serves and still honours, so a manifest using it
    # dangles exactly the same way; `serviceAccountName` wins when both are set, as the API server does.
    for field in ("serviceAccountName", "serviceAccount"):
        sa = spec.get(field)
        if isinstance(sa, str) and sa:
            # The controller manager creates `default` in every namespace, so naming it is never dangling --
            # and naming nothing selects `default` too, which is why an unset field yields nothing here.
            if sa != "default":
                yield "ServiceAccount", sa, (*pt.path, field)
            break
    volumes = spec.get("volumes")
    if isinstance(volumes, list):
        for i, v in enumerate(volumes):
            if not isinstance(v, dict):
                continue
            for key, kind, field in _VOLUME_REFS:
                name = _required_name(v.get(key), field)
                if name is not None:
                    yield kind, name, (*pt.path, "volumes", i, key, field)
            sources = get_path(v, ("projected", "sources"))
            if not isinstance(sources, list):
                continue
            for j, src in enumerate(sources):
                if not isinstance(src, dict):
                    continue
                for key, kind, field in _PROJECTED_REFS:
                    name = _required_name(src.get(key), field)
                    if name is not None:
                        yield kind, name, (*pt.path, "volumes", i, "projected", "sources", j, key, field)
    for c in containers(pt):
        env_from = c.container.get("envFrom")
        if isinstance(env_from, list):
            for i, item in enumerate(env_from):
                if not isinstance(item, dict):
                    continue
                for key, kind in _ENVFROM_REFS:
                    name = _required_name(item.get(key), "name")
                    if name is not None:
                        yield kind, name, (*c.path, "envFrom", i, key, "name")
        env = c.container.get("env")
        if not isinstance(env, list):
            continue
        for i, item in enumerate(env):
            if not isinstance(item, dict):
                continue
            for key, kind in _ENVVAR_REFS:
                name = _required_name(get_path(item, ("valueFrom", key)), "name")
                if name is not None:
                    yield kind, name, (*c.path, "env", i, "valueFrom", key, "name")


def _generated_claim_names(doc: Document) -> set[str]:
    """The PersistentVolumeClaim names this object's own `volumeClaimTemplates` stand for.

    A StatefulSet's claims are created by the controller as `<template>-<statefulset>-<ordinal>`, so no
    PersistentVolumeClaim of the template's bare name is ever in a bundle and never should be. A template
    name named as a `claimName` is therefore a reference the controller satisfies, not a dangling one, and
    reporting it would be a HIGH finding on a correct StatefulSet.
    """
    templates = get_path(doc.data, ("spec", "volumeClaimTemplates"))
    if not isinstance(templates, list):
        return set()
    out: set[str] = set()
    for t in templates:
        name = get_path(t, ("metadata", "name")) if isinstance(t, dict) else None
        if isinstance(name, str) and name:
            out.add(name)
    return out


@rule(
    "KN-C017",
    "Pod names an object that is not in this namespace",
    Stage.AUDIT,
    "wiring",
    Severity.HIGH,
    "Add the object to this namespace, point the reference at one that is already there, or -- for a ConfigMap "
    "or Secret the container can start without -- set optional: true on the reference.",
    "A pod spec names a ConfigMap, Secret, PersistentVolumeClaim or ServiceAccount in its own namespace. If no "
    "such object exists the Pod never runs: a missing ServiceAccount is refused at admission, a missing claim "
    "leaves it Pending, and a missing ConfigMap or Secret leaves the container in CreateContainerConfigError or "
    "the Pod in ContainerCreating. The failure arrives after the deploy rather than during it. A kind is judged "
    "only where the bundle defines at least one object of it in that namespace: a correct repository often "
    "carries no Secrets (an operator or a person creates them), so a namespace that defines none is not evidence.",
    subjects=(WORKLOAD_SUBJECT,),
    context=_DANGLE_KINDS,
)
def _c017(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if ctx.partial_bundle:
        # A single file cannot tell "this ConfigMap does not exist" from "you did not pass it", and reporting
        # the first would be five findings on the correct repository of every project that keeps its
        # ConfigMaps in another file. Not evaluated, and never clean: the reason says what to pass instead.
        ctx.nothing_to_judge(
            r.rule_id,
            "part of a namespace was passed, so an object that lives in a file you did not pass is not an absent one",
        )
        return
    present: dict[tuple[str, str], set[str]] = {}
    for kind in _DANGLE_KINDS:
        for d in ctx.by_kind(kind):
            if d.name:
                present.setdefault((kind, ctx.ns(d)), set()).add(d.name)
    #: (namespace, kind) pairs a reference needed and the bundle does not MANAGE: no object of that kind there.
    unjudged: dict[str, set[str]] = {}
    for d, pt in ctx.workloads():
        ns = ctx.ns(d)
        generated = _generated_claim_names(d)
        for kind, name, path in _dangling_candidates(pt):
            defined = present.get((kind, ns))
            if defined is None:
                # The first design fired here, and the full suite answered with 98 failures, every one a correct
                # repository (G396). A directory is the whole namespace for what people COMMIT; a correct
                # GitOps repository commits no Secrets -- sealed-secrets, external-secrets, cert-manager or a
                # person create them -- and often no ServiceAccounts or claims. A namespace that defines no
                # object of a kind says nothing about whether one of a given name exists, so the kind is not
                # judged here, and the record says so.
                unjudged.setdefault(ns, set()).add(kind)
                continue
            if name in defined:
                continue
            if kind == "PersistentVolumeClaim" and name in generated:
                continue
            # "nothing in namespace shop defines it" is a statement about the INPUT that an object of that
            # kind and name the rules refused to read makes false (G368, class 24). By kind and name, which
            # is this text's own granularity and no wider.
            if ctx.cannot_judge_absence(r.rule_id, kind, namespace=ns, name=name, suppresses_finding=True):
                continue
            shown = sorted(defined)
            more = f" and {len(shown) - 3} more" if len(shown) > 3 else ""
            # True even where something outside the bundle creates it: the bundle manages this kind here, so
            # the name is most often a typo of one it does define, and those are named for that reader.
            yield r.finding(
                d,
                path,
                f"Pod names the {kind} {name!r}, which nothing in this bundle defines in namespace {ns}, though it "
                f"defines {', '.join(repr(n) for n in shown[:3])}{more} there. Unless something outside this "
                f"bundle creates it, the Pod will not run.",
            )
    if unjudged:
        parts = [f"no {' or '.join(sorted(kinds))} in namespace {ns}" for ns, kinds in sorted(unjudged.items())]
        more = f" and {len(parts) - 3} more namespace(s)" if len(parts) > 3 else ""
        ctx.nothing_to_judge(
            r.rule_id,
            f"the bundle defines {'; '.join(parts[:3])}{more}, so a name a pod spec gives there may be an object "
            "created outside the bundle (a secrets operator, cert-manager, a provisioner, by hand) and its absence "
            "is not evidence",
        )


# =====================================================================================================
# VALIDATE - the edge names a Service that is here (KN-V024, G405)
# =====================================================================================================
# Here for the reason KN-C017 is: `rules.py` has under 2 KiB left under the plugin directory's per-file limit.
#
# An Ingress routes to a Service by NAME, in its own namespace, on a port the Service must serve. No rule read
# that link: KN-N003, KN-N009, KN-N011 and KN-V019 read the Ingress alone, KN-V011 and KN-V012 read the Service
# against its pods, and the comment above KN-C017 that sent this question to "KN-V011 and KN-N009" named two
# rules that do not ask it. So the mechanism walk drew `edge-admits` and `service-selects-pods` as adjacent
# hops with nothing between them, and an Ingress routing to a Service that does not exist -- or to port 9999
# of one that serves 8080 -- walked "A request finds your Pod" complete at exit 0. The request gets a 503.
#
# The discipline is KN-C017's, for the reason G396 learned the hard way:
#
# * A port is judged whenever the Service IS in the input, fragment or not: both objects are in front of the
#   rule, so nothing rests on an absence.
# * A missing Service is judged only where the input is the whole namespace (`partial_bundle` false) AND the
#   namespace defines at least one Service. A fragment cannot show an absence; and a namespace that commits an
#   Ingress and no Service at all has its Services made elsewhere (a chart, an operator), so a name it gives
#   is not evidence either. Both are recorded as nothing to judge, never as clean.
# * A Service of that name the rules refused to read (a Knative `Service`) is not an absent one (G368).
_NOT_A_SERVICE = (
    "an Ingress backend here is not a Service (a `resource` backend, or none), so there is no Service to look for"
)
_FRAGMENT = (
    "part of a namespace was passed, so a Service an Ingress names that is in a file you did not pass is not an "
    "absent one"
)
_NO_SERVICES_THERE = (
    "an Ingress's namespace defines no Service in this input, so a Service it names may be created outside the "
    "bundle and its absence is not evidence"
)
_NO_PORTS = "a Service an Ingress names declares no ports in this input, so the port the Ingress names was not compared"
_NO_PORT_NAMED = "an Ingress backend names no port that can be read (neither a number nor a name)"


def _ingress_backends(doc: Document) -> Iterator[tuple[Any, PathT]]:
    """Every backend this Ingress routes to, with its path: the default backend, then each rule's paths."""
    spec = doc.data.get("spec") if isinstance(doc.data, dict) else None
    if not isinstance(spec, dict):
        return
    if spec.get("defaultBackend") is not None:
        yield spec["defaultBackend"], ("spec", "defaultBackend")
    rules = spec.get("rules")
    if not isinstance(rules, list):
        return
    for i, entry in enumerate(rules):
        paths = get_path(entry, ("http", "paths")) if isinstance(entry, dict) else None
        if not isinstance(paths, list):
            continue
        for j, item in enumerate(paths):
            if isinstance(item, dict):
                yield item.get("backend"), ("spec", "rules", i, "http", "paths", j, "backend")


def _service_ports(services: list[Document]) -> tuple[set[int], set[str]]:
    """The port numbers and port names these Services serve (several only when the bundle repeats a name)."""
    numbers: set[int] = set()
    names: set[str] = set()
    for svc in services:
        ports = get_path(svc.data, ("spec", "ports"))
        for port in ports if isinstance(ports, list) else ():
            if not isinstance(port, dict):
                continue
            if type(port.get("port")) is int:
                numbers.add(port["port"])
            if isinstance(port.get("name"), str) and port["name"]:
                names.add(port["name"])
    return numbers, names


@rule(
    "KN-V024",
    "Ingress routes to a Service that is not in its namespace, or to a port it does not serve",
    Stage.VALIDATE,
    "wiring",
    Severity.MEDIUM,
    "Point the backend at a Service that exists in the Ingress's own namespace, on a port number or port name "
    "that Service declares under spec.ports.",
    "An Ingress backend names a Service in the Ingress's own namespace and one of that Service's ports. If the "
    "Service is not there, or does not serve that port, the controller has nowhere to send the request and "
    "answers 503. The port is judged whenever the Service is in the input. A missing Service is judged only "
    "where a whole namespace was passed and that namespace defines at least one Service: a fragment cannot show "
    "an absence, and a namespace that commits no Service has them made elsewhere.",
    subjects=("Ingress", "Service"),
)
def _v024(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    here: dict[tuple[str, str], list[Document]] = {}
    managed: set[str] = set()
    for svc in ctx.by_kind("Service"):
        managed.add(ctx.ns(svc))
        if svc.name:
            here.setdefault((ctx.ns(svc), svc.name), []).append(svc)
    for ing in ctx.by_kind("Ingress"):
        ns = ctx.ns(ing)
        backends = list(_ingress_backends(ing))
        if not backends:
            ctx.nothing_to_judge(r.rule_id, _NOT_A_SERVICE)
        for backend, path in backends:
            ref = backend.get("service") if isinstance(backend, dict) else None
            name = ref.get("name") if isinstance(ref, dict) else None
            if not isinstance(ref, dict) or not isinstance(name, str) or not name:
                ctx.nothing_to_judge(r.rule_id, _NOT_A_SERVICE)
                continue
            found = here.get((ns, name))
            if not found:
                if ctx.partial_bundle:
                    ctx.nothing_to_judge(r.rule_id, _FRAGMENT)
                elif ns not in managed:
                    ctx.nothing_to_judge(r.rule_id, _NO_SERVICES_THERE)
                elif not ctx.cannot_judge_absence(
                    r.rule_id, "Service", namespace=ns, name=name, suppresses_finding=True
                ):
                    shown = sorted(n for (space, n) in here if space == ns)
                    more = f" and {len(shown) - 3} more" if len(shown) > 3 else ""
                    yield r.finding(
                        ing,
                        (*path, "service", "name"),
                        f"Backend names the Service {name!r}, which nothing in this bundle defines in namespace "
                        f"{ns}, though it defines {', '.join(repr(n) for n in shown[:3])}{more} there. Unless "
                        "something outside this bundle creates it, requests to this backend get a 503.",
                    )
                continue
            port = ref.get("port")
            number = port.get("number") if isinstance(port, dict) else None
            port_name = port.get("name") if isinstance(port, dict) else None
            numbers, names = _service_ports(found)
            if not numbers and not names:
                ctx.nothing_to_judge(r.rule_id, _NO_PORTS)
            elif type(number) is int:
                if number not in numbers:
                    yield r.finding(
                        ing,
                        (*path, "service", "port", "number"),
                        f"Backend names port {number} of the Service {name!r}, which serves "
                        f"{', '.join(str(n) for n in sorted(numbers)) or 'no numbered port'}.",
                    )
            elif isinstance(port_name, str) and port_name:
                if port_name not in names:
                    yield r.finding(
                        ing,
                        (*path, "service", "port", "name"),
                        f"Backend names the port {port_name!r} of the Service {name!r}, whose named ports are "
                        f"{', '.join(repr(n) for n in sorted(names)) or 'none'}.",
                    )
            else:
                ctx.nothing_to_judge(r.rule_id, _NO_PORT_NAMED)
