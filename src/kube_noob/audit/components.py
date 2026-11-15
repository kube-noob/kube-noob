"""The rules that read a cluster's own components rather than a workload: the kubelet (G302) and the trust the
API server places in an admission webhook (G303).

These are `@rule` definitions like every other, registered in `rules.RULES` by importing this module; they live
here only because `rules.py` has to stay under the 256 KiB the Claude plugin directory reads per file, which it
crossed when `KN-S046` was added. `argv.py`, `cpconfig.py` and `cpflags.py` were split out of it for the same
reason; this is the first split that carries rule definitions, so `rules.py` imports it at the END of its own
body, after `rule` and `AuditContext` exist.

The readers are elsewhere again: `audit/kubelet.py` knows the five shapes a kubelet is configured in and the two
upstream default tables that disagree about an absent setting, and `audit/webhookca.py` reads an X.509 validity
window with the standard library alone. Nothing here parses anything.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterator
from typing import Any

from kube_noob.audit.argv import _quoted, _shown
from kube_noob.audit.kubelet import (
    INSECURE_CIPHER_SUITES,
    KUBELET_AUTHORIZATION_MODES,
    KUBELET_DEFAULTS_CHECKED,
    PREFERRED_CIPHER_SUITES,
    KubeletSettings,
    kubelet_sources,
)
from kube_noob.audit.kubelet import read_bool as kubelet_bool
from kube_noob.audit.kubelet import read_duration as kubelet_duration
from kube_noob.audit.kubelet import read_gates as kubelet_gates
from kube_noob.audit.kubelet import read_int as kubelet_int
from kube_noob.audit.kubelet import read_strings as kubelet_strings
from kube_noob.audit.kubelet import resolve as kubelet_resolve
from kube_noob.audit.model import Finding, Severity, Stage
from kube_noob.audit.ownership import owner as component_owner
from kube_noob.audit.rules import AuditContext, Rule, rule
from kube_noob.audit.webhookca import read_bundle as read_ca_bundle
from kube_noob.yamlio import Document, PathT

# =====================================================================================================
# AUDIT - the kubelet (G302)
# =====================================================================================================
# The kubelet is the component a cluster has most copies of and the one nothing in this catalogue read. The
# five shapes a fleet configures it in, and the TWO upstream default tables that disagree about what an absent
# setting means, live in `kube_noob.audit.kubelet`; these rules only decide. Each declines where the shape does
# not state a setting and something not in the input could (a `--config` file, the command line beside a
# configuration object), rather than filling it from a default it did not read (G302).


def _kubelet_sources(ctx: AuditContext, r: Rule) -> list[KubeletSettings]:
    """Every kubelet in the input, with the ones that could not be read already declined and named.

    No kubelet at all is a QUIET decline: "nothing to look at" is not "looked and found it clean", and counting
    it clean would make every application bundle evidence for AC-3 and AC-14 (class 14).
    """
    sources = kubelet_sources(ctx)
    if not sources:
        ctx.cannot_decide(r.rule_id)
        return []
    out: list[KubeletSettings] = []
    for s in sources:
        ctx.looked_at(r.rule_id, s.ref)
        # Whose kubelet this is. A worker kubelet is the customer's on every platform kube-noob knows -- on ROSA
        # through `rosa create kubeletconfig` and a machine pool -- and a control-plane one is not, on any managed
        # platform. A role the object does not state is read as the control plane's there, because assuming the
        # worker role would read Red Hat's own configuration as the customer's (G304).
        own = component_owner(ctx.platform, "kubelet-worker" if s.role == "worker" else "kubelet")
        if not own.theirs:
            stated = "" if s.role else ", and this object does not say which node role it configures"
            ctx.cannot_decide(r.rule_id, f"{s.where} configures a kubelet, and {own.why}{stated}", s.ref)
            continue
        if s.declined:
            ctx.cannot_decide(r.rule_id, f"{s.where} {s.declined}", s.ref)
            continue
        for why in s.unread[:3]:
            ctx.cannot_decide(r.rule_id, f"{s.where} {why}", s.ref)
        out.append(s)
    return out


def _kubelet_value(
    ctx: AuditContext, r: Rule, s: KubeletSettings, setting: str, reader: Callable[[Any], Any]
) -> tuple[str, Any]:
    """("stated"|"default", the parsed value) -- or ("unknown", None) with the decline already recorded.

    A value the kubelet's own parser would refuse means the kubelet does not start, so it is declined with the
    FIELD named and never the value: a decline reason carries no text from the input (G281).
    """
    how, value = kubelet_resolve(s, setting)
    if how == "unknown":
        ctx.cannot_decide(r.rule_id, f"{s.where} does not state {s.flag(setting)}, and {value}", s.ref)
        return "unknown", None
    parsed = reader(value)
    if parsed is None:
        ctx.cannot_decide(
            r.rule_id,
            f"{s.where} sets {s.flag(setting)} to a value the kubelet does not parse, so it does not start",
            s.ref,
        )
        return "unknown", None
    return how, parsed


def _said(s: KubeletSettings, setting: str, how: str) -> str:
    """How a message introduces the value: what the object says, or the upstream default for its shape."""
    if how == "stated":
        return f"{s.where} sets {s.flag(setting)}"
    table = "the kubelet's command-line defaults" if s.defaults == "argv" else "a KubeletConfiguration's defaults"
    return f"{s.where} does not state {s.flag(setting)}, so {table} apply ({KUBELET_DEFAULTS_CHECKED})"


@rule(
    "KN-S042",
    "kubelet accepts requests it does not authenticate",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Set authentication.anonymous.enabled to false, authentication.x509.clientCAFile to the cluster CA, and "
    "readOnlyPort to 0 (--anonymous-auth=false, --client-ca-file and --read-only-port=0 on the command line).",
    "The kubelet serves every pod's logs, exec and running state on port 10250. With anonymous authentication "
    "on, a request with no credentials is served as system:anonymous; with no client CA file it cannot "
    "authenticate a certificate at all, so the only identity left is a bearer token the API server vouches "
    "for; and the read-only port serves the node's pods, specs and metrics with no authentication and no "
    "authorization whatsoever. The command line and a KubeletConfiguration file have OPPOSITE defaults for the "
    "first and third of those, so which shape wrote the setting decides what an absent one means.",
    ("k8s-kubelet-authn-authz", "k8s-kubelet-config"),
)
def _s042(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for s in _kubelet_sources(ctx, r):
        how, anonymous = _kubelet_value(ctx, r, s, "anonymousAuth", kubelet_bool)
        if how != "unknown" and anonymous:
            yield r.finding(
                s.doc,
                s.path("anonymousAuth") or ("kind",),
                f"{_said(s, 'anonymousAuth', how)} to true: a request to the kubelet with no credentials is served "
                "as system:anonymous in group system:unauthenticated, and what it may read or run on the node is "
                "whatever the kubelet's authorizer allows those names.",
            )
        how, ca = _kubelet_value(ctx, r, s, "clientCAFile", lambda v: v if isinstance(v, str) else None)
        if how != "unknown" and not ca.strip():
            yield r.finding(
                s.doc,
                s.path("clientCAFile") or ("kind",),
                f"{_said(s, 'clientCAFile', how)} to a certificate authority, so the kubelet authenticates no "
                "client certificate at all: x509 authentication is off and only bearer tokens remain.",
                severity=Severity.MEDIUM,
            )
        how, port = _kubelet_value(ctx, r, s, "readOnlyPort", kubelet_int)
        if how != "unknown" and port != 0:
            yield r.finding(
                s.doc,
                s.path("readOnlyPort") or ("kind",),
                f"{_said(s, 'readOnlyPort', how)} to {port}, a read-only port that serves the node's pods, their "
                "specs and its metrics with no authentication and no authorization: anyone who can reach the node "
                "on that port can enumerate every workload on it.",
            )


@rule(
    "KN-S043",
    "kubelet authorizes every request it authenticates",
    Stage.AUDIT,
    "security",
    Severity.CRITICAL,
    "Set authorization.mode to Webhook (--authorization-mode=Webhook), so the API server's "
    "SubjectAccessReview decides what each caller may do on the node.",
    "AlwaysAllow is the kubelet's COMMAND-LINE default and it allows every request the kubelet authenticated, "
    "so one accepted credential -- including an anonymous one (KN-S042) -- can read any pod's logs and exec "
    "into any container on the node. A KubeletConfiguration file defaults to Webhook instead, which asks the "
    "API server, so an absent setting means the opposite thing in the two shapes.",
    ("k8s-kubelet-authn-authz", "k8s-kubelet-config"),
)
def _s043(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for s in _kubelet_sources(ctx, r):
        how, mode = _kubelet_value(
            ctx,
            r,
            s,
            "authorizationMode",
            lambda v: v if isinstance(v, str) and v in KUBELET_AUTHORIZATION_MODES else None,
        )
        if how == "unknown" or mode != "AlwaysAllow":
            continue
        yield r.finding(
            s.doc,
            s.path("authorizationMode") or ("kind",),
            f"{_said(s, 'authorizationMode', how)} to AlwaysAllow: every request the kubelet authenticates is "
            "allowed, so one credential it accepts can read any pod's logs and exec into any container on this "
            "node, whatever RBAC says.",
        )


@rule(
    "KN-S044",
    "kubelet node protections are turned off",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Set protectKernelDefaults and makeIPTablesUtilChains to true, leave streamingConnectionIdleTimeout at a "
    "non-zero duration, and leave eventRecordQPS above 0.",
    "Four settings the kubelet uses to protect the node it runs on. With protectKernelDefaults false the "
    "kubelet overwrites kernel tunables instead of refusing to start on a node that disagrees with it; with "
    "makeIPTablesUtilChains false it stops maintaining the iptables chains Services rely on; a zero "
    "streamingConnectionIdleTimeout leaves exec and port-forward connections open forever; and a zero "
    "eventRecordQPS removes the rate limit on event creation, so one node can flood the API server.",
    ("k8s-kubelet-config",),
)
def _s044(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for s in _kubelet_sources(ctx, r):
        for setting, wanted, why in (
            (
                "protectKernelDefaults",
                True,
                "the kubelet overwrites the node's kernel tunables to its own values instead of refusing to start "
                "on a node configured differently, so a node's hardening is silently undone",
            ),
            (
                "makeIPTablesUtilChains",
                True,
                "the kubelet stops maintaining the iptables utility chains, so the rules Services and kube-proxy "
                "depend on are left to whatever else writes them",
            ),
        ):
            how, value = _kubelet_value(ctx, r, s, setting, kubelet_bool)
            if how != "unknown" and value is not wanted:
                yield r.finding(
                    s.doc,
                    s.path(setting) or ("kind",),
                    f"{_said(s, setting, how)} to {str(value).lower()}: {why}.",
                )
        how, idle = _kubelet_value(ctx, r, s, "streamingConnectionIdleTimeout", kubelet_duration)
        if how != "unknown" and idle == 0:
            yield r.finding(
                s.doc,
                s.path("streamingConnectionIdleTimeout") or ("kind",),
                f"{_said(s, 'streamingConnectionIdleTimeout', how)} to 0, which the kubelet reads as no timeout: an "
                "exec, attach or port-forward connection stays open until something else closes it.",
            )
        how, qps = _kubelet_value(ctx, r, s, "eventRecordQPS", kubelet_int)
        if how != "unknown" and qps == 0:
            yield r.finding(
                s.doc,
                s.path("eventRecordQPS") or ("kind",),
                f"{_said(s, 'eventRecordQPS', how)} to 0, which the kubelet reads as no limit: this node can create "
                "events as fast as it likes, and the API server's own storage is what runs out.",
            )


@rule(
    "KN-S045",
    "kubelet serving TLS is weak or its certificate is never rotated",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Set serverTLSBootstrap and rotateCertificates to true, leave the RotateKubeletServerCertificate feature "
    "gate on, and list only cipher suites from crypto/tls CipherSuites() in tlsCipherSuites.",
    "The kubelet serves exec, logs and the node's whole running state over TLS. Without serverTLSBootstrap it "
    "serves a self-signed certificate nothing in the cluster verifies and never replaces it; without "
    "rotateCertificates its CLIENT certificate to the API server expires instead of being renewed; and a "
    "tlsCipherSuites list drawn from Go's InsecureCipherSuites() offers RC4, 3DES, CBC-SHA1 or a key exchange "
    "with no forward secrecy to anything that asks for it.",
    ("k8s-kubelet-config", "go-cipher-suites"),
)
def _s045(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for s in _kubelet_sources(ctx, r):
        how, suites = _kubelet_value(
            ctx,
            r,
            s,
            "tlsCipherSuites",
            lambda v: (
                names
                if (names := kubelet_strings(v)) is not None
                and all(n in INSECURE_CIPHER_SUITES or n in PREFERRED_CIPHER_SUITES for n in names)
                else None
            ),
        )
        if how != "unknown":
            weak = [n for n in suites if n in INSECURE_CIPHER_SUITES]
            if weak:
                yield r.finding(
                    s.doc,
                    s.path("tlsCipherSuites") or ("kind",),
                    f"{_said(s, 'tlsCipherSuites', how)} to a list that includes {_quoted(', '.join(sorted(weak)))}, "
                    "which Go's own crypto/tls marks insecure (InsecureCipherSuites at go1.27.4): the kubelet offers "
                    "them to anything that connects to it.",
                )
        for setting, what in (
            (
                "serverTLSBootstrap",
                "the kubelet serves a self-signed certificate that nothing in the cluster verifies and that it "
                "never replaces, so a client cannot tell this kubelet from anything else answering on its address",
            ),
            (
                "rotateCertificates",
                "the kubelet's client certificate to the API server is never renewed, so the node drops out of the "
                "cluster when it expires instead of bootstrapping a new one",
            ),
        ):
            how, value = _kubelet_value(ctx, r, s, setting, kubelet_bool)
            if how != "unknown" and value is False:
                yield r.finding(
                    s.doc,
                    s.path(setting) or ("kind",),
                    f"{_said(s, setting, how)} to false: {what}.",
                    severity=Severity.MEDIUM if setting == "rotateCertificates" else Severity.HIGH,
                )
        if not s.stated("featureGates"):
            continue
        gates = kubelet_gates(s.values["featureGates"][0])
        if gates is None:
            ctx.cannot_decide(
                r.rule_id,
                f"{s.where} sets {s.flag('featureGates')} in a shape the kubelet does not decode, so which gates "
                "are on was not read",
                s.ref,
            )
            continue
        if gates.get("RotateKubeletServerCertificate") is False:
            yield r.finding(
                s.doc,
                s.path("featureGates"),
                f"{s.where} turns the RotateKubeletServerCertificate feature gate off, which has been on by default "
                "since Kubernetes 1.12: the kubelet cannot request a serving certificate from the CSR API however "
                "serverTLSBootstrap is set, so it serves a self-signed one.",
                severity=Severity.HIGH,
            )


# =====================================================================================================
# AUDIT - the trust the API server places in an admission webhook (G303)
# =====================================================================================================
# `KN-S030` already reports `failurePolicy: Ignore`, which decides what happens when a webhook cannot be
# reached; this rule is about the bundle that decides WHETHER it can be reached, and does not repeat it.

#: Annotations whose controller writes `clientConfig.caBundle` at runtime: OpenShift's service CA operator and
#: cert-manager's CA injector. With one of these the value in the manifest is not the value the API server uses,
#: in either direction, so the rule declines rather than reporting an absent or stale bundle (G303).
CA_BUNDLE_INJECTORS = (
    "service.beta.openshift.io/inject-cabundle",
    "cert-manager.io/inject-ca-from",
    "cert-manager.io/inject-ca-from-secret",
    "cert-manager.io/inject-apiserver-ca",
)
#: The group the two webhook configuration kinds are served in. A kind of either name in any other group is a
#: different resource (class 3).
ADMISSION_GROUP = "admissionregistration.k8s.io"


@rule(
    "KN-S046",
    "Admission webhook CA bundle is missing or not a certificate the API server can use",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Put the PEM certificate of the authority that signed the webhook's serving certificate in "
    "clientConfig.caBundle, base64-encoded; or let a controller fill it (annotate the configuration with "
    'service.beta.openshift.io/inject-cabundle: "true" on OpenShift, or cert-manager.io/inject-ca-from).',
    "clientConfig.caBundle is the only thing that tells the API server which authority to verify the webhook's "
    "serving certificate against. A bundle that is empty, not base64, not a PEM certificate, expired or not yet "
    "valid is worse than an absent one, because the manifest looks configured while every call to the webhook "
    "fails the same way: the check the cluster believes it has is not running, and failurePolicy (KN-S030) "
    "decides whether that shows up as an outage or as silence. With no bundle at all the API server verifies "
    "against the system trust roots on its own host, which no in-cluster Service certificate is signed by.",
    ("k8s-admission-webhook-failure-policy", "k8s-apiservice-types"),
)
def _s046(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """Every webhook of every ValidatingWebhookConfiguration and MutatingWebhookConfiguration in the input.

    The X.509 reading is `kube_noob.audit.webhookca`, which is the standard library and nothing else. Its one
    limit is that OpenSSL hands back only the certificates it would keep as trust anchors, so a block it did not
    return is DECLINED as a certificate whose validity window was not read -- never counted as a bundle holding
    no certificate, and never allowed to hide the blocks that WERE read (class 15, class 24).
    """
    now = int(dt.datetime.now(dt.UTC).timestamp())
    seen = False
    for d in ctx.by_kind("ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"):
        if d.api_version.split("/", 1)[0] != ADMISSION_GROUP:
            continue
        seen = True
        ref = _shown(d.ref(), 160)
        ctx.looked_at(r.rule_id, ref)
        annotations = (d.data.get("metadata") or {}).get("annotations") if isinstance(d.data, dict) else None
        injector = (
            next((a for a in CA_BUNDLE_INJECTORS if a in annotations), "") if isinstance(annotations, dict) else ""
        )
        if injector:
            ctx.cannot_decide(
                r.rule_id,
                f"{ref} carries an annotation whose controller injects clientConfig.caBundle at runtime, so the "
                "value in the manifest is not the one the API server uses",
                ref,
            )
            continue
        hooks = d.data.get("webhooks") if isinstance(d.data, dict) else None
        if not isinstance(hooks, list):
            ctx.cannot_decide(
                r.rule_id,
                f"{ref} has no webhooks list, which the API server does not accept, so what it configures was not read",
                ref,
            )
            continue
        for i, hook in enumerate(hooks):
            if not isinstance(hook, dict):
                ctx.cannot_decide(
                    r.rule_id, f"{ref} has a webhooks entry that is not a mapping, so it was not read", ref
                )
                continue
            name = _quoted(hook.get("name") or f"webhooks[{i}]", 120)
            config = hook.get("clientConfig")
            if not isinstance(config, dict):
                what = "no clientConfig mapping" if config is None else "a clientConfig that is not a mapping"
                ctx.cannot_decide(
                    r.rule_id,
                    f"{ref} webhook {name} has {what}, which the API server does not accept, so where it sends "
                    "requests was not read",
                    ref,
                )
                continue
            yield from _ca_bundle(ctx, r, d, i, ref, name, config, now)
    if not seen:
        ctx.cannot_decide(r.rule_id)


def _ca_bundle(
    ctx: AuditContext,
    r: Rule,
    d: Document,
    i: int,
    ref: str,
    name: str,
    config: dict[str, Any],
    now: int,
) -> Iterator[Finding]:
    path: PathT = ("webhooks", i, "clientConfig", "caBundle")
    if "caBundle" not in config:
        if not isinstance(config.get("service"), dict):
            return  # a webhook at a URL may legitimately hold a publicly trusted certificate
        yield r.finding(
            d,
            ("webhooks", i, "clientConfig"),
            f"{ref} webhook {name} sends requests to a Service in the cluster and names no caBundle, so the API "
            "server verifies that Service's certificate against the system trust roots on its own host, which no "
            "in-cluster serving certificate is signed by: every call to this webhook fails.",
            severity=Severity.MEDIUM,
        )
        return
    bundle = read_ca_bundle(config["caBundle"])
    if bundle.problem:
        yield r.finding(
            d,
            path,
            f"{ref} webhook {name} has a clientConfig.caBundle that {bundle.problem}: the API server cannot build "
            "a trust pool from it, so every call to this webhook fails while the manifest looks configured.",
        )
        return
    for window in bundle.windows:
        subject = _quoted(window.subject or "<no common name>", 120)
        if window.not_after <= now:
            yield r.finding(
                d,
                path,
                f"{ref} webhook {name} has a clientConfig.caBundle whose certificate {subject} expired: the API "
                "server will not verify the webhook's serving certificate against an expired authority, so every "
                "call to this webhook fails.",
            )
        elif window.not_before > now:
            yield r.finding(
                d,
                path,
                f"{ref} webhook {name} has a clientConfig.caBundle whose certificate {subject} is not valid until "
                "a date in the future, so the API server cannot use it yet and every call to this webhook fails "
                "until then.",
            )
    if bundle.unread:
        # OpenSSL returned fewer certificates than the field holds blocks -- a leaf certificate is the usual
        # reason. Saying "no certificate" there would be an absence reading as an answer (class 1).
        ctx.cannot_decide(
            r.rule_id,
            f"{ref} webhook {name} has a clientConfig.caBundle holding a certificate kube-noob read as PEM and "
            "DER but whose validity window it did not read, because the standard library returns a window only "
            "for a certificate it would keep as a trust anchor",
            ref,
        )
