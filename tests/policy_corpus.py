"""Seeded random manifests for the policy/audit equivalence test: every field the generated policies read, with the
values that sit on either side of each rule (missing, empty, case variants, zero, the boundary)."""

from __future__ import annotations

import copy
import random
from typing import Any

IMAGES = (
    "quay.io/acme/web@sha256:" + "a" * 64,
    "quay.io/acme/web:1.2.3",
    "quay.io/acme/web:latest",
    "quay.io/acme/web",
    "registry.local:5000/team/app",
    "registry.local:5000/team/app:v2",
    "app:latest@sha256:" + "b" * 64,
    "app:v1@sha256:short",
    "app:x:latest",
    "nginx:",
    "",
    # ingress-nginx controller releases on either side of the fixed versions (KN-S024), and tags the rule cannot read
    "registry.k8s.io/ingress-nginx/controller:v1.11.4@sha256:" + "c" * 64,
    "registry.k8s.io/ingress-nginx/controller:v1.12.0",
    "registry.k8s.io/ingress-nginx/controller-chroot:v1.13.8",
    "registry.k8s.io/ingress-nginx/controller:v1.15.1@sha256:" + "d" * 64,
    "registry.k8s.io/ingress-nginx/controller:latest",
    "quay.io/mirror/ingress-nginx/controller:1.16.0",
    "quay.io/acme/controller:v1.11.4",
)
CAPS_ADD = ([], ["NET_BIND_SERVICE"], ["net_bind_service"], ["CAP_NET_BIND_SERVICE"], ["SYS_ADMIN"], ["CHOWN"], ["ALL"])
CAPS_DROP = (None, [], ["ALL"], ["all"], ["NET_RAW"], ["NET_RAW", "ALL"])
SECCOMP = (None, "RuntimeDefault", "Localhost", "Unconfined")
LOCALHOST_PROFILES = (None, "", "  ", "profiles/app.json")
SYSCTLS = (
    None,
    None,
    [],
    [{"name": "net.core.somaxconn", "value": "1024"}],
    [{"name": "kernel.shm_rmid_forced=1+kernel.core_pattern", "value": "1"}],
    [{"name": "net.ipv4.ip_forward", "value": "1+0"}],
    [{"name": "fs.x", "value": "a=b"}],
    [{"name": "fs.y"}],
)
WORKDIRS = ("/app", "/proc/self/fd/7", "/proc", "/procs", " /proc/1 ", "/opt/proc")
# subPath values on either side of KN-S025 (CVE-2023-3676): plain relative paths and shell or PowerShell syntax.
SUBPATHS = (
    None,
    "logs",
    "logs/app",
    "plain-name_1.txt",
    "logs$(Start-Process cmd)",
    "a;b",
    "x`y",
    "it's",
    'q"x',
    "a|b",
    "a&b",
    "out>f",
    "line\nbreak",
    "data (old)",
)
VOLUMES = (
    {"name": "v", "hostPath": {"path": "/var/log"}},
    {"name": "v", "hostPath": {"path": "/var/run/docker.sock"}},
    {"name": "v", "emptyDir": {}},
    {"name": "v", "emptyDir": {}},
    {"name": "v", "gitRepo": {"repository": "https://github.com/acme/app.git", "directory": ".git"}},
    {"name": "v", "gitRepo": {"repository": "/srv/git/app"}},
)
ENV = (
    [],
    [{"name": "LOG_LEVEL", "value": "info"}],
    [{"name": "DB_PASSWORD", "value": "hunter2"}],
    [{"name": "db_password", "value": "$(DB_PASSWORD)"}],
    [{"name": "API_KEY", "value": "   "}],
    [{"name": "API_KEY", "value": "<redacted>"}],
    [{"name": "DATABASE_URL", "value": "postgres://app:s3cr3t@db:5432/app"}],
    [{"name": "AWS", "value": "AKIA" + "ABCDEFGHIJKLMNOP"}],
    [{"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "t", "key": "t"}}}],
    [{"name": "JWT", "value": "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2Q"}],
)
ARGS = (
    None,
    ["--port=8080"],
    ["--password=hunter2"],
    ["--password=$(PASS)"],
    ["--db-token:abc"],
    ["--password-file=/run/secrets/p"],
    ["serve", "--api-key=   "],
    ["-token=***"],
    ["--url=https://u:p@host/"],
)
KINDS = ("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob")


def _maybe(rng: random.Random, value: Any, p: float = 0.5) -> Any:
    return value if rng.random() < p else None


def _set(d: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        d[key] = value


def _sc(rng: random.Random, container: bool) -> dict[str, Any] | None:
    if rng.random() < 0.12:
        return None
    sc: dict[str, Any] = {}
    _set(sc, "runAsUser", _maybe(rng, rng.choice((0, 1000, 1001)), 0.4))
    _set(sc, "runAsNonRoot", _maybe(rng, rng.choice((True, False)), 0.6))
    _set(sc, "fsGroup", None if container else _maybe(rng, rng.choice((0, 2000)), 0.3))
    profile = rng.choice(SECCOMP)
    if profile is not None:
        sc["seccompProfile"] = {"type": profile}
        if profile == "Localhost":
            lp = rng.choice(LOCALHOST_PROFILES)
            if lp is not None:
                sc["seccompProfile"]["localhostProfile"] = lp
    if not container:
        sysctls = rng.choice(SYSCTLS)
        if sysctls is not None:
            sc["sysctls"] = copy.deepcopy(sysctls)
    if container:
        _set(sc, "privileged", _maybe(rng, rng.choice((True, False)), 0.3))
        _set(sc, "allowPrivilegeEscalation", _maybe(rng, rng.choice((True, False)), 0.7))
        _set(sc, "readOnlyRootFilesystem", _maybe(rng, rng.choice((True, False)), 0.7))
        _set(sc, "procMount", _maybe(rng, rng.choice(("Default", "Unmasked")), 0.2))
        caps: dict[str, Any] = {}
        add = rng.choice(CAPS_ADD)
        if add:
            caps["add"] = add
        drop = rng.choice(CAPS_DROP)
        if drop is not None:
            caps["drop"] = drop
        if caps or rng.random() < 0.2:
            sc["capabilities"] = caps
    return sc


# A `host` on a probe or lifecycle handler (KEP-4940's `probeHost`), which KN-S029 reports and its generated
# policy refuses. Without these the corpus never produced one, so the parity between the rule and its CEL was
# asserted over 900 objects that could not tell the two apart.
PROBE_HOSTS: tuple[str | None, ...] = (None, None, None, None, "127.0.0.1", "10.0.0.1", "metadata.internal")


def _handler(rng: random.Random) -> dict[str, Any]:
    """An httpGet or tcpSocket handler, sometimes with a host on it."""
    h: dict[str, Any] = (
        {"httpGet": {"path": "/healthz", "port": 8080}} if rng.random() < 0.8 else {"tcpSocket": {"port": 8080}}
    )
    inner = next(iter(h.values()))
    _set(inner, "host", rng.choice(PROBE_HOSTS))
    return h


def _probe(rng: random.Random) -> dict[str, Any] | None:
    if rng.random() < 0.3:
        return None
    p: dict[str, Any] = _handler(rng)
    _set(p, "periodSeconds", _maybe(rng, rng.choice((1, 4, 5, 10, 30)), 0.6))
    _set(p, "failureThreshold", _maybe(rng, rng.choice((1, 2, 3)), 0.6))
    _set(p, "timeoutSeconds", _maybe(rng, rng.choice((1, 5, 10, 30)), 0.5))
    return p


def _lifecycle(rng: random.Random) -> dict[str, Any] | None:
    """A lifecycle hook, which KEP-4940 covers as well as the three probes."""
    if rng.random() < 0.85:
        return None
    return {rng.choice(("preStop", "postStart")): _handler(rng)}


def _resources(rng: random.Random) -> dict[str, Any] | None:
    if rng.random() < 0.15:
        return None
    r: dict[str, Any] = {}
    req = {k: v for k, v in (("cpu", "100m"), ("memory", "128Mi")) if rng.random() < 0.8}
    if req or rng.random() < 0.2:
        r["requests"] = req
    if rng.random() < 0.75:
        r["limits"] = {"memory": "256Mi"} if rng.random() < 0.85 else {"cpu": "1"}
    return r


def _container(rng: random.Random, name: str, app: bool) -> dict[str, Any]:
    c: dict[str, Any] = {"name": name}
    image = rng.choice(IMAGES)
    if image or rng.random() < 0.5:
        c["image"] = image
    _set(c, "securityContext", _sc(rng, True))
    _set(c, "resources", _resources(rng))
    _set(c, "workingDir", _maybe(rng, rng.choice(WORKDIRS), 0.3))
    env = rng.choice(ENV)
    if env:
        c["env"] = copy.deepcopy(env)
    args = rng.choice(ARGS)
    if args is not None:
        c[rng.choice(("args", "command"))] = list(args)
    if rng.random() < 0.3:
        c["ports"] = [{"containerPort": 8080, **({"hostPort": rng.choice((0, 80))} if rng.random() < 0.5 else {})}]
    if rng.random() < 0.35:
        mount: dict[str, Any] = {"name": "v", "mountPath": "/data"}
        _set(mount, "subPath", rng.choice(SUBPATHS))
        c["volumeMounts"] = [mount]
    if app:
        _set(c, "readinessProbe", _probe(rng))
        _set(c, "livenessProbe", _probe(rng))
        _set(c, "startupProbe", _maybe(rng, _probe(rng), 0.85))
    # Not gated on `app`: an init container's handler reaches the kubelet exactly the same way, and `_s029`
    # walks init and ephemeral containers too.
    _set(c, "lifecycle", _lifecycle(rng))
    return c


def pod_spec(rng: random.Random) -> dict[str, Any]:
    spec: dict[str, Any] = {"containers": [_container(rng, f"app{i}", True) for i in range(rng.choice((1, 1, 2)))]}
    if rng.random() < 0.25:
        spec["initContainers"] = [_container(rng, "init", False)]
    _set(spec, "securityContext", _sc(rng, False))
    for f in ("hostNetwork", "hostPID", "hostIPC"):
        _set(spec, f, _maybe(rng, rng.choice((True, False)), 0.12))
    _set(spec, "automountServiceAccountToken", _maybe(rng, rng.choice((True, False)), 0.6))
    _set(spec, "terminationGracePeriodSeconds", _maybe(rng, rng.choice((0, 30)), 0.3))
    if rng.random() < 0.35:
        spec["volumes"] = [copy.deepcopy(rng.choice(VOLUMES))]
    if rng.random() < 0.3:
        spec["topologySpreadConstraints"] = [
            {"maxSkew": 1, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "ScheduleAnyway"}
        ]
    elif rng.random() < 0.2:
        spec["affinity"] = {
            "podAntiAffinity": {
                "preferredDuringSchedulingIgnoredDuringExecution": [
                    {"weight": 1, "podAffinityTerm": {"topologyKey": "kubernetes.io/hostname"}}
                ]
            }
        }
    return spec


def workload(rng: random.Random, i: int, kinds: tuple[str, ...] = KINDS) -> dict[str, Any]:
    kind = rng.choice(kinds)
    meta = {"name": f"w{i}", "namespace": "shop"}
    labels = {"app": f"w{i}"}
    spec = pod_spec(rng)
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": kind, "metadata": {**meta, "labels": labels}, "spec": spec}
    template = {"metadata": {"labels": labels}, "spec": spec}
    api = {"ReplicationController": "v1", "Job": "batch/v1", "CronJob": "batch/v1"}.get(kind, "apps/v1")
    if kind == "DeploymentConfig":
        api = "apps.openshift.io/v1"
    if kind == "CronJob":
        body: dict[str, Any] = {"schedule": "*/5 * * * *", "jobTemplate": {"spec": {"template": template}}}
    elif kind in {"Job", "DaemonSet"}:
        body = {"template": template}
    else:
        body = {
            "selector": {"matchLabels": labels} if kind != "ReplicationController" else labels,
            "template": template,
        }
        if kind == "DeploymentConfig":
            body["selector"] = labels
        replicas = rng.choice((None, 0, 1, 2, 3))
        if replicas is not None:
            body["replicas"] = replicas
    return {"apiVersion": api, "kind": kind, "metadata": meta, "spec": body}


def rbac(rng: random.Random, i: int) -> dict[str, Any]:
    verbs = (
        ["get", "list"],
        ["*"],
        ["create"],
        ["escalate"],
        ["bind"],
        ["patch"],
        ["update"],
        ["watch"],
        ["impersonate"],
    )
    resources = (
        ["pods"],
        ["*"],
        ["secrets"],
        ["pods/exec"],
        ["pods/attach"],
        ["nodes/proxy"],
        ["deployments"],
        ["cronjobs"],
        ["pods/ephemeralcontainers"],
        ["persistentvolumes"],
        ["configmaps"],
        ["controllerrevisions"],
        ["statefulsets", "controllerrevisions"],
    )
    kind = rng.choice(("Role", "ClusterRole"))
    rules = []
    for _ in range(rng.choice((1, 1, 2))):
        r: dict[str, Any] = {"apiGroups": rng.choice(([""], ["apps"], ["*"])), "resources": list(rng.choice(resources))}
        r["verbs"] = list(rng.choice(verbs))
        rules.append(r)
    meta: dict[str, Any] = {"name": f"role-{i}"}
    if kind == "Role":
        meta["namespace"] = "shop"
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind, "metadata": meta, "rules": rules}


def binding(rng: random.Random, i: int) -> dict[str, Any]:
    kind = rng.choice(("RoleBinding", "ClusterRoleBinding"))
    meta: dict[str, Any] = {"name": f"b-{i}"}
    if kind == "RoleBinding":
        meta["namespace"] = "shop"
    role = rng.choice(("cluster-admin", "view", "edit"))
    # KN-S028: subjects that are everyone of a kind, look-alikes, and the built-in bindings' label
    subject = rng.choice(
        (
            {"kind": "ServiceAccount", "name": "web", "namespace": "shop"},
            {"kind": "ServiceAccount", "name": "web", "namespace": "shop"},
            {"kind": "Group", "name": "system:unauthenticated"},
            {"kind": "Group", "name": "system:authenticated"},
            {"kind": "Group", "name": "system:serviceaccounts"},
            {"kind": "Group", "name": "system:serviceaccounts:shop"},
            {"kind": "Group", "name": "system:authenticated:oauth"},
            {"kind": "User", "name": "system:anonymous"},
            {"kind": "Group", "name": "system:anonymous"},
            {"kind": "User", "name": "system:authenticated"},
        )
    )
    if rng.random() < 0.15:
        meta["labels"] = {"kubernetes.io/bootstrapping": rng.choice(("rbac-defaults", "other"))}
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": meta,
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role},
        "subjects": [{"kind": "ServiceAccount", "name": "ci", "namespace": "shop"}, copy.deepcopy(subject)],
    }


def service(rng: random.Random, i: int) -> dict[str, Any]:
    spec: dict[str, Any] = {"selector": {"app": "web"}, "ports": [{"port": 443}]}
    _set(spec, "type", rng.choice((None, "ClusterIP", "NodePort", "LoadBalancer", "LoadBalancer")))
    ranges = rng.choice((None, [], ["203.0.113.0/24"], ["0.0.0.0/0"], [" ::/0 "]))
    if ranges is not None:
        spec["loadBalancerSourceRanges"] = ranges
    ips = rng.choice((None, None, [], ["203.0.113.10"], ["203.0.113.10", "198.51.100.7"]))
    if ips is not None:
        spec["externalIPs"] = ips
    meta: dict[str, Any] = {"name": f"s{i}", "namespace": "shop"}
    ann = rng.choice(
        (
            None,
            {"service.beta.kubernetes.io/aws-load-balancer-internal": "true"},
            {"service.beta.kubernetes.io/aws-load-balancer-internal": " TRUE "},
            {"service.beta.kubernetes.io/aws-load-balancer-internal": "false"},
            {"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"},
            {"networking.gke.io/load-balancer-type": "Internal"},
            {"other": "x"},
        )
    )
    if ann is not None:
        meta["annotations"] = ann
    return {"apiVersion": "v1", "kind": "Service", "metadata": meta, "spec": spec}


def route(rng: random.Random, i: int) -> dict[str, Any]:
    spec: dict[str, Any] = {"to": {"kind": "Service", "name": "web"}}
    if rng.random() < 0.8:
        tls: dict[str, Any] = {}
        _set(tls, "termination", rng.choice((None, "edge", "passthrough", "reencrypt", "edge-ish")))
        _set(tls, "insecureEdgeTerminationPolicy", rng.choice((None, "", "None", "Redirect", "Allow", "Bogus")))
        _set(tls, "certificate", rng.choice((None, None, "", "-----BEGIN CERTIFICATE-----")))
        spec["tls"] = tls
    return {
        "apiVersion": "route.openshift.io/v1",
        "kind": "Route",
        "metadata": {"name": f"r{i}", "namespace": "shop"},
        "spec": spec,
    }


INGRESS_ANNOTATIONS = (
    None,
    {},
    {"nginx.ingress.kubernetes.io/configuration-snippet": "more_set_headers x;"},
    {"nginx.ingress.kubernetes.io/auth-url": "http://auth.shop.svc/verify"},
    {"nginx.ingress.kubernetes.io/rewrite-target": "/"},
    {"nginx.ingress.kubernetes.io/ssl-redirect": "true"},
    {"kubernetes.io/ingress.class": "nginx"},
    {"kubernetes.io/ingress.class": " nginx "},
    {"kubernetes.io/ingress.class": "haproxy"},
    {"other": "x"},
)


def ingress(rng: random.Random, i: int) -> dict[str, Any]:
    rule: dict[str, Any] = {"host": "web.example.com"}
    if rng.random() < 0.7:  # KN-N011: the path types, one or two paths
        backend = {"service": {"name": "web", "port": {"number": 80}}}
        rule["http"] = {
            "paths": [
                {
                    "path": "/x",
                    "pathType": rng.choice(("Prefix", "Exact", "ImplementationSpecific")),
                    "backend": backend,
                }
                for _ in range(rng.choice((1, 2)))
            ]
        }
    spec: dict[str, Any] = {"rules": [rule]}
    tls = rng.choice((None, [], [{"hosts": ["web.example.com"], "secretName": "t"}]))
    if tls is not None:
        spec["tls"] = tls
    _set(spec, "ingressClassName", _maybe(rng, rng.choice(("nginx", "openshift-default", " nginx", "Nginx")), 0.5))
    meta: dict[str, Any] = {"name": f"i{i}", "namespace": "shop"}
    ann = rng.choice(INGRESS_ANNOTATIONS)
    if ann is not None:
        meta["annotations"] = dict(ann)
    return {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": meta, "spec": spec}


def configmap(rng: random.Random, i: int) -> dict[str, Any]:
    data = rng.choice(
        (
            None,
            {},
            {"allow-snippet-annotations": "true"},
            {"allow-snippet-annotations": "false"},
            {"allow-snippet-annotations": " True "},
            {"annotations-risk-level": "Critical"},
            {"annotations-risk-level": "High"},
            {"strict-validate-path-type": "false"},
            {"strict-validate-path-type": "true"},
            {"use-forwarded-headers": "true"},
            # KN-S026: credentials and their look-alikes
            {"DB_PASSWORD": "hunter2"},
            {"db_password": "$(DB_PASSWORD)"},
            {"redis.password": "  "},
            {"api-key": "<redacted>"},
            {"client_secret": "abc123"},
            {"tls-secret": "web-tls"},
            {"token-ttl": "30m"},
            {"GITHUB_TOKEN": "ghp_x"},
            {"DATABASE_URL": "postgres://app:s3cr3t@db:5432/app"},
            {"app.properties": "db.url=jdbc:x\ndb.password=hunter2\n"},
            {"app.properties": "db.password=${DB_PASSWORD}\npassword.min-length=12\n"},
            {"app.yaml": 'auth:\n  "token": "abc"\n'},
            {"app.yaml": "auth:\n  token: ''\n"},
            {"env": "export API_KEY=xyz\nLOG=1\n"},
            {"key.pem": "-----BEGIN RSA PRIVATE KEY-----\nMII\n"},
        )
    )
    doc: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": f"cm{i}", "namespace": "ingress-nginx"},
    }
    if data is not None:
        doc["data"] = dict(data)
    return doc


def secret(rng: random.Random, i: int) -> dict[str, Any]:
    """KN-S027: legacy ServiceAccount token Secrets among the other types (never with data)."""
    doc: dict[str, Any] = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": f"sec{i}", "namespace": "shop"}}
    kind = rng.choice(
        (
            None,
            "Opaque",
            "kubernetes.io/service-account-token",
            "kubernetes.io/service-account-token",
            "kubernetes.io/dockerconfigjson",
            "kubernetes.io/tls",
            "kubernetes.io/basic-auth",
        )
    )
    if kind is not None:
        doc["type"] = kind
    if kind == "kubernetes.io/service-account-token":
        doc["metadata"]["annotations"] = {"kubernetes.io/service-account.name": "ci"}
    return doc


def persistent_volume(rng: random.Random, i: int) -> dict[str, Any]:
    """KN-ST006: local paths and NFS/SMB CSI volume handles on either side of the signatures."""
    spec: dict[str, Any] = {"capacity": {"storage": "1Gi"}, "accessModes": ["ReadWriteOnce"]}
    if rng.random() < 0.5:
        spec["local"] = {
            "path": rng.choice(("/mnt/disks/ssd1", "C:\\data\\app", "/mnt/a;b", "/mnt/$(x)", "/mnt/it's", "/mnt/a b"))
        }
    else:
        csi: dict[str, Any] = {
            "driver": rng.choice(("nfs.csi.k8s.io", "smb.csi.k8s.io", "ebs.csi.aws.com")),
            "volumeHandle": rng.choice(
                (
                    "srv/share#app#",
                    "srv/share#legit/../../exports#",
                    "srv/share#..#",
                    "srv/share#a..b#",
                    "vol-0123",
                    "srv\\share#..\\x#",
                )
            ),
        }
        sub = rng.choice((None, "app", "../etc", "a/..", "a..b", "x/../y"))
        if sub is not None:
            csi["volumeAttributes"] = {"server": "srv", "subDir": sub}
        spec["csi"] = csi
    return {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": f"pv{i}"}, "spec": spec}


def netpol(rng: random.Random, i: int) -> dict[str, Any]:
    peers = (
        {"podSelector": {"matchLabels": {"app": "front"}}},
        {"namespaceSelector": {}},
        {"namespaceSelector": {}, "podSelector": {}},
        {"namespaceSelector": {}, "podSelector": {"matchLabels": {"app": "x"}}},
        {"namespaceSelector": {"matchLabels": {"team": "a"}}},
        {"ipBlock": {"cidr": "0.0.0.0/0"}},
        {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}},
        {"ipBlock": {"cidr": "10.0.0.0/8"}},
    )
    ingress_rules = []
    for _ in range(rng.choice((0, 1, 2))):
        r: dict[str, Any] = {}
        if rng.random() < 0.7:
            r["from"] = [copy.deepcopy(rng.choice(peers)) for _ in range(rng.choice((0, 1, 2)))]
        if rng.random() < 0.4:
            r["ports"] = [{"port": 8080}]
        ingress_rules.append(r)
    spec: dict[str, Any] = {"podSelector": {}}
    if ingress_rules or rng.random() < 0.5:
        spec["ingress"] = ingress_rules
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": f"n{i}", "namespace": "shop"},
        "spec": spec,
    }


def egress_firewall(rng: random.Random, i: int) -> dict[str, Any]:
    rules = (
        {"type": "Allow", "to": {"dnsName": "api.example.com"}},
        {"type": "Deny", "to": {"cidrSelector": "0.0.0.0/0"}},
        {"type": "Deny", "to": {"cidrSelector": "::/0"}},
        {"type": "Deny", "to": {"cidrSelector": "0.0.0.0/0"}, "ports": [{"protocol": "TCP", "port": 25}]},
        {"type": "Allow", "to": {"cidrSelector": "10.0.0.0/8"}},
    )
    egress = [copy.deepcopy(rng.choice(rules)) for _ in range(rng.choice((0, 1, 2, 3)))]
    name = rng.choice(("default", "default", "egress"))
    return {
        "apiVersion": "k8s.ovn.org/v1",
        "kind": "EgressFirewall",
        "metadata": {"name": name, "namespace": "shop"},
        "spec": {"egress": egress},
    }


def scc(rng: random.Random, i: int) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "apiVersion": "security.openshift.io/v1",
        "kind": "SecurityContextConstraints",
        "metadata": {"name": f"scc{i}"},
    }
    for f in (
        "allowPrivilegedContainer",
        "allowHostNetwork",
        "allowHostPID",
        "allowHostIPC",
        "allowHostDirVolumePlugin",
        "allowHostPorts",
        "allowPrivilegeEscalation",
    ):
        _set(doc, f, _maybe(rng, rng.random() < 0.2, 0.5))
    doc["runAsUser"] = {"type": rng.choice(("MustRunAsRange", "RunAsAny", "MustRunAsNonRoot"))}
    return doc


def storage_class(rng: random.Random, i: int) -> dict[str, Any]:
    prov = rng.choice(
        ("ebs.csi.aws.com", "efs.csi.aws.com", "disk.csi.azure.com", "topolvm.io", "kubernetes.io/aws-ebs")
    )
    doc: dict[str, Any] = {
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": {"name": f"sc{i}"},
        "provisioner": prov,
    }
    _set(doc, "volumeBindingMode", rng.choice((None, "Immediate", "WaitForFirstConsumer")))
    params = rng.choice(
        (
            None,
            {},
            {"provisioningMode": "efs-ap"},
            {"provisioningMode": "efs-ap", "fileSystemId": "fs-1"},
            {"provisioningMode": "", "fileSystemId": "fs-1"},
        )
    )
    if params is not None:
        doc["parameters"] = params
    return doc


def pdb(rng: random.Random, i: int) -> dict[str, Any]:
    spec: dict[str, Any] = {"selector": {"matchLabels": {"app": "w"}}}
    choice = rng.choice(
        (
            ("maxUnavailable", 0),
            ("maxUnavailable", 1),
            ("maxUnavailable", "0%"),
            ("maxUnavailable", "25%"),
            ("minAvailable", "100%"),
            ("minAvailable", 1),
            ("minAvailable", "50%"),
            ("minAvailable", 2),
        )
    )
    spec[choice[0]] = choice[1]
    return {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {"name": f"p{i}", "namespace": "shop"},
        "spec": spec,
    }


def machine_config(rng: random.Random, i: int) -> dict[str, Any]:
    kind = rng.choice(("MachineConfig", "MachineConfigPool"))
    return {
        "apiVersion": "machineconfiguration.openshift.io/v1",
        "kind": kind,
        "metadata": {"name": f"99-mc-{i}"},
        "spec": {},
    }


def apiservice(rng: random.Random, i: int) -> dict[str, Any]:
    """KN-S037: local and remote APIServices, with and without the flag, with and without a caBundle."""
    spec: dict[str, Any] = {
        "group": f"g{i}.example.com",
        "version": "v1",
        "groupPriorityMinimum": 100,
        "versionPriority": 10,
    }
    if rng.random() < 0.75:
        spec["service"] = {"name": f"ext{i}", "namespace": "ext", "port": rng.choice((443, 8443))}
    flag = rng.choice((None, None, True, False))
    if flag is not None:
        spec["insecureSkipTLSVerify"] = flag
    if rng.random() < 0.3 and flag is not True:
        spec["caBundle"] = "LS0tLS1CRUdJTg=="
    return {
        "apiVersion": "apiregistration.k8s.io/v1",
        "kind": "APIService",
        "metadata": {"name": f"v1.g{i}"},
        "spec": spec,
    }


def corpus(seed: int, n: int, openshift: bool) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    makers = [rbac, binding, service, ingress, netpol, storage_class, pdb, configmap, secret, persistent_volume]
    if openshift:
        makers += [route, egress_firewall, scc, machine_config]
    kinds = (*KINDS, "DeploymentConfig") if openshift else KINDS
    out: list[dict[str, Any]] = []
    for i in range(n):
        if rng.random() < 0.6:
            out.append(workload(rng, i, kinds))
        else:
            out.append(rng.choice(makers)(rng, i))
    # Kinds added after the corpus was first seeded draw from their own generator, so every object above is the
    # same one it always was and no existing rule's cross-check moved.
    extra = random.Random(seed + 37)
    out.extend(apiservice(extra, n + i) for i in range(max(n // 20, 8)))
    return out
