"""Step 7 - Red Team: hostile-auditor scenarios evaluated against the whole bundle.

Each scenario answers one adversarial question ("what happens if a worker node dies mid-operation?") with a verdict,
the evidence (finding ids / objects), blast radius, safeguards and the commands that verify the safeguard in a cluster.
"""

from __future__ import annotations

from collections.abc import Callable

from kube_noob.audit.model import Finding, RedTeamScenario, Severity
from kube_noob.audit.podspec import REPLICATED_KINDS, replicas
from kube_noob.audit.rules import AuditContext
from kube_noob.yamlio import get_path

ScenarioFn = Callable[[AuditContext, list[Finding]], RedTeamScenario | None]


def _ids(findings: list[Finding], *rule_ids: str) -> list[Finding]:
    return [f for f in findings if f.rule_id in rule_ids]


def _evidence(fs: list[Finding], limit: int = 8) -> list[str]:
    out = [f"{f.rule_id} {f.resource}{(' ' + f.path) if f.path else ''}: {f.message}" for f in fs[:limit]]
    if len(fs) > limit:
        out.append(f"... and {len(fs) - limit} more")
    return out


def _verdict(fs: list[Finding]) -> tuple[str, Severity]:
    if not fs:
        return "mitigated", Severity.INFO
    return "exposed", max(f.severity for f in fs)


def node_crash(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    if not any(d.kind in REPLICATED_KINDS for d in ctx.docs):
        return None
    fs = _ids(findings, "KN-C007", "KN-C008", "KN-C010", "KN-ST002", "KN-C001")
    verdict, sev = _verdict(fs)
    return RedTeamScenario(
        "RT-NODE-CRASH",
        "What happens if a worker node crashes mid-operation?",
        verdict,
        sev,
        _evidence(fs),
        "Single-replica or co-located workloads go down until rescheduled (~5 min default eviction for unreachable "
        "nodes); RWO volumes stay attached to the dead node and block replacement pods (Multi-Attach) until the "
        "attachment times out.",
        [
            "replicas >= 2 (3 for production) with topologySpreadConstraints across zones and hostnames",
            "PodDisruptionBudget maxUnavailable: 1",
            "StatefulSet + volumeClaimTemplates (or RWX storage) instead of a shared RWO claim",
            "readinessProbe so traffic shifts only to healthy replicas",
        ],
        [
            "oc get pods -o wide -l <app-label>   # replicas on distinct nodes/zones",
            "oc adm drain <node> --ignore-daemonsets --delete-emptydir-data --dry-run=server",
            "oc get pdb -n <ns>",
        ],
    )


def zone_outage(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    if not any(d.kind in REPLICATED_KINDS for d in ctx.docs):
        return None
    fs = _ids(findings, "KN-C010", "KN-ST003")
    zonal_sts = [
        d
        for d in ctx.by_kind("StatefulSet")
        if any(
            "ReadWriteOnce" in (get_path(v, ("spec", "accessModes")) or [])
            for v in get_path(d.data, ("spec", "volumeClaimTemplates")) or []
            if isinstance(v, dict)
        )
    ]
    verdict, sev = _verdict(fs)
    evidence = _evidence(fs)
    if zonal_sts and ctx.platform in {"rosa-classic", "rosa-hcp"}:
        evidence.append(
            f"{', '.join(d.ref() for d in zonal_sts)}: EBS-backed RWO volumes are zonal; pods pinned to a lost AZ "
            "cannot move until the zone returns."
        )
        verdict, sev = "exposed", max(sev, Severity.MEDIUM)
    return RedTeamScenario(
        "RT-ZONE-OUTAGE",
        "What happens if an entire availability zone fails?",
        verdict,
        sev,
        evidence,
        "Replicas concentrated in one zone all fail together; zonal block volumes cannot follow pods to another zone.",
        [
            "topologySpreadConstraints on topology.kubernetes.io/zone with maxSkew: 1",
            "StorageClass volumeBindingMode: WaitForFirstConsumer",
            "application-level replication for stateful services (do not rely on a single zonal volume)",
        ],
        [
            "oc get pods -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName -l <app-label>",
            "oc get nodes -L topology.kubernetes.io/zone",
        ],
    )


def rwx_split_brain(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    shared: list[str] = []
    pvc_modes = {
        (d.namespace or "", d.name): get_path(d.data, ("spec", "accessModes")) or []
        for d in ctx.by_kind("PersistentVolumeClaim")
    }
    for d, pt in ctx.workloads():
        if (replicas(d) or 1) < 2:
            continue
        for v in pt.spec.get("volumes") or []:
            claim = get_path(v, ("persistentVolumeClaim", "claimName")) if isinstance(v, dict) else None
            if claim and "ReadWriteMany" in pvc_modes.get((d.namespace or "", str(claim)), []):
                shared.append(f"{d.ref()} ({replicas(d)} replicas) writes to RWX claim '{claim}'")
    fs = _ids(findings, "KN-ST001")
    if not shared and not fs:
        return None
    evidence = shared + _evidence(fs)
    return RedTeamScenario(
        "RT-RWX-SPLIT-BRAIN",
        "Does this ReadWriteMany volume cause split-brain, locking or corruption?",
        "exposed",
        Severity.HIGH if fs else Severity.MEDIUM,
        evidence,
        "RWX only guarantees that several pods can mount the volume. Concurrent writers need application-level "
        "coordination: embedded databases (SQLite, BoltDB, H2, Lucene indexes) on NFS/EFS/CephFS can corrupt or "
        "deadlock; NFS advisory locks are not honoured by every library. Without a valid RWX class the PVC never "
        "binds at all.",
        [
            "confirm the application supports multiple concurrent writers (or elect a single writer via a Lease)",
            "never put embedded databases on shared file storage; use a StatefulSet with per-replica RWO volumes",
            "use a real RWX class (efs-sc on ROSA, ocs-storagecluster-cephfs on ODF)",
        ],
        ["oc get pvc -n <ns> -o wide", "oc describe pvc <claim> -n <ns>   # look for ProvisioningFailed"],
    )


def exposure(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    if not ctx.by_kind("Route", "Ingress", "Service", "Gateway", "HTTPRoute"):
        return None
    fs = _ids(
        findings,
        "KN-N002",
        "KN-N003",
        "KN-N004",
        "KN-N005",
        "KN-N001",
        "KN-N007",
        "KN-N008",
        "KN-N009",
        "KN-N010",
        "KN-N011",
        "KN-N012",
    )
    verdict, sev = _verdict(fs)
    return RedTeamScenario(
        "RT-EXPOSURE",
        "Is there an exposed route, insecure ingress path or open lateral-movement path?",
        verdict,
        sev,
        _evidence(fs),
        "Plain-HTTP routes leak credentials; public load balancers and NodePorts expose services to the internet; "
        "missing NetworkPolicies let any compromised pod reach this workload.",
        [
            "Route tls.termination edge/reencrypt with insecureEdgeTerminationPolicy: Redirect",
            "default-deny NetworkPolicy + allow from the ingress router namespace only",
            "internal load balancers / loadBalancerSourceRanges",
        ],
        [
            "oc get routes -A -o custom-columns=NAME:.metadata.name,TLS:.spec.tls.termination,"
            "INSECURE:.spec.tls.insecureEdgeTerminationPolicy",
            "oc get networkpolicy -n <ns>",
            "curl -sv http://<route-host>/   # must redirect to https",
        ],
    )


def privilege_escalation(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    fs = _ids(
        findings,
        "KN-S001",
        "KN-S005",
        "KN-S009",
        "KN-S010",
        "KN-S015",
        "KN-S016",
        "KN-S017",
        "KN-S019",
        "KN-S020",
        "KN-S021",
        "KN-S022",
        "KN-S023",
        "KN-S025",
        "KN-S028",
        "KN-ST006",
        "KN-S002",
        "KN-S003",
        # The control plane itself: an API server that authorizes everything, and an etcd anyone can reach, are
        # the cluster takeover this scenario is about, one step shorter (G272).
        "KN-S038",
        "KN-S039",
    )
    fs = [f for f in fs if f.severity >= Severity.MEDIUM]
    if not ctx.docs:
        return None
    verdict, sev = _verdict(fs)
    return RedTeamScenario(
        "RT-PRIVESC",
        "If an attacker gets code execution in this pod, can they escalate to the node or the cluster?",
        verdict,
        sev,
        _evidence(fs),
        "Privileged containers, host namespaces/paths, dangerous capabilities and broad RBAC each turn a single "
        "compromised pod into node or cluster takeover.",
        [
            "Pod Security 'restricted' (restricted-v2 SCC on OpenShift)",
            "automountServiceAccountToken: false; least-privilege Roles without wildcards",
            "RHACS/StackRox deploy-time enforcement of the matching default policies",
        ],
        [
            "oc auth can-i --list --as=system:serviceaccount:<ns>:<sa>",
            "oc get pod <pod> -o jsonpath='{.metadata.annotations.openshift\\.io/scc}'",
        ],
    )


def upgrade_block(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    if not ctx.by_kind("PodDisruptionBudget"):
        return None
    fs = _ids(findings, "KN-C009")
    verdict, sev = _verdict(fs)
    return RedTeamScenario(
        "RT-UPGRADE-BLOCK",
        "Will this stall a cluster upgrade or node drain?",
        verdict,
        sev,
        _evidence(fs),
        "A PDB that permits zero disruptions makes `drain` wait forever; OpenShift/ROSA upgrades roll nodes one by "
        "one and stop at this node.",
        ["maxUnavailable: 1 with replicas >= 2", "monitor PodDisruptionBudgetAtLimit alerts"],
        [
            "oc get pdb -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,"
            "ALLOWED:.status.disruptionsAllowed"
        ],
    )


def secret_leak(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    fs = _ids(findings, "KN-S013", "KN-S018", "KN-S026", "KN-S027", "KN-S014")
    fs = [f for f in fs if f.severity >= Severity.LOW]
    if not fs:
        return None
    verdict, sev = _verdict(fs)
    return RedTeamScenario(
        "RT-SECRET-LEAK",
        "Can secrets leak through manifests, Git history, env dumps or mounted tokens?",
        verdict,
        sev,
        _evidence(fs),
        "Literal credentials end up in Git, CI logs and `oc get -o yaml`; mounted SA tokens give API access to any "
        "attacker with RCE.",
        [
            "secretKeyRef / external secret store",
            "automountServiceAccountToken: false",
            "rotate any credential that was ever committed",
        ],
        [
            "git log -p | grep -iE 'password|token|secret'   # audit history",
            "oc set env deployment/<name> --list -n <ns>",
        ],
    )


def resource_starvation(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    fs = _ids(findings, "KN-C004", "KN-C005", "KN-C006", "KN-C003", "KN-C014")
    if not any(True for _ in ctx.workloads()):
        return None
    verdict, sev = _verdict(fs)
    return RedTeamScenario(
        "RT-RESOURCE-STARVATION",
        "Can a traffic spike or memory leak take down neighbours or trigger restart storms?",
        verdict,
        sev,
        _evidence(fs),
        "Unbounded memory triggers node OOM kills of unrelated pods; BestEffort pods are evicted first; aggressive "
        "liveness probes amplify slowness into restarts; a manifest that sets spec.replicas under an HPA scales the "
        "workload back down on every apply, peak or not.",
        [
            "requests + memory limits on every container",
            "namespace LimitRange and ResourceQuota",
            "liveness checks only the process; failureThreshold >= 3",
            "no spec.replicas on a workload an HPA scales; minReplicas sets the floor",
        ],
        ["oc adm top pods -n <ns>", "oc get events -n <ns> --field-selector reason=OOMKilling"],
    )


def supply_chain(ctx: AuditContext, findings: list[Finding]) -> RedTeamScenario | None:
    fs = [f for f in _ids(findings, "KN-S012") if f.severity >= Severity.MEDIUM]
    if not any(True for _ in ctx.workloads()):
        return None
    verdict, sev = _verdict(fs)
    return RedTeamScenario(
        "RT-SUPPLY-CHAIN",
        "Could a different (malicious or broken) image run than the one that was reviewed?",
        verdict,
        sev,
        _evidence(fs),
        "Mutable tags can be re-pushed; rollbacks become non-deterministic and scans/signatures no longer apply to "
        "what runs.",
        [
            "pin images by digest",
            "verify signatures (sigstore/cosign) via admission policy",
            "RHACS 'Latest tag' and image-signature policies in enforce mode",
        ],
        ["oc get pods -n <ns> -o jsonpath='{range .items[*]}{.status.containerStatuses[*].imageID}{\"\\n\"}{end}'"],
    )


SCENARIOS: tuple[ScenarioFn, ...] = (
    node_crash,
    zone_outage,
    rwx_split_brain,
    exposure,
    privilege_escalation,
    upgrade_block,
    secret_leak,
    resource_starvation,
    supply_chain,
)


def red_team(ctx: AuditContext, findings: list[Finding]) -> list[RedTeamScenario]:
    out: list[RedTeamScenario] = []
    for fn in SCENARIOS:
        s = fn(ctx, findings)
        if s is not None:
            out.append(s)
    return out
