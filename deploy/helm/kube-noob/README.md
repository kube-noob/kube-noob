# kube-noob Helm chart

Runs kube-noob as a token-protected MCP service on OpenShift 4.20 and later or Kubernetes 1.33 and later. kube-noob
has no AI inside: OpenShift Lightspeed, Claude or any MCP client calls its tools (audit, diagnose, cited docs,
learning), and it calls no model itself.

## Install

```bash
helm install kube-noob oci://ghcr.io/kube-noob/charts/kube-noob -n kube-noob --create-namespace
```

The chart generates a random bearer token in the Secret `<release>-kube-noob-token` and keeps it across
`helm upgrade`. To bring your own, create a Secret with the key `token` and set `auth.existingSecret`; do this with
`helm template` or GitOps (Argo CD, Flux), where the chart cannot look the Secret up and would rotate the token.
Clients connect to `http://<release>-kube-noob.<namespace>.svc:8080/mcp` with `Authorization: Bearer <token>`.

## Secure by default

- Pods are written for `restricted-v2` (arbitrary UID, no capabilities, `RuntimeDefault` seccomp, read-only root
  filesystem). The Pod Security `restricted` half is enforced in CI; `restricted-v2` is an OpenShift SCC and
  every CI cluster is kind, so that half is the pod spec meeting the SCC's requirements rather than an SCC
  admitting it -- [docs/roadmap.md](https://github.com/aashishmahajan/kube-noob/blob/main/docs/roadmap.md) tracks
  the OpenShift cluster that would close it.
- NetworkPolicy: ingress only from the same namespace and the OpenShift router; egress to DNS only.
- No web access, no cluster access and no model calls unless you turn them on.
- The admission webhook is off unless you set `admission.enabled`, and denies nothing unless you list a rule in
  `admission.enforce`.

## Main values

| Value | Default | Effect |
|---|---|---|
| `auth.existingSecret` | `""` | Your token Secret; empty generates one |
| `config.offline` | `false` | Admin lock: no web, no downloads, local models only |
| `config.webEnabled` | `false` | HTTPS GET to allowlisted documentation domains; opens egress 443 |
| `config.clusterEnabled` | `false` | Read-only cluster tools (never Secrets), including the attack-path scan, which reads RBAC objects (Roles and RoleBindings; ClusterRoles and ClusterRoleBindings with `rbac.scope: cluster`); needs `networkPolicy.egress.apiServerCIDRs` |
| `posture.report.enabled`, `.keep` | `false`, `14` | A daily drift and policy report (read-only snapshot of hashes and names, compared with yesterday's) on the PVC; the MCP tool `posture_report` returns the newest. Needs `config.clusterEnabled`, `persistence.enabled` and `replicaCount: 1` |
| `alertReports.store`, `.maxReports`, `.maxAgeDays`, `.maxReportBytes` | `true`, `200`, `14`, `1048576` | Evidence reports for Alertmanager payloads posted to `POST /v1/alert-reports`, kept owner-only in `<dataDir>/alert-reports` and read back with `GET /v1/alert-reports[/<id>]`. On the pod's emptyDir without `persistence.enabled`, so they go with the pod; a worst case (`maxReports` x `maxReportBytes`) over 512 MiB is refused there. Allow the Alertmanager's namespace in with `networkPolicy.allowIngressNamespace`; the receiver configuration is in docs/operations.md |
| `rhacs.enabled`, `.endpoint`, `.tokenSecret`, `.caConfigMap`, `.centralNamespace`, `.egressCIDRs` | `false`, `https://central.stackrox.svc` | Read RHACS Central's policies (GET only) for the MCP tool `rhacs_compare_live`: overlap and gaps between your RHACS policies and kube-noob's rules. The token Secret is sent only to `endpoint`; egress opens to the Central pods (TCP 8443) or `egressCIDRs` (TCP 443) |
| `watch.enabled` | `false` | Always-on incident watch in the release namespace and `rbac.namespaces`; needs `config.clusterEnabled` and `replicaCount: 1` |
| `probe.enabled`, `dryRun.enabled` | `false` | Capability tiers P and D (SECURITY.md): render a Role in the release namespace and `rbac.namespaces` only when enabled; need `config.clusterEnabled`; every action still needs a person's approval; `dryRun.rules` lists what may be dry-run (never Secrets) |
| `itsm.writeEnabled`, `notify.enabled`, `gate.enabled` | `false` | Tiers W and G: attach evidence to tickets, forward reports, forward approved tool calls; W is refused under `config.offline` |
| `jira.sync.enabled` | `false` | Keep a local copy of Red Hat's public Jira (`jira.sync.projects`, default set) for "what became of this bug?" answers; REST API at one request per second, `jira.sync.maxRequests` per run every `jira.sync.intervalHours` (24 daily, 48 every 2 days), recording what changed for `kube-noob corpus jira-changes`; opens egress 443 (EgressFirewall: redhat.atlassian.net only); needs `persistence.enabled` and `replicaCount: 1`; refused under `config.offline` |
| `db.enabled`, `db.image.digest` | `false`, `""` | The public `kube-noob-db` image (docs with licenses, release history, known issues; no Jira data), pinned by digest only (the chart refuses to render without one): an init container copies `db.path` with `cp` into a `db.sizeLimit` scratch volume and `serve` imports it when it was built after the copy the pod has. No egress. Verify the signature with `cosign verify` first |
| `jira.seed.source` | `none` | Start every new pod from your organisation's Jira main copy (`kube-noob corpus jira-snapshot`) instead of waiting for a first sync: `image` (an init container copies `jira.seed.path` from the private, pinned `jira.seed.image` with `cp`) or `pvc` (`jira.seed.pvc.claimName`, read-only, `jira.seed.pvc.subPath` folder); `serve` imports the newest `*.tgz` once when the pod has no copy, then the sync fetches only what changed. The snapshot holds Red Hat ticket text: keep it private |
| `jira.seed.keySecret.name`, `.key` | `""`, `key` | Opens a sealed seed (`kube-noob corpus seal`, `jira.seed.path` ending in `.tgz.enc`): the Secret's key file is mounted read-only (0440) for the server container only and named by `KUBE_NOOB_SEED_KEY_FILE`. A wrong or missing key imports nothing and is logged; the pod keeps serving. Needs `jira.seed.source` |
| `mustGather.pvc.claimName` | `""` | A claim of must-gathers, mounted read-only at `/srv/kube-noob/must-gather` (`mustGather.pvc.subPath` optional). Sets `mustGather.allowedDir`: the `analyze_must_gather` MCP tool reads only paths inside it; without a claim the service offers no such tool |
| `memory.source` | `none` | Your team's memory repository (`kube-noob memory init`), mounted read-only at `/srv/kube-noob/memory` and read by every tool: `configMap` (`memory.configMap.name`, entries as keys), `pvc` (`memory.pvc.claimName`) or `git` (an init container clones `memory.git.url` at `memory.git.ref` with `memory.git.image`; ssh:// needs `memory.git.sshSecret` with `ssh-privatekey` and `known_hosts`; egress opens only to `memory.git.egressCIDRs`, and the EgressFirewall names the host; under `config.offline` only an in-cluster `*.svc` host) |
| `admission.enabled` | `false` | kube-noob-admission, a validating webhook (tier A, SECURITY.md): every finding of a created or updated object is a `kubectl` warning. `admission.enforce` (rule ids) denies those rules only, and on an update only a new finding; `failurePolicy: Ignore`, `admission.timeoutSeconds` 3. Serving certificate: `admission.certificates` `openshift-service-ca` (default), `cert-manager` (`admission.certManager.issuerRef`) or `secret` (`admission.tls.secretName`, `.caBundle`). Skips the system namespaces, `openshift-*`, the release namespace, `admission.excludedNamespaces` and namespaces labelled `kube-noob.io/admission=disabled`. `admission.lookups` (a ClusterRole that lists PDBs, NetworkPolicies, PVCs, HPAs and StorageClasses) lets cross-object rules warn; needs `networkPolicy.egress.apiServerCIDRs`. Two replicas, a PodDisruptionBudget and soft anti-affinity; port 8443 is open to every source unless `admission.networkPolicy.from` narrows it |
| `audit.allowedRegistries` | `[]` | Registries an image may come from (`KN-S036`): a lower-case host with an optional port, optionally narrowed to one organisation by a path -- `quay.io`, `registry.example.com:5000`, `quay.io/my-org`. It is written into both config files, so the audit tools, the admission webhook and `kube-noob policy generate` give one verdict, and the webhook restarts when it changes. Empty is not "allow everything": the rule declines, reports nothing and is not recorded as checked, and `admission.enforce: [KN-S036]` without a list is refused at install |
| `rbac.namespaces` | `[]` | Namespaces it may read besides its own (`rbac.scope=cluster` for all) |
| `egressFirewall.enabled` | `false` | OVN-Kubernetes EgressFirewall: API server and allowlisted domains only, then deny (namespace-wide) |
| `persistence.enabled` | `false` | Keep progress, notes and indexed runbooks on a PVC; with the default ReadWriteOnce access mode it needs `replicaCount: 1` and switches the Deployment to the Recreate strategy |
| `route.enabled` | `false` | OpenShift Route with edge TLS. Needs `route.host`: a Route with no host gets a generated `<name>-<namespace>.<apps-domain>` hostname, which the chart cannot put in `server.allowedHosts`, so every MCP call would answer **421 Invalid Host header** while both probes stayed green. The chart refuses to render without it. `oc get ingresses.config/cluster -o jsonpath={.spec.domain}` gives the domain |
| `resources` | 256Mi request, 512Mi limit | About 85 MiB peak with built-in knowledge, plus about 25 MiB per MB of indexed text |

All values and their schema: `values.yaml` and `values.schema.json`. Guides for service, sidecar and OpenShift
Lightspeed setups: <https://github.com/aashishmahajan/kube-noob/blob/main/docs/openshift.md>.

## Test

```bash
helm test kube-noob -n kube-noob
```
