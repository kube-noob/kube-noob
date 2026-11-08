# Release readiness: kube-noob 0.1.0

Assessed 2026-10-27. Every row is backed by a command that was run, a CI job, or a cited source.

## 1. End-to-end evidence

| Area | Verified by | Result |
|---|---|---|
| Tests | CI on Python 3.11-3.13, 80 % coverage gate | pass |
| Package | wheel + sdist, `twine check`, clean venv from the hash-pinned lock, `pip check` | pass |
| CLI | 26 commands against the installed wheel | pass (`helm-audit` needs `helm`; CI covers it) |
| MCP stdio | SDK client spawning `kube-noob mcp`: 22 tools, prompts, resources; misspelled arguments rejected | pass |
| MCP HTTP | bearer auth, Host/Origin checks, 8 MB body limit, audit log, read-only cluster tools, Secrets refused | pass |
| Kubernetes | CI `e2e-kind`: server-side dry runs, legacy API migration, Helm install, `helm test`, live crash-loop diagnosis | pass |
| Air-gapped | full workflow in a network namespace with no route, including a local model on loopback | pass |
| Web opt-in | allowlisted live fetch; other hosts blocked; tool absent when disabled | pass |
| Scale | 22,913-chunk corpus: index 1.9 s, 210 MB RSS, search p50 22 ms | fits chart limits |
| Release | dry run of wheel + amd64/arm64 UBI image | pass |
| Supply chain | `pip-audit`, CodeQL, Scorecard, SHA-pinned actions | pass |

Not verified here: a live OpenShift / ROSA HCP cluster (run the smoke test in section 6) and a real Anthropic model call.

## 2. Residual risks

| Risk | Severity | Mitigation / next step |
|---|---|---|
| One shared bearer token for the HTTP service | Medium | kube-rbac-proxy or OAuth proxy; per-tool authorization; MCP OAuth for remote use |
| Prompt injection via untrusted text (Jira, web, cluster logs) | Medium | read-only server limits impact; next: untrusted-content envelopes |
| Built-in facts age | Medium | weekly risk review flags upstream drift (docs/operations.md) |
| Reward is a proxy over 16 held-out tasks | Medium (training) | grow the benchmark; judge spot checks |
| Not run on real OpenShift / ROSA HCP | High for release claims | smoke test before announcing ROSA support |
| Lexical retrieval; in-memory index | Low | optional embeddings; SQLite FTS5 for large corpora |

Fixed during this assessment: all red-team findings (2 high, 8 medium, 12 low); strict tool arguments; request size limit;
tool audit log; clean model-endpoint errors; arm64 image build (QEMU); dead code removed.

## 3. ROSA HCP gaps (from openshift-docs `modules/`)

| Gap | Add |
|---|---|
| Cluster-level config | audit `rosa create cluster` / Terraform `rhcs`: machine CIDR, PrivateLink, egress lockdown, KMS, FIPS, shared VPC, external auth + break-glass, no-CNI |
| Machine pools | spot + termination queue, Capacity Reservations, Windows LI, disk size, Local Zones, tuning configs, kubeletconfig, n-2 skew |
| AutoNode (Karpenter) | `EC2NodeClass` / `NodePool` validation and readiness playbook |
| Workload AWS identity | `rosa create iamserviceaccount`, role-arn annotations, Secrets Store CSI |
| Live ROSA data | read-only `rosa`/OCM backend (cluster, machine pools, upgrades, ingress, log forwarders) |
| Upgrade readiness | one report: removed APIs for the target, PDB blockers, pool skew |
| Red team | spot interruption, reservation exhaustion, IdP outage, KMS key disabled, egress dependency blocked |

## 4. Free sources (licenses checked 2026-10-27)

Redistributable: openshift/runbooks, kubernetes-mixin, prometheus-operator/runbooks, kyverno/policies,
gatekeeper-library, kube-linter, Polaris, kubescape regolibrary, falcosecurity/rules, kubernetes/enhancements,
openshift/enhancements, kubernetes/kubernetes, Argo CD, cert-manager, kustomize, operator-sdk, oc-mirror, bitnami/charts
(Apache-2.0); trivy-checks (MIT); Red Hat Security Data CSAF/VEX/OSV/SBOM and GitHub Advisory Database (CC BY 4.0).

Retrieval only: EKS best practices and OWASP Kubernetes Top Ten (CC BY-SA 4.0), public Jira, Microsoft Threat Matrix (no
LICENSE). Never ingest CIS Benchmark text; reference control ids only.

## 5. Distribution

| Channel | Path | Status |
|---|---|---|
| PyPI | trusted publishing from `release.yml` (environment `pypi`) | pending publisher configured |
| MCP Registry | `server.json` + `mcp-name` marker in the README; `release.yml` publishes with GitHub OIDC after PyPI | automated |
| Claude Code (own marketplace) | `/plugin marketplace add aashishmahajan/kube-noob` | live |
| Claude directory (plugins) | submit at claude.ai/directory/manage, "Plugin bundle"; needs a paid plan, public repo, LICENSE + README in the plugin folder; the plugin runs bundled source with a `uv.lock` (no `uvx` download, which is held for policy review) and links PRIVACY.md | submitted |
| OpenShift Helm charts (community) | fork openshift-helm-charts/charts, PR the OWNERS file, then the release `.tgz` ([openshift-catalog.md](openshift-catalog.md)); check first with `podman run --rm -v "$PWD/deploy/helm":/charts:z quay.io/redhat-certification/chart-verifier verify --set profile.vendorType=community /charts/kube-noob` | chart ready |
| Homebrew | `brew tap kube-noob/kube-noob https://github.com/aashishmahajan/kube-noob`, `brew trust --formula kube-noob/kube-noob/kube-noob`, then `brew install kube-noob`; the release workflow writes `Formula/kube-noob.rb` once PyPI has the version (`python scripts/brew_formula.py <version> --write`) and CI installs it that way | live for 0.2.2 |
| Claude Desktop `.mcpb` | the directory no longer accepts MCPB; optional release asset | not planned |
| claude.ai Connectors (remote) | needs one hosted HTTPS server with OAuth; poor fit for in-cluster use | not planned |
| OpenShift Developer Catalog | community Helm chart via `openshift-helm-charts/charts` (OWNERS PR first); partner listing needs Partner Connect and a certified image | next |
| Red Hat container certification | `preflight` checks UBI base, non-root, `/licenses`, required labels, unique tag | labels and `/licenses` added |
| OperatorHub | needs an operator bundle and a CRD | later |
| OpenShift Lightspeed | external MCP servers via `OLSConfig` feature gate `MCPServer`; check `oc explain olsconfig.spec.mcpServers` | document after 0.1.0 |

Sources: code.claude.com/docs/en/plugins, claude.com/docs/plugins/submit, claude.com/docs/connectors,
modelcontextprotocol.io/registry, github.com/modelcontextprotocol/mcpb, github.com/redhat-openshift-ecosystem/openshift-preflight,
github.com/openshift-helm-charts/charts, docs.redhat.com (OpenShift Lightspeed 1.0 OLSConfig API).

Positioning: Red Hat's OpenShift MCP server (Technology Preview, based on containers/kubernetes-mcp-server) operates
clusters; kube-noob teaches, audits and diagnoses offline and can sit next to it.

## 6. Release gates

| Gate | Status |
|---|---|
| CI green on `main`; release dry run | done |
| PyPI pending publisher | done |
| Private vulnerability reporting enabled | maintainer |
| ROSA HCP smoke test on a real cluster | maintainer, before announcing ROSA support |
| Tag `v0.1.1` (v0.1.0 never reached PyPI: publish action bundled twine 6.1.0, which rejects Metadata-Version 2.5; fixed and gated by `scripts/check_publishable.sh`) | ready |

ROSA HCP smoke test (logged in with `oc login`; read-only):

```bash
uvx --from git+https://github.com/aashishmahajan/kube-noob kube-noob debug deployment/console -n openshift-console --platform rosa-hcp --cluster-enabled
oc get deploy,svc,route,pvc,networkpolicy -n openshift-console -o yaml | uvx --from git+https://github.com/aashishmahajan/kube-noob kube-noob audit -f - --platform rosa-hcp --version 4.22
```
