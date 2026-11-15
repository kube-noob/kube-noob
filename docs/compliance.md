# Compliance: FedRAMP High and NIST SP 800-53

kube-noob is software that runs inside your system boundary; it is not a cloud service and holds no FedRAMP
authorization of its own. FedRAMP authorizes cloud service offerings, so kube-noob counts as a component of the
offering it runs in (for example an OpenShift or ROSA cluster in a FedRAMP High environment), and the controls below
are met by how that offering deploys and operates it. This page says what kube-noob gives as evidence, how to deploy
it inside a High boundary, and what is not covered yet. Researched 2026-10-27.

FedRAMP is changing: the Consolidated Rules for 2026 apply to every authorization from 1 January 2027, and the
Vulnerability Detection and Response rules from 7 December 2026 for obtaining and for maintaining a certification,
with a grace period to 7 March 2027. 20x Class D (the high-impact class) is not in pilot yet: RFC-0033 proposes the
Phase 4 pilot for FY27 Q1 and Q2, with the application window 1-4 December 2026 and a cap of ten participants, and
applicants need a CR26-compliant Class C certification first (checked 2026-10-31).
Both Rev5 baselines and the 20x Key Security Indicators are written against NIST SP 800-53 Rev. 5 controls, which is
what kube-noob maps to.

## Evidence kube-noob produces

| Evidence | Controls it supports | How |
|---|---|---|
| Every audit finding names the NIST SP 800-53 controls it is evidence about; each report has a `controlSummary` | CM-6, CM-7, AC-6, SC-7, SC-8, IA-5(7) and the rest in the table below | `kube-noob audit -f k8s/ --format json` (also over MCP) |
| Changes are validated before they reach the cluster | CM-3(2) | `kube-noob audit` in CI (exit 1 on high findings), `fix`, `protocol` |
| Posture: what the process can reach, and FIPS mode | CM-7, SC-7, SC-13 | `kube-noob doctor` (exit 1 on a contradiction); `config_status` over MCP |
| Policy denials and NetworkPolicy reachability explained | AC-4, SC-7, AC-3 | `kube-noob policy explain`, `kube-noob policy reach` |
| Signed image and chart, build provenance, image SBOM, hash-pinned dependencies | SI-7, SR-4, SR-11, SA-10 | Release workflow; verification commands in [SECURITY.md](../SECURITY.md) |
| Dependency and code scanning, weekly risk review | RA-5, SI-2, SA-11 | Dependabot, `pip-audit`, CodeQL, OpenSSF Scorecard, `risk-review` workflow |
| Each requirement traced to a test | SA-11, CA-2 (input) | [guidance.md](guidance.md) |

## Deploying inside a FedRAMP High boundary

| Control | Setting |
|---|---|
| CM-7, SC-7 | Chart `config.offline=true` (no web, no corpus downloads, local models only); keep the chart's NetworkPolicy (DNS-only egress) and add the EgressFirewall on OVN-Kubernetes |
| SC-13 | Install OpenShift in FIPS mode and use the UBI-based image: kube-noob uses only SHA-256 and the system OpenSSL, so its crypto runs in the validated module. `kube-noob doctor` must show `FIPS mode on` |
| AC-3, AC-6 | Live cluster access stays off unless needed; when on it is read-only, namespace-scoped, never reads Secrets and redacts values |
| IA-2, IA-5, AC-2 | Put the HTTP service behind the OpenShift OAuth proxy backed by your PIV/CAC identity provider instead of relying only on the shared bearer token |
| AU-2, AU-3, AU-12 | Ship the container's stdout to cluster logging and your SIEM: each tool call logs the tool, argument sizes, outcome and duration, never content |
| SI-7, SR-11 | Deploy by digest from your mirror and verify the cosign signature and provenance before admission (RHACS or a Sigstore admission policy) |
| RA-5, SI-2 | Scan the image in your registry (RHACS, Quay, Clair) and fix within the Vulnerability Detection and Response timeframes; take patch releases from the weekly risk review |
| SC-28 | Keep the data directory on an encrypted storage class, or set `learningEnabled: false`; kube-noob stores nothing else |
| CM-2, CM-6 | Keep `kube-noob.yaml` in Git as a ConfigMap; run `kube-noob doctor` in the pipeline |

Using kube-noob with an AI client in a High boundary: kube-noob never calls a model. The client's model must itself
be authorized at High, for example Claude through Amazon Bedrock in AWS GovCloud (US), Claude for Government, or
Claude on Google Vertex AI with Assured Workloads, or a model you host inside the boundary (`kube-noob ask` with
`openai-compatible` and a `*.svc` endpoint).

## Not covered yet

- Per-user identity in the service: authorization is one shared token unless you add the OAuth proxy, and audit
  records do not carry the caller's identity yet.
- The 20x Key Security Indicator crosswalk now ships -- `kube-noob ksi` -- and what is left is its reach, not its
  absence. 29 of the 31 controls kube-noob maps are cited by an indicator; `SC-6` and `SC-36` are cited by none, so
  no finding reaches an indicator through them, and 15 of the 46 indicators have no kube-noob rule behind them at
  all and say so rather than showing a zero. See [FedRAMP 20x KSI](fedramp-ksi.md), which is generated from the
  vendored dataset with its version and hash. The five specifics this bullet used to carry were all wrong by
  2026-11-02 and it asserted them anyway: there is no separate `FRMR.KSI.key-security-indicators.json` at 25.11C,
  there are ten families and not eleven, indicators are keyed by mnemonic and not by number, and nothing in the
  consolidated dataset is flagged retired -- the seven ids recorded here as `retired: true` no longer exist as ids.
- FIPS mode is checked by `doctor` but not exercised in CI (no FIPS-mode runner).
- No 3PAO assessment, Iron Bank listing, DISA STIG review of the image, or CISA secure software development
  attestation has been done.

## The 98 audit rules and their controls

| Rule | What it checks | NIST SP 800-53 Rev. 5 controls |
|---|---|---|
| KN-C001 | No readiness probe | CP-10 |
| KN-C002 | No liveness probe | CP-10 |
| KN-C003 | Liveness probe is aggressive | CP-10, SC-5 |
| KN-C004 | Missing CPU/memory requests | SC-6 |
| KN-C005 | Missing memory limit | SC-5, SC-6 |
| KN-C006 | Request exceeds limit | CM-6 |
| KN-C007 | Single replica | CP-10, SC-36 |
| KN-C008 | No PodDisruptionBudget | CP-10 |
| KN-C009 | PodDisruptionBudget blocks all voluntary evictions | SI-2, CP-10 |
| KN-C010 | Replicas not spread across zones/nodes | SC-36 |
| KN-C011 | terminationGracePeriodSeconds is 0 | CP-10 |
| KN-C012 | HPA cannot compute CPU utilization | SC-6 |
| KN-C013 | Pull secret exists only in another namespace | CM-6 |
| KN-C014 | Workload scaled by an HPA also sets spec.replicas | CM-6, SC-6 |
| KN-C015 | Pod names a resource claim that is not in this bundle | CM-6 |
| KN-C016 | Namespace has workloads but no ResourceQuota or LimitRange | SC-5, SC-6 |
| KN-N001 | Namespace has workloads but no NetworkPolicy | SC-7, SC-7(5), AC-4 |
| KN-N002 | Route without TLS | SC-8, SC-8(1) |
| KN-N003 | Ingress without TLS | SC-8, SC-8(1) |
| KN-N004 | LoadBalancer Service open to the internet | SC-7, AC-4 |
| KN-N005 | NodePort Service | SC-7, CM-7 |
| KN-N006 | EgressFirewall rule is shadowed | SC-7, SC-7(5), AC-4 |
| KN-N007 | NetworkPolicy allows all ingress | SC-7, SC-7(5), AC-4 |
| KN-N008 | Service uses externalIPs | SC-7, SC-8, AC-4 |
| KN-N009 | Ingress uses a risky ingress-nginx annotation | CM-7, SI-2, SC-7 |
| KN-N010 | ingress-nginx ConfigMap widens what an Ingress may ask of the controller | CM-6, CM-7, SI-2 |
| KN-N011 | Ingress path type ImplementationSpecific on ingress-nginx | SI-2, SI-10, CM-7 |
| KN-N012 | NetworkPolicy selects no pod in this bundle | SC-7, SC-7(5), AC-4 |
| KN-N013 | Egress is denied without allowing cluster DNS | SC-7, CP-10 |
| KN-N014 | Admin network policy the cluster's CNI does not enforce | SC-7, SC-7(5), AC-4 |
| KN-S001 | Privileged container | AC-6, CM-7, SC-39 |
| KN-S002 | Privilege escalation not disabled | AC-6, AC-6(10), CM-7 |
| KN-S003 | Container may run as root | AC-6, CM-6 |
| KN-S004 | Fixed UID/fsGroup conflicts with OpenShift restricted-v2 SCC | CM-6, AC-6 |
| KN-S005 | Dangerous Linux capabilities added | AC-6, CM-7 |
| KN-S006 | Capabilities not dropped | AC-6, CM-7 |
| KN-S007 | Writable root filesystem | CM-7, SI-7 |
| KN-S008 | Seccomp profile not set to RuntimeDefault | CM-6, CM-7, SC-39 |
| KN-S009 | Host namespaces shared | SC-39, AC-6 |
| KN-S010 | hostPath volume | AC-6, SC-39 |
| KN-S011 | hostPort used | SC-7, CM-7 |
| KN-S012 | Mutable image reference | CM-2, SI-7 |
| KN-S013 | Secret value hard-coded in environment | IA-5(7), SC-28 |
| KN-S014 | ServiceAccount token automounted | AC-6, IA-5, CM-7 |
| KN-S015 | RBAC wildcard grants | AC-3, AC-6 |
| KN-S016 | Binding to cluster-admin | AC-6, AC-6(5) |
| KN-S017 | RBAC privilege-escalation paths | AC-3, AC-5, AC-6 |
| KN-S018 | Secret material committed in manifests | IA-5(7), SC-28 |
| KN-S019 | Permissive SecurityContextConstraints | AC-6, CM-7, SC-39 |
| KN-S020 | Unmasked /proc | SC-39, CM-7 |
| KN-S021 | gitRepo volume | SI-2, CM-7, SC-39 |
| KN-S022 | Pod sysctl name or value contains '+' or '=' | SI-2, SC-39, CM-7 |
| KN-S023 | Container workingDir under /proc | SI-2, SC-39 |
| KN-S024 | ingress-nginx controller image below the fixed releases | SI-2, SA-22 |
| KN-S025 | volumeMount subPath carries shell or PowerShell characters | SI-2, SI-10, SC-39 |
| KN-S026 | Credential stored in a ConfigMap | IA-5(7), SC-28 |
| KN-S027 | Legacy ServiceAccount token Secret | IA-5, AC-6 |
| KN-S028 | RBAC binding grants a role to everyone | AC-14, AC-3, AC-6 |
| KN-S029 | Probe or lifecycle handler with a host | SC-7, CM-7 |
| KN-S030 | Admission webhook fails open | CM-7, SI-7 |
| KN-S031 | Device claim requests administrative access | AC-6, SC-4 |
| KN-S032 | Namespace does not enforce a pod security level | AC-6, CM-6 |
| KN-S033 | MachineConfigPool is paused | SI-2 |
| KN-S034 | Operator Subscription upgrades without review | CM-3(2) |
| KN-S035 | Cluster audit logging is turned off, for everyone or for one group | AU-2, AU-12 |
| KN-S036 | Image from a registry outside the allowlist | CM-2, SI-7 |
| KN-S037 | APIService does not verify the extension API server it forwards to | SC-8, SC-8(1), CM-6 |
| KN-S038 | kube-apiserver allows anonymous requests or authorizes every request | AC-3, AC-14, CM-6 |
| KN-S039 | etcd serves clients or peers in plaintext, or without client certificates | SC-8, SC-8(1), AC-3 |
| KN-S040 | OpenShift API server does not encrypt resources at rest | SC-28, SC-28(1) |
| KN-S041 | OpenShift LDAP identity provider connects without TLS | SC-8, SC-8(1), IA-5 |
| KN-ST001 | ReadWriteMany requested from a ReadWriteOnce-only StorageClass | CM-6 |
| KN-ST002 | ReadWriteOnce volume shared by a rolling Deployment | CM-6, CP-10 |
| KN-ST003 | Zonal storage with Immediate volume binding | SC-36, CM-6 |
| KN-ST004 | EFS StorageClass is missing required parameters | CM-6 |
| KN-ST005 | PVC has no storage request | CM-6, SC-6 |
| KN-ST006 | PersistentVolume path carries command or traversal characters | SI-2, SI-10, AC-6 |
| KN-V001 | Object is missing apiVersion, kind or metadata.name | CM-3(2), CM-6 |
| KN-V002 | apiVersion does not serve this kind | CM-3(2), CM-6 |
| KN-V003 | OpenShift-only API used on a non-OpenShift target | CM-3(2), CM-6 |
| KN-V004 | API requires an add-on on this platform | CM-3(2), CM-6 |
| KN-V005 | API removed in the target Kubernetes version | CM-3(2), SA-22 |
| KN-V006 | Deprecated API in the target Kubernetes version | SA-22 |
| KN-V008 | DeploymentConfig is deprecated | SA-22 |
| KN-V009 | metadata.name is not a valid DNS-1123 name | CM-3(2), CM-6 |
| KN-V010 | Workload selector does not match its pod template labels | CM-3(2), CM-6 |
| KN-V011 | Service selects no pods in this bundle | CM-3(2), CM-6 |
| KN-V012 | Service targetPort name is not declared by the selected containers | CM-3(2), CM-6 |
| KN-V014 | Duplicate object in bundle | CM-3(2), CM-6 |
| KN-V015 | EgressFirewall must be named 'default' | SC-7, CM-6 |
| KN-V016 | Route TLS configuration is invalid | SC-8, CM-6 |
| KN-V017 | MachineConfig is not a customer lever on ROSA | CM-6 |
| KN-V018 | Duplicate key in a YAML mapping | CM-3(2), CM-6 |
| KN-V019 | Ingress targets the retired ingress-nginx | SA-22 |
| KN-V020 | Container claims a resource the Pod does not declare | CM-3(2), CM-6 |
| KN-V021 | Pod resource claim names no source, or two | CM-3(2), CM-6 |
| KN-V022 | Resource claims set at pod level, where they are forbidden | CM-3(2), CM-6 |
| KN-V023 | Service numeric targetPort is not a declared containerPort | CM-3(2), CM-6 |

Control titles ([NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)):

| Control | Title |
|---|---|
| AC-3 | Access Enforcement |
| AC-4 | Information Flow Enforcement |
| AC-5 | Separation of Duties |
| AC-6 | Least Privilege |
| AC-6(5) | Least Privilege \| Privileged Accounts |
| AC-6(10) | Least Privilege \| Prohibit Non-privileged Users from Executing Privileged Functions |
| AC-14 | Permitted Actions Without Identification or Authentication |
| AU-2 | Event Logging |
| AU-12 | Audit Record Generation |
| CM-2 | Baseline Configuration |
| CM-3(2) | Configuration Change Control \| Testing, Validation, and Documentation of Changes |
| CM-6 | Configuration Settings |
| CM-7 | Least Functionality |
| CP-10 | System Recovery and Reconstitution |
| IA-5 | Authenticator Management |
| IA-5(7) | Authenticator Management \| No Embedded Unencrypted Static Authenticators |
| SA-22 | Unsupported System Components |
| SC-4 | Information in Shared System Resources |
| SC-5 | Denial-of-service Protection |
| SC-6 | Resource Availability |
| SC-7 | Boundary Protection |
| SC-7(5) | Boundary Protection \| Deny by Default — Allow by Exception |
| SC-8 | Transmission Confidentiality and Integrity |
| SC-8(1) | Transmission Confidentiality and Integrity \| Cryptographic Protection |
| SC-13 | Cryptographic Protection |
| SC-28 | Protection of Information at Rest |
| SC-28(1) | Protection of Information at Rest \| Cryptographic Protection |
| SC-36 | Distributed Processing and Storage |
| SC-39 | Process Isolation |
| SI-2 | Flaw Remediation |
| SI-7 | Software, Firmware, and Information Integrity |
| SI-10 | Information Input Validation |

## Sources

- [FedRAMP Consolidated Rules transition (Cloud Security Alliance research note)](https://labs.cloudsecurityalliance.org/research/csa-research-note-fedramp-20x-consolidated-rules-transition/)
- [FedRAMP Vulnerability Detection and Response](https://fedramp.gov/2026/providers/20x/rules/vulnerability-detection-and-response/)
- [FedRAMP 20x Key Security Indicators](https://www.fedramp.gov/20x/standards/20x-ksi)
- [RFC-0033: 20x Phase 4 development tracks for Class D](https://www.fedramp.gov/rfcs/0033/)
- [Claude public sector FAQ (FedRAMP High availability)](https://support.claude.com/en/articles/13756069-public-sector-faqs)
