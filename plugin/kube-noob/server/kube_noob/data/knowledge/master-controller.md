---
searchWeight: 0.5
id: master-controller
title: Master Controller - the 7-step engineering protocol
tags: [protocol, sre, architecture]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
sources:
  - {title: "kube-noob protocol (original)", url: "https://github.com/kube-noob/kube-noob", license: Apache-2.0}
---
# Master Controller - the 7-step engineering protocol

No solution, manifest or recommendation leaves kube-noob without passing all seven steps. Every step has a
deterministic tool behind it, so the output can be checked instead of trusted.

## 1. Clarify
Find missing or conflicting parameters before doing anything: target platform (vanilla Kubernetes, OpenShift on-prem
IPI/UPI, ROSA Classic, ROSA with HCP), platform version, storage needs (size, access mode, class), exposure (Route,
Ingress, Gateway API, LoadBalancer), namespace, image, replica count. If a wrong guess would make the result unsafe or
wrong (for example ReadWriteMany on a cluster whose only class is EBS), ask a sharp question. Otherwise state the
assumption explicitly. Tool: `kubenoob_clarify_requirements`.

## 2. Validate
Check every object against the target platform: the apiVersion must serve the kind (Route is `route.openshift.io/v1`;
`apps.openshift.io/v1` serves DeploymentConfig), OpenShift-only APIs (Route, SecurityContextConstraints,
DeploymentConfig) must not be sent to vanilla Kubernetes, removed APIs (e.g. `policy/v1beta1` PodDisruptionBudget,
removed in 1.25) must be migrated, and every field must exist in the schema (strict validation catches typos such as
`imagePullPolice`). Tool: `kubenoob_validate_manifests`.

## 3. Research
Ground the answer in the local knowledge base and corpus (Kubernetes docs, OpenShift docs, ROSA/HyperShift docs,
Helm docs, StackRox policies and changelog, public Jira insights) and cite chunk ids like `[kn:ocp-scc#0]`. Web lookups
happen only when the operator set `webEnabled: true`. Tool: `kubenoob_search_knowledge`.

## 4. Audit
Security and structural soundness: least-privilege RBAC (no wildcards, no cluster-admin bindings), non-root
containers with `allowPrivilegeEscalation: false`, dropped capabilities and RuntimeDefault seccomp, no host
namespaces or hostPath, NetworkPolicy isolation, TLS on every Route/Ingress, secrets never inlined, storage access modes
that the StorageClass can actually provide. Tool: `kubenoob_audit_manifests`.

## 5. Calibrate
Production efficiency and availability: requests and memory limits sized from observed usage, readiness and liveness
probes that do not cause restart storms, at least two replicas spread across zones and nodes with
topologySpreadConstraints, a PodDisruptionBudget that still allows drains (maxUnavailable: 1), HPA only with CPU
requests set.

## 6. Generate
Produce the final artifact: clean, commented YAML (or a Helm chart) plus the commands to validate it in a cluster
(`oc apply --dry-run=server -f`, `kubectl diff -f`). Mechanical fixes (API migrations, securityContext hardening,
Route TLS, PDB) are applied automatically and listed; anything that needs application knowledge (probe paths, image
digests) is listed as a manual follow-up. Tools: `kubenoob_generate_manifests`, `kubenoob_fix_manifests`,
`kubenoob_generate_helm_chart`.

## 7. Red Team
Attack your own output before presenting it:
- What happens if a worker node crashes mid-operation? (single replicas, RWO volumes shared by a Deployment)
- What happens if an availability zone fails? (zonal EBS volumes, no zone spread)
- Does this ReadWriteMany volume cause split-brain or locking issues? (embedded databases on NFS/EFS/CephFS)
- Is there an exposed route or insecure ingress path? (plain HTTP, public load balancers, missing NetworkPolicy)
- Can a compromised pod escalate to the node or the cluster?
- Will this block a cluster upgrade? (PDBs that allow zero disruptions)
Patch what is found, re-run the audit, and only then present. Tool: `kubenoob_red_team`.

## Output structure
1. **Audit & Validation Brief** - platform targets, versions, assumptions, constraints found.
2. **Production Manifest / Solution** - the validated YAML or blueprint.
3. **Red Team Findings & Safeguards** - scenarios, remaining risks, verification commands.
Tool for the whole pipeline: `kubenoob_run_protocol`.
