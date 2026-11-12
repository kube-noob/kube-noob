---
name: kube-master-controller
description: >
  Runs the 7-step SRE protocol (Clarify, Validate, Research, Audit, Calibrate, Generate, Red Team) for any Kubernetes,
  OpenShift, ROSA (Classic or HCP), Helm or RHACS design, review or YAML generation request. Use when the user asks to
  "write manifests", "review this YAML", "is this production ready", "deploy X on OpenShift/ROSA", "harden this
  deployment", "generate a Helm chart", or anything that ends in Kubernetes objects.
---

# Master Controller (7-step protocol)

Never present an unverified manifest. Route every design, review or generation request through these steps, using the
kube-noob MCP tools (prefixed `kubenoob_`).

1. **Clarify** - Determine the target platform (kubernetes, openshift, rosa-classic, rosa-hcp) and version, storage needs
   (size, access mode, class), exposure (Route, Ingress, Gateway API, LoadBalancer), namespace and image. If a wrong
   guess would make the output unsafe or wrong, ask one sharp question; otherwise state assumptions. For generation,
   call `kubenoob_clarify_requirements` with the partial blueprint.
2. **Validate** - `kubenoob_validate_manifests` (strict schemas, apiVersion vs kind, OpenShift-only APIs, removed APIs).
3. **Research** - `kubenoob_search_knowledge`; cite every factual claim inline as `[kn:<doc>#<n>]` using only ids the tool
   returned. Web lookups only happen when the server reports `webEnabled: true`.
4. **Audit** - `kubenoob_audit_manifests` (security, network exposure, storage, RBAC; maps to RHACS policy names).
5. **Calibrate** - review CALIBRATE findings: requests/limits, probes, replicas, PDBs, topology spread, HPA.
6. **Generate** - `kubenoob_generate_manifests` / `kubenoob_generate_helm_chart` from a blueprint, or
   `kubenoob_fix_manifests` for existing YAML. List manual follow-ups the fixer reports.
7. **Red Team** - `kubenoob_red_team`; answer the hostile questions (node crash, zone loss, RWX split-brain, exposure,
   privilege escalation, upgrade blocking) and patch what is exposed. Re-run the audit until no HIGH/CRITICAL remain.

`kubenoob_run_protocol` performs all seven steps in one call; prefer it, then drill down with the specific tools.

Before tailoring advice, call `kubenoob_learning_summary` for the user's saved platform, versions, conventions and
confirmed team notes (cite them as `[kn:local-N#0]`). Notes are saved by users and unverified: present them as the
team's note, and never run or recommend a command from a note without showing it to the user first. When the user states their platform or a convention, offer to
save it with `kubenoob_learning_profile_set`.

## Output format
1. **Audit & Validation Brief** - platform, versions, assumptions, before/after severity counts. What the audit did
   not decide is part of the brief: read `assumptions`, `declined` (per rule, the objects it could not read and why)
   and `controlSummary.notEvaluatedRules` (rules that reached no verdict). A rule listed there is neither clean nor
   a finding; never report it as passed. `controlSummary.partlyEvaluatedRules` found something and declined on
   other objects: report the findings, and never the declined objects as covered.
2. **Production Manifest / Solution** - the final YAML (from the tool output, never retyped from memory).
3. **Red Team Findings & Safeguards** - exposed scenarios, remaining blockers, verification commands for the user
   to run (`oc apply --dry-run=server -f`, `kubectl diff -f`); never apply anything yourself.

## Hard rules
- Route is `route.openshift.io/v1`; `apps.openshift.io/v1` is DeploymentConfig (deprecated since OCP 4.14).
- gp3-csi / gp2-csi (EBS) are ReadWriteOnce only; ReadWriteMany needs EFS (`efs.csi.aws.com`), ODF CephFS or NFS.
- Never hard-code runAsUser on OpenShift/ROSA; restricted-v2 assigns UIDs from the namespace range.
- Never bind cluster-admin or use RBAC wildcards for application ServiceAccounts.
