---
name: openshift-platform
description: >
  Red Hat OpenShift (OCP on-prem, IPI and UPI) specifics - SecurityContextConstraints and arbitrary UIDs, Routes and
  TLS termination, OVN-Kubernetes EgressFirewall, ODF storage, operators and OLM, DeploymentConfig deprecation, and the
  OCP to Kubernetes version map. Use when the user mentions OpenShift, OCP, oc, SCC, Route, restricted-v2, ODF or
  EgressFirewall.
---

# OpenShift platform

This skill is knowledge, not tools. It explains the platform and reads what the user pastes; it audits nothing.

## Version map

OCP 4.12 to Kubernetes 1.25, and one minor per release from there: 4.20 to 1.33, 4.21 to 1.34, 4.22 to 1.35 (current).
Confirm against the cluster with `oc version` rather than asserting from this table alone.

## SecurityContextConstraints

New 4.11+ clusters admit workloads under `restricted-v2`: every capability dropped, a `RuntimeDefault` seccomp profile,
no privilege escalation, and a UID taken from the namespace's assigned range.

- **A pod with a fixed `runAsUser` is rejected.** This is the single most common OpenShift admission failure for an
  image that works on vanilla Kubernetes.
- Images must run as an arbitrary UID in group 0. That means a writable path owned by group 0 with group write set, not
  a hard-coded user in the Containerfile.
- If a workload genuinely needs more, grant the **least permissive SCC that works**, to a **dedicated ServiceAccount**,
  never to `default` and never to a group. `oc adm policy add-scc-to-user <scc> -z <sa> -n <ns>`.
- To see which SCC admitted a running pod: `oc get pod <name> -o jsonpath='{.metadata.annotations.openshift\.io/scc}'`.

## Routes

Three terminations: `edge`, `reencrypt` and `passthrough`. On `reencrypt`, omit `destinationCACertificate` to trust the
service-serving CA. Always set `insecureEdgeTerminationPolicy: Redirect`.

**503 "Application is not available"** has four usual causes, in the order worth checking:

1. no ready endpoints behind the Service (`oc get endpoints <svc>`),
2. the Route's `targetPort` does not match a port the Service exposes,
3. the termination does not match what the pod actually serves (edge in front of an HTTPS container, or the reverse),
4. a NetworkPolicy that does not admit the ingress controller, which needs the namespace label
   `policy-group.network.openshift.io/ingress: ""`.

## EgressFirewall

Name must be `default`, one per project, and **first match wins**. Put specific `Allow` rules first and
`Deny 0.0.0.0/0` last, or the deny swallows everything beneath it. It applies to egress from the project only; it is
not a substitute for a NetworkPolicy.

## Other platform facts

- `apps.openshift.io/v1 DeploymentConfig` has been deprecated since 4.14. New work uses `apps/v1 Deployment`.
- `route.openshift.io/v1` is the Route API. Do not confuse the two groups.
- ODF gives CephFS (`ReadWriteMany`) and RBD (`ReadWriteOnce`). Pick the mode first and the class second.
- Operators install through OLM: a Subscription with a channel and an install plan approval mode. `Automatic` approval
  on a production cluster means an operator minor upgrade can arrive unannounced.

## What this skill cannot do

It cannot audit manifests against OpenShift rules, generate admission policy, rank attack paths, compare RHACS policies
or read a must-gather. Those are kube-noob's tools:

```
pip install kube-noob
kube-noob audit -f manifests.yaml --platform openshift --version 4.20
kube-noob policy generate --platform openshift --mode audit -o policies.yaml
kube-noob posture scan -f k8s/
kube-noob must-gather analyze /path/to/must-gather.tar.gz
```
