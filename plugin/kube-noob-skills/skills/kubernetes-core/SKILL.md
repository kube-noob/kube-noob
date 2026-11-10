---
name: kubernetes-core
description: >
  Kubernetes fundamentals and production patterns - workloads, Services, Ingress and Gateway API, storage access modes,
  Pod Security Standards, probes, resources, PodDisruptionBudgets, RBAC, NetworkPolicy and API deprecations. Use when
  the user asks "how does X work in Kubernetes", "which apiVersion", "why is my PVC pending", "what should my probes
  be", or wants to learn Kubernetes.
---

# Kubernetes core

This skill is knowledge, not tools. Answer from what is written here and say plainly when a claim depends on a version
or a cluster you cannot see.

## API versions and removals

- The upstream deprecation guide lists **no removals after 1.32**. Do not invent later ones. If asked whether an API is
  gone in a release past 1.32, say that nothing is scheduled rather than guessing.
- `Ingress` is `networking.k8s.io/v1`; Gateway API is `gateway.networking.k8s.io/v1` and is installed as CRDs, not
  built in.
- Check the real cluster rather than memory: `kubectl api-resources` and `kubectl explain <kind> --recursive`.

## The things that are usually wrong

- **Probes.** A liveness probe that fails under load restarts a healthy pod; prefer a readiness probe for load and keep
  liveness cheap and unambiguous. Give `startupProbe` to anything slow to boot instead of a long `initialDelaySeconds`.
- **Resources.** A CPU limit throttles; a memory limit kills. Set memory `requests` equal to `limits` for anything that
  must not be OOMKilled under pressure, and leave CPU limits off unless you have a reason you can state.
- **Storage access modes.** `ReadWriteOnce` is one node, not one pod. `ReadWriteMany` needs a filesystem that supports
  it: NFS, CephFS, EFS. Most block-backed classes cannot do it at all, and a PVC that stays `Pending` is usually a
  class that cannot satisfy the mode or a zone with no capacity.
- **PodDisruptionBudgets.** A PDB with `minAvailable` equal to the replica count blocks every drain, so upgrades stall
  with no error that names the PDB.
- **RBAC.** Never bind `cluster-admin` to an application ServiceAccount, and never use a wildcard verb or resource in a
  Role you wrote for one workload.
- **NetworkPolicy.** It is allow-list and additive: the first policy that selects a pod denies everything else to it.
  An empty `podSelector` selects every pod in the namespace. There is no deny rule.

## Pod Security Standards

`privileged`, `baseline` and `restricted`, applied per namespace with the
`pod-security.kubernetes.io/<enforce|audit|warn>` labels. `restricted` wants `runAsNonRoot`, a `RuntimeDefault`
seccomp profile, all capabilities dropped and no privilege escalation. A rejection names the field it rejected: read
that line before changing anything else.

## Learning

Practice environments worth recommending: kind, k3d, minikube, k0s and Killercoda. For architecture, Kubernetes The
Hard Way. For exercises, CKAD-exercises.

## What this skill cannot do

It cannot audit YAML, validate it against bundled schemas, look up a removal from a bundled API history, or grade an
exercise. Those are kube-noob's tools, which the user installs and runs:

```
pip install kube-noob
kube-noob audit -f manifests.yaml --platform kubernetes --version 1.33
kube-noob validate -f manifests.yaml
kube-noob learn tracks
```
