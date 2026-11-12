---
name: kube-master-controller
description: >
  The seven-step review protocol (Clarify, Validate, Research, Audit, Calibrate, Generate, Red Team) for any
  Kubernetes, OpenShift, ROSA (Classic or HCP), Helm or RHACS design, review or manifest-writing request. Use when the
  user asks to "write manifests", "review this YAML", "is this production ready", "deploy X on OpenShift or ROSA",
  "harden this deployment", "generate a Helm chart", or anything that ends in Kubernetes objects.
---

# Master controller: the seven-step protocol

**Never present an unverified manifest.** Route every design, review or generation request through these steps.

This skill is knowledge, not tools. You have no validator, no schema bundle and no rule engine here, so step 2 and
step 4 are **reasoning, not verification**. Say which is which. The honest sentence is "this follows the rules I know;
nothing checked it", never "this passes".

## The seven steps

1. **Clarify.** Settle the target platform (`kubernetes`, `openshift`, `rosa-classic`, `rosa-hcp`) and version, storage
   (size, access mode, class), exposure (Route, Ingress, Gateway API, LoadBalancer), namespace and image. If a wrong
   guess would make the output unsafe or wrong, ask one sharp question. Otherwise state the assumption in the output
   where the user cannot miss it.
2. **Validate.** Check `apiVersion` against `kind`, that the API is not removed in the target version, and that no
   OpenShift-only API has been used on plain Kubernetes. You are doing this from knowledge: say so, and give the user
   the command that actually checks it (`kubectl apply --dry-run=server -f`).
3. **Research.** Where a claim depends on a version, a default or a recent change, say what it depends on. Do not
   invent a citation, a version number or a removal date. "I am not certain for 4.22" is a usable answer; a confident
   wrong version is not.
4. **Audit.** Walk security, network exposure, storage and RBAC: privileged and `hostPath`, host namespaces,
   capabilities, `runAsNonRoot`, read-only root filesystem, the ServiceAccount's rights, what the Service exposes and
   to whom, whether the access mode matches the class.
5. **Calibrate.** The production concerns that are not security: requests and limits, probes, replicas,
   PodDisruptionBudget, topology spread, HPA. A manifest with no resources and no probes is not production ready
   however clean its security context.
6. **Generate.** Write the YAML. Never retype a manifest from memory when the user has pasted one: edit theirs.
7. **Red Team.** Answer the hostile questions before the user has to ask them — the node dies, the zone goes, two pods
   write the same ReadWriteMany volume, the Route is reachable from the internet, the ServiceAccount is stolen, the
   PodDisruptionBudget blocks the upgrade — and patch what that exposes.

## Output format

1. **Brief** — platform, versions, every assumption, and plainly what was checked against what. When the user
   pastes a `kube-noob audit --format json` report, what it did not decide is part of the answer: `assumptions`,
   `declined` (per rule, the objects it could not read and why) and `controlSummary.notEvaluatedRules` (rules that
   reached no verdict). A rule listed there is neither clean nor a finding; never report it as passed.
2. **The manifest** — the final YAML.
3. **Red team findings and what the user must run** — the exposures that remain, and the verification commands:

```
kubectl apply --dry-run=server -f manifests.yaml
kubectl diff -f manifests.yaml
oc adm policy scc-subject-review -f manifests.yaml
```

Never apply anything yourself.

## Hard rules

- `Route` is `route.openshift.io/v1`. `apps.openshift.io/v1` is `DeploymentConfig`, deprecated since OCP 4.14.
- `gp3-csi` and `gp2-csi` are EBS and ReadWriteOnce only. ReadWriteMany needs EFS (`efs.csi.aws.com`), ODF CephFS or
  NFS.
- Never hard-code `runAsUser` on OpenShift or ROSA: `restricted-v2` assigns UIDs from the namespace range.
- Never bind `cluster-admin` to an application ServiceAccount, and never use an RBAC wildcard in a Role written for one
  workload.
- A `ReadWriteMany` volume mounted by more than one writer needs the application to tolerate it. Most do not.

## What this skill cannot do

It cannot validate against bundled schemas, run the rule engine, generate audited manifests or run the red team
mechanically. Those are kube-noob's tools, which run the same seven steps and return the findings with rule ids:

```
pip install kube-noob
kube-noob protocol --help
kube-noob audit -f manifests.yaml --platform openshift --version 4.20
kube-noob validate -f manifests.yaml --platform openshift
kube-noob redteam -f manifests.yaml
kube-noob fix -f manifests.yaml
```
