---
name: rhacs-stackrox
description: >
  Red Hat Advanced Cluster Security (RHACS) and StackRox - Central, Sensor, Admission Controller, Collector, the
  default policies, admission denials from policyeval.stackrox.io, roxctl in CI and the release history (4.10, 4.11,
  5.0). Use when the user mentions RHACS, ACS, StackRox, roxctl, Central, SecuredCluster or a policy violation.
---

# RHACS / StackRox

This skill is knowledge, not tools. It explains RHACS behaviour and reads a denial the user pastes.

## Components

Central (the UI, the API and the policy engine), Scanner, and per-cluster: Sensor, Admission Controller and Collector.
Collector is the only one that needs privileged access, because it reads kernel events.

## Why a policy did or did not block

- Deploy-time policies are evaluated by the **`policyeval.stackrox.io`** webhook. A denial naming that webhook is RHACS,
  not Kyverno, not Gatekeeper, not an SCC.
- **Only policies with enforcement enabled block admission.** The default deploy policies are inform-only, and several
  are disabled out of the box, so "RHACS is installed" does not mean "RHACS is stopping this".
- Runtime policies cannot block admission at all. If the user expects a runtime policy to have prevented a deployment,
  that is the misunderstanding to correct first.
- Reproduce a deploy-time check without applying anything: `roxctl deployment check --file manifest.yaml`.

## Versions

4.10.0 shipped 2026-03-03 and 4.11.0 on 2026-06-12. **The next release is 5.0; there is no 4.12.** From 4.9 onward the
SecuredCluster CR uses `admissionControl.enforce` in place of `enforceOnCreates` and `enforceOnUpdates`.

## In CI

`roxctl` needs an API token and the Central endpoint. Fail the build on policy violations with
`roxctl deployment check --file manifest.yaml` and let image checks run against the registry, not against a local
build, so the result matches what the cluster will see.

## What this skill cannot do

It cannot validate a Central or SecuredCluster custom resource against the bundled operator CRD schemas, compare an
RHACS policy export against kube-noob's rules to find the gaps, or search the local copy of public ROX Jira issues.
Those are kube-noob's tools:

```
pip install kube-noob
kube-noob validate -f securedcluster.yaml
kube-noob rhacs compare -f policies.json
kube-noob ticket ROX-12345
```
