---
name: helm-charts
description: >
  Helm 3 and Helm 4 charts - structure, values.schema.json, templating, releases, rollback and the common failures
  ("another operation is in progress", ownership metadata, "no matches for kind"). Use when the user asks to create,
  review, debug or upgrade a Helm chart or release.
---

# Helm

This skill is knowledge, not tools. It can explain a chart and read one the user pastes; it cannot render or audit one.

## Versions

Helm 4.0.0 shipped 2025-11-12, and Helm 3 and 4 minors now release together. An `apiVersion: v2` chart works with both.

## Chart structure that survives review

- `values.schema.json` is the cheapest correctness win in a chart: it turns a typo in `values.yaml` into an error at
  install time instead of a Deployment with an empty image. Write one.
- Template the namespace nowhere. Let `--namespace` decide it, or the chart cannot be installed twice.
- Never put a secret value in `values.yaml`, including as a default to be overridden.
- Guard every optional block with `if`, and quote every templated string that could parse as a number or a boolean:
  `{{ .Values.tag | quote }}`.

## Release failures and what they mean

| Message | Cause | Fix |
| - | - | - |
| `another operation (install/upgrade/rollback) is in progress` | a previous operation was interrupted and the release is stuck `pending-*` | `helm history <rel>`, then `helm rollback <rel> <last good revision>` |
| `invalid ownership metadata` | the object already exists and was not created by this release | adopt it with the `meta.helm.sh/release-name`, `meta.helm.sh/release-namespace` annotations and the `app.kubernetes.io/managed-by: Helm` label, or delete it |
| `no matches for kind "X" in version "Y"` | the API was removed in this cluster's version, or the CRD is not installed | migrate the manifest to the current API, or install the CRD first |
| an upgrade that reports success but changes nothing | the rendered output is identical | `helm template` both revisions and compare, or install the `helm-diff` plugin |

## In CI

```
helm lint --strict
helm template . | kubectl apply --dry-run=server -f -
helm upgrade --install --atomic --wait --timeout 10m
```

`--atomic` rolls back on failure, which is what you want in a pipeline and not what you want when you are trying to see
why it failed: drop it when debugging.

## What this skill cannot do

It cannot generate a chart, audit rendered output, or diagnose a release error from its text. Those are kube-noob's
tools:

```
pip install kube-noob
kube-noob helm-chart --name orders-api --image registry.example.com/orders:1.4 --platform openshift
kube-noob helm-audit ./mychart --platform openshift
helm template . | kube-noob audit -f - --platform openshift
kube-noob diagnose -f helm-error.txt
```
