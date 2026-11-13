---
id: kube-noob-cli
title: kube-noob itself - the commands, the CI gate and the exception list
tags: [kube-noob, ci, gate, audit, exceptions]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-11-01
license: Apache-2.0
# A question needs a word of this document's subject: it answers about kube-noob, not about Kubernetes.
requires:
  - [kube-noob, kubenoob]
sources:
  - {title: "kube-noob use cases", url: "https://github.com/kube-noob/kube-noob/blob/main/docs/use-cases.md", license: Apache-2.0}
  - {title: "kube-noob operations", url: "https://github.com/kube-noob/kube-noob/blob/main/docs/operations.md", license: Apache-2.0}
---

## Use `gate` in CI, not `audit`

`kube-noob audit -f <file>` is the interactive command: it prints findings for one input. **`kube-noob gate` is the
CI command**, and it is what belongs in a pipeline. It takes manifests, Helm charts, Containerfiles and scanner
reports together, applies one exception list across all of them, and writes the formats a CI system reads:

```bash
kube-noob gate -f rendered.yaml \
  --exceptions exceptions.yaml \
  --fail-on high \
  --sarif kube-noob.sarif \
  --summary "$GITHUB_STEP_SUMMARY"
```

- `--sarif` writes SARIF 2.1.0 for GitHub code scanning, so findings appear on the pull request's changed lines.
- `--summary` writes Markdown for the job summary; `--codequality` writes GitLab's code quality JSON.
- `--chart <dir>` renders a chart with helm and gates the output, so no separate `helm template` step is needed.
- `--containerfile <path>` audits the image build in the same run.
- `--skip-unreadable` gates the files that could be read and lists the rest under `unreadable` in the report.

## Exit codes are the contract

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | findings at or above `--fail-on` |
| 2 | configuration error, or a file that is not there |
| 3 | clarification needed |
| 4 | a kube-noob error, or refused input |
| 5 | the evidence was incomplete: unreadable files, or `--require-complete` on a partial must-gather |

5 exists so a gate never reads a blind run as a clean one. Never treat 5 as 1: 1 means rules found something, 5
means the rules did not see everything.

## The exception list

Accepted risks are data, not a disabled check. `--exceptions` takes a `kube-noob.io/v1 ExceptionList`:

```yaml
apiVersion: kube-noob.io/v1
kind: ExceptionList
exceptions:
  - rule: KN-S001
    scope: {namespace: arc-runners}
    owner: platform-team@example.com
    reason: "docker-build runner pool needs DinD until the move to rootless builds"
    expires: 2026-12-31
```

An entry hides the findings it covers while it is active. An **expired entry fails the gate**, so an exception
cannot quietly become permanent, and `kube-noob exceptions check` reports the list's state on its own.

## What audit reads, and what it does not

The audit rules read Kubernetes objects: every document needs `apiVersion` and `kind`. A Helm **values** file is not
a manifest and is refused rather than scored — render it first (`helm template … | kube-noob audit -f -`), or pass
the chart to `gate --chart`. `kube-noob insight` is the one command that takes anything: it recognises what the
input is (events, logs, an alert, a denial, a ticket, manifests, a question) and runs the analysers that apply.

## The other commands worth knowing

| Command | What it answers |
|---|---|
| `insight` | "here is some output, what is it and what is wrong" — the router |
| `diagnose` | a pasted error, event or log: the likely cause and read-only next steps |
| `known-issues` | is this a reported OpenShift issue, and in which release is it fixed |
| `policy reach` | can pod A reach pod B — AdminNetworkPolicy, NetworkPolicy and BaselineAdminNetworkPolicy in order |
| `policy explain` | why admission denied this (Pod Security, SCC, Kyverno, Gatekeeper, VAP, RHACS) |
| `upgrade-risks` | the risks Red Hat declares for an OpenShift update, offline |
| `must-gather analyze` | open a must-gather safely; `--require-complete` exits 5 on partial evidence |
| `explain-rule <id>` | what a rule id means, its citations and the controls it maps to |
| `doctor` | what is switched on, and what each capability tier needs |
