# Open questions, for an external reviewer

[ideation-review.md](ideation-review.md) records what three external reviews proposed and what this project
decided. This file is its forward-facing twin: the decisions that are **still open**, written so a reader with no
prior context can argue with them.

It is written to be pasted whole into another model or handed to a person. Every number in it was read off the
code or the repository on 2026-11-08 at `v0.9.2`, not recalled.

**How to answer usefully.** Disagree with the sequence, the trade-offs or the framing. Do not propose a list of
new checks: about 250 were proposed in the last round, five survived, and the refusals are recorded with reasons
in [ideation-review.md](ideation-review.md). The useful contribution is judgement on the five numbered questions
at the end, not coverage.

## What the thing is, in ten lines

kube-noob is an offline-first rulebook for Kubernetes, OpenShift, ROSA HCP, Helm and RHACS that an AI calls as
tools. It has **no AI inside**: the model does the talking, kube-noob supplies the rules, the read-only steps and
the sources, and returns the same answer every time. It ships as a CLI, an MCP server, a Claude Code plugin, an
Agent Skill, a kubectl plugin, a Helm chart, an admission webhook and a container image. Apache-2.0.

The single defect class it exists to refuse: **an absence, an unknown, or an unrecognised shape read as a pass, a
zero, or "every port".** Verdicts are three-valued. A wrong ALLOW is far worse than a wrong DENY. The HTML report
is the one artifact that leaves the terminal, and it opens with how much of the run reached *no* verdict, because
every other scanner reports only what failed and a reader who sees only that cannot tell a clean cluster from an
unexamined one.

## The non-negotiables

These are not up for review. They are listed so a reviewer does not spend effort on proposals that will be
refused, and the reasons are in [ideation-review.md](ideation-review.md).

- No credential this tool has promised not to hold. It never reads Secrets' contents.
- No runtime telemetry claimed by a static reader.
- No writes to anyone's cluster. Read-only, always.
- No AI inside. A bundled model would make answers non-deterministic and the tool unauditable.
- Offline by default. Network and cluster access are opt-in, per-surface.

## The plan as it stands

**Correctness first, moat second.** Between 2026-11-02 and 2026-11-08 nothing moved a moat item: it was all
correctness, four adversarial passes, 49 defects, and eight guidance rows (G259-G266). The roadmap's own principle
says that is the right order, but it means the differentiating work has not started.

The queue, reconciled against the code on 2026-11-11: **24 shipped, 6 partial, 27 not started.**

Sequence, with what each already has:

1. **GOV3** three missing: a named `corpus pack` entry point, `corpus import --verify`, signing instructions.
2. **I1** Alertmanager receiver, the forwarders. The per-alert report, its storage and the receipt-to-report clock
   shipped on 2026-11-11 (G274), so *alert to evidence pack in a minute* is now a measured number (p95 23 ms for the
   bundled payload here, 5.7 s for the review's worst 500-alert payload, a 30 s budget per post). Left: posting the report on to chat or ITSM (tier W), and whether a
   report should ever read the cluster.

I2 (CI surfaces) shipped on 2026-11-11: `audit --format sarif`, NIST controls on the SARIF rules, and both SARIF
outputs validated against the vendored OASIS schema. E2 (installed-operator inventory) shipped the same day:
`operators inventory` over manifests, a must-gather or the cluster, which unblocks E1, R5 and the upgrade pre-mortem.

V3 (blast radius) shipped on 2026-11-11: `posture reach` anchors on the one workload object named, `--format json|yaml` is a capped,
schema-held graph whose undetermined legs are nodes, `--format mermaid` draws it, and `posture_reach` /
`cluster_posture_reach` serve it over MCP (G273).

## The proposals, with what exists today

| Item | Proposal | What already exists |
|---|---|---|
| **R2** | Certificate expiry from TLS Secrets and Routes in a bundle | Nothing reads a `notAfter`. Needs `cryptography` as a **new runtime dependency** |
| **N13** | Caller identity in audit records, and reading as the caller | Authorization is one shared bearer token; the server keeps no per-request audit record |
| **N1** | Compliance Operator results reader | `compliancecheckresults` and `rules.compliance.openshift.io` are namespaced, non-secret, get/list; their `Rule` CRs carry NIST, CIS, SRG and PCI annotations |
| **N2** | Must-gather node configuration | A standard must-gather carries every rendered `MachineConfig`: `kubelet.conf`, kernel arguments, `fips`, CRI-O config, signature policy |
| **N8** | API-server configuration from a must-gather | TLS profile, audit policy, effective arguments. Field stability across 4.x needs a real bundle first |
| **N10** | DRA: a `deviceClassName` naming no known class | Four rules already cover what a manifest proves |
| **R5** | Operator and add-on vulnerability surface | Shipped as a lookup (G278): `operators issues` lists the release-note issues that name or mention each operator for the cluster's release, for Red Hat's builds, and never decides whether the installed version has the fix. It is not a gate. Open: the join through the local Jira copy (components, fix and affects versions per ticket, `tickets.py`; projects in `jira_catalog.DEFAULT_PROJECTS`), which is the step that would answer for operator versions |
| **R6** | Admission sees pod specs inside operator CRDs -- policies half | The webhook runs the audit and finds them; the generated policies do not. Needs a kind job |
| **P10** | Host-networked pods selected by policies the spec says cannot select them | Found red-teaming P4. Changes shared v1alpha1 primitives, so deliberately not folded in |
| **M6** | `net verify`: policy says allowed, packets say dropped | The roadmap calls this "the insurance on the policy wedge". Needs an OVN cluster to validate |

Release-pipeline hardening, found by an adversarial pass over `release.yml`, none blocking but each makes the
next failure worse: `demos` sits in `github-release.needs`, so a recording flake after PyPI has published leaves
no release page; `image` pushes before it attests, the opposite order from PyPI; `publish-pypi` lacks
`skip-existing: true`, so a rerun after a partial upload fails; `homebrew` checks out `main` rather than the tag.

## The five questions

**1. Is `cryptography` worth it?** R2 (certificate expiry) was asked for by all three external reviews and
nothing in the codebase reads a `notAfter`. It needs a C-extension crypto dependency in a tool whose pitch is
offline-first, auditable and small. Is there a stdlib-only path that is honest about what it can parse, or is the
dependency simply the right call? What would you weigh?

**2. Should N13 outrank the entire moat queue?** Caller identity is ranked first by the FedRAMP High requirements
and by every multi-tenant reviewer. Today authorization is one shared bearer token and the HTTP server keeps no
per-request audit record at all. The counter-argument is that the moat items are what make the product
*different*, and identity is what makes it *adoptable*. Which failure is worse: a differentiated tool nobody can
deploy in a regulated environment, or a deployable tool with no moat?

**3. Is I1 the right north-star proof, or a distraction?** The claim is *alert to evidence pack in a minute*, and
I1 (Alertmanager receiver; its report and clock shipped 2026-11-11) is what makes it measurable. But the roadmap itself calls M6 (`net verify` -- policy
says allowed, packets say dropped) "the insurance on the policy wedge", and M6 is the harder, more defensible
thing. Which should be built first, and does proving the north-star claim matter if the wedge is unproven?

**4. Where is the line on "an unknown must not read as a pass"?** Today it costs real usability: three-valued
verdicts everywhere, a report that opens with what was *not* evaluated, a chart guard that refuses to skip. Is
there a point where this becomes noise a reader learns to ignore -- and if so, what is the signal that it has
been crossed?

**5. What is missing that is not on any list?** The last round produced 250 proposals and five survivors, which
suggests the lists are not the constraint. If you were to kill one shipped feature to fund one unbuilt thing,
which pair, and why?

## Reading list for a reviewer

- [roadmap.md](roadmap.md) -- the program, the moat backlog reconciliation, the riskiest assumptions
- [ideation-review.md](ideation-review.md) -- 250 proposals, five survivors, the refusals with reasons
- [guidance.md](guidance.md) -- every defect this project has made, what it cost and the test that holds it
- [limits.md](limits.md) -- what it refuses to claim
- [editions.md](editions.md) -- what is enterprise-candidate rather than core
- [safety-contract.md](safety-contract.md) -- the invariants, checked by a script on every run
