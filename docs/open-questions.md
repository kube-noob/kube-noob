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
| **N1** | Compliance Operator results reader | **Shipped** as `kube-noob compliance results` (G323), and without the live read this row assumed: it reads files and must-gathers only, so it needs no credential. See [roadmap.md](roadmap.md) |
| **N2** | Must-gather node configuration | A standard must-gather carries every rendered `MachineConfig`: `kubelet.conf`, kernel arguments, `fips`, CRI-O config, signature policy |
| **N8** | API-server configuration from a must-gather | TLS profile, audit policy, effective arguments. Field stability across 4.x needs a real bundle first |
| **N10** | DRA: a `deviceClassName` naming no known class | Four rules already cover what a manifest proves |
| **R5** | Operator and add-on vulnerability surface | Shipped as a lookup (G278): `operators issues` lists the release-note issues that name or mention each operator for the cluster's release, for Red Hat's builds, and never decides whether the installed version has the fix. It is not a gate. Open: the join through the local Jira copy (components, fix and affects versions per ticket, `tickets.py`; projects in `jira_catalog.DEFAULT_PROJECTS`), which is the step that would answer for operator versions |
| **R6** | Admission sees pod specs inside operator CRDs -- policies half | The webhook runs the audit and finds them; the generated policies do not. Needs a kind job |
| **R8** | A permissive SCC whose own `users`/`groups` name everyone | `KN-S019` reports the SCC, `KN-S028` RBAC bindings to everyone, attack paths one ServiceAccount at a time; no single audit finding for the SCC's own subject list |
| **P10** | Host-networked pods selected by policies the spec says cannot select them | Found red-teaming P4. Changes shared v1alpha1 primitives, so deliberately not folded in |
| **M6** | `net verify`: policy says allowed, packets say dropped | The roadmap calls this "the insurance on the policy wedge". Needs an OVN cluster to validate |

Release-pipeline hardening, found by an adversarial pass over `release.yml`, none blocking but each makes the
next failure worse: `demos` sits in `github-release.needs`, so a recording flake after PyPI has published leaves
no release page -- and from 0.10.0 that release page is also where krew's archive lives, so the krew-index manifest
points at nothing; `image` pushes before it attests, the opposite order from PyPI; `homebrew` checks out `main`
rather than the tag, which is what that job needs (it commits the formula onto `main`) and which also means it runs
`scripts/brew_formula.py` from `main` rather than from the tag. `publish-pypi` lacking `skip-existing: true` is
fixed: it is set, so a rerun after a partial upload is a no-op rather than the failure that skips every job behind
it.

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

## Answered from outside, 2026-11-21

**Question 4 got an answer, and it was the same answer twice.** Two external reviews were run independently on the
same summary of this product. Both located the same gap, and both located it where the code was, not where the
prose was.

- One argued that three-valued verdicts cannot survive contact with the tooling that consumes them: "every
  commercial platform and most open-source aggregators collapse results to pass/fail/severity. An 'undetermined'
  state has no column. It is either dropped or mapped to 'pass' or 'info.' The honest signal is destroyed at the
  first hop."
- The other, reviewing the repository, wrote a release blocker in the same words from the other direction: "No
  evidence laundering: SARIF, OSCAL, HTML, MCP, and agent summaries cannot upgrade an incomplete result into a
  pass."

Checked against the code rather than argued with, and they were right about `audit --format sarif`: the
unevaluated rules reached `toolExecutionNotifications` and never `runs[].results`, so a code-scanning upload read
`12 alerts` and nothing about fifty-five rules that had no verdict (G328, fixed). So the answer to question 4 is
not "is three-valued output noise" -- it is that **the line is not at the verdict, it is at every hop the verdict
takes**, and each hop has to be checked by running it rather than by reading the renderer. The remaining hops that
have not been checked this way: OSCAL, the HTML report, the Markdown job summary, the GitHub Action's own outputs,
and what an MCP client's model does with `undetermined` in its final answer to the user.

The market claims in both reviews (which scanners dominate, how large the air-gapped segment is, what a given
acquisition proved) are unverified here and are not treated as findings.

**Two `kind` conventions now live in `gate.py`, and one of them should probably change.** The gate's undetermined
result omits `kind`, which SARIF defaults to `fail`, so an incomplete gate reads as a failure result; `notAudited`
and the two coverage rules added in G328 use `kind: "review"`. The second is the more correct reading of the
format, but changing the first would lower the severity an existing consumer sees for an incomplete gate, which is
a deliberate decision and not a tidy-up. Related and unresolved: SARIF's prose on whether `level` must be `none`
whenever `kind` is not `fail` was not read (the spec page was not fetched), and the vendored schema does not
encode the constraint, so `kind: "review"` with `level: "note"` validates. If the prose does require it, every
`kind: review` result in this file is non-conforming and a strict validator in someone's pipeline would reject the
document -- which would be the same class of first-hop failure all over again.

## Proposed and not built, 2026-11-22: one file per guidance row

This one is about the repository's own record rather than the product, and it is here because it is a decision
and not a tidy-up. **Nothing below is implemented.** Every number was read off the tree at `981cd9f` on 2026-11-22.

**What it is today.** [guidance.md](guidance.md) is one append-only table: 310 rows, G01 to G343, 542 KB, the
longest single row 29,712 characters. Every behaviour change appends one row to its end.

**What that has cost, four separate ways.**

- *Every open branch conflicted on it whenever another merged*, because each appends at the same line. That was
  fixed by `merge=union` in `.gitattributes` (G297).
- *The fix writes rows twice.* Union cannot conflict, so when both sides carry the same row in differing hunks it
  keeps both and reports nothing. Twice in one session: G335 once, then six rows at a time with three changelog
  bullets. Now named by a test (G347), which is a detector for a defect the format keeps producing.
- *Two branches take the same number.* The next number is "the highest one there, plus one", read from whatever
  `main` the branch was cut from, so concurrent branches pick the same one by arithmetic. On 2026-11-21 G340 went
  to two branches at once and the later became G345, in a follow-up commit, because a number is cited from test
  names, changelog bullets and commit messages, and a citation that resolves to two rows resolves to neither.
- *A row in the wrong shape is not read.* `tests/test_guidance.py` finds rows with a three-column expression. Six
  rows (G279, G319-G322, G325) are written in two columns with their citations inline, so no citation in them has
  been checked since they were written. They happen to resolve today. Nothing would say if they stopped.

**The proposal.** One file per row, `docs/guidance/G0346.md`, each holding the rule, the prose and an
`Enforced by` list. A twelfth generator, `scripts/guidance_table.py`, writes the table in `docs/guidance.md` from
those files and has a `--check` form like the other eleven.

- *Allocation.* The filename is the claim on the number. Two branches that both create `G0346.md` with different
  contents produce an add/add conflict: git stops, and the pull request reads `dirty`. That is the same collision
  as today, made loud at the merge instead of silent through it. It does not stop two branches choosing the same
  number, and the later one still has to renumber everywhere the number is cited; what it removes is the case
  where nobody is told.
- *Duplicates.* A stacked branch that carries a row `main` already has carries an identical file, which merges to
  one file. The repeated-row defect stops being detected and starts being impossible.
- *The table.* Generated, sorted by number, so its lines are rewritten rather than appended and it would have to
  leave the union list (`tests/test_merge_attributes.py` holds that list to exactly the append-only files). It
  would then conflict on every merge the way `docs/roadmap.md` does, resolved by running the script. The
  alternative is to stop committing the table and leave `docs/guidance.md` as a page that points at the directory,
  which costs the one-page read that the README links to.
- *The existing check.* `test_every_rule_has_existing_checks` would read the files instead of matching lines: one
  id per file, taken from the filename and required to match the heading inside; a file with no `Enforced by`
  entry fails by name instead of being skipped as a line that did not match. The duplicate-id assertion and the
  guidance half of `tests/test_append_only_duplicates.py` would go; the changelog half stays, because
  `CHANGELOG.md` is still merged by union.

**What the migration costs.**

- One commit that splits 310 rows into 310 files. It has to be mechanical and provable: the acceptance test is
  that the generator, run on the new files, reproduces today's table byte for byte before anything is reordered.
  The six two-column rows have to be given an `Enforced by` list by hand, and some of what they cite is shorthand
  (`::test_name` with the file implied) that has never had to resolve.
- Every pull request open at that moment (5 on 2026-11-22) conflicts once and has its row moved into a file. So it
  is done with the queue empty or not at all.
- Citations. Inside this repository the table is cited by number, not by line: 1,661 mentions of a `G<n>` in 224
  files outside the table, and those survive. One link names the file by URL (the README, to
  `blob/main/docs/guidance.md`), and survives if the table stays committed. No link in this repository carries a
  line anchor. Links from outside it were not measured and cannot be from here: anything that points at a line of
  `guidance.md` on `main` -- the site, an issue, a review comment -- breaks once, when rows that are in merge order
  today (G320 sits above G319) become sorted. A permalink to a commit is unaffected.
- `git blame` on a row restarts at the migration commit. The history before it is in the old file.

**The case against.**

- 310 small files today, and the table grew by 46 rows between `v0.9.2` (2026-11-08) and 2026-11-22. A directory
  that gains three files a day is its own cost: GitHub's listing truncates at 1,000 entries, which at that rate is
  about seven months away.
- `git log -p docs/guidance.md` currently reads as this project's lessons in the order they were learned, in one
  place. Across several hundred files the same question needs `git log -- docs/guidance/`, and the answer is
  interleaved with every edit to every row.
- A twelfth generator is a twelfth thing to re-run. `sync_plugin_server` and `doc_numbers` are already the two
  that a change most often leaves stale, and this one would be stale after *every* change, by construction.
- The cheaper position is the current one. Three of the four costs above now have a test standing on them
  (G297, G347), the fourth is a six-row repair, and what remains is renumbering when two branches collide -- which
  the proposal makes louder and does not prevent. "One pull request at a time", which [AGENTS.md](../AGENTS.md)
  already asks for, prevents it outright and costs nothing to build.

**What would decide it.** Whether more than one branch is going to be open at a time as a matter of course. If
the rule is one pull request at a time and it holds, this is a migration to fix a problem the rule already
prevents. If several agents are going to work in parallel worktrees -- which is what happened on 2026-11-21, and
is how all four costs were found in two days -- then the table is a single line every one of them writes to, and
a detector per failure mode is the more expensive design.

## Reading list for a reviewer

- [roadmap.md](roadmap.md) -- the program, the moat backlog reconciliation, the riskiest assumptions
- [ideation-review.md](ideation-review.md) -- 250 proposals, five survivors, the refusals with reasons
- [guidance.md](guidance.md) -- every defect this project has made, what it cost and the test that holds it
- [limits.md](limits.md) -- what it refuses to claim
- [editions.md](editions.md) -- what is enterprise-candidate rather than core
- [safety-contract.md](safety-contract.md) -- the invariants, checked by a script on every run
