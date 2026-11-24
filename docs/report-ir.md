# The report needs a coverage ledger, and the renderers should project it

Status: a finding and a proposal, 2026-11-23. The measurement is reproducible with the commands in the last
section; the proposal is for the maintainer to accept, change or refuse. **The DATA MODEL below is superseded**:
"The ledger as specified above cannot carry this" records the object-keyed shape's own counterexample, measured in
this repository, and the obligation-keyed correction. The finding, the measurement and the landing order still
stand; read the minimal shape as the smallest thing that would have caught the defects of G343, G363 and G366, and
not as the schema to build.

## The finding in one paragraph

A kube-noob report records what a rule could NOT do (`notEvaluated`, `declined`, `notAudited`, `unreadable`,
`skipped`) and never what it DID read. "Clean" is therefore not a recorded fact. Every consumer derives it by
subtraction -- the rules that ran, minus the rules with findings -- and a rule "ran" as soon as one object gave it a
subject. So when an input holds clean objects AND one object nothing read, every derived figure is computed over a
denominator that silently excludes the unread object, and comes out byte-identical to the figure for the clean
objects alone. The verdict word is right (`undetermined`, `incomplete`, exit 1 or 5). The numbers beside it are not.

G343 fixed this for one renderer and one cause (OSCAL, an unreadable file). G363 fixed it for two renderers and a
second cause (OSCAL and `red_team`, an unaudited object), by passing the unread list into each and overriding the
result. This document counts what is left, and the count is the argument: the same patch is owed in at least nine
more places, and a tenth renderer written tomorrow would be wrong on its first day, because the report still gives
it a `clean` it has to trust.

## The measurement

Input: a hardened Pod and its default-deny NetworkPolicy (the suite's clean fixture), with and without a Tekton
`Task` carrying a privileged `docker:24-dind` step beside them. The Task is in a kind with no reader, so no rule
read it. Run through the real CLI on `main` at `f3014519` (0.10.0 plus receipts), and again with G360/G363 applied.

| Surface | Figure it states | Clean input | Mixed input | Kind |
|---|---|---|---|---|
| `audit --format json`, `gate --format json`, `validate`, MCP `audit_manifests` | `controlSummary.controls[].clean`, summed | 88 | 88 | (c) per-control record |
| `audit` text | `rules: 42 evaluated, 56 not evaluated`; `(N clean)` on 19 control lines | same | same | (b) and (c) |
| `gate --summary` (Markdown) and `gate --html` | `42 rules evaluated, 56 not evaluated` (`controls.coverage_line`) | same | same | (b) |
| `ksi --format json`, MCP `fedramp_ksi` | per-indicator `clean`, summed; `withheld: 0`; `evidenced: true` | 190 over 26 indicators | 190 over 26 indicators | (c) |
| `ksi --html` | the tile "31 indicators -- Evidenced and clean: rules ran, nothing open" | 31 | 31 | (b) |
| `audit --receipt`, `gate --receipt` | `payload.scope.controlCoverage.clean` | 88 | 88 | (b), in a document meant to be re-derived by a third party |
| `posture snapshot` | `coverage.evaluatedRules`; stdout `N objects, 0 findings`; `notRead: []` | 42 rules, 2 objects | 42 rules, 2 objects (the input has 3) | (c) and (b) |
| `posture diff` | `Findings: 0 new, N fixed`; the "Control standing" table's Clean column | -- | see below | (c) |
| `posture scan`, MCP `posture_scan` | `workloads: 1`, "0 attack paths from 0 exposures"; exit 0 with `--fail-above` | same | same, with the Task under `notRead` | (b), and (a) at the exit code |
| `vuln threat`, MCP `threat_model` | 5 threats `mitigated` for application `prod` | 5 | 5, with the object under `notRead` | (d) per element, (b) per application |
| `audit --oscal`, `gate --oscal` | objectives `satisfied/pass` | 16 | 16 on `main`; 0 with G363 | (c), fixed by G363 |
| `redteam`, MCP `red_team` | `RT-RESOURCE-STARVATION`, `RT-SUPPLY-CHAIN` | `mitigated` | `mitigated` on `main`; `undecided` with G363 | (c), fixed by G363 |

(a) a renderer that loses the withheld verdict; (b) an aggregate over a denominator it never read; (c) a per-rule,
per-control or per-finding record that says clean, pass, fixed or mitigated where it should say not determined;
(d) correct.

The worst instance is `posture diff`. Snapshot a privileged Deployment (12 findings, one critical), change only its
`apiVersion` to `apps.k8s.io/v1` so that no rule reads it, snapshot again and diff:

    Since ...: 0 added, 0 removed, 1 changed, 2 unchanged. Findings: 0 new, 12 fixed, 0 open.
    ## Fixed findings
    | KN-S001 | Deployment/prod/web | critical | unowned |

The first line of the same report says the verdict is undetermined and names the object. The table under it lists
the critical finding as fixed. Nothing was fixed; the object stopped being read.

The same holds for every position of the unread object (first file, last file, middle of one file), for a refused
`apiVersion` in place of a kind with no reader, for a refused object that is the only subject a rule could have had
(a Service, a ClusterRoleBinding), for an accepted `--skip-unreadable` file beside a refusal nobody accepted, and
for a kind with no reader beside a kind whose reader missed a container. Only the surfaces G363 changed differ.

## What is correct, and should stay as it is

- The verdict word and exit code of `audit`, `gate`, `verify`, `protocol`, `ksi`, the receipts' `verdict` block,
  `receipt verify`, SARIF (`KN-NOT-AUDITED`, `kube-noob/undetermined`), GitLab code quality, the annotations, the
  Markdown and HTML headlines, `insight`'s `skipped` row, and the admission webhook's warning. Each names the object.
- `vuln threat` per element: a threat is recorded against one workload, and `mitigated` on `Pod/prod/ok` is a
  statement about `Pod/prod/ok`.
- `notEvaluated` reasons for a rule whose only possible subject was refused: "1 Service not audited (...)", not
  "no Service in the input". Held by a test since G364.
- The admission webhook: it is sent one object at a time, so it has no mixture to get wrong.

## Why a per-renderer patch is the wrong fix

Count the places that would each need "pass the unread rows in and subtract, or override":
`controls.summary` (the `clean` bucket), `controls.coverage_line` (`len(RULE_CONTROLS) - total`), `cli._print_report`
(its own "rules: N evaluated" line), `fedramp` (per-indicator `clean` and `evidenced`), `report_html` (the indicator
tiles), `receipt` (`controlCoverage`), `drift` (snapshot `coverage`, the diff's `fixed` list, the standing table),
`attack_paths` (summary and exit code), `vuln/threat` (application counts) -- nine, after the two G363 already did
and the one G343 did before it. The repository's own rule for this is review class 25: fix the predicate, not the
call site. There is no predicate to fix, because "clean" is not in the report; each of those nine re-derives it.

Three further reasons the patch repeats rather than converges:

1. **Each patch needs a judgement the renderer is not placed to make.** Which rules does an unread Tekton Task
   withhold? G363 answered "all of them" for OSCAL (no objective is satisfied while a row is open), which is safe
   and coarse. A control table that zeroed every `clean` beside any unread object would be the muted alert: one
   CRD in a repository and the whole table reads "not determined" forever. The precise answer -- the rules whose
   subject kinds the unread object could have been -- is known to the engine at the moment it declines, and to
   nothing downstream.
2. **The unread facts live in five lists with five shapes** (`notAudited`, `declined`, `notEvaluated`,
   `unreadable`, `skipped[].forbidsVerdict`), and `posture` keeps two more of its own (`notRead`, `refused`).
   A refused ClusterRoleBinding is under `notRead` only and `posture scan --fail-above` exits 0; a refused
   Deployment is under both and it exits 5. Every renderer that learns one list has four left to learn.
3. **The conformance suite cannot hold it.** Its two predicates ask whether an output SAYS something was withheld.
   A third predicate -- no figure in this output is computed over a denominator that excludes an unread object --
   needs to know, per renderer, which fields are figures. With a ledger it is one assertion over the ledger and a
   check that each renderer's figures equal a projection of it.

## The minimal shape

One mandatory block on the report, written by the engine, the only place that knows:

```yaml
coverage:
  schema: kube-noob.coverage/1
  objects:                      # one row per object or file the input held: the denominator
    - ref: Pod/prod/ok
      file: pod.yaml
      state: read               # read | partly-read | not-read
    - ref: Task/ci/build
      file: a-task.yaml
      state: not-read
      why: pods are in a kind kube-noob has no reader for     # a fixed phrase, never input text (class 7)
      acceptedBy: null          # or the exception / --skip-unreadable that accepted it
  rules:                        # one row per rule in the rule set: every rule appears exactly once
    - id: KN-S001
      state: clean              # clean | findings | not-evaluated | not-determined
      read: 1                   # objects of its subject kinds that it read
      unread: 1                 # objects it could have had as a subject and did not read, not accepted
    - id: KN-N004
      state: not-evaluated
      why: no Service in the input
  totals: {objects: 3, read: 2, notRead: 1, accepted: 0}
```

Three invariants, each one test:

- **Closed world.** Every rule in the rule set has exactly one row; every object and file `gate.collect` saw has
  exactly one row. A rule with no row, or an object with none, fails the build. This is the property the current
  shape lacks: today the absence of a record means "clean".
- **`clean` is earned.** A rule's state is `clean` only when `unread == 0` (or every unread row is accepted). With
  an open unread subject and no finding it is `not-determined`. `findings` stays `findings`: a finding is a finding.
- **Which rules an unread object touches is decided once.** An object of a known kind under a refused group
  touches the rules that read that kind. A pod spec nothing read (a kind with no reader, a container the reader
  missed) touches every rule that reads a pod spec. An unparseable file touches every rule. This is the judgement
  in point 1 above, made where the information is.

Everything else is a projection: `controlSummary.clean` counts rules in state `clean`; "N rules evaluated" is
`clean + findings`; an OSCAL objective is satisfied when every rule behind it is `clean`; a `red_team` scenario is
`mitigated` when every rule it rests on is `clean`; a KSI indicator's `clean` is the same count; a snapshot stores
the ledger, and `diff` calls a finding `fixed` only when its rule's state on that object went from `findings` to
`clean`, and `not determined` when the object's state went to `not-read`. `open_not_audited`, `open_unread` and
`forbids_verdict` become readers of the ledger and then disappear into it.

It adds no dependency and no new concept to the CLI: it is the report saying, once, what G343 and G363 each
taught one renderer to work out.

## What should land first

1. **The ledger, additive, with the closed-world test and nothing reading it.** `coverage` appears in the report
   beside the existing keys; no renderer changes; every existing figure is unchanged. The only new assertions are
   the invariants above, over the conformance fixtures. This is the step that can be reviewed on its own, and it
   is where the "which rules does this object touch" decision is made and argued.
2. **`controls.summary` reads the ledger.** This one change moves `clean` in `audit`, `gate`, `validate`, the MCP
   tools, the text view, the receipt and KSI together, because they all read `controlSummary`. Expect documented
   figures to move; `scripts/doc_numbers.py` and `tests/test_absent_kinds.py` are where they will show.
3. **The third conformance predicate**, `figures_agree_with_the_ledger`, per adapter, on the mixed fixtures. From
   here a renderer that derives its own figure fails the matrix.
4. **`drift`**: the snapshot stores the ledger; `fixed` requires `findings -> clean`. This is the worst lie in the
   table and it is deliberately not first, because fixed in place it is a tenth copy of the subtraction.
5. **OSCAL and `red_team` drop their `unaudited` / `not_audited` parameters** and read rule states. G363's tests
   stay as they are and must still pass: that is the check that the ledger means what the patches meant.
6. **`posture` and `vuln threat`** fold `notRead` / `refused` into object rows, which also settles why a refused
   binding and a refused workload exit differently.

Until step 2 lands, G363 is the right patch to keep: it makes the two compliance-facing outputs coarse and safe.

## Found on the way, and separate from the above

- **Fixed in the same change (G365).** `policy reach` and MCP `check_network_policy` matched `kind: NetworkPolicy`
  without its group, so a `projectcalico.org/v3 NetworkPolicy` was evaluated as a Kubernetes one and answered
  DENIED while `audit` refused the object. A reader, not a renderer; it now asks `rules.refusal`.
- **Not fixed: a decision.** `gate -f dir/` skips every file under a chart's `templates/` ("a Helm template",
  `forbidsVerdict` false). A refused, privileged Deployment in plain YAML there, beside a clean Pod, gives
  `gate` `passed`, exit 0, "gate passed", 16 OSCAL objectives satisfied and a receipt with `exitCode: 0`; `audit -f`
  on the same directory exits 1 undetermined and `verify -f` exits 5 not-determined. The file is named under
  `skipped` and `notRun`. Whether an unrendered chart forbids a verdict is the muted-alert question G325 recorded
  for "not a Kubernetes manifest", and it is the maintainer's to answer; but three commands giving three answers
  about one directory is a fact, and `verify`'s help says it agrees with `gate`.
- **Not fixed: follows from the ledger.** `posture scan --fail-above` exits 0 beside a refused ClusterRoleBinding
  or a Tekton Task with a privileged step (listed under `notRead`), and 5 beside a refused Deployment or Service
  (listed under `refused` as well).
- **Not fixed: `validate` exits 0 with `summary.verdict: undetermined`** on the mixed input, where `audit` exits 1.

## The ledger as specified above cannot carry this, and that is why it is keyed wrong (G368)

The shape in "The minimal shape" keys coverage by OBJECT, and each rule's row counts the objects of its own
SUBJECT kinds that it read and did not read. That is enough for every defect measured above, and it is not enough
for the one measured next, which is in this repository today:

```
Deployment/prod/web          apps/v1, replicas: 1
NetworkPolicy/prod/dd        projectcalico.org/v3
```

`notAudited` names `NetworkPolicy/prod/dd`, the verdict is undetermined and the exit code is 1. All correct. In the
same report, **KN-N001 fired a MEDIUM finding reading "No NetworkPolicy for namespace prod in this bundle."**, and
five rules recorded `evaluated without networking.k8s.io NetworkPolicy`. Now score those against the ledger:
KN-N001's subject is the workload kinds, it read the one Deployment, it refused nothing of its own subject, so its
row is `read: 1, unread: 0` and its state is `findings`. **Every invariant above holds and the row is a lie.** The
rule's subject is not the evidence it needs: it needs the SET of NetworkPolicies in the namespace, and the thing it
could not read is not one of its subjects.

Eight rules in `src/kube_noob/audit/rules.py` declare that second dependency already, as `context=(...)`, and ten
declare an overlapping version of it as `_PARTNER_KINDS`; the first is never checked against unreadability at all,
and the second only against a malformed shape, never against a refused apiVersion. One question, two declarations,
each checked against a different half of the answer -- class 9, and the reason the ledger must be keyed by the
obligation rather than by the object:

- **Obligations are the primary entity, not objects.** An obligation's evidence is a QUERY over the input ("the
  NetworkPolicies of namespace N", "a PodDisruptionBudget selecting these labels"), declared by the rule and
  resolved by the engine. A row keyed by object has nowhere to record that a query came back incomplete, and a
  namespace with ten Deployments and zero NetworkPolicies produces no candidate object row at all -- so a
  naive aggregation over object rows reports it 100% passing, which is the product's own defect reintroduced by
  its own fix.
- **Coverage, evaluation and verdict stay three dimensions, not one word.** Coverage answers whether the declared
  evidence was read; evaluation whether the rule ran over what was read; verdict what it concluded. Collapsing
  them is what every two-valued scanner does.
- **The composition law is asymmetric, and the asymmetry is the whole point.** For an obligation whose VIOLATION
  is witnessed by one object ("no container runs privileged"), reading more input can only add violations, so
  `violated` is sound on partial coverage and `satisfied` requires complete coverage. For one whose SATISFACTION
  is witnessed by one object ("some NetworkPolicy isolates this namespace"), reading more can only add
  satisfactions, so `satisfied` is sound on partial coverage and `violated` requires complete coverage. KN-N001 is
  the second kind and was being treated as the first. An object-keyed ledger cannot express which kind an
  obligation is, so it cannot check either rule.

What landed for G368 is the join at the granularity the current code has: one `cannot_judge_absence` predicate that
asks whether the input holds an object of a `context` kind that nothing read, per namespace, and makes the rule
undecided with the refusal phrase instead of letting it state an absence. That is the per-rule form of the law
above, and it is the evidence that the declaration belongs in the IR rather than in eight rule bodies.

## Reproducing the measurement

```bash
mkdir -p /tmp/mixed && cd /tmp/mixed
# pod.yaml and netpol.yaml: _HARDENED_POD and _DNS_POLICY from tests/test_renderer_conformance.py
# a-task.yaml: _TEKTON_TASK from the same file
kube-noob --format json audit -f . | python -c "import json,sys; r=json.load(sys.stdin); print(r['summary'], sum(c['clean'] for c in r['controlSummary']['controls']))"
kube-noob --format json ksi -f . | python -c "import json,sys; r=json.load(sys.stdin); print(r['verdict'], sum(i.get('clean') or 0 for i in r['indicators']))"
kube-noob gate -f . --summary /dev/stdout | grep 'rules evaluated'
kube-noob posture snapshot -f . -o snap.json
```

Remove `a-task.yaml` and run them again: the verdict changes and no figure does.
