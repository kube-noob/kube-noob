# The adversarial corpus

Sixteen Kubernetes and OpenShift manifests built for one purpose: to make a scanner under-report. Beside each one
is `honest-answer.yaml`, which records what the object is, what the honest answer to it is — the verdict word and
the exit code — and one sentence on the mechanism by which a tool that does not model its own incompleteness would
report less than is there.

Every case is a shape kube-noob has **measured**, not one anyone reasoned about. Each was reproduced with the real
CLI before it was written down, and `scripts/corpus_run.py` reproduces all sixteen on demand.

## There is no scoreboard here, on purpose

This directory holds no table of what any other tool does, names no competitor and makes no claim about anyone
else's behaviour: a league table invites an argument about the table, while a reproducible corpus invites you to
run it yourself and find out — which is the only form of this claim you have any reason to believe.

## Run it against kube-noob

```bash
python scripts/corpus_run.py
```

It drives the real CLI over every case as a child process, reads each command's own verdict word out of that
command's own output, and fails when an answer is not the recorded one — so the corpus is also a regression suite.
It reads no clock, no network and no cluster, and it runs each case twice to check that the same files give the
same bytes. `--case <id>` runs one.

## Run it against the tool you already use

Each case is a directory. `manifests/` (or, for case 06, `before/` and `after/`) is the input; point your scanner
at it and compare what it tells you with `honest-answer.yaml`:

```bash
cd corpus/08-a-pod-spec-at-a-path-the-reader-does-not-walk
cat honest-answer.yaml
```

What to look for is not whether your tool uses the same words. It is whether the answer **distinguishes an absence
from a pass**: whether the object that was not read is named, whether a count that could not be computed is
presented as a zero, and whether the process exit status lets a CI job tell "nothing found" from "nothing looked
at". Most of these inputs hold a privileged container, a host mount or a cluster-admin binding that a reader
can miss entirely; where your tool reports no findings and exits 0 on one of them, that is the answer the
case was built to get, and the `mechanism` line says how it got there.

## What a record says

```yaml
id: 08-a-pod-spec-at-a-path-the-reader-does-not-walk
object: "..."            # what is in the fixture
mechanism: "..."         # how a tool that does not model incompleteness under-reports it
setup: [...]             # commands run first, when the case needs two snapshots (case 06 only)
honest:
  command: [...]         # argv after `kube-noob`, run with the case directory as the working directory
  verdict: incomplete    # the word the command itself publishes
  exit_code: 1           # the published exit-code contract (see AGENTS.md)
  must_name: [...]       # what the answer must name; an unread object that is not named is the defect
also: [...]              # further measured assertions for the same fixture
open_defect: {...}       # an answer measured here that the maintainer does not call honest, with its G-row
```

`{tmp}` in an argv is a directory the runner makes for that case and removes afterwards.

## If a record and the tool disagree

**The tool is what is wrong until proven otherwise, and the record is not edited to match it.** A recorded honest
answer that nobody observed is the defect this product exists to refuse, committed into its own corpus; an expected
answer quietly adjusted to whatever the code now does is the same defect with a cleaner diff. Where a measured
answer is one the maintainer does not call honest and has not fixed, it is recorded under `open_defect` with the
`docs/guidance.md` row that holds the measurement — printed by the runner, asserted by nothing, so the commit that
fixes it does not have to fight the corpus.

## The cases

| # | Case | Honest verdict | Exit |
|---|---|---|---|
| 01 | a name that forges output | failed | 1 |
| 02 | a kind under a group the rules do not know | incomplete | 1 |
| 03 | cluster-admin under a near-miss group | incomplete | 1 |
| 04 | a misgrouped cluster network policy | incomplete | 1 |
| 05 | a refused object beside a readable one | incomplete | 1 |
| 06 | an object that stops being readable | undetermined | 1 |
| 07 | a container past the two hundredth item | incomplete | 1 |
| 08 | a pod spec at a path the reader does not walk | incomplete | 1 |
| 09 | a Rollout with a privileged container | incomplete | 1 |
| 10 | duplicate YAML keys | failed | 1 |
| 11 | anchors and aliases | failed | 1 |
| 12 | apiVersion skew on a known kind | failed | 1 |
| 13 | host-namespace flags in an operator CRD | incomplete | 1 |
| 14 | a Service with no selector | incomplete | 5 |
| 15 | a duplicate key on the wrapper around a refused object | incomplete | 1 |
| 16 | a zero beside an endpoint nothing resolved | incomplete | 5 |

This table is generated by nothing and is the one place in this directory that can go stale; `honest-answer.yaml`
is the record, and `tests/test_the_adversarial_corpus.py` holds the table to the records.

## Nothing here is real

Every name, image digest, API group, address and hostname is invented. `example.com`, `example.invalid` and
`203.0.113.0/24` are reserved for documentation (RFC 2606, RFC 6761, RFC 5737). There is no credential, no token
and no real organisation's name in this directory, and `tests/test_the_adversarial_corpus.py` fails if one appears.
