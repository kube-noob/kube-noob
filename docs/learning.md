# Learning with kube-noob

## The case: a flight simulator for Kubernetes objects

Reading docs teaches the vocabulary. Writing YAML and getting precise feedback teaches the habits. kube-noob closes
that loop offline:

- **Graded by production rules.** Exercises are checked by the 60-rule audit engine and the strict schemas that review
  real manifests. A passing answer is one a platform team would accept.
- **Platform-aware.** The same Deployment is right on Kubernetes and wrong on OpenShift (fixed `runAsUser` against
  `restricted-v2`) or on ROSA HCP (storage class, Routes). Learners see why.
- **Cited.** Lessons and feedback point to credited sources (`[kn:<doc>#<n>]`), so learners know where each rule
  comes from.
- **No cluster, no cloud bill, no network.** It runs on a laptop, in a classroom or on an air-gapped machine.

The curriculum has 6 tracks (Kubernetes, OpenShift, ROSA HCP, Helm, RHACS/StackRox), with 18 lessons, 9 graded
exercises and 15 quiz questions.

## Running a class

```bash
pipx install kube-noob
kube-noob learn tracks --learner alice
kube-noob learn lesson k8s-101-objects --learner alice
kube-noob learn exercise k8s-ex-hardened-deployment
kube-noob learn submit k8s-ex-hardened-deployment -f answer.yaml --learner alice
kube-noob learn progress --learner alice
```

- Each learner earns credits for passing exercises and quizzes. Progress lives in their data directory.
- A submission exits 0 when it passes, so instructors can grade a folder of answers in a script.
- In Claude, the `tutor` prompt runs the same loop conversationally, one concept at a time.
- Running kube-noob as a shared server for a whole class (one deployment, several learners connecting over HTTP)?
  Every caller must pass its own `learner`; the server refuses the CLI's single-user `"local"` default so no
  learner's progress is ever silently shared with another's.

Start with `kube-noob demo learn` to see a full lesson-and-grade cycle in seconds.

## Mechanism walks: what happens, in order, and where it stops

Every other track teaches what to write and what passes. The `mechanisms` track teaches what *happens*, in
order, along one path -- and grades it against your own manifests, offline:

```
kube-noob learn mechanism mech-net-request-to-pod -f ./manifests
```

Each hop gets one of three answers, and the third is why this exists:

- **holds** -- the objects the hop needs are here, and the rules that read them found nothing. The step names
  those rules, so you can check the claim.
- **BROKEN** -- a rule on this hop produced a finding, reported with its id and severity. The walk carries on to
  the end, because a finding is a verdict.
- **cannot judge** -- an object the hop needs is absent, or it is here and nothing could read it. **The walk
  stops.** The hops after it are not drawn and are counted as not walked.

That last rule is the whole point. A `projectcalico.org/v3 NetworkPolicy` in the middle of the path is an object
kube-noob has no reader for; a walk that continued past it would report the readiness hop as working on a path
whose policy hop nobody looked at. So the path's verdict is that no verdict was reached:

| what the walk did | verdict | exit |
|---|---|---|
| every observable hop holds | `complete` | `0` |
| reached the end, a hop is broken | `broken` | `1` |
| stopped at a hop it could not judge | `stopped` | `5` |

`5` and `1` are not two answers to the same question: `1` says the path was walked and something on it is wrong,
`5` says the path was not walked.

A hop whose evidence no manifest can hold -- the veth pair, the bridge, the overlay -- is marked `observable:
false` in the curriculum. It is printed as **not checked**, names no rules, and is never counted as a hop that
holds. kube-noob does not claim to have checked something it cannot see, in a lesson any more than in an audit.

## What kube-noob remembers

kube-noob keeps a small local file, `<dataDir>/learning.json`. By default that is
`~/.local/share/kube-noob/learning.json`, or `/var/lib/kube-noob` in the container with persistence enabled.

| Kept | How it gets there |
|---|---|
| Profile: platform, versions, team conventions | you state it (`kube-noob learning profile`, or the `learning_profile_set` tool) |
| Notes: symptom, cause, fix | only after you confirm a fix worked (`kube-noob learning note`, `learning_note_add`) |
| Counters: which playbooks, rules and platforms come up | automatic; ids only, never content |

It never keeps raw logs, manifests, credentials, cluster objects or conversations. Notes that look like any of these
are rejected.

- **Search.** Notes appear in search results and can be cited as `[kn:local-N#0]`.
- **Training data.** Notes are never exported as training data.
- **Agent context.** The agent adds your profile to its context.

**Upgrade-safe.** The file lives outside the installed package, so upgrading the CLI, the plugin or the image keeps it.
`schemaVersion` migrates older files forward and keeps keys written by newer versions. A file from a newer version
opens read-only. A corrupt file is moved aside, never overwritten.

```bash
kube-noob learning show
kube-noob learning profile --platform rosa-hcp --openshift 4.22 --convention "namespaces are <team>-<env>"
kube-noob learning note --symptom "..." --cause "..." --fix "..."
kube-noob learning forget local-3
```

To turn it off, set `learningEnabled: false` or `KUBE_NOOB_LEARNING_ENABLED=false`. To back it up, copy the file.
