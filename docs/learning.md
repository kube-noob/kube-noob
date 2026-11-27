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

The curriculum has 6 tracks (Kubernetes, OpenShift, ROSA HCP, Helm, RHACS/StackRox), with 22 lessons, 9 graded
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
| every observable hop holds, and at least one hop was judged | `complete` | `0` |
| reached the end, a hop is broken | `broken` | `1` |
| found a broken hop, then stopped at a hop it could not judge | `broken`, with `stoppedAt` set | `1` |
| stopped at a hop it could not judge, nothing broken before it | `stopped` | `5` |
| judged no hop at all | `stopped` | `5` |
| every hop it read holds, and the audit of the same input is undetermined | `stopped`, `stoppedAt` null | `5` |

`5` and `1` are not two answers to the same question: `1` says something on the path is wrong, `5` says the path
was not walked far enough to say. A broken hop answers the question by itself -- no hop after it can make the path
work -- so a walk that finds one and then stops is `1`, with the stop named beside it, not `5` (G400).

**The network lesson follows the Ingress to its Service.** Its second hop asks whether every Service an Ingress
backend names is in the namespace, and serves the port the backend names (KN-V024). An Ingress routing to a
Service that is not there, or to port 9999 of one that serves 8080, is BROKEN at that hop when a whole namespace
was passed; on a fragment the missing Service may be in another file, so the hop says **cannot judge**. Before
this hop existed the walk went from "there is an Ingress" straight to "the Service finds pods", and an Ingress
pointing at nothing walked complete (G405).

**A walk judges one namespace, and names it.** A path runs inside a namespace: an Ingress routes to a Service of
its own namespace, and a Service selects pods of its own. The second line of the text view says
`namespace judged: 'shop'`, and the JSON carries `namespaces`. When the objects the path reads are in more than
one namespace the walk does not pick one: the first hop says **cannot judge**, the namespaces are named, and the
exit is `5`. Pass the manifests of one namespace. An object that states no namespace counts as a namespace of its
own, because nothing in the manifest says where `kubectl apply -n` will put it (G404).

**The walk does not say more than the audit of the same files.** Three things stop a hop, or the path, that no
rule on the hop reports (G406):

- an object the hop reads carries a *schema* finding from the validation stage -- a required field missing, a
  duplicate key, a duplicate object. The hop says **cannot judge** and shows the finding, because the object is
  not what the API server would accept as written;
- the input holds a pod spec nothing read (an Argo Rollout, a kind with no reader). Every hop about workloads
  says **cannot judge** and names it, because it may be the workload the hop is about;
- `kube-noob audit` on the same input is `undetermined` for any other reason. The walk is then `stopped` at `5`
  with `stoppedAt` null, never `complete`.

A walk can still be `complete` where `audit` exits `1` on a finding that is not about this path -- an image tag,
a missing `seccompProfile`. The walk answers for one path.

**One file is a fragment, and a fragment cannot show that something is missing.** Pass a directory and the walk
takes it to be the whole namespace; pass one file (or paste text into the `learn_mechanism` tool without
`partial_bundle: false`) and it is part of one. A hop whose only findings rest on an object that is *not* in the
input -- no autoscaler holding a single replica at two, no pod the Service or the NetworkPolicy selects -- then
says **cannot judge** and lists the finding under it, instead of BROKEN: the object may be in the file you did
not pass. The same bytes in a directory are BROKEN. `kube-noob audit` on one file still reports those findings;
only the walk's verdict about the path is withheld (G408).

A hop whose evidence no manifest can hold -- the veth pair, the bridge, the overlay -- is marked `observable:
false` in the curriculum. It is printed as **not checked**, names no rules, and is never counted as a hop that
holds. kube-noob does not claim to have checked something it cannot see, in a lesson any more than in an audit.

That applies to the path as well as to the hop. **A walk that judged no hop answers `5`, however many hops it
drew.** "Every observable hop on this path holds" is vacuously true of a path with no observable hops, and a
lesson marked `observable: false` hop by hop printed exactly that at exit `0` -- a page of green over a walk
that checked nothing (G395). A hop's **title** is also held to what its rules decide: the network lesson's
policy hop says the namespace has a policy that is neither open nor inert, because the rules behind it fire on
an absent, over-permissive or inert policy and none of them can establish that a packet is admitted.

### A Pod calls a Service

```
kube-noob learn mechanism mech-net-pod-calls-a-service -f ./manifests
```

The in-cluster call: the namespace has a policy that is neither open nor inert (KN-N001, KN-N007, KN-N012); no
policy stops the calling pods from reaching cluster DNS on port 53 (KN-N013); cluster DNS answers the Service name,
which is **not checked**; the Service selects pods here and its ports are ones they declare (KN-V011, KN-V012,
KN-V023); the workload owns its pods (KN-V010); the containers declare readiness (KN-C001); and the node sends
the ClusterIP to an endpoint, which is **not checked**. A namespace with no NetworkPolicy is BROKEN at the first
hop and stops at the DNS hop, because KN-N013 has no policy to read (G420).

### A packet meets a NetworkPolicy

```
kube-noob learn mechanism mech-net-network-policy -f ./manifests
```

Six hops, four of them in a manifest: the namespace has a NetworkPolicy (KN-N001); every policy here selects a
pod that is here (KN-N012); the cluster's network plugin turns the policy into rules on each node, which is
**not checked**; no policy carries an ingress rule that is open to every source (KN-N007); the node admits the
packet a rule allows and drops the rest, which is **not checked**; and no policy stops the pods it selects from
reaching cluster DNS (KN-N013). A namespace with no NetworkPolicy is BROKEN at the first hop and stops at the
second, because every later rule has no policy to read.

Read the titles literally here too. Measured before the lesson was written (G421): KN-N012 is silent about a
workload that no policy selects, KN-N007 is silent about a rule that names ports and no `from`, and no rule
compares a policy's ports with the ports the containers declare -- a policy naming port 9999 in front of a
container on 8080 is nobody's finding. The hops say so in their own sentences, and none of them says a packet
gets in: a default-deny walks `complete`, because a policy is here, it selects pods and no rule in it is open.

### Deploy an app

```
kube-noob learn mechanism mech-cp-deploy-an-app -f ./manifests
```

Nine hops from the manifest to a pod that is ready, five of them in the manifest: nothing here is refused for
its identity, its API version, its selector or a request above its limit (KN-V001, KN-V002, KN-V005, KN-V009,
KN-V010, KN-C006); every container declares the CPU and memory it asks the scheduler for (KN-C004); every
ConfigMap, Secret, claim and ServiceAccount a pod names is in this namespace (KN-C017); every container names
its image by digest (KN-S012); and the containers declare a readiness probe (KN-C001). The four between them --
the API server admitting and storing the object, the controllers creating the pods, the scheduler binding one,
the kubelet starting it -- are **not checked**, because a running cluster decides them.

Pass a directory. A single file is part of a namespace, so a name it does not define is not a missing object:
KN-C017 declines, and the walk stops at that hop at exit 5 instead of calling it found. It stops the same way
when a pod names a Secret and the bundle defines no Secret at all, since an operator may create it. A pod
template with `containers: []` walked `complete` when this lesson was written (G422); the schema stage now
reports a pod spec with no regular container (KN-V007, G431), init and ephemeral containers not counted, and
no hop that reads the workload holds beside it.

### RBAC and ServiceAccounts

```
kube-noob learn mechanism mech-sec-rbac-and-serviceaccounts -f ./manifests
```

Six hops a manifest can answer for, and one it cannot: no pod spec leaves the automatic token mount on (KN-S014),
no binding names everyone (KN-S028) or the `cluster-admin` role (KN-S016), no Role or ClusterRole uses a wildcard
(KN-S015) or carries a grant KN-S017 lists as an escalation path, no Secret is a long-lived ServiceAccount token
(KN-S027) -- and then the API server authorizes the request, which is **not checked**, because the authorizer
chain and the roles of the live cluster are not in a manifest.

Read the titles literally. Each rule reads every object of its kind **in the input**; none of them joins a pod
to its ServiceAccount, a ServiceAccount to its bindings, or a binding to the role it names. A binding to the
built-in `admin` ClusterRole, which no manifest carries, leaves the Role hops holding on the roles that are
here and saying so -- the walk never states what a ServiceAccount can do. And every one of these rules was
measured on an input without its object before a hop was written (G401): five abstain, so a bundle with no
binding, no Role or no Secret **stops** at that hop; the sixth, KN-S014, fires on a pod whose ServiceAccount
was never passed, so its hop needs a ServiceAccount in the input and is `cannot judge` without one. The Secret
hop is last for that reason: a bundle whose Secrets live in an external store has none, and placed earlier it
would stop the walk before any RBAC hop was read.

### Each lesson's worked examples

A walkable lesson names the bundles that show it under `examples:` in the curriculum -- directories relative to
this repository's `tests/fixtures`, for instance `mechanism/deploy/complete` and `mechanism/deploy/broken`. They
are for the repository and for a page built from it: the installed package ships no `tests/`, so a walk never
opens or prints them. Every entry is held to a directory that exists and whose walk reaches a verdict (G423).

### Watching the walk

```
kube-noob learn mechanism mech-net-request-to-pod -f ./manifests --format html > walk.html
```

`--format html` writes the same walk as one page you open in a browser: the components the lesson's hops touch,
drawn in hop order and labelled with the objects from your own manifests; an event that travels from hop to hop
with a caption such as `02/06  Ingress/shop/shop -> Service/shop/orders-api`; and, for the selected hop, its
verdict, the rules it rests on, the objects it read and the findings on it. Play and pause, previous and next,
the left and right arrow keys and space all step it, and the address ends in `#step-N` so a hop can be linked.

It is a third view of the dict `--format json` prints, not a second opinion, and it keeps the walk's rules:

- The exit code is the walk's, `0`, `1` or `5`, exactly as for the text and JSON views.
- The event is drawn only for a hop a rule read. At a BROKEN hop it arrives and fails. At a hop that could not be
  judged it stops short and the page says why. For a hop marked **not observable**, and for a hop that was **not
  walked** because the walk stopped first, no event is drawn at all, and the page says so in those words -- the
  state is text, not only a colour, and neither is ever shown as passing.
- Every declared hop is on the page, including the ones after a stop, which the text view only counts.
- The page is complete without playing it and without its script: every hop's detail is in the HTML.
- It fetches nothing. There is no URL in the file -- no font, no image, no library -- and its
  Content-Security-Policy forbids the browser from loading one. Names from your manifests are text on the page,
  never markup, and the same input gives the same bytes, so the file can be attached to a review or diffed.

`--format html` belongs to `learn mechanism` alone; any other command refuses it with exit `2` rather than print
something else under that name.

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
