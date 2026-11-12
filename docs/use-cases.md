# Use cases

Pick your role, run the demo, then try it on your own files. Every demo runs offline in under a second and never
touches your cluster or your saved progress: `kube-noob demo --list`.

## No AI inside: three ways to use it

kube-noob is the rulebook, not the chatbot. Its audit rules, playbooks, docs index and graders give the same answer
every time, and they run where you put them.

1. **With Claude** (plugin in Claude Code or Cowork): ask in your own words and paste YAML, events or logs. Claude
   calls kube-noob's tools and explains the results. Your conversation goes to Claude as usual; kube-noob sends
   nothing.
2. **With OpenShift Lightspeed or another MCP client**: the same tools, served in your cluster
   ([openshift.md](openshift.md)). That client's model does the talking.
3. **With no AI at all**: the CLI below. Audits, diagnoses, cited search, lessons and evidence bundles need no model
   and no network, which suits CI gates and air-gapped clusters.
4. **With Claude, knowledge only** (the `kube-noob-skills` plugin): the same seven skills with no MCP server and no
   code at all, for somewhere a plugin may not run anything. Claude gets the platform facts and the review protocol;
   it gets no audit, no validator and no diagnosis, and each skill says so rather than implying otherwise.

`kube-noob ask` is the one optional command that uses a model: one you configure, and only a local one under the
offline lock.

## Learner or trainer: practise Kubernetes objects offline

You write YAML and get graded feedback straight away. The grader uses the same rules as a production review, and it
knows the platform: an SCC rejection on OpenShift, a storage class on ROSA HCP.

```bash
kube-noob demo learn
kube-noob learn tracks
kube-noob learn lesson k8s-101-objects
kube-noob learn exercise k8s-ex-hardened-deployment
kube-noob learn submit k8s-ex-hardened-deployment -f my-answer.yaml
```

The [learning guide](learning.md) covers running a class.

## Developer: ship YAML that passes on OpenShift and ROSA HCP

```bash
kube-noob demo audit
kube-noob audit -f k8s/ --platform openshift --version 4.22
kube-noob fix -f k8s/deployment.yaml --platform openshift -o fixed.yaml
kube-noob protocol "deploy orders-api" --blueprint examples/blueprint.yaml
kube-noob helm-chart --name orders-api --namespace shop --image quay.io/acme/orders:1.4.2 --platform rosa-hcp -o charts
```

To gate pull requests, run `kube-noob audit -f k8s/ --fail-on high` in CI. It exits 1 on any HIGH or CRITICAL finding.

If you target a Kubernetes or OpenShift minor newer than the one kube-noob's removed-API data was read at, the
report says so rather than reporting nothing:

```console
$ kube-noob validate -f k8s/ --platform openshift --version 4.25
kube-noob audit | platform=openshift k8s=1.38 | score=100.0 |
  not checked: The Kubernetes deprecated-API migration guide was read at 1.37, so no removed or deprecated API
  finding here means none through 1.37 -- not none in 1.38. Check the guide for 1.38 before reading this as clean.
```

In JSON the same thing arrives as a `notCheckedBeyond` block, and `api_history` carries `checkedThrough` and
`beyondCheckedVersions`. A target at or below the ceiling says nothing extra, because for those the answer is
complete.

When the report is going into a model's context rather than a terminal, add `--compact`:

```bash
kube-noob --format json audit -f k8s/ --platform openshift --compact
```

Each rule's constant fields -- title, severity, remediation, citations, controls and the rest -- are collected
once into a `ruleInfo` map keyed by rule id instead of being repeated on every finding that rule produced. On
this repository's `examples/` directory that is 115 findings over 21 rules, and the JSON goes from 146 374 to
74 961 bytes with nothing dropped: `kube_noob.audit.compact.expand_report` turns it back into the flat report
exactly. The MCP and HTTP tool takes the same thing as `compact: true`, off by default so the flat shape stays
what it was. The exit code is the audit's either way, so a gate reads the same verdict with the flag as without.

### The GPU claim that will be refused on apply

Dynamic Resource Allocation is GA from Kubernetes 1.34, and its wiring is three names deep: a container names a
pod-level claim, which in turn names a `ResourceClaim` or a `ResourceClaimTemplate`. A plural on one of those names
reads at a glance like a device request that was made, and `kubectl apply --dry-run=client` does not catch it
either, because a client dry run only validates against the schema and the schema cannot express the reference:

```console
$ kube-noob validate -f k8s/trainer.yaml
kube-noob audit | platform=kubernetes k8s=1.35 | score=90.0 | high=1
  note: No Kubernetes version given; assumed 1.35.
[HIGH    ] KN-V020   Deployment/ml/trainer L18 spec.template.spec.containers[0].resources.claims[0].name
           Container 'train' claims 'gpus', which is not one of the Pod's resource claims: the Pod declares gpu.
           fix: Name a claim the Pod declares: every resources.claims[].name has to match a spec.resourceClaims[].name.
```

The path is printed by index, but the `fingerprint` the JSON report carries beside it is computed from a
name-keyed locator (`containers[name=train]`), so inserting a sidecar ahead of this container does not rotate
the identity a baseline matches on (G190).

The same rule fires when the Pod declares no `resourceClaims` at all, which is the shape a copied container block
produces. `KN-V021` covers the other half: a `spec.resourceClaims` entry that sets both `resourceClaimName` and
`resourceClaimTemplateName`, or neither -- the API server refuses both, and nothing before apply says which.

Two more rules read across the bundle. Audit the **directory**, not one file, because both depend on objects the
other documents carry:

```console
$ kube-noob audit -f k8s/ --version 1.35
[HIGH    ] KN-C015   Pod/ml/inference L11 spec.resourceClaims[0].resourceClaimName
           Pod resource claim names the ResourceClaim 'gpu-pool', which no document in this bundle defines in namespace ml. The Pod is admitted and then stays Pending.
[HIGH    ] KN-S031   ResourceClaim/ml/telemetry L30 spec.devices.requests[0].exactly.adminAccess
           ResourceClaim request 'gpu' sets adminAccess: true, and namespace ml in this bundle does not carry resource.kubernetes.io/admin-access: "true". The API server will refuse this object, so the claim does not exist and nothing that depends on it will schedule.
```

`KN-C015` is the post-deploy failure: the Pod is admitted and then sits Pending, so nothing goes red until
someone looks. It is namespaced and kind-exact -- a `ResourceClaim` called `gpu-pool` does not satisfy a
`resourceClaimTemplateName: gpu-pool` -- and `audit -f one-file.yaml` says nothing, because a claim in a file you
did not pass is not a missing claim.

`KN-S031` is the privilege one. `adminAccess` ignores every ordinary claim to the device with respect to access
modes and allocations, so the workload reaches devices another tenant holds exclusively; it is the DRA equivalent
of a privileged container, and the only gate is a namespace label. When the `Namespace` is in the bundle and does
not carry that label, the message above says the API server will refuse the object, because that is a verdict
rather than a risk. Without the `Namespace` the same finding reports the privilege and claims nothing about
admission.

What none of the four rules claims is `cannot allocate all claims`, the scheduler event users actually report.
Allocation is matched against the `ResourceSlice` objects a driver publishes from the hardware it found, so no
manifest can decide it. For the same reason there is no rule for a `deviceClassName` that names no `DeviceClass`
in the bundle: a `DeviceClass` is cluster-scoped and installed by the driver, so it is absent from almost every
manifest set and such a rule would fire on every correct repository.

## SRE or on-call: diagnose before you change anything

Not sure what you have? `insight` names it first (events, logs, a denial, manifests, a ticket, a build log, a
question; several at once), runs every analyser that applies and merges the answer: findings with their source,
read-only next steps, and what it did not analyse and why. Input with no evidence gets the read-only commands that
collect some. A document is related reading for a long pasted post only when it shares words with the post beyond
the name of its subject: every Gatekeeper post says "gatekeeper".

```bash
kube-noob insight -f whatever-you-copied.txt
oc describe pod web-1 -n shop | kube-noob insight --platform openshift
kube-noob insight 'why does my pod stay Pending?'
```

`insight` recognises a packet capture by its header and reports it under `skipped`, with the reason, because the
pcap analyser is not built: it does not pretend to have read it. That is why the line is not in the block above --
a command in a block of working commands reads as a capability.

1. Paste events, `describe` output or logs into `diagnose`: as quoted text (multi-line is fine; single quotes stop the
   shell expanding `$`), as a file with `-f`, or piped in. An Alertmanager webhook payload works as it is. You get
   the signals it found (alert names, event and container reasons), the likely cause, then read-only steps (get,
   describe, logs, events).
2. Commands that run inside a container are listed next, and changes come last. Both are marked as needing approval.

```bash
kube-noob demo diagnose
kube-noob diagnose 'Back-off restarting failed container api in pod api-1'
kube-noob diagnose -f events.txt
kube-noob diagnose -f alert.json
kube-noob signals -f alert.json
oc get events -n shop --sort-by=.lastTimestamp | kube-noob diagnose
kube-noob bundle deployment/orders-api -n shop --cluster-enabled
```

Signals rank the playbooks: a firing `etcdHighNumberOfLeaderChanges` puts the etcd playbook first even when the
words differ, and a payload's `openshift_version` (or `version`) label, when it names an OpenShift 4 release, picks
the reported issues for that version. `signals` (MCP: `kubenoob_extract_signals`) lists what was found, the alerts the
words imply ("leader changed"), each catalogue entry's upstream source and the playbooks they point at.

An ImagePullBackOff whose pull secret sits in another namespace is named for what it is: kubelet's
`FailedToRetrieveImagePullSecret` event (or the question in those words) ranks the pull-secret playbook first, with the
secret and namespace filled in, read-only checks that list Secret names (never values), and the cause the words point
at shown first with its own fix and steps: a secret in another namespace gets "create or sync it in the pod's
namespace and link it" and `kubectl get secrets -A --field-selector metadata.name=<secret>`; only a question that says
OpenShift and names another project's internal registry gets `system:image-puller`. The 17 playbooks that answer
most real posts work this way (cause-linked triage): each cause carries the words that point at it, the read-only
steps that confirm it and its fixes, and text that never says OpenShift gets `kubectl` steps. When nothing in the text
points at one cause, the playbook's most common cause is shown rather than a guess. Plain words name a playbook when
they are specific to the failure ("my Service has no endpoints", "my pod keeps restarting", "the readiness probe keeps
failing", "the PVC stays Pending"), and the steps carry the names in what you paste: `kubectl get svc web` and its
`{.spec.selector}` output give `kubectl describe svc web` and `kubectl get pods -l app=web-frontend`. `audit` catches it before deploy
(KN-C013) when the bundle defines the Secret only in another namespace, and the in-cluster debug reads the pod's and
its ServiceAccount's pull secret names.

```bash
kube-noob diagnose 'ImagePullBackOff when the pull secret sits in a different namespace from the pod'
oc describe pod web-7d9c6b9f5-x2k8p -n shop | kube-noob diagnose --platform openshift
```

`bundle` writes a redacted, read-only evidence pack (`bundle.md` and `bundle.json`) that you can attach to a ticket.
Once a fix is confirmed, save it with `kube-noob learning note`. The team finds it next time as `[kn:local-N#0]`.

### Ask in words, and it names the command

`insight` recognises what you paste. Ask it a question instead and it says which command answers it, because the
answer to "which of our exposed services could reach a node?" is `posture scan`, not a list of `kubectl describe`
steps. The mapping is keyword-matched and deterministic -- there is no model making the choice -- and it covers
attack paths, pod-to-pod reachability, upgrade risks, Kyverno migration, FedRAMP indicators, exceptions, rule
explanations, the RHACS comparison, CVE ranking, the CI gate, drift, Helm failures, builds, must-gathers, threat
models, the learning tracks, policy generation, fixes and the audit itself. A pasted error or manifest gets none
of it: those are diagnosed, not routed.

```bash
kube-noob insight 'which of our exposed services could reach a node?'
kube-noob insight 'what could break if I upgrade OpenShift from 4.16 to 4.18?'
kube-noob insight 'how do I suppress KN-S010 for one namespace until next quarter?'
```

### Does it answer our problems? Test it on them

`kube-noob selftest --cases` runs your own problems through the same diagnosis, search, known-issue and audit paths
the CLI and MCP server use, offline. Start with a plain list of questions (one per line, or multi-line pastes
separated by `---`): each is answered and listed for you to label. Add `expect` (the playbook, documents, issues or
rules you expect, phrases the answer must or must not mention) and the case becomes a test with a pass or fail.
YAML, JSONL and CSV (for a spreadsheet export) work too; `examples/problems.yaml` shows every field.

```bash
kube-noob selftest --cases examples/problems.yaml
kube-noob selftest --cases our-problems.txt --out problem-report
kube-noob selftest --cases our-problems.yaml --gate 0.9
```

kube-noob has no model, so nothing is learned by itself: a failed case is fixed with a playbook, signal, rule or
team memory entry that is reviewed like any other change, and then guards against regressions.

### Is this CVE fixed in my OpenShift?

`corpus advisories` keeps Red Hat's VEX statements for the products kube-noob covers, so search answers which
component is fixed by which erratum, which is not affected and why, offline. The public `kube-noob-db` image carries
them already.

```bash
kube-noob corpus advisories --online --cves CVE-2023-44487
kube-noob search 'CVE-2023-44487 openshift haproxy router'
```

### Is this a known bug?

`known-issues` matches an error or symptom against the issues Red Hat lists in the OpenShift 4.20, 4.21 and 4.22 release
notes: known issues, and the issues each update fixed. You get the issue link, whether a fix exists and in which
version, the workaround, and the release-notes file it came from. Pass your version and issues already fixed there are
left out. `diagnose` runs the same check, and on a live cluster `debug` and `bundle` read the version themselves.
A match needs several rare words in common, so everyday errors such as OOMKilled never pull in an unrelated bug;
an error copied word for word from an issue (seven words in a row, one of them rare) is a match on its own.

```bash
kube-noob known-issues 'could not find any suitable subnets for creating the ELB' --version 4.20.8
kube-noob diagnose -f events.txt --platform openshift --version 4.21.4
kube-noob corpus known-issues --online
```

The bundled index is dated (`kube-noob doctor` prints it, and every MCP result carries `knowledgeAsOf`);
`corpus known-issues --online` refreshes it from the release notes on GitHub.

### What could go wrong with this update?

Red Hat attaches known risks to some OpenShift updates ("conditional updates"): a cluster sees them in
`oc adm upgrade --include-not-recommended` when it can reach an update service, and a disconnected cluster only through
a local OpenShift Update Service. `upgrade-risks` answers before you start, with no network: it lists the risks declared
for your update in the public update graph (targets 4.18 and later), with the message, the link and the version that
fixes each. A risk either applies to every cluster, or one fact decides it (the platform type, whether the cluster is a
hosted control plane, a ClusterOperator, an enabled capability, a node label, assigned egress IPs) and you get the
read-only `oc` command or the must-gather file that shows it, or its PromQL query is shown as written because it
cannot be evaluated offline. Whether the update is in your channel is not checked.

```bash
kube-noob upgrade-risks --from 4.20.3 --to 4.21.4
kube-noob upgrade-risks --from 4.18.5 --to 4.19.0 --format json
```

The snapshot is dated and pinned to an upstream commit (`kube-noob doctor` prints it);
`scripts/vendor_upgrade_risks.py` refreshes it from a clone of openshift/cincinnati-graph-data.

### Has Red Hat seen this error before?

The release notes list only a few hundred issues. Red Hat's public Jira holds every reported ticket, including the ones
closed as Not a Bug, Won't Do or Duplicate, which often answer the question faster than a fix would. `corpus jira`
keeps a local copy of every ticket in the OpenShift, ROSA, ACM and RHACS projects (OCPBUGS, ROX, HOSTEDCP and 25
more; `jira-projects` lists them), whatever its status. After that, `known-issues`, `diagnose`, `debug` and the
incident watch also say what became of each matching ticket:

- fixed, in which release, and whether your version already has the fix ("updating to 4.21.3 or later fixes it");
- open, with a fix merged or proposed;
- closed as Not a Bug (expected behaviour or a configuration issue), Won't Do, Cannot Reproduce, Obsolete, or as a
  duplicate of another ticket, which is then followed;
- the workaround, cause or "why closed" sentence from the latest comments.

The copy keeps each ticket's full description and every comment, so you can audit it yourself; commenters appear as
Commenter A, B and so on (per ticket), and names, emails, phone numbers and account ids are removed.

```bash
kube-noob corpus jira-projects --online
kube-noob corpus jira --online
kube-noob known-issues 'x509: certificate signed by unknown authority' --version 4.21.1
kube-noob ticket OCPBUGS-12345 --version 4.21.1
```

The copy is read through Jira's REST API, never by scraping its web pages, at one request per second or slower (the
site's robots.txt asks for that), with a request budget per run (`--max-requests`, default 600). Each later run
fetches only what changed and resumes where a budget stopped it; a request returns up to 100 tickets, and OCPBUGS alone
has keys past 87,000, so the first copy of the default set completes over several runs. Tickets are public but not
licensed for redistribution: they stay in
your data directory (`corpus/jira-*.jsonl` plus a search index in `jira/`), kube-noob never publishes them, and
`--projects all` or `--projects OCPBUGS,ROX` choose other projects. In the cluster, `jira.sync.enabled` keeps the copy
current from the service; offline clusters import a copy built elsewhere with `corpus import`.

### One main copy for the whole organisation, and what changed since yesterday

Seal the copy with your own key before it goes into an image, and give pods the key from a Secret: a new pod answers
ticket questions from its first minute with no Jira egress, and a wrong key imports nothing and says so. The
`jira-db-image` workflow does this after every refresh and refuses a public repository.

```bash
openssl rand -base64 32 > seed.key
kube-noob corpus jira-snapshot -o jira-snapshot.tgz
kube-noob corpus seal jira-snapshot.tgz -o jira-snapshot.tgz.enc --key-file seed.key
kubectl create secret generic kn-seed-key --from-file=key=seed.key
helm upgrade --install kube-noob deploy/helm/kube-noob --set jira.seed.source=image --set jira.seed.image.repository=quay.io/acme/kube-noob-db-jira --set jira.seed.image.digest=sha256:<digest> --set jira.seed.path=/seed/jira-snapshot.tgz.enc --set jira.seed.keySecret.name=kn-seed-key --set config.offline=true
```


Nobody should wait hours for a first sync. Keep one main copy, refresh it every other day (or daily), and start every
other install from it:

```bash
kube-noob corpus jira --online
kube-noob corpus jira-snapshot -o jira-snapshot.tgz
kube-noob corpus import jira-snapshot.tgz
```

The snapshot holds the tickets, the sync state and the change log; an install that imports it answers at once and its
own sync (if any) only fetches what changed since. A brand-new copy fetches each project's open tickets first, so the
tickets people reconcile arrive in the first run. Every sync records what moved, and reconciliation reads it offline:

```bash
kube-noob corpus jira-changes --since 1d
kube-noob corpus jira-changes --since 2026-10-25 --project OCPBUGS --kind fixed --kind reopened
```

You get the tickets fixed (and in which versions), closed as not a bug, won't fix or duplicate, reopened, given a fix
version or opened, each with its link, and the open tickets per project and verdict. Over MCP the same is the
`kubenoob_ticket_changes` tool. `kube-noob corpus jira-audit` shows what the copy holds: tickets per project and
verdict, comments kept against what Jira reported, tickets cut at the size cap or still in the older format, key
coverage, size, sync state, what the anonymiser replaced, and a self-check that no email, account id or profile link
is left (the daily workflow fails if one is).

The `corpus-refresh` workflow keeps the main copy in GitHub Actions: every other day at 05:17 UTC (set the repository
variable `JIRA_EVERY_DAYS` to `1` for every day), newest updates first, continuing the previous run's copy. A run that
cannot decrypt that copy fails and leaves it in place. The changes and open tickets are in the run summary, and the
new copy is uploaded only encrypted with your `CORPUS_PASSPHRASE`. Ticket text is not published on the website. In
OpenShift, put the snapshot in a private image and set `jira.seed` so every new pod starts from it (an init container
copies it; the image needs `cp` and must run as non-root):

```bash
gh run download "$(gh run list --repo kube-noob/kube-noob --workflow corpus-refresh.yml --status success --limit 1 --json databaseId --jq '.[0].databaseId')" --repo kube-noob/kube-noob -n jira-main-copy-encrypted -D seed
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in seed/jira-snapshot.tgz.enc -out seed/jira-snapshot.tgz -pass env:CORPUS_PASSPHRASE
printf 'FROM registry.access.redhat.com/ubi9/ubi-micro:latest\nCOPY --chmod=0444 jira-snapshot.tgz /seed/jira-snapshot.tgz\nUSER 1001\n' > seed/Containerfile
podman build -t registry.example.com/platform/kube-noob-jira-seed:2026-10-28 seed
podman push registry.example.com/platform/kube-noob-jira-seed:2026-10-28
helm upgrade --install kube-noob deploy/helm/kube-noob --reuse-values --set jira.seed.source=image --set jira.seed.image.repository=registry.example.com/platform/kube-noob-jira-seed --set jira.seed.image.tag=2026-10-28
```

`jira.seed.source: pvc` reads the snapshot from a read-only claim instead. Keep the image, bucket or volume private:
the tickets are public but not licensed for redistribution.

### What is in this must-gather? Opening one safely

A must-gather from a customer or another team is untrusted input. `must-gather analyze` reads the directory, or the
`.tar.gz` that `tar cvaf` made of it, without extracting anything or running anything: an archive member with an
absolute path or `..` refuses the whole archive, links and device files are never followed, nested archives (audit
logs) are listed and not opened, and files named like Secrets are never read. It says which gather images wrote
what, for which version (`version`) and when (`timestamp`), and how many resources, namespaces, pods and logs each
holds.

Then it says what is wrong, most severe first: a Failing or unavailable cluster version and an update that stopped
partway, cluster operators that are not Available or are Degraded, NotReady nodes (control-plane first) and node
pressure, degraded machine config pools, failed OLM operators, pods that cannot start (CrashLoopBackOff with the last
error line from the container's log, image pull errors, OOM kills, Unschedulable), warning events by reason, and
etcd's slow-disk and leader-election lines. Each finding names the file it came from, the signals it carries (the
same keys known-issue and memory matching use) and read-only commands to confirm it on the live cluster. A plain
`oc adm inspect` output works too; whatever was not collected is listed.

```bash
oc adm must-gather
tar cvaf must-gather.tar.gz must-gather.local.*/
kube-noob must-gather analyze must-gather.tar.gz
kube-noob must-gather analyze must-gather.tar.gz --fail-on critical
kube-noob --format json must-gather analyze must-gather.local.5421342344627712289/
```

Before you open a case, `--report` writes `report.md` and `report.json` with every finding matched to the known
OpenShift bugs for the version the cluster runs (and to your team's approved memory entries), and `--case-draft`
adds `case-draft.md`: environment, update history, evidence files, matched bugs and the read-only checks to paste,
with a `[FILL IN: ...]` for everything only you know. `kube-noob demo must-gather` shows the whole flow offline.

```bash
kube-noob must-gather analyze must-gather.tar.gz --report case-01 --case-draft
kube-noob demo must-gather
```

From an MCP client, `kubenoob_analyze_must_gather` takes the must-gather's path. The local server reads any path
you give it; a shared server on OpenShift reads only the must-gathers on the claim you mount
(`mustGather.pvc.claimName`).

```bash
helm upgrade --install kube-noob deploy/helm/kube-noob --reuse-values --set mustGather.pvc.claimName=case-files
```

```text
OpenShift 4.20.3; updating to 4.20.4; platform AWS; 1/2 nodes Ready; 2/3 cluster operators Available, 1 Degraded
findings: 2 critical, 8 high, 10 medium, 2 low, 2 info
  CRITICAL clusterversion: the cluster version operator reports Failing [ClusterOperatorDegraded]
  CRITICAL clusteroperators: cluster operator image-registry is not Available [NoReplicasAvailable]
  HIGH     pods: shop/ReplicaSet/web-6b8f9: container web: CrashLoopBackOff (2 pods), 14 restarts
           log: Error: connect ECONNREFUSED 10.0.0.5:5432
           next: oc describe pod -n shop web-7d9f
  MEDIUM   etcd: etcd logged "slow fdatasync" 1 time(s) on 1 member(s)
```

### Which operators are installed, at what version, and from where?

`operators inventory` lists what OLM installed: each operator's package, version (and whether `spec.version` stated
it or it was read off the name), catalog, channel, approval mode, its namespace and the namespaces it serves, its
phase, an upgrade waiting to happen and a Manual approval waiting for a person. OLM copies an operator's
ClusterServiceVersion into every namespace it serves; those copies are folded into one operator with the list of
namespaces, never counted as more installs. A Subscription with nothing installed, and a ClusterServiceVersion with
no Subscription (catalog and channel then say unknown), each get a state of their own.

It reads manifests, a must-gather or the cluster (ClusterServiceVersions and Subscriptions only, read-only). What it
could not read is part of the answer, and the list is `listed` only when nothing it needs was skipped: no
ClusterServiceVersions read is "not determined"; a file it could not parse, a file the must-gather reader skipped, an
object it could not use, or a namespace with CSVs and no Subscription in the files you gave makes it `partial` and is
named; a cluster that answers 404 for `operators.coreos.com` on both reads is "not an OLM cluster". None of them is
reported as zero operators. A Subscription counts as installed only through the CSV its `installedCSV` names.
`--require-complete` exits 5 on anything but a complete answer. With `-f DIR`, every `.yaml`, `.yml` and `.json` file
is read on its own. Operators installed by Helm or plain manifests are outside it, and it says so.

```bash
kube-noob operators inventory --must-gather must-gather.tar.gz
oc get csv,sub,ip,og -A -o yaml > olm.yaml
kube-noob operators inventory -f olm.yaml --format json
kube-noob --cluster-enabled operators inventory --live --require-complete
```

```text
operator inventory (must-gather): partial -- 1 operator from OLM data; Subscriptions were not read, so catalog, channel and approval are not determined for every operator
  rhacs-operator.v4.6.0  package unknown  version 4.6.0 (derived from the name)  state subscription-not-read  phase Failed [InstallCheckFailed]
      namespace rhacs-operator; copied into 1: shop
      catalog unknown, channel unknown, approval unknown (not read)
not read: subscriptions (not-read) not in this must-gather (namespaces/<ns>/operators.coreos.com/subscriptions)
```

From an MCP client, `kubenoob_operator_inventory` takes the objects as YAML, `kubenoob_cluster_operator_inventory`
reads the cluster when cluster access is on, and `kubenoob_analyze_must_gather` and `kube-noob must-gather
analyze` return the same inventory as `operatorInventory`.

### Why was this denied?

`policy explain` reads a denial and explains it policy by policy: Kyverno, OPA Gatekeeper, ValidatingAdmissionPolicy,
Pod Security Admission, OpenShift SCC, RHACS, ResourceQuota, LimitRange and RBAC. You get the policy and rule, the
field that failed, read-only commands with the names filled in, the change that satisfies the policy (a ready patch
for Pod Security and RBAC, scoped to exactly the missing permission) and the audit rules that would have caught it
before deploy. Exceptions, quota increases and new permissions are marked as the policy owner's decision. `diagnose`,
`debug` and `bundle` add the same explanation when a denial is in the text.

```bash
kubectl apply -f deploy.yaml 2>&1 | kube-noob policy explain
kube-noob policy explain -f examples/events-scc.txt --platform openshift
```

### Can pod A reach pod B?

`policy reach` evaluates all three network policy tiers the way the cluster does: egress from the source and
ingress to the destination must both allow the port, and each direction runs through `AdminNetworkPolicy`, then the
namespace's NetworkPolicies, then `BaselineAdminNetworkPolicy`. The two cluster-scoped tiers are why the answer
needs them: an ANP `Deny` blocks traffic every NetworkPolicy in the namespace allows, and a BANP decides the traffic
no NetworkPolicy selects. Each verdict names the tier, the policy and the rule that decided it, says for every other
rule whether the peer or the port did not match, and proposes the smallest NetworkPolicy that would allow the
traffic. There is a third verdict: two `AdminNetworkPolicy` objects at one priority whose rules disagree have no
defined winner in the API, so the answer is `undetermined` (`UNKNOWN` in the text output), it names both policies,
and it proposes nothing -- a NetworkPolicy cannot override the admin tier whichever way the tie lands. A duplicate
priority is reported as a note even where the tied policies agree. It exits 1 when the traffic is denied or
undetermined, so CI can assert the paths an application needs. `--live` reads the
policies, both admin tiers, namespace labels and workloads from the cluster (read-only); a cluster without the
`network-policy-api` CRDs is a note, not a failure. EgressFirewall and CNI-specific policies are listed as not
evaluated.

Those two cluster-scoped tiers only decide on a cluster whose CNI enforces them, and Calico stopped: it removed
`AdminNetworkPolicy` and `BaselineAdminNetworkPolicy` support in 3.32 in favour of `ClusterNetworkPolicy` and does
not enforce them from 3.32 onward, without reporting an error. Pass `--cni calico:3.32` and every policy in that
tier is reported as **NOT ENFORCED** -- read, named, and not allowed to decide -- with the replacement kind, so an
`ANP` that looks like a guardrail is shown as the no-op it has become. The NetworkPolicies then give the answer,
which can be the opposite of the one that tier would have given. A CNI nobody documents either way (`--cni
cilium:1.18`) is evaluated both ways -- with the tier and without it -- and the verdict is `undetermined` only
where the two readings disagree: evaluating the tier would assume enforcement and dropping it would assume the
reverse, but an answer that holds under both still holds. A Calico version too coarse to decide (`--cni calico:3`,
which does not say whether the cluster is on 3.31 or 3.32) is treated the same way. With `--live` the flag is
usually unnecessary: Calico publishes its version in `clusterinformations.crd.projectcalico.org` and kube-noob
reads it, so the answer uses the cluster's real CNI rather than an assumption. A cluster without that CRD is not
running Calico and behaves as before; a read the token is not allowed to make says so and changes nothing; and an
explicit `--cni` always wins, because a caller who passes it knows something a forbidden read cannot see.

`kube-noob audit --cni calico:3.32` turns the same fact into a finding a CI gate fails on: **KN-N014** reports an
`AdminNetworkPolicy` or `BaselineAdminNetworkPolicy` that this CNI no longer enforces, at HIGH, because a policy
gate that silently stopped applying is worse than one that was never there. `gate --cni` takes it too. Without the
flag the rule is reported as NOT EVALUATED rather than clean: no manifest states which CNI runs the cluster, and
"nobody told me" is not "the policy is enforced".

```bash
kube-noob policy reach --from web/frontend --to shop/orders-api --port 8080 -f examples/netpol-shop.yaml
kube-noob policy reach --from shop/orders-api --to shop/payments --port 9090 -f examples/netpol-shop.yaml
kube-noob policy reach --from web/frontend --to shop/orders-api --port 8080 -f examples/netpol-admin-tiers.yaml
kube-noob policy reach --from web/frontend --to shop/orders-api --port 8080 -f examples/netpol-admin-tiers.yaml --cni calico:3.32
kube-noob policy reach --from shop/orders-api --to shop/payments --port grpc --live --cluster-enabled
```

### What did we learn last time?

`memory` keeps your team's fixes as code: one reviewed YAML file per lesson in a repository you own
(`entries/MEM-<n>.yaml`), with the signals it shows, the cause, the fix and what happened each time someone applied it.
`memory match` puts the entries next to the playbooks: signals first (an alert name in a payload), then distinctive
words. Fixes come first, then runbooks, then what was tried and did not work; an entry whose fix is already in your
version shows as retired. Each match says how often it was applied and how often it resolved the problem.

```bash
kube-noob memory init team-memory
kube-noob memory add team-memory --symptom "etcd leader changes after the update" --cause "catalog sync I/O" --fix "update to 4.21.1" --signal alert:etcdHighNumberOfLeaderChanges --platform openshift
kube-noob memory validate team-memory
kube-noob memory match -f alert.json --dir team-memory --version 4.21.0
kube-noob memory outcome team-memory MEM-1 --result resolved --ticket INC-4211 --cluster prod-east
kube-noob demo memory
```

`validate` is the guard against a poisoned entry, and `init` writes a CI workflow that runs it on every pull request:
every patch is validated, audited and red-teamed, commands must carry the classifier's labels, and grants of the
privileged SCC, cluster-admin, hostPath or wildcard RBAC fail unless the entry records who accepted the risk and why.
`add` writes a proposed entry and never commits; `migrate-learning` turns confirmed learning notes into proposed
entries, and `import --from servicenow-json|servicenow-csv|jira-json|jira-csv -f export` turns resolved tickets into
proposed entries with their outcomes, without the people in them. `replay` answers whether that memory would have
helped: it replays later tickets in order, without hindsight, and reports hits, misses and, with your labels,
how many matches were useful (the gate is 30%). kube-noob reads the repository where it runs and never uploads, bundles or exports it.

Set `memory.paths` (or `KUBE_NOOB_MEMORY_PATHS`) and `diagnose`, `known-issues`, `debug` and `bundle` add the
matching approved entries to every answer, cited as `[mem:MEM-<n>]`. Over MCP, `kubenoob_memory_match` searches
them and `kubenoob_memory_propose` turns a fix the user confirmed into an entry; only a local stdio server saves
it (as proposed, after the user asks), and the HTTP server never writes.

### Always on: the incident watch

`watch` polls your namespaces read-only (pods, events, deployments, replicasets; never Secrets) and turns what it sees
into incidents: crash loops, OOM kills, image pulls, container config errors, pods that cannot be created (with the
policy that denied them), scheduling, mount and probe failures, stuck rollouts and evictions. Each new incident is
explained once (playbook, policy denial, reported OpenShift bug) and gets a "what changed" note when it started soon
after a rollout ("started 4 min after the rollout to revision 2: image 2.7.0 -> 2.7.1; memory limit 256Mi -> 128Mi").

The incident ledger is its memory: how often each incident came back, how long each one lasted, and the fix your team
confirmed, which comes back with the next occurrence and with the same problem in other workloads. Claude or
Lightspeed read it through `kubenoob_incidents`; in the cluster, set `watch.enabled` in the chart.

```bash
kube-noob --cluster-enabled watch -n shop -n payments
kube-noob --cluster-enabled watch -n shop --once
kube-noob incidents
kube-noob incidents show inc-3fa94c0e12
kube-noob incidents confirm inc-3fa94c0e12 --cause "memory limit cut to 128Mi" --fix "restored the 256Mi limit"
```

### What does this Ceph health code mean? Rook-Ceph and OpenShift Data Foundation

Paste `ceph health detail`, `ceph status` (text or `-f json`), a CephCluster's status or a firing Rook or ODF alert
into `kube-noob insight`. Each health code gets what it means, the likely causes, the fix in words and the read-only
steps that confirm it: the CephCluster status first (no shell needed), then the Ceph commands to run in the Rook
toolbox, which need approval because they execute in a container. On ODF the steps use `oc` and `openshift-storage`;
on Rook they use `kubectl` and `rook-ceph`. When the usual fix can lose data (unfound objects, inconsistent placement
groups, lost monitor quorum, full OSDs), the answer says to stop and involve storage support, and kube-noob never
offers the destructive command. ODF alerts that only say "contact support" come with the evidence to collect first.

```bash
oc get cephcluster -n openshift-storage -o jsonpath='{.status.ceph.details}' | kube-noob insight -f -
kube-noob insight -f ceph-health-detail.txt --platform openshift
```

## Platform admin: run it inside the cluster, locked down

```bash
kube-noob demo posture
helm install kube-noob deploy/helm/kube-noob --set auth.existingSecret=kube-noob-token --set config.offline=true
kube-noob doctor
```

`config.offline=true` (or `KUBE_NOOB_OFFLINE=1`) is an admin lock:

- no web, no corpus downloads, and local models only;
- nothing later in the config chain can lift it;
- the chart refuses to render if web access is also requested.

Start answering from day one without any egress: build the corpus image yourself and pin it by digest. Pods import
it on start when it is newer than what they have.

> **Not published yet.** The `db-image` workflow that would publish a public `kube-noob-db` image has failed on
> every scheduled run since it was added and has never published one, so there is no image to pull. Pack your own
> bundle with `kube-noob corpus db-bundle`, check it with `kube-noob corpus db-check`, put it in an image and push
> that to a registry you control, then pin its digest below. This note goes when the workflow publishes.

```bash
helm upgrade --install kube-noob deploy/helm/kube-noob --set db.enabled=true --set db.image.repository=<your-registry>/kube-noob-db --set db.image.digest=sha256:<digest> --set config.offline=true
kube-noob corpus db-check kube-noob-db.tgz
```

`doctor` prints what the process can reach and exits 1 if the configuration contradicts the lock. To add kube-noob
as a tool in OpenShift Lightspeed, or to run it as a sidecar, follow [openshift.md](openshift.md). Index your own
runbooks with `kube-noob corpus add-docs <folder> --source platform-runbooks`, and prove the answers on your
machine with `kube-noob selftest`.

## Build: from a failed build to the fix

`build diagnose` reads the log your CI system already wrote: GitHub Actions (`gh run view <id> --log-failed`),
Jenkins (the console), Tekton (`tkn pipelinerun logs <run>`) or an OpenShift build (`oc logs build/<name>`). It names
the failing step and why it is that step (the step with `##[error]`, the stage that ran before the skipped ones, the
task that `tkn` reports failed, the STEP buildah stopped at), the error line and its template, the cause class
(dependency fetch, compile, test, image push, registry auth, quota, timeout, out of memory, permissions), reported
issues and team memory for the error lines, and the fix for that system (a BuildConfig push secret, a Tekton step's
`computeResources`, `timeout-minutes`). Quoted lines are redacted.

```bash
gh run view 1234567890 --log-failed > build.log
kube-noob build diagnose -f build.log --format text
oc logs build/web-7 -n shop | kube-noob build diagnose -f - --platform openshift --version 4.20
```

`build audit` checks a Containerfile before it is built and the image after: base images pinned by digest, a
non-root `USER` (on OpenShift: group 0 owns what it writes), no credentials in `ENV`, `ARG`, `LABEL`, `RUN` or copied
files, no download piped into a shell, package caches cleaned, a health check or the workload's probes, a multi-stage
build. With `--context` it lists the credential files `COPY . .` would take; with `--image-layout` it reads the built
image from disk (no pull, no extraction) and finds credentials in its layers, including one a later layer deleted,
and in its config and history. Values are never printed, only the kind and where.

```bash
kube-noob build audit -f Containerfile --context . --manifests k8s/deployment.yaml
skopeo copy docker://quay.io/acme/web:1.8.0 oci:/tmp/web-oci:1.8.0
kube-noob build audit -f Containerfile --image-layout /tmp/web-oci --fail-on high
```

### Gate a release before it deploys

`gate` is one command for CI: the audit rules over manifests and rendered charts, the exception list, whether each
finding would be refused by the generated admission policy in enforce mode, open reported issues in the target
OpenShift release that name a kind you deploy, and the Containerfile checks. It exits 1 at `--fail-on` and writes
SARIF (GitHub code scanning), a Markdown summary and GitLab code quality JSON. Findings in a rendered chart point at
the template file.

```bash
kube-noob gate --chart deploy/helm/shop --values deploy/helm/shop/values-prod.yaml --containerfile Containerfile \
  --platform openshift --version 4.20 --exceptions kube-noob-exceptions.yaml --sarif kube-noob.sarif \
  --summary kube-noob-summary.md
```

GitHub Actions (add `github/codeql-action/upload-sarif` after it to see findings in code scanning):

```yaml
- uses: aashishmahajan/kube-noob@<tag>
  with:
    chart: deploy/helm/shop
    values: deploy/helm/shop/values-prod.yaml
    containerfiles: Containerfile
    platform: openshift
    version: "4.20"
```

The action also prints the findings as annotations, so they appear on the pull request instead of only in the log
(`--github-annotations` does the same from the CLI; `annotations: "false"` turns it off). Findings at or above
`--fail-on` are errors and the rest are warnings. GitHub displays ten annotations of each kind per step, so the
tenth says how many are not shown rather than letting the eleventh disappear: the SARIF file and the job summary
carry every one.

The audit writes SARIF too, for a pipeline that wants findings in code scanning without the gate's pass-or-fail:

```bash
kube-noob audit -f k8s/ --platform openshift --version 4.20 --format sarif > kube-noob.sarif
```

Every rule in either file carries the NIST SP 800-53 controls it is evidence about, as `NIST-800-53/AC-6` tags a
code-scanning view can filter on and as a `nist-800-53` list a program can read. And because a SARIF file is only a
list of results, the audit's own caveats go into it as notifications on the run: what it did not evaluate because
it was given part of a namespace, and any file it could not read. A short list from a partial audit should not be
mistaken for a clean one by whatever reads the file next. Both outputs are validated against the OASIS SARIF 2.1.0
schema in this project's own CI.

With the images' scanner output (`--scanner-report`, plus `--vex` and `--kev`), the gate also lists their
vulnerabilities after Red Hat VEX, ranked against the manifests; a fixable or known-exploited one at `--fail-on`
fails it, an unfixable one is reported without blocking.

```bash
trivy image -f json --list-all-pkgs -o trivy.json quay.io/acme/shop:1.4
kube-noob gate -f k8s/ --platform openshift --version 4.20 --scanner-report trivy.json \
  --kev known_exploited_vulnerabilities.json --sarif kube-noob.sarif
```

Tekton: `oc apply -f deploy/tekton/kube-noob-gate.yaml`, then a pipeline task with `taskRef: {name: kube-noob-gate}`,
the source workspace and `params: [{name: paths, value: k8s}]`. GitLab: include
`deploy/gitlab/kube-noob-gate.gitlab-ci.yml` and extend `.kube-noob-gate` with `KUBE_NOOB_PATHS`; findings show in
the merge request through the code quality report.

### Which tests are flaky, and which steps got slower?

`build analytics` reads a CI history on disk: one folder per run with `run.json` (the run, its jobs and steps, as the
GitHub Actions API or `gh run view --json` writes it), the run's JUnit XML reports and, for failed runs, the build
log. It lists the flaky tests (passed and failed on the same commit, or failed then passed on a rerun within a run),
tests that fail without being flaky, commits with both a failed and a successful run, each step's mean, median, p90
and maximum with its trend (newest half against oldest half), and the failure classes per week.

```bash
kube-noob build analytics --history ci-history/ --format text
GITHUB_TOKEN=<token> kube-noob --config ci.yaml build history --github acme/shop --workflow ci.yml -o ci-history
```

`build history` needs `ci.githubEnabled: true` and reads only: every attempt of every run, with a random pause between
requests. GitHub serves test reports and logs from another host, so add them with `gh run download <run-id> -D
ci-history/run-<run-id>-<attempt>` for flaky-test analysis.

## Security: policy-aligned reviews and red-team scenarios

Each audit finding maps to the RHACS (StackRox) policy that would fire. `redteam` shows how an attacker would use a
bundle: escape paths, lateral movement, credential exposure.

```bash
kube-noob redteam -f k8s/ --platform openshift
kube-noob explain KN-S004
```

### Something a reviewer will actually open

`--html` writes one self-contained page: `gate --html report.html`, `posture report --html`, `posture diff --html`,
`ksi --html`. One file, inline styling, no script, no stylesheet, no font, no image -- nothing the browser fetches,
so it opens from an email attachment on a laptop with no network, which is the situation this tool is used in.
Verified that way rather than asserted: a test parses the page and fails on any `src`, `href` on a `<link>`, inline
handler or `<script>`, and the page is rendered in a real browser with the request log checked.

The caveats come first and the findings after, because a reader who meets an empty findings table first has already
drawn their conclusion. `audited: false`, `assumed`, `not checked that far`, a file that could not be read, a
withheld control standing, and the shows/does-not-show pair all survive into the page -- an HTML report that drops
them would be the same defect in a third format.

The page is laid out as what it is: an evidence document, not a dashboard. It opens with the verdict as a sentence, the three numbers that decide what the reader does next -- findings, how much reached no verdict, and what was evaluated and clean -- and a provenance block stating the scope those numbers are true of. Section 1 is the limits of the examination, numbered and ahead of anything the run found, because a rule that was never evaluated is indistinguishable from a clean one in any table that does not say so. Sections are numbered so a reviewer can cite one, every finding and control row has an id so a colleague can be sent to a single line, and controls with nothing to report fold away on screen and open again in print, so the PDF in an audit package is never a subset of the page.

The page carries charts, and they are drawn rather than plotted: inline SVG, still no script and still nothing
fetched. A gate report gets findings by severity; a posture report gets open findings per control, the five
standing buckets as a stacked bar, and open against excepted findings across the snapshots still kept. Three rules
decide what may be drawn. A chart shows only what a table on the same page shows, so every bar has a row under it
to check. Every bar is labelled with its name and its count, so a reader in print, in forced colours or with no
colour vision at all loses nothing -- the palettes were put through a colour-vision validator in both light and
dark rather than eyeballed. And a count that was withheld is not drawn at all: the trend is withheld entirely when
any snapshot in the series could not read every resource, when a report written before kube-noob recorded that
cannot say, when a kept file could not be read back, or when the folder mixes a `-f` run with a `--live` run --
in every case with the reason and the per-snapshot counts in its place, because a line through a floor publishes
a fall in findings that may only be a fall in what kube-noob was allowed to see.

Everything from a manifest is escaped before it is written. Resource names, messages and paths come from someone
else's cluster, and this is the one place in the product where that text becomes a document another person opens:
a Deployment named `<script>alert(1)</script>` appears as text, and a test asserts both that it is shown and that
it is inert.

```bash
kube-noob gate -f deploy/ --fail-on high --html gate-report.html
kube-noob posture report --live --html posture.html
kube-noob ksi -f deploy/ --html ksi.html
```

### Which FedRAMP 20x indicators does a finding speak to?

`ksi` joins kube-noob's findings to the FedRAMP 20x Key Security Indicators through the NIST SP 800-53 controls both
sides name: every indicator in the dataset carries `controls: [...]`, kube-noob maps every rule to the controls it
gives evidence about, and the crosswalk is the inversion. With `-f` it audits first and reports, per indicator, the
findings, the rules that ran and found nothing, and the rules that did not run at all -- a zero on its own cannot
tell a clean indicator from one nothing looked at.

Read the two lines under a curated indicator before quoting the first one, and read the rule titles printed beside
them. `KSI-CNA-RNT` (Restricting Network Traffic) is evidence that policies exist, not that the cluster enforces
them; `KSI-SVC-VRI` (Validating Resource Integrity) is evidence that images are pinned by digest, not that any
signature verifies; `KSI-RPL-ABO` (Aligning Backups with Objectives) is about surviving the loss of a pod, and says
nothing about backups at all. 15 of the 46 indicators have no kube-noob rule behind them and say so instead of
showing a zero.

Two rows carry a warning rather than evidence, and they are the most useful thing in the page. An indicator and a
rule meet here only because they name the same NIST control, and a shared control is not shared subject matter:
`KSI-IAM-SNU` is about how non-user credentials are issued, it cites `ac-4` (Information Flow Enforcement), and
kube-noob maps its NetworkPolicy rules to `ac-4` because that is what `ac-4` is -- so eight traffic and RBAC rules
arrive under an authentication indicator. Those rows say so on their face.

`ksi -f` reads its input exactly as `audit` does, which is deliberate: it refuses a Helm values file instead of
scoring it, treats one file as part of a namespace rather than the whole of it, exits 5 and names a file it could
not read, and carries the audit's own assumptions into the page. A finding whose rule reaches no indicator -- a
schema error, or a rule whose only control nothing cites -- is listed under `findingsNotMapped` rather than
dropped, and a filter that hides rows says how many.

It is a projection of one audit, not a second audit, so the numbers reconcile: it takes the same
`--exceptions` list and the same `--min-severity` as `audit`, with the same defaults. An excepted finding is
counted under `excepted` on the indicators it reaches rather than as an open finding -- an exception is a
reviewed, owned, expiring decision about a control, and it reads the same way on both pages -- and a finding the
threshold removed is reported as `withheld` rather than counted clean. An expired or refused entry fails the
gate here too, with exit 1.

```bash
kube-noob ksi
kube-noob ksi -f k8s/ --evidenced-only
kube-noob ksi -f k8s/ --exceptions kube-noob-exceptions.yaml --format json
kube-noob ksi --control AC-6 --format json
kube-noob ksi --indicator KSI-IAM-JIT
```

The MCP server and the skill expose the same crosswalk as `fedramp_ksi`, with `manifests` optional. One difference
from `audit_manifests`, and it is deliberate: `partial_bundle` defaults to **true** there, because a manifest pasted
into a conversation is usually a fragment and a rule that fires on an absent object cannot tell a real gap from an
object the caller did not paste. Set it false for a whole namespace. A test holds the two front doors to the same
answer on the same input.

Every row carries its own `evidence.shows` and `evidence.doesNotShow`, not only the counts, because the JSON is the
whole of what an assistant reads and a count without that second sentence is the thing this page exists to prevent.
A row whose rules reach it only through a shared control carries a `warning` as well. Without an audit there are no
counts at all and `audited` is `false`: zeroes on 28 rows would read as 28 clean results. When a rule declines, the
row names it -- `notEvaluatedRules: ["KN-N014"]` on an AdminNetworkPolicy bundle is the rule asking for the
cluster's CNI, which `--cni` and the tool's `cni` supply. And when the target version is past the removal table's
ceiling the reply carries `notCheckedBeyond`, because SA-22's evidence is exactly those removed-API rules.

The dataset is vendored with its version and sha256 and the crosswalk is generated from it, because the hand-written
version of this mapping asserted a release, a family count, an id scheme and a retirement list that were all wrong
at once. A mapping is evidence, never a compliance claim: see [FedRAMP 20x KSI](fedramp-ksi.md).

### What does RHACS check that kube-noob does not, and the other way round?

`rhacs compare` maps every RHACS policy (export them from the RHACS portal with Export policy to JSON, or
`POST /v1/policies/export`) to kube-noob's rules, by the default policy names each rule cites and by the
policy's criteria, and gives each one outcome with the reason. Overlap names the rules and any difference in severity
or scope (RHACS scopes a policy by namespace; kube-noob checks every object). Related means the same risk seen another
way: RHACS records who exec'd into a pod, kube-noob checks who is allowed to (KN-S017); RHACS combines a privileged
container with fixable CVEs, kube-noob checks the privileged part. Gap names a deploy-time setting kube-noob has no
rule for. Outside is what a static manifest check cannot see: image contents and vulnerabilities, processes and
network flows at runtime, API events, label conventions. The report also lists where the two disagree, the default
policies RHACS ships disabled that kube-noob checks, and the kube-noob rules no policy covers. A policy with
criteria kube-noob does not know is unexplained and the command exits 1.

```bash
kube-noob rhacs compare -f policies.json --format text
kube-noob rhacs compare -f policies.json --format text --outcome gap --outcome related
ROX_API_TOKEN=<token> kube-noob --config rhacs.yaml rhacs compare --live
```

`--live` reads Central with `rhacs.enabled: true` and `rhacs.endpoint` in the configuration: GET only, to that host
only, a token that can read policies (the Analyst role is enough), a short random pause between requests; under the
offline lock only an in-cluster Central (`*.svc`).

### Which exposure leads where? Attack paths

`posture scan` follows what is exposed (a Route, an Ingress, a LoadBalancer, NodePort or externalIPs Service) to the
pods it reaches and what an attacker running code in them could do: take the node (a privileged container, a
hostPath volume, the host's PID or network namespace, near-root capabilities) or use the pod's ServiceAccount token
(read Secrets, exec into pods, create workloads that run as any ServiceAccount of the namespace, escalate, bind or
impersonate, the kubelet API, or on OpenShift a privileged SCC plus the right to create pods). Each path scores
exposure (internet 3, node network or a restricted load balancer 2, internal 1) times blast radius (1-10, cluster-wide
above one namespace), lists every step with the field that proves it, and ends with a fix. A pod with
`automountServiceAccountToken: false` has no token step; unexposed pods are not paths. It reads RBAC objects, never
Secrets (Secret objects in a bundle are dropped unread). `--fail-above` makes it a CI gate. NetworkPolicies on the
entry edge are not applied: check a path with `policy reach`.

A workload whose pod spec is embedded in a CRD is scored per component, named `Kind/namespace/name[component]`: a
Ray head and each worker group separately, a KServe predictor, transformer and explainer separately. Where the
operator generates the pod's labels rather than the manifest carrying them, the scan says so in `limitations`
naming that component -- its node and API capabilities are scored, but no exposure edge can be traced to it from
that input, which is not the same as it being unexposed.

```bash
kube-noob posture scan -f k8s/
kube-noob posture scan -f k8s/ --fail-above 17
kube-noob --cluster-enabled posture scan --live -n shop -n payments
```

### AI and GPU workloads: the pods an operator runs for you

A KServe `InferenceService` or a KubeRay `RayCluster`, `RayService` or `RayJob` does not keep its pod spec at
`spec.template.spec`. It carries one per component -- `spec.predictor` (and its `workerSpec` for multi-node
inference), `spec.transformer`, `spec.explainer` and `spec.canary[].predictor` for KServe; `headGroupSpec.template`
and every entry of `workerGroupSpecs` for Ray, under `rayClusterConfig` in a RayService and `rayClusterSpec` in a
RayJob, plus that job's `submitterPodTemplate` -- and those are the pods that actually run. Every pod-level rule in
the catalogue reads them: a privileged predictor, a Ray worker running as root, a `hostPath` mount, a mutable
image tag, a mounted ServiceAccount token, a missing memory limit on something holding a model in RAM. Findings
name the component, so `spec.workerGroupSpecs.0.template.spec.containers.0` tells you which group to change.

A predictor written the usual way is read the usual way. `model: {modelFormat: {name: sklearn}, storageUri: ...}`
is a container, not a settings block -- as are the ten framework shorthands it replaced (`sklearn`, `xgboost`,
`tensorflow`, `pytorch`, `triton`, `onnx`, `huggingface`, `pmml`, `lightgbm`, `paddle`) and the explainer's `art`
-- so a privileged `model:` scores exactly what the same container in a `containers:` list would. KubeRay's
`autoscalerOptions` is read as what it is too: a container the operator injects into the head pod.

Two things these objects cannot tell you from a manifest, and both are said rather than assumed. An operator
merges extra labels onto the pods and creates the Services they are served through, so where no exposure edge can
be proven `posture scan` names the component and lists what it can do instead of leaving it looking unexposed; and
a Service or NetworkPolicy selector that does not match the labels the manifest shows makes the wiring rules
decline, because the label it asks for may be one the operator adds -- telling you a working NetworkPolicy
protects nothing would be worse than saying nothing.

It reads these four kinds in full, each at paths taken from the published CRD schema, and it checks the API group
before reading: a CRD of the same name from somewhere else is left alone, and the report says which group it
declared and that its pods were not audited rather than going quiet.

The admission webhook runs the same rules, so a privileged predictor or a root Ray head is refused there too:
the chart asks the API server to send `serving.kserve.io` InferenceServices and `ray.io` RayClusters, RayJobs
and RayServices, whether or not KServe or KubeRay is installed (a webhook rule for a resource the cluster does
not serve never matches). The generated ValidatingAdmissionPolicies and Kyverno policies do **not** cover these
kinds -- their CEL would have to index each CRD's own pod-spec paths -- and the generated file says so in its
header rather than leaving "the policies refuse exactly what the audit reports" to be read as covering them.

**Any other workload CRD is named, not passed.** There are far more of them than four -- Argo Rollouts, Knative
Services, Kubeflow Notebooks, the training-operator jobs, Seldon, Volcano, JobSet, Flink, ECK -- and a guessed
path would produce a confident wrong finding, so kube-noob does not guess. It recognises the shape instead: an
object of a kind it has no reader for that contains a pod spec is reported as one it did not audit, with the
object and the path, and `posture scan` records the same in `notRead`. You get a gap you can see rather than a
clean report you cannot trust, and a kind worth reading properly can be added with its published schema.

```bash
kube-noob audit -f serving/            # the same 98 rules, now reaching the components
kube-noob posture scan -f serving/     # per-component attack paths
kube-noob --cluster-enabled posture scan --live -n model-serving
```

### Which vulnerabilities matter here? Scanner output, VEX and reachability

`vuln report` reads what your scanner already wrote: Trivy or Grype JSON, a CycloneDX or SPDX SBOM, or an RHACS
image scan. Every format gives the same finding per package, installed version, CVE and fix version. Red Hat VEX
then removes what Red Hat says does not affect the image's product (or is already fixed in the installed version),
and each removed finding cites the statement, its justification and the VEX document. SBOMs carry packages, not
findings: their RPMs are matched against the same VEX statements. With the CISA KEV catalog (CC0) and the manifests
that run the images, findings are ranked by base score x exposure (internet 3, node network 2, internal 1) x
privileges (1 + the workload's blast radius / 10) x known exploitation (2 when listed), each with its attack path.

```bash
kube-noob corpus advisories --online --since 2026-10-01
trivy image -f json --list-all-pkgs -o trivy.json quay.io/acme/shop:1.4
kube-noob vuln report -r trivy.json -m k8s/ --kev known_exploited_vulnerabilities.json
kube-noob vuln report -r sbom.spdx.json --vex csaf_vex/ --format json
ROX_API_TOKEN=<token> kube-noob --config rhacs.yaml vuln report --rhacs-image sha256:<digest> -m k8s/
```

VEX for RHEL speaks about Red Hat RPMs only; Python, Java and JavaScript packages keep the scanner's verdict, and the
output says how many were outside VEX. A vendor's own RPM (nginx.org's `1.26.1-2.el9.ngx`) is not Red Hat's build,
so Red Hat's statements leave it alone. A module stream's statement (`nodejs:18`) applies to that stream only, and
when statements for one package disagree the finding stays. RHACS and Trivy without `--list-all-pkgs` name binary
packages only; give the image's SBOM too so not-affected statements, which name source RPMs, can match.

Reports of the same image (same digest or image id, or the same tag and the same RHEL release) are assessed
together; two images never share VEX scoping. A finding with no severity in the report is graded by its CVSS score,
or medium without one, and a known-exploited one counts as at least high, so it cannot slip past `--fail-on`. A
CycloneDX report's own analysis (`not_affected`, `resolved`) does not clear its findings unless you pass
`--trust-report-vex`: whoever wrote the report could otherwise empty it. `--product` takes CPE prefixes down to a
release (`cpe:/o:redhat:enterprise_linux:9`), so RHEL 8 statements never speak for a RHEL 9 image.

### Which code findings matter? SAST output, the images that ship it and the pods that run it

`code report` reads the SARIF your SAST tools already write: Semgrep, Bandit, SpotBugs with FindSecBugs, ESLint and
CodeQL (kube-noob has no analysis engine of its own). The same file, line and CWE reported by several tools becomes
one finding with every tool as a source; suppressed results, results the baseline says are fixed and non-failing
results are excluded with the reason, and lint or quality results are counted but never ranked. Severity comes from
the tool's `security-severity` score (bands as GitHub code scanning uses them), Bandit's issue severity, or the SARIF
level.

With the Containerfiles (`-c PATH=IMAGE[,context=DIR][,target=STAGE]`; the context defaults to the Containerfile's
directory, so `docker build -f deploy/Containerfile .` is `-c deploy/Containerfile=IMAGE,context=.`), each file is
followed into the images that ship it: copied (with its path in the image) or built (an input of a stage the final
image copies from or builds on, including sources bind-mounted with `RUN --mount=type=bind`), and the
`<Containerfile>.dockerignore` or the context's `.dockerignore` is honoured. Containerfiles are read the way
BuildKit reads them (a byte order mark, tabs, heredocs only in RUN, COPY and ADD; COPY wildcards that never cross
`/`). With
the manifests, findings rank by exposure and privileges like image vulnerabilities, each with its attack path, so an
SQL injection behind a Route ranks above the same weakness in an internal worker, and a finding in `tests/` that no
image ships is listed apart. With the images' scanner reports (`-r`), every language-package vulnerability points at
the line to change: the lockfile the image copied, and the manifest that declares the package.

```bash
semgrep --config auto --sarif -o semgrep.sarif
bandit -r web -f sarif -o bandit.sarif
kube-noob code report -s semgrep.sarif -s bandit.sarif -s codeql.sarif \
  -c web/Containerfile=quay.io/acme/shop-web -c worker/Containerfile=quay.io/acme/shop-worker \
  -m deploy/ -r trivy-web.json --source-root "$GITHUB_WORKSPACE" --fail-on high
kube-noob gate -f deploy/ --containerfile web/Containerfile --sarif-report semgrep.sarif --fail-on high
kube-noob gate --containerfile deploy/Containerfile,context=. --sarif-report codeql.sarif --fail-on high
```

Bandit writes SARIF with its `sarif` extra (`pip install "bandit[sarif]"`), ESLint with
`@microsoft/eslint-formatter-sarif`, SpotBugs with `-sarif`, CodeQL with `codeql database analyze --format=sarif-latest`.
Pass `--source-root` with the directory the tools ran in when their SARIF has absolute paths (ESLint always writes
them; SpotBugs names its source directories). In the gate, a finding fails the build only when one of the gate's
Containerfiles ships its file, or when shipping cannot be known: a path outside the source root, a path that is no
file of the repository (the scanner ran in a subdirectory), or a Containerfile that could not be read as a build.
Those fail closed and say why.

### What could go wrong with this application? A threat model

`vuln threat` builds a STRIDE threat model per application (workloads sharing `app.kubernetes.io/part-of`, else a
namespace): entry points (Routes, Ingresses, exposed Services), trust boundaries (internet to cluster, pod to node,
pod to the API through its token, the namespace network), data stores (StatefulSets, PVCs, database and cache
images) and identities (the mounted ServiceAccounts and their RBAC). Each threat has a status (open with the failing
rules as evidence, mitigated, or not assessed), the kube-noob rules, generated admission policies and RHACS policies
that mitigate it, and MITRE ATT&CK for Containers technique ids. With `-r`, public-facing exploits are assessed from
the images' scanner reports.

```bash
kube-noob vuln threat -f k8s/ --platform openshift --version 4.20
kube-noob vuln threat -f k8s/ -r trivy.json --format json
```

### Move off legacy Kyverno policies before 1.20

Kyverno 1.19 deprecated ClusterPolicy, Policy, the cleanup
policies and the legacy PolicyException, and 1.20 removes them. `kube-noob policy migrate-check -f policies/` reads
your policies and says, rule by rule, what moves to the CEL types and how. A rule is `direct` when a
`validationFailureAction: Enforce` becomes `validationActions: [Deny]` or a label pattern becomes a CEL check. It is
`inverted` when a `deny` must be rewritten as the allowed case. It is `manual` for JMESPath, API lookups, anchors or
strategic merge patches, and `blocked` when Kyverno documents no CEL equivalent, such as `sum()` or manifest
validation. Each finding points at the line and the Kyverno documentation section. With `-o migration/` it writes a
draft CEL policy for each rule that maps directly, plus a `kyverno test` skeleton that runs the old rule and the draft
on the same good and bad resources; run `kyverno test migration/` and keep a draft only when both pass. In CI,
`--fail-on blocked` stops a pipeline that still depends on something CEL cannot do. Nothing is applied: kube-noob
lints, your Kyverno CLI proves.

```bash
kube-noob policy migrate-check -f policies/
kube-noob policy migrate-check -f policies/ -o migration/ --fail-on blocked
```

### What changed since yesterday? The daily drift and policy report

`posture snapshot` records every watched object (workloads, Services, Routes, Ingresses, NetworkPolicies, RBAC,
SCCs, PDBs, HPAs, ConfigMaps, StorageClasses, claims and namespaces) as a hash of its desired state plus a short hash
per field, and today's findings with each object's owner (its `owner` or `team` label, else its namespace's). No
values are kept. `posture diff` compares two snapshots: objects added, removed and changed with the fields that
changed, findings new and fixed, and open findings by namespace, owner, rule and **NIST control**. Scaling, status, server-set
metadata and the ReplicaSets and pods a controller makes are not drift. `posture report` does both in one step and
keeps the newest snapshots and reports (JSON and Markdown) in a folder; `serve` with `posture.reportEnabled` (chart:
`posture.report.enabled`) writes one a day at a random time, and the MCP tool `posture_report` returns the newest
with an `ageSeconds`, since a failed daily run leaves the previous report as the latest one.
Excepted findings (`--exceptions`) are not counted open.

The control grouping answers a platform team's question rather than a rule author's: which controls are standing
open, and in which namespaces. A finding counts once for every control its rule names, so that column does not sum
to the finding total. Beside it, `controlStanding` separates the two things a count cannot: a control whose rules
ran and found nothing (`clean`) from one nothing evaluated (`notEvaluated`). That needs the snapshot to record
which rules ran, so a snapshot taken before that record existed gets the counts and no standing at all, and the
report says why -- a control with no open finding is not a control that passed.

A live snapshot records what it could not read, and the diff uses it. An object that was in yesterday's snapshot
and is missing from today's is only `removed` if today's run could read its kind; if the backend refused that
resource -- RBAC narrowed, a CRD uninstalled -- the object is `undetermined` and its findings are
`undetermined` rather than `fixed`, and the report says so above every count. Losing permission to look is not a
finding being fixed, and a report that conflated the two would call an RBAC regression an improvement.

```bash
kube-noob posture snapshot -f k8s/ -o monday.json
kube-noob posture diff monday.json tuesday.json --markdown drift.md
kube-noob --cluster-enabled posture report --live -n shop --exceptions kube-noob-exceptions.yaml
```

### Accept a risk on purpose: exceptions as code

An exception is a file entry, reviewed by pull request like the manifests: the rule, the objects it covers (a
namespace, or a prefix such as `team-*`, optionally a kind and a name pattern; a cluster-scoped object by kind and
exact name), who owns it, why, and when it expires (at most 400 days ahead). `kube-noob audit --exceptions` hides
exactly the findings an active exception covers and lists them as excepted with the owner and expiry; the same rule on
any other object still fails. An expired entry, or one refused for a missing owner or reason, an unknown rule, a scope
wider than a namespace or an expiry too far out, fails the gate (exit 1) with the reason. Exceptions nothing uses are
reported so they can be deleted. `policy generate --exceptions` turns the active entries into exemptions in their
rule's admission policy, including the ReplicaSets and pods the excepted workload makes.

```bash
kube-noob exceptions check examples/kube-noob-exceptions.yaml
kube-noob audit -f k8s/ --exceptions examples/kube-noob-exceptions.yaml
kube-noob policy generate --mode enforce --exceptions examples/kube-noob-exceptions.yaml -o policies.yaml
```

### What this cluster's audit configuration can and cannot record

Pass the cluster's `APIServer` object (it is in a must-gather, and `oc get apiserver cluster -o yaml` prints it)
and the audit adds a detection-coverage block: which categories of API activity the settings record -- who did
what to which object, what a create or update contained, what a get or list returned, an OAuth token grant,
activity on Event objects -- and which they do not.

Every row is read from the manifests `cluster-kube-apiserver-operator` generates the real policy from
(openshift/library-go), not from the API type's summary comment, and the block names that source so a reader
can check it. The difference matters: the comment says events are never logged, and the rule that dropped them
was removed in OpenShift 4.18 -- and one release later on a hosted control plane, because HyperShift generates
that policy from its own vendored copy, so ROSA HCP records Event activity from 4.19 and not from 4.18. That
row is therefore decided by `--platform` and `--version` together, and reported as undecidable without a
version; telling a reader that a deleted Event left no trace on a cluster whose audit log has it would be the
worst kind of wrong here. Two other rows the comment does not mention: no profile records the body of a Secret, a
ServiceAccount token, a Route, a token review or an OAuthClient, and nothing is recorded for the discovery and
health endpoints. A third is version-dependent in the other direction: the `machineconfiguration.openshift.io`
group's bodies ARE recorded under the body profiles before 4.18 and not from 4.18, and because the manifest
spells that rule's key `resource` rather than `resources` -- which the loader drops -- it covers every resource
of the group rather than the two it names. A `customRules` entry is reported per group with its precedence, and the
cluster-wide sentence says which groups it does not describe, because the first matching entry wins.

It also lists what no reading of that object can establish -- whether the records leave the cluster, how long
they are kept, whether anyone reads them, and anything that is not an API request to the OpenShift-provided API
servers. That is the honest half of a coverage claim, and the reason this is a projection of one setting rather
than a family of checks about a SIEM kube-noob has no credentials for.

```bash
oc get apiserver cluster -o yaml > apiserver.yaml
kube-noob audit -f apiserver.yaml --platform openshift --version 4.20
kube-noob audit -f apiserver.yaml --platform openshift --version 4.20 --format json | jq .detectionCoverage
```

### Does the control plane check who it talks to?

Five rules read the settings that decide whether the cluster's own components verify, authenticate and encrypt.
`KN-S037` reports an APIService that sends its API group to an extension API server with `insecureSkipTLSVerify`
(an absent `caBundle` is not a finding: the API server then uses its system trust roots, and OpenShift's service CA
fills it). `KN-S038` reads a kubeadm-style kube-apiserver static pod for the AlwaysAllow authorizer and anonymous
authentication; `KN-S039` reads the etcd static pod for plaintext listeners on a network address and for client
certificates switched off (a trusted CA file switches them on too, as etcd reads it; `--auto-tls` with no
`--cert-file` or `--key-file` switches them off again, because etcd then replaces its TLS settings with a generated
certificate's). Both recognise the component by what the container runs, never by its name or a label, and
recognition is fail-safe: a container is passed over only when nothing points at the binary -- no image whose name
has it as a dash-separated component (`etcd-amd64`, `kube-apiserver-amd64`, `hyperkube`; not `etcd-operator`),
none of its flags, no `ETCD_*` variable, no mention of it (or of k3s, rke2 or k0s) as a command word in argv, args,
env values or a script -- or when it is positively something else: `etcdctl`, `k3s agent`, or a script on the
etcd image made only of etcdctl and coreutils. A path is the program only in a `bin` or `sbin` directory, `.` or
`/`, so `tar czf b /var/lib/etcd` is not etcd. the insecure port on a network address is a CRITICAL finding on a
stated release up to 1.19;
kube-apiserver's flags are read as its parser reads them (`--authorization_mode` is `--authorization-mode`), and an
absent flag is the upstream default, named in the finding with the releases it was checked at:
anonymous authentication is on unless `--anonymous-auth=false`, and an API server given neither
`--authorization-mode` nor `--authorization-config` authorizes everything. On OpenShift, `KN-S040` reports
encryption at rest switched off on the same `APIServer` object `KN-S035` reads, and `KN-S041` an LDAP identity
provider with `insecure: true` and an `ldap://` URL.

Each says so when it cannot decide, and that is most of the work. An `--authorization-config` or
`--authentication-config` file is on the node and not in the input; a `--config-file` replaces every etcd flag;
`envFrom` can set any `ETCD_*` variable (an empty `--config-file=` falls through to `ETCD_CONFIG_FILE`, as etcd
reads it); a shell script (directly, as `busybox sh` or after `env`), a wrapper such as `tini` or `go-runner`, an
image entrypoint (no `command`, or `command: []`), or any other entrypoint -- a script file, `s6-svscan`, `/pause`,
`python3 -c` -- that something points at is not executed; k3s, rke2 and k0s set the API server's other flags from
their own defaults (an AlwaysAllow passed through `--kube-apiserver-arg` is still read as a finding); ABAC and
Webhook authorize from a file not in the input; a non-zero insecure port on 1.20-1.23, and any insecure-port flag on 1.24 or later or an assumed version, is a
setting the server refuses; an object that writes the flags -- a kubeadm `ClusterConfiguration`, Cluster API's
`KubeadmControlPlane`, the `kubeadm-config` ConfigMap, a kind cluster, a k0s `ClusterConfig`, a Rancher `Cluster` --
is read for AlwaysAllow, an explicit `anonymous-auth: true` and a plaintext etcd URL, and named as not read for the rest; `--enable-v2` is refused by etcd 3.6 unless the image says 3.5; a kubeadm
`ClusterConfiguration` or an OpenShift `KubeAPIServer` writes the flags and is named as seen and not read; a `$(VAR)` anywhere in argv is not expanded; a flag
kube-noob does not know, given without `=` before another flag, may swallow it (so `--version` or `-h` there is
not read as one); an authorization-mode combination the API server refuses to start with, and a `KMS` encryption
type with no `kms` block, are not read as a setting; an encryption type or identity provider type openshift/api
does not define is not guessed at. On ROSA with HCP the API server, etcd
and the OAuth server are configured from the `HostedCluster` on the management cluster, on the rest of the
OpenShift family the API server is operator-managed, and off OpenShift the OpenShift objects are not read (the
reason names `--platform openshift`). In each case the rule is left out of the evaluated list and the report states why -- naming every declined
object, up to a cap -- in the text view, the JSON (`declined`), the SARIF notifications, the MCP result and the
gate's JSON, SARIF, Markdown and HTML. When the rule found nothing anywhere, its controls count it as not
evaluated and `controlSummary.notEvaluatedRules` names it. When it found something on one object and declined on
another, the finding is reported and counted under its controls as a finding, the decline is still stated in
`assumptions` and `declined`, and `controlSummary.partlyEvaluatedRules` names it (as do the KSI rows, the OSCAL
control remarks, the text view, the SARIF and the gate); it is not in `notEvaluatedRules`, which lists rules that
reached no verdict at all, so every rule not evaluated in full is in exactly one of the two. `declined[rule].decided`
says how many objects the rule read in full beside the ones it declined. An
input with nothing of the rule's kind declines quietly; `controlSummary.notEvaluatedRules` and the text view's
"not evaluated:" line still name it. An exception whose rule did not reach a verdict is listed under
`exceptions.unusedNotEvaluated` as well as `unused`, and the text view does not call it stale.

```bash
kube-noob audit -f /etc/kubernetes/manifests/ --platform kubernetes --version 1.33
oc get apiserver cluster -o yaml > cp.yaml; echo --- >> cp.yaml; oc get oauth cluster -o yaml >> cp.yaml
kube-noob audit -f cp.yaml --platform openshift --version 4.20
```

### Enforce the audit rules at admission

`policy generate` turns every audit rule that can be decided from one object into an admission policy: a
ValidatingAdmissionPolicy with its binding (built into Kubernetes 1.30+, so every OpenShift 4.20+), a Kyverno
ValidatingPolicy (`policies.kyverno.io/v1`, Kyverno 1.18+), or both, carrying the same CEL. Each policy is named
after its rule (`kube-noob-kn-s001`), and its message carries the rule id, the fix and the source. Start in audit
mode, which admits and warns (`kubectl` prints the warning; the API audit log and Kyverno reports record it), then
switch a rule to enforce when its warnings are gone.

The policies refuse exactly what `kube-noob audit` reports for that one object at low severity or above, never
more: a test compares both on 2,700 generated objects, and CI applies every policy to a kind cluster and checks
that a server-side dry-run refuses the rule's bad fixture and admits its good one. Four rules check less than the
audit and say so in a `kube-noob.io/limitation` annotation (a `--password` value in the next argument, a
ServiceAccount's token opt-out, an HPA-scaled workload, a budget compared with the replica count). Rules that need
other objects (a Service and its pods, a claim and its StorageClass) or that the API server already enforces are
listed in the file header with the reason. Platform namespaces (`kube-*`, and `openshift-*` on OpenShift) and the
platform's operators are exempt; calibrate rules (probes, resources, replicas) skip objects a controller owns, so a
rollout is never blocked by its own ReplicaSets.

One rule is generated only when you have configured it: `KN-S036` refuses an image from a registry outside
`audit.allowedRegistries`, and with no list there is nothing to enforce, so the file header says so rather than
emitting a policy that admits everything. Set the list in the configuration file (`quay.io`, or
`quay.io/my-org` to narrow it to one organisation) and it generates for both engines. Two kinds of list are
refused rather than compiled, again with the reason in the header: one naming `docker.io`, because deciding
whether `nginx` is a Docker Hub image needs string handling the API server's CEL does not have, and one whose
host has no dot, port or `localhost`, because `myregistry/app` is a Docker Hub image and the policy would admit
what `kube-noob audit` reports.

```bash
kube-noob policy generate --platform openshift --version 4.20 --mode audit -o kube-noob-policies.yaml
oc apply -f kube-noob-policies.yaml
kube-noob policy generate --rule KN-S001 --rule KN-S009 --mode enforce --engine vap -o enforce.yaml
kube-noob policy generate --engine kyverno --exclude-namespace legacy-apps -o kyverno.yaml
```

Through the MCP or HTTP tool there is no `-o`, so the inline YAML is capped at 128 KiB: every rule on every
engine renders about 380 KB (~95,000 tokens), which is more than most callers can hold. Over the limit the result
is the counts, `skipped`, `yamlOmitted: true`, the byte count and how to ask for less -- 14,168 bytes instead of
380,670, with nothing truncated. Narrow it with `rules` or a single `engines` entry, or pass `allow_large: true`
if you can hold the whole set.

With `-o`, the JSON or YAML result is the path, the file's size and the counts -- not the policy set as well.
The whole generated set is about 358 KB of YAML, so returning it inline *and* writing it made the result larger
with `-o` than without; a caller that names a file has already said where it wants the bytes. Without `-o` the
rendered YAML is still returned inline, because there is nowhere else for it to go.

### Every finding as a kubectl warning: the admission webhook

The generated policies cover the rules CEL can decide. `kube-noob-admission` runs the audit itself: every finding of
a created or updated object comes back to `kubectl` and `oc` as an admission warning (`Warning: [KN-S001] Privileged
container: ...`, at most `admission.maxWarnings`, each at most 256 characters), so developers see them where they
work. It denies nothing until you list a rule in `admission.enforce`, and then only that rule, and on an update only
a finding the old object did not have: turning a rule on never freezes a Deployment that already breaks it. The
webhook has `failurePolicy: Ignore` and a 3-second timeout, so a dead or slow webhook never blocks the cluster; it
never mutates, stores nothing but counters, and fetches nothing. The system namespaces, `openshift-*`, its own
namespace, `admission.excludedNamespaces` and namespaces labelled `kube-noob.io/admission=disabled` are skipped, and
so are Pods, ReplicaSets and Jobs a controller owns (their owner was checked). Rules about other objects of the
namespace (a PodDisruptionBudget for a Deployment, a NetworkPolicy, a claim's StorageClass) warn only with
`admission.lookups`, which lists those kinds read-only in the background, and can never be enforced. Exceptions use
the same ExceptionList as `kube-noob audit --exceptions`.

`kubectl debug` is checked too, which almost nothing checks: an ephemeral container is added through the
`pods/ephemeralcontainers` subresource, a different admission request from the Pod's own creation. The webhook
evaluates that one subresource and reports only what the request adds, so a privileged debug container is
refused where the rule is enforced while a Pod that already breaks that rule can still be debugged. The
generated policies are deliberately not extended to it: they have no before-and-after comparison, so one would
refuse every debug of an already-failing Pod.

One rule needs configuring before the webhook can say anything about it. `KN-S036` compares every image against
`audit.allowedRegistries`, and with no list it declines, so it warns about nothing; set the list and the webhook,
`kube-noob audit` and `policy generate` all read the same one and give the same verdict. Enforcing it without a
list is refused at install and at startup rather than denying nothing, and an entry that could never match an
image -- `MyRegistry`, or a host with no dot, port or `localhost` -- is refused by the chart's values schema and
when the configuration loads.

```bash
helm upgrade --install kube-noob oci://ghcr.io/kube-noob/charts/kube-noob -n kube-noob --create-namespace \
  --set admission.enabled=true --set "audit.allowedRegistries={quay.io/my-org}"
helm upgrade kube-noob oci://ghcr.io/kube-noob/charts/kube-noob -n kube-noob --reuse-values \
  --set "admission.enforce={KN-S001,KN-S009}"
kube-noob admission review -f review.json --enforce KN-S001
```

On OpenShift the service CA operator issues the serving certificate and injects the CA (the default,
`admission.certificates: openshift-service-ca`); elsewhere use `cert-manager` with an issuer, or `secret` with your
own certificate and CA bundle. CI installs it on a kind cluster: warnings in warn mode, 600 fuzzed reviews never
denied, 50 requests per second for 30 seconds under 50 ms at p99, denial of the enforced rule only, an update of an
existing breaker admitted, and nothing blocked with the webhook scaled to zero.

### Evidence an assessor can import: OSCAL assessment-results

```bash
kube-noob audit -f k8s/ --platform openshift --version 4.22 --oscal > assessment-results.json
kube-noob gate  -f k8s/ --platform openshift --version 4.22 --oscal > assessment-results.json
```

An OSCAL 1.2.3 assessment-results document, from either command: each finding becomes an observation with
method `EXAMINE`, and each control becomes an OSCAL finding targeting that control's objective id
(`ac-6.10_obj`). What it will not say is the point. A control is `satisfied` only where its rules actually ran
and produced nothing. A control no rule evaluated is named under `exclude-controls` and gets no finding at all.
A control whose rules ran and reported findings that a `--min-severity` filter removed is `not-satisfied` with
reason `other`, never a pass -- so the verdict per control is the same at every filter level, and no flag turns
a failing audit into a clean record. An accepted exception is `not-satisfied` too, with the same reason: a
signed-off finding is a recorded decision, not a met objective. Every description ends with the sentence the
report carries, that this is evidence about a control and not a claim of compliance.

Every uuid is a v5 uuid over the assessment -- the objects, every finding's identity, each control's coverage
and the imported plan -- so two runs over the same bundle are byte-identical and a pipeline can diff them,
while two runs that reach different verdicts cannot collide on one identity.
`--oscal-import-ap https://grc.example.com/ap.json` points the required `import-ap` at your assessment plan;
without it the document says plainly that no plan was imported rather than inventing one. The exit code is the
audit's or the gate's either way, so the verdict is the same with the flag as without.


## Claude and MCP users

Install the plugin or add the MCP server (see the [README](../README.md)), then ask for the `getting_started` prompt.
It reads your saved profile, asks for your role and platform, and suggests the first three tools to use.

### Chat on claude.ai: the Agent Skill

The local MCP server does not run in chat on claude.ai. Upload `kube-noob-skill-<version>.zip` (a release asset, or
`python scripts/build_skill.py --zip kube-noob-skill.zip` from a checkout) under **Customize > Skills** and turn on
code execution. Paste a describe, an event or a manifest: Claude runs `kn.py insight` or `kn.py audit_manifests` in
its sandbox and cites the playbook, rule and issue ids kube-noob returns. The skill is always offline: no web lookups,
no cluster, no model inside.

## Model builders

Build the corpus, score answers with the deterministic reward and export datasets: see [training](training.md).
