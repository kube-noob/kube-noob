# External ideation, reviewed

Three external AI reviews of kube-noob's FedRAMP KSI report arrived on 2026-11-05. Between them they proposed
about 250 checks, a dozen modules, two architectures and five "if I could only build five things" lists. This
file is the durable record of what was in them and what this project decided, so the thinking is not lost in a
chat log and nobody re-litigates it from memory.

| Source | sha256 (first 16) | Shape |
|---|---|---|
| Review A | `2c07edf49120ed01` | 12 control families, ~120 numbered checks (`IAM-001`...), a five-engine architecture, an evidence-contract field list |
| Review B | `8365003f7cc3cd30` | A 6-phase roadmap, 8 rule families with detection logic and test cases (`KN-WRK-001`...), an evidence JSON schema, a KSI mapping registry, a 12-gate test matrix |
| Review C | `a6f58a188fd6c762` | 12 security modules, 8 "standout" features, a FedRAMP intelligence layer, a remediation engine, a 3-score risk model, 10 extra ideas |

The reviews are not quoted here. Every proposal below is restated in this project's own words, and every verdict
was checked against the code on 2026-11-06 — the 92-rule catalogue, the 108 commands, the 48 MCP tools — not
recalled.

## What they got right, and what that is worth

All three independently identified the same architectural point, and all three put it first: **a shared NIST
control ID must never imply that a rule proves a KSI's subject**. Two of them named `onSubject` as the field to
make mandatory. That is [G219](guidance.md), shipped before the reviews were written, and the reviews were
reading the report it produces — so this is confirmation rather than discovery. It is still worth recording,
because three independent readers reaching for the same safeguard is the strongest available evidence that the
safeguard is the right one and should never be quietly relaxed.

They also converged on a second point this project had already made load-bearing: **an unknown must not read as
a pass**. Review B wrote test cases for it ("a partial manifest bundle does not produce a namespace-wide pass",
"missing seccomp on a node with unknown support returns Not evaluated, not a false pass"); Review C proposed a
six-state verdict model; Review A asked for an `Evaluation status` field. kube-noob has three-valued verdicts,
`cannot_decide`, `partial_bundle`, `notEvaluatedRules` and `notReadBeyond`. Same conclusion, arrived at
independently.

Where the reviews are weakest is uniform and predictable: **they price every proposal at the cost of naming it**.
Review A's 120 checks include MFA enforcement, JIT access expiry, crypto-mining detection, log retention
verification, restore-test evidence and training-effectiveness review. Each is a real control. None of them can
be decided by a tool that holds no credential for an identity provider, a SIEM, a backup system or an HR system,
and Review A says so itself in three separate asides — then counts them in the total anyway. A catalogue of 250
checks of which 60 can answer is not five times better than a catalogue of 92 that all can; it is the same
product with 190 rows that say "not evaluated", which is the coverage theatre [G226](guidance.md) exists to
refuse.

## Verdicts

Verdict key: **Shipped** — in the product today. **Shipped differently** — the need is met, by a different shape,
and the difference is the point. **Taken** — accepted into the backlog with an id. **Refused** — a deliberate no,
with the reason. **Blocked** — wanted, but gated on something this project does not have.

### Already shipped before the reviews were written

| Proposal | Where it lives |
|---|---|
| `onSubject` as a mandatory mapping field; never derive a KSI from a shared NIST id (all three) | `audit/fedramp.py`, G219, G221, G226 |
| Six-state / explicit-unknown verdicts; partial bundles must not pass (A, B, C) | three-valued verdicts, `cannot_decide`, `partial_bundle`, `notEvaluatedRules` |
| Versioned, hash-pinned FedRAMP ruleset rather than a copied KSI table (B) | `vendor/fedramp/fedramp-ksi.json`, rules `2026.11.02.01`, regenerated and `--check`ed by `scripts/fedramp_ksi.py` |
| Attack-path analysis, exposure × blast radius, every step with its evidence field (B, C — C called it the strongest differentiator) | `posture scan`, `attack_paths.py` |
| Privileged containers, host namespaces, hostPath, capabilities, seccomp, resource limits, pod-security enforcement (B's family A) | `KN-S001`, `KN-S009`, `KN-S010`, `KN-S005`/`KN-S006`, `KN-S008`, `KN-C004`/`KN-C005`, `KN-S032` |
| Wildcard RBAC, cluster-admin bindings, escalate/bind/impersonate, token automount, legacy token Secrets (B's family B) | `KN-S015`, `KN-S016`, `KN-S017`, `KN-S014`, `KN-S027` |
| Namespace without NetworkPolicy, allow-all ingress, a policy selecting no pods, external exposure, unenforced CNI tier (B's family C) | `KN-N001`, `KN-N007`, `KN-N012`, `KN-N004`/`KN-N008`, `KN-N014` |
| Credentials in env and in ConfigMaps, secret material in manifests (B's family D) | `KN-S013`, `KN-S026`, `KN-S018` |
| Kubernetes audit logging not configured, and event types absent for one group (B's `KN-LOG-001`/`002`, A's `AUD-001`/`003`) | `KN-S035`, G226 — the one logging question a credential-free tool can decide |
| Mutable image tags / digest pinning (A, B, C) | `KN-S012` |
| CVEs ranked by reachability, with VEX applied rather than raw CVSS (A, C) | `vuln`, Red Hat VEX, VUL1 |
| GitOps / live drift against an approved state (A, B, C) | `drift.py`, `posture snapshot` and `posture diff` |
| Exception management with owner, reason, expiry and scope (C) | `exceptions check` — refuses an entry with no owner, an unknown rule, too wide a scope, or an expiry over 400 days |
| Pre-deploy guardrails on manifests and Helm charts (C) | `gate`, `helm-audit`, SARIF, the GitHub action, pre-commit hooks, a Tekton task |
| Ticket creation from findings (C) | `ticket` |
| Evidence export for an auditor (B, C) | OSCAL export, `--html`, `ksi` |
| Multi-framework mapping without pretending similar ids mean identical requirements (C) | NIST SP 800-53 Rev. 5 + FedRAMP 20x KSI, with the `onSubject` discipline between them; Docker CIS benchmark items cited on the rules that match them |
| Historical posture and control-regression detection (C's idea 4) | `posture snapshot` / `posture diff`, per-control standing in `drift.py` |

### Shipped differently, and the difference is the point

| Proposal | What kube-noob does instead, and why |
|---|---|
| An evidence JSON schema with ~14 provenance fields per finding, an evidence store with integrity hashes, and a reproducible six-months-later answer (B §4, C's evidence vault) | Findings carry the rule, the object ref, the exact field path, the value, the controls, the severity and the platform/version the verdict was made under; the reproducibility story is the **snapshot**, not a vault — `posture snapshot` writes an owner-only snapshot with its own checksum manifest, and the audit is deterministic on the same bytes. A per-finding integrity hash over evidence the tool itself just read is ceremony: it proves the tool did not corrupt its own output, not that the cluster was in that state. Worth revisiting only when someone needs to hand a third party evidence they cannot re-collect. |
| Separate `rules/` tree with JSON/YAML rule definitions and a JSON Schema per rule (B §9) | Rules are Python with a declarative registry and a `tests/fixtures/rules/<id>.yaml` good/bad pair each, which AGENTS.md requires before a rule merges. A YAML rule DSL buys third-party rule authoring, which nobody has asked for, and costs the type checker — the thing that catches a rule bug before any test runs (G220, G223). |
| "Three independent scores: security risk, compliance readiness, operational resilience" (C §5) | Attack paths score exposure × blast radius; the KSI view counts evidence and gaps; reliability and availability rules are a separate category. Deliberately **not** composed into three headline numbers, for the same reason the KSI page shows no percentage: a single number invites the comparison it cannot support. |
| A dashboard with asset, finding, coverage and unevaluated tiles (B §8, C) | `--html` ships a self-contained report with the caveats rendered above the findings (U1). A live dashboard is U2 and is worth nothing before N11's `/metrics` exists. |
| Remediation: explain / prepare a patch / apply through a controlled integration (C §4) | `fix` and `generate` produce the manifest change and the admission policy; **the third option is refused** — see below. |
| Installed-operator and resource inventory (A, B's `KN-SUP-006`, C's module A) | The operator half shipped as moat item **E2** (`operators inventory`, G270): installed OLM operators from manifests, a must-gather or the cluster, with what could not be read stated. A general resource inventory did not. An "authoritative real-time inventory" (`KSI-PIY-GIV`) from a read-only scanner is a narrower claim than the reviews imply: the inventory says which of its inputs it could not read. |

### Taken into the backlog

These are the proposals that survived: a real gap, decidable from evidence kube-noob can actually reach, and not
already queued. Each gets an id in [roadmap.md](roadmap.md).

| id | What, and why it survived |
|---|---|
| **R1** | ~~A rule for excessive RBAC access to Secret objects~~ — **the claim behind this item was wrong, and the correction is the item.** It said "there is no catalogue rule that reports it on its own". `KN-S017` has reported it all along, as one branch of the escalation-paths rule, which is what this file got for reading the three reviews' gap lists instead of the code. What the reviews actually asked for was finer than a new rule and the catalogue was not doing it: `list` returns the Secrets' **contents**, so one grant hands over every value in scope, while a `get` hands over the ones whose names the holder already knows — and both were reported identically, a namespaced `list` at LOW. Fixed in `KN-S017` (G240), along with a false positive it turns out to have had: a `get` narrowed by `resourceNames` is the least-privilege pattern upstream recommends, and the rule was calling it an escalation path. |
| **R2** | **Certificate expiry from TLS Secrets and Routes already in the bundle.** All three reviews ask for it. Nothing in the code reads a `notAfter` today — verified against the code this time, not the reviews' gap lists. Parsing the public certificate needs no credential, no network and no private key. It does need an X.509 parser, and `cryptography` is in `requirements.lock` only **transitively**: building a rule on an undeclared dependency is the G228 defect, and declaring one is a decision about every install, the air-gap bundle and the plugin's own lock. **Blocked on the maintainer's call**, recorded rather than guessed. |
| **R3** | **Registry and publisher allowlist as a configurable rule.** Review A (`IMG-006`), B (`KN-SUP-005`) and C all name it; nothing implements it. It is decidable from the image reference plus a policy the operator supplies, and it fails honestly when no policy is configured (not evaluated, not clean). |
| **R4** | ~~A detection-coverage statement for the logging family~~ — **shipped** (G244). Review C's "detection coverage map", from `KN-S035`'s reading of the audit configuration: which categories of API activity this cluster's own settings can and cannot record, per group where a `customRules` entry overrides the top level. Every row is the field documentation of `Audit` in openshift/api rather than advice, an unrecognised profile is reported as undecidable instead of empty, and the block carries what no reading of that object can establish — forwarding, retention, review, and anything that is not an API request. One honest answer in place of eleven unanswerable AUD-* checks. |
| **R5** | **Operator Subscription and add-on vulnerability surface.** Review A's `RA-010` ("vulnerable third-party operators"). **Shipped narrower than proposed** (G278): the shipped corpus cannot match installed CSV *versions* -- it keys issues by OpenShift release and text and states fixes as OpenShift releases -- so `operators issues` is a release-note lookup through an explicit name table, for Red Hat's builds and the cluster's release, that never decides a fix and is not a gate. Third-party operators are not in the OpenShift release notes at all, and community or certified builds are not looked up, so `RA-010`'s "third-party" half stays unanswered. The next step is the local Jira copy's components and fix versions. |

Not one of the five is a new engine, an integration or a credential. That is the test they had to pass.

### Refused, with the reason

Grouped by the reason, because the reasons repeat and the grouping is the argument.

**It needs a credential this product has promised not to hold.** MFA enforcement, IdP account lifecycle,
joiner/mover/leaver evidence, dormant and orphaned accounts, OIDC issuer validation against the live issuer, JIT
access expiry, authentication-failure monitoring (A's `IAM-001`, `004`-`012`; B's `KN-IAM-007`, `KN-ORG-001`;
C's module C). Log forwarding health, SIEM ingestion timestamps, log retention and tamper-protection, alert-rule
execution, log-review records (A's `AUD-004`-`AUD-012`; B's `KN-LOG-003`-`008`; C's module D). Secret rotation
and revocation records, KMS key lifecycle (A's `SEC-003`, `005`, `008`, `011`; B's `KN-SEC-004`, `008`).
Backup completion, restore tests, RPO/RTO, immutability (A's `BCP-001`-`012`; B's family G; C's module I).
Training effectiveness, incident exercises, security-investment review (B's family H). Cloud IAM, security
groups, bucket exposure, disk encryption, metadata-service reachability (A §10; C's module J). CI/CD approvals,
branch protection, pipeline identity, separation of duties (A §11; C's module K).

Every one of these is a legitimate control and kube-noob reports that it cannot evaluate it. The reviews propose
closing the gap with read-only integrations to an IdP, a SIEM, a cloud provider, a secret manager, a backup
system, a Git provider and a training system. That is between seven and twelve credentialed connectors, each with
a permission model, a token lifecycle and a blast radius — in a product whose entire distribution argument is
that it runs offline in a disconnected cluster and holds nothing. The honest gap is cheaper than the connector,
and it is the reason a FedRAMP assessor can run this at all.

**It needs runtime telemetry, and a static scanner must never claim to have it.** Shell execution, reverse
shells, crypto-mining, syscall anomalies, container-escape indicators, behavioural baselines (A's
`RUN-001`-`012`; C's module E). Both reviews say plainly that a manifest scanner cannot establish these, and
both then list them as checks to build. kube-noob's own rules are the inverse: they report the *configuration
that makes an escape possible*, which is decidable from the manifest, and say nothing about what happened. A
Falco or Tetragon integration is a different product with a different trust model; the `insight` router already
recognises Falco output when a person pastes it, which is the correct depth for a tool with no agent.

**It is a write to a customer's cluster.** Review C's remediation option 3 ("apply a fix through a controlled
integration"), auto-created pull requests, assignment and post-deploy verification. Review B states the rule
itself better than this file could: no rule may create, patch, delete, restart or exec, and any write-capable
capability must be a separately permissioned product rather than hidden in the scanner. kube-noob generates the
patch and the policy and stops. The safety contract (`scripts/safety_contract.py`) proves it, per release.

**It is an organisational artifact, and a tool that reports on it is making it up.** Data-classification
discovery, PII detection, data-removal completion, unapproved data exports, deletion requests fulfilled (A §12;
B's `KN-DAT-001`/`002`; C's module L). `KSI-SVC-RUD` is a workflow with human sign-off. A scanner can report
that a PersistentVolumeClaim was deleted. It cannot report that data was removed, and the gap between those two
sentences is the whole control.

**It is a product this project is not.** "An AI-powered Continuous Security Posture, Attack-Path and Compliance
Evidence Platform" (C §10), a security digital twin, risk prediction, an AI security analyst, multi-tenant
architecture with its own RBAC and SSO. The product's positioning is **"No AI inside. Works with yours."** — the
engine is deterministic, which is what makes its output usable as evidence and reproducible in a disconnected
cluster. An AI analyst inside the tool would invert that. Multi-tenancy, platform SSO and a 3PAO-grade evidence
platform also need a legal entity and an assessment this project does not have; see
[the honest ceiling](roadmap.md) and [editions.md](editions.md).

**It renames things that already work.** Review B's proposal to re-namespace the catalogue as `KN-WRK-*`,
`KN-IAM-*`, `KN-NET-*`, `KN-SEC-*` while preserving the old ids. Review B also says, correctly, "keep the
existing rule IDs: add new rule families without breaking existing reports" — those two instructions conflict,
and the existing ids win. `KN-S001` is in published reports, SARIF uploads, exception files, generated Kyverno
and Gatekeeper policies, the OSCAL export and six people's CI configuration. A prefix is not worth a migration.

**It is already a release blocker here, phrased as a proposal.** Review B's ten acceptance criteria (unique
versioned rule ids, positive/negative/incomplete tests per rule, evidence provenance per finding, no KSI pass
from a shared NIST id, no organisational KSI from configuration, redaction, demonstrably read-only, versioned
mappings, posture separated from compliance readiness) map one-for-one onto rules already enforced by
`scripts/check.sh`, `scripts/safety_contract.py`, the `tests/fixtures/rules/` requirement in AGENTS.md and
G219-G226. Recorded as agreement, not as work.

## What the reviews missed

Worth writing down, because it is the measure of what external ideation is and is not good for. None of the three
reviews found a defect. Between them they proposed about 250 checks and did not identify a single case where the
existing engine returns a wrong answer. The four red-team passes run on 2026-11-05/06 found 49, and the two that
mattered most are the kind no catalogue proposal would have reached:

- a rule that skipped its cross-object branch under `partial_bundle` **without declining**, so it counted clean
  while the report's own caveats said otherwise;
- pod specs embedded in operator CRDs read as clean by every pod-level rule, because the reader looked only at
  `spec.template.spec` ([G229](guidance.md)) — a KServe predictor running privileged, as root, with
  `hostPath: /` produced 14 findings as a Deployment and zero as an `InferenceService`.

Both are the same failure the reviews correctly named in the abstract — an absence reading as a pass — found in
the place the reviews could not see, which is inside the code. Breadth proposals come from reading the output;
defects come from attacking the engine. Keep asking for both, and do not mistake one for the other.

## External review D (GPT), 2026-11-11

A fourth external review proposed fifteen checks on the control plane and the trust boundaries around it: who
the aggregator, the API server, etcd and the OAuth server verify, and who can reach them. Each verdict below was
checked against the code on 2026-11-11, and the claim that five of them are absent was checked by searching the
source rather than the catalogue: before G272 no file read `insecureSkipTLSVerify`, `anonymous-auth`,
`authorization-mode`, `AlwaysAllow`, `identityProviders`, `spec.encryption` or `listen-client-urls`. As above, the
review is restated in this project's words and not quoted. The verdict key is the one at the top of this file.

| Proposal | Verdict | What, precisely |
|---|---|---|
| An APIService whose aggregator does not verify the extension API server | **Taken and shipped** as `KN-S037` (G272) | `insecureSkipTLSVerify: true` with a `spec.service`. A local APIService (no service) is out of scope, and an absent `caBundle` is not a finding: upstream uses the API server's system roots, and OpenShift's service CA fills it. Generated as a ValidatingAdmissionPolicy; not for Kyverno, whose default resourceFilters exclude APIService |
| A kube-apiserver that accepts anonymous requests or authorizes every request | **Taken and shipped** as `KN-S038` (G272) | Read from the argv of a container whose `command` runs the binary (or `hyperkube kube-apiserver`). An absent flag is the upstream default, named with the releases it was checked at; a mode the API server does not accept declines. A named `--authorization-config` or `--authentication-config` file declines the half it governs, and the whole OpenShift family declines with the reason. Every other way of starting it -- a shell script, a wrapper, `hyperkube apiserver`, k3s, rke2, k0s, an image entrypoint, `$(VAR)` anywhere in argv, a flag that may swallow the next -- declines with the reason; an input with no API server declines quietly |
| etcd serving clients or peers in plaintext, or without client certificates | **Taken and shipped** as `KN-S039` (G272) | Network-address `http://` in `--listen-client-urls`, `--listen-client-http-urls`, `--advertise-client-urls`, `--listen-peer-urls` and `--initial-advertise-peer-urls`, and client certificates off beside a network TLS listener -- off meaning neither the switch nor a trusted CA file, either of which makes etcd require a certificate. Loopback and sockets are not findings. Flags, then `ETCD_*` variables, then defaults, as etcd reads them; `--config-file` and `envFrom` decline the container, and one undecidable setting declines that setting and keeps what was decided. Launch shapes not read directly decline as for `KN-S038`, OpenShift's own shell-wrapped etcd pod among them |
| OpenShift encryption at rest switched off | **Taken and shipped** as `KN-S040` (G272) | The same `APIServer` singleton and reader as `KN-S035`. Unset or `identity` is a finding; a type openshift/api does not define declines; ROSA with HCP declines, because a hosted control plane's encryption is the `HostedCluster`'s `spec.secretEncryption` |
| An OpenShift identity provider that does not verify its server | **Taken and shipped** as `KN-S041` (G272), for the one switch the API defines | Only LDAP has an explicit insecure switch: `insecure: true` with an `ldap://` URL is plaintext, `ldaps://` always uses TLS, `insecure: false` upgrades with StartTLS. A missing `ca` is the system roots, not a finding; an unknown provider type declines; ROSA with HCP declines (`spec.configuration.oauth` on the `HostedCluster`). `HTPasswd` is not flagged: no primary source says a local htpasswd provider is insecure |
| The same, for an `http://` URL on a BasicAuth, Keystone, GitLab or RequestHeader provider | **Blocked** on a primary source | Whether the authentication operator accepts an `http://` URL there, or refuses to honour the provider, could not be verified on 2026-11-11. A finding that says passwords cross in plaintext about a provider the platform refuses would be wrong in the direction that matters, so it is not shipped until the operator's validation is read |
| Helm hook resources skipped by the chart audit | **Shipped** | `helm template` writes hooks unless `--no-hooks` and test hooks unless `--skip-tests` (helm/helm `pkg/cmd/template.go` at v4.0.0, `cmd/helm/template.go` at v3.19.0); `helm-audit` and `gate --chart` pass neither, and nothing downstream filters an annotation. `tests/test_helm_hooks.py` holds that a privileged `pre-install` Job and its ClusterRole get exactly the findings of the same objects without the annotation, and that the gate points them at the hook's own template |
| A validating or mutating webhook that fails open | **Shipped** as `KN-S030` | Every webhook in a Validating- or MutatingWebhookConfiguration whose `failurePolicy` is `Ignore`, and any value that is neither `Fail` nor `Ignore` (the API server refuses it, so the check does not exist). Absent is `Fail`, the default, and clean. It does not read `timeoutSeconds`, `sideEffects`, `matchPolicy`, the selectors, or whether the service behind the webhook exists |
| ServiceAccount tokens exposed to workloads that do not need them | **Shipped** as `KN-S014`, with `KN-S027` | Every pod template that automounts its token: unless the pod sets `automountServiceAccountToken: false`, or its ServiceAccount in the bundle does and the pod does not override it with `true`. LOW, because whether the token matters is what the RBAC rules (`KN-S015`-`KN-S017`) and the attack-path scan decide. `KN-S027` reports long-lived token Secrets. Neither reads a token mounted by hand through a projected volume, nor whether the application calls the API |
| Routes and Ingresses that serve plain HTTP | **Shipped** as `KN-N002` and `KN-N003` | A Route without `spec.tls` (HIGH) or with `insecureEdgeTerminationPolicy: Allow` (MEDIUM); an Ingress with no `spec.tls` (MEDIUM). Neither checks that the TLS hosts cover every rule host, that an Ingress controller redirects HTTP, that an edge Route's backend leg is encrypted, a certificate's expiry (R2), or Gateway API listeners |
| An admission webhook whose selectors let some objects bypass it | **Refused** | Whether a bypass is a defect turns on which webhooks are mandatory, and no manifest states that. Excluding namespaces is how webhooks are meant to be scoped -- `KN-S030`'s own remediation says to. A configurable list of mandatory webhooks would be the `KN-S036` pattern (a policy from the configuration file, declining without one) and can be Taken when someone asks for it |
| A webhook `caBundle` that is not a valid certificate | **Blocked** on R2 | Reading a certificate is the X.509 parser decision R2 is waiting on; this is one more reader of the same dependency |
| Kubelet authentication and authorization | **Taken** already, as N2 | The kubelet's configuration is in the rendered `MachineConfig`s a must-gather carries, which is N2. No manifest kube-noob audits states it |
| A privileged SCC granted to a subject that should not have it | **Taken** as **R8** | `KN-S019` reports an SCC that allows privileged containers, host namespaces, host directories, host ports, privilege escalation or `RunAsAny` UIDs, whoever may use it; it does not read the SCC's `users` or `groups`. `KN-S028` reports RBAC bindings to everyone (`system:authenticated`, `system:serviceaccounts`, `system:unauthenticated` ...) for any role, including one with `use` on an SCC, but not an SCC's own subject list. The attack-path scan does read `users` and `groups` -- for one ServiceAccount at a time, and only as a path when that account can also create workloads. So an SCC whose own `groups` hand a permissive SCC to every authenticated user is never one audit finding. That is the gap R8 takes |
| A CRD conversion webhook that can break or alter objects | **Refused** | A conversion webhook that is down makes the resource unavailable, which is an availability question rather than a trust boundary, and the API server already refuses most malformed conversion configurations itself. There is no decidable setting to report |

Four of the fifteen were already in the product (Helm hooks now held by a test), two are refused with the reason,
two are blocked on a fact or a decision this project does not have yet, two are taken into the backlog (N2 was
already there, R8 is new), and five are new rules. The new ones share one property the review did not ask for and
the code had to supply: each **declines with a stated reason** where the manifest does not say -- a flag that names
a file on the node, a hosted control plane, a shell script or wrapper, a value behind `$(VAR)` -- and with none
where there is nothing of its kind to read. The first version did not hold that everywhere: an adversarial review
found fifteen shapes that still read as clean or that declined invisibly, each now held by a test in
`tests/test_control_plane_review.py`. The same review found that most of the older catalogue counts as evaluated
and clean when the input holds nothing of its kind -- 91 rules do on a single ConfigMap -- which inflates the
coverage record for every control; that is recorded as a finding about the catalogue, not fixed here.
