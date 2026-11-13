# Shipping kube-noob through Red Hat's distribution channels

Researched 2026-10-30 against the live Red Hat, Helm and GitHub documentation. Every factual claim below is tied to a
page in [Sources](#sources). Where a source contradicted an earlier assumption in
[openshift-catalog.md](openshift-catalog.md), this file follows the source and says so.

Read this with [openshift-catalog.md](openshift-catalog.md) (the short route map) and
[release-readiness.md](release-readiness.md) (the per-release checklist). This file is the decision document: which
channel, in what order, with the commands, and with the blockers stated plainly.

## First, a terminology correction

There is no longer anything called "the OpenShift marketplace" that a maintainer can submit to.

- **Red Hat Marketplace** (marketplace.redhat.com), the commercial storefront operated by IBM, is deprecated. Red Hat's
  own article tells customers using partner software through it to contact the vendor for migration instructions to an
  operator in the Red Hat Ecosystem Catalog. It is not a submission target.
- What people usually mean by "the OpenShift marketplace" is one of three in-console or on-web catalogs:
  1. the **Helm charts catalog** in the OpenShift web console's Developer Catalog, which by default "lists the Helm
     charts from the Red Hat OpenShift Helm chart repository" at `https://charts.openshift.io/index.yaml`;
  2. **OperatorHub** in the console, whose community tier is built from the `community-operator-index` image generated
     from the `redhat-openshift-ecosystem/community-operators-prod` repository;
  3. the **Red Hat Ecosystem Catalog**, which lists Red Hat *certified* containers, operators and Helm charts and is fed
     by Red Hat Software Certification through Partner Connect.

kube-noob can reach (1) today, as a community chart, with no Red Hat account and no money. It cannot reach (3) without a
Red Hat partner enrollment. (2) is technically open but, as argued below, is the wrong shape for this tool.

## The channels, honestly

| Channel | What it gets you | Prerequisites | Cost | Can one unfunded maintainer finish it? |
|---|---|---|---|---|
| OpenShift Helm charts, community tier | The chart in every cluster's console Developer Catalog, served from `charts.openshift.io` | GitHub account named in an `OWNERS` file; a packaged chart; DCO sign-off | Free | **Yes** |
| GHCR/Quay OCI chart + container image | `helm install oci://...` works today for anyone who reads the README | Nothing beyond what already ships | Free | **Already done** |
| Artifact Hub | Searchable listing on artifacthub.io, plus a "Verified Publisher" badge | Artifact Hub sign-in; an `artifacthub-repo.yml` with the repository ID | Free | **Yes** |
| Red Hat Software Certification (certified container, then certified chart) | "Certified" badge, Red Hat Ecosystem Catalog listing, the `images-are-certified` check passing | Red Hat **Corporate Account**, partner program enrollment, a certification component and a Pyxis API token | Free in fees, expensive in paperwork | **No, as things stand** |
| OperatorHub community tier | An entry in the console's OperatorHub | An actual Operator (CSV, bundle, catalog metadata), DCO sign-off with a real name | Free | Yes, but it should not be done |

### 1. OpenShift Helm charts, community tier — the right target

The `openshift-helm-charts/charts` repository holds charts "provided by the community, by partners or Red Hat", and
charts in it "go through an automated Red Hat OpenShift certification workflow". Submitted charts become available
through "the official repository URL: https://charts.openshift.io", which is the index the console reads by default.

The community path has two distinct pull requests, in order:

1. An **`OWNERS`-only** pull request. The docs are explicit: for community charts you "submit the *OWNERS* file PR
   towards `main` branch under your charts/community directory", and this "should be sent prior to sending any charts to
   the repo". The path shape is `charts/community/<vendor-label>/<chart-name>/OWNERS`. For kube-noob that is
   `charts/community/kube-noob/kube-noob/OWNERS`, because `deploy/openshift-catalog/OWNERS` sets `vendor.label:
   kube-noob` and `chart.name: kube-noob`, and the docs require that "the `vendor/label` and chart name must match the
   directory structure".
2. A **chart** pull request adding `charts/community/kube-noob/kube-noob/<version>/`. You may submit either the
   `helm package` tarball placed directly in the version directory, or the chart source under a `src/` subdirectory, but
   not both. kube-noob already produces the tarball in CI, so submit the tarball.

A `report.yaml` from chart-verifier is **optional**: "If a report is not provided, run the chart-verifier and confirm
all mandatory checks pass." Under the community profile the mandatory surface is tiny — the profile description states
"The `helm-lint` check is the only mandatory check with all other checks optional." (The per-check table on the same
page marks `helm-lint` as optional for community, so the page contradicts itself; assume `helm-lint` must pass, which it
does — see [the chart gate](#what-must-be-true-of-the-chart-before-submission).)

On merge, "the CI/CD pipeline will publish the chart in the GitHub releases and add it to the Helm charts repository
index": a `gh-pages` commit named `kube-noob-kube-noob-0.7.0 index.yaml (#<PR>)` and, for source submissions, a release
tagged `<vendor-label>-<chart-name>-<version>`.

One correction to [openshift-catalog.md](openshift-catalog.md): it says the chart pull request "waits for a manual
approval". The current submission documentation describes no Red Hat approval gate — it says that after you open the PR
"it will take a few minutes to run all the checks and merge the PR automatically", and the only manual steps it lists
are yours as the submitter. Expect automation; do not plan around a reviewer. The `OWNERS` pull request is the one that
establishes your vendor label, so that is the one most likely to attract human attention.

### 2. GHCR/Quay — the zero-gatekeeper path, already live

`.github/workflows/release.yml` already does all of this at tag time: it builds and signs the image with cosign, packages
the chart, pushes it to `oci://ghcr.io/kube-noob/charts`, signs the chart manifest, and attaches
`kube-noob-<version>.tgz` to the GitHub release. `kube-noob-0.7.0.tgz` is on release `v0.7.0` today.

One documentation caveat worth fixing in the README if it is phrased otherwise: **`helm repo add` does not work against
an OCI registry.** Helm's registries documentation only ever references OCI charts through `oci://` URIs with
`helm pull`, `helm show` and `helm install`; a classic `helm repo add` needs an HTTP repository serving an `index.yaml`.
kube-noob publishes an OCI artifact, not an `index.yaml`, so the install instruction must be the `oci://` form.

That also sets a limit on console visibility outside `charts.openshift.io`: the console's Helm repository objects are
configured with a repository URL, and the OpenShift documentation points at `https://charts.openshift.io/index.yaml` as
that URL's shape. **Unverified:** I could not confirm from the current OpenShift documentation whether a cluster-scoped
Helm repository object accepts an `oci://` URL. Until that is confirmed, treat "appears in the console" as something
only the `charts.openshift.io` submission delivers, and treat GHCR as the CLI path.

### 3. Red Hat Software Certification / Partner Connect — blocked on a company

The Red Hat Software Certification Workflow Guide has whole sections for "Certifying or Validating Containerized
Applications" and "Certifying or Validating Helm charts", so a certified chart is a real product — but it rides on a
certified container. Two hard prerequisites stand in the way:

- **Enrollment is built for companies.** The current Partner Enrollment Guide (May 2026) requires creating a Red Hat
  account of the **Corporate Account** type, completing a "Detailed Company information" section in which the Website
  field is required for every program, attesting to the Partner Code of Conduct, confirming Integrity Training, and
  agreeing to the terms, conditions and program guidelines. The guide speaks of submitting applications "on behalf of
  your company entities". It does not explicitly forbid a sole maintainer, and kube-noob does have a website
  (kube-noob.com), so an application is not obviously impossible — but it is designed for a legal entity, and nothing in
  the guide promises an individual will be accepted.
- **Submission needs partner-issued credentials.** `preflight` — the tool that checks "whether partner-submitted
  containers meet minimum requirements for Red Hat Software Certification" — submits results with
  `--pyxis-api-token=...` and `--certification-component-id=...`. Both come from a certification component inside a
  Partner Connect project. Without enrollment there is nothing to submit to.

There is also a dependency loop. The `images-are-certified` check is **Mandatory** for the `partner` and `redhat`
profiles. kube-noob's chart defaults to `ghcr.io/kube-noob/kube-noob`, which is not a Red Hat certified image. So a
certified chart requires a certified image first, which requires the partner account. Under the `community` profile that
check is optional, which is exactly why the community tier is the viable one.

The groundwork is already laid, to the project's credit: `Containerfile` builds on
`registry.access.redhat.com/ubi9/python-312`, runs as a numeric non-root user with group-0-writable directories
(restricted-v2 compatible), ships licences to `/licenses/`, and carries the `name`, `vendor`, `version`, `release`,
`summary`, `description` and `maintainer` labels that container certification's required-label check wants. If
enrollment ever happens, the image is close to ready.

### 4. OperatorHub / community-operators — do not do this

`community-operators-prod` is "the canonical source for Kubernetes Operators" behind OpenShift's OperatorHub, and the
bar is a curated one: automated vetting in CI followed by manual review, and DCO sign-off on every commit with a real
name ("Every PR needs to be signed", no pseudonyms, Author and `Signed-off-by` must match).

**Recommendation: skip it.** An Operator earns its keep when software has a custom resource lifecycle to reconcile —
upgrades to orchestrate, state to converge, CRDs to own. kube-noob is a stateless, read-only MCP server with no CRDs at
all (there is no `crds/` directory and no `CustomResourceDefinition` in any template). Wrapping the existing Helm chart
in a Helm-based Operator purely to appear in OperatorHub would add a reconcile loop, a bundle, an index image and a
permanent maintenance obligation, in exchange for a catalog entry the Helm catalog already provides. Revisit only if
kube-noob grows cluster-scoped custom resources it must own.

### 5. Artifact Hub — cheap, worth doing

Artifact Hub takes a repository from its control panel after sign-in. Two badges are available: **Verified Publisher**,
by adding an `artifacthub-repo.yml` containing the repository's `repositoryID` at the same level as `index.yaml`, and an
**ownership claim**, by listing yourself in that file's `owners` section with the email you sign in with. Note the
Verified Publisher mechanism assumes an HTTP chart repository serving `index.yaml`. **Unverified:** I could not reach
Artifact Hub's Helm-specific repository page to confirm how `oci://` repositories are registered and verified; check that
page before starting.

## Recommended order

1. **Submit the `OWNERS` pull request to `openshift-helm-charts/charts` first, today.** It is the long pole: nothing else
   in the chart path can start until that vendor label exists, it is a single tiny file, and the chart is already in a
   state that passes the community bar. Do it before anything cosmetic.
2. **Then the 0.7.0 chart pull request**, from the tarball already attached to release `v0.7.0`. This is the single step
   that puts kube-noob in the OpenShift console.
3. **Then Artifact Hub**, once you have decided how to serve an index — it is an hour's work and it is where people
   search for charts.
4. **Then, and only if you want it, revisit Red Hat certification.** It is gated on a partner enrollment designed for a
   legal entity. If kube-noob ever has one, the image is already shaped for it.
5. **Do not build an Operator.**

The reasoning for putting the community chart ahead of everything: it is the only channel that is simultaneously
achievable by one person, free, and visible in the product people actually use. Certification is the only channel that
confers the "Certified" badge, and it is the only one you cannot unilaterally complete — so it must not block the others.

## What must be true of the chart before submission

### What I could not run, and what you must run yourself

**I could not install `helm` or `chart-verifier` in this environment.** The session's egress proxy refused
`get.helm.sh:443` outright (`CONNECT tunnel failed, response 403`), GitHub release assets for `helm/helm` and
`redhat-certification/chart-verifier` are not reachable from this session, and there is no container runtime available
(`docker` is on `PATH` but there is no daemon: `dial unix /var/run/docker.sock: connect: no such file or directory`).
So the two commands below are **yours to run**, not findings I am reporting.

Install Helm and lint the chart from a fresh shallow clone:

```zsh
mkdir -p ~/kube-noob-src && cd ~/kube-noob-src
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
gh repo clone kube-noob/kube-noob . -- --depth 1
helm lint --strict deploy/helm/kube-noob
helm template deploy/helm/kube-noob >/dev/null && echo "template ok"
```

Run chart-verifier 1.16.1 with the community profile against the released tarball:

```zsh
mkdir -p ~/kube-noob-verify && cd ~/kube-noob-verify
gh release download v0.7.0 --repo kube-noob/kube-noob --pattern "kube-noob-0.7.0.tgz" --clobber
podman run --rm -v "$PWD":/charts:z quay.io/redhat-certification/chart-verifier:1.16.1 verify --set profile.vendorType=community /charts/kube-noob-0.7.0.tgz
```

The `chart-testing` check "Installs the chart and verifies it on a Red Hat OpenShift Container Platform cluster", so
without a cluster it cannot pass. If the run above stops on it, exclude it and re-run:

```zsh
cd ~/kube-noob-verify
podman run --rm -v "$PWD":/charts:z quay.io/redhat-certification/chart-verifier:1.16.1 verify --set profile.vendorType=community -x chart-testing /charts/kube-noob-0.7.0.tgz
```

To see what else that release ships, and to confirm which chart-verifier assets exist if you would rather use a binary
than the image:

```zsh
gh release view v0.7.0 --repo kube-noob/kube-noob
gh release view 1.16.1 --repo redhat-certification/chart-verifier
```

### What I did verify, statically, against the community check list

Checked by reading `deploy/helm/kube-noob/` directly. Each row names the chart-verifier check it corresponds to.

| Check | Finding | Status |
|---|---|---|
| `is-helm-v3` | `Chart.yaml` has `apiVersion: v2` | Pass |
| `has-readme` | `deploy/helm/kube-noob/README.md` exists, 7.8 KB | Pass |
| `contains-test` | `templates/tests/test-health.yaml` carries `helm.sh/hook: test` | Pass |
| `has-kubeversion` | `kubeVersion: ">=1.25.0-0"` | Pass |
| `contains-values` | `values.yaml` exists, 29 top-level keys | Pass |
| `contains-values-schema` | `values.schema.json` is valid JSON, `$schema` draft-07, root `required: [image, config, auth, service]` | Pass |
| `not-contains-crds` | No `crds/` directory; no `CustomResourceDefinition` anywhere under the chart | Pass |
| `not-contain-csi-objects` | No CSI object kinds. `storage.k8s.io` appears only as an `apiGroups` entry in `templates/rbac.yaml` (`storageclasses`, `get`/`list`, behind `.cluster`) and in `templates/admission.yaml` — RBAC rules, not CSI objects | Pass |
| `required-annotations-present` | `Chart.yaml` sets `charts.openshift.io/name`, `charts.openshift.io/provider`, `charts.openshift.io/supportURL` | Pass |
| `has-notes` (optional everywhere) | `templates/NOTES.txt` present | Pass |
| `signature-is-valid` | `deploy/openshift-catalog/OWNERS` has `publicPgpKey: null`, so no `.prov` is submitted and nothing is checked | Not applicable |
| `helm-lint` | Not run here. `release.yml`'s `chart` job runs `helm lint --strict deploy/helm/kube-noob` *before* `helm package`, and `kube-noob-0.7.0.tgz` is attached to release `v0.7.0` — so lint passed for 0.7.0 in CI | Pass, by CI evidence |
| `chart-testing` | Needs a live OpenShift cluster; neither runnable here nor mandatory under the community profile | Not run |
| `images-are-certified` | `values.yaml` defaults to `ghcr.io/kube-noob/kube-noob`, which is not a Red Hat certified image. Optional under the community profile; **mandatory** under partner/redhat | Expected fail, acceptable |

I also validated `values.yaml` against `values.schema.json` with a draft-07 validator: **zero errors**. That is the
condition `helm lint --strict` would otherwise trip on, so the lint result above is consistent.

**Nothing needs fixing before the community submission.** Two things to be aware of rather than fix:

- `templates/admission.yaml` renders a cert-manager `Certificate`, a custom resource owned by a CRD the chart does not
  ship. That is fine for `not-contains-crds`, but a console user who enables admission without cert-manager installed
  will get a failed install. Confirm it is off by default and documented as requiring cert-manager.
- The chart version must equal the release tag. `release.yml` already enforces this (`Chart version ... does not match
  tag`), so submit the tarball from the matching release rather than repackaging by hand.

## The commands

Nothing below needs a Red Hat account. All of it runs from a shell with `gh` and `git`; you have no local clone, so the
first block creates one. `gh` has no commit command, so `git commit -s` stays — the `-s` is required, because the
sign-off is what the DCO check reads.

### Step 1 — the `OWNERS` pull request

```zsh
gh repo fork openshift-helm-charts/charts --clone
cd charts
git switch -c kube-noob-owners
mkdir -p charts/community/kube-noob/kube-noob
gh api repos/kube-noob/kube-noob/contents/deploy/openshift-catalog/OWNERS --jq .content | base64 -d > charts/community/kube-noob/kube-noob/OWNERS
cat charts/community/kube-noob/kube-noob/OWNERS
git add charts/community/kube-noob/kube-noob/OWNERS
git commit -s -m "Add OWNERS for the kube-noob community chart"
git push -u origin kube-noob-owners
gh pr create --repo openshift-helm-charts/charts --title "Add OWNERS for the kube-noob community chart" --body "Adds the OWNERS file for the kube-noob community chart. kube-noob is an Apache-2.0 deterministic Kubernetes, OpenShift and ROSA audit, debugging and learning tool exposed as an MCP server, with no LLM inside: https://github.com/kube-noob/kube-noob. The chart follows in a separate pull request, per the community submission flow."
```

Watch it to completion:

```zsh
cd charts
gh pr checks --watch
gh pr view --web
```

### Step 2 — the chart pull request, after step 1 merges

```zsh
cd charts
git switch main
git pull --ff-only https://github.com/openshift-helm-charts/charts main
git switch -c kube-noob-0.7.0
mkdir -p charts/community/kube-noob/kube-noob/0.7.0
gh release download v0.7.0 --repo kube-noob/kube-noob --pattern "kube-noob-0.7.0.tgz" --dir charts/community/kube-noob/kube-noob/0.7.0 --clobber
git add charts/community/kube-noob/kube-noob/0.7.0
git commit -s -m "Add kube-noob 0.7.0 community chart"
git push -u origin kube-noob-0.7.0
gh pr create --repo openshift-helm-charts/charts --title "Add kube-noob 0.7.0 community chart" --body "kube-noob 0.7.0, Apache-2.0: deterministic Kubernetes, OpenShift, ROSA HCP, Helm and RHACS audit, debugging and learning tools exposed as an MCP server. No LLM inside, offline by default, read-only against clusters, never reads Secrets. Runs under restricted-v2 as a numeric non-root user on a UBI9 base, with NetworkPolicies on by default. Signed OCI copy at oci://ghcr.io/aashishmahajan/charts/kube-noob."
gh pr checks --watch
```

### Step 3 — confirm it landed

```zsh
gh api "repos/openshift-helm-charts/charts/commits?sha=gh-pages&per_page=5" --jq '.[].commit.message'
curl -fsSL https://charts.openshift.io/index.yaml | grep -A3 "kube-noob"
```

### Step 4 — verify the install path a console user will take

On a cluster where you have a project:

```zsh
helm repo add openshift-helm-charts https://charts.openshift.io/
helm repo update openshift-helm-charts
helm search repo openshift-helm-charts/kube-noob
helm install kube-noob openshift-helm-charts/kube-noob --namespace kube-noob --create-namespace
```

The GHCR path, which works today and does not use `helm repo add`:

```zsh
helm show chart oci://ghcr.io/kube-noob/charts/kube-noob
helm install kube-noob oci://ghcr.io/kube-noob/charts/kube-noob --namespace kube-noob --create-namespace
```

Charts 0.7.1 and earlier, the 0.7.0 this document submits among them, were pushed before the project moved into the
`kube-noob` organisation and stay at `oci://ghcr.io/aashishmahajan/charts/kube-noob`; 0.9.0 and later are only at the
address above.

## Honest blockers

- **The "Certified" badge and the Red Hat Ecosystem Catalog listing are out of reach without a legal entity.** Partner
  enrollment asks for a Corporate Account and detailed company information, and speaks of acting "on behalf of your
  company entities". Nothing promises an individual will be accepted. Do not plan a release around it.
- **A certified Helm chart cannot precede a certified container.** `images-are-certified` is mandatory for the partner
  and `redhat` profiles, so the chart's default image would have to be a certified one. That is a second-order
  dependency on the same enrollment.
- **There is no support SLA, and certification implies one.** kube-noob is a single-maintainer project whose
  `supportURL` is a GitHub issue tracker. Certification is a commercial relationship; the community tier is not. The
  chart's `charts.openshift.io/supportURL` already says so honestly — keep it that way.
- **Red Hat Marketplace is not a destination.** It is deprecated; Red Hat redirects its users to the Ecosystem Catalog.
- **`helm repo add` will never work against GHCR.** If any documentation or marketing copy says it does, it is wrong;
  OCI charts are referenced with `oci://`.
- **OperatorHub would cost a permanent maintenance obligation for a catalog entry the Helm catalog already gives.** The
  recommendation is to decline it, not to defer it.
- **No OpenShift AI MCP catalog submission path could be found.** [openshift-catalog.md](openshift-catalog.md) records
  the same conclusion. Treat it as "contact Red Hat when there is traction", not as a process.
- **Two things I could not verify** and which should be checked before relying on them: whether an OpenShift
  cluster-scoped Helm repository object accepts an `oci://` URL, and how Artifact Hub registers and verifies an `oci://`
  Helm repository.

## Owner-only steps

Everything in this section needs an account, a credential or a signature that only the project owner can provide.
Nothing above depends on any of it, except where noted.

1. **GitHub account named in `OWNERS`.** `deploy/openshift-catalog/OWNERS` lists `githubUsername: aashishmahajan`. The
   submission docs require that "your GitHub username must appear under `users`", so step 1 and step 2 above must be
   pushed from that account. Confirm `gh auth status` shows it before you start.
2. **DCO sign-off under a real name.** `git commit -s` reads `user.name` and `user.email`. The community-operators
   prerequisites page states the rule plainly — real name, no pseudonyms, Author and `Signed-off-by` must match — and the
   same expectation applies to signed-off contributions generally. Set these once:

   ```zsh
   git config --global user.name "<your real name>"
   git config --global user.email "<the address on your GitHub account>"
   ```

   Both values go into every commit you push and into the public `Signed-off-by` line, so use the address you are
   willing to have published. This file does not name them: a document in a public repository is a scraping target,
   and the values are yours to supply at the moment you run the command.

3. **Optional: a PGP key for chart provenance.** `OWNERS` currently has `publicPgpKey: null`. Signed submissions put a
   base64-encoded public key there and add `kube-noob-<version>.tgz.prov` beside the tarball. This is a real signing key
   you must generate and hold; nobody else can. Leave it `null` unless you want provenance, because setting it turns on
   the `signature-is-valid` check.
4. **Artifact Hub sign-in.** Repositories are added from the control panel after signing in, and the ownership claim is
   tied to the signed-in email. Only you can do this, and only you can decide which email the claim is bound to.
5. **Red Hat account, if and only if you pursue certification.** This means a Corporate Account at connect.redhat.com,
   the company information section, the Partner Code of Conduct attestation, Integrity Training, and the program terms.
   After enrollment it also means a certification component and its Pyxis API token, which `preflight` needs as
   `--pyxis-api-token` and `--certification-component-id`. Treat all of this as a separate project, not a release task.

## Sources

- [Red Hat OpenShift Helm chart submission documentation](https://github.com/openshift-helm-charts/charts/blob/main/docs/README.md)
- [openshift-helm-charts/charts repository README](https://github.com/openshift-helm-charts/charts)
- [chart-verifier: Helm chart checks and profiles](https://github.com/redhat-certification/chart-verifier/blob/main/docs/helm-chart-checks.md)
- [chart-verifier releases](https://github.com/redhat-certification/chart-verifier/releases)
- [chart-verifier 1.16.1 release](https://github.com/redhat-certification/chart-verifier/releases/tag/1.16.1)
- [Red Hat Software Certification Workflow Guide (2025)](https://docs.redhat.com/en/documentation/red_hat_software_certification/2025/html/red_hat_software_certification_workflow_guide/index)
- [Red Hat Partner Enrollment Guide, May 2026](https://connect.redhat.com/sites/default/files/2026-05/Partner%20Enrollment%20%20Guide%20May%202026.docx.pdf)
- [openshift-preflight](https://github.com/redhat-openshift-ecosystem/openshift-preflight)
- [community-operators-prod](https://github.com/redhat-openshift-ecosystem/community-operators-prod)
- [Community operator contributing prerequisites](https://redhat-openshift-ecosystem.github.io/operator-pipelines/users/contributing-prerequisites/)
- [Working with Helm charts in OpenShift](https://docs.redhat.com/en/documentation/openshift_dedicated/4/html/applications/working-with-helm-charts)
- [Sunset of the Red Hat Marketplace, operated by IBM](https://access.redhat.com/articles/7130828)
- [Helm: using OCI-based registries](https://helm.sh/docs/topics/registries/)
- [Artifact Hub: repositories](https://artifacthub.io/docs/topics/repositories/)
