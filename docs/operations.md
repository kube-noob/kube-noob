# Operations: weekly risk review and releases

## When this runs

| When (UTC) | What | Where |
|---|---|---|
| Daily 05:17 UTC, every other day by default | Red Hat Jira main copy. `JIRA_EVERY_DAYS=1` runs it daily. A run that cannot decrypt the previous copy fails and does not replace it | `corpus-refresh.yml` |
| Sunday 03:41 UTC | Corpus refresh also ingests Git docs and release history | `corpus-refresh.yml` |
| Monday 04:23 | CodeQL | `codeql.yml` |
| Monday 06:41 | Risk review: dependency CVEs, released-image CVEs, upstream drift, SDK drift | `risk-review.yml` |
| Monday 04:37 US Central (09:37 or 10:37 UTC) | Agent review: reads the issue and open Dependabot PRs, verifies facts, fixes, pushes a patch and hands back the tag command | Claude scheduled task "kube-noob weekly risk review" |
| Tuesday 03:41 | OpenSSF Scorecard | `scorecard.yml` |
| Weekly | Dependabot PRs for pip, Actions and the base image | `dependabot.yml` |

The risk review opens or updates one GitHub issue per ISO week titled `Weekly risk review <year>-W<week>` with the
label `risk-review`, plus `release-needed` when a patch release is recommended. It then closes every other open
`risk-review` issue as superseded, so the open list holds the current week only: an open issue is a claim that
something wants doing, and a report that has been replaced is not making that claim. The run fails rather than
closing anything if it cannot establish this week's issue number, because closing on an unknown number would
close the week it had just written.

### The Red Hat Jira copy: where it lives

Ticket text is not on kube-noob.com and is not in the public `kube-noob-db` image. Red Hat's issue content is not redistributable. The website's known-issues pages are the release-note bugs, which are a different, smaller set.

The main copy is the encrypted artifact `jira-main-copy-encrypted` from the last successful `corpus-refresh` run. Import it locally (the passphrase is the `CORPUS_PASSPHRASE` Actions secret, not something to paste into a chat):

```bash
# after decrypting the artifact to jira-snapshot.tgz with that passphrase
kube-noob corpus import jira-snapshot.tgz
kube-noob ticket OCPBUGS-1234
kube-noob corpus jira-changes --since 2d
```

A sync only adds or refreshes tickets. It will not write a shard smaller than the one it loaded. The scheduled pull runs every other day, newest updates first (`ORDER BY updated DESC`). Set the repository variable `JIRA_EVERY_DAYS` to `1` for a daily pull. Do not rotate `CORPUS_PASSPHRASE` until the current artifact has been re-encrypted with the new value: a mismatch now fails the workflow instead of discarding the copy, and `fresh=true` is the only way to start over on purpose.

## When the corpus refresh refuses the copy

The privacy audit exits 1 rather than keep a copy that still has person-shaped text in it, which is the right
way round. Each finding now reads `<TICKET> <field>: <kind> <shape>`, where the shape is the match with its
content removed -- `spelled-out email A at A.A`, `account id 9A9A9A9` -- so a failure can be triaged from the CI
log without decrypting the copy and without the log carrying anyone's details.

Two known false-positive shapes, both from patterns that are deliberately broad because missing real personal
data is worse than over-matching:

- `account id 9A9A9A9` on a `sha256:` image digest. `BARE_ACCOUNT_ID` matches any 24-character hex run starting
  with `5`, which a digest fragment satisfies. The anonymiser replaces it with `<account>`, so the ticket text
  loses a digest; it is not a leak. Do not narrow the pattern to fix the cosmetics.
- `spelled-out email A at A.A` on text like "ping Commenter A at quay.io", which is what a labelled commenter
  name followed by a hostname looks like. `anonymise` scrubs again after labelling for exactly this reason, so a
  surviving one means the text reached the audit by another path.

A finding whose shape is neither of those is a real leak: fix the anonymiser, do not raise the gate.

## Risk vectors and the release rule

| Vector | Signal | Release? |
|---|---|---|
| Python dependency CVE with a fix | `pip-audit` on `requirements.lock` | yes, patch |
| Fixable HIGH/CRITICAL CVE in the released image | Trivy on `ghcr.io/kube-noob/kube-noob:<latest>` | yes, patch (rebuild) |
| Upstream release newer than verified knowledge | Kubernetes, OpenShift, Helm, StackRox vs `scripts/risk_baseline.json` | yes, after re-verifying facts |
| New `mcp` or `anthropic` SDK | PyPI vs lock pins | review; release only if behaviour changes |
| Unfixed CVE (no fix yet) | pip-audit / Trivy | review, document, no release |

## Procedure

1. Open the latest `risk-review` issue (or run `gh workflow run risk-review.yml`).
2. For each reason, make the fix on `main`:
   - dependency: `uv pip compile pyproject.toml --generate-hashes --python-version 3.12 --universal --upgrade-package <pkg> -o requirements.lock`
   - image: no code change needed; the release rebuilds on the current UBI digest
   - drift: re-verify the affected facts against the source, update knowledge, catalog and tests, then bump
     `scripts/risk_baseline.json`
3. Verify locally: `scripts/check.sh` (plugin copy, lint, types, tests, self-test).
4. Bump and changelog: `python scripts/bump_version.py <next> "<one-line reason>"`.
5. Commit, push, and wait for CI to pass on `main`.
6. Tag and push: `git tag v<next> && git push origin v<next>`. The release workflow publishes to PyPI (trusted
   publishing), pushes the signed multi-arch image and the signed OCI Helm chart to GHCR, publishes to the MCP
   Registry and creates the GitHub release with the chart `.tgz` and demo GIFs.
7. After PyPI shows the version: `python scripts/brew_formula.py <next> --write`, commit and push; the brew workflow
   installs it on macOS and Linux.
8. Close the weekly issue with the release link.

Tags must be pushed by a person or the scheduled agent: tags pushed with the workflow `GITHUB_TOKEN` do not trigger
other workflows.

The Claude plugin directory reads the plugin (`.claude-plugin/marketplace.json` and `plugin/kube-noob/`) from `main`,
and its review shows the commit it last checked. Work done on another branch reaches it only after that branch is
merged to `main` and someone presses "Check for new commits" (or sets up push updates) in the plugin portal. A version
that is bumped on `main` but never tagged never reaches PyPI, the image or the MCP Registry: 0.5.0 (073fe80) was
bumped on `main` and not tagged, so PyPI stopped at 0.4.0.

## When a release fails before anything is published

The opposite case, and it happened on **v0.8.0**: the tag was pushed, the first job failed on
`ModuleNotFoundError: No module named 'yaml'` -- a step that imported the package before the runtime
dependencies were installed, fixed in G228 -- and nothing reached PyPI, the chart repository, the MCP
Registry, Homebrew or a GitHub release. The website was right to keep showing the previous version: it is
built from the latest RELEASE, and the latest release was still 0.7.1.

Verify before deciding, because the two cases are repaired in opposite ways:

```bash
pip index versions kube-noob
gh release list --repo <owner>/<repo> --limit 5
gh run list --repo <owner>/<repo> --workflow release.yml --limit 5
```

If nothing published, **cut the next patch version rather than re-pushing the tag**. The rule above --
never delete or re-push a tag -- is about a release that published somewhere, and the reason to keep it here
is different and still good: a tag someone may have fetched must keep meaning one tree. So bump, land the fix
that broke the run, and release from a commit that contains it:

```bash
python scripts/bump_version.py <next patch> "<one line for the CHANGELOG>"
python scripts/sync_plugin_server.py && bash scripts/check.sh
git commit -s -am "release: <next patch>" && git push
gh release list --repo <owner>/<repo> --limit 3
```

The version that never published is simply skipped, which is what the record should say about it. Do not
publish the new version under the old number: the tag for it points at a tree without the fix.

## When a release job fails after the others have published

The jobs publish to five places and only the last of them is the GitHub release, so a failure there leaves PyPI,
the chart repository, the MCP Registry and Homebrew holding the version while the release carries nothing. This
happened on v0.7.1.

**Do not delete the release and do not delete or re-push the tag.** Deleting the release destroys the assets the
run already built, and `videos` and `site` with them; re-pushing the tag re-runs `publish-pypi`, which fails
because PyPI versions are immutable, and `github-release` never runs because it waits on that job.

Re-run the one job instead. It re-runs its dependents (`videos`, `site`) and nothing upstream, and it takes the
artifacts from the original run, which are retained for 90 days:

```bash
gh api "repos/<owner>/<repo>/actions/runs/<run id>/attempts/<n>/jobs?per_page=50" \
  --jq '.jobs[] | select(.name == "github-release") | .id'
gh api -X POST "repos/<owner>/<repo>/actions/jobs/<job id>/rerun"
```

The videos can also be re-rendered and re-attached on their own, against a release that already exists, which is
what `videos.yml`'s `workflow_dispatch` is for:

```bash
gh workflow run videos.yml --repo <owner>/<repo> -f tag=v<version>
```

If the artifacts have expired, build the wheel, chart, GIFs and skill ZIP from the tag and upload them with
`gh release upload`; the release step is idempotent, so running the job again after that is safe.

## Alert evidence reports (the Alertmanager receiver)

`kube-noob serve` answers `POST /v1/alert-reports` with one evidence report per alert in an Alertmanager payload
and, with `alertReports.store`, keeps it in `<dataDir>/alert-reports`: owner-only, the newest
`alertReports.maxReports` (200), none older than `alertReports.maxAgeDays` (14), each at most
`alertReports.maxReportBytes` (1 MiB). The report is built from the payload and kube-noob's local knowledge alone; it
reads no cluster and sends nothing anywhere. One post gets `alertReports.budgetSeconds` (30) of work; alerts not
reached by then keep a `not-evaluated` row, are named in `notIncluded`, and the stored record says the same.

The chart keeps no report by default (`alertReports.store: false`): it runs two replicas, each with its own volume,
and a report kept by one is not found through the Service on the other. To keep them set `alertReports.store: true`
and `replicaCount: 1` (the chart refuses the first without the second, as it does for `watch.enabled` and
`posture.report.enabled`), and `persistence.enabled` if they should outlive the pod. Off, every POST still answers
with the report and `stored: false`.

Field names below were checked against Alertmanager v0.28.1 (`docs/configuration.md`: `webhook_config` has `url`,
`url_file`, `send_resolved`, `http_config`, `max_alerts`, `timeout`; `http_config.authorization` has `type`, default
`Bearer`, and `credentials` or `credentials_file`; the webhook posts `Content-Type: application/json`,
`notify/util.go` `PostJSON`) and prometheus-operator v0.80.0 (`pkg/apis/monitoring/v1beta1/alertmanager_config_types.go`:
`webhookConfigs[].url`, `sendResolved`, `maxAlerts`, `httpConfig.authorization.credentials` as a Secret key selector).

The platform Alertmanager sees every namespace's alerts. Add a receiver to its configuration (on OpenShift, the
`alertmanager.yaml` key of the `alertmanager-main` Secret in `openshift-monitoring`) and route to it:

```yaml
receivers:
  - name: kube-noob
    webhook_configs:
      - url: http://kube-noob.kube-noob.svc:8080/v1/alert-reports
        send_resolved: true
        max_alerts: 500
        http_config:
          authorization:
            type: Bearer
            credentials: <the token from the Secret the chart's NOTES name>
```

A namespace's own alerts can go through an `AlertmanagerConfig` in that namespace instead. The operator adds a
`namespace` matcher for the object's own namespace to its top route, so this one only ever sees alerts from the
namespace it lives in; the token Secret has to be in that namespace too:

```yaml
apiVersion: monitoring.coreos.com/v1beta1
kind: AlertmanagerConfig
metadata:
  name: kube-noob
  namespace: kube-noob
spec:
  route:
    receiver: kube-noob
    groupBy: [alertname]
  receivers:
    - name: kube-noob
      webhookConfigs:
        - url: http://kube-noob.kube-noob.svc:8080/v1/alert-reports
          sendResolved: true
          maxAlerts: 500
          httpConfig:
            authorization:
              type: Bearer
              credentials:
                name: kube-noob-token
                key: token
```

Two chart settings decide whether the post arrives: the Alertmanager's namespace must be allowed in by the chart's
NetworkPolicy (`networkPolicy.allowIngressNamespace: openshift-monitoring`, or `openshift-user-workload-monitoring`
for the user-workload Alertmanager), and the server's body limit is 1.5 MiB (1,572,864 bytes). `max_alerts` bounds
the count, not the size: 500 alerts fit only while each averages under about 3 KB of labels and annotations, so set
it from your own alerts (a group of 900 alerts of 1.9 KB each was refused). A post above the limit gets 413 and is
not read at all. Alertmanager does not retry it: its webhook notifier retries a 5xx answer only and drops any 4xx as
a failed notification (`notify/util.go`, `Retrier.Check`, v0.28.1). A storage failure is not a 4xx: the POST still
answers 200 with the report and `stored: false`.

Reading them back, with the same bearer token:

```bash
curl -sH "Authorization: Bearer $TOKEN" http://kube-noob.kube-noob.svc:8080/v1/alert-reports?limit=20
curl -sH "Authorization: Bearer $TOKEN" http://kube-noob.kube-noob.svc:8080/v1/alert-reports/<id>
kubectl -n kube-noob exec deploy/kube-noob -- kube-noob alerts list
```

What to watch:

- `stored: false` on a POST is the answer, not an error: the report is in the response and `notStoredReason` says why
  it was not kept (storing is off, the folder is a link or belongs to another user, the disk is full). The server
  log line `alert report <id> not stored` carries the same reason; the dashboard's "Reports kept, not kept" panel
  counts them.
- `kube_noob_alert_report_duration_seconds` is the receipt-to-report time, from the request reaching the route to the
  report being ready (before it is written), including any wait: reports are built two at a time. The north-star
  claim is under a minute; after `alertReports.budgetSeconds` (30) a post starts no further alert, so one post
  ends within the budget plus the one alert in progress. `kube-noob demo
  alerts` posts the bundled payload to an in-process server and fails over 2 s. Measured on the 2-core, 7 GB build
  machine on 2026-11-12, idle apart from one other test run: the bundled payload 0.09 s as the first request of a
  fresh process, then p50 22 ms and p95 23 ms over 250 posts; the review's worst in-bounds payloads 4.5 s (150 alerts,
  five 2,000-character fields each, 1.51 MB) and 5.7 s (500 alerts of 2.8 KB, 1.49 MB). Before the redaction fix the
  first of those took 40.4 s. With other test suites on both cores the same two took about 15 s each, which is what
  `budgetSeconds` is for.
- `kube_noob_alert_reports_evicted_total` rising steadily means retention is doing its job; reports you need longer
  belong in a ticket, not in a larger `maxReports`.
- `retentionNotRemoved` on a POST means retention found something it could not remove under a report's name (a
  directory, say): the report was stored, and the log names the count. Remove the stray entry by hand.
- To keep nothing: `alertReports.store: false`. To delete what was kept: remove `<dataDir>/alert-reports`.

## Rollback

- PyPI versions are immutable. Yank the bad version (`pypi.org/manage/project/kube-noob/releases/`), fix forward, and
  release the next patch.
- GHCR: delete or retag the bad image version; users pinned by digest are unaffected.
- MCP Registry and the Claude plugin follow the next published version.

## Escalation

- Vulnerability reports arrive through GitHub private vulnerability reporting (see `SECURITY.md`); acknowledge within
  3 business days.
- A failing release workflow blocks the release: fix and re-tag with the next patch version (never reuse a version).
