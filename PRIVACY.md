# Privacy

kube-noob is open-source software that you run yourself: on your computer, in your CI, or in your cluster. The
maintainers run no service for it and receive nothing from it. There are no accounts, no telemetry and no analytics.
The website's contact and license forms are the one place the maintainer receives data: see
[The website](#the-website-kube-noobcom).

There is no AI inside kube-noob. When you use it from Claude, OpenShift Lightspeed or another MCP client, that client
and its model do the talking and call kube-noob's tools. What you share in that conversation is handled by that
product under its own terms and privacy policy. kube-noob adds no network traffic of its own.

## What it reads

- Text you give it: manifests, events, logs, error messages and questions. It processes them in memory to answer;
  names it finds there (a pod, a Service, a label selector, a namespace) go only into the steps it prints.
- Its bundled knowledge, and documents you index yourself with `kube-noob corpus add-docs`.
- Only if you turn on cluster access: read-only requests to the Kubernetes or OpenShift API of your current
  kubeconfig context. It never reads Secrets and redacts values that look like credentials.

## What it stores, on your machine only

Everything lives in the data directory: `~/.local/share/kube-noob` by default, or `KUBE_NOOB_DATA_DIR`.

| File | Contents | How to remove it |
|---|---|---|
| `progress/<learner>.json` | Lessons read, exercise and quiz results, points. The learner id is a label you choose (default `local`); use a nickname, not an email address. A shared server (service or sidecar, meant for several learners through one deployment) refuses the default and requires each caller's own id, so one person's progress is never silently mixed into another's | Delete the file |
| `learning.json` | Your profile (platform, versions, team conventions) and fixes you confirmed (symptom, cause, fix). Notes that contain credentials, logs or manifests are rejected. Counters record rule and playbook ids only, never your text | `kube-noob learning forget <id>`, delete the file, or set `learningEnabled: false` |
| `corpus/` | Documents you indexed with `corpus add-docs` (credentials masked), and public corpus data you built or imported | Delete the directory |
| `corpus/jira-*.jsonl`, `jira/` | Only after `kube-noob corpus jira`, `jira.sync.enabled` or importing a snapshot: the public Red Hat Jira tickets of the chosen projects (title, status, versions, the full description and every comment; comment authors appear only as per-ticket pseudonyms such as Commenter A, their names in the text and their @mentions are replaced by the same pseudonym, other mentions become @user, and emails, phone numbers, account ids and profile links are removed; reporter, assignee and author identities are never stored), the sync state, a search index and `jira/changes.jsonl` (each ticket's status, resolution and fix-version changes seen by a sync: key, project, type, when, before and after; no text). Public data, not redistributable: kube-noob never publishes it | Delete the files |
| `corpus/DB_SEED.json`, `known_issues/` | Only after importing the public `kube-noob-db` bundle (`corpus import`, chart `db.enabled`): when the bundle was built and the release-note known issues it carried. The bundle itself holds public documentation and release facts only, never Jira data or anything about you; kube-noob downloads nothing for it: your cluster pulls the image you pinned | Delete the files |
| A sealed snapshot (`kube-noob corpus seal`, `<dataDir>/seed/*.tgz.enc`, the `kube-noob-db-jira` image) | Only when you make one: a Jira snapshot encrypted with your key (AES-256-GCM). The key lives in your Secret store (chart `jira.seed.keySecret`, workflow secret `JIRA_SEED_KEY`) and never in the image, the chart values or kube-noob's files; the plaintext exists only in a temporary folder next to the data while it is imported. The `jira-db-image` workflow pushes it only to a repository that refuses anonymous access | Delete the image or file; rotate the key |
| A Jira snapshot (`kube-noob corpus jira-snapshot -o <file>`, `<dataDir>/seed/*.tgz`) | Only when you make one: the files above in one owner-only archive, for your other installs to import. It holds Red Hat ticket text: keep it inside your organisation (a private image, bucket or volume). The `corpus-refresh` workflow uploads it only encrypted with your `CORPUS_PASSPHRASE` | Delete the file |
| Your team memory repository (`memory.paths`, chart `memory.source`) | Entries your team wrote and reviewed (`entries/MEM-<n>.yaml`). kube-noob reads it where it runs and writes only on `kube-noob memory init`, `add`, `outcome`, `import` and `migrate-learning`; it never uploads, bundles, publishes or exports it. `memory import` reads a ticket export on your machine and keeps no people: assignee, caller and reporter fields are not read, and emails, account ids, @mentions, phone numbers and named people are removed from the text | It is your repository: remove entries in Git |
| `incidents.json` | Only when the incident watch runs (`kube-noob watch`, `watch.enabled`): per incident the namespace, workload, signal, redacted event and status lines, the diagnosis ids and steps, rollout changes (image names, environment variable names, resource values), when it opened and resolved, and fixes a person confirmed. Never log lines, object specs or Secret values. Resolved incidents are dropped after `watch.retentionDays` (30) unless a fix was confirmed | Delete the file |
| `alert-reports/<id>.json`, `alert-reports/<id>.summary.json` | Only on the HTTP server (`kube-noob serve`; in the chart only with `alertReports.store: true`, which needs `replicaCount: 1`), for each Alertmanager payload posted to `POST /v1/alert-reports`, while `alertReports.store` is true: the evidence report. Per alert it keeps the alert's name, state, start time and fingerprint, eight labels (severity, namespace, pod, container, service, instance, node, job), its `summary` (or `message`), and inside the diagnosis evidence up to five lines that can quote its `summary`, `description` and `message` annotations; plus what kube-noob's own knowledge says about it, and the id, when it arrived and how long the report took. Every label and annotation value is redacted for credential shapes (passwords, bearer and basic credentials, API keys, private keys including one cut short, cloud and chat tokens, credentials in URLs) before it is cut to 2,000 characters, and every `scheme://` URL in it is replaced by `[url removed]`. Not kept: any other annotation (`runbook_url` among them), `generatorURL`, `externalURL`, the receiver and group key, request headers, the caller's address and the token. Owner-only (0700 folder, 0600 files). The newest `alertReports.maxReports` (200) are kept, none older than `alertReports.maxAgeDays` (14 days), each at most `alertReports.maxReportBytes` (1 MiB). On the chart's emptyDir (no `persistence.enabled`) they go with the pod. The CLI, the stdio MCP server and the Claude plugin never write it | Delete the folder, or set `alertReports.store: false` |
| `posture/snapshot-*.json`, `posture/report-*` | Only when you run `kube-noob posture report` or `serve` with `posture.reportEnabled`: per watched object its kind, namespace, name, owner label, a hash of its desired state and a 12-character hash per field; the audit findings (rule, object, severity, owner). Never field values, ConfigMap data or Secrets. The newest `posture.keep` (14) are kept, owner-only (0600). A snapshot also keeps the audit's assumptions, which name kinds and counts, never object contents. A report read back for the trend in the HTML page contributes four values per snapshot -- the timestamp, the open and excepted counts, and whether the read was complete -- and no object name reaches the chart | Delete the folder |

Nothing from a request is kept after it is answered, except the alert reports in the table above, which are kept from the Alertmanager payloads posted to them. What is listed above stays until you delete it; the maintainers
never receive it.

`kube-noob must-gather analyze --report DIR` writes `report.md`, `report.json` and, with `--case-draft`, `case-draft.md` to the folder you name; they hold redacted findings from the must-gather, never its Secrets, and nothing is sent anywhere. `kube-noob bundle` writes a redacted evidence pack to the folder you name (default `./kube-noob-bundle`). The MCP
server's log line records each tool name, argument sizes and duration, never argument contents.

## What the redactor removes

One redactor (`kube_noob.debug.cluster.redact_text`) runs on what `diagnose`, `insight`, the must-gather report, build
logs, the incident watch, the evidence bundle, cluster output and every alert report keep or show, and the learning-note
filter refuses any text it would change. It replaces with `***` (or a marker such as `***JWT***`):

- `Authorization: Bearer <value>`; a bare `Bearer <value>` of 16 characters or more with letters and digits;
  `Authorization: Basic <value>` when the value can be base64 credentials (8 characters or more of the base64
  alphabets, with a digit or both cases), the whole value;
- `name=value`, `name: value` and `"name": "value"` for `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`
  (`apikey`, `api-key`) and `access_key`, also with up to four words in front: `client_secret=`,
  `aws_secret_access_key=`, `DB_PASSWORD=`, `CLIENT_SECRET:`, `X-Auth-Token:`. A reference to a Secret is left as
  written only where the text proves it is one: `kubectl describe`'s `<set to the key 'password' in secret
  'orders-db'>`, the same in words (`secret 'orders-db' key 'password'`), and a manifest's `valueFrom`/`secretKeyRef`.
  A value that merely looks like `<name>/<key>` (`DB_PASSWORD: orders-db/password`) is redacted, because
  `password=prod-db/secret` has the same shape and is a password: this over-redacts rather than leaks;
- `apikey <value>` and `access_key <value>` when the value is 16 characters or more with letters and digits (so
  "rotate the apikey whenever a teammate leaves" stays as written);
- secrets passed as flags: `--password x`, `--db-password=x`, `--api-key x`, `--client-secret x`, `--token=x`, `--pwd x`,
  `--access-key x`;
- JWTs; AWS access key ids; Stripe-style `sk_live_`/`rk_test_` keys of 24 characters or more; Vault, GitHub and Slack
  tokens; the password in `scheme://user:password@host`;
- a private key from its `-----BEGIN ... PRIVATE KEY-----` line to its END line; a key cut short (no END after it) loses
  its base64 body -- lines separated by whitespace, by JSON-escaped `\n`, or by a newline and a log prefix (an RFC 3339
  timestamp, a CRI `stdout F`, `kubectl logs --prefix`'s `[pod/name/container]`), or the body flattened onto the BEGIN
  line -- and a BEGIN line with no body after it, which holds no key material, is left as written; the
  `"private_key": "..."` string of a service-account key file, also when it is cut short before its closing quote.

What it does not catch, so treat any text you hand kube-noob as possibly still holding these:

- `token <value>` or `password <value>` with neither `=` nor `:` nor a leading dash: in prose a value and the next word
  look the same;
- a password glued to a short flag, `-p<password>` (MySQL's form);
- URL-encoded names, such as `password%3D` followed by the value;
- a private key split across fields or quoted line by line (two labels, a JSON list of `"..."` lines), or whose lines
  carry a log prefix other than the three above;
- a bare random string with no name and no known prefix, a Basic value under 8 characters or of one case without a
  digit, a bare Bearer value under 16 characters or without a digit, an `apikey <value>` under 16 characters or
  without a digit, and a JWT whose segments are under 8 characters.

## What it sends, and where

By default, nothing. Each destination below is off until you turn it on.

| Destination | Turned on by | What is sent |
|---|---|---|
| Your cluster's API server | `cluster.enabled: true` or `--cluster-enabled` | Read-only get, list and logs requests for the allowlisted resources (`docs/safety-contract.md`); since the operator inventory, that includes OLM ClusterServiceVersions and Subscriptions, which name installed operators and their versions and carry no credentials |
| Allowlisted documentation sites (listed below) | `webEnabled: true`; refused under the offline lock | HTTPS GET of the page address; nothing is downloaded to disk or run |
| The model you configure | Only `kube-noob ask`, `kube-noob train bench` and the eval judge | Your question and the tool results; under the offline lock, local models only |
| The GitHub Actions API (`ci.githubApiUrl`, default api.github.com) | `ci.githubEnabled: true`; only `kube-noob build history`; under the offline lock only an in-cluster `*.svc` host | HTTPS GET of the repository's workflow runs, their attempts and jobs, with your token; the runs are written to the folder you name |
| Nowhere: the admission webhook (`kube-noob admission serve`, chart `admission.enabled`) | Running it | It receives the objects your API server sends it (never Secrets or ConfigMaps), answers with warnings or a denial, keeps only request counts and latencies, and sends nothing; `admission.lookups` adds read-only lists of five kinds from your API server, as in the row above |
| Nowhere: `/metrics` on the HTTP server | Running the HTTP server (the sidecar or the chart) | Whoever can reach the port with the bearer token reads counters only: the tool names this build serves, how many calls each had, their outcomes and durations, the version, and how old the built-in knowledge is. No argument, no resource name, no namespace, no manifest content and no caller address appears in any label, and the label values come from fixed sets so a caller cannot add one. It sends nothing itself; Prometheus scrapes it |
| Nowhere: `/v1/alerts` on the HTTP server | Running the HTTP server; your Alertmanager configured to post there | It receives the alert payload your Alertmanager sends, reads the signals out of it in memory and answers; nothing is stored and nothing is sent on |
| Nowhere: `/v1/alert-reports` on the HTTP server | Running the HTTP server; your Alertmanager configured to post there | It receives the alert payload your Alertmanager sends and answers with an evidence report built from the payload and local knowledge alone (no cluster read, no fetch); with `alertReports.store` it keeps that report in the data directory (row above) and sends nothing on. `GET /v1/alert-reports` and `GET /v1/alert-reports/<id>` hand kept reports to whoever holds the bearer token |
| Your RHACS Central (`rhacs.endpoint`) | `rhacs.enabled: true` (chart `rhacs.enabled`); only `kube-noob rhacs compare --live`, the `rhacs_compare_live` tool and `kube-noob vuln report --rhacs-image`; under the offline lock only an in-cluster `*.svc` Central | HTTPS GET of `/v1/policies` and `/v1/policies/<id>`, and of `/v1/images/<digest>` for the images you name, with your API token; policies and image scans are read in memory and not stored |
| Your git host (the chart's `memory.git.url`) | `memory.source: git` in the chart; under `config.offline` only an in-cluster `*.svc` host | A shallow `git clone` of your memory repository by the pod's init container at start, through egress opened to `memory.git.egressCIDRs` only; kube-noob itself sends nothing |
| Red Hat's security data (security.access.redhat.com) | Only `kube-noob corpus advisories --online`; refused under the offline lock (`--from-archive` reads a downloaded file instead) | HTTPS GET of `changes.csv` and the VEX document of each CVE, one request a second plus jitter, within `--max-requests`; nothing about you |
| Public GitHub repositories and the public Red Hat Jira | Only `kube-noob corpus build`, `jira`, `jira-projects`, `history` and `known-issues`, and `jira.sync.enabled` in the service; refused under the offline lock | Requests for public data: Jira search queries (project key, an "updated in the last N minutes" or "key below N" filter) through its REST API, at most one per second |

The default web allowlist is kubernetes.io, helm.sh, docs.redhat.com, docs.openshift.com, access.redhat.com,
cloud.redhat.com, developers.redhat.com, redhat.atlassian.net, docs.aws.amazon.com, github.com,
raw.githubusercontent.com, stackrox.io, www.stackrox.io, gateway-api.sigs.k8s.io and kind.sigs.k8s.io, with their
subdomains. You can shorten or replace it with `web.allowedDomains`.

`kube-noob doctor` prints what the running process can reach. Administrators can set `offline: true` (or
`KUBE_NOOB_OFFLINE=1`) to block web access and downloads and to allow only local models; nothing later in the
configuration can lift it.

## The Claude plugin

The plugin starts the bundled server on your computer over stdio, with web access, cluster access and model calls
off. Its Python dependencies are installed from PyPI at the versions and hashes in the plugin's `uv.lock`, into a
throwaway environment in uv's cache (and uv's managed CPython once, if no Python 3.11 or later is installed). The
plugin ships only the modules of the stdio server: no CLI, model agent, HTTP service, web client or cluster access,
so it reads no credentials and makes no network calls of its own. Personal data is never requested. If text you paste contains some, it is processed in memory
and not stored, except words you choose to put in a confirmed note or a learner id.

## The knowledge-only plugin

`kube-noob-skills` contains Markdown and one image. There is no server in it, no Python and nothing to run, so it
starts no process, installs no dependency, reads no file of yours and makes no network connection. What you type
goes to Claude as it always does; this plugin adds nothing to that and receives nothing from it.

## The Agent Skill

The skill runs where Claude runs code: your computer in Claude Code, a sandbox for chat on claude.ai. It reads only
the files named in a call, makes no network connections (web, cluster and model are forced off) and sends nothing to
the maintainer. Like the server, it keeps learning progress and notes you confirm in kube-noob's data folder
(`KUBE_NOOB_DATA_DIR`, else `~/.local/share/kube-noob`) inside that environment; a claude.ai sandbox discards them
when it ends.

## The website (kube-noob.com)

A static site on GitHub Pages, built from this repository's releases. It sets no cookies, runs no analytics and loads
its pages, scripts and fonts from its own host only. GitHub Pages, which serves it, keeps its own access logs under
GitHub's privacy statement. Data leaves your browser in three cases, and only when you act:

- **Contact, feedback and student-license forms.** When you submit one, what you typed goes to a Google Apps Script
  web app the maintainer runs, which stores it in the maintainer's private Google Sheet and emails the maintainer a
  copy. A message keeps its time, topic or area, rating, your name, email address, text and the page it was sent
  from. A student license keeps its id, your name, email address and school, and that you said you are a student; the
  license id is emailed to you. The data is used only to reply to you or to keep your student record, is not sold or
  shared, and is deleted on request through the contact form.
- **Bring your own AI.** That page sends your Anthropic API key and your messages from your browser straight to
  `api.anthropic.com`, under Anthropic's terms for your key; the site never receives them. The key is kept in memory,
  or in the tab's session storage only if you tick the box.
- **Playground.** It runs kube-noob's tools in your browser: what you paste stays on your device.

## Children

kube-noob is not directed at children under 18.

## Contact

Security reports: [SECURITY.md](SECURITY.md). Anything else:
[GitHub issues](https://github.com/kube-noob/kube-noob/issues).
