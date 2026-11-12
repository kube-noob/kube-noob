# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **"Report a vulnerability"** button on the repository's
Security tab (private vulnerability reporting). Do not open a public issue. Expect an acknowledgement within 3 business
days and a fix or mitigation plan within 30 days for confirmed issues.

## Supported versions

The latest minor release receives security fixes.

## Default posture

kube-noob makes no outbound connections and touches no cluster unless you enable it. This is tested in CI and was
verified end to end inside a network namespace with no route (docs/release-readiness.md). With web access enabled it
only performs HTTPS GETs to allowlisted documentation domains, refuses non-text content types (archives, binaries,
scripts), streams at most `web.maxBytes`, never writes the content to disk and never executes it. The admin lock
(`offline: true` / `KUBE_NOOB_OFFLINE=1`) overrides `webEnabled`, blocks corpus downloads and allows only loopback or
in-cluster model endpoints; no later configuration source can lift it. `kube-noob doctor` reports the effective
posture. The local learning file stores only user-confirmed summaries and ids, never logs, manifests or credentials. The MCP server's only subprocesses are read-only `oc`/`kubectl` calls (argv, no shell)
when cluster access is enabled; the maintainer CLI commands `corpus build --online` and `helm-audit` run `git` and
`helm template` locally.

The Agent Skill (`skill/kube-noob`) cannot be configured out of this posture: its runner forces the offline lock,
web and cluster off and no model on every call, ignoring the config file and `KUBE_NOOB_*` variables, imports the
bundled server source only (it refuses another installed kube-noob), and its tools start no other program and
open no connection (a test runs them with both refused).

## Security design

| Area | Control |
|---|---|
| Network | `webEnabled: false` by default; all outbound HTTP goes through one guarded client; web requests (and every redirect) must be HTTPS to an allowlisted domain. |
| Cluster access | Opt-in (`cluster.enabled`), read-only verbs on an allowlist of resources, Secrets never readable, ConfigMap values / sensitive env values / token-like log content redacted, strict argument validation, no shell. |
| HTTP server | Refuses to bind non-loopback without a bearer token (constant-time compare, and two `Authorization` headers are refused rather than resolved last-wins) unless explicitly overridden; DNS-rebinding protection with a Host allowlist; health endpoints are the only unauthenticated paths. The body limit is 1.5 MiB, below the 1,000,000-character argument cap so no valid request is refused, and a body on the public health paths is refused with 405 before it is buffered, so an unauthenticated caller cannot make the server hold memory. The REST routes (`/v1/...`) are behind the same token and body limit, pass the same Host and Origin checks, accept only `application/json` posts, and exist only for the tools the shared server offers (none that writes). `/metrics` is inside the same token check unless `server.metrics.allowUnauthenticated` opens it, answers GET and HEAD only, and carries counters whose every label value comes from a fixed set -- an exception type a caller can provoke collapses to `error` rather than becoming a new Prometheus label. |
| Input parsing | YAML SafeLoader only, 5 MB / 1000-document caps, alias-expansion budget against billion-laughs. |
| Suggested commands | Steps a diagnosis prints are read-only and copy-paste safe: a name taken from the input (pod, Service, label selector, namespace) is pasted into a command only when it is made of letters, digits and `@._:/=+#%,-` and does not start with `#`, otherwise its placeholder stays; a Service selector is used only when every key and value is a valid label; no step prints a Secret's values. Every validator ends with `\Z`, not `$` (Python's `$` also matches before a final newline, so a must-gather namespace `"shop\n"` once split a printed step into two shell lines); a test fails on any new validator anchored with `$`. |
| Must-gathers | Opened as a stream or a walk with no links followed; nothing extracted or run; Secrets-named files never read; YAML pre-scanned for aliases, documents and depth before libyaml loads it. The `analyze_must_gather` MCP tool is offered by the HTTP server only with `mustGather.allowedDir` and reads only paths that resolve inside it (links resolved first); it is not in the Claude plugin. |
| Prompt injection | Every MCP tool result and the knowledge resource is cleaned before it leaves the server. Removed: invisible Unicode (tags, bidi overrides, zero-width other than an emoji's joiner, soft hyphens and other word splitters), chat-template and role markers, tool-call markup, instructions aimed at a model (matched on a normalised copy: full-width and mathematical letters folded, Cyrillic and Greek look-alikes mapped, entities and colour codes decoded, hyphenated line breaks joined; English, Spanish, French, German, Italian, Portuguese, Russian, Chinese, Japanese, Korean; inside base64), every remote image address and a link's query when it can carry data. Flagged but kept: phrases that are operations as often as attacks ("send the credentials to vault.example.com"). The result carries `untrusted: true` and the signals. Evals: 66 of 66 and 25 of 25 with no finding on 148 benign lines; the red team's 50 new attacks 48 caught and its 55 adversarial benign lines 1 altered (a remote badge image), 8 flagged; these sets were used to tune, RT2 measures blind. |
| HTML report | One file with nothing the browser fetches and nothing it runs: no script, stylesheet, font or image, and the charts are inline SVG rather than a plotting library. Every value from a manifest is escaped before it is written, inside the SVG as well as in the page, because a `<title>` or a label is as good a place to run a script as a table cell is; a test parses what is produced and fails on any `src`, `<link href>`, inline handler, `<script>`, `<use>`, `<image>` or `<foreignObject>`. |
| Container | UBI 9, non-root numeric UID, works with OpenShift arbitrary UIDs, read-only root filesystem in the chart, all capabilities dropped, RuntimeDefault seccomp. |
| Supply chain | Hash-pinned dependencies (`requirements.lock`), SHA-pinned Actions, CodeQL, OpenSSF Scorecard, Dependabot, `pip-audit` in CI, PyPI Trusted Publishing, SLSA provenance attestations, SBOM, keyless cosign signatures. |
| Data | Corpus records carry license and redistributability; Jira identities and emails are scrubbed; non-redistributable content is never published unencrypted by CI. Retention and destinations: [PRIVACY.md](PRIVACY.md). |
| Private Jira seed | Sealed with the organisation's key: AES-256-GCM per 1 MiB chunk with counter nonces and a last-chunk flag, a per-file key from PBKDF2-HMAC-SHA256 (600,000 iterations, random salt); any edit, reorder, drop, truncation or wrong key fails and nothing is written. The key comes from a mounted Secret file only (mode 0440, the server container alone). The `jira-db-image` workflow refuses a repository anyone can list and an image anyone can pull, and refuses a copy whose anonymiser self-check finds a person. |
| Public data image | `kube-noob-db` holds one archive that `corpus db-check` gates twice in CI (before the build and on the image's own copy) and again on the pushed digest: redistributable records on allow-listed licenses only, no Jira data, every file listed with its checksum, no links or special files. Published only when the maintainer enables it, attested and keyless-signed; the chart accepts it by digest only, copies it with `cp` in a read-only, capability-free init container, and `corpus import` re-validates the whole archive before copying anything. |
| Red Hat Jira sync | REST API only (no page scraping, per Atlassian's Acceptable Use Policy); one request per second or slower (robots.txt crawl delay) plus random jitter, a request budget per run, the in-cluster sync's first run after a random 30 s to 10 min and every interval +/- 10%, clones from GitHub spaced by a random pause, the scheduled refresh started at a random offset, backoff on 429 with `Retry-After`; the client can only GET from the Jira host (plus POST to its search endpoint) over HTTPS; project and issue keys are validated before they reach a query; the local ticket index is mode 0600. |
| Claude plugin | Runs the readable stdio server bundled in the plugin with `uv run --frozen --isolated`; every dependency is pinned by version and sha256 in `uv.lock`; no LLM SDK is installed and no package-manager variable is set; only the modules the stdio server imports ship, so nothing in the plugin reads a credential; web, cluster and model calls are off. |
| Directory plugin | `kube-noob-skills` ships Markdown and JSON only: no server, script, hook or `bin/`. Its skills run the CLI the user installed through Claude's Bash tool, so every command goes through the user's own permission prompt; the plugin pre-approves no tool (no `allowed-tools`) and runs nothing as a skill loads. No command it runs carries `--cluster-enabled`, `--web-enabled`, `--live` or `--online`, pasted text reaches the CLI as a file written with a quoted heredoc rather than as an argument, and the only fetch it can cause is a pinned `uvx --from kube-noob==<release>` run the user agreed to. Tests parse every command line in the skills against the real argument parser. The CLI's JSON is not cleaned like an MCP result, so text quoted from the input reaches Claude as it was; the skills tell Claude to treat every string as data. |
| Availability | A burst of idle or slow connections starves the HTTP server's connection pool: uvicorn counts connections towards `limit_concurrency` and nothing reclaims one that never sent a request (`timeout_keep_alive` applies between requests on a keep-alive connection), so every request including the kubelet's probes answers 503 until they close. kube-noob cannot close this in process. Buffered-body memory is bounded -- the limit is 1.5 MiB and the concurrency limit 64, so 96 MiB against a 512Mi container -- and the liveness probe is four times more forgiving than readiness, so sustained overload sheds traffic instead of restarting the pod. **Expose the port through a reverse proxy, ingress or service mesh that enforces a header-read and idle timeout.** The default sidecar deployment binds 127.0.0.1, where only containers in the same pod can reach it. |
| Sidecar | Binds 127.0.0.1 only, so only containers in the same pod can call it (the pod is the trust boundary); no Service port, no token, no egress needed. CI proves the port is closed on the pod IP. |
| Egress on OpenShift | Chart NetworkPolicy allows DNS only by default; optional OVN-Kubernetes EgressFirewall allows only the API server and allowlisted HTTPS domains, then denies all. |
| Homebrew | The formula installs the release wheel and wheels-only dependencies pinned by hash from the release's `requirements.lock`. |

Workflows run only reviewed code with write-capable tokens or caches: no checkout takes a ref typed into a workflow
input, and the videos workflow renders only a release tag and a pipeline commit that are on the default branch.
CodeQL (`security-extended`, Python and Actions) runs on every pull request and on main.

## The directory plugin and a remote server

The Claude plugin directory accepts a remote MCP server from an organization that is not Verified, so
`kube-noob-skills` could declare an `http` server whose URL and bearer token come from `userConfig` and point it at
the user's own `kube-noob serve`. It does not, for now. What the documentation says, read 2026-11-12:

- A `sensitive` value "masks input and stores the value in secure storage instead of `settings.json`", and
  `${user_config.KEY}` is substituted into an MCP server's `url` and `headers`
  ([plugins reference](https://code.claude.com/docs/en/plugins-reference#user-configuration)). The
  token would not be written into the plugin's files.
- But a server whose URL option is unset is an error, not an absence: Claude Code reports `Invalid MCP server config
  ... URL is unset or invalid` on the plugin's Errors tab
  ([troubleshooting](https://code.claude.com/docs/en/plugins/troubleshooting)). Chat ignores such a server and Cowork
  ignores one whose option has no default ([platform support](https://claude.com/docs/plugins/platform-support)).
  Most people installing from the directory will never run `kube-noob serve`, so the default state of every install
  would be an error, and a skill would have to name `kubenoob_*` tools that exist only on some installs.
- `kube-noob serve` on a laptop is a local process presented as a remote one. That is the thing the directory gates on
  Verified status, reached by a side door; a reviewer could fairly read it that way.

The CLI path covers the same commands with no credential at all. If it is ever shipped, the server is optional, the
token is a `sensitive` option and the URL has no default; `tests/test_plugin.py::test_bundle_names_no_credential_variables`
does not cover it (it scans `plugin/kube-noob/server/`), so a test for the directory plugin has to refuse any literal
header value. That decision is the maintainer's.

## Capability tiers

kube-noob reads by default and changes nothing. Everything else is a tier, off by default; every action in a tier
needs a person's approval for exactly that action, valid for 15 minutes and usable once. `kube-noob doctor` prints
each tier and what it needs.

| Tier | Switch | Allows | Needs |
|---|---|---|---|
| R | `cluster.enabled` | get, list and logs on the allowlisted resources (including Roles, RoleBindings, ClusterRoles and ClusterRoleBindings for the attack-path scan); Secrets never | get/list/watch RBAC |
| R | `ci.githubEnabled` | GET of a repository's GitHub Actions runs, attempts and jobs, to `ci.githubApiUrl` only, no redirects | a token with `actions: read` in `$GITHUB_TOKEN` |
| R | `rhacs.enabled` | GET of RHACS Central's policies (`/v1/policies`) and of the image scans you name (`/v1/images/<digest>`, `vuln report --rhacs-image`), to `rhacs.endpoint` only, no redirects | an RHACS API token that can read policies and images (for example the Analyst role) in `$ROX_API_TOKEN` |
| P | `probe.enabled` | an ephemeral debug container or a probe Job | patch on `pods/ephemeralcontainers`; create and delete on Jobs (chart Role only when enabled) |
| D | `dryRun.enabled` | server-side dry-run (`?dryRun=All`) of a manifest | create and patch on `dryRun.rules` resources, never Secrets: Kubernetes authorizes a dry-run exactly like the real request |
| W | `itsm.writeEnabled`, `notify.enabled` | attach evidence to a ticket; forward a report | the external system's token; refused under the offline lock |
| G | `gate.enabled` | forward a tool call a person approved to an upstream MCP server | nothing from kube-noob; the upstream keeps its own access |
| M | `llm.provider` | `kube-noob ask`, `train bench` and the eval judge call a model; no MCP tool and no other command does | the key named in `llm.apiKeyEnv` (only `*_API_KEY` variables, so never the server's own `KUBE_NOOB_HTTP_TOKEN`), or `$ANTHROPIC_API_KEY` for `provider: anthropic` -- which is that provider's default and is sent nowhere else. An `openai-compatible` endpoint with no `apiKeyEnv` is called with no `Authorization` header. Endpoint error bodies are redacted before kube-noob quotes them. Refused under the offline lock unless the endpoint is loopback or `*.svc` |
| A | `admission.enforce` (chart `admission.enabled` runs the webhook) | `kube-noob admission serve` denies a create or update for a listed rule, and on an update only a finding the old object did not have; otherwise it only warns; it never mutates, and `failurePolicy: Ignore` means a dead webhook blocks nothing -- which KN-S030 reports as a HIGH finding, correctly: a policy gate whose purpose is to deny should set `Fail`. For this webhook the trade-off is deliberate and accepted on the record in `.github/kube-noob-exceptions.yaml`, because an audit webhook that is down must not stop a cluster admitting objects. If you audit your own kube-noob install you will see the same finding; accept it the same way rather than lowering the rule. The object's name is `<release>-kube-noob-admission.<namespace>.kube-noob.io`, so it embeds your release name and namespace, and a cluster-scoped exception must name it exactly -- copy the shape of our entry, not its name | a serving certificate (OpenShift service CA, cert-manager or your Secret); with `admission.lookups`, a ClusterRole with get and list on PodDisruptionBudgets, NetworkPolicies, PersistentVolumeClaims, HorizontalPodAutoscalers and StorageClasses |

Tier A is configuration rather than an action: whoever lists a rule in `admission.enforce` approves every denial of
that rule, so it has no per-action approval. The read-only backends have no method that writes. Code that changes something exists only while its tier is on.
kube-noob's own audit flags what the P and D Roles allow (KN-S017, medium): pods started by Jobs or added as
ephemeral containers can act as any ServiceAccount in the namespace, so enable them only in namespaces that enforce
Pod Security `restricted`.

## Compliance

Audit findings name the NIST SP 800-53 Rev. 5 controls they are evidence about, and `kube-noob doctor` reports FIPS
mode. How to deploy kube-noob inside a FedRAMP High boundary, and what is not covered yet:
[docs/compliance.md](docs/compliance.md).

## Verifying releases

```bash
gh attestation verify dist/kube_noob-*.whl --repo kube-noob/kube-noob
cosign verify ghcr.io/kube-noob/kube-noob:<version> \
  --certificate-identity-regexp 'https://github.com/kube-noob/kube-noob/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
