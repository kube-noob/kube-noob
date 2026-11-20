# Working on kube-noob as an agent

This file is for an AI coding agent (Claude Code, Codex, Cursor and anything that reads `AGENTS.md`). A human
contributor wants [CONTRIBUTING.md](CONTRIBUTING.md); the ground rules there apply here too, and this file adds what
an agent gets wrong.

## The one command that decides whether you are done

```bash
bash scripts/check.sh
```

It runs the gates CI runs on code: the plugin copy, the Agent Skill build, the safety contract, the compliance
document, the numbers the documents quote, the KSI crosswalk, ruff (lint and format), mypy, the full test suite
**with CI's coverage floor**, kube-noob's own self-test, both `pip-audit` runs, `uv lock --check`, the wheel built
and installed and driven, the MCP and plugin end-to-end runs, `check_publishable.sh`, the Homebrew formula against
PyPI, the OSCAL document against the pinned NIST schema and the gate's SARIF against the vendored OASIS one. It
takes about twenty minutes.

Where this machine lacks a tool, the step is **named at the end under NOT RUN** rather than passed over — read that
list, because "it did not run" is not "it passed", and CI still runs it. `helm` is the usual entry, which leaves
`ci/helm-and-dogfood` as the one job no local run covers.

This used to claim it ran every gate and ran eleven fewer, and it passed four times running while CI failed
(G260, G261, G263, G264). `tests/test_check_sh.py` now fails if a gate a CI code job runs is neither in check.sh
nor named with a reason, so the claim above stays true as ci.yml changes.

Read its **exit status**, not its last lines. Piping it through `tail` or `head` replaces the exit status with the
pipe's, so a failing gate looks green — and a step killed by SIGPIPE reports 141, which is a failure too:

```bash
bash scripts/check.sh > /tmp/gate.log 2>&1; echo "exit: $?"
```

Do not report a change as working until that exit status is 0. "The tests I wrote pass" is not the gate.

## After any change under `src/`

```bash
python scripts/sync_plugin_server.py
python scripts/safety_contract.py --check
python scripts/compliance_doc.py --check
python scripts/doc_numbers.py --check
python scripts/permissions_doc.py --check
```

`src/` is the only source of truth. `plugin/kube-noob/server/kube_noob/` is a **generated copy** — never edit it, and
never add a module to it by hand. The sync script decides which modules ship, and it deliberately leaves some out
(`kube_noob.mustgather`, `kube_noob.rhacs_central`, the image audit): the plugin must read nothing from the user's
machine and hold no credential. If a test fails because something is missing from the plugin, the answer is almost
always that it is meant to be missing.

`scripts/safety_contract.py` regenerates `docs/safety-contract.md` from the code. If it reports a mismatch, the
contract document is stale — regenerate it, do not edit it.

`scripts/compliance_doc.py` does the same for the rule table, the control-titles table and the rule count in the
heading of `docs/compliance.md` — run it after adding a rule or a control instead of editing those tables. It
rewrites only those three regions and leaves the prose alone, and it REFUSES rather than half-rewriting a table
whose shape has changed. A control the document evidences through posture rather than through a rule (`SC-13`,
via `kube-noob doctor`) lives in `POSTURE_CONTROLS` in that script, because generating from `RULE_CONTROLS` alone
would delete it.

`scripts/permissions_doc.py` regenerates `docs/permissions.md`: which API resources each live capability reads,
recorded by running it against a fixture cluster, and what the chart's read-only Role and ClusterRole grant. After a
change to a live reader or to `ALLOWED_RESOURCES`, regenerate it; `tests/test_permissions_doc.py` holds the chart to
the allowlist in both directions (G293).

`scripts/doc_numbers.py` does the same for the measured numbers in `docs/limits.md` (how many rules generate an
admission policy per platform) and `docs/use-cases.md` (the compaction measurement). Both are measured by running
the command the document shows -- the compaction one shells out to the CLI, because the sentence is about the
bytes that command writes and an in-process reconstruction was 20 bytes off. Four of these numbers were wrong at
once on 2026-11-05, and two of them summed to a rule count retired three releases ago (G212).

## Tests first, and make them fail first

Write the test, run it, see it red, then fix the code. A test written after the fix tends to assert what the code
does rather than what it should do. Name the test after the behaviour (`test_a_blind_run_is_not_reported_as_a_clean_one`),
not after the function.

Then test what you skipped, not only what you built. `docs/review-classes.md` lists the twenty-six defect classes
that adversarial reviews found in changes that had passed this gate with tests; for each class that applies to your
change, write the test before you push, and after every fix test the neighbouring input (the other wrapper, the
other type, the other order) in the same commit. A review will try those first.

## Gates that catch agents specifically

| Gate | What it refuses |
|---|---|
| `tests/test_distribution.py::test_no_source_file_is_ignored_by_git` | a new source file that `.gitignore` would drop, so the wheel ships without it |
| `tests/test_security_hardening.py::test_validators_end_with_backslash_z_not_dollar` | a validation regex ending in `$`, which matches before a trailing newline; use `\Z` |
| `tests/test_distribution.py::test_bundled_yaml_parses_under_every_yaml_parser` | a colon inside an unquoted scalar in a flow collection. Local libyaml accepts `[k:1]`; the libyaml in the browser build does not, so a file that parses in CI breaks a shipped install. Quote it: `["k:1"]` |
| `tests/test_plugin.py::test_bundle_names_no_credential_variables` | a credential variable name (`*_TOKEN`, `*_API_KEY`) appearing anywhere in the plugin copy, **including in a comment** |
| `tests/test_plugin.py::test_manifest_uses_only_fields_the_plugin_reference_defines` | a field the plugin manifest reference does not define |
| `docs/guidance.md` row check | a row whose `file.py::test_name` citation does not resolve. Every behaviour claim in that table must name a test that exists |
| `tests/test_timing_assertions.py::test_no_test_asserts_a_tight_wall_clock_budget` | a raw wall-clock comparison below 30 s in a test. A tight budget measures the runner, and when it loses it reports a false failure; state the shape of the regression and let `tests/bounds.py` derive the ceiling, or assert the bounded output instead and drop the clock (G326) |

## Documentation is part of the change, not a follow-up

A behaviour change updates, in the same commit:

- `CHANGELOG.md` — under `## Unreleased`, saying what was wrong and why it mattered, not what you did
- `docs/guidance.md` — a new `G<n>` row citing the tests that hold the behaviour
- `PRIVACY.md` / `SECURITY.md` — when what leaves the process, or what the process can reach, changed
- `docs/use-cases.md` — when there is a new thing a user can do

## Exit codes are a public contract

`kube_noob/cli.py` means exactly this, and CI pipelines depend on it:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | findings at or above `--fail-on`, or a verdict that is undetermined (`audit`/`gate`/`ksi`/`posture diff|report`: an object the rules did not read and no `notAudited:` exception accepted, or a rule that declined on every object it had -- `summary.verdict`; the exceptions gate) -- never 0 for undetermined, whatever `--fail-on` says (G272, G281) |
| 2 | configuration error, or a file that is not there |
| 3 | clarification needed |
| 4 | a kube-noob error, or refused input |
| 5 | the evidence was incomplete (`--require-complete`, unreadable files, a file the directory walk declined to read as a manifest) |
| 141 | the output pipe closed |

An error kube-noob did not anticipate is caught at the entry point (`cli.main`) and reported as one cleaned line
on stderr with exit 4, never a raw traceback that exits 1; set `KUBE_NOOB_DEBUG=1` to print the traceback too,
through the same output boundary (G279).

Never add a meaning to an existing code. 5 exists because a gate that crashed used to leave 1, and a pipeline read
that as policy violations. For the same reason an exception nothing else caught exits 4 with that one line, never
Python's default 1 (G276, G279); `posture scan --fail-above` exits 5 on what was refused (an object of the wrong
shape, a read the cluster forbade or did not answer) and, with `--require-complete`, on anything under `notRead`.

### 1 and 5 are not two answers to the same question (G272)

Three-valued verdicts make two codes available for a run that is not a clean pass, and they answer different
questions. **1 means a verdict was reached and it is not a pass.** **5 means no verdict was reached, because the
evidence offered was not enough to reach one.** A command picks by which of those happened, never by how bad the
result feels, and the two are not a disagreement between commands: they are a disagreement between "may this
pass?" and "could this be decided at all?".

So an **undetermined verdict is exit 1**, not 5. A rule that declined on the only API server it could see, an
object nothing read, a tie between two policies: the run looked, got as far as an answer, and the answer is not a
pass. `audit`, `gate` and `policy reach` all exit 1 there, and **`--fail-on` and `--min-severity` never lower it**
-- an undetermined report is not a clean one at any threshold, so "no severity is worth failing on" cannot turn it
into a 0. `gate`'s headline for it is `incomplete`, never `passed`
(`tests/test_control_plane_review7.py::test_an_undetermined_audit_exits_1_whatever_fail_on_says`,
`tests/test_control_plane_review7.py::test_the_gate_is_incomplete_not_passed_on_an_undetermined_audit`,
`tests/test_netpol_anp.py::test_the_reach_command_prints_and_exits_on_an_undetermined_verdict`).

**5 is for evidence kube-noob refused to decide from**: a file that could not be read and `--skip-unreadable` was
not given, so no verdict was attempted at all, and `--require-complete` on a command whose answer is not complete,
where the caller has said that a partial answer is not an answer
(`tests/test_red_team_rt3.py::test_a_crash_never_wears_the_exit_code_of_a_policy_failure`,
`tests/test_blast_radius.py::test_require_complete_exits_5_when_a_leg_is_not_determined`). `--skip-unreadable` is
the caller saying "decide without that file", so the run does decide: the file stays named in `unreadable` in
every format, and the exit code is the verdict's, not 5
(`tests/test_red_team_rt3.py::test_one_bad_file_does_not_hide_the_findings_in_the_good_ones`). The order follows
from that: the refusal is checked before the verdict, so an unreadable file in a directory that would also have
been undetermined is 5, and the same directory with `--skip-unreadable` is 1.

That is the general shape and not an exception: **a waiver the person asked for does not change the exit code, and
the evidence it waived is still named in the output.** `--skip-unreadable` and an accepted `notAudited` row are
the same move -- the person has taken responsibility for what was not read, so a verdict WAS reached on the
evidence that remained and the code is that verdict's. What the waiver must never do is make the gap disappear:
the skipped file stays in `unreadable` and the accepted record stays in `notAudited`, in the text view and in
JSON and YAML and in the MCP result alike. A waiver is an answer about less evidence, never a cleaner answer about
the same evidence.

A command whose own answer is a decision rather than a score reads the same rule the other way round: when it
cannot decide whether to allow something, no verdict was reached, so that is a 5 and not a 1. That is the same
sentence, not an exception to it.

How two commands fit the table (G280):

- `kube-noob verify` answers with 0 (allow), 1 (deny) and 5 (not determined), and like every command exits 2 on a
  usage or configuration error (`-f` and `--command` together or neither, a file that is not there, `verify -f -`
  with nothing on stdin, a `--cni` that is not NAME or NAME:VERSION) and 4 on an internal error or refused input;
  `--help` lists the same five. 1 is "findings at or above `--fail-on`": the audit's findings, a grant in
  the command that the memory verifier counts as one (cluster-admin, the privileged SCC, wildcard RBAC), or a
  literal credential in `set env` (KN-S013's finding, before there is a manifest). 5 is "the evidence was
  incomplete": what the change does could not be read from its text and the local files -- a URL, a delete whose
  target is cluster state, an `exec`. That is the rule above and not an exception to it: no verdict was reached.
  A deny with something unread is still 1, because a verdict WAS reached and more evidence cannot turn a deny into
  an allow -- where `gate`, whose answer is a score over a set it promises to have read, exits 1 for its own
  undetermined verdict instead. Both are listed in the output.
- `kube-noob hook claude-code` does not use this table. It answers in Claude Code's hook protocol, where the caller
  reads exit codes: 0 lets the call proceed (with a JSON `ask` on stdout when the user must decide), 2 blocks it,
  and every other code would let it through -- so once it is running the hook exits with nothing but 0 or 2, a
  configuration error or a crash included. A hook that cannot start at all is what `"onFailure": "block"` in the
  settings it installs is for.

## Versions

Only `python scripts/bump_version.py <version> "<reason>"` changes a version; it updates PyPI, the MCP Registry
entry, the plugin, the chart and the image metadata together, and `tests/test_distribution.py` enforces that they
agree. Tagging, releasing and publishing are the maintainer's, never an agent's.

## One pull request at a time

Every change here edits two append-only files: a `G<n>` row at the end of `docs/guidance.md`, numbered from the
highest one already there, and a bullet under `## Unreleased` in `CHANGELOG.md`. Two branches cut from the same
`main` therefore pick the **same** next number and insert at the **same** line. That is not bad luck; it is
arithmetic, and it cost this repository several rounds of conflict resolution that produced no code.

Both files are append-only, so `.gitattributes` gives them `merge=union` and a merge keeps both sides' lines
instead of stopping (G297). It does not pick your `G<n>` for you: two branches can still land the same number, and
`tests/test_guidance.py` fails on a duplicate. Nothing whose lines are rewritten -- `docs/roadmap.md`,
`docs/limits.md`, `docs/use-cases.md`, `docs/compliance.md`, `docs/safety-contract.md` -- is merged that way, so
those still conflict and are resolved by regenerating them with their script.

So: open one pull request, land it, then start the next. If a second branch is already open, merge `origin/main`
into it (never rebase, never force-push), take the higher `G<n>` for the later change, and regenerate the
generated documents before asking anyone to merge it.

## Commits

Sign off every commit (`git commit -s`) to certify the Developer Certificate of Origin. Never force-push, rebase or
rewrite history on a shared branch.

## Already done (2026-11-04) — do not re-derive

- Live `policy reach` reads Cilium `cilium.io/v2` `ciliumclusterwidenetworkpolicies` and Calico
  `crd.projectcalico.org/v1` `globalnetworkpolicies`, cluster-scoped, once. A 404 stays a NetworkPolicy answer. A 403
  does not. A namespace `CiliumNetworkPolicy` is not read and does not flip a pod-to-pod verdict. Merged as #38
  (`cfe8acd`), on top of the file and hostNetwork case in #37 (`69a4959`).
- pydantic is 2.14.2 in the plugin lock, the skill install hint and `requirements.lock` (#39, `e05e056`). The package
  version is still 0.7.1. Do not tag, release or publish.
- A corpus shard bigger than the bundle allows is stored as parts, not by raising `db_bundle.MAX_MEMBER` (300 MB).
  `PART_MAX` is 250 MB. Files are `<shard>.jsonl` then `<shard>-2.jsonl`. `vuln.parts.shard_paths` reads them.
  The plugin must not import `sources`: that package is how the Jira client, which names `JIRA_API_TOKEN`, would
  be bundled. Held by `tests/test_db_bundle.py::test_a_shard_over_the_member_cap_is_written_as_parts_and_read_back`
  and `tests/test_jira_main_copy.py::test_the_plugin_gets_reconciliation_without_the_jira_client` (G262).
- `brew.yml` asks for macOS only on `workflow_dispatch` and `workflow_call`. A push, a pull request and the schedule
  run Ubuntu. Run 41858323552 was cancelled because GitHub did not assign a macOS runner. The formula itself passed
  on Ubuntu.
- Issue #22 (weekly risk review 2026-W45) stays open until a later week supersedes it.
- kube-noob.com is built by the private site repo and pushed to `kube-noob/kube-noob-www`. The path
  `aashishmahajan/kube-noob-www` is the wrong target (site PR #4, merged). The push is still denied: both deploy
  keys on `kube-noob-www` are `enabled: false` (ids 168038103 and 168088767, the second titled `kube-noob-site
  deploy`) because the organization has deploy keys turned off. Creating a key returns 422 "Deploy keys are
  disabled for this repository". The token available to an agent cannot change that organization setting (403).
  An owner turns Deploy keys back on under the organization's Member privileges, then checks that key 168088767
  is enabled. Do not mint a replacement key unless that one is deleted. Do not force-push `kube-noob-www` by
  hand. The hand publish `f6ff300` (2026-11-04) left Pages with `cname: null`, so https://kube-noob.com returns
  GitHub's "Site not found" while https://kube-noob.github.io/kube-noob-www/ still serves the files. Putting the
  domain back is `PUT /repos/kube-noob/kube-noob-www/pages` with `cname=kube-noob.com`. This token cannot do that
  (403, including a workflow whose `GITHUB_TOKEN` has `pages: write`). An owner sets Custom domain to
  `kube-noob.com` in the repository's Pages settings. `www` still CNAMEs to `aashishmahajan.github.io`, so that
  name does not match the certificate. The package version is still 0.7.1.
- The Claude plugin directory refuses `plugin/kube-noob` and always will while this organisation is not Verified:
  "Local MCP servers accepted only from Verified organizations" and "Files outside the allowed types accepted only
  from Verified organizations" (2026-11-10). 99 of its 218 files are a refused type and `.mcp.json` declares a local
  stdio server, so no edit keeps the server and passes. There is no way to apply for Verified status: Anthropic's own
  docs say the label is decided during review and the portal has no step for it. Do not strip the server out of
  `plugin/kube-noob` -- it is what installs from this repository's own marketplace, and its seven skills call 46
  `kubenoob_*` tools, so a server-less copy of them would name tools that do not exist. `plugin/kube-noob-skills` is
  the directory's plugin, rewritten rather than copied (G267). Since G276 its skills drive the CLI the user installed
  through Claude's Bash tool: `kube-noob --version` first (never `kubectl noob` or `uvx`, which fetch), then every
  command as `KUBE_NOOB_FOR_MODEL=1 KUBE_NOOB_LEARNING_ENABLED=false kube-noob ... --format json` into a private
  `mktemp -d` folder, and "nothing has been audited" when no engine is there. `tests/test_directory_plugin.py` maps
  every `kubenoob_*` tool the full skills call to a CLI command or a stated reason, parses every command line with the
  real parser, and runs every command a skill's table names on a fixture to check the fields the row cites. A tool
  added to a full skill, or a field renamed in a command's JSON, fails there. Do not add `allowed-tools`, a `!`-command
  line, a heredoc, a fixed `/tmp` path, a hook, `bin/` or a package launcher to that plugin. A remote MCP server
  pointing at the user's own `kube-noob serve` through `userConfig` is admissible and was not shipped: an unset URL is
  an error on every install that does not run `serve` (SECURITY.md, "The directory plugin and a remote server").
