# Website: what is out of date

The site lives in its own repository, which a working session has to be sourced at — it cannot be edited from a
session attached to this one. So this file is the queue: anything shipped here that the site states differently goes
in the table below when it is merged, and comes out when the site is updated. Numbers go stale faster than prose,
so every number below names the command that prints the true value rather than repeating it in a second place.

**Last drained: 2026-11-14, product at `3c1073f` ("docs: the review defect classes live in the repository", G296),
site repository at `ba062bc` on branch `site/catch-up-2026-11-14` (kube-noob/kube-noob-site#6, open).**
The site build before that was 2026-11-08 from `v0.9.2` (`kube-noob-www` `39deb8d`), so the gap drained here was six
days and eight commits. Record the date, the product commit and the site commit here every time, including when the
answer is "nothing to drain": a queue that cannot say when it was last drained cannot tell you whether ten rows is a
backlog or a morning's work.

## The numbers the site quotes

Run this and compare it against every page that states a count. A page that states one of these and disagrees is
wrong, not merely old: the compliance document said "The 78 audit rules" with 89 in the code for long enough to
reach a reader (G206), and these are the same kind of claim.

```bash
python -c "import sys; sys.path.insert(0,'src'); from kube_noob import __version__; from kube_noob.audit.engine import list_rules; from kube_noob.audit.controls import RULE_CONTROLS; from kube_noob.audit.redteam import SCENARIOS; from kube_noob.debug.playbooks import PLAYBOOKS; from kube_noob.learn.tutor import curriculum; from kube_noob.toolkit import Toolkit; from kube_noob.config import load_settings; t=curriculum()['tracks']; print('version', __version__); print('rules', len(list_rules())); print('controls', len({c for cs in RULE_CONTROLS.values() for c in cs})); print('playbooks', len(PLAYBOOKS)); print('red-team scenarios', len(SCENARIOS)); print('tracks', len(t), 'lessons', sum(len(x.get('lessons',[])) for x in t)); print('MCP tools', len(Toolkit(load_settings()).specs()))"
```

As of 2026-11-23 on `release/0.10.0`, merged up to `b8ad0f0`: version 0.10.0, 99 rules,
31 NIST SP 800-53 Rev. 5 controls,
67 offline playbooks, 9 red-team scenarios, 6 tracks with 18 lessons, 58 MCP tools. These seven figures are
asserted against the code by `tests/test_guidance.py::test_the_website_queue_states_the_real_numbers`, so this
paragraph cannot drift the way the compliance document's heading did. `docs/scorecard.md` and
`krew/noob.yaml` are generated from the same source and are worth copying from rather than retyping.

**Run it in a checkout at `origin/main`, not in whatever the working tree happens to be.** The 2026-11-14 session
found its product checkout eight commits behind `origin/main`, where the same command printed 49 MCP tools instead
of 54 — it reads a local configuration file if one is beside it, which is also why
`tests/conftest.py` isolates the environment before asserting these figures. Export the ref you mean
(`git archive origin/main | tar -x -C <dir>`) and run it there.

**Nothing on the site needs these numbers typed in.** `generate.py` computes every count on the home page, the
flow diagram and `/insights/` from the product checkout it builds against, so the figures above are a check on the
published site, not a thing to copy into it. The one that had actually drifted on 2026-11-08 was the MCP tool count
(48 published against 54 in the code), and it corrects itself on the next deploy.

## Queue

| # | What changed | Where on the site | Source of truth |
|---|---|---|---|
| 25 | The HTML report is **worth a screenshot and still has none**. `/evidence/` shows the real masthead — the verdict, the lede and the three numbers, including the middle one, withheld or not evaluated — rendered in the site's own markup from `report_html._masthead_of` at build time, which is true but is not the file. A rendered image of the actual page (a reviewer's laptop, no network, section 1 "Limits of this examination" below the fold) would say in one picture what that section says in a paragraph. The site build already has Chromium through Playwright for `smoke.mjs`, so the honest way is to render it during the deploy rather than to commit a picture that can go stale | `/evidence/`, and the social preview if one is ever rebuilt | `src/kube_noob/report_html.py`, `kube-noob gate -f examples/insecure-deployment.yaml --html /tmp/r.html`, G256, G257, G259, U1, U3 |
| 26 | **There is no drift or posture-over-time page.** Nothing on the site states drift wrongly, which was the old row's worry — it states nothing at all. `posture diff` and `posture report` report completeness as three values (complete, incomplete, or **unknown** for a snapshot taken before 0.8 that carries no `notRead` key), a snapshot keeps what the audit had to assume (`assumptions`, capped at 60), and per-control standing has five buckets. A snapshot whose completeness is unknown cannot be subtracted from one whose completeness is known and called a delta, and that is the interesting thing to show — the `--html` posture page carries the charts for it | a new page, or a section of `/evidence/` | `src/kube_noob/drift.py`, `kube-noob posture report --format json`, G214, G216, G255 |
| 27 | **There is no CNI support matrix.** `/` names all four policy tiers in cluster order and says an undocumented CNI leaves the verdict undetermined, which is correct but is not a matrix. The facts a matrix would have to carry: `ClusterNetworkPolicy` (`policy.networking.k8s.io/v1alpha2`) is evaluated, not merely named (`Accept`/`Deny`/`Pass`, `protocols` in place of `ports`, a Baseline tier that is no longer a singleton named `default` and carries a priority, a peer with no recognised field treated as a newer CRD); **Calico 3.32 removed ANP and BANP enforcement in favour of it**, so any text pairing Calico with AdminNetworkPolicy is wrong; and `--cni NAME[:VERSION]` makes an AdminNetworkPolicy that Calico 3.32+ does not enforce report as inert | a new page under the policy section | `src/kube_noob/debug/cnp.py`, `src/kube_noob/debug/cni.py`, `kube-noob debug reachability --help`, G207, G209, G258 |
| 28 | **There is no attack-paths page.** `/blast-radius/` covers `posture reach` (one named workload, five legs) and links `posture scan` without showing it. `posture scan` now ranks more escalation rights (token minting, ephemeral containers, webhook control, PersistentVolume and certificate issuance), projected and legacy Secret-mounted tokens, Gateway API HTTPRoutes and Istio VirtualServices, and OpenShift's legacy `authorization.openshift.io` RBAC. If such a page ever lists what the scan finds, the list will be short the day it is written, and **it must not say an RBAC right it does not list is harmless**: only a short named list is (reviews, leases, events, status writes), and anything else is reported not determined | a new page, beside `/blast-radius/` | `src/kube_noob/attack_paths.py`, `src/kube_noob/blast_radius.py`, `docs/use-cases.md`, G273 |
| 29 | **There is no admission page.** `/docs/use-cases/` is mirrored and carries it; nothing the site writes itself mentions admission, so nothing is wrong and nothing is shown. What such a page must get right: `policy generate` emits a ValidatingAdmissionPolicy and a Kyverno ValidatingPolicy for `KN-S036` and the bundled webhook evaluates it; two kinds of allowlist are deliberately refused rather than compiled (`docker.io`, and a host with no dot, port or `localhost`); the webhook receives KServe `InferenceService` and KubeRay `RayCluster`/`RayJob`/`RayService`, but **the generated policies do not cover those kinds**, so the page must not say admission covers every rule on every kind; and the chart's own KN-S030 finding is accepted in `.github/kube-noob-exceptions.yaml` with an owner and an expiry | a new page | `src/kube_noob/admission.py`, `SECURITY.md`, G205, G229, G242, G243, G248 |
| 30 | **There is no CI or GitHub Action page.** `/evidence/` carries SARIF, OSCAL, KSI and `--github-annotations` as four cards; the Action's inputs, the exception list, the exit codes and what "Not run" means in a pipeline are only in the mirrored docs. This is the page a stranger from GitHub most plausibly wants | a new page | `action.yml`, `src/kube_noob/gate.py`, G215, G216 |
| 31 | **The site's own defect queue is no longer published.** `collect_docs` mirrors every `docs/*.md` into "More", so this file was a public page at `/docs/website-updates/` — a page of claims contradicting the pages around it, with internal defect ids in every row. `generate.py` now holds `NOT_PUBLISHED = ("docs/website-updates.md",)` and a test asserts the page is absent. If this file is ever renamed, that tuple and `test_the_sites_own_defect_queue_is_not_published` have to move with it | nothing to do; recorded so the next session does not wonder where the page went | `kube-noob-site` `generate.py`, `tests/test_site.py` |
| 32 | **Publishing needs a release, or a run by hand.** `deploy.yml` builds from the product's **latest release**, which is `v0.9.2` -- a tag cut before the organisation move, so it names the previous owner throughout and every page published from it carries the old `brew tap` URL. That is why the live site still shows it; no site change fixes it. The pages merged on 2026-11-14 document `main`: `kube-noob examples copy` ships in 0.10.0, and `/start/` falls back to download instructions without it. Cut 0.10.0 and let `site-sync` dispatch, which publishes the code and the pages together; a `workflow_dispatch` with `product_ref: main` publishes sooner but labels every page 0.10.0, because that is what `__version__` says | nothing on the site; an owner action | `kube-noob-site` `.github/workflows/deploy.yml`, `src/kube_noob/__init__.py` |
| 33 | **Two owner-only Pages actions are still open.** `kube-noob-www` belongs to the `kube-noob` organisation, but the domain was verified, and `www` pointed, under the previous personal account. The site README now gives the organisation's own steps: verify `kube-noob.com` under the `kube-noob` organisation's Settings > Pages (TXT `_github-pages-challenge-kube-noob`), point the `www` CNAME at `kube-noob.github.io`, and remove the old TXT record. A verification held by the old account does not cover this repository | nothing on the site; two owner actions | `kube-noob-site` `README.md`, GitHub docs "Verifying your custom domain for GitHub Pages" |
| 34 | **Next drain: what is in flight but not landed at `3c1073f`.** None of these is on the site, and none should be until it merges — a `verify` pre-flight command and a Claude Code hook; `gate --require-evaluated`; CI `evidence` outputs; and a FIPS, permissions and air-gap documentation set. When each lands, replace this row with a row of its own naming the page it belongs on | nothing yet | `git log origin/main --oneline` |
| 35 | **Every page's rule and control count is wrong.** The control plane and its trust boundaries landed after this file was last drained: `KN-S037` (an APIService that skips TLS verification to its extension API server), `KN-S038` (kube-apiserver with anonymous auth or the AlwaysAllow authorizer, read from the static pod), `KN-S039` (etcd serving clients or peers in plaintext or without client certificates), `KN-S040` (OpenShift encryption at rest off), `KN-S041` (an OpenShift LDAP identity provider without TLS). Rules 93 to **98**, controls 30 to **31** (SC-28(1)), both measured at `4d2485d`, not copied. Each of the five **declines** with a stated reason where it cannot decide -- on ROSA with HCP, behind an `--authorization-config` file, in a shell-wrapped static pod -- so the site must not describe them as checks that pass there | every page stating a rule or control count; the compliance page | `docs/compliance.md`, generated by `scripts/compliance_doc.py`, G272 |

## Checklist for the weekend session

1. Source the session at the site repository (this one cannot reach it). It is `kube-noob/kube-noob-site` (private,
   the source) and `kube-noob/kube-noob-www` (public, built files only, force-pushed one fresh commit per deploy —
   **never hand-edit it, and never regenerate it by hand either**: the deploy workflow is what publishes).
2. Run the facts command above in a checkout of THIS repository **at `origin/main`**, and work from its output.
   Never retype a number from this file: the paragraph above is a check on the published site, and `generate.py`
   computes every count the site shows from the product checkout it builds against.
3. Walk the queue table top to bottom; delete each row as the site catches up, and record the date, the product
   commit and the site commit at the top of this file. Row numbers are append-only: never renumber.
4. Check the install page against `docs/install.md` and the `Formula/` directory rather than memory: Homebrew, pip,
   pipx, uv, the container image, the Helm chart, the Claude plugin and the Agent Skill each have their own current
   instructions there. The site now reads that table at build time (`install_rows()` in `generate.py`), so the fix
   for a wrong install command is usually in this repository, not in the site's.
5. **krew**: the plugin and its manifest ship here, but the krew-index pull request is owner-only and is not open.
   `kubectl krew install noob` does not work, and a site test refuses `kubectl krew`, `krew install` and
   `krew-index` on every page. Do not relax it until the index pull request merges.
6. Positioning: the site must not call kube-noob an AI, an assistant, a chatbot or an agent. `tests/test_brand.py`
   and `tests/test_guidance.py` hold that line for this repository's copy, and since 2026-11-14 the site holds it
   too — `test_the_site_never_calls_kube_noob_an_ai_an_assistant_a_chatbot_or_an_agent` runs the same four patterns
   over the site's own pages and sources, so it is no longer a manual read. "No AI inside. Works with yours." is the
   line.
7. Before pushing, in the site repository: `ruff check .`, `python -m pytest -q tests` with `KN_PRODUCT` pointing at
   a product checkout at `origin/main`, `node --test forms/test/backend.test.mjs`, `node bundle.mjs _site`, and
   `node smoke.mjs` if Chromium and the Pyodide distribution are available (337 MB; the deploy workflow runs it
   regardless, before anything is pushed).
8. Anything the site shows as command output must be a real run made at build time, not prose about it. The pages
   added on 2026-11-14 (`/start/`, `/blast-radius/`, `/operators/`, `/evidence/`, `/testing/`) call the product and
   print what it returned, and tests assert the page contains that run's own strings. Keep it that way: a described
   answer goes on saying "five legs" long after a leg stopped being determined.
