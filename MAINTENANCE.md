# Maintenance

This file states what you can and cannot rely on if you adopt kube-noob. It is deliberately blunt: a security tool
that quietly stops being maintained is worse than one you never adopted, so the real situation is written down here
rather than implied.

For vulnerability reporting and security response targets, see [SECURITY.md](SECURITY.md). This file covers
everything else.

## Project status

**Pre-1.0.** The first release (v0.1.0) was tagged 2026-10-27 and v0.9.2 on 2026-11-08: 17 releases in thirteen days.
That pace means active development, not a stable contract. Until 1.0:

- Rule ids are stable once published. A rule is deprecated, never silently repurposed.
- Output schemas may gain fields in a minor release. Fields are not removed or re-typed without a deprecation note
  in the changelog.
- CLI flags may be added. Removing or renaming one requires a deprecation period of at least one minor release.
- The audit verdict for a given rule and input is covered by tests and is not changed without a changelog entry.

If you need a frozen interface today, pin an exact version and read the changelog before upgrading.

## Bus factor

**One.** kube-noob is maintained by a single person and there is no company, foundation or other legal entity behind
it. Nothing about the code quality changes that, and no document can substitute for it.

What this means concretely for an adopter:

- There is no support contract, no SLA and no commercial escalation path.
- If the maintainer becomes unavailable, releases stop until someone else takes over.
- Apache-2.0 means the code, the rules and the generated policies remain yours to use and fork regardless.

The mitigations that actually exist are listed under Succession below. Judge the project on those, not on this
paragraph.

## What is permanently open

The CLI, the rule set, the policy generator, the MCP server, the Helm chart and the generated admission policies are
Apache-2.0 and stay that way. The generated ValidatingAdmissionPolicies and Kyverno policies are plain Kubernetes
objects with no runtime dependency on kube-noob: once applied, your cluster enforces them whether or not this project
continues. That is deliberate, and it is the main thing protecting you from the bus factor above.

## Bill of materials

[`docs/sbom.spdx.json`](docs/sbom.spdx.json) is an SPDX 2.3 inventory of everything a release installs,
generated offline from `requirements.lock` by `scripts/sbom.py` and carrying the per-artifact SHA-256 hashes
the lock pins. It is reproducible: the same lock gives byte-identical output, with no timestamp and no UUID, so
a stale document is a diff rather than a judgement call. A test fails when it drifts, and the release attaches
it beside the wheel.

## Supported versions

| What | Supported |
| --- | --- |
| Releases | The latest minor receives fixes. Older minors receive nothing. |
| Python | See `requires-python` in `pyproject.toml`. |
| Kubernetes | Rules are checked through the version recorded as `CHECKED_THROUGH` in `src/kube_noob/catalog.py`. Past that, the audit says so in its output rather than guessing. |
| OpenShift | The versions exercised in the CI matrix. |

The knowledge ceiling is a first-class output, not a disclaimer: ask for a version beyond it and the report states
that the version was not checked.

## Response expectations

Security reports follow [SECURITY.md](SECURITY.md): acknowledgement within 3 business days, a fix or mitigation plan
within 30 days for confirmed issues.

Everything else is best effort, and that phrase is meant literally. A bug report with a reproduction is far more
likely to be fixed quickly than one without. There is no triage rotation.

## Succession

If you are reading this because the project looks unmaintained, here is what a successor needs. The list is kept
current because an undocumented dependency is the thing that actually kills a handover.

| Asset | Where it lives | Needed to |
| --- | --- | --- |
| Source | GitHub repository | Fork and continue |
| PyPI package | `kube-noob` on PyPI | Publish wheels |
| Homebrew tap | `Formula/kube-noob.rb` in this repository | Publish brew installs |
| Container images | GHCR | Publish images |
| Release attestations | GitHub artifact attestations, keyed to the publishing account | Verify provenance |
| Documentation site | The site repository | Publish docs |

A fork can replace every one of these except the existing attestation history, which stays keyed to the account that
produced it. Nothing in the tool phones home or requires any of them at runtime.

To offer to co-maintain, open an issue. The bar is a track record of merged changes in this repository, not an
introduction.

## If maintenance stops

Signals that it has, in rough order of reliability: no release in six months while Kubernetes has shipped a minor;
security reports unacknowledged past the window in SECURITY.md; CI red on the default branch for weeks.

In that case: pin the last release, keep using the generated admission policies (they need nothing from this project),
and fork. The rule set is the valuable part and it is yours under Apache-2.0.
