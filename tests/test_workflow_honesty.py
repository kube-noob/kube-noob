"""A job that cannot do its work must not report success.

Three times in one release cycle a green check meant nothing: the chart's Route passed both probes while every MCP
call answered 421; `kube-noob doctor` printed `posture: OK` with no SDK and no key; and the `site` job of a release
printed SUCCESS while doing nothing at all, because `SITE_DISPATCH_TOKEN` was unset -- it warned and `exit 0`. The
site then served the previous release's media under the new release's banner for a day, and nobody saw a red check.

A missing secret is a real failure of the thing the job exists to do. It belongs in the part of the run a person
looks at, which is the conclusion, not a warning annotation nobody opens.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# A step that bails out because a secret or a variable is absent. The two shapes used in this repository.
# The first version of this only matched `if [ -z "${X_TOKEN}" ]; then` exactly, which let 13 of 14 shapes past --
# including `"$X_TOKEN"` without braces, a form already in jira-db-image.yml. Match the shapes a person writes.
_MISSING_SECRET = re.compile(
    r"""(?:if|elif)\s+\[\[?\s+-z\s+"?\$\{?(?P<var>[A-Z][A-Z0-9_]*(?:TOKEN|PASSPHRASE|KEY|SECRET|PASSWORD|PAT))"""
    r"""(?::-[^}]*)?\}?"?\s+\]\]?|test\s+-z\s+"?\$\{?(?P<var2>[A-Z][A-Z0-9_]*(?:TOKEN|PASSPHRASE|KEY|SECRET|PASSWORD|PAT))(?::-[^}]*)?\}?"?"""
)


def test_no_job_exits_zero_because_a_secret_it_needs_is_missing() -> None:
    """`exit 0` there is the lie. Either the job does its work, or the run is red and says what to add."""
    offenders: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            m = _MISSING_SECRET.search(line)
            if not m:
                continue
            var = m["var"] or m["var2"]
            # Read the guard's own line too (a one-liner puts the exit there) and stop at its `fi`, so the window
            # cannot bleed into the next step. Any non-zero exit, or `false`, means the job does not lie.
            body = [line[m.end() :]]
            for follow in lines[n + 1 :]:
                if re.match(r"\s*fi\b", follow):
                    break
                body.append(follow)
            verdict = None
            for follow in body:
                if re.search(r"\bexit\s+[1-9]|^\s*false\b|\bthen\s+false\b", follow):
                    verdict = "fails"
                    break
                # A guard may exit 0 when the run still does the work another way, and it has to say which way:
                # `# honest-skip: <what happens instead>` in the branch. Stating it is the point.
                if re.search(r"#\s*honest-skip:", follow):
                    verdict = "declared"
                    break
                if re.search(r"\bexit\s+0\b", follow):
                    verdict = "lies"
                    break
            if verdict == "lies":
                offenders.append(f"{path.name}:{n + 1}: no {var} -> exit 0")
    assert offenders == [], (
        "these jobs report success while skipping the work they exist to do, so nobody learns the secret is "
        f"missing: {offenders}"
    )


def test_the_drift_check_does_not_call_a_site_that_is_ahead_a_failure() -> None:
    """Equality alone called a site serving a NEWER ref than the latest release a failed deploy, which is how
    `site-sync` went red on 2026-11-01 while nothing was wrong, and how a site deliberately built from a branch
    would be reported as broken.
    """
    text = (WORKFLOWS / "site-sync.yml").read_text(encoding="utf-8")
    assert "sort -V" in text, "the drift check compares versions by string equality, so 'ahead' reads as 'behind'"
    assert "non-release ref" in text, "a site built from a branch must be a notice, not a failure"


def test_the_drift_check_still_alarms_while_the_site_is_built_from_a_branch() -> None:
    """The first rewrite traded a false alarm for no alarm. Treating any non-release ref as a notice meant that
    while kube-noob.com served `main` -- which it does, and which is the only way to publish a correction before
    the next tag -- a release whose deploy never ran would never be reported. That is the one thing the job is
    for. The branch case now compares the version the build recorded, and falls through to the age check when it
    is behind.
    """
    text = (WORKFLOWS / "site-sync.yml").read_text(encoding="utf-8")
    branch_case = text.split("*)", 1)[1].split("esac", 1)[0]
    assert "jq -r '.product" in branch_case, (
        "the non-release branch ignores build.json's product version, so it cannot tell a deliberate branch build "
        "from a deploy that never ran"
    )
    assert "sort -V" in branch_case, "the branch case does not compare versions"
    # It must not short-circuit unconditionally: an exit 0 has to sit inside the at-or-past test.
    stripped = "\n".join(ln for ln in branch_case.splitlines() if not ln.strip().startswith("#"))
    tail = stripped.rsplit("fi", 1)[-1]
    assert "exit 0" not in tail, (
        "the branch case exits 0 after its version test, so a site behind the latest release is still passed"
    )


def test_the_secret_that_gates_an_hour_of_work_is_checked_before_the_hour() -> None:
    """corpus-refresh failed on a missing CORPUS_PASSPHRASE only at its last step, after a paced Jira fetch of up
    to 3000 requests a second apart. A check whose answer is known at the start belongs at the start.
    """
    import yaml

    doc = yaml.safe_load((WORKFLOWS / "corpus-refresh.yml").read_text(encoding="utf-8"))
    steps = [s for job in doc["jobs"].values() for s in job.get("steps", [])]
    names = [str(s.get("name", "")) for s in steps]
    guards = [
        i
        for i, s in enumerate(steps)
        if "CORPUS_PASSPHRASE" in str(s.get("run", "")) and "exit 1" in str(s.get("run", ""))
    ]
    assert guards, "no step fails on a missing CORPUS_PASSPHRASE"
    fetch = next((i for i, n in enumerate(names) if "paced" in n.lower()), None)
    assert fetch is not None, "could not find the paced fetch step; update this test with it"
    assert min(guards) < fetch, (
        f"the first passphrase check is step {min(guards)} ({names[min(guards)]!r}) and the paced fetch is step "
        f"{fetch}; the run spends the hour before finding out it cannot keep the result"
    )


def test_every_piped_step_sets_pipefail() -> None:
    """`cmd | tee file` reports `tee`'s exit status, not `cmd`'s.

    GitHub runs a `run:` block with `bash -e {0}` and no `pipefail`, so a step that pipes its real work into `tee`
    to keep a copy of the JSON cannot fail when that work fails. Eight such steps existed across the two corpus
    workflows, including the one that packs the database bundle that is published to users.

    The exception is a step that pipes deliberately in order to inspect the output afterwards and asserts on it
    itself; those are listed, with the assertion that follows them.
    """
    # path -> the line of a deliberate pipe whose own check follows it
    allowed = {
        # applies a manifest expecting it to be denied, then greps the captured output for the denial
        ("ci.yml", "kubectl apply -f /tmp/priv.yaml 2>&1 | tee /tmp/applied.out"),
    }
    offenders: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        lines = path.read_text().split("\n")
        for i, line in enumerate(lines):
            if "| tee " not in line and "| tee\t" not in line:
                continue
            if (path.name, line.strip()) in allowed:
                continue
            # `set -o pipefail` has to be in the same run block, which starts at the nearest `run:`
            start = next((j for j in range(i, -1, -1) if re.search(r"^\s*(?:run|-\s*run):", lines[j])), 0)
            block = "\n".join(lines[start : i + 1])
            if "pipefail" not in block:
                offenders.append(f"{path.name}:{i + 1}: {line.strip()[:80]}")
    assert not offenders, "piped step whose exit status is tee's, not the command's:\n" + "\n".join(offenders)


def test_the_weekly_risk_review_closes_the_week_it_supersedes() -> None:
    """One issue per week, opened and never closed, turns the open-issue list into a calendar.

    `risk-review.yml` searches for an open issue whose title matches *this* week and edits it, else creates one. It
    never touches last week's. So 2026-W44 ("no action needed this week") sat open from 27 October while W45
    superseded it, and by December there would be six open issues all saying nothing is wrong -- with any week
    that did need attention buried among them. An open issue is a claim that something wants doing; a report that
    has been replaced is not making that claim any more.

    This is the same failure as the rest of this file: the information was there, and the thing a human reads was
    not updated to reflect it.
    """
    import yaml

    doc = yaml.safe_load((WORKFLOWS / "risk-review.yml").read_text(encoding="utf-8"))
    steps = [s for job in doc["jobs"].values() for s in job.get("steps", [])]
    runs = [str(s.get("run", "")) for s in steps]
    opener = next((r for r in runs if "gh issue create" in r), None)
    assert opener is not None, "no step opens the weekly issue; update this test with the new one"
    assert "gh issue close" in opener, (
        "the step that opens this week's risk review must close the ones it supersedes, or the open-issue list "
        "grows one stale 'no action needed' report per week"
    )
    # Closing must be scoped to superseded reviews, never to this week's own issue or to unrelated work.
    assert "risk-review" in opener, "the close has to be scoped by the risk-review label"


# A variable holding a bundle of flags -- `reg="--set a=1 --set b=2"` -- is meant to be used UNQUOTED, so the shell
# splits it into separate arguments. Quoted, it becomes ONE argument, and helm reports `unknown flag: --set a=1`.
# That is how the registry-allowlist guard (G243) failed from the day it was written: `"$reg"` instead of `$reg`.
_FLAG_BUNDLE = re.compile(r'^\s*(?P<name>[a-z_][a-z0-9_]*)=(?P<q>["\'])(?P<val>--[^"\']*\s[^"\']*)\2\s*$')


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations, so a `for x in ... \\` list is one line and can be recognised as a list."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        buf += raw[:-1] + " " if raw.rstrip().endswith("\\") else raw
        if not raw.rstrip().endswith("\\"):
            out.append(buf)
            buf = ""
    if buf:
        out.append(buf)
    return out


def test_no_bundle_of_flags_is_passed_to_a_command_as_a_single_argument() -> None:
    """`"$reg"` is one argv element; `$reg` is several. helm rejects the first with `unknown flag`.

    Quoting it inside a `for args in "$a" "$b"` list is correct -- each element is split later by `cmd $args` -- so
    only a quoted use in a command's own arguments is the defect. Found after `ci/helm-and-dogfood` spent a day red
    on a guard that could never have passed.
    """
    bad: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text()
        bundles = {m.group("name") for line in text.splitlines() if (m := _FLAG_BUNDLE.match(line))}
        if not bundles:
            continue
        quoted = re.compile(r'"\$\{?(' + "|".join(sorted(bundles)) + r')\}?"')
        for line in _logical_lines(text):
            if re.match(r"\s*(for|while)\s+\w+\s+in\s", line):
                continue
            for hit in quoted.finditer(line):
                bad.append(f"{path.name}: {hit.group(0)} in {line.strip()[:110]}")
    assert not bad, "a flag bundle quoted into one argument:\n" + "\n".join(bad)


# The pinned PyPI publish action runs `twine check dist/*` and then `exec twine upload dist/*` over the WHOLE
# directory. twine 7.0.0 rejects anything that is not a Python distribution -- sbom.spdx.json with "Unknown
# distribution format", the krew archive with "No PKG-INFO in archive" -- and aborts before opening a
# connection. From cf08981 to v0.9.0 both sat in dist/, so publish-pypi would have failed on the first run that
# reached it. Nothing caught it: check_publishable.sh is the twin of that check but ran BEFORE those two steps,
# and ci.yml's publishable job builds the dists without ever running them (G265).
_WRITES_INTO_DIST = re.compile(
    r"(?:\b(?:cp|mv|install|tar|cat|touch)\b[^\n]*?\bdist/)|(?:>\s*\"?dist/)|(?:--archive\s+\"?dist/)"
)
# `python -m build` is what creates dist/ in the first place; it is the only writer allowed.
_BUILDS = "python -m build"


def _build_dist_steps() -> list[dict[str, Any]]:
    spec: dict[str, Any] = yaml.safe_load((WORKFLOWS / "release.yml").read_text())
    return list(spec["jobs"]["build-dist"]["steps"])


def test_nothing_but_a_python_distribution_is_written_into_dist() -> None:
    """A release asset that is not a distribution goes in assets/. In dist/ it aborts the upload."""
    offenders: list[str] = []
    for step in _build_dist_steps():
        run = step.get("run") or ""
        if _BUILDS in run:
            continue
        for line in run.splitlines():
            if _WRITES_INTO_DIST.search(line):
                offenders.append(f"{step.get('name') or step.get('id') or 'step'}: {line.strip()[:100]}")
    assert not offenders, (
        "these put a non-distribution file into dist/, which makes `twine upload dist/*` abort:\n"
        + "\n".join(offenders)
    )


def test_the_publishable_check_runs_after_everything_that_touches_dist() -> None:
    """It is the twin of the publish action's own check, so it has to see the directory the action will see."""
    steps = _build_dist_steps()
    check_at = [i for i, s in enumerate(steps) if "check_publishable.sh" in (s.get("run") or "") and not s.get("id")]
    assert check_at, "build-dist no longer runs check_publishable.sh over the dists"
    touches = [
        i
        for i, s in enumerate(steps)
        if "dist/" in (s.get("run") or "") and "check_publishable.sh" not in (s.get("run") or "")
    ]
    assert max(touches) < max(check_at), (
        f"check_publishable.sh runs at step {max(check_at)} but step {max(touches)} still touches dist/ "
        f"({steps[max(touches)].get('name') or 'unnamed'}) -- it would be checking a directory that changes after it"
    )


def test_provenance_is_attempted_twice_and_still_decides_the_job() -> None:
    """v0.9.0 died on Rekor's read-after-write 404 with every artefact already correct. One retry, and the job
    still fails if both attempts do -- `continue-on-error` on the retry would make the attestation optional."""
    steps = _build_dist_steps()
    attests = [s for s in steps if "attest-build-provenance" in str(s.get("uses", ""))]
    assert len(attests) == 2, f"expected a first attempt and one retry, found {len(attests)}"
    first, second = attests
    assert first.get("continue-on-error") is True, "the first attempt must not fail the job on its own"
    assert second.get("continue-on-error") is not True, (
        "the retry must decide the job; otherwise nothing published is guaranteed to be attested"
    )
    assert "steps.attest.outcome == 'failure'" in str(second.get("if")), "the retry must be gated on the first failing"
    for a in attests:
        subjects = str((a.get("with") or {}).get("subject-path"))
        assert "dist/*" in subjects and "assets/*" in subjects, "both directories are released, so both are attested"
