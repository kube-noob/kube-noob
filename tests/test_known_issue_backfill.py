"""G317: the bundled reported-issue index reaches down to OpenShift 4.14, and says per release what it reaches.

The index held 4.20-4.22, so `known-issues`, `operators issues` and the gate answered "not determined" for every
cluster on a release people actually run. That answer was correct -- the index could not say -- and useless.

The back-fill is data, not mechanism, so what this file holds is the honesty of the statement around it: a
release inside the range answers `determined`, one outside still answers `not-determined` with its reason, and
the coverage statement says **per release** how far that release's notes were read and on what day they were
read. One global "as of" over nine releases would claim a freshness the older ones may not have, and one global
"indexed through" would hide that 4.14's notes reach a different update from 4.22's -- a match tier that does not
say what it did not match (docs/review-classes.md class 15).
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from kube_noob import known_issues as ki
from kube_noob.sources import release_notes as rn

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "kube_noob" / "data" / "known_issues"
BACKFILLED = ("4.14", "4.15", "4.16", "4.17", "4.18", "4.19")
#: The Claude plugin directory reads files up to 256 KiB; the bundled index ships inside the plugin.
PLUGIN_FILE_LIMIT = 256 * 1024


def _knowledge() -> dict[str, object]:
    return ki.get_index().knowledge()


# -- the data ------------------------------------------------------------------------------------------------


def test_every_release_from_4_14_to_4_22_is_in_the_index() -> None:
    assert _knowledge()["openshiftReleases"] == [f"4.{y}" for y in range(14, 23)]


def test_every_back_filled_release_has_both_known_and_fixed_issues() -> None:
    """A release with fixed issues and no known ones would answer "nothing is open" from an unread section, which
    is how the first run of this back-fill read the 4.14-4.19 notes: their known issues are in a different file
    from the one 4.20 and later use, so there were none at all."""
    kinds: dict[str, set[str]] = {}
    for issue in ki.get_index().issues:
        kinds.setdefault(issue.minor, set()).add(issue.kind)
    for minor in BACKFILLED:
        assert kinds.get(minor) == {"known", "fixed"}, (minor, kinds.get(minor))


def test_an_issue_open_at_x_0_and_fixed_in_a_later_update_carries_that_fix() -> None:
    """A release's notes legitimately list an issue as known at ``x.y.0`` and as fixed in a later update of the
    same release. What must not happen is the known record staying open-looking: ``link_fixes`` gives it the
    earliest release that lists it fixed, so nothing reads as still open after its own fix."""
    known = {(i.minor, i.id): i for i in ki.get_index().issues if i.kind == "known"}
    fixed = {(i.minor, i.id) for i in ki.get_index().issues if i.kind == "fixed"}
    overlap = sorted(set(known) & fixed)
    assert overlap, "the notes do list some issue as known and later fixed within one release"
    for key in overlap:
        assert known[key].fixed_in, key


def test_a_books_known_issues_do_not_swallow_the_updates_fixed_issues() -> None:
    """Reading a 4.14-4.19 book's last-of-its-level "Known issues" heading to the end of the file turned every
    update's fixed-issue bullet into a known issue of that release -- hundreds of bugs reported as still open
    after they were fixed. Each back-filled release now reports far fewer known issues than fixed ones, which is
    what a release's notes actually look like."""
    counts: dict[str, dict[str, int]] = {}
    for issue in ki.get_index().issues:
        counts.setdefault(issue.minor, {"known": 0, "fixed": 0})[issue.kind] += 1
    for minor in BACKFILLED:
        assert counts[minor]["known"] < counts[minor]["fixed"], (minor, counts[minor])
        assert counts[minor]["known"] < 120, (minor, counts[minor])


def test_every_record_cites_a_release_notes_file_and_a_commit() -> None:
    for issue in ki.get_index().issues:
        assert re.fullmatch(
            r"https://github\.com/openshift/openshift-docs/blob/[0-9a-f]{40}/"
            r"(modules|release_notes)/[A-Za-z0-9_./-]+\.adoc",
            issue.source,
        ), issue.source


def test_the_generated_files_name_the_url_and_the_retrieval_date_of_every_release() -> None:
    for f in sorted(DATA.glob("*.json")):
        meta = json.loads(f.read_text(encoding="utf-8"))
        assert sorted(meta["minors"]) == [f"4.{y}" for y in range(14, 23)], f.name
        for minor, where in meta["minors"].items():
            assert where["branch"] == f"enterprise-{minor}"
            assert re.fullmatch(r"[0-9a-f]{40}", where["commit"]), (f.name, minor)
            assert where["url"] == f"https://github.com/openshift/openshift-docs/tree/{where['commit']}"
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", where["retrievedAt"]), (f.name, minor)


def test_every_bundled_part_stays_inside_the_plugin_file_limit() -> None:
    files = sorted(DATA.glob("*.json"))
    assert len(files) > 7, "the back-fill splits the index into more parts, as the generator already does"
    for f in files:
        assert len(f.read_bytes()) < PLUGIN_FILE_LIMIT, (f.name, len(f.read_bytes()))


# -- the statement -------------------------------------------------------------------------------------------


def test_the_coverage_statement_says_per_release_what_was_indexed_and_as_of_when() -> None:
    indexed = ki.coverage("4.16.20")["indexed"]
    assert [row["minor"] for row in indexed] == [f"4.{y}" for y in range(14, 23)]
    for row in indexed:
        assert row["indexedThrough"].startswith(row["minor"] + ".")
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["asOf"])
        assert row["source"].startswith("https://github.com/openshift/openshift-docs/tree/")


def test_the_per_release_statement_is_in_the_knowledge_block_every_consumer_returns() -> None:
    detail = _knowledge()["openshiftReleaseDetail"]
    assert isinstance(detail, list)
    assert [row["minor"] for row in detail] == list(_knowledge()["openshiftReleases"])


@pytest.mark.parametrize("version", [f"4.{y}.3" for y in range(14, 23)])
def test_a_release_inside_the_index_is_determined(version: str) -> None:
    cov = ki.coverage(version)
    assert cov["status"] == "determined", cov
    minor = version.rsplit(".", 1)[0]
    # The sentence quotes this release's own reach and date, not the index's widest ones.
    through = next(r for r in cov["indexed"] if r["minor"] == minor)
    assert through["indexedThrough"] in cov["why"] and through["asOf"] in cov["why"]


@pytest.mark.parametrize("version", ["4.13.20", "4.12.0", "4.9.55"])
def test_a_release_below_the_index_is_still_not_determined_with_its_reason(version: str) -> None:
    cov = ki.coverage(version)
    assert cov["status"] == "not-determined"
    assert "NOT DETERMINED" in cov["why"] and "is not one of them" in cov["why"]
    assert "4.14" in cov["why"], cov["why"]


def test_a_release_above_the_index_is_still_not_determined() -> None:
    cov = ki.coverage("4.23.1")
    assert cov["status"] == "not-determined" and "4.23" in cov["why"]


def test_a_z_stream_newer_than_its_own_release_was_read_to_is_not_determined() -> None:
    """Per release, not per index: 4.14's notes reach a different update from 4.22's, and the refusal has to use
    the right one or a 4.14 cluster is told it is covered by 4.22's reach."""
    through = {row["minor"]: row["indexedThrough"] for row in ki.coverage(None)["indexed"]}
    for minor, reach in through.items():
        z = int(reach.rsplit(".", 1)[1])
        cov = ki.coverage(f"{minor}.{z + 1}")
        assert cov["status"] == "not-determined", (minor, cov)
        assert cov["indexedThrough"] == reach
        assert ki.coverage(f"{minor}.{z}")["status"] == "determined", minor


def test_the_text_view_carries_the_per_release_statement() -> None:
    cov = ki.coverage("4.15.2")
    line = ki.coverage_line(cov)
    assert line is None, "a covered release has nothing to warn about"
    outside = ki.coverage("4.13.1")
    assert ki.coverage_line(outside) == outside["why"]
    assert "4.14" in outside["why"] and "4.22" in outside["why"]


# -- what the gate's verdict will read ------------------------------------------------------------------------


def test_the_coverage_status_is_one_of_the_three_words_the_gate_verdict_reads() -> None:
    """``gate``'s ``knownIssuesVerdict`` (G284, on another branch) reads this status. The back-fill must not add a
    fourth value or rename one, so the widened index needs no change there when it lands."""
    seen = {ki.coverage(v)["status"] for v in [None, "latest", "4.13.1", "4.16.3", "4.23.9", "4.16.999"]}
    assert seen <= {"determined", "not-determined", "not-narrowed"}
    assert seen == {"determined", "not-determined", "not-narrowed"}


# -- the parser the generator uses ----------------------------------------------------------------------------


def test_the_known_issues_body_of_a_book_stops_at_the_errata_part() -> None:
    book = (
        "= Release notes\n\n== Known issues\n\n"
        "* A real known issue (link:https://issues.redhat.com/browse/OCPBUGS-1[OCPBUGS-1])\n\n"
        "include::modules/rn-async-errata.adoc[leveloffset=+1]\n\n"
        "include::modules/zstream-4-14-78.adoc[leveloffset=+2]\n\n"
        "* A fixed issue that is not open (link:https://issues.redhat.com/browse/OCPBUGS-2[OCPBUGS-2])\n"
    )
    body = rn.known_issues_body(book)
    assert "OCPBUGS-1" in body and "OCPBUGS-2" not in body


def test_an_inline_update_is_read_with_its_own_version_and_date() -> None:
    book = (
        '= Release notes\n\n[id="ocp-4-14-58_{context}"]\n'
        "=== RHBA-2025:1 - 4.14.58 bug fix advisory\n\nIssued: 05 November 2025\n\n"
        '[id="ocp-4-14-58-bug-fixes_{context}"]\n==== Bug fixes\n\n'
        "* Before this update something was wrong, and with this release it is fixed. "
        "(link:https://issues.redhat.com/browse/OCPBUGS-3[OCPBUGS-3])\n\n"
        '[id="ocp-4-14-57_{context}"]\n=== RHBA-2025:2 - 4.14.57 bug fix advisory\n\nIssued: 29 October 2025\n'
    )
    got = rn.inline_updates(book, "4.14")
    assert [v for v, _ in got] == ["4.14.58", "4.14.57"]
    assert "OCPBUGS-3" in got[0][1] and "4.14.57" not in got[0][1]


def test_an_update_of_another_release_is_not_read_as_this_one() -> None:
    book = '= Release notes\n\n[id="ocp-4-15-58_{context}"]\n=== 4.15.58\n'
    assert rn.inline_updates(book, "4.14") == []


def test_a_split_update_is_read_and_takes_its_date_from_its_about_file(tmp_path: Path) -> None:
    """``zstream-4-19-19-bug-fixes.adoc`` beside ``-about.adoc`` and ``-updating.adoc``. Matching only
    ``zstream-4-19-19.adoc`` skipped every split update of 4.14, 4.15, 4.18 and 4.19."""
    mods = tmp_path / "modules"
    mods.mkdir()
    (mods / "zstream-4-19-19-about.adoc").write_text("= 4.19.19\n\nIssued: 12 November 2025\n", encoding="utf-8")
    (mods / "zstream-4-19-19-bug-fixes.adoc").write_text(
        "== Bug fixes\n\n* Before this update it broke; with this release it is fixed. "
        "(link:https://issues.redhat.com/browse/OCPBUGS-4[OCPBUGS-4])\n",
        encoding="utf-8",
    )
    recs = rn.parse_release(rn.Release("4.19", tmp_path, "0" * 40))
    assert [(r["id"], r["version"], r["issued"]) for r in recs] == [("OCPBUGS-4", "4.19.19", "2025-11-12")]


def test_a_credential_shaped_variable_name_in_a_quoted_command_is_replaced_not_dropped() -> None:
    """The 4.14 and 4.15 notes quote ``-H "Authorization: Bearer $API_TOKEN"`` in an Assisted Installer issue.

    The Claude plugin bundles this index, and a credential variable name anywhere in the plugin copy is refused
    (``tests/test_plugin.py::test_bundle_names_no_credential_variables``) because a reviewer scanning the bundle
    cannot tell a vendor's placeholder from a variable kube-noob reads. Only the NAME is replaced: the issue, its
    id and its cited source stay, so the back-fill neither drops the record nor smuggles the name through.
    """
    names = re.compile(r"\b[A-Z][A-Z0-9_]*_(?:TOKEN|API_KEY|SECRET_ACCESS_KEY|ACCESS_KEY_ID)\b")
    for issue in ki.get_index().issues:
        assert not names.search(issue.text), (issue.id, issue.source)
    substituted = [i for i in ki.get_index().issues if "CREDENTIAL_VARIABLE" in i.text]
    assert substituted, "the notes do quote such a command, so the substitution must be visible"
    for issue in substituted:
        assert "Bearer $CREDENTIAL_VARIABLE" in issue.text
        assert issue.source.endswith(".adoc")


def test_the_redaction_leaves_ordinary_text_alone() -> None:
    assert rn._CREDENTIAL_VAR.sub("CREDENTIAL_VARIABLE", "the TOKEN_BUCKET and api_token are untouched") == (
        "the TOKEN_BUCKET and api_token are untouched"
    )
    assert rn._CREDENTIAL_VAR.sub("CREDENTIAL_VARIABLE", 'Bearer $JIRA_API_TOKEN"') == 'Bearer $CREDENTIAL_VARIABLE"'


def test_the_known_issues_command_prints_the_per_release_reach() -> None:
    """The text view of the index, not only the JSON: the caveat that exists in one format only is class 6."""
    import io
    from contextlib import redirect_stdout

    from kube_noob.cli import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["known-issues", "etcd leader changed", "--version", "4.16.3"]) == 0
    out = buf.getvalue()
    for row in ki.get_index().release_detail():
        assert f"OpenShift {row['minor']} read to {row['indexedThrough']} as of {row['asOf']}" in out


def _vendor_script() -> Any:
    spec = importlib.util.spec_from_file_location("kn_vendor_backfill", ROOT / "scripts/vendor_known_issues.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kn_vendor_backfill"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_the_generator_refuses_an_index_whose_release_has_no_known_issues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The defect this back-fill was built out of, caught where the maintainer is standing.

    A generator reading only the `modules/rn-ocp-*` extracts produced an index that answered "nothing is reported
    open" for six releases from a section it never opened: no error, no empty file, just a release whose notes
    report plenty and whose records say otherwise. A CI test catches the regression after the fact; `--check`
    refuses it at the moment of regeneration.
    """
    mod = _vendor_script()
    for f in DATA.glob("*.json"):
        (tmp_path / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(mod, "OUT", tmp_path)
    assert mod.check() == 0
    capsys.readouterr()
    for f in sorted(tmp_path.glob("openshift-4.16-known-*.json")):
        f.unlink()
    assert mod.check() == 1
    out = capsys.readouterr().out
    assert "OpenShift 4.16 has no known issue" in out
    assert "a section was not read" in out
    assert "ocp-<x>-<y>-release-notes.adoc" in out
    assert "an indexed release has no known or no fixed issues" in (mod.__doc__ or "")


def test_the_generator_refuses_a_release_with_no_fixed_issues_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The neighbouring input, not only the reported one (class 21): the other extract can go missing too."""
    mod = _vendor_script()
    for f in DATA.glob("*.json"):
        (tmp_path / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(mod, "OUT", tmp_path)
    for f in sorted(tmp_path.glob("openshift-4.21-fixed-*.json")):
        f.unlink()
    assert mod.check() == 1
    assert "OpenShift 4.21 has no fixed issue" in capsys.readouterr().out
