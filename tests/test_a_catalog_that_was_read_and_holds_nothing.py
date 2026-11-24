"""A KEV catalog that was read and holds nothing is not one that was never given (G381).

`Kev.describe()` asked `if not self.entries` and answered "no KEV catalog given" for both. The two are
different facts: one says nobody supplied a catalog, the other says a catalog was supplied, parsed, and
matched against -- and found nothing because it holds nothing. A reader told the first when the second is
true concludes "add --kev and you would learn more", when the truth is "you did, and it is empty".

The same read hid a second absence: `parse` walked past every entry that is not a mapping or carries no
well-formed CVE id without counting it, and never compared what it read against the `count` the catalog
declares for itself. A catalog declaring 1200 entries of which one parsed described itself as "1 CVEs" --
a number that is the size of what was read standing where the size of the catalog should stand.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kube_noob.vuln import kev

RELEASED = "2026-11-01T00:00:00Z"


def catalog(entries: list[Any], count: int | None = None, version: str = "2026.11.01") -> str:
    doc: dict[str, Any] = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": version,
        "dateReleased": RELEASED,
        "vulnerabilities": entries,
    }
    if count is not None:
        doc["count"] = count
    return json.dumps(doc)


def entry(cve: str) -> dict[str, str]:
    return {
        "cveID": cve,
        "vendorProject": "v",
        "product": "p",
        "vulnerabilityName": "n",
        "dateAdded": "2026-01-01",
        "shortDescription": "s",
        "requiredAction": "a",
        "dueDate": "2026-02-01",
        "knownRansomwareCampaignUse": "Unknown",
    }


def test_a_catalog_nobody_gave_says_so() -> None:
    """The hand-built default is the only thing that may claim no catalog was given."""
    k = kev.Kev()
    assert k.given is False
    assert k.describe() == "no KEV catalog given"


def test_a_catalog_that_was_read_and_holds_nothing_does_not_claim_it_was_never_given() -> None:
    """The defect: an empty-but-present catalog described itself as absent."""
    k = kev.parse(catalog([], count=0))
    assert k.given is True
    assert k.entries == {}
    said = k.describe()
    assert "no KEV catalog given" not in said
    assert "2026.11.01" in said and "2026-11-01" in said
    assert "holds no entries" in said


def test_a_catalog_with_entries_names_its_version_date_and_size() -> None:
    k = kev.parse(catalog([entry("CVE-2026-0001"), entry("CVE-2026-0002")], count=2))
    assert k.describe() == "CISA KEV 2026.11.01 (2026-11-01), 2 CVEs"
    assert k.shortfall() == 0


def test_a_catalog_that_declares_more_than_was_read_says_how_many_were_not() -> None:
    """1 of 1200 read described itself as `1 CVEs`: the size of the read standing for the size of the catalog."""
    k = kev.parse(catalog([entry("CVE-2026-0001"), {"cveID": "not-a-cve"}, 99], count=1200))
    assert len(k.entries) == 1
    assert k.declared_count == 1200
    assert k.skipped == 2
    assert k.shortfall() == 1199
    said = k.describe()
    assert "1200" in said
    assert "2 row(s) were not read" in said


@pytest.mark.parametrize("bad", [{"cveID": "CVE-bogus"}, {"cveID": ""}, {"nope": 1}, 42, "x", None, []])
def test_every_entry_that_cannot_match_is_counted_not_dropped(bad: Any) -> None:
    """An entry nothing can match is an absence; dropping it silently makes the catalog look whole."""
    k = kev.parse(catalog([entry("CVE-2026-0001"), bad], count=2))
    assert len(k.entries) == 1
    assert k.skipped == 1
    assert "1 row(s) were not read" in k.describe()


def test_a_catalog_that_declares_no_count_claims_no_shortfall() -> None:
    """Absent `count` is not a declared zero: the catalog said nothing, so nothing is owed."""
    k = kev.parse(catalog([entry("CVE-2026-0001")]))
    assert k.declared_count is None
    assert k.shortfall() == 0
    assert k.describe() == "CISA KEV 2026.11.01 (2026-11-01), 1 CVEs"


@pytest.mark.parametrize("bogus", [-1, True, False, "1200", 1.5, None, kev.MAX_ENTRIES + 1])
def test_a_count_that_is_not_a_plausible_integer_is_not_believed(bogus: Any) -> None:
    """A declared count is input; a hostile or malformed one must not become kube-noob's own arithmetic."""
    k = kev.parse(catalog([entry("CVE-2026-0001")], count=bogus))
    assert k.declared_count is None
    assert k.shortfall() == 0


def test_a_declared_count_below_what_was_read_never_reports_a_negative_shortfall() -> None:
    k = kev.parse(catalog([entry("CVE-2026-0001"), entry("CVE-2026-0002")], count=1))
    assert k.shortfall() == 0
    assert "were not read" not in k.describe()


def test_lookup_is_unchanged_by_any_of_this() -> None:
    """The negative control: a well-formed catalog answers exactly as it did before."""
    k = kev.parse(catalog([entry("CVE-2026-0001")], count=1))
    assert k.get("CVE-2026-0001") is not None
    assert k.get("cve-2026-0001") is not None
    assert k.get("CVE-2026-9999") is None
