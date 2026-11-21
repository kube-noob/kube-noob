"""The `## Status` section of `docs/roadmap.md` is published verbatim on the website, and nothing here said so.

`kube-noob-site`'s `generate.py` has `roadmap_status()`, which lifts exactly that section into `/insights/`. The
site then refuses three strings on every page it writes itself -- `kubectl krew`, `krew install`, `krew-index` --
because the index pull request is not open, so `kubectl krew install noob` does not work and no page may offer it.

A row naming that command was moved into `## Status` in this repository. The site's own test caught it a week
later, in a session sourced at the other repository, with the product commit long since merged. Nothing in this
repository could have caught it, which is the defect: the guard lived where the content is PUBLISHED and not where
it is WRITTEN.

So it lives here too. This is a copy of another repository's assertion, which is a second source of truth and
normally the thing to avoid (review class 9) -- the reason it is right here is that the two cannot be merged: the
string is authored in this repository and rendered in that one, and a check in only one place is a check that
fires after the fact.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: Verbatim from `kube-noob-site` `tests/test_site.py`, in
#: `test_the_install_commands_are_the_ones_in_the_products_install_page`. If that list changes, this one has to.
REFUSED_BY_THE_SITE = ("kubectl krew", "krew install", "krew-index")


def _status_section() -> str:
    """What `roadmap_status()` in the site's `generate.py` extracts, by the same expression."""
    text = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    match = re.search(r"^## Status\n(.*?)(?=^## )", text, re.MULTILINE | re.DOTALL)
    assert match, "docs/roadmap.md has no `## Status` section; the site's roadmap_status() would publish nothing"
    return match.group(1)


@pytest.mark.parametrize("claim", REFUSED_BY_THE_SITE)
def test_the_published_status_section_offers_no_install_the_site_refuses(claim: str) -> None:
    """The regression, and it is one-directional: this section may say the submission is waiting, and may not
    print the command that submission would enable."""
    assert claim.lower() not in _status_section().lower(), (
        f"docs/roadmap.md `## Status` contains {claim!r}. The site publishes that section verbatim at /insights/ "
        "and refuses that string on every page it writes, because the plugin index pull request is not open. Say "
        "what is waiting without naming the command."
    )


def test_the_rest_of_the_roadmap_may_still_discuss_it() -> None:
    """The limit. Only the published section is constrained: the roadmap's own detail rows exist to record exactly
    this kind of owner-only work, and emptying them to satisfy a website would be the tail wagging the dog."""
    whole = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    assert "krew" in whole.lower(), "the roadmap stopped recording the plugin index work altogether"


def test_the_section_the_site_lifts_is_still_there_and_not_empty() -> None:
    """If this ever fails, `roadmap_status()` publishes an empty block and the /insights/ page loses a section
    without the site noticing: an absence that reads as nothing-to-report."""
    section = _status_section()
    assert section.strip(), "the `## Status` section is empty"
    assert "|" in section, "the `## Status` section is no longer a table; check the site still renders it"
