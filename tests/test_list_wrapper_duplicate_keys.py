"""A duplicate key on a `kind: List` wrapper is KN-V018 on the wrapper itself (G287).

Recorded on this branch; the fix ships with G272 (rules/control-plane owns `yamlio._open_list` and found the same
defect in its review). Every test red today is `xfail(strict=True)`, and the day G272 merges it passes, strict
turns that into a failure, and whoever merges removes the marker so the behaviour is enforced from then on.

`gate -f list.yaml` -- a `kind: List` with `items: []` followed by a second `items:` holding a ConfigMap -- passed
with exit 0 and no KN-V018, while the same duplicate key inside an item fired KN-V018 CRITICAL. `yamlio._flatten_lists`
handed each item its own duplicate-key records and dropped the wrapper's. A YAML parser keeps the last `items`
silently, so the list a reviewer read is not the list that was written, which is exactly what KN-V018 says.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob import gate, yamlio
from kube_noob.audit.engine import analyze
from kube_noob.cli import main

#: Red on main today. The three tests without it already hold and guard the neighbours the fix must not break.
G272 = pytest.mark.xfail(strict=True, reason="fixed on rules/control-plane (G272); enforced when it merges")

ITEM = "- apiVersion: v1\n  kind: ConfigMap\n  metadata: {name: cm, namespace: shop}\n  data: {a: b}\n"
WRAPPER_ITEMS_TWICE = "apiVersion: v1\nkind: List\nitems: []\nitems:\n" + ITEM
WRAPPER_KIND_TWICE = "apiVersion: v1\nkind: List\nkind: List\nitems:\n" + ITEM
WRAPPER_API_TWICE = "apiVersion: v1\napiVersion: v1\nkind: List\nitems:\n" + ITEM
ITEMS_THRICE = "apiVersion: v1\nkind: List\nitems: []\nitems: []\nitems:\n" + ITEM
TYPED_WRAPPER = "apiVersion: v1\nkind: ConfigMapList\nitems: []\nitems:\n" + ITEM
EMPTY_TWICE = "apiVersion: v1\nkind: List\nitems: []\nitems: []\n"
CLEAN = "apiVersion: v1\nkind: List\nitems:\n" + ITEM
DUP_IN_ITEM = "apiVersion: v1\nkind: List\nitems:\n" + ITEM + "  data: {c: d}\n"


def _v018(text: str) -> list:  # type: ignore[type-arg]
    return [f for f in analyze(text, "kubernetes", None, partial_bundle=True).findings if f.rule_id == "KN-V018"]


@G272
def test_a_duplicate_items_key_on_the_wrapper_is_kn_v018_on_the_wrapper() -> None:
    found = _v018(WRAPPER_ITEMS_TWICE)
    assert len(found) == 1
    f = found[0]
    assert f.resource.startswith("List/") and "items" in f.message
    assert f.line == 4, "positioned at the second occurrence"
    assert f.severity.name == "CRITICAL"


@G272
@pytest.mark.parametrize(
    ("text", "key", "line"),
    [(WRAPPER_KIND_TWICE, "kind", 3), (WRAPPER_API_TWICE, "apiVersion", 2)],
)
def test_a_duplicate_kind_or_api_version_on_the_wrapper_is_reported(text: str, key: str, line: int) -> None:
    found = _v018(text)
    assert [(f.line, key in f.message) for f in found] == [(line, True)]


@G272
def test_items_duplicated_three_times_is_two_findings_at_the_second_and_third() -> None:
    assert sorted(f.line for f in _v018(ITEMS_THRICE)) == [4, 5]


def test_a_typed_list_wrapper_is_held_to_the_same_rule() -> None:
    """`ConfigMapList` is a list wrapper too; whether or not it is unwrapped, its own duplicate key is reported."""
    found = _v018(TYPED_WRAPPER)
    assert len(found) >= 1 and all("items" in f.message for f in found)
    assert any(f.line == 4 for f in found)


@G272
def test_a_wrapper_with_no_items_at_all_still_reports_its_duplicate() -> None:
    found = _v018(EMPTY_TWICE)
    assert len(found) == 1 and found[0].line == 4


def test_the_items_are_still_flattened_and_audited_as_before() -> None:
    docs = yamlio.load_documents(WRAPPER_ITEMS_TWICE)
    items = [d for d in docs if d.kind == "ConfigMap"]
    assert len(items) == 1 and items[0].name == "cm"
    # a clean wrapper leaves no trace: the same documents, and nothing fires on it
    clean = yamlio.load_documents(CLEAN)
    assert [d.ref() for d in clean] == ["ConfigMap/shop/cm"]
    assert _v018(CLEAN) == []
    # the report's resources name the objects, not the wrapper, unless the wrapper itself has a finding
    assert analyze(CLEAN, "kubernetes", None, partial_bundle=True).resources == ["ConfigMap/shop/cm"]


def test_a_duplicate_inside_an_item_still_lands_on_the_item() -> None:
    found = _v018(DUP_IN_ITEM)
    assert len(found) == 1 and found[0].resource == "ConfigMap/shop/cm" and found[0].line == 8


@G272
def test_nothing_else_fires_on_the_wrapper() -> None:
    rep = analyze(WRAPPER_ITEMS_TWICE, "kubernetes", None, partial_bundle=True)
    assert {(f.rule_id, f.resource) for f in rep.findings if f.resource != "ConfigMap/shop/cm"} == {
        ("KN-V018", "List/<unnamed>")
    }


@G272
def test_the_gate_fails_on_the_wrapper_duplicate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "list.yaml"
    path.write_text(WRAPPER_ITEMS_TWICE, encoding="utf-8")
    assert main(["--format", "json", "gate", "-f", str(path)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["passed"] is False
    hit = [f for f in out["findings"] if f["ruleId"] == "KN-V018"]
    assert len(hit) == 1 and hit[0]["line"] == 4 and hit[0]["uri"].endswith("list.yaml")
    # and `fix` writes the items, not a wrapper carrying a duplicate
    assert main(["fix", "-f", str(path), "-o", str(tmp_path / "out.yaml")]) == 0
    fixed = (tmp_path / "out.yaml").read_text(encoding="utf-8")
    assert "kind: ConfigMap" in fixed and "kind: List" not in fixed


@G272
def test_gate_source_classification_still_sees_the_items() -> None:
    src = gate.Source("list.yaml", WRAPPER_ITEMS_TWICE)
    rep = gate.run([src], platform="kubernetes")
    assert not rep["passed"] and any(f["ruleId"] == "KN-V018" for f in rep["findings"])
