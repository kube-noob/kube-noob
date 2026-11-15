"""Neighbour variants for the false-pass benchmark (G311): every enforced case's input is also run as its
mechanical neighbours, and a neighbour that answers more kindly than its parent fails the suite.

``docs/review-classes.md`` class 21 -- "fixing the reported shape, not its neighbours" -- is the class that file
itself says closes most review rounds: the fix covered the exact input in the report, and the other wrapper, the
other type, the other order still failed. Every case in ``tests/falsepass/cases`` is a shape that once read as a
pass. ``tests/falsepass/variants.py`` derives each case's neighbours from one table of transformations drawn from
what the reviews actually found, and holds the tool to one law:

    A variant may be as conservative as its parent, or more -- never less.

That law is checkable without knowing the right answer for a generated input, which is what makes it cheap: the
parent's verdict is already known to be honest (it is an enforced case), so a neighbour that shows the parent's
forbidden shape, exits 0 where the parent did not, or scores higher than the parent is a defect whatever the
honest answer for that neighbour would have been. A neighbour that declines more firmly is fine.

Every transformation preserves the deciding evidence somewhere in the input (``test_every_transformation_keeps_the
_deciding_evidence_in_the_input``). Without that invariant the law would be unsound: a transformation that deleted
the privileged container would make a clean verdict correct, and the law would read it as a defect.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest
import yaml

from tests.falsepass import harness as fp
from tests.falsepass import variants as fpv

ROOT = Path(__file__).resolve().parents[1]
CASES = fp.load_cases()
ENFORCED = [c for c in CASES if c.enforced]
DERIVATIONS = [fpv.derive(c) for c in ENFORCED]
WITH_VARIANTS = [d for d in DERIVATIONS if d.variants]

#: ``FALSEPASS_VARIANTS=all`` runs the whole matrix instead of the capped six per case. The cap is CI's budget
#: (``variants.CAP_REASON``); the whole matrix is the owner-run pass, and it is the same derivation uncapped, so
#: nothing but the number of variants differs.
LAW_CAP = None if os.environ.get("FALSEPASS_VARIANTS") == "all" else fpv.MAX_VARIANTS_PER_CASE
LAW = [d for d in (fpv.derive(c, cap=LAW_CAP) for c in ENFORCED) if d.variants]

#: The neighbours the corpus already holds a case for. The law does not judge one whose case is still waiting:
#: the case IS the record, the benchmark runs it, and failing here as well would fail the suite for a defect that
#: is filed and owned. The day that case's probe holds it stops waiting and the law judges the neighbour again.
LEDGER = fpv.filed(CASES)


# -- the table is one table ----------------------------------------------------------------------------------------


def test_the_transformations_are_one_table_with_a_unique_name_and_a_reason_each() -> None:
    names = [t.name for t in fpv.TRANSFORMS]
    assert len(names) == len(set(names)), names
    assert len(names) >= 20, "the table is the whole point; a handful of transformations is not the class-21 set"
    for t in fpv.TRANSFORMS:
        assert t.name == t.name.lower().strip() and " " not in t.name, t.name
        assert t.why.endswith("."), f"{t.name}: the reason is a sentence and it reaches the generated page"
        assert len(t.why) > 30, t.name


def test_no_other_module_names_a_transformation_so_the_table_stays_the_one_place() -> None:
    """A transformation named in a second file is class 9 (a second source of truth): the next author edits one."""
    elsewhere: list[str] = []
    for path in sorted(ROOT.glob("**/*.py")):
        if "/.venv/" in str(path) or path.name == "variants.py" or path == Path(__file__):
            continue
        text = path.read_text("utf-8", errors="replace")
        for t in fpv.TRANSFORMS:
            if f'"{t.name}"' in text or f"'{t.name}'" in text:
                elsewhere.append(f"{path.relative_to(ROOT)}: {t.name}")
    assert elsewhere == [], elsewhere


def test_every_variant_names_its_transformation_in_its_provenance() -> None:
    for derivation in WITH_VARIANTS:
        for variant in derivation.variants:
            assert variant.transform in variant.provenance
            assert variant.case.id in variant.provenance
            assert variant.target in variant.provenance
            assert variant.id == f"{variant.case.id}::{variant.transform}"


# -- determinism ---------------------------------------------------------------------------------------------------


def test_the_same_case_produces_the_same_variants_in_the_same_order_byte_for_byte() -> None:
    for case in ENFORCED:
        first, second = fpv.derive(case), fpv.derive(case)
        assert [v.id for v in first.variants] == [v.id for v in second.variants], case.id
        assert [v.text for v in first.variants] == [v.text for v in second.variants], case.id
        assert first.not_derived == second.not_derived


def test_the_variants_are_the_same_bytes_in_a_fresh_interpreter() -> None:
    """In-process equality cannot see a dependence on the hash seed or on dictionary insertion luck; a second
    interpreter, started with a different seed, can."""
    script = "\n".join(
        [
            f"import sys; sys.path.insert(0, {str(ROOT)!r}); sys.path.insert(0, {str(ROOT / 'src')!r})",
            "from tests.falsepass import harness as fp, variants as fpv",
            "out = []",
            "for c in fp.load_cases():",
            "    if not c.enforced: continue",
            "    d = fpv.derive(c)",
            "    out.append([c.id, d.not_derived, [[v.transform, v.digest] for v in d.variants]])",
            "import json; print(json.dumps(out))",
        ]
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=fp.TIMEOUT_SECONDS,
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "1", "HOME": str(ROOT)},
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    mine = [[d.case.id, d.not_derived, [[v.transform, v.digest] for v in d.variants]] for d in DERIVATIONS]
    assert json.loads(proc.stdout) == mine


# -- the bound -----------------------------------------------------------------------------------------------------


def test_the_cap_bounds_every_case_and_the_whole_suite() -> None:
    for derivation in DERIVATIONS:
        assert len(derivation.variants) <= fpv.MAX_VARIANTS_PER_CASE, derivation.case.id
    assert fpv.total(DERIVATIONS) <= len(ENFORCED) * fpv.MAX_VARIANTS_PER_CASE


def test_the_cap_is_a_named_constant_with_its_measurement_written_down() -> None:
    assert isinstance(fpv.MAX_VARIANTS_PER_CASE, int) and fpv.MAX_VARIANTS_PER_CASE > 0
    assert "second" in fpv.CAP_REASON and str(fpv.MAX_VARIANTS_PER_CASE) in fpv.CAP_REASON
    assert fpv.__doc__ and str(fpv.MAX_VARIANTS_PER_CASE) in fpv.__doc__


def test_the_cap_spreads_the_table_so_no_transformation_is_never_tried() -> None:
    """The cap is a budget, not a statement that the transformations past it do not matter: each case starts the
    table at its own offset, so across the corpus every transformation is tried."""
    tried = {v.transform for d in DERIVATIONS for v in d.variants}
    assert tried == {t.name for t in fpv.TRANSFORMS}, sorted({t.name for t in fpv.TRANSFORMS} - tried)


def test_the_time_bound_is_per_variant_and_not_shared() -> None:
    parent = fpv.Verdict(exit=1, scores={})
    slow = fp.Run(("audit",), 1, "{}", "", fp.TIMEOUT_SECONDS + 1.0)
    variant = WITH_VARIANTS[0].variants[0]
    assert any("took" in b for b in fpv.judge(variant, parent, slow, {}, None))
    quick = fp.Run(("audit",), 1, "{}", "", fp.TIMEOUT_SECONDS - 1.0)
    assert fpv.judge(variant, parent, quick, {}, None) == []


# -- the law -------------------------------------------------------------------------------------------------------


def _variant() -> fpv.Variant:
    return WITH_VARIANTS[0].variants[0]


def test_a_variant_that_exits_zero_where_its_parent_did_not_is_a_breach() -> None:
    parent = fpv.Verdict(exit=1, scores={})
    run = fp.Run(("audit",), 0, "{}", "", 0.1)
    breaches = fpv.judge(_variant(), parent, run, {}, None)
    assert len(breaches) == 1 and "exit 0" in breaches[0]


def test_a_variant_that_scores_higher_than_its_parent_is_a_breach() -> None:
    parent = fpv.Verdict(exit=1, scores={"summary.score": 62.0})
    run = fp.Run(("audit",), 1, "{}", "", 0.1)
    breaches = fpv.judge(_variant(), parent, run, {"summary": {"score": 100}}, None)
    assert len(breaches) == 1 and "summary.score" in breaches[0]


def test_a_variant_that_shows_the_shape_its_parent_forbids_is_a_breach() -> None:
    """The parent's `forbid` names the false pass as it was observed; a neighbour that shows it is the same false
    pass one wrapper away, which is the whole reason the neighbours are generated."""
    derivation = WITH_VARIANTS[0]
    case = dataclasses.replace(derivation.case, forbid=fp.Checks(json={"summary.verdict": "clean"}))
    variant = dataclasses.replace(derivation.variants[0], case=case)
    data = {"summary": {"verdict": "clean"}}
    parent = fpv.Verdict(exit=1, scores={})
    run = fp.Run(("audit",), 1, json.dumps(data), "", 0.1)
    (block,) = fpv.judge(variant, parent, run, data, None)
    assert "breach: forbidden summary.verdict" in block


def test_a_variant_that_declines_more_firmly_than_its_parent_is_not_a_breach() -> None:
    parent = fpv.Verdict(exit=1, scores={"summary.score": 62.0})
    run = fp.Run(("audit",), 4, "{}", "", 0.1)
    assert fpv.judge(_variant(), parent, run, {"summary": {"score": 10}}, None) == []


def test_a_breach_prints_the_case_the_transformation_and_both_verdicts_and_nothing_else() -> None:
    parent = fpv.Verdict(exit=1, scores={"summary.score": 62.0})
    run = fp.Run(("audit",), 0, "{}", "", 0.1)
    variant = _variant()
    (block,) = fpv.judge(variant, parent, run, {"summary": {"score": 62}}, None)
    lines = block.splitlines()
    assert [line.split(":")[0] for line in lines] == ["case", "transform", "parent", "variant", "breach"]
    assert lines[0] == f"case: {variant.case.id}"
    assert lines[1] == f"transform: {variant.transform} on {variant.target}"
    assert lines[2] == "parent: exit 1, summary.score 62.0"
    assert lines[3] == "variant: exit 0, summary.score 62.0"
    assert len(lines) == 5, block


# -- what the generator cannot derive is listed, never skipped ------------------------------------------------------


def test_every_enforced_case_is_either_derived_or_listed_with_a_reason() -> None:
    for derivation in DERIVATIONS:
        if derivation.variants:
            assert derivation.not_derived == "", derivation.case.id
            assert derivation.target
        else:
            assert derivation.not_derived, f"{derivation.case.id}: no variants and no reason is a silent skip"
            assert derivation.target is None


def test_a_case_whose_input_is_generated_in_code_is_listed_not_silently_dropped() -> None:
    generated = [d for d in DERIVATIONS if d.case.generate and not d.case.inputs]
    assert generated, "the corpus has generated-input cases; this test is about them"
    for derivation in generated:
        assert "generated in code" in derivation.not_derived


def test_a_case_whose_only_input_is_not_a_manifest_is_listed_with_that_reason() -> None:
    reasons = {d.not_derived for d in DERIVATIONS if d.not_derived}
    assert any("no YAML or JSON file" in r for r in reasons), sorted(reasons)


def test_the_law_runs_no_variant_of_a_case_that_waits_for_a_branch() -> None:
    """A case waiting for a branch is run and not enforced; its neighbours wait with it the same way. They are
    still derived, so the generated page can count them without running anything."""
    waiting = [c for c in CASES if not c.enforced]
    assert waiting, "the corpus has waiting cases; this test is about them"
    law_ids = {d.case.id for d in LAW}
    assert not any(c.id in law_ids for c in waiting)
    assert fpv.derive(next(c for c in waiting if c.inputs)).variants


# -- the invariant the law rests on --------------------------------------------------------------------------------


def test_every_transformation_keeps_every_document_the_parent_had() -> None:
    """The law reads a kinder answer as a defect, which is only sound while the parent's evidence is still in the
    input. A transformation that dropped the list item that is not an object -- the very thing a case is about --
    would make a kinder answer correct, which is how three wrapper transformations were caught silently filtering
    the documents that are not mappings. Documents, not names: a name cannot see a scalar document go missing."""
    missing: list[str] = []
    for derivation in WITH_VARIANTS:
        assert derivation.target is not None and derivation.case.inputs is not None
        original = (fp.INPUTS / derivation.case.inputs / derivation.target).read_text("utf-8")
        wanted = Counter(fpv.document_forms(original))
        assert wanted, derivation.case.id
        for variant in derivation.variants:
            have = Counter(fpv.document_forms(variant.text))
            lost = wanted - have
            if lost:
                missing.append(f"{variant.id}: {sorted(lost)[:2]}")
    assert missing == [], missing


def test_every_transformation_keeps_every_named_object_the_parent_had() -> None:
    """The same invariant read the other way, through a wrapper of any depth."""
    for derivation in WITH_VARIANTS:
        assert derivation.case.inputs is not None and derivation.target is not None
        wanted = fpv.identities((fp.INPUTS / derivation.case.inputs / derivation.target).read_text("utf-8"))
        for variant in derivation.variants:
            assert not wanted - fpv.identities(variant.text), variant.id


def test_a_transformation_that_adds_a_sibling_is_judged_on_the_exit_alone() -> None:
    """A mangled kind, name or parent can only keep the evidence by sitting BESIDE the original, so the variant
    has one object more than its parent and every count moves honestly. The forbid and score legs are dropped
    there and the exit leg is not: adding a sibling cannot turn a bundle with a finding into a success."""
    adding = next(d for d in WITH_VARIANTS for v in d.variants if v.adds_objects)
    variant = next(v for v in adding.variants if v.adds_objects)
    case = dataclasses.replace(variant.case, forbid=fp.Checks(json={"counts.installed": 1}), mcp_forbid=fp.Checks())
    variant = dataclasses.replace(variant, case=case)
    parent = fpv.Verdict(exit=1, scores={"summary.score": 10.0})
    data = {"counts": {"installed": 1}, "summary": {"score": 99}}
    run = fp.Run(("audit",), 1, json.dumps(data), "", 0.1)
    assert fpv.judge(variant, parent, run, data, None) == []
    not_adding = dataclasses.replace(variant, adds_objects=False)
    breaches = fpv.judge(not_adding, parent, run, data, None)
    assert len(breaches) == 2, breaches
    assert any("counts.installed" in b for b in breaches) and any("summary.score" in b for b in breaches)
    exits_zero = fp.Run(("audit",), 0, json.dumps(data), "", 0.1)
    assert len(fpv.judge(variant, parent, exits_zero, data, None)) == 1


def test_at_least_half_the_table_adds_no_sibling_so_the_whole_law_still_bites() -> None:
    adding = [t.name for t in fpv.TRANSFORMS if t.adds_objects]
    assert 0 < len(adding) < len(fpv.TRANSFORMS) // 2, adding


def test_the_identity_reader_finds_an_object_however_deeply_a_wrapper_holds_it() -> None:
    plain = "apiVersion: v1\nkind: Pod\nmetadata: {name: web, namespace: shop}\n"
    assert fpv.identities(plain) == {"Pod/shop/web"}
    wrapped = yaml.safe_dump({"apiVersion": "v1", "kind": "List", "items": [yaml.safe_load(plain)]})
    assert fpv.identities(wrapped) == {"Pod/shop/web"}
    nested = yaml.safe_dump({"kind": "List", "items": [{"kind": "List", "items": [yaml.safe_load(plain)]}]})
    assert fpv.identities(nested) == {"Pod/shop/web"}
    assert fpv.identities("not: a manifest\n") == set()
    assert fpv.identities(":::not yaml at all:::\n[") == set()


def test_a_wrapper_transformation_really_wraps_and_a_reordering_really_reorders() -> None:
    derivation = next(
        d
        for d in WITH_VARIANTS
        if d.target is not None and d.target.endswith((".yaml", ".yml")) and len(fpv.documents(d)) >= 2
    )
    by_name = {v.transform: v for v in fpv.derive(derivation.case, cap=None).variants}
    wrapped = yaml.safe_load(by_name["list-wrap"].text)
    assert wrapped["kind"] == "List" and isinstance(wrapped["items"], list)
    reversed_docs = list(yaml.safe_load_all(by_name["documents-reversed"].text))
    assert reversed_docs == list(reversed(fpv.documents(derivation)))


def test_the_duplicate_key_transformations_write_the_key_twice_and_still_parse() -> None:
    case = next(
        d for d in WITH_VARIANTS if d.target is not None and d.target.endswith((".yaml", ".yml")) and fpv.documents(d)
    )
    by_name = {v.transform: v for v in fpv.derive(case.case, cap=None).variants}
    for name, key in (("duplicate-key-on-the-object", "kind"), ("duplicate-key-on-the-wrapper", "kind")):
        text = by_name[name].text
        at_level = [ln for ln in text.splitlines() if ln.startswith(f"{key}:")]
        assert len(at_level) >= 2, (name, at_level)
        assert list(yaml.safe_load_all(text)), name


def test_the_hidden_character_transformations_use_the_set_the_output_boundary_knows() -> None:
    from kube_noob import sanitize

    for name in ("hidden-characters-in-the-wrapper-kind", "hidden-characters-in-every-name", "bidi-in-the-api-version"):
        transform = next(t for t in fpv.TRANSFORMS if t.name == name)
        assert transform.marks, name
        for ch in transform.marks:
            assert sanitize.has_invisible(f"a{ch}b"), f"{name}: {ch!r} is not one the boundary knows"


# -- the law, over the corpus --------------------------------------------------------------------------------------


@pytest.mark.parametrize("derivation", LAW, ids=[d.case.id for d in LAW])
def test_no_neighbour_of_an_enforced_case_answers_more_kindly_than_it(
    derivation: fpv.Derivation, tmp_path: Path
) -> None:
    checked = fpv.check(derivation, tmp_path, ledger=LEDGER)
    assert checked.breaches == [], "\n\n".join(checked.breaches)


def test_review_classes_names_the_generator_under_class_twenty_one() -> None:
    """`docs/review-classes.md` says class 21 is the one that closes most rounds, and its instruction was "list
    the adjacent inputs and test each". The class now has a machine behind it, and the row says so."""
    row = next(
        line
        for line in (ROOT / "docs" / "review-classes.md").read_text("utf-8").splitlines()
        if line.startswith("| 21 | ")
    )
    assert "tests/test_false_pass_variants.py" in row


# -- the ledger of neighbours the corpus already holds a case for ---------------------------------------------------


def test_the_ledger_is_read_from_the_filed_cases_and_nowhere_else() -> None:
    """One source of truth: a case filed for a kinder neighbour says so in its own provenance, in the sentence the
    generator writes into every variant. There is no second list to keep in step (class 9)."""
    # An EMPTY ledger is the stronger state, not a broken test: nothing is forgiven, and the law above then runs
    # every derived neighbour of every enforced case. G312..G315 emptied it by landing the four filed cases, so
    # the loop below is the test and it holds vacuously on nothing.
    for (parent, transform), owner in LEDGER.items():
        assert parent in {c.id for c in CASES}, parent
        assert transform in {t.name for t in fpv.TRANSFORMS}, transform
        assert owner.provenance.count("neighbour variant") == 1
        assert parent in owner.provenance and transform in owner.provenance


def test_every_neighbour_on_the_ledger_is_owned_by_a_case_that_is_still_waiting() -> None:
    """A filed case that has started enforcing has had its fix; its neighbour must be judged again, not forgiven
    for good. So an entry whose owner enforces is a stale line on the ledger and this fails on it."""
    stale = [f"{p}::{t} is owned by {o.id}, which enforces now" for (p, t), o in LEDGER.items() if o.enforced]
    assert stale == [], stale


def test_every_filed_case_holds_the_bytes_the_generator_derives() -> None:
    """The filed case must BE the neighbour, not a paraphrase of it: its input at the parent's target path is one
    of the variant texts it says it owns. Otherwise the ledger forgives a neighbour nobody reproduced."""
    by_owner: dict[str, list[tuple[str, str]]] = {}
    for (parent, transform), owner in LEDGER.items():
        by_owner.setdefault(owner.id, []).append((parent, transform))
    for owner_id, owned in sorted(by_owner.items()):
        owner = next(c for c in CASES if c.id == owner_id)
        assert owner.inputs is not None, owner_id
        wanted: list[str] = []
        for parent_id, transform in sorted(owned):
            parent = next(c for c in CASES if c.id == parent_id)
            variant = next((v for v in fpv.derive(parent, cap=None).variants if v.transform == transform), None)
            assert variant is not None, f"{owner_id} owns {parent_id}::{transform}, which is not derived"
            held = fp.INPUTS / owner.inputs / variant.target
            assert held.is_file(), f"{owner_id} has no input at {variant.target}, the parent's target"
            wanted.append(variant.text)
        assert held.read_text("utf-8") in wanted, owner_id


def test_a_waiting_filed_case_takes_its_neighbour_off_the_law_and_an_enforcing_one_does_not(tmp_path: Path) -> None:
    if not LEDGER:
        pytest.skip("the ledger is empty: nothing is forgiven, so the law above already runs every neighbour")
    derivation = next(d for d in LAW if any((d.case.id, v.transform) in LEDGER for v in d.variants))
    checked = fpv.check(derivation, tmp_path / "with", ledger=LEDGER)
    assert checked.on_the_ledger, derivation.case.id
    for transform, owner_id in checked.on_the_ledger:
        assert (derivation.case.id, transform) in LEDGER and owner_id in {c.id for c in CASES}
    without = fpv.check(derivation, tmp_path / "without", ledger={})
    assert not without.on_the_ledger
    assert len(without.breaches) > 0, "the ledger would be forgiving a neighbour that does not breach the law"


def test_the_ledger_forgives_a_small_minority_of_the_neighbours_and_names_each() -> None:
    """A ledger that grew to cover most of the neighbours would be the gate turned off one line at a time. Every
    forgiven neighbour is named by the case that owns it, and they stay a small minority of what the law runs."""
    derived = [(d.case.id, v.transform) for d in LAW for v in d.variants]
    forgiven = [k for k in derived if (o := LEDGER.get(k)) is not None and not o.enforced]
    if not forgiven:
        pytest.skip("nothing is forgiven, which is what this test wants to stay true of a non-empty ledger")
    assert len(forgiven) * 10 < len(derived), f"{len(forgiven)} of {len(derived)} neighbours are on the ledger"
    for key in forgiven:
        assert LEDGER[key].expected_on, key
