"""Neighbour variants for the false-pass benchmark: every case's input, derived into the inputs one step away.

``docs/review-classes.md`` class 21 -- "fixing the reported shape, not its neighbours" -- is the class that file
says closes most review rounds: the fix covered the exact input in the report, and the other wrapper, the other
type, the other order still failed. Every case in ``cases/`` is a shape that once read as a pass, so every case's
neighbours are the shapes most likely to still read as one. This module derives them mechanically from one table,
``TRANSFORMS``, and holds the tool to one law:

    A variant may be as conservative as its parent, or more -- never less.

If the parent case's shape is reported honestly today (a finding, a not-evaluated, an undetermined, a non-zero
exit), then no variant of it may show the shape the parent forbids, exit 0 where the parent did not, or score
higher than the parent did. That law is what makes this cheap: nobody has to decide what the honest answer for a
generated input *is*, only that it cannot be kinder than one already known to be honest.

**The invariant the law rests on.** Every transformation keeps the deciding evidence somewhere in the input --
checked by ``tests/test_false_pass_variants.py::test_every_transformation_keeps_the_deciding_evidence_in_the_input``,
which reads every object identity out of the parent's file and requires each one to still be present in the
variant's. A transformation that deleted the privileged container would make a clean verdict *correct* and the law
would read it as a defect. That is why the odd-container transformations put the strange shape on a wrapper beside
the real objects rather than in place of them, and why the ones that rewrite a document keep the original
documents after their own.

**The bound.** One variant is one CLI run of the parent's own command, so the suite's cost is its variant count.
``MAX_VARIANTS_PER_CASE`` is 4: the smallest cap at which every transformation in the table is still tried
somewhere in the corpus, measured, with the measurement in ``CAP_REASON``. Each case starts the table at its own
offset (from a digest of its id, not the hash seed), so the four it runs are not the same four every time, and
across the corpus all 26 are reached -- a test holds that and fails if a later case breaks it, which is when the
cap gets measured again. ``FALSEPASS_VARIANTS=all`` in ``tests/test_false_pass_variants.py`` runs the whole matrix
for an owner-run pass.

**Determinism.** ``derive(case)`` reads only the case file and its inputs, and emits with sorted keys, so the same
case produces the same variants in the same order, byte for byte, in any interpreter.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from tests.falsepass import harness as fp
from tests.falsepass.harness import Case

#: Seconds one variant may take. The bound is per variant, not shared across a case's variants: a cap that a
#: wrapper makes quadratic shows up on the one run that pays for it, and sharing the budget would hide it.
TIMEOUT_SECONDS = fp.TIMEOUT_SECONDS

#: How many variants of one case the suite runs. Chosen from the measurement in ``CAP_REASON``, not guessed.
MAX_VARIANTS_PER_CASE = 4

#: Why the cap is what it is. Held by ``test_the_cap_is_a_named_constant_with_its_measurement_written_down``.
CAP_REASON = (
    "The cap is not a taste: it is the SMALLEST number of neighbours per case at which every transformation in "
    "the table is still tried somewhere in the corpus, which is the coverage property that matters, and it was "
    "measured rather than guessed. Each case starts the table at its own offset, so at 1 neighbour per case four "
    "transformations are never tried at all, at 2 and at 3 one still is not (typed-list-wrap, which applies only "
    "where every document is a mapping of one kind), and at 4 all 26 are "
    "(test_the_cap_spreads_the_table_so_no_transformation_is_never_tried holds this, and fails if a later case or "
    "a new transformation breaks it -- then the cap is measured again, which is the point). Anything above 4 buys "
    "repetition of transformations already exercised, and it is not free: one variant is one CLI run of the "
    "parent's own command, so the suite's cost is its variant count. Measured on this branch by running the whole "
    "matrix serially, one run each -- 1,069 neighbours over the 63 enforced cases: 629 seconds in all, 0.45 "
    "seconds at the median, 0.59 at the mean, 0.97 at the ninetieth percentile, 10.1 for the slowest single run "
    "(the tail is the must-gather trees and the stub-cluster reads). With the 54 parent runs the law compares "
    "against, 4 costs 187 seconds of command time, 5 costs 222 and 6 costs 256. The cap is per case rather than "
    "overall, so one case with a large input cannot spend another's budget."
)

#: Invisible characters, built from code points so that none of them sits in this source file. Each one is in the
#: set ``kube_noob.sanitize`` already marks at the output boundary, asserted by the test of that name.
_ZWSP = chr(0x200B)  # zero width space
_SHY = chr(0x00AD)  # soft hyphen
_RLO = chr(0x202E)  # right-to-left override
_ALM = chr(0x061C)  # Arabic letter mark

#: The group a transformation moves a kind into. RFC 2606 reserves ``.invalid``, so the variant claims nothing
#: about a real API group.
_OTHER_GROUP = "example.invalid"

#: The file kinds a variant can be derived from: a manifest the command reads, not a stub's exit code or stderr.
_MANIFEST_SUFFIXES = (".yaml", ".yml", ".json")


@dataclass(frozen=True)
class Shape:
    """One input file as a transformation sees it: its documents, its text and its suffix."""

    docs: tuple[Any, ...]
    text: str
    suffix: str

    @property
    def objects(self) -> list[dict[str, Any]]:
        return [d for d in self.docs if isinstance(d, dict)]

    @property
    def yaml_only(self) -> bool:
        """A ``.json`` target keeps its format: a variant that also changed the file's language would conflate two
        changes in one failure message, and a multi-document JSON file is not a shape any reader models."""
        return self.suffix in (".yaml", ".yml")


@dataclass(frozen=True)
class Transform:
    """One neighbour, and why the reviews say it is worth trying. ``why`` reaches the generated page."""

    name: str
    why: str
    apply: Callable[[Shape], str | None]
    marks: tuple[str, ...] = ()
    #: Whether the variant holds objects the parent did not. To mangle a kind, a name or a parent and still keep
    #: the deciding evidence, a transformation has to put the mangled form BESIDE the original -- which means the
    #: variant has one more object than its parent, so a count, a per-object assertion and a score computed over
    #: objects all move for an honest reason. The law's forbid and score legs are not comparable then, and
    #: ``judge`` drops them; the exit leg still holds, because adding a sibling to a bundle that already had a
    #: finding cannot make the run a success.
    adds_objects: bool = False


# -- emitting ------------------------------------------------------------------------------------------------------


def _emit(docs: list[Any], shape: Shape) -> str | None:
    """The documents as the target file's own language. ``None`` when they cannot be written in it."""
    if shape.suffix == ".json":
        if len(docs) != 1:
            return None
        return json.dumps(docs[0], indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return str(yaml.safe_dump_all(docs, sort_keys=True, default_flow_style=False, allow_unicode=True))


def _wrapper(items: Any, kind: str = "List", api: str = "v1") -> dict[str, Any]:
    return {"apiVersion": api, "items": items, "kind": kind}


def _dup_line(text: str, pattern: re.Pattern[str]) -> str | None:
    """The first line matching ``pattern``, written twice: a duplicate key at exactly that level."""
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if pattern.match(line):
            return "".join([*lines[: i + 1], line, *lines[i + 1 :]])
    return None


_TOP_KIND = re.compile(r"^kind:")
_METADATA_NAME = re.compile(r"^ {2}name:")


def _rewrite(shape: Shape, key: str, change: Callable[[str], str]) -> str | None:
    """A copy of every object with its ``key`` rewritten by ``change``, and then the originals.

    The copy, not the object: a kind or an apiVersion nothing serves leaves no object a rule can read, and a
    verdict with nothing to say about nothing is honestly empty. Keeping the originals after the copies means the
    parent's own finding is still there to be made, so a kinder answer is the mangled sibling having silenced it --
    which is the defect (class 25), not the empty read."""
    objects = shape.objects
    if not objects or not shape.yaml_only:
        return None
    if not all(isinstance(o.get(key), str) and o[key] for o in objects):
        return None
    return _emit([{**o, key: change(o[key])} for o in objects] + list(shape.docs), shape)


def _copies(shape: Shape, change: Callable[[dict[str, Any]], dict[str, Any]]) -> str | None:
    """A changed copy of every object, and then the originals, so the deciding evidence is still in the file."""
    objects = shape.objects
    if not objects or not shape.yaml_only:
        return None
    return _emit([change(o) for o in objects] + list(shape.docs), shape)


def _renamed(shape: Shape, change: Callable[[str], str]) -> str | None:
    """A copy of every object under a changed name, and then the originals. ``None`` where an object has no name:
    a copy of an unnamed object is a duplicate and nothing to do with the name this transformation is about."""
    objects = shape.objects
    if not objects or not shape.yaml_only:
        return None
    if any(not isinstance(o.get("metadata"), dict) or not isinstance(o["metadata"].get("name"), str) for o in objects):
        return None
    copies = [{**o, "metadata": {**o["metadata"], "name": change(o["metadata"]["name"])}} for o in objects]
    return _emit(copies + list(shape.docs), shape)


_HEAD = ("apiVersion", "kind", "metadata")


def _typed_list_wrap(shape: Shape) -> str | None:
    """The objects inside a ``<Kind>List``. Only where every object is the same kind and that kind is a string:
    a document whose ``kind`` is a list or a number has no typed wrapper, and inventing one would test a shape
    the corpus already holds a case for rather than this case's neighbour."""
    objects = shape.objects
    if not objects or len(objects) != len(shape.docs):
        return None  # a document that is not a mapping has no place in a typed list, and must not be dropped
    if any(not isinstance(o.get("kind"), str) or not isinstance(o.get("apiVersion"), str) for o in objects):
        return None
    kinds = {str(o["kind"]) for o in objects}
    apis = {str(o["apiVersion"]) for o in objects}
    if len(kinds) != 1 or len(apis) != 1:
        return None
    return _emit([_wrapper(objects, kind=next(iter(kinds)) + "List", api=next(iter(apis)))], shape)


def _split(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """One object as two documents sharing its head, each carrying half of the rest."""
    head = {k: v for k, v in obj.items() if k in _HEAD}
    rest = sorted(k for k in obj if k not in _HEAD)
    half = len(rest) // 2 or 1
    return [
        {**head, **{k: obj[k] for k in rest[:half]}},
        {**head, **{k: obj[k] for k in rest[half:]}},
    ]


# -- the table -----------------------------------------------------------------------------------------------------
# One table, in one place. A transformation named in a second file is a second source of truth (class 9), so a test
# refuses one. Each entry's ``why`` is the sentence the generated page carries, and the review that found the shape.


TRANSFORMS: tuple[Transform, ...] = (
    Transform(
        "list-wrap",
        "The objects arrive as the items of one `v1` `kind: List`, which is what `kubectl get -o yaml` writes and "
        "what a reader that only walks documents never descends into.",
        lambda s: _emit([_wrapper(list(s.docs))], s) if s.docs else None,
    ),
    Transform(
        "typed-list-wrap",
        "The same objects inside a typed `<Kind>List` rather than a plain `List`, which is the wrapper a single "
        "`kubectl get <kind>` actually returns and a separate branch in every loader that special-cases `List`.",
        _typed_list_wrap,
    ),
    Transform(
        "nested-list-wrap",
        "A `List` whose single item is another `List` holding the objects: a loader that unwraps one level and "
        "then audits what it finds sees a wrapper where a workload should be.",
        lambda s: _emit([_wrapper([_wrapper(list(s.docs))])], s) if s.docs else None,
    ),
    Transform(
        "list-items-mapping",
        "A wrapper whose `items` is a mapping keyed by index rather than a sequence, beside the real objects: a "
        "mapping where a sequence was is the shape class 4 names, and the container's own defect is class 23.",
        lambda s: (
            _emit([_wrapper([_wrapper({str(i): d for i, d in enumerate(s.docs)}), *s.docs])], s) if s.docs else None
        ),
    ),
    Transform(
        "list-items-null",
        "A wrapper whose `items` is null, beside the real objects: null is the value a missing key and an explicit "
        "`items:` with nothing after it both produce, and it used to read as an empty cluster.",
        lambda s: _emit([_wrapper([_wrapper(None), *s.docs])], s) if s.docs else None,
    ),
    Transform(
        "list-items-scalar",
        "A wrapper whose `items` is a non-string scalar, beside the real objects: an integer where a sequence was "
        "is the shape that crashed a reader which checked for a list by truthiness.",
        lambda s: _emit([_wrapper([_wrapper(7), *s.docs])], s) if s.docs else None,
    ),
    Transform(
        "list-items-empty",
        "A wrapper whose `items` is an empty sequence, beside the real objects: an empty collection is the one "
        "shape a reader is most likely to answer with a count of zero rather than with what it could not read.",
        lambda s: _emit([_wrapper([_wrapper([]), *s.docs])], s) if s.docs else None,
    ),
    Transform(
        "list-item-not-an-object",
        "A wrapper whose `items` holds a scalar before the real objects: an item that is not a mapping among items "
        "that are, which is the shape that made a reader stop at the first element and report what it had.",
        lambda s: _emit([_wrapper([7, *s.docs])], s) if s.docs else None,
    ),
    Transform(
        "duplicate-key-on-the-wrapper",
        "A `List` wrapper whose own `kind` is written twice: the items are checked for duplicate keys and the "
        "container that holds them is not, which is class 23 exactly.",
        lambda s: _dup_line(_emit([_wrapper(list(s.docs))], s) or "", _TOP_KIND) if s.docs and s.yaml_only else None,
    ),
    Transform(
        "duplicate-key-on-the-object",
        "Each object's own top-level `kind` written twice: YAML takes the last and says nothing, so a reader that "
        "does not look for the repeat answers about a kind the author did not write.",
        lambda s: _dup_line(_emit(list(s.docs), s) or "", _TOP_KIND) if s.objects and s.yaml_only else None,
    ),
    Transform(
        "duplicate-key-in-metadata",
        "A duplicate `name` inside `metadata`: the same defect one level down, where the duplicate decides which "
        "object the answer is about rather than which kind.",
        lambda s: _dup_line(_emit(list(s.docs), s) or "", _METADATA_NAME) if s.objects and s.yaml_only else None,
    ),
    Transform(
        "kind-case-swapped",
        "Every `kind` with its letter case swapped. Kubernetes kinds are case-sensitive, so this is a kind nothing "
        "serves -- which must be not-evaluated and never a clean read of the kind it resembles (class 3).",
        lambda s: _rewrite(s, "kind", str.swapcase),
        adds_objects=True,
    ),
    Transform(
        "kind-with-spaces",
        "Every `kind` wrapped in spaces. A matcher that strips before comparing and a matcher that does not "
        "disagree about this input, and the honest answer is the same either way: say which it read.",
        lambda s: _rewrite(s, "kind", lambda k: f" {k} "),
        adds_objects=True,
    ),
    Transform(
        "api-version-case-swapped",
        "Every `apiVersion` with its letter case swapped: the group is a DNS name and the version is not, so a "
        "comparison that folds case reads a group this cluster does not serve as one it does.",
        lambda s: _rewrite(s, "apiVersion", str.swapcase),
        adds_objects=True,
    ),
    Transform(
        "api-version-group-moved",
        "Every `apiVersion` moved into another group, keeping the version: a foreign kind of the same name is a "
        "different kind, and matching `kind` without its group is class 3.",
        lambda s: _rewrite(s, "apiVersion", lambda a: f"{_OTHER_GROUP}/{a.split('/')[-1]}"),
        adds_objects=True,
    ),
    Transform(
        "documents-reversed",
        "The documents in reverse order. Order must not change the answer at all: a verdict that depends on which "
        "document came first is class 5, and the duplicate-and-ordering defects were found this way.",
        lambda s: _emit(list(reversed(s.docs)), s) if len(s.docs) >= 2 and s.yaml_only else None,
    ),
    Transform(
        "documents-rotated",
        "The first document moved to the end: the deciding object is now in another document, which is the shape "
        "that a reader walking only the first document, or caching by document index, answers wrongly.",
        lambda s: _emit([*s.docs[1:], s.docs[0]], s) if len(s.docs) >= 3 and s.yaml_only else None,
    ),
    Transform(
        "empty-document-between",
        "An empty document before and after every document, which is what a trailing `---` and a template that "
        "rendered to nothing both produce; an empty document is not an object and not an absence of objects.",
        lambda s: (
            "".join("---\n" + "---\n" + (_emit([d], s) or "") for d in s.docs) + "---\n"
            if s.docs and s.yaml_only
            else None
        ),
    ),
    Transform(
        "documents-joined",
        "The first two documents merged into one mapping, and then the originals: two objects joined into one is "
        "what a careless `yq` or a Helm template without its separator writes.",
        lambda s: (
            _emit([{**s.objects[0], **s.objects[1]}, *s.docs], s) if len(s.objects) >= 2 and s.yaml_only else None
        ),
        adds_objects=True,
    ),
    Transform(
        "documents-split",
        "Every object split into two documents that share its `apiVersion`, `kind` and `metadata`, and then the "
        "originals: the same object collected twice, in halves, which is the conflict a reader must report.",
        lambda s: (
            _emit(
                [part for o in s.objects for part in _split(o)] + list(s.docs),
                s,
            )
            if s.yaml_only and any(len(set(o) - set(_HEAD)) >= 2 for o in s.objects)
            else None
        ),
        adds_objects=True,
    ),
    Transform(
        "body-one-level-deeper",
        "A copy of every object whose body sits one level deeper, under a parent nothing reads, and then the "
        "originals: the deciding field under a different parent is how a rule came to answer about nothing.",
        lambda s: _copies(
            s,
            lambda o: {
                **{k: v for k, v in o.items() if k in _HEAD},
                "spec": {k: v for k, v in o.items() if k not in _HEAD},
            },
        ),
        adds_objects=True,
    ),
    Transform(
        "hidden-characters-in-the-wrapper-kind",
        "A `List` wrapper whose `kind` carries a zero-width space and a soft hyphen: it reads as `List` to a human "
        "and is not `List` to a matcher, so it must be not-evaluated and must never reach output unmarked.",
        lambda s: _emit([_wrapper(list(s.docs), kind=f"Li{_ZWSP}s{_SHY}t")], s) if s.docs else None,
        marks=(_ZWSP, _SHY),
    ),
    Transform(
        "hidden-characters-in-every-name",
        "A copy of every object with a zero-width space inside its name, and then the originals: two objects whose "
        "names differ only by a character that does not print is both a duplicate (class 5) and output the "
        "boundary must mark (class 7).",
        lambda s: _renamed(s, lambda n: n[:1] + _ZWSP + n[1:]),
        marks=(_ZWSP,),
        adds_objects=True,
    ),
    Transform(
        "bidi-in-the-api-version",
        "A `List` wrapper whose `apiVersion` carries a right-to-left override and an Arabic letter mark: a "
        "bidirectional control in a version string reorders what a reader sees without changing what it matches.",
        lambda s: _emit([_wrapper(list(s.docs), api=f"v{_RLO}1{_ALM}")], s) if s.docs else None,
        marks=(_RLO, _ALM),
    ),
    Transform(
        "crlf",
        "The same bytes with CRLF line endings, which is what a checkout on Windows and a pasted manifest both "
        "produce: a block scalar's content now ends in a carriage return the parser keeps.",
        lambda s: s.text.replace("\r\n", "\n").replace("\n", "\r\n") if "\n" in s.text else None,
    ),
    Transform(
        "utf8-bom",
        "A UTF-8 byte order mark before the first document: a file a Windows editor saved, where the first key's "
        "name begins with a character no comparison expects.",
        lambda s: "﻿" + s.text if not s.text.startswith("﻿") else None,
    ),
)


# -- deriving ------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Variant:
    """One neighbour of one case: the same command, over one input file rewritten by one transformation."""

    case: Case
    transform: str
    why: str
    target: str
    text: str
    runs_mcp: bool
    adds_objects: bool = False

    @property
    def id(self) -> str:
        return f"{self.case.id}::{self.transform}"

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()[:16]

    @property
    def provenance(self) -> str:
        return f"neighbour variant of {self.case.id}: {self.transform} on {self.target}"


@dataclass(frozen=True)
class Derivation:
    """A case's neighbours, or -- when it has none -- the reason, in words. Never a silent skip (class 1)."""

    case: Case
    target: str | None
    variants: tuple[Variant, ...]
    not_derived: str


def _parse(path: Path) -> tuple[Any, ...] | None:
    try:
        text = path.read_text("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        docs = tuple(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return None
    return docs if any(isinstance(d, dict) for d in docs) else None


def _candidates(case: Case) -> list[str]:
    """Every manifest under the case's inputs, as paths relative to it, in a fixed order."""
    if case.inputs is None:
        return []
    root = fp.INPUTS / case.inputs
    out: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in _MANIFEST_SUFFIXES:
            continue
        if _parse(path) is None:
            continue
        out.append(path.relative_to(root).as_posix())
    return out


def _target(case: Case) -> str | None:
    """The file the variants rewrite: the one the command or the tool names, else the first manifest. One file per
    case, because the cost is one CLI run per variant and the file the command names is the deciding one."""
    candidates = _candidates(case)
    if not candidates:
        return None
    spoken = " ".join([*case.argv, json.dumps(case.mcp_args, sort_keys=True)])
    named = [c for c in candidates if c in spoken]
    return (named or candidates)[0]


def _offset(case_id: str) -> int:
    """Where this case starts the table. From a digest of the id, so it does not move with the hash seed."""
    return int(hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:8], 16) % len(TRANSFORMS)


def derive(case: Case, cap: int | None = MAX_VARIANTS_PER_CASE) -> Derivation:
    """``case``'s neighbours, in a fixed order, or the reason it has none. ``cap=None`` is the whole matrix.

    Static: it reads the case file and its inputs and runs nothing, so the generated page can carry the counts
    and ``scripts/false_pass_report.py --check`` stays a file comparison. Whether a case *enforces* is decided at
    run time by its probe, and the law runs the variants of the enforced ones only -- a case that waits for a
    branch has its neighbours derived and not run, exactly as the case itself is."""
    if case.inputs is None:
        reason = (
            "the input is generated in code, not a file in the corpus"
            if case.generate
            else "the case has no input files"
        )
        return Derivation(case, None, (), reason)
    target = _target(case)
    if target is None:
        return Derivation(case, None, (), "the inputs hold no YAML or JSON file a transformation can read")
    path = fp.INPUTS / case.inputs / target
    docs = _parse(path)
    assert docs is not None  # _candidates only returns files that parse
    shape = Shape(docs=docs, text=path.read_text("utf-8"), suffix=path.suffix.lower())
    runs_mcp = case.mcp_tool is not None and f"{{text:{target}}}" in json.dumps(case.mcp_args, sort_keys=True)
    start = _offset(case.id)
    out: list[Variant] = []
    for i in range(len(TRANSFORMS)):
        transform = TRANSFORMS[(start + i) % len(TRANSFORMS)]
        text = transform.apply(shape)
        if text is None or text == shape.text:
            continue
        out.append(Variant(case, transform.name, transform.why, target, text, runs_mcp, transform.adds_objects))
        if cap is not None and len(out) >= cap:
            break
    if not out:
        return Derivation(case, None, (), f"no transformation applies to {target}")
    return Derivation(case, target, tuple(out), "")


def documents(derivation: Derivation) -> list[Any]:
    """The parsed documents of the file a derivation's variants rewrite."""
    assert derivation.target is not None and derivation.case.inputs is not None
    docs = _parse(fp.INPUTS / derivation.case.inputs / derivation.target)
    return list(docs or ())


def total(derivations: list[Derivation]) -> int:
    return sum(len(d.variants) for d in derivations)


#: How a case filed FOR a kinder neighbour says which neighbours it owns. Every variant writes the same sentence
#: into its provenance, so a case filed for one repeats it, and the law can tell a neighbour already on the ledger
#: from a new one. This is the corpus's own discipline applied to the neighbours: a filed case waits for its fix
#: behind a probe, its neighbour waits with it, and the day the probe holds the filed case enforces AND the law
#: starts judging that neighbour again -- so nothing is forgiven for longer than the defect lives.
_FILED = re.compile(r"neighbour variants? of ([a-z0-9][a-z0-9-]*): ([a-z0-9-]+(?:, [a-z0-9-]+)*) on ")


def filed(cases: list[Case]) -> dict[tuple[str, str], Case]:
    """Which (case, transformation) neighbours the corpus already holds a case for."""
    out: dict[tuple[str, str], Case] = {}
    for case in cases:
        match = _FILED.search(case.provenance)
        if match is None:
            continue
        for transform in match.group(2).split(", "):
            out[(match.group(1), transform)] = case
    return out


def document_forms(text: str) -> list[str]:
    """Every document in a manifest, in one canonical form each, and every node a wrapper's ``items`` holds.

    The law is only sound while the parent's own documents are all still in the variant's input, and a set of
    names cannot see a document that is not a mapping -- a list item that is not an object, a bare scalar -- being
    quietly dropped. Wrapping is one of the transformations, so a document that moved inside an ``items`` counts
    as still present; a document that disappeared does not. A leading byte order mark is removed first: it is a
    transformation of its own and it removes no document.
    """
    try:
        docs = list(yaml.safe_load_all(text.lstrip("\ufeff")))
    except yaml.YAMLError:
        return []
    out: list[str] = []

    def walk(node: Any, depth: int) -> None:
        out.append(json.dumps(node, sort_keys=True, default=str))
        if depth > 8:
            return
        if isinstance(node, dict):
            items = node.get("items")
            if isinstance(items, list):
                for item in items:
                    walk(item, depth + 1)
            elif isinstance(items, dict):
                for item in items.values():
                    walk(item, depth + 1)

    for doc in docs:
        walk(doc, 0)
    return sorted(out)


def identities(text: str) -> set[str]:
    """Every object identity (`<Kind>/<namespace>/<name>`) in a manifest, however deeply a wrapper holds it. The
    law is only sound while the evidence is still in the input, and this is how that is checked."""
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return set()
    out: set[str] = set()

    def walk(node: Any, depth: int) -> None:
        if depth > 8:
            return
        if isinstance(node, list):
            for item in node:
                walk(item, depth + 1)
            return
        if not isinstance(node, dict):
            return
        kind, metadata = node.get("kind"), node.get("metadata")
        if isinstance(kind, str) and kind and isinstance(metadata, dict) and isinstance(metadata.get("name"), str):
            namespace = metadata.get("namespace")
            out.add(f"{kind}/{namespace if isinstance(namespace, str) else '-'}/{metadata['name']}")
        walk(node.get("items"), depth + 1)

    for doc in docs:
        walk(doc, 0)
    return out


# -- the law -------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    """How kind an answer was: the exit code, and every score in it. Nothing else is compared."""

    exit: int
    scores: dict[str, float]

    def show(self, only: dict[str, float] | None = None) -> str:
        keys = sorted(self.scores if only is None else {k: v for k, v in self.scores.items() if k in only})
        return ", ".join([f"exit {self.exit}", *(f"{k} {self.scores[k]}" for k in keys)])


def scores(data: Any) -> dict[str, float]:
    """Every numeric ``score`` in an output, by path. A score is the one number that reads as a grade."""
    out: dict[str, float] = {}

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}.{key}" if path else str(key)
                if key == "score" and isinstance(value, int | float) and not isinstance(value, bool):
                    out[here] = float(value)
                walk(value, here)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    walk(data, "")
    return out


def judge(variant: Variant, parent: Verdict, run: fp.Run, data: Any, mcp: tuple[Any, str] | None) -> list[str]:
    """What this variant did that its parent did not permit. One block per breach, and nothing in a block but the
    case, the transformation, the two verdicts and the breach -- a failure a reader can act on without a rerun."""
    case = variant.case
    here = Verdict(run.exit, scores(data))
    breaches: list[str] = []
    if run.seconds > TIMEOUT_SECONDS or run.exit == -1:
        breaches.append(f"the run took {run.seconds:.1f} s, past the {TIMEOUT_SECONDS:.0f} s bound for one variant")
    if parent.exit != 0 and run.exit == 0:
        breaches.append(f"the parent exited {parent.exit} and this exits 0")
    comparable = not variant.adds_objects and run.exit == parent.exit
    if comparable:
        # Two reasons a count or a score is not comparable with its parent's, and in both the exit leg still is.
        # A variant that holds a sibling the parent did not moves every count for an honest reason. And a variant
        # whose exit differs has not given the same KIND of answer: a case's forbidden shape is a claim about the
        # answer that case got, so `notSucceeded: 0` beside `verdict: not-determined` and exit 5 is not the
        # `notSucceeded: 0` beside `verdict: listed` and exit 0 that the case was filed for -- it is the honest
        # reading of an input nothing could be read from, and the exit code says so.
        for path, value in sorted(parent.scores.items()):
            mine = here.scores.get(path)
            if mine is not None and mine > value:
                breaches.append(f"{path} is {mine}, above the parent's {value}")
        # Exit 0 is the monotonic rule above, so it is not also a forbidden shape; a non-zero forbidden exit stays.
        forbid = dataclasses.replace(case.forbid, exit=tuple(e for e in case.forbid.exit if e != 0))
        breaches += fp.violations(forbid, run, data, run.stdout, run.stderr, True)
        if mcp is not None:
            value, text = mcp
            breaches += ["the tool result " + p for p in fp.violations(case.mcp_forbid, None, value, text, "", True)]
    return [
        "\n".join(
            [
                f"case: {case.id}",
                f"transform: {variant.transform} on {variant.target}",
                f"parent: {parent.show()}",
                f"variant: {here.show(parent.scores)}",
                f"breach: {breach}",
            ]
        )
        for breach in breaches
    ]


@dataclass(frozen=True)
class Checked:
    """What the law found for one case: the breaches, and the neighbours it did not judge because the corpus
    already holds a case for them. The second list is printed, never silently dropped (class 1)."""

    breaches: list[str]
    on_the_ledger: list[tuple[str, str]]


def check(
    derivation: Derivation,
    work: Path,
    python: str = sys.executable,
    ledger: dict[tuple[str, str], Case] | None = None,
) -> Checked:
    """Run the parent once, then every variant once, and judge each against the parent.

    A neighbour the corpus already holds a WAITING case for is not judged here: the case is the record, it is run
    by the benchmark, and judging it twice would fail the suite for a defect that is filed and owned. The day that
    case's probe holds, it stops waiting and this starts judging the neighbour again."""
    case = derivation.case
    on_the_ledger: list[tuple[str, str]] = []
    todo = []
    for variant in derivation.variants:
        owner = (ledger or {}).get((case.id, variant.transform))
        if owner is not None and not owner.enforced:
            on_the_ledger.append((variant.transform, owner.id))
            continue
        todo.append(variant)
    if not todo:
        return Checked([], on_the_ledger)
    parent_inputs = fp._materialise(case, work / "parent")
    parent_run = fp.run_cli(case, parent_inputs, work / "parent" / "home", python)
    parent = Verdict(parent_run.exit, scores(parent_run.json))
    breaches: list[str] = []
    for i, variant in enumerate(todo):
        here = work / f"v{i:02d}"
        inputs = fp._materialise(case, here)
        (inputs / variant.target).write_text(variant.text, "utf-8")
        run = fp.run_cli(case, inputs, here / "home", python)
        mcp = fp.run_mcp(case, inputs) if variant.runs_mcp else None
        breaches += judge(variant, parent, run, run.json, mcp)
    return Checked(breaches, on_the_ledger)
