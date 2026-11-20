"""A new tight wall-clock assertion has to fail on its author, not on somebody's merge three weeks later.

G263 replaced two wall-clock budgets with assertions about the code, and left thirty-three. Two of those have
since blocked merges -- `test_hostile_and_oversized_input_is_bounded_and_fast` at 1.0239 s and 1.0607 s against a
`< 1.0` guarding work that takes 0.001 s, and `test_a_post_that_cannot_get_a_slot_is_refused_with_503_within_the_wait`
at 3.1 s against a `< 3` standing in for a 0.3 s deadline. G326 converted all of them to `tests/bounds.py`.

That conversion is worth nothing by itself, because the next tight assertion is one line away. So this is a
structural guard, in the shape of `tests/test_image_copy_modes.py` and `tests/test_empty_collection_guards.py`:
it parses the test tree and refuses a raw wall-clock comparison below a floor.

The floor is `bounds.MAX_CEILING_SECONDS`, and it is one number rather than two on purpose (`docs/review-classes.md`
class 9). That constant is the loosest ceiling `tests/bounds.py` will ever hand out, so:

- below it, a hand-written number is one the helper would have computed -- and computed better, because the helper
  scales with the interpreter here, allows for a stall on a shared runner, says what regression it is for when it
  fires, and refuses outright when the ceiling it produced could not catch that regression. There is no reason to
  write such a number by hand, so the guard does not allow it.
- at or above it, a raw number cannot be measuring the runner. Nothing in this suite honestly takes thirty
  seconds; an assertion at or above that only fires on a catastrophe, which is what
  `test_alert_report_review.py`'s documented sixty-second ceiling is for -- the north-star minute from
  `docs/operations.md`, a claim about the product rather than a complexity shape.

There is deliberately no list of the existing call sites. An allowlist is a second source of truth that drifts
(class 9), and it would have to be edited by exactly the change this guard exists to stop.

Three exemptions, all structural rather than per-file:

- `time.process_time` and `time.thread_time` measure CPU used by this process, which does not advance while the
  process is descheduled. They are immune to the defect, and `test_explain_stays_fast_on_hostile_input` already
  says so in its own comment. A wall clock is `perf_counter`, `monotonic` or `time`.
- a comparison against something that is not a number -- `elapsed < small * 8` -- is a ratio between two
  measurements taken on the same machine. That is the other correct fix, and the one G263 made.
- `tests/bounds.py` itself, which is where the comparisons now live.
"""

from __future__ import annotations

import ast
import pathlib

from tests import bounds

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"

#: Below this a hand-written wall-clock number is refused; see the module docstring. Tied to the helper's own
#: loosest ceiling so the two cannot drift apart.
FLOOR_SECONDS = bounds.MAX_CEILING_SECONDS
#: Clocks that advance while this process is not running, so a reading of one is partly a reading of the machine.
WALL_CLOCKS = frozenset({"perf_counter", "monotonic", "time", "perf_counter_ns", "monotonic_ns"})
#: Clocks that do not. Exempt.
CPU_CLOCKS = frozenset({"process_time", "thread_time", "process_time_ns", "thread_time_ns"})
#: This guard's own fixtures, and the module the comparisons moved into.
EXEMPT_FILES = frozenset({"bounds.py", pathlib.Path(__file__).name})


def _reads_a_wall_clock(node: ast.AST) -> bool:
    """``time.perf_counter()``, ``monotonic()`` or a bare ``time()`` anywhere inside ``node``."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            func = n.func
            name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            if name in CPU_CLOCKS:
                return False if node is n else _reads_a_wall_clock_excluding(node, n)
            if name in WALL_CLOCKS:
                return True
    return False


def _reads_a_wall_clock_excluding(node: ast.AST, cpu_call: ast.Call) -> bool:
    return any(
        isinstance(n, ast.Call)
        and n is not cpu_call
        and (n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")) in WALL_CLOCKS
        for n in ast.walk(node)
    )


def _clock_reading_helpers(tree: ast.Module) -> set[str]:
    """Functions in this module whose own body reads a wall clock.

    `test_a_padded_object_does_not_outrun_the_webhooks_timeout` is written as `elapsed, out = took(4000)`, where
    `took` does the timing. Without this the guard reads `elapsed` as an unknown and misses the comparison -- which
    it did, on the one site G263 had already thought about.
    """
    return {
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and _reads_a_wall_clock(n)
    }


def _clock_names(fn: ast.AST, helpers: frozenset[str] = frozenset()) -> set[str]:
    """Locals in ``fn`` assigned from a wall clock: `waited = time.monotonic() - started` and its kin.

    Without this the guard reads `assert waited < 3` as a comparison of two unknowns, which is the exact form the
    second proven flake was written in. ``helpers`` are functions that do the timing themselves, so a name
    assigned from calling one carries a clock reading too.
    """
    names: set[str] = set()
    for _ in range(3):  # a name assigned from a name assigned from a clock; three passes settle every case here
        for n in ast.walk(fn):
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(n, ast.Assign):
                targets, value = list(n.targets), n.value
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                targets, value = [n.target], n.value
            if value is None:
                continue
            carries = (
                _reads_a_wall_clock(value)
                or any(isinstance(x, ast.Name) and x.id in names for x in ast.walk(value))
                or any(
                    isinstance(x, ast.Call) and isinstance(x.func, ast.Name) and x.func.id in helpers
                    for x in ast.walk(value)
                )
            )
            if carries:
                names.update(t.id for t in targets if isinstance(t, ast.Name))
    return names


def _number(node: ast.expr, module_constants: dict[str, float]) -> float | None:
    """``node`` as a number, resolving a module-level `NAME = <number>`; None if it is not a plain number.

    A right-hand side that is not a number is a ratio against another measurement, which is exempt.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return float(node.value)
    if isinstance(node, ast.Name):
        return module_constants.get(node.id)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _number(node.operand, module_constants)
        return None if inner is None else -inner
    return None


def _module_constants(tree: ast.Module) -> dict[str, float]:
    out: dict[str, float] = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant):
            value = n.value.value
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                out.update({t.id: float(value) for t in n.targets if isinstance(t, ast.Name)})
    return out


def _enclosing(tree: ast.Module) -> dict[int, ast.AST]:
    """Line number -> the innermost function holding it, for resolving clock-carrying locals."""
    out: dict[int, ast.AST] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for line in range(n.lineno, (n.end_lineno or n.lineno) + 1):
                out[line] = n
    return out


def tight_wall_clock_assertions(root: pathlib.Path | None = None) -> list[str]:
    """Every `assert <wall clock> < <number below the floor>` under ``root``, as `file:line: text`."""
    bad: list[str] = []
    for path in sorted((root or TESTS).rglob("*.py")):
        if path.name in EXEMPT_FILES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants, holders = _module_constants(tree), _enclosing(tree)
        helpers = frozenset(_clock_reading_helpers(tree))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assert):
                continue
            holder = holders.get(node.lineno)
            clocks = _clock_names(holder, helpers) if holder is not None else set()
            for cmp in (x for x in ast.walk(node.test) if isinstance(x, ast.Compare)):
                for left, op, right in zip([cmp.left, *cmp.comparators], cmp.ops, cmp.comparators, strict=False):
                    measured, limit = (left, right) if isinstance(op, (ast.Lt, ast.LtE)) else (right, left)
                    if not isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                        continue
                    timed = _reads_a_wall_clock(measured) or any(
                        isinstance(x, ast.Name) and x.id in clocks for x in ast.walk(measured)
                    )
                    if not timed:
                        continue
                    seconds = _number(limit, constants)
                    if seconds is None or seconds >= FLOOR_SECONDS:
                        continue
                    bad.append(
                        f"{path.name}:{node.lineno}: `{ast.unparse(cmp)}` compares a wall clock against {seconds:g}s"
                    )
    return bad


def test_no_test_asserts_a_tight_wall_clock_budget() -> None:
    assert not tight_wall_clock_assertions(), (
        "a wall-clock comparison below "
        f"{FLOOR_SECONDS:g}s measures the runner as much as the code, and when it loses it reports a false "
        "failure -- the mirror image of the false pass this product exists to prevent:\n  "
        + "\n  ".join(tight_wall_clock_assertions())
        + "\nUse tests/bounds.py: `bounded` for a complexity shape, `within_deadline` for a deadline the code "
        "itself configures, `not_blocked_by` for a fast call that must not queue behind a slow one. If the real "
        "assertion is about bounded output rather than elapsed time, assert that instead and drop the clock."
    )


# --- the guard, proved against snippets rather than against the tree it is guarding -------------------------------

TIGHT = """
import time
def test_x() -> None:
    start = time.perf_counter()
    work()
    assert time.perf_counter() - start < 1.0
"""
TIGHT_VIA_LOCAL = """
import time
def test_x() -> None:
    started = time.monotonic()
    work()
    waited = time.monotonic() - started
    assert waited < 3, "the wait for a slot is bounded"
"""
TIGHT_VIA_CONSTANT = """
import time
CEILING = 2.5
def test_x() -> None:
    t = time.monotonic()
    work()
    assert time.monotonic() - t < CEILING
"""
TIGHT_REVERSED = """
import time
def test_x() -> None:
    t = time.monotonic()
    work()
    assert 0.5 > time.monotonic() - t
"""
TIGHT_VIA_HELPER = """
import time
def test_x() -> None:
    def took(n: int) -> float:
        start = time.perf_counter()
        work(n)
        return time.perf_counter() - start
    elapsed = took(4000)
    assert elapsed < 5.0
"""
TIGHT_INSIDE_AN_EXPRESSION = """
import time
def test_x() -> None:
    started = time.monotonic()
    r = run()
    assert r.done_at - started < 0.9, "it waited for the slow ones"
"""
CPU_CLOCK = """
import time
def test_x() -> None:
    start = time.process_time()
    work()
    assert time.process_time() - start < 3.0
"""
A_RATIO = """
import time
def test_x() -> None:
    small = measure(1000)
    elapsed = measure(4000)
    assert elapsed < small * 8
"""
GENEROUS = """
import time
def test_x() -> None:
    t = time.perf_counter()
    work()
    assert time.perf_counter() - t < 60.0
"""


def test_the_guard_sees_every_shape_of_tight_assertion(tmp_path: pathlib.Path) -> None:
    """The six shapes in this repository's history: the two that blocked merges, and the two a first version of
    this guard missed -- a local helper doing the timing, and a clock reading inside a larger expression."""
    for name, source in (
        ("a literal on the assert line", TIGHT),
        ("a local carrying the elapsed time", TIGHT_VIA_LOCAL),
        ("a module-level constant", TIGHT_VIA_CONSTANT),
        ("the comparison written the other way round", TIGHT_REVERSED),
        ("a local helper that does the timing", TIGHT_VIA_HELPER),
        ("a clock reading inside a larger expression", TIGHT_INSIDE_AN_EXPRESSION),
    ):
        room = tmp_path / name.replace(" ", "-")
        room.mkdir()
        (room / "test_snippet.py").write_text(source, encoding="utf-8")
        assert tight_wall_clock_assertions(room), f"the guard missed {name}"


def test_the_guard_lets_through_what_is_not_the_defect(tmp_path: pathlib.Path) -> None:
    """A CPU clock does not advance while the process is descheduled; a ratio and a catastrophe ceiling are the
    two fixes this guard is pushing people towards, so flagging them would make it useless."""
    for name, source in (
        ("a process_time budget", CPU_CLOCK),
        ("a ratio between two measurements", A_RATIO),
        (f"a ceiling at or above {FLOOR_SECONDS:g}s", GENEROUS),
    ):
        room = tmp_path / name.replace(" ", "-")
        room.mkdir()
        (room / "test_snippet.py").write_text(source, encoding="utf-8")
        assert not tight_wall_clock_assertions(room), (
            f"the guard wrongly flagged {name}: {tight_wall_clock_assertions(room)}"
        )


def test_the_guard_is_not_passing_because_it_found_nothing_to_look_at() -> None:
    """`tight_wall_clock_assertions` returning nothing has to mean the tree is clean, not that it was not read."""
    files = [p for p in TESTS.rglob("*.py") if p.name not in EXEMPT_FILES]
    assert len(files) > 100, f"only {len(files)} test files parsed; the guard would pass vacuously"
    timed = [p for p in files if "perf_counter" in p.read_text(encoding="utf-8")]
    assert timed, "no file reads a wall clock at all, so the guard has nothing to be a guard against"
