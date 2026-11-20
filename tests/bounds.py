"""A wall-clock assertion is a proxy for a complexity property, and a tight one measures the runner instead.

G263 established the rule for two call sites. This module generalises it to all of them.

`test_a_padded_object_does_not_outrun_the_webhooks_timeout` and `test_the_memory_demo_runs_offline_under_a_second`
were fixed by hand. Thirty-six wall-clock assertions stood in thirty-four tests; thirty-one of them below the
loosest ceiling this module will hand out, and two of those have since blocked merges:

- `test_hostile_and_oversized_input_is_bounded_and_fast` asserted `< 1.0` and measured 1.0239 s on one run and
  1.0607 s on another, blocking PR #77's `test (3.11)` job after the identical sha had gone 19 of 19 green on a
  `workflow_dispatch` run. The work it timed is 0.001 s here, so the assertion overshot by a factor of a thousand
  on a run where the code did nothing slow: it measured a second of descheduling, not a second of work.
- `test_a_post_that_cannot_get_a_slot_is_refused_with_503_within_the_wait` asserted `waited < 3` and measured
  3.1 s, with the server's own deadline monkeypatched to 0.3 s -- so the hard-coded 3 was ten times the thing it
  claimed to be checking and told nobody when it failed.

A false failure is the mirror image of the false pass this product exists to prevent, and the repository's own rule
-- never assert a precision you do not have -- applies to its tests. So a timing assertion here states the SHAPE of
the regression it guards against and lets that shape pick the ceiling.

How a ceiling is picked
-----------------------
Each `Shape` names the smallest regression the assertion has to catch, as a multiple of the honest time. The
ceiling is the geometric mean of 1x (the honest time) and that multiple, so the assertion sits exactly as far
above the noise as it sits below the regression:

    slack = sqrt(shape.catches_at)

A linear scan that turns quadratic is about `n` times the work, and these call sites run at n in the tens of
thousands, so `QUADRATIC.catches_at = 100` is conservative by two orders of magnitude and still yields a ceiling
ten times the honest time. A cap that stops being applied is only as large a regression as the cap's own ratio,
so `SMALL_MULTIPLE` admits far less slack -- and when that leaves no room at all, `VacuousBound` is raised and
says so rather than letting a meaningless assertion pass.

The environment enters twice, because the two things that go wrong on a shared runner are different in kind:

- multiplicatively, because a coverage tracer really does make the interpreter slower. Measured in this container
  on two of these call sites: 0.3067 s -> 0.2779 s for the regex-dominated ceph text scan (no cost at all, the
  work is inside `re`) and 0.3051 s -> 0.4613 s for the Python-object-heavy SARIF merge (1.51x). `SLOWDOWN` is set
  above the worst measured, because which call site is which is not knowable from here.
- additively, because a shared runner does not slow the process down, it stops running it. The ceph flake is the
  proof: 0.001 s of work, 1.0607 s observed. No multiplier models that; an allowance for a stall does.

So: `ceiling = honest x slack x SLOWDOWN + STALL_ALLOWANCE`, clamped into `[MIN_CEILING, MAX_CEILING]`.

Both environment terms are read once, at import, from the environment and from whether a coverage tracer is
loaded. They are frozen into module constants, so no fixture, no `monkeypatch` and no test ordering can change
what a later test's ceiling is -- a calibration loop would have given a ceiling that depended on what else the
runner was doing at the moment it ran, which is the defect, not the fix.

What this catches, and what it does not
---------------------------------------
It catches a regression that multiplies the work by at least `shape.catches_at`: a linear scan turning quadratic
or cubic, a cap no longer applied, a backtracking pattern reintroduced, a wait that ignores its deadline, a hang.

It does NOT catch, and is not asked to:

- a wrong answer produced quickly. Only the deterministic assertions inside the block do that, which is why every
  call site keeps them and why several call sites kept only them.
- work that got FASTER by being skipped. A rule that stops firing, a scan that returns early, a cap that drops
  everything: all of those make the timer happier. This is the important one, because it is the shape of a false
  pass, and no timer anywhere can see it.
- a regression smaller than `shape.catches_at`. A 3x slowdown passes every ceiling here, deliberately.
- anything at all about absolute performance. These are not budgets. `kube-noob`'s performance claims are tested
  by `tests/test_admission.py`'s ratio assertion, which compares two sizes on the same machine.

And a ceiling is not always the right tool. Where the honest cost is itself seconds, `MAX_CEILING_SECONDS` caps
the ceiling below the slack the shape asked for, and the result can be a false failure rather than a guard:
`test_diagnose_lists_its_signals_and_stays_fast_on_hostile_text` costs 5.0 s honestly, the linear shape asks for
104 s, the cap gives 30 s, and it crossed that in three of twenty-five runs under load. That one is a ratio now --
half and full of each input, back to back on the same machine, so a stall slows both and the verdict stays about
the code. Two more sites are in the same position and have not crossed their cap (the 20,000-event must-gather at
23.9 s and the megabyte sanitize pastes at 18.4 s, worst of twenty-five runs each), so they keep the ceiling they
already had; `bounded`'s failure says when the cap, rather than the derivation, is what was crossed.
"""

from __future__ import annotations

import dataclasses
import math
import os
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

#: No ceiling below this is about the code. The two proven flakes overshot by 1.06 s and 0.1 s on work measured at
#: 0.001 s and at nothing; a container's CFS quota slice, a GC pause and a co-tenant's burst are each tens to
#: hundreds of milliseconds, and they add. Measured on the two-core build machine for comparison: one millisecond
#: of work, repeated two thousand times under four times oversubscription, overshot by at most eleven
#: milliseconds -- a development machine does not produce the stall a hosted runner does, which is why the
#: shared-runner allowance below is set from the runner observation and not from a local measurement.
MIN_CEILING_SECONDS = 0.5
#: Above this a ceiling asserts nothing new: the CI job's own step timeout and the suite's runtime bite first, so a
#: longer ceiling only delays the same failure. It is also the number this repository already chose by hand for
#: "loose enough that only a hang trips it" (`test_the_memory_demo_runs_offline_under_a_second`, G263), so a
#: `NO_HANG` site lands on the ceiling it already had. A call site that honestly needs more than this has to
#: assert a ratio instead (`tests/test_admission.py`), not a bigger number. It is also the floor the structural
#: guard enforces on a hand-written number (`tests/test_timing_assertions.py`), so the two cannot drift apart:
#: below the loosest ceiling the helper will hand out there is no reason to write one by hand.
MAX_CEILING_SECONDS = 30.0


def _under_coverage() -> bool:
    """A coverage tracer is loaded. CI runs `pytest --cov` with `branch = true`; a developer usually does not."""
    return "coverage" in sys.modules or bool(os.environ.get("COVERAGE_RUN") or os.environ.get("COV_CORE_SOURCE"))


def _on_shared_runner() -> bool:
    """GitHub Actions sets both of these; so does every other hosted CI this repository is likely to meet."""
    return bool(os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI"))


def _slowdown() -> float:
    override = os.environ.get("KUBE_NOOB_TEST_SLOWDOWN")
    if override:
        return max(float(override), 1.0)
    return 2.0 if _under_coverage() else 1.0


def _stall_allowance() -> float:
    """Seconds a shared runner may simply not run this process for.

    2.0 s is twice the one stall that has actually failed a merge here (1.0607 s of wall clock across 0.001 s of
    work, PR #77's `test (3.11)`). It is the shared-runner value that gets the margin, because that is where the
    evidence is: two thousand repetitions of a millisecond of work on the two-core build machine, under four times
    oversubscription, never overshot by more than eleven milliseconds, so a local measurement would have set this
    far too low. The cost of being generous is only that a regression has to be larger to be caught, and
    `VacuousBound` refuses the call site when the generosity has eaten the signal.
    """
    override = os.environ.get("KUBE_NOOB_TEST_STALL_ALLOWANCE")
    if override:
        return max(float(override), 0.0)
    return 2.0 if _on_shared_runner() else MIN_CEILING_SECONDS


#: Frozen at import: see the module docstring on why this is not measured per session.
SLOWDOWN = _slowdown()
STALL_ALLOWANCE = _stall_allowance()


@dataclasses.dataclass(frozen=True)
class Shape:
    """The shape of the work a call site guards, and the smallest regression the assertion must catch.

    ``catches_at`` is that regression as a multiple of the honest time. It is a deliberate under-estimate: the real
    regression at these input sizes is larger, and claiming less than is true is what leaves the ceiling room.
    """

    name: str
    catches_at: float
    regression: str

    @property
    def slack(self) -> float:
        """How far above the honest time the ceiling sits: as far above the noise as below the regression."""
        return math.sqrt(self.catches_at)


#: Work linear in the size of the input. A regression to quadratic is about `n` times the work, and every call site
#: using this runs at `n` in the thousands or more, so 100x is conservative by orders of magnitude.
LINEAR = Shape("linear", 100.0, "a scan linear in the input turning quadratic")
#: Work linear in two dimensions at once -- a scan over objects that each look at a shared index. The regression
#: G252 and the attack-path scan both hit is cubic, which took minutes where the fixed form takes seconds.
CUBIC_RISK = Shape("cubic-risk", 1000.0, "a bounded scan turning quadratic or cubic (minutes, not milliseconds)")
#: A regular expression, or a parser standing in for one, against input built to make it backtrack. The blowup is
#: exponential rather than a multiple of anything: the Makefile line in `test_verify.py` took 62 s where the reader
#: that replaced the pattern takes microseconds, which is more than ten thousand times. Use this only where the
#: honest time really is microseconds -- the large slack then lands on `MIN_CEILING_SECONDS` anyway, which is the
#: right ceiling for work that is instant when it is correct. Where the honest time is a tenth of a second or more,
#: `LINEAR` is the shape: its ceiling catches a quadratic regression too, and a blowup is far past either.
BACKTRACKING = Shape("backtracking", 10_000.0, "catastrophic backtracking reintroduced (62 s for one line, here)")
#: A regression that is only a small multiple -- about twenty-five times -- of the honest time. Two kinds here: a
#: cap on how much is examined no longer being applied, which is only as large as the cap's own ratio; and a
#: per-line scan going quadratic in a 600-character line, measured at 92 ms against 4 ms honest in
#: `tests/test_capability_routes.py` (G252). Little room, so where a deterministic assertion carries the same
#: contract, prefer it -- and where there is no room at all, `VacuousBound` says so instead of passing.
SMALL_MULTIPLE = Shape("small-multiple", 25.0, "a cap no longer applied, or a line scan turning quadratic (~25x)")
#: A fixed amount of work whatever the input: the input is refused, or read once, before anything scales with it.
#: The regression is that it starts scaling, and the measured cost of that here was 62 s for one Makefile line
#: against the microseconds the refusal takes -- more than ten thousand times, not a small multiple.
FIXED_WORK = Shape("fixed-work", 10_000.0, "an input that is refused being read after all (62 s for one, here)")
#: Nothing is being measured except that the thing finishes. The assertions beside it carry the whole contract and
#: the clock is here only so that a hang is a failure rather than a job that runs until CI kills it.
NO_HANG = Shape("no-hang", 1_000_000.0, "a hang, a deadlock, or a reach for something that is not there")


class VacuousBound(AssertionError):
    """The ceiling a shape and an environment produced cannot catch the regression the shape names.

    Raised instead of passing. A timing assertion that cannot fail for any regression it is written for is worse
    than no assertion: it reads as a guard in review and it is not one. The call site has to either keep a strict
    assertion with its reason stated, or drop the clock and rely on its deterministic assertions.
    """


def derived_ceiling(shape: Shape, honest_seconds: float) -> float:
    """What the shape and the environment ask for, before the clamps."""
    return honest_seconds * shape.slack * SLOWDOWN + STALL_ALLOWANCE


def ceiling_for(shape: Shape, honest_seconds: float) -> float:
    """The ceiling this shape and this environment give work that honestly takes ``honest_seconds``.

    `MAX_CEILING_SECONDS` can clamp this BELOW what the shape asked for, and then the shape is no longer what sets
    the ceiling. Three call sites are in that position -- the four 400 KB diagnose pastes, the 20,000-event
    must-gather and the megabyte sanitize pastes all honestly cost seconds, so ten times that is past the cap. For
    those the ceiling is the number the test already had, the helper adds the message and the vacuity check rather
    than headroom, and `bounded`'s failure says the ceiling was capped so the reader is not told a derivation that
    did not happen. The four-400-KB site is the suite's slowest timed block and its most likely next false
    failure: it measured 32.5 s, 35.7 s and 37.1 s against this 30 s cap in three of sixteen runs with five other
    pytest processes and a full suite run competing for two cores. Raising the cap was considered and rejected --
    it would loosen `test_the_memory_demo_runs_offline_under_a_second` from the 30 s G263 chose to 60 s and
    `test_reach_and_scan_of_16000_objects_take_seconds_not_hours` from 20 s to 60 s, which is a weakening of two
    deliberate numbers to buy headroom only an oversubscribed developer machine needs.
    """
    return min(max(derived_ceiling(shape, honest_seconds), MIN_CEILING_SECONDS), MAX_CEILING_SECONDS)


def _report(where: str, shape: str, elapsed: float, ceiling: float) -> None:
    """With ``KUBE_NOOB_TEST_BOUNDS_REPORT`` set, print what each block actually took.

    How ``honest_seconds`` is re-measured when work legitimately changes, rather than guessed:
    ``KUBE_NOOB_TEST_BOUNDS_REPORT=1 pytest tests/... -s | grep kube-noob-bounds``.
    """
    if os.environ.get("KUBE_NOOB_TEST_BOUNDS_REPORT"):
        print(f"kube-noob-bounds {where} shape={shape} elapsed={elapsed:.4f} ceiling={ceiling:.4f}", flush=True)


def _caller() -> str:
    frame = sys._getframe(3)
    return f"{os.path.basename(frame.f_code.co_filename)}:{frame.f_lineno}"


def _environment() -> str:
    return (
        f"x{SLOWDOWN:g} for the interpreter here"
        f"{' (a coverage tracer is loaded)' if _under_coverage() else ''}"
        f" + {STALL_ALLOWANCE:g}s allowed for a stall"
        f"{' on a shared runner' if _on_shared_runner() else ''}"
    )


@contextmanager
def bounded(shape: Shape, *, honest_seconds: float, guards: str) -> Iterator[None]:
    """Fail if the block takes long enough to mean ``shape``'s regression, and not before.

    ``honest_seconds`` is a MEASUREMENT of the block on a correct implementation, not a budget: update it when the
    work legitimately changes, never to make a failure go away. ``guards`` says, in the call site's own words, what
    regression this is here to catch; it is printed when the assertion fires, because `assert 1.06 < 1.0` is why
    these have been dismissed as flakes rather than read.
    """
    ceiling = ceiling_for(shape, honest_seconds)
    detectable = honest_seconds * shape.catches_at
    if ceiling >= detectable:
        raise VacuousBound(
            f"a {shape.name} ceiling of {ceiling:.2f}s cannot catch {shape.regression}, which at "
            f"{honest_seconds:.3f}s of honest work would take about {detectable:.2f}s. "
            f"{_environment()}. Drop the clock and rely on this block's deterministic assertions, or keep a "
            f"strict assertion and say in the test why it is safe -- do not loosen this one until it passes."
        )
    start = time.perf_counter()
    yield
    elapsed = time.perf_counter() - start
    _report(_caller(), shape.name, elapsed, ceiling)
    if elapsed >= ceiling:
        asked = derived_ceiling(shape, honest_seconds)
        capped = (
            f" The shape asked for {asked:.1f}s and `MAX_CEILING_SECONDS` capped it at {ceiling:.2f}s, so the cap "
            f"is what you crossed, not the derivation: this block honestly costs {honest_seconds:.3f}s and the cap "
            f"leaves it only {ceiling / max(honest_seconds, 1e-9):.1f}x."
            if asked > ceiling
            else f" The headroom above the honest time is {ceiling - honest_seconds * shape.slack * SLOWDOWN:.2f}s."
        )
        raise AssertionError(
            f"{elapsed:.2f}s, over a ceiling of {ceiling:.2f}s. This assertion guards {guards}; the shape is "
            f"{shape.name}, so it is written to catch {shape.regression}. The ceiling is {honest_seconds:.3f}s "
            f"measured honest x{shape.slack:.1f} ({_environment()}).{capped} At {elapsed:.2f}s the work has "
            f"regressed by at least {elapsed / max(honest_seconds, 1e-9):.0f}x, or this machine is more loaded "
            f"than a shared runner; check the former before assuming the latter."
        )


@contextmanager
def within_deadline(*, deadline_seconds: float, source: str, ignored_would_take: float, guards: str) -> Iterator[None]:
    """Fail if the block outlives a deadline the CODE ITSELF configures.

    Different in kind from `bounded`: the claim is not about how fast the machine is but about whether the code
    honours its own bound, so the ceiling is derived from that bound. The block must hold ONLY the waiting: a
    ceiling derived from a deadline measures that deadline and nothing else, so any set-up -- building a server,
    loading a catalogue, writing a fixture -- goes outside it or the ceiling is a budget again. ``source`` names
    the constant it came from,
    so a test cannot drift away from the value it is asserting about. ``ignored_would_take`` is how long the block
    takes if the bound is ignored -- the regression -- and the ceiling is refused if it has grown past it.
    ``guards`` is printed on failure, in the call site's own words.
    """
    ceiling = min(deadline_seconds * 2.0 + STALL_ALLOWANCE, MAX_CEILING_SECONDS)
    if ceiling >= ignored_would_take:
        raise VacuousBound(
            f"a ceiling of {ceiling:.2f}s cannot tell a deadline of {deadline_seconds:g}s ({source}) from one "
            f"ignored, which would take about {ignored_would_take:g}s. {_environment()}"
        )
    start = time.monotonic()
    yield
    elapsed = time.monotonic() - start
    _report(_caller(), f"deadline({deadline_seconds:g}s)", elapsed, ceiling)
    if elapsed >= ceiling:
        raise AssertionError(
            f"{elapsed:.2f}s, over a ceiling of {ceiling:.2f}s for a deadline of {deadline_seconds:g}s "
            f"({source}). This assertion guards {guards}: ignoring the deadline would take about "
            f"{ignored_would_take:g}s. {_environment()}"
        )


#: The ceiling a contrast assertion gets: enough room for the interpreter here and for a stall, and no more. The
#: slow side has to be at least twice this, or the contrast is smaller than the noise and `not_blocked_by` refuses.
CONTRAST_CEILING_SECONDS = MIN_CEILING_SECONDS + STALL_ALLOWANCE


@contextmanager
def not_blocked_by(*, blocked_seconds: float, source: str, guards: str) -> Iterator[None]:
    """Fail if a fast operation took long enough to mean it waited behind a slow one.

    Third in kind. `bounded` and `within_deadline` have an upper bound they can be generous about; this one does
    not, because its whole signal is the GAP between "answered straight away" and "answered after the slow thing
    finished". Raising the ceiling here does not buy stability, it erases the assertion -- so the ceiling is fixed
    at what this environment needs and the SLOW side is what has to be big enough. ``blocked_seconds`` is how long
    the operation takes if it does wait, from the constant named in ``source``; the call site is refused if that is
    not at least twice the ceiling, which is the honest way to say "make the blocking operation slower".
    """
    ceiling = CONTRAST_CEILING_SECONDS
    if blocked_seconds < 2 * ceiling:
        raise VacuousBound(
            f"a blocked call would take about {blocked_seconds:g}s ({source}), which is not twice the "
            f"{ceiling:.2f}s this environment needs for a ceiling ({_environment()}), so a pass here would not "
            f"mean the call was not blocked. Raise the blocking side to at least {2 * ceiling:.2f}s."
        )
    start = time.perf_counter()
    yield
    elapsed = time.perf_counter() - start
    _report(_caller(), f"contrast(blocked~{blocked_seconds:g}s)", elapsed, ceiling)
    if elapsed >= ceiling:
        raise AssertionError(
            f"{elapsed:.2f}s, over a ceiling of {ceiling:.2f}s. This assertion guards {guards}: a call that waited "
            f"behind the slow side would take about {blocked_seconds:g}s ({source}), a call that did not takes "
            f"almost nothing. At {elapsed:.2f}s it is between the two, so read it rather than retrying -- either "
            f"it was partly blocked, or this machine stalled for over {ceiling:.2f}s. {_environment()}"
        )
