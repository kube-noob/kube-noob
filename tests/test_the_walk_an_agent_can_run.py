"""The mechanism walk had no MCP tool, so no agent and no browser could run it.

`learn mechanism` shipped as a command only. The MCP surface carried nine learning tools and not this one, which
means the Claude plugin, any MCP client and the website's playground -- which runs kube-noob's real tools in a Web
Worker and can only call tools by name -- could not walk a hop chain at all. The one answer in this product that
says WHERE a path stops being knowable was reachable from a terminal and nowhere else.

The lookup, the audit and the walk now live in `Toolkit.mechanism`, and `cli.py` calls it. That is the point of
`test_the_command_and_the_tool_give_the_same_answer`: two surfaces over one path is the second-source defect
(class 9), and the way to hold it is to compare the answers, not to grep for the call.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from kube_noob import toolkit as tk
from kube_noob.config import load_settings

ROOT = Path(__file__).resolve().parents[1]
INSECURE = ROOT / "examples" / "insecure-deployment.yaml"
MECHANISM = "mech-net-request-to-pod"


def _kit(tmp_path: Path) -> tk.Toolkit:
    return tk.Toolkit(load_settings(overrides={"offline": True, "dataDir": str(tmp_path / "data")}))


def _spec(kit: tk.Toolkit) -> object:
    by_name = {s.name: s for s in kit.specs()}
    assert "learn_mechanism" in by_name, (
        f"the mechanism walk has no MCP tool; the surface has {sorted(n for n in by_name if 'learn' in n)}"
    )
    return by_name["learn_mechanism"]


def test_the_walk_is_an_mcp_tool(tmp_path: Path) -> None:
    """Without this the walk is a terminal-only answer, and the playground cannot reach it."""
    _spec(_kit(tmp_path))


def test_the_tool_writes_nothing(tmp_path: Path) -> None:
    """A walk is a reading. It records no progress and earns no credits, so it is read-only on a shared server.

    Measured, not asserted from the flag: the data folder is compared before and after.
    """
    kit = _kit(tmp_path)
    spec = _spec(kit)
    assert getattr(spec, "read_only", False) is True, "the walk writes nothing, so its tool has to say so"
    data = tmp_path / "data"
    before = sorted(p.relative_to(tmp_path).as_posix() for p in data.rglob("*")) if data.exists() else []
    kit.mechanism(tk.MechanismIn(mechanism_id=MECHANISM, manifests=INSECURE.read_text("utf-8")))
    after = sorted(p.relative_to(tmp_path).as_posix() for p in data.rglob("*")) if data.exists() else []
    assert after == before, f"the walk wrote to the data folder: {sorted(set(after) - set(before))}"


def test_a_stopped_walk_says_stopped_and_names_the_hop(tmp_path: Path) -> None:
    """The answer the tool exists for: not a pass, not a failure, and it says which hop went unanswered."""
    out = _kit(tmp_path).mechanism(tk.MechanismIn(mechanism_id=MECHANISM, manifests=INSECURE.read_text("utf-8")))
    assert out["verdict"] == "stopped", f"verdict was {out['verdict']!r}"
    assert out["exitCode"] == 5, f"exitCode was {out['exitCode']!r}"
    assert out.get("stoppedAt"), "a stopped walk that does not name the hop is an unanswered question with no address"
    hops = [str(step["step"]) for step in out["steps"]]
    assert out["stoppedAt"] in hops, f"stoppedAt {out['stoppedAt']!r} is not among the hops reported: {hops}"
    assert out["stoppedAt"] == hops[-1], f"the walk reported hops past the stop: {hops}"
    # The hops after the stop are not in `steps` at all, and that absence has to be counted rather than left to
    # be noticed. `counts.notReached` is what makes it legible: an agent reading one `cannot-judge` hop and no
    # tally could take the path for a one-hop path. The identity below is the whole accounting.
    counts = out["counts"]
    assert counts["declared"] == len(out["steps"]) + counts["notReached"], (
        f"the hops do not add up: {counts} against {len(out['steps'])} reported"
    )
    assert counts["notReached"] > 0, "a stopped walk that reached every hop is not a stopped walk"
    assert counts["judged"] == 0 or all(step["verdict"] != "holds" for step in out["steps"][-1:]), (
        "the hop the walk stopped at was reported as holding"
    )


def test_the_command_and_the_tool_give_the_same_answer(tmp_path: Path) -> None:
    """One path, one answer.

    `cli.py` held its own copy of the lookup and the walk. Two surfaces computing the same verdict separately is
    the defect `docs/review-classes.md` numbers 9, and the guard is to compare what they SAY -- a test that
    grepped the CLI for the call would pass on a reimplementation that drifts.
    """
    done = subprocess.run(
        [sys.executable, "-m", "kube_noob", "--format", "json", "learn", "mechanism", MECHANISM, "-f", str(INSECURE)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"), "KUBE_NOOB_OFFLINE": "1"},
        check=False,
        timeout=300,
    )
    assert done.returncode == 5, f"the command exited {done.returncode}: {done.stderr[-400:]}"
    from_command = json.loads(done.stdout)
    from_tool = _kit(tmp_path).mechanism(tk.MechanismIn(mechanism_id=MECHANISM, manifests=INSECURE.read_text("utf-8")))
    assert from_command == from_tool, "the command and the tool disagree about the same path"


def test_a_fragment_is_not_told_its_namespace_is_missing_something(tmp_path: Path) -> None:
    """The difference `partial_bundle` makes on a walk is a VERDICT, not a count.

    `audit` has always had this input: a directory is a whole namespace, one file is a fragment, and
    `cli._partial_input` decides. The tool shipped without it, so every call declared the pasted text complete
    -- and on a walk that is not a softer number, it is the opposite answer. Measured on a bundle with no
    NetworkPolicy:

        partial_bundle=True   hop `policy-admits-the-packet` -> cannot-judge, verdict stopped, exit 5
                              "KN-N001, KN-N007, KN-N012 reached no verdict here: part of a namespace was passed"
        partial_bundle=False  hop `policy-admits-the-packet` -> fails,        verdict broken,  exit 1
                              "KN-N001 found something on this hop"

    A reader who pastes one Deployment into the browser playground has not told anyone their namespace lacks a
    NetworkPolicy. Reporting that hop BROKEN claims it does, from evidence that cannot say so -- the product's
    own rule, pointed the other way round: an absence read as a FINDING rather than as a pass.
    """
    bundle = (ROOT / "tests" / "fixtures" / "mechanism" / "complete.yaml").read_text("utf-8")
    without = bundle[: bundle.index("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy")]
    kit = _kit(tmp_path)

    def hop(partial: bool) -> dict[str, object]:
        walked = kit.mechanism(tk.MechanismIn(mechanism_id=MECHANISM, manifests=without, partial_bundle=partial))
        found = [s for s in walked["steps"] if s["step"] == "policy-admits-the-packet"]
        assert found, f"the policy hop was not reached at all: {[s['step'] for s in walked['steps']]}"
        return {"verdict": walked["verdict"], "exit": walked["exitCode"], "hop": found[0]["verdict"]}

    fragment, whole = hop(True), hop(False)
    assert fragment == {"verdict": "stopped", "exit": 5, "hop": "cannot-judge"}, fragment
    assert whole == {"verdict": "broken", "exit": 1, "hop": "fails"}, whole


def test_a_pasted_bundle_is_a_fragment_unless_the_caller_says_otherwise(tmp_path: Path) -> None:
    """The default is the safe direction, and the safe direction is the one that withholds.

    If this ever flips, a caller who says nothing gets `broken` where the honest answer is `cannot judge`, and
    the page tells readers their clusters are missing objects they never mentioned.
    """
    assert tk.MechanismIn(mechanism_id=MECHANISM, manifests="a: 1").partial_bundle is True
    bundle = (ROOT / "tests" / "fixtures" / "mechanism" / "complete.yaml").read_text("utf-8")
    without = bundle[: bundle.index("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy")]
    defaulted = _kit(tmp_path).mechanism(tk.MechanismIn(mechanism_id=MECHANISM, manifests=without))
    assert defaulted["verdict"] == "stopped", (
        f"a caller who said nothing got {defaulted['verdict']!r}; the default has to withhold, not accuse"
    )


def test_an_unknown_mechanism_names_the_ones_this_build_has(tmp_path: Path) -> None:
    """ "No such mechanism" with no list is a dead end; the caller cannot tell a typo from a missing lesson."""
    with pytest.raises(KeyError) as raised:
        _kit(tmp_path).mechanism(tk.MechanismIn(mechanism_id="no-such-path", manifests="a: 1"))
    said = str(raised.value.args[0])
    assert "no-such-path" in said, said
    assert MECHANISM in said, f"the refusal lists no known mechanism: {said}"


def test_the_description_tells_a_client_that_stopped_is_not_a_pass() -> None:
    """The description is what an agent reads before it calls this. It has to carry the rule, not just the shape."""
    said = str(getattr(_spec(tk.Toolkit(load_settings(overrides={"offline": True}))), "description", ""))
    for phrase in ("stopped", "not checked", "neither a pass nor a failure", "stoppedAt"):
        assert phrase in said, f"the tool description never says {phrase!r}: {said}"
