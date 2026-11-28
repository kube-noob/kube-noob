"""An answer that arrives after the API server stopped waiting is not an answer (G441).

The red team's Pod with 8,000 privileged containers (607 KB) took 4.4 s through `admission.review_bytes`, and a
megabyte took 8 to 9 s. The chart's `timeoutSeconds` is 3 and its `failurePolicy` was `Ignore`, so the API server
gave up and admitted the object with no warning: the denial was right and nobody received it. G337 fixed the
cases the webhook can see ("admitted what it could not evaluate, and said nothing"); a timeout is the one it
cannot see, so the webhook has to answer before it.

Three things, each held here:

- the hot path. Two thirds of that time was `load_documents(json.dumps(obj))` -- writing the parsed object out
  and parsing it again with a pure-Python YAML composer. `documents_from_objects` builds the same documents from
  the object, and is held equal to the round trip on every rule fixture, because work that got faster by being
  skipped is the one regression no clock can see (`tests/bounds.py`).
- a budget. An object of more than `MAX_OBJECT_NODES` values, a request of more than `MAX_BODY` bytes, or an
  evaluation that has used up `Config.deadline` is not judged, and the answer says so at once.
- what "not judged" means. With a rule enforced it is a denial, with the reason; in warn mode, which cannot
  deny, it is an admission with a warning. Never `allowed: true` and nothing else.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import admission as adm
from kube_noob import yamlio
from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Stage
from tests import bounds

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "tests" / "fixtures" / "rules"
CHART = ROOT / "deploy" / "helm" / "kube-noob"

#: Measured before G441 on these exact bodies, `admission.review_bytes`, warm, the build container: the Pod of
#: 16,000 privileged containers (1.25 MB) took 6.29 s and the Pod of one container with 30,000 environment
#: variables (1.01 MB) took 4.04 s -- the red team measured 9.42 s and 7.98 s for the same two shapes. After:
#: 0.04 s each, both refused by the node budget. (With the second parse gone and no budget they would take about
#: 2.2 s and 0.15 s: faster, and for the first still past a 1.8 s deadline, which is why there is a budget.)
BEFORE_16000_CONTAINERS = 6.29
BEFORE_30000_ENV = 4.04


def _pod(containers: int = 1, env: int = 0, annotation: int = 0, privileged: bool = True) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": "p", "namespace": "shop"}
    if annotation:
        meta["annotations"] = {"pad": "x" * annotation}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": meta,
        "spec": {
            "containers": [
                {
                    "name": f"c{i}",
                    "image": "nginx",
                    "securityContext": {"privileged": privileged},
                    **({"env": [{"name": f"E{j}", "value": "v"} for j in range(env)]} if env else {}),
                }
                for i in range(containers)
            ]
        },
    }


def _review(obj: Any, op: str = "CREATE", ns: str = "shop", old: Any = None, **extra: Any) -> dict[str, Any]:
    req: dict[str, Any] = {
        "uid": "u-441",
        "operation": op,
        "namespace": ns,
        "userInfo": {"username": "dev"},
        "object": obj,
        **extra,
    }
    if old is not None:
        req["oldObject"] = old
    return {"apiVersion": adm.API_VERSION, "kind": "AdmissionReview", "request": req}


def _body(obj: Any, **kwargs: Any) -> bytes:
    return json.dumps(_review(obj, **kwargs)).encode()


def _nodes(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + sum(_nodes(v) for v in value.values())
    if isinstance(value, list):
        return 1 + sum(_nodes(v) for v in value)
    return 1


def _not_judged(out: dict[str, Any], cfg: adm.Config) -> dict[str, Any]:
    """The answer for a request the webhook did not evaluate: never a bare `allowed: true`."""
    r: dict[str, Any] = out["response"]
    said = [w for w in r.get("warnings", []) if w.startswith(adm.NOT_EVALUATED)]
    assert said, r
    assert all(len(w) <= adm.WARNING_CHARS for w in r["warnings"])
    if cfg.enforce:
        assert r["allowed"] is False and r["status"]["code"] == 403
        assert "did not evaluate" in r["status"]["message"]
        for rule in cfg.enforce:
            assert rule in r["status"]["message"], "the denial names what is enforced"
    else:
        assert r["allowed"] is True and "status" not in r, "warn mode cannot deny"
    return r


ENFORCING = adm.Config.build(enforce=["KN-S001"])
WARNING = adm.Config.build()


def test_a_megabyte_pod_is_answered_inside_the_webhooks_deadline() -> None:
    """The red team's two megabyte Pods and a third that is a megabyte of annotation, through `review_bytes`.

    The ceiling is derived from the deadline the webhook itself configures (`Config.deadline`, three fifths of
    the chart's `timeoutSeconds`), and it is refused as vacuous unless the times measured before the change are
    past it. The clock is not the whole assertion: each answer is checked for what it says."""
    many = _body(_pod(containers=16_000))
    wide = _body(_pod(env=30_000))
    padded = _body(_pod(annotation=1_000_000))
    assert len(many) > 1_200_000 and len(wide) > 1_000_000 and len(padded) > 1_000_000
    adm.review_bytes(_body(_pod()), ENFORCING)  # imports and cold caches are not what is being timed
    answers: dict[str, dict[str, Any]] = {}
    with bounds.within_deadline(
        deadline_seconds=ENFORCING.deadline,
        source="admission.Config.deadline for the chart's default admission.timeoutSeconds: 3",
        ignored_would_take=BEFORE_16000_CONTAINERS + BEFORE_30000_ENV,
        guards="three megabyte Pods through admission.review_bytes, enforce mode",
    ):
        for name, body in (("many", many), ("wide", wide), ("padded", padded)):
            answers[name] = adm.review_bytes(body, ENFORCING, deadline_seconds=ENFORCING.deadline)
    assert ENFORCING.deadline < ENFORCING.timeout_seconds == 3
    for name in ("many", "wide"):
        r = _not_judged(answers[name], ENFORCING)
        assert r["uid"] == "u-441" and "values" in r["status"]["message"], name
    # A megabyte is not the budget: one container under a megabyte of annotation is four values more than a
    # small Pod, so it is judged, and denied for the rule it breaks.
    r = answers["padded"]["response"]
    assert r["allowed"] is False and "[KN-S001]" in r["status"]["message"]
    assert not any(w.startswith(adm.NOT_EVALUATED) for w in r["warnings"])
    # Warn mode: the same two are admitted, and say that nothing was judged.
    for body in (many, wide):
        _not_judged(adm.review_bytes(body, WARNING), WARNING)


def test_the_node_budget_is_exact_and_does_not_outrank_a_skip() -> None:
    probe = _pod(containers=1)
    per_container = _nodes(_pod(containers=2)) - _nodes(probe)
    fits = (adm.MAX_OBJECT_NODES - _nodes(probe)) // per_container + 1
    at, over = _pod(containers=fits), _pod(containers=fits + 1)
    assert _nodes(at) <= adm.MAX_OBJECT_NODES < _nodes(over)
    judged = adm.review_bytes(_body(at), ENFORCING)["response"]
    assert judged["allowed"] is False and "[KN-S001]" in judged["status"]["message"], "at the budget: judged"
    assert not any(w.startswith(adm.NOT_EVALUATED) for w in judged["warnings"])
    for cfg in (ENFORCING, WARNING):
        r = _not_judged(adm.review_bytes(_body(over), cfg), cfg)
        assert str(adm.MAX_OBJECT_NODES) in " ".join(r["warnings"]).replace(",", "")
    # the old object is evaluated too, so it is counted too
    small = _pod(privileged=False)
    _not_judged(adm.review_bytes(_body(small, op="UPDATE", old=over), ENFORCING), ENFORCING)
    # ... and the object is counted once, not once per kind of container: a clean object over budget is not judged
    _not_judged(adm.review_bytes(_body(_pod(containers=fits + 1, privileged=False)), ENFORCING), ENFORCING)
    # A request the webhook skips costs nothing, so the budget has no say in it.
    skipped = {"uid": "u-441", "allowed": True}
    assert adm.review_bytes(_body(over, ns="kube-system"), ENFORCING)["response"] == skipped
    assert adm.review_bytes(_body(over, op="DELETE"), ENFORCING)["response"] == skipped
    assert adm.review_bytes(_body(over, subResource="status"), ENFORCING)["response"] == skipped


def test_a_request_the_webhook_cannot_read_is_not_admitted_as_if_it_had_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every path that used to end in "...; admitted" whatever was enforced."""
    huge = b'{"request": {"uid": "u", "object": {"metadata": {"annotations": {"a": "' + b"x" * adm.MAX_BODY + b'"}}}}}'
    deep = ("[" * 5000 + "]" * 5000).encode()
    for cfg in (ENFORCING, WARNING):
        for body, why in (
            (huge, "larger than"),
            (b"nope", "not JSON"),
            (deep, "not JSON"),
            (b"[]", "not an AdmissionReview"),
            (b'{"request": 7}', "not an AdmissionReview"),
        ):
            r = _not_judged(adm.review_bytes(body, cfg), cfg)
            assert why in " ".join(r["warnings"]), (why, r)
    # a rule that raises, and an object past the parser's own limits
    nested: Any = "x"
    for _ in range(yamlio.MAX_DEPTH + 5):
        nested = {"a": nested}
    for cfg in (ENFORCING, WARNING):
        r = _not_judged(adm.review(_review({**_pod(), "spec": {"containers": [], "x": nested}}), cfg), cfg)
        assert "ManifestError" in " ".join(r["warnings"])

    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("a rule crashed on what the requester sent")

    monkeypatch.setattr(adm, "_findings", boom)
    for cfg in (ENFORCING, WARNING):
        r = _not_judged(adm.review(_review(_pod()), cfg), cfg)
        assert "RuntimeError" in " ".join(r["warnings"]) and "requester sent" not in json.dumps(r)
        assert r["uid"] == "u-441"


def test_the_deadline_is_checked_before_each_evaluation(monkeypatch: pytest.MonkeyPatch) -> None:
    """A request that waited in the queue until its time was gone is not evaluated at all, and an update whose
    first evaluation used the time up is not given a second one: the API server has stopped waiting, so more
    work only delays the next request."""
    clock = [100.0]
    calls: list[str] = []
    real = adm._findings

    def slow(obj: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        calls.append(str(obj["metadata"]["name"]))
        clock[0] += 5.0
        return real(obj, *args, **kwargs)

    monkeypatch.setattr(adm, "_now", lambda: clock[0])
    monkeypatch.setattr(adm, "_findings", slow)
    for cfg in (ENFORCING, WARNING):
        calls.clear()
        r = _not_judged(adm.review(_review(_pod()), cfg, deadline=clock[0] - 0.001), cfg)
        assert calls == [] and "in time" in " ".join(r["warnings"]), "late before it started: nothing is evaluated"
        calls.clear()
        old = _pod(privileged=False)
        old["metadata"]["name"] = "old"
        r = _not_judged(adm.review(_review(_pod(), "UPDATE", old=old), cfg, deadline=clock[0] + 1.0), cfg)
        assert calls == ["p"], "the old object is not evaluated once the time is gone"
    # with time in hand, and with no deadline at all (`kube-noob admission review`), the answer is the verdict
    calls.clear()
    out = adm.review(_review(_pod(), "UPDATE", old=_pod(privileged=False)), ENFORCING, deadline=clock[0] + 60.0)
    assert out["response"]["allowed"] is False and "[KN-S001]" in out["response"]["status"]["message"]
    assert adm.review(_review(_pod()), ENFORCING)["response"]["allowed"] is False
    # review_bytes turns seconds into that deadline, from when it was called
    late = adm.review_bytes(_body(_pod()), ENFORCING, deadline_seconds=-1.0)
    _not_judged(late, ENFORCING)


def test_the_deadline_follows_the_charts_timeout() -> None:
    for seconds in range(1, 31):
        cfg = adm.Config.build(timeout_seconds=seconds)
        assert 0.5 <= cfg.deadline <= seconds - 0.4, seconds
    assert adm.Config.build().timeout_seconds == 3 and adm.Config.build().deadline == pytest.approx(1.8)
    for bad in (0, 31, -1):
        with pytest.raises(adm.AdmissionConfigError, match="timeoutSeconds"):
            adm.Config.build(timeout_seconds=bad)


@pytest.mark.parametrize("cfg", [ENFORCING, WARNING], ids=["enforce", "warn"])
def test_the_server_answers_at_its_deadline_while_the_evaluation_is_still_running(
    cfg: adm.Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Checking between evaluations cannot interrupt one. The server can: it stops waiting at the deadline and
    answers, with the request's own uid -- a response with another uid is an error to the API server, which
    `failurePolicy: Ignore` turns back into a silent admission."""
    from starlette.testclient import TestClient

    quick = adm.Config.build(enforce=sorted(cfg.enforce), timeout_seconds=1)
    held = 20.0
    release = threading.Event()
    started = threading.Event()

    evaluations: list[str] = []

    def stuck(obj: dict[str, Any], *_: Any, **__: Any) -> Any:
        evaluations.append(str(obj["metadata"]["name"]))
        started.set()
        release.wait(held)
        return [], ""

    monkeypatch.setattr(adm, "_findings", stuck)
    with TestClient(adm.app(quick)) as client:
        try:
            with bounds.within_deadline(
                deadline_seconds=quick.deadline,
                source="admission.Config.deadline with admission.timeoutSeconds: 1",
                ignored_would_take=held,
                guards="an evaluation that does not finish, behind POST /validate",
            ):
                old = _pod(privileged=False)
                old["metadata"]["name"] = "old"
                answer = client.post("/validate", json=_review(_pod(), "UPDATE", old=old)).json()
            assert started.is_set(), "the evaluation did start"
            r = _not_judged(answer, quick)
            assert r["uid"] == "u-441" and "in time" in " ".join(r["warnings"])
            # the event loop was never blocked: probes and metrics answer while the evaluation is still held
            assert client.get("/healthz").text == "ok\n"
            m = client.get("/metrics").text
            assert "kube_noob_admission_not_evaluated_total 1" in m
            outcome = "denied" if quick.enforce else "warned"
            assert f'kube_noob_admission_requests_total{{outcome="{outcome}"}} 1' in m
        finally:
            release.set()
        # The worker was given the time the request ARRIVED, so once that is gone it starts nothing more: the
        # abandoned update does not go on to evaluate its old object while the next request waits behind it.
        after = client.post("/validate", json=_review(_pod(privileged=False))).json()["response"]
        assert after["allowed"] is True and after["uid"] == "u-441"
        assert evaluations == ["p", "p"], "one evaluation for the abandoned update, one for the request after it"


def test_the_server_refuses_an_oversized_body_without_reading_it() -> None:
    from starlette.testclient import TestClient

    for cfg in (ENFORCING, WARNING):
        with TestClient(adm.app(cfg)) as client:
            declared = client.post("/validate", content=b"x", headers={"content-length": str(adm.MAX_BODY + 1)})
            _not_judged(declared.json(), cfg)
            _not_judged(client.post("/validate", content=b"nope").json(), cfg)
            ok = client.post("/validate", json=_review(_pod(privileged=False))).json()["response"]
            assert ok["allowed"] is True and ok["uid"] == "u-441"
            assert "kube_noob_admission_not_evaluated_total 2" in client.get("/metrics").text


# -- the hot path: the same documents, without writing the object out and parsing it again ---------------------------


def _fixture_objects() -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for path in sorted(RULES.glob("KN-*.yaml")):
        data = yaml.safe_load(path.read_text())
        for which in ("good", "bad"):
            for n, doc in enumerate(yaml.safe_load_all(data[which])):
                if isinstance(doc, dict):
                    out.append((f"{path.stem}/{which}/{n}", doc))
    return out


def _report(docs: list[yamlio.Document], lines: bool = True) -> tuple[list[Any], list[Any], str]:
    report = analyze(
        docs, platform="openshift", version="4.20", stages={Stage.VALIDATE, Stage.AUDIT, Stage.CALIBRATE}, schema=False
    )
    findings = [
        (f.rule_id, f.doc_index, f.path, f.line if lines else 0, f.resource, f.message) for f in report.findings
    ]
    return [d.data for d in docs], findings, str(report.undetermined() or "")


def test_the_documents_are_the_ones_the_round_trip_gave() -> None:
    """Faster by not doing work is the regression a clock rewards. So the new path is held to the old one, on
    every object of every rule fixture: the same data, the same findings on the same lines, the same statement
    of what was not read."""
    objects = _fixture_objects()
    assert len(objects) > 200, "the fixtures are the population"
    differing = []
    for name, obj in objects:
        old = _report(yamlio.load_documents(json.dumps(obj)))
        new = _report(yamlio.documents_from_objects([obj]))
        if old != new:
            differing.append(name)
    assert not differing, differing
    # Several objects at once (the lookups' context follows the admitted object), and a list wrapper opened.
    # Lines are left out of this comparison, and only this one: the second object of the joined text was on
    # line 3 and the third on line 5, which was a fact about the text the webhook wrote and about no object.
    some = [obj for _, obj in objects[:40]]
    old = _report(yamlio.load_documents("\n---\n".join(json.dumps(o) for o in some)), lines=False)
    assert _report(yamlio.documents_from_objects(some), lines=False) == old
    wrapper = {"apiVersion": "v1", "kind": "PodList", "items": [_pod(), None, _pod(privileged=False)]}
    assert _report(yamlio.documents_from_objects([wrapper, None, _pod()]), lines=False) == _report(
        yamlio.load_documents(json.dumps(wrapper) + "\n---\nnull\n---\n" + json.dumps(_pod())), lines=False
    )


def test_the_webhook_does_not_parse_its_object_a_second_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hot path itself, held without a clock: up to the budget the second parse was only two or three times
    the work, which no ceiling here is tight enough to see and none should be (`tests/bounds.py`)."""

    def reparsed(*_: Any, **__: Any) -> Any:
        raise AssertionError("the admitted object was written out and parsed again")

    monkeypatch.setattr(yamlio, "load_documents", reparsed)
    monkeypatch.setattr(yamlio.yaml, "SafeLoader", reparsed)
    old = _pod(privileged=False)
    for doc in (_review(_pod()), _review(_pod(), "UPDATE", old=old)):
        r = adm.review(doc, ENFORCING)["response"]
        assert r["allowed"] is False and "[KN-S001]" in r["status"]["message"], r
    lookups = adm.Config.build(lookups=True)
    pdb = {"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": {"name": "x", "namespace": "shop"}}
    r = adm.review(_review(_pod()), lookups, lambda _ns: [pdb])["response"]
    assert r["allowed"] is True and any(w.startswith("[KN-S001]") for w in r["warnings"]), "context objects too"


def test_the_direct_path_keeps_the_parsers_limits_and_does_not_share_the_callers_object() -> None:
    from kube_noob.errors import ManifestError

    lone = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "a\ud800b", "labels": {"k\udfff": "v"}}}
    [doc] = yamlio.documents_from_objects([lone])
    assert doc.data["metadata"]["name"] == "a�b" and "k�" in doc.data["metadata"]["labels"]
    assert doc.data == yamlio.load_documents(json.dumps(lone))[0].data, "a lone surrogate, as the YAML path reads it"
    assert lone["metadata"]["name"] == "a\ud800b", "the caller's object is not written to"
    doc.data["metadata"]["name"] = "changed"
    assert lone["metadata"]["name"] == "a\ud800b"
    assert doc.line_for(("spec", "containers", 0)) == 1 and doc.index == 0
    nested: Any = 1
    for _ in range(yamlio.MAX_DEPTH + 2):
        nested = [nested]
    with pytest.raises(ManifestError, match="nested too deeply"):
        yamlio.documents_from_objects([{"a": nested}])
    with pytest.raises(ManifestError, match="too complex"):
        yamlio.documents_from_objects([list(range(50))], max_nodes=50)
    assert len(yamlio.documents_from_objects([list(range(49))], max_nodes=50)) == 1
    with pytest.raises(ManifestError, match="too complex"):
        yamlio.documents_from_objects([list(range(30)), list(range(30))], max_nodes=50)  # one budget for all
    with pytest.raises(ManifestError, match="not a string"):
        yamlio.documents_from_objects([{1: "a"}])
    with pytest.raises(ManifestError, match="More than"):
        yamlio.documents_from_objects([{"a": 1}] * (yamlio.MAX_DOCUMENTS + 1))


def test_the_time_is_linear_in_the_object_up_to_the_budget() -> None:
    """Both halves back to back on the same machine, so a slow runner slows both (G263): four times the
    containers is about four times the time, and was about sixteen before G252."""
    cfg = adm.Config.build(enforce=["KN-S001"])
    probe = _pod()
    per_container = _nodes(_pod(containers=2)) - _nodes(probe)
    large = (adm.MAX_OBJECT_NODES - _nodes(probe)) // per_container
    small = large // 4
    import time

    def took(n: int) -> tuple[float, dict[str, Any]]:
        doc = _review(_pod(containers=n))
        start = time.perf_counter()
        out: dict[str, Any] = adm.review(doc, cfg)["response"]
        return time.perf_counter() - start, out

    took(200)
    quarter, _ = took(small)
    with bounds.bounded(bounds.NO_HANG, honest_seconds=0.6, guards="the largest object the webhook evaluates"):
        whole, out = took(large)
    assert whole < quarter * 8, f"{whole:.2f}s for {large} containers against {quarter:.2f}s for {small}"
    assert out["allowed"] is False and "[KN-S001]" in out["status"]["message"], "evaluated, not refused"


# -- the chart -------------------------------------------------------------------------------------------------------


def test_failure_policy_is_a_choice_the_chart_states() -> None:
    """`Ignore` was hard-coded. It is the availability half of a trade, and the other half is enforcement: with
    `Ignore`, a webhook that is down or late admits what it was not asked about. The default stays `Ignore` --
    warn mode has nothing to enforce, and an upgrade must not start blocking a cluster -- and the chart says
    what it means beside the value."""
    import jsonschema

    text = (CHART / "templates" / "admission.yaml").read_text()
    assert "    failurePolicy: {{ $a.failurePolicy }}\n" in text
    assert "failurePolicy: Ignore" not in text and "failurePolicy: Fail" not in text, "not hard-coded either way"
    assert 'if not (has $a.failurePolicy (list "Ignore" "Fail"))' in text
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["admission"]["failurePolicy"] == "Ignore" and values["admission"]["timeoutSeconds"] == 3
    schema = jsonschema.Draft7Validator(json.loads((CHART / "values.schema.json").read_text()))
    assert not list(schema.iter_errors(values))
    for good in ("Ignore", "Fail"):
        assert not list(schema.iter_errors({**values, "admission": {**values["admission"], "failurePolicy": good}}))
    for bad in ("ignore", "", "Warn", None, True):
        assert list(schema.iter_errors({**values, "admission": {**values["admission"], "failurePolicy": bad}})), bad
    raw = (CHART / "values.yaml").read_text()
    comment = raw.split("  failurePolicy: Ignore", 1)[0].rsplit("\n\n", 1)[-1]
    for phrase in ("Ignore = availability", "Fail = enforcement", "admitted without being judged", "enforce"):
        assert phrase in comment, phrase
    notes = (CHART / "templates" / "NOTES.txt").read_text()
    assert "admission.failurePolicy" in notes and "$a.enforce" in notes, "said at install when a rule is enforced"
    readme = (CHART / "README.md").read_text()
    assert "`admission.failurePolicy`" in readme and "Ignore = availability" in readme


def test_the_chart_tells_the_server_how_long_the_api_server_waits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kube_noob.config import load_settings

    text = (CHART / "templates" / "admission.yaml").read_text()
    assert "      timeoutSeconds: {{ $a.timeoutSeconds }}\n" in text, "in the server's config.yaml"
    assert "    timeoutSeconds: {{ $a.timeoutSeconds }}\n" in text, "and in the webhook configuration"
    checksum = next(line for line in text.splitlines() if "checksum/config" in line)
    assert "$a.timeoutSeconds" in checksum, "the webhook restarts when its deadline changes"
    config = tmp_path / "config.yaml"
    config.write_text("admission:\n  enforce:\n    - KN-S001\n  timeoutSeconds: 10\n")
    monkeypatch.setenv("KUBE_NOOB_CONFIG", str(config))
    s = load_settings()
    assert s.admission.timeout_seconds == 10
    assert adm.Config.build(timeout_seconds=s.admission.timeout_seconds).deadline == pytest.approx(6.0)
    config.write_text("admission:\n  timeoutSeconds: 31\n")
    with pytest.raises(Exception, match=r"timeoutSeconds|timeout_seconds"):
        load_settings()
    # ... and the command hands it to the webhook's configuration, which is where the deadline is read from
    from kube_noob.cli import main

    built: list[dict[str, Any]] = []
    real = adm.Config.build

    def build(**kwargs: Any) -> adm.Config:
        built.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(adm.Config, "build", build)
    config.write_text("admission:\n  timeoutSeconds: 10\n")
    request = tmp_path / "review.json"
    request.write_text(json.dumps(_review(_pod(privileged=False))))
    assert main(["admission", "review", "-f", str(request)]) == 0
    assert built and built[-1]["timeout_seconds"] == 10
