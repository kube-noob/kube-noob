"""ADM1 (R3.3): the kube-noob-admission webhook. Warn mode never denies (fuzzed), enforce denies only the listed rules,
it never mutates, a broken input is admitted, and it answers well under 50 ms."""

from __future__ import annotations

import copy
import json
import random
import re
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import admission as adm
from kube_noob.audit.engine import analyze
from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "tests" / "fixtures" / "rules"


def _fixtures() -> list[tuple[str, str, dict[str, Any]]]:
    out = []
    for path in sorted(RULES.glob("KN-*.yaml")):
        data = yaml.safe_load(path.read_text())
        for which in ("good", "bad"):
            for doc in yaml.safe_load_all(data[which]):
                if isinstance(doc, dict) and doc.get("kind"):
                    out.append((data["rule"], which, doc))
    return out


FIXTURES = _fixtures()


def _review(obj: Any, op: str = "CREATE", ns: str | None = None, old: Any = None, **extra: Any) -> dict[str, Any]:
    meta = obj.get("metadata") if isinstance(obj, dict) and isinstance(obj.get("metadata"), dict) else {}
    req: dict[str, Any] = {
        "uid": "0b1c2d3e-uid",
        "kind": {"group": "", "version": "v1", "kind": obj.get("kind") if isinstance(obj, dict) else "x"},
        "resource": {"group": "", "version": "v1", "resource": "x"},
        "namespace": ns if ns is not None else str(meta.get("namespace") or "shop"),
        "operation": op,
        "userInfo": {"username": "dev"},
        "object": obj,
        **extra,
    }
    if old is not None:
        req["oldObject"] = old
    return {"apiVersion": adm.API_VERSION, "kind": "AdmissionReview", "request": req}


def _well_formed(out: dict[str, Any], cfg: adm.Config) -> dict[str, Any]:
    assert out["apiVersion"] == adm.API_VERSION and out["kind"] == "AdmissionReview"
    r = out["response"]
    assert "patch" not in r and "patchType" not in r, "never mutates"
    assert all(len(w) <= adm.WARNING_CHARS for w in r.get("warnings", []))
    assert len(r.get("warnings", [])) <= cfg.max_warnings + 1
    return dict(r)


# -- warn mode -------------------------------------------------------------------------------------------------------

_JUNK: list[Any] = [None, "", "x" * 5000, 0, -1, 2**63, 1.5, True, [], {}, ["a"], {"a": {"b": [1, {}]}}, "\u202e\u0000"]


def _mutate(rng: random.Random, value: Any, depth: int = 0) -> Any:
    if depth > 6 or rng.random() < 0.15:
        return copy.deepcopy(rng.choice(_JUNK))
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            roll = rng.random()
            if roll < 0.08:
                continue  # drop a key
            out[k] = _mutate(rng, v, depth + 1) if roll < 0.4 else v
        if rng.random() < 0.1:
            out[rng.choice(["privileged", "hostPID", "image", "spec", "metadata", "ownerReferences"])] = rng.choice(
                _JUNK
            )
        return out
    if isinstance(value, list):
        out_list = [(_mutate(rng, v, depth + 1) if rng.random() < 0.4 else v) for v in value]
        if rng.random() < 0.1:
            out_list = out_list * rng.randint(2, 30)
        return out_list
    return value


def test_warn_mode_never_denies_fuzzed() -> None:
    cfg = adm.Config.build(platform="openshift", version="4.20")
    seen_warnings = 0
    for seed in range(1500):
        rng = random.Random(seed)
        _, _, base = rng.choice(FIXTURES)
        obj = _mutate(rng, copy.deepcopy(base))
        op = rng.choice(["CREATE", "UPDATE", "CREATE", "DELETE", "CONNECT", "", None, 7])
        old = _mutate(rng, copy.deepcopy(base)) if op == "UPDATE" else None
        doc = _review(obj if isinstance(obj, dict) else {"kind": "x"}, str(op), old=old)
        if rng.random() < 0.05:
            doc["request"]["object"] = rng.choice(_JUNK)
        if rng.random() < 0.05:
            doc["request"] = rng.choice(_JUNK)
        r = _well_formed(adm.review(doc, cfg), cfg)
        assert r["allowed"] is True, (seed, r)
        seen_warnings += bool(r.get("warnings"))
    assert seen_warnings > 300, "the fuzz reached the rules, not only the input checks"
    for body in (b"", b"{", b"[1]", b"null", b"[" * 200_000, b'{"request": 5}', b"\xff\xfe"):
        r = _well_formed(adm.review_bytes(body, cfg), cfg)
        assert r["allowed"] is True
    big = json.dumps(_review({"kind": "Pod", "x": "y" * (adm.MAX_BODY + 1)})).encode()
    assert adm.review_bytes(big, cfg)["response"]["allowed"] is True


def _registries(rule: str) -> tuple[str, ...]:
    """The fixture's `allowedRegistries`, which KN-S036 needs to decide anything at all (G243)."""
    data = yaml.safe_load((RULES / f"{rule}.yaml").read_text())
    return tuple(str(r) for r in (data.get("allowedRegistries") or []))


def test_every_bad_fixture_warns_and_is_admitted() -> None:
    for rule, which, doc in FIXTURES:
        if which != "bad" or rule in adm.SKIPPED_RULES | adm.CROSS_OBJECT:
            continue
        registries = _registries(rule)
        cfg = adm.Config.build(platform="openshift", version="4.20", allowed_registries=registries)
        ns = (doc.get("metadata") or {}).get("namespace") or "shop"
        r = _well_formed(adm.review(_review(doc, ns=ns), cfg), cfg)
        assert r["allowed"] is True
        single = {
            f.rule_id
            for f in analyze(
                yaml.safe_dump(doc), platform="openshift", version="4.20", allowed_registries=registries
            ).findings
        }
        if rule in single:
            assert any(w.startswith(f"[{rule}]") for w in r.get("warnings", [])), (rule, r.get("warnings"))


def test_the_registry_rule_declines_rather_than_warning_without_an_allowlist() -> None:
    """With no list the webhook says nothing about registries, and refuses to pretend it is enforcing one."""
    bad = yaml.safe_load(yaml.safe_dump(next(d for r, w, d in FIXTURES if r == "KN-S036" and w == "bad")))
    off = adm.Config.build(platform="openshift", version="4.20")
    r = _well_formed(adm.review(_review(bad, ns="shop"), off), off)
    assert r["allowed"] is True and not [w for w in r.get("warnings", []) if w.startswith("[KN-S036]")]
    on = adm.Config.build(platform="openshift", version="4.20", allowed_registries=("quay.io/my-org",))
    warned = _well_formed(adm.review(_review(bad, ns="shop"), on), on)
    assert any(w.startswith("[KN-S036]") for w in warned.get("warnings", []))
    with pytest.raises(adm.AdmissionConfigError, match="allowedRegistries"):
        adm.Config.build(enforce=["KN-S036"], platform="openshift", version="4.20")
    enforcing = adm.Config.build(
        enforce=["KN-S036"], platform="openshift", version="4.20", allowed_registries=("quay.io/my-org",)
    )
    denied = _well_formed(adm.review(_review(bad, ns="shop"), enforcing), enforcing)
    assert denied["allowed"] is False and "[KN-S036]" in denied["status"]["message"]


# -- enforce ---------------------------------------------------------------------------------------------------------


ENFORCEABLE = sorted(
    {rule for rule, _, _ in FIXTURES} - adm.SKIPPED_RULES - adm.CROSS_OBJECT - {"KN-V015", "KN-V017", "KN-N006"}
)


@pytest.mark.parametrize("rule", ENFORCEABLE)
def test_enforce_denies_only_the_listed_rule(rule: str) -> None:
    data = yaml.safe_load((RULES / f"{rule}.yaml").read_text())
    platform, version = data.get("platform", "openshift"), str(data.get("version", "4.20"))
    registries = tuple(str(r) for r in (data.get("allowedRegistries") or []))
    cfg = adm.Config.build(enforce=[rule], platform=platform, version=version, allowed_registries=registries)
    denied_bad = False
    for which in ("good", "bad"):
        for doc in [d for d in yaml.safe_load_all(data[which]) if isinstance(d, dict)]:
            ns = (doc.get("metadata") or {}).get("namespace") or "shop"
            r = _well_formed(adm.review(_review(doc, ns=ns), cfg), cfg)
            single = {
                f.rule_id
                for f in analyze(
                    yaml.safe_dump(doc), platform=platform, version=version, allowed_registries=registries
                ).findings
            }
            if rule in single and which == "bad":
                assert r["allowed"] is False, (rule, doc.get("kind"))
                assert f"[{rule}]" in r["status"]["message"] and r["status"]["code"] == 403
                assert r["status"]["message"].endswith(f"(enforced rules: {rule})")
                denied_bad = True
            elif rule not in single:
                assert r["allowed"] is True, (rule, which, r)
    assert denied_bad, f"{rule}: the bad fixture was not denied"


def test_update_denies_only_new_findings_and_skips(tmp_path: Path) -> None:
    data = yaml.safe_load((RULES / "KN-S001.yaml").read_text())
    good, bad = yaml.safe_load(data["good"]), yaml.safe_load(data["bad"])
    cfg = adm.Config.build(enforce=["KN-S001"], platform="openshift", version="4.20")
    assert adm.review(_review(bad, "UPDATE", old=good), cfg)["response"]["allowed"] is False
    kept = adm.review(_review(bad, "UPDATE", old=bad), cfg)["response"]
    assert kept["allowed"] is True and any(w.startswith("[KN-S001]") for w in kept["warnings"]), "warned, not frozen"
    for case in (
        _review(bad, "DELETE"),
        _review(bad, "CONNECT"),
        _review(bad, subResource="status"),
        _review(bad, ns="kube-system"),
        _review(bad, ns="openshift-monitoring"),
        _review(bad, ns="openshift"),
    ):
        r = adm.review(case, cfg)["response"]
        assert r == {"uid": "0b1c2d3e-uid", "allowed": True}, case["request"].get("namespace")
    gone = copy.deepcopy(bad)
    gone["metadata"]["deletionTimestamp"] = "2026-10-28T00:00:00Z"
    assert adm.review(_review(gone), cfg)["response"] == {"uid": "0b1c2d3e-uid", "allowed": True}
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "p", "namespace": "shop"},
        "spec": bad["spec"]["template"]["spec"],
    }
    assert adm.review(_review(pod), cfg)["response"]["allowed"] is False, "a bare Pod is checked"
    owned = copy.deepcopy(pod)
    owned["metadata"]["ownerReferences"] = [
        {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "x", "uid": "1", "controller": True}
    ]
    assert adm.review(_review(owned), cfg)["response"] == {"uid": "0b1c2d3e-uid", "allowed": True}
    mine = adm.Config.build(enforce=["KN-S001"], excluded=["shop"], platform="openshift")
    assert adm.review(_review(bad), mine)["response"]["allowed"] is True
    gen = copy.deepcopy(bad)
    gen["metadata"].pop("name")
    gen["metadata"]["generateName"] = "web-"
    assert adm.review(_review(gen), cfg)["response"]["allowed"] is False, "generateName objects are checked too"


def test_config_and_exceptions(tmp_path: Path) -> None:
    for kwargs, msg in (
        ({"enforce": ["KN-X999"]}, "unknown rules"),
        ({"enforce": ["KN-N001"]}, "cannot enforce KN-N001"),
        ({"enforce": ["KN-S018"]}, "cannot enforce KN-S018"),
        ({"max_warnings": 0}, "1-50"),
    ):
        with pytest.raises(adm.AdmissionConfigError, match=msg):
            adm.Config.build(**kwargs)  # type: ignore[arg-type]
    bad = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["bad"])
    today = time.strftime("%Y-%m-%d")
    later = f"{int(today[:4]) + 1}{today[4:]}"
    exc = (
        "apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions:\n- id: EXC-1\n  rule: KN-S001\n"
        "  scope: {namespace: shop, kind: Deployment, name: web}\n  owner: team-web\n"
        f"  reason: The web tier needs it until the move\n  expires: {later}\n"
    )
    cfg = adm.Config.build(enforce=["KN-S001"], platform="openshift", exceptions_text=exc)
    r = adm.review(_review(bad), cfg)["response"]
    assert r["allowed"] is True and not any(w.startswith("[KN-S001]") for w in r.get("warnings", []))
    other = copy.deepcopy(bad)
    other["metadata"]["name"] = "api"
    assert adm.review(_review(other), cfg)["response"]["allowed"] is False, "the exception covers web only"
    with pytest.raises(adm.AdmissionConfigError, match="refused entries"):
        adm.Config.build(exceptions_text=exc.replace("  owner: team-web\n", ""))


def test_warning_cap_and_truncation() -> None:
    bad = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["bad"])
    bad["spec"]["template"]["spec"]["containers"][0]["name"] = "c" * 300
    cfg = adm.Config.build(max_warnings=2, platform="openshift")
    r = _well_formed(adm.review(_review(bad), cfg), cfg)
    assert len(r["warnings"]) == 3 and r["warnings"][-1].startswith("kube-noob: ")
    assert any(w.endswith("...") for w in r["warnings"])


# -- lookups ---------------------------------------------------------------------------------------------------------


class _Backend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def get(self, resource: str, namespace: str | None = None) -> dict[str, Any]:
        self.calls.append((resource, namespace))
        if resource == "poddisruptionbudgets" and namespace == "shop":
            return {
                "items": [
                    {
                        "apiVersion": "policy/v1",
                        "metadata": {"name": "web", "namespace": "shop"},
                        "spec": {"minAvailable": 1, "selector": {"matchLabels": {"app": "web"}}},
                    }
                ]
            }
        if resource == "networkpolicies":
            raise PermissionError("forbidden")
        return {"items": []}


def test_lookups_fill_cross_object_rules_without_blocking() -> None:
    good = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["good"])
    backend, pauses = _Backend(), []
    lookups = adm.Lookups(backend, sleep=pauses.append, rng=random.Random(7))
    cfg = adm.Config.build(platform="openshift", lookups=True)
    first = adm.review(_review(good), cfg, lookups)["response"]
    # No context yet: the PDB list was never read, so KN-C008 is not evaluated -- said, not warned (G279). Before,
    # it warned that a PDB was missing from a list nobody had read.
    assert not any(w.startswith("[KN-C008]") for w in first["warnings"])
    assert any("were not evaluated" in w and "poddisruptionbudgets" in w for w in first["warnings"])
    assert backend.calls == [], "a request never waits for the API server"
    lookups.refresh()
    assert ("poddisruptionbudgets", "shop") in backend.calls and ("storageclasses", None) in backend.calls
    assert pauses and all(0.05 <= p <= 0.2 for p in pauses) and len(set(pauses)) > 1, "jittered"
    assert any("networkpolicies in shop" in e for e in lookups.errors)
    after = adm.review(_review(good), cfg, lookups)["response"]
    assert not any(w.startswith("[KN-C008]") for w in after.get("warnings", [])), "the cached PDB counts"
    off = adm.Config.build(platform="openshift")
    assert not any(w.startswith("[KN-C008]") for w in adm.review(_review(good), off)["response"].get("warnings", []))


# -- server, speed, CLI ----------------------------------------------------------------------------------------------


def test_asgi_app_metrics_and_limits() -> None:
    from starlette.testclient import TestClient

    cfg = adm.Config.build(enforce=["KN-S001"], platform="openshift")
    bad = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["bad"])
    client = TestClient(adm.app(cfg))
    r = client.post("/validate", json=_review(bad))
    assert r.status_code == 200 and r.json()["response"]["allowed"] is False
    assert client.post("/validate", content=b"nope").json()["response"]["allowed"] is True
    huge = client.post("/validate", content=b"x", headers={"content-length": str(adm.MAX_BODY + 1)})
    assert huge.json()["response"]["allowed"] is True
    assert client.get("/validate").status_code == 405
    assert client.get("/healthz").text == "ok\n" and client.get("/readyz").status_code == 200
    m = client.get("/metrics").text
    assert 'kube_noob_admission_requests_total{outcome="denied"} 1' in m
    assert 'kube_noob_admission_duration_seconds_bucket{le="+Inf"} 3' in m


def test_a_padded_object_does_not_outrun_the_webhooks_timeout() -> None:
    """The locator was O(n^2) in a list's length, so an object padded with containers neutralised the webhook.

    Measured before the fix: 2,000 containers took 6.1 s, 8,000 took 90 s and 16,000 took 352 s -- all far
    past the chart's `timeoutSeconds: 3`, so the API server gave up and admitted the object with no warning
    and no denial, while the single process stayed busy and every other request timed out with it. The keys a
    list's items share are computed once per list now (G252), which makes the cost linear.
    """
    cfg = adm.Config.build(enforce=["KN-S001"], platform="kubernetes")

    def padded(n: int) -> dict[str, Any]:
        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "d", "namespace": "shop"},
            "spec": {
                "selector": {"matchLabels": {"a": "b"}},
                "template": {
                    "metadata": {"labels": {"a": "b"}},
                    "spec": {
                        "containers": [
                            {"name": f"c{i}", "image": "nginx", "securityContext": {"privileged": True}}
                            for i in range(n)
                        ]
                    },
                },
            },
        }

    def took(n: int) -> tuple[float, dict[str, Any]]:
        start = time.perf_counter()
        out = adm.review(_review(padded(n)), cfg)["response"]
        return time.perf_counter() - start, out

    # The first call pays for imports and cold caches -- measured here, 500 containers cost 1.33 s cold and
    # 0.2 s warm -- so warm up before timing anything, or the small sample carries the startup and the ratio
    # reads as sub-linear.
    took(200)
    # The property this test is named for is the SHAPE of the curve, not a number of seconds: quadratic in
    # four times the input is about sixteen times the time, linear is about four. A wall-clock budget is a
    # proxy for that, and it is the proxy that depends on the runner -- 5.0 s held for months and then failed
    # at 5.44 s on one shared 3.11 runner, on a release commit, while 3.12, 3.13 and 3.14 passed the same
    # code (G263). Both halves of a ratio run back to back on the same machine, so a slow runner slows both
    # and the verdict stays about the code.
    small, _ = took(1000)
    elapsed, out = took(4000)
    assert elapsed < small * 8, (
        f"{elapsed:.2f}s for 4,000 against {small:.2f}s for 1,000 -- growing faster than linear "
        f"(quadratic would be about 16x, linear about 4x)"
    )
    # A ceiling far enough above any plausible runner that only a catastrophe trips it. This is not a
    # performance budget; the ratio above is.
    assert elapsed < 60.0, f"{elapsed:.1f}s for 4,000 containers"
    assert out["allowed"] is False, "and it still decides: the denial is the point of being fast enough"
    # The sibling memo must not change what a locator says: a shared name is still ambiguous, a unique one
    # still identifies its item.
    from kube_noob.yamlio import load_documents, locator

    doc = load_documents(yaml.safe_dump(padded(3)))[0]
    path = ("spec", "template", "spec", "containers", 1)
    assert locator(doc.data, path, doc.ambiguous_keys).endswith("[name=c1]")
    dupes = padded(2)
    dupes["spec"]["template"]["spec"]["containers"][1]["name"] = "c0"
    same = load_documents(yaml.safe_dump(dupes))[0]
    assert locator(same.data, path, same.ambiguous_keys).endswith("[1]")


def test_p99_well_under_50_ms() -> None:
    cfg = adm.Config.build(platform="openshift", version="4.20")
    cases = [_review(doc) for _, which, doc in FIXTURES if which == "bad"][:60]
    times = []
    for _ in range(5):
        for c in cases:
            t0 = time.perf_counter()
            adm.review(c, cfg)
            times.append(time.perf_counter() - t0)
    times.sort()
    p99 = times[int(len(times) * 0.99) - 1]
    assert p99 < 0.05, f"p99 {p99 * 1000:.1f} ms"


def test_cli_review(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = yaml.safe_load(yaml.safe_load((RULES / "KN-S001.yaml").read_text())["bad"])
    f = tmp_path / "review.json"
    f.write_text(json.dumps(_review(bad)))
    assert main(["admission", "review", "-f", str(f)]) == 0
    assert json.loads(capsys.readouterr().out)["response"]["allowed"] is True
    assert main(["admission", "review", "-f", str(f), "--enforce", "KN-S001"]) == 1
    capsys.readouterr()
    assert main(["admission", "review", "-f", str(f), "--enforce", "KN-C008"]) == 2
    cert = tmp_path / "missing.crt"
    assert main(["admission", "serve", "--tls-cert", str(cert), "--tls-key", str(cert)]) == 2


# -- the chart (deploy/helm/kube-noob/templates/admission.yaml); rendered and installed in CI (helm, kind) -------------

CHART = ROOT / "deploy" / "helm" / "kube-noob"


def test_chart_carries_the_registry_allowlist_to_both_config_files() -> None:
    """One list, three readers (R3c, G243).

    `kube-noob audit` in the sidecar, the webhook, and `policy generate` must agree about which registries are
    approved, so the chart writes the same value into both config files -- and refuses at install, rather than
    at a crash loop, when the list could never match an image or when the rule is enforced without one.
    """
    import jsonschema

    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["audit"]["allowedRegistries"] == []
    schema = jsonschema.Draft7Validator(json.loads((CHART / "values.schema.json").read_text()))
    good = {**values, "audit": {"allowedRegistries": ["quay.io/my-org", "localhost:5000", "registry.local:5000/t"]}}
    assert not list(schema.iter_errors(good))
    for bad in (["MyRegistry"], ["quay.io/My-Org"], [""], ["quay.io/"], ["quay.io"] * 65, [5]):
        assert list(schema.iter_errors({**values, "audit": {"allowedRegistries": bad}})), bad
    for name in ("configmap.yaml", "admission.yaml"):
        text = (CHART / "templates" / name).read_text()
        assert "allowedRegistries: {{- toYaml . | nindent 8 }}" in text, name
    admission = (CHART / "templates" / "admission.yaml").read_text()
    assert 'has "KN-S036" ($a.enforce | default list)' in admission, "enforcing it with no list must not render"
    checksum = next(line for line in admission.splitlines() if "checksum/config" in line)
    assert "allowedRegistries" in checksum, "the webhook must restart when the allowlist changes"


def test_chart_values_and_schema() -> None:
    import jsonschema

    values = yaml.safe_load((CHART / "values.yaml").read_text())
    schema = jsonschema.Draft7Validator(json.loads((CHART / "values.schema.json").read_text()))
    assert not list(schema.iter_errors(values))
    a = values["admission"]
    assert a["enabled"] is False and a["enforce"] == [] and a["lookups"] is False, "off and warn-only by default"
    assert a["timeoutSeconds"] == 3 and a["certificates"] == "openshift-service-ca"
    for bad in (
        {"enforce": ["KN-X"]},
        {"enforce": ["KN-S001", "KN-S001"]},
        {"timeoutSeconds": 31},
        {"timeoutSeconds": 0},
        {"certificates": "self-signed"},
        {"maxWarnings": 51},
        {"excludedNamespaces": ["Not_A_Namespace"]},
        {"tls": {"caBundle": "not base64!"}},
        {"certManager": {"issuerRef": {"kind": "Secret"}}},
        {"mutate": True},
    ):
        assert list(schema.iter_errors({**values, "admission": {**a, **bad}})), bad


def test_chart_webhook_matches_the_server() -> None:
    from kube_noob.audit.rules import RULES
    from kube_noob.cli import build_parser

    text = (CHART / "templates" / "admission.yaml").read_text()
    for line in (
        "failurePolicy: Ignore",
        "sideEffects: None",
        "admissionReviewVersions: [v1]",
        "matchPolicy: Equivalent",
        "path: /validate, port: 443",
        'service.beta.openshift.io/inject-cabundle: "true"',
        "service.beta.openshift.io/serving-cert-secret-name:",
        "cert-manager.io/inject-ca-from: {{ $ns }}/{{ $name }}",
        "scheme: HTTPS",
        "operations: [CREATE, UPDATE]",
    ):
        assert line in text, line
    assert "mutating" not in text.lower() and "patch" not in text.lower(), "a validating webhook only"
    excluded = text.split("concat (list ", 1)[1].split(" $ns)", 1)[0].replace('"', "").split()
    assert set(excluded) == adm.SYSTEM_NAMESPACES, "the namespaceSelector skips what the server skips"
    assert 'startsWith("openshift-")' in text and adm.SYSTEM_PREFIXES == ("openshift-",)
    owned = text.split("request.kind.kind in [", 1)[1].split("]", 1)[0].replace('"', "").replace(",", "").split()
    assert set(owned) == adm.OWNED_KINDS
    lookups = text.split("kind: ClusterRole\n", 1)[1].split("---", 1)[0]
    for resource in (*adm.CONTEXT_RESOURCES, "storageclasses"):
        assert f"resources: [{resource}]" in lookups, resource
    assert "secrets" not in lookups and "verbs: [get, list]" in lookups
    rules = text.split("    rules:\n", 1)[1]
    for resource in (
        "pods",
        "deployments",
        "statefulsets",
        "daemonsets",
        "replicasets",
        "jobs",
        "cronjobs",
        "deploymentconfigs",
        "services",
        "ingresses",
        "routes",
        "networkpolicies",
        "roles",
        "rolebindings",
        # The AI-workload CRDs that carry pod specs (R6, G248). The webhook already audits the containers
        # inside them -- it is the same rule code -- so the only reason a privileged KServe predictor was
        # admitted while the same container in a Deployment was denied is that these were never sent.
        "inferenceservices",
        "rayclusters",
        "rayjobs",
        "rayservices",
    ):
        assert re.search(rf"[\[ ,]{resource}[\],]", rules), resource
    assert "scope: Namespaced" in rules and "secrets" not in rules
    serve = build_parser().parse_args(["admission", "serve", "--port", "8443", "--tls-cert", "/c", "--tls-key", "/k"])
    assert (serve.port, serve.tls_cert, serve.tls_key) == (8443, "/c", "/k")
    assert '"--port", "8443"' in text and "/etc/kube-noob-admission/tls/tls.key" in text
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["admission"]["enforce"] == [] and all(r in RULES for r in ("KN-S001",))


def test_a_debug_container_is_checked_and_the_pods_own_findings_are_not_repeated() -> None:
    """R7/G250: `kubectl debug` goes through `pods/ephemeralcontainers`, which nothing was matching.

    Three things have to hold at once, and each was a defect taken the other way: the request is evaluated at
    all; the owner check does not skip it (no owner carries an ephemeral container, so a managed workload's
    Pod would have been the one request nothing checked); and only what the request ADDS is reported, or a Pod
    that already breaks an enforced rule could never be debugged.
    """
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "web-7d9f",
            "namespace": "shop",
            "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "web-7d9", "controller": True}],
        },
        "spec": {"containers": [{"name": "web", "image": "nginx", "securityContext": {"privileged": True}}]},
    }
    debug = copy.deepcopy(pod)
    debug["spec"]["ephemeralContainers"] = [
        {"name": "debugger", "image": "quay.io/evil/tools:latest", "securityContext": {"privileged": True}}
    ]
    cfg = adm.Config.build(enforce=["KN-S001"], platform="kubernetes")
    req = _review(debug, "UPDATE", old=pod, ns="shop", subResource="ephemeralcontainers")
    out = _well_formed(adm.review(req, cfg), cfg)
    assert out["allowed"] is False, "a privileged debug container is the request this rule is for"
    assert "debugger" in out["status"]["message"]
    assert out["warnings"] and all("debugger" in w for w in out["warnings"]), out["warnings"]
    assert not any("'web'" in w for w in out["warnings"]), "the pod's own findings belong to its own request"
    # The same Pod with a clean debug container is admitted, privileged app container and all.
    clean = copy.deepcopy(pod)
    clean["spec"]["ephemeralContainers"] = [
        {
            "name": "d",
            "image": "quay.io/o/t@sha256:" + "a" * 64,
            "securityContext": {
                "privileged": False,
                "allowPrivilegeEscalation": False,
                "runAsNonRoot": True,
                "runAsUser": 1001,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "64Mi"}},
        }
    ]
    ok = _well_formed(
        adm.review(_review(clean, "UPDATE", old=pod, ns="shop", subResource="ephemeralcontainers"), cfg), cfg
    )
    assert ok["allowed"] is True and not ok.get("warnings")
    # Every other subresource is still somebody else's business.
    for other in ("status", "exec", "log", "portforward", "scale"):
        res = adm.review(_review(debug, "UPDATE", old=pod, ns="shop", subResource=other), cfg)["response"]
        assert res["allowed"] is True and not res.get("warnings"), other
    assert set(adm.SUBRESOURCES) == {"ephemeralcontainers"}
    text = (CHART / "templates" / "admission.yaml").read_text()
    assert "pods/ephemeralcontainers" in text.split("    rules:\n", 1)[1]


def test_the_webhook_sends_every_kind_whose_pod_specs_the_audit_reads() -> None:
    """The rules list is derived from what the audit can read, not maintained beside it (R6, G248).

    `kube_noob.audit.podspec.EMBEDDED_POD_SPEC_GROUPS` is the audit's own table of CRDs that carry pod specs.
    A kind added there and not here would be audited on a directory and admitted by the cluster, which is the
    gap this closed -- so the test reads that table rather than a list someone has to remember to update.
    """
    from kube_noob.audit.podspec import EMBEDDED_POD_SPEC_GROUPS

    text = (CHART / "templates" / "admission.yaml").read_text()
    rules = text.split("    rules:\n", 1)[1]
    for kind, groups in EMBEDDED_POD_SPEC_GROUPS.items():
        plural = f"{kind.lower()}s"
        assert re.search(rf"[\[ ,]{plural}[\],]", rules), f"{kind}: the webhook is never sent {plural}"
        for group in groups:
            assert f"apiGroups: [{group}]" in rules, group


def test_the_webhook_audits_a_container_inside_a_crd() -> None:
    """End to end on the kinds the chart now sends: the finding, the denial and the field path."""
    isvc = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": {"name": "m", "namespace": "shop"},
        "spec": {
            "predictor": {
                "model": {
                    "modelFormat": {"name": "sklearn"},
                    "image": "quay.io/o/m:1.2",
                    "securityContext": {"privileged": True},
                }
            }
        },
    }
    warn = adm.Config.build(platform="kubernetes")
    out = _well_formed(adm.review(_review(isvc, ns="shop"), warn), warn)
    assert out["allowed"] is True
    assert any(w.startswith("[KN-S001]") and "model" in w for w in out["warnings"]), out["warnings"]
    enforcing = adm.Config.build(enforce=["KN-S001"], platform="kubernetes")
    denied = _well_formed(adm.review(_review(isvc, ns="shop"), enforcing), enforcing)
    assert denied["allowed"] is False and "InferenceService/shop/m" in denied["status"]["message"]
    ray = {
        "apiVersion": "ray.io/v1",
        "kind": "RayCluster",
        "metadata": {"name": "r", "namespace": "shop"},
        "spec": {
            "headGroupSpec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "ray-head", "image": "quay.io/o/ray:1", "securityContext": {"privileged": True}}
                        ]
                    }
                }
            }
        },
    }
    out = _well_formed(adm.review(_review(ray, ns="shop"), warn), warn)
    assert any(w.startswith("[KN-S001]") and "ray-head" in w for w in out["warnings"]), out["warnings"]


def test_chart_config_loads_as_the_server_reads_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.config import load_settings

    exceptions = tmp_path / "exceptions.yaml"
    exceptions.write_text("apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions: []\n")
    config = tmp_path / "config.yaml"
    config.write_text(
        "offline: true\nwebEnabled: false\ndefaultPlatform: openshift\nllm:\n  provider: none\ncluster:\n"
        "  enabled: true\n  backend: in-cluster\nadmission:\n  enforce:\n    - KN-S001\n  excludedNamespaces:\n"
        '    - kube-system\n    - kube-noob\n  lookups: true\n  maxWarnings: 10\n  version: "4.20"\n'
        f"  exceptionsFile: {exceptions}\n"
    )
    monkeypatch.setenv("KUBE_NOOB_CONFIG", str(config))
    s = load_settings()
    assert s.offline and s.cluster.enabled and s.admission.enforce == ["KN-S001"] and s.admission.lookups
    cfg = adm.Config.build(
        enforce=s.admission.enforce,
        excluded=s.admission.excluded_namespaces,
        platform=s.default_platform,
        version=s.admission.version,
        exceptions_text=exceptions.read_text(),
        lookups=s.admission.lookups,
    )
    assert cfg.enforce == frozenset({"KN-S001"}) and "kube-noob" in cfg.excluded
