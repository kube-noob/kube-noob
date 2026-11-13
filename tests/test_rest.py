"""I6: REST routes beside MCP on the HTTP server. Contract tests: every documented route answers as its OpenAPI
operation says, the committed document matches the code, and the routes keep the HTTP server's guards (bearer
token, body limit, Host and Origin checks, JSON-only posts)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from starlette.testclient import TestClient

from kube_noob.config import load_settings
from kube_noob.mustgather import sample
from kube_noob.server import rest
from kube_noob.server.http import http_app

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "rest-" + "token-" + "x" * 8
AUTH = {"Authorization": f"Bearer {TOKEN}"}

DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: web, image: quay.io/shop/web:1.0}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: db, namespace: shop}
spec:
  selector: {matchLabels: {app: db}}
  template:
    metadata: {labels: {app: db}}
    spec:
      containers: [{name: db, image: quay.io/shop/db:1.0}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: batch, namespace: shop}
spec:
  selector: {matchLabels: {app: batch}}
  template:
    metadata: {labels: {app: batch}}
    spec:
      containers: [{name: batch, image: quay.io/shop/batch:1.0}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: db-from-web, namespace: shop}
spec:
  podSelector: {matchLabels: {app: db}}
  policyTypes: [Ingress]
  ingress:
  - from: [{podSelector: {matchLabels: {app: web}}}]
    ports: [{port: 5432}]
"""

BODIES: dict[str, dict[str, Any]] = {
    "/v1/insight": {"text": "Back-off restarting failed container web in pod web-7d9f_shop"},
    "/v1/diagnose": {"text": "0/3 nodes are available: 3 Insufficient memory."},
    "/v1/audit": {"manifests": DEPLOY, "platform": "openshift", "version": "4.20"},
    "/v1/known-issues": {"text": "etcd leader changed frequently", "platform": "openshift", "version": "4.20.3"},
    "/v1/upgrade-risks": {"current": "4.20.3", "target": "4.21.4"},
    "/v1/policy/migrate-check": {
        "policies": "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: require-team\nspec:\n"
        "  validationFailureAction: Enforce\n  rules:\n  - name: team\n    match:\n      any:\n      - resources:\n"
        "          kinds: [Pod]\n    validate:\n      message: team label\n      pattern:\n        metadata:\n"
        '          labels:\n            team: "?*"\n'
    },
    "/v1/policy/reach": {"manifests": DEPLOY, "source": "shop/web", "destination": "shop/db", "port": 5432},
    "/v1/memory/match": {"text": "web crash-loops when the database is down"},
    "/v1/reports": {},
    # Alertmanager's own payload, posted whole (the route passes the body as one argument).
    "/v1/alert-reports": json.loads((ROOT / "examples" / "alertmanager-etcd.json").read_text(encoding="utf-8")),
}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    gathers = tmp_path / "gathers"
    sample.write(gathers / "case-1")
    memory = tmp_path / "memory"
    from kube_noob.memory import repo

    repo.init_repo(memory)
    s = load_settings(
        overrides={
            "dataDir": str(tmp_path / "data"),
            "server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]},  # noqa: S104
            "memory": {"paths": [str(memory)]},
            "mustGather": {"allowedDir": str(gathers)},
        }
    )
    BODIES["/v1/must-gather"] = {"path": str(gathers / "case-1" / "must-gather.tar.gz"), "top": 3}
    with TestClient(http_app(s)) as c:
        yield c


def _schema(doc: dict[str, Any], path: str) -> dict[str, Any]:
    body = doc["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]
    return {**body, "components": doc["components"]}


def test_every_route_answers_its_contract(client: Any) -> None:
    doc = client.get("/v1/openapi.json", headers=AUTH).json()
    assert set(doc["paths"]) == {r.path for r in rest.ROUTES}
    for path, body in BODIES.items():
        if "post" in doc["paths"][path]:
            jsonschema.validate(body, _schema(doc, path))
        r = client.post(path, json=body, headers=AUTH)
        assert r.status_code == 200, (path, r.text)
        assert "knowledgeAsOf" in r.json(), path
    assert client.get("/v1/reports", headers=AUTH).status_code == 200
    assert client.post("/v1/policy/reach", json=BODIES["/v1/policy/reach"], headers=AUTH).json()["verdict"] == "allowed"
    blocked = {**BODIES["/v1/policy/reach"], "source": "shop/batch"}
    assert client.post("/v1/policy/reach", json=blocked, headers=AUTH).json()["verdict"] != "allowed"
    mg = client.post("/v1/must-gather", json=BODIES["/v1/must-gather"], headers=AUTH).json()
    assert mg["cluster"]["version"] == "4.20.3" and len(mg["findings"]) == 3
    routes = client.get("/v1", headers=AUTH).json()["routes"]
    assert {r["path"] for r in routes} == {r.path for r in rest.ROUTES}


def test_the_committed_document_matches_the_code() -> None:
    committed = json.loads((ROOT / "docs" / "api" / "openapi.json").read_text())
    assert committed == rest.full_document(), "run python scripts/gen_openapi.py"
    for path, ops in committed["paths"].items():
        for op in ops.values():
            assert {"200", "400", "401", "413", "500"} <= set(op["responses"]), path
            if "requestBody" in op:
                ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
                assert ref.removeprefix("#/components/schemas/") in committed["components"]["schemas"]


def test_errors(client: Any) -> None:
    assert client.post("/v1/diagnose", json={"text": "xyz"}).status_code == 401
    r = client.post("/v1/diagnose", json={"text": "xyz", "nope": 1}, headers=AUTH)
    assert r.status_code == 400 and r.json()["outcome"] == "invalid-arguments"
    assert (
        client.post(
            "/v1/diagnose", content=b"{not json", headers={**AUTH, "Content-Type": "application/json"}
        ).status_code
        == 400
    )
    assert client.post("/v1/diagnose", json=["text"], headers=AUTH).json()["error"] == "the body must be a JSON object"
    plain = client.post("/v1/diagnose", content=b'{"text": "x"}', headers={**AUTH, "Content-Type": "text/plain"})
    assert plain.status_code == 400  # a cross-site form or text/plain post never reaches a tool
    outside = client.post("/v1/must-gather", json={"path": "/etc/passwd"}, headers=AUTH)
    assert outside.status_code == 400 and "outside mustGather.allowedDir" in outside.json()["error"]
    big = b'{"text": "' + b"x" * (9 * 1024 * 1024) + b'"}'
    assert (
        client.post("/v1/diagnose", content=big, headers={**AUTH, "Content-Type": "application/json"}).status_code
        == 413
    )
    assert client.get("/v1/diagnose", headers=AUTH).status_code == 405


def test_host_and_origin_checks(tmp_path: Path) -> None:
    s = load_settings(overrides={"dataDir": str(tmp_path / "data")})  # loopback sidecar, no token: rebinding checks
    with TestClient(http_app(s), base_url="http://127.0.0.1:8080") as c:
        assert c.post("/v1/diagnose", json={"text": "xyz"}).status_code == 200
        evil = c.post("/v1/diagnose", json={"text": "xyz"}, headers={"Origin": "http://evil.example"})
        assert evil.status_code == 403
    with TestClient(http_app(s), base_url="http://evil.example") as c:
        assert c.post("/v1/diagnose", json={"text": "xyz"}).status_code == 421
        assert c.get("/v1/openapi.json").status_code == 421


def test_shared_server_routes_only_offered_tools(tmp_path: Path) -> None:
    s = load_settings(overrides={"dataDir": str(tmp_path / "data")})
    with TestClient(http_app(s), base_url="http://127.0.0.1:8080") as c:
        paths = {r["path"] for r in c.get("/v1").json()["routes"]}
        assert "/v1/memory/match" not in paths and "/v1/must-gather" not in paths and "/v1/diagnose" in paths
        assert c.post("/v1/must-gather", json={"path": "/x"}).status_code == 404
