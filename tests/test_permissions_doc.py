"""docs/permissions.md is generated from the code: what each live capability reads, through the read-only backend,
recorded against a fixture cluster; and the chart's Role/ClusterRole grant exactly that set (G293).

A permission matrix written by hand drifts the day a reader adds a resource; one recorded from the reads the code
makes cannot. The chart is held to the allowlist both ways: a grant the code never reads is a finding, and so is a
read the chart does not grant. A list the cluster forbids is reported as not read, naming the resource, never as
"none".
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "permissions_doc.py"
DOC = ROOT / "docs" / "permissions.md"
sys.path.insert(0, str(ROOT / "scripts"))

import permissions_doc as pd  # noqa: E402


def _check(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(SCRIPT), "--check", *args]
    return subprocess.run(cmd, check=False, capture_output=True, text=True, cwd=ROOT)


def test_the_document_is_current_and_the_check_refuses_a_stale_one(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--check"], check=False, capture_output=True, text=True, cwd=ROOT
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    stale = tmp_path / "permissions.md"
    stale.write_text(DOC.read_text(encoding="utf-8") + "| hand-written row | reads | `secrets` |\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--check", "--doc", str(stale)],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 1 and "stale" in proc.stdout + proc.stderr


def test_every_live_capability_has_a_row_and_every_row_is_recorded_not_written() -> None:
    matrix = pd.matrix()
    names = {row.capability for row in matrix}
    for wanted in (
        "cluster_posture_scan",
        "cluster_posture_reach",
        "cluster_operator_inventory",
        "cluster_operator_known_issues",
        "cluster_check_traffic",
        "cluster_check_namespace",
        "cluster_debug",
        "cluster_get",
        "cluster_version",
        "posture snapshot --live",
        "admission webhook",
    ):
        assert any(wanted in n for n in names), wanted
    text = DOC.read_text(encoding="utf-8")
    for row in matrix:
        assert row.capability in text
        for _group, plural in row.reads:
            assert f"`{plural}`" in text, (row.capability, plural)
    for line in text.splitlines():
        if line.startswith("| ") and line.count("|") >= 4:
            resources = line.rsplit("|", 2)[1]
            assert "secret" not in resources.lower(), line


def test_the_chart_grants_exactly_what_the_code_can_read() -> None:
    """Both scopes: the ClusterRole is the allowlist; the namespace Role is its namespaced part. No Secrets."""
    code_cluster, code_ns = pd.code_grants()
    chart_cluster, chart_ns = pd.chart_grants()
    assert chart_cluster == code_cluster, {
        "chart-only": chart_cluster - code_cluster,
        "code-only": code_cluster - chart_cluster,
    }
    assert chart_ns == code_ns, {"chart-only": chart_ns - code_ns, "code-only": code_ns - chart_ns}
    assert ("", "pods/log") in code_ns
    assert not any(plural.split("/")[0] == "secrets" for _, plural in chart_cluster | chart_ns)
    assert pd.chart_verbs() == {("get", "list")}
    union = set().union(*(row.reads for row in pd.matrix()))
    assert union == code_cluster, {
        "allowlisted but read by nothing": code_cluster - union,
        "read but not allowlisted": union - code_cluster,
    }


def test_a_capability_that_reads_only_a_few_resources_says_so() -> None:
    rows = {row.capability: row for row in pd.matrix()}
    inventory = next(r for name, r in rows.items() if "cluster_operator_inventory" in name)
    assert {p for _, p in inventory.reads} == {"clusterserviceversions", "subscriptions"}
    version = next(r for name, r in rows.items() if "cluster_version" in name)
    assert version.reads == {("config.openshift.io", "clusterversions")} and version.endpoints == {"/version"}
    debug = next(r for name, r in rows.items() if "cluster_debug" in name)
    assert ("", "pods/log") in debug.reads and ("", "serviceaccounts") in debug.reads


class _ForbiddingBackend:
    """A FakeBackend whose list of one resource is forbidden (RBAC 403), as a narrower Role would answer."""

    name = "fake"

    def __init__(self, forbidden: str) -> None:
        self.forbidden = forbidden
        self.fixture = pd.FixtureCluster()

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **kw: Any) -> dict[str, Any]:
        from kube_noob.errors import ClusterAccessError

        if resource == self.forbidden:
            raise ClusterAccessError(
                f"Forbidden: GET /apis/apps/v1/namespaces/{namespace}/{resource}: {resource} is forbidden: "
                f'User "system:serviceaccount:kube-noob:kn" cannot list resource "{resource}" (status 403)'
            )
        return self.fixture.get(resource, name=name, namespace=namespace, **kw)

    def logs(self, *a: Any, **kw: Any) -> str:
        return self.fixture.logs(*a, **kw)

    def version(self) -> dict[str, Any]:
        return self.fixture.version()


@pytest.mark.parametrize("forbidden", ["pods", "rolebindings", "deployments"])
def test_a_forbidden_list_is_reported_as_not_read_naming_the_resource_never_as_none(
    forbidden: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """`posture scan --live` under a Role narrower than the chart's: the text view and the JSON both say which
    list was not read and why, and neither reads the refusal as an empty namespace."""
    from kube_noob.cli import main
    from kube_noob.debug import cluster

    monkeypatch.setattr(cluster, "get_backend", lambda _s: _ForbiddingBackend(forbidden))
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path))
    assert main(["posture", "scan", "--live", "--cluster-enabled", "-n", "shop"]) == 0
    text = capsys.readouterr().out
    line = next((x for x in text.splitlines() if x.startswith("not read: ")), "")
    assert f"{forbidden} in shop: " in line and "orbidden" in line, text
    assert main(["--format", "json", "posture", "scan", "--live", "--cluster-enabled", "-n", "shop"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert any(n.startswith(f"{forbidden} in shop: ") and "orbidden" in n for n in out["notRead"]), out["notRead"]
    assert out["notRead"], "a refused list is never an empty list"
