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
    # Both ways, over the recorded rows only (`cluster_get` IS the allowlist, so it would prove nothing): what the
    # capabilities read is the allowlist minus the named set read only through `cluster_get`, and that set is held
    # exactly, so a drift in either direction -- a capability that starts reading `nodes`, or one that stops reading
    # `routes` -- fails here and in `--check` (review finding 4).
    union = pd.recorded_union(pd.matrix())
    assert union - code_cluster == set(), "read but not allowlisted"
    assert code_cluster - union - {("", "pods/log")} == set(pd.CLUSTER_GET_ONLY), {
        "read by nothing, not listed": code_cluster - union - {("", "pods/log")} - pd.CLUSTER_GET_ONLY,
        "listed, but read by a capability": pd.CLUSTER_GET_ONLY & union,
    }
    assert ("", "pods/log") in union, "the watch and the debugger read logs"


def test_a_capability_that_reads_only_a_few_resources_says_so() -> None:
    rows = {row.capability: row for row in pd.matrix()}
    inventory = next(r for name, r in rows.items() if "cluster_operator_inventory" in name)
    assert {p for _, p in inventory.reads} == {"clusterserviceversions", "subscriptions"}
    version = next(r for name, r in rows.items() if "cluster_version" in name)
    assert version.reads == {("config.openshift.io", "clusterversions")} and version.endpoints == {"/version"}
    debug = next(r for name, r in rows.items() if "cluster_debug" in name)
    assert ("", "pods/log") in debug.reads and ("", "serviceaccounts") in debug.reads
    watch = next(r for name, r in rows.items() if "cluster_check_namespace" in name)
    assert ("", "pods/log") in watch.reads, "the prose says it reads the crashing container's log, so the row must"


class _ForbiddingBackend(pd.RecordingBackend):
    """The recording backend with one read forbidden (RBAC 403), as a Role narrower than the chart's answers;
    `pods/log` forbids the log subresource."""

    def __init__(self, forbidden: str) -> None:
        super().__init__()
        self.forbidden = forbidden

    def _refuse(self, plural: str, namespace: str | None) -> None:
        from kube_noob.errors import ClusterAccessError

        raise ClusterAccessError(
            f"Forbidden: GET /api/v1/namespaces/{namespace or ''}/{plural}: {plural} is forbidden: "
            f'User "system:serviceaccount:kube-noob:kn" cannot list resource "{plural}" (status 403)'
        )

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **kw: Any) -> dict[str, Any]:
        from kube_noob.debug.cluster import resolve_resource

        plural, _ = resolve_resource(resource)
        if plural == self.forbidden:
            self._refuse(plural, namespace)
        return super().get(resource, name=name, namespace=namespace, **kw)

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str:
        if self.forbidden == "pods/log":
            self._refuse("pods/log", namespace)
        return super().logs(namespace, pod, container, tail, previous)


REFUSAL_WORDS = ("not read", "forbidden", "unread", "could not be read", "not determined")


def _every_recorded_read() -> list[tuple[str, str]]:
    return sorted({(row.capability, plural) for row in pd.matrix() if row.recorded for _g, plural in row.reads})


@pytest.mark.parametrize(("capability", "forbidden"), _every_recorded_read())
def test_every_read_of_every_row_names_itself_when_forbidden(capability: str, forbidden: str, tmp_path: Path) -> None:
    """Review finding 3, as a sweep over the whole matrix: forbid each recorded read of each capability, one at a
    time, and the capability's own result must name that resource beside a refusal word -- never a silent drop
    (the watch's log and ClusterVersion, the debugger's ServiceAccount were) and never an answer as if the list
    were empty."""
    from kube_noob.errors import KubeNoobError

    run = next(fn for cap, _what, fn in pd.RUNNERS if cap == capability)
    try:
        blob = json.dumps(run(_ForbiddingBackend(forbidden), tmp_path), default=str)
    except Exception as exc:  # the object asked about could not be read: a refusal that names it is an answer
        if not isinstance(exc, KubeNoobError) and not type(exc).__module__.startswith("kube_noob"):
            raise
        blob = f"RAISED: {exc}"
    assert forbidden in blob, (capability, forbidden, blob[:600])
    low = blob.lower()
    assert any(w in low for w in REFUSAL_WORDS), (capability, forbidden, blob[:600])


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
    assert text.startswith("not determined: 1 resource list(s) not read ("), text.splitlines()[0]
    assert main(["--format", "json", "posture", "scan", "--live", "--cluster-enabled", "-n", "shop"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert any(n.startswith(f"{forbidden} in shop: ") and "orbidden" in n for n in out["notRead"]), out["notRead"]
    assert (
        out["summary"].startswith("not determined: 1 resource list(s) not read (") and "attack paths" in out["summary"]
    )
    assert out["notRead"], "a refused list is never an empty list"


def test_the_watch_and_the_debugger_name_their_bonus_reads_when_forbidden(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """The log a crash-looping container's diagnosis would have used, the ClusterVersion the known-issue match
    would have used, the ServiceAccount a stuck pull would have named: each refused read is a line in the text
    view and an entry in the JSON, never a diagnosis that silently ran without it (review finding 3)."""
    from kube_noob import toolkit
    from kube_noob.cli import main
    from kube_noob.debug import cluster

    watch = ["watch", "--once", "--cluster-enabled", "-n", "shop"]
    debug = ["--cluster-enabled", "debug", "deployment/web", "-n", "shop"]
    for n, (forbidden, args, phrase) in enumerate(
        (
            ("pods/log", watch, "read failed: shop/pods/log web-6d4-x1/app: not read ("),
            ("clusterversions", watch, "read failed: clusterversions: not read ("),
            ("serviceaccounts", debug, "serviceaccounts/web: not read ("),
        )
    ):
        monkeypatch.setattr(cluster, "get_backend", lambda _s, f=forbidden: _ForbiddingBackend(f))
        monkeypatch.setattr(toolkit, "get_backend", lambda _s, f=forbidden: _ForbiddingBackend(f))  # debug: the kit
        monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / f"text{n}"))  # a fresh ledger: the incident is new
        assert main(args) == 0
        text = capsys.readouterr().out
        assert phrase in text and "orbidden" in text, (forbidden, text)
        monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / f"json{n}"))
        assert main(["--format", "json", *args]) == 0
        blob = capsys.readouterr().out
        assert forbidden in blob and "not read (" in blob, (forbidden, blob[:800])
