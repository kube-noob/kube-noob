"""Alerts Alertmanager truncated out of a webhook payload are part of the answer (G289).

A v4 webhook payload with `"truncatedAlerts": 2` and one alert reported `summary.alerts: 1`, `notIncluded: []` and
exit 0: `alertmanager.split` dropped the count. Alertmanager's `webhook_config` documents the field as "how many
alerts have been truncated due to max_alerts" (prometheus/alertmanager docs/configuration.md, retrieved 2026-11-13):
those alerts were never sent, so a report that does not say so claims to have seen the whole group.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from kube_noob.cli import main
from kube_noob.config import Settings, load_settings
from kube_noob.server.http import http_app
from kube_noob.signals import alertmanager
from kube_noob.toolkit import AlertReportIn, Toolkit

TOKEN = "alerts-" + "tok-" + "y" * 10
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _alert(name: str, state: str = "firing", **labels: str) -> dict[str, Any]:
    return {"status": state, "labels": {"alertname": name, **labels}, "annotations": {"summary": f"{name} fired"}}


def _payload(*alerts: dict[str, Any], **top: Any) -> str:
    return json.dumps({"version": "4", "status": "firing", "receiver": "kube-noob", **top, "alerts": list(alerts)})


def _report(tmp_path: Path, text: str) -> dict[str, Any]:
    kit = Toolkit(Settings.model_validate({"dataDir": str(tmp_path / "data")}), shared=True)
    out: dict[str, Any] = kit.alert_report(AlertReportIn(payload=text))["report"]
    return out


def _truncated_entries(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [n for n in body["notIncluded"] if n["what"] == "alerts truncated by Alertmanager"]


def test_split_carries_the_truncated_count() -> None:
    s = alertmanager.split(_payload(_alert("A"), truncatedAlerts=2))
    assert s is not None and s.truncated == 2 and s.truncated_unreadable is None
    assert alertmanager.split(_payload(_alert("A"))).truncated == 0  # type: ignore[union-attr]
    assert alertmanager.split(_payload(_alert("A"), truncatedAlerts=0)).truncated == 0  # type: ignore[union-attr]


def test_a_truncated_payload_is_reported_as_incomplete_with_the_count(tmp_path: Path) -> None:
    body = _report(tmp_path, _payload(_alert("KubeNodeNotReady", "resolved", node="worker-1"), truncatedAlerts=2))
    s = body["summary"]
    assert s["alerts"] == 1 and s["truncatedByAlertmanager"] == 2 and s["alertsInGroup"] == 3
    (entry,) = _truncated_entries(body)
    assert entry["count"] == 2 and "max_alerts" in entry["why"] and "never" in entry["why"]
    assert s["complete"] is False and any("truncated" in why for why in s["incompleteBecause"])
    assert any("2 truncated by Alertmanager" in c for c in body["caveats"])


def test_an_untruncated_payload_is_complete_and_unchanged_in_shape(tmp_path: Path) -> None:
    body = _report(tmp_path, _payload(_alert("KubeNodeNotReady", "resolved", node="worker-1")))
    s = body["summary"]
    assert s["truncatedByAlertmanager"] == 0 and s["alertsInGroup"] == 1
    assert s["complete"] is True and s["incompleteBecause"] == []
    assert _truncated_entries(body) == [] and not any("truncated" in c for c in body["caveats"])


def test_a_v3_payload_without_the_field_is_complete(tmp_path: Path) -> None:
    text = json.dumps({"version": "3", "status": "firing", "alerts": [_alert("A", namespace="shop")]})
    body = _report(tmp_path, text)
    assert body["summary"]["truncatedByAlertmanager"] == 0 and body["summary"]["complete"] is True


@pytest.mark.parametrize("value", ["2", -1, True, 2.5, {"n": 2}, [2]])
def test_a_truncated_count_of_the_wrong_shape_is_not_read_as_zero(tmp_path: Path, value: Any) -> None:
    body = _report(tmp_path, _payload(_alert("A", namespace="shop"), truncatedAlerts=value))
    s = body["summary"]
    assert s["truncatedByAlertmanager"] is None, "an unreadable count is not a zero"
    assert s["alertsInGroup"] is None
    assert s["complete"] is False and any("truncatedAlerts" in why for why in s["incompleteBecause"])
    (entry,) = _truncated_entries(body)
    assert entry["count"] is None and "not a non-negative integer" in entry["why"]


def test_the_text_view_says_how_many_of_the_group_the_payload_holds(tmp_path: Path, capsys: Any) -> None:
    path = tmp_path / "alert.json"
    path.write_text(_payload(_alert("KubeNodeNotReady", "resolved", node="worker-1"), truncatedAlerts=2))
    assert main(["alerts", "report", "-f", str(path)]) == 0
    out = capsys.readouterr().out
    assert "1 of 3 alerts in this payload; 2 truncated by Alertmanager (max_alerts)" in out
    assert "not included: 2 alerts truncated by Alertmanager" in out
    assert main(["--format", "json", "alerts", "report", "-f", str(path)]) == 0
    body = json.loads(capsys.readouterr().out)["report"]
    assert body["summary"]["truncatedByAlertmanager"] == 2


def test_not_evaluated_alerts_make_the_report_incomplete_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob import alert_report

    monkeypatch.setattr(alert_report, "_now", lambda: 10.0)
    body = alert_report.build(
        _payload(_alert("A", namespace="shop")),
        lambda text, version: {"signals": {"items": []}},
        memory_configured=False,
        deadline=0.0,
    )
    assert body["summary"]["complete"] is False
    assert any("not evaluated" in why for why in body["summary"]["incompleteBecause"])


def test_the_rest_route_and_the_list_row_carry_the_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    settings = load_settings(
        overrides={
            "dataDir": str(tmp_path / "data"),
            "server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]},  # noqa: S104
        }
    )
    text = _payload(_alert("KubeNodeNotReady", "resolved", node="worker-1"), truncatedAlerts=2)
    with TestClient(http_app(settings), base_url="http://testserver") as c:
        posted = c.post("/v1/alert-reports", content=text, headers={**AUTH, "Content-Type": "application/json"})
        assert posted.status_code == 200
        out = posted.json()
        assert out["report"]["summary"]["truncatedByAlertmanager"] == 2
        assert out["report"]["summary"]["complete"] is False
        listed = c.get("/v1/alert-reports", params={"limit": 5}, headers=AUTH).json()
        row = listed["reports"][0]
        assert row["alerts"] == 1 and row["truncatedByAlertmanager"] == 2 and row["complete"] is False


def test_the_cli_list_and_show_views_say_truncated(
    tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the HTTP receiver stores reports; `alerts list` and `alerts show` read that store."""
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    settings = load_settings(
        overrides={
            "dataDir": str(tmp_path / "data"),
            "server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]},  # noqa: S104
        }
    )
    text = _payload(_alert("KubeNodeNotReady", "resolved", node="worker-1"), truncatedAlerts=2)
    with TestClient(http_app(settings), base_url="http://testserver") as c:
        out = c.post("/v1/alert-reports", content=text, headers={**AUTH, "Content-Type": "application/json"}).json()
    assert out["stored"] is True
    config = tmp_path / "kube-noob.yaml"
    config.write_text(f"dataDir: {tmp_path / 'data'}\n")
    assert main(["--config", str(config), "alerts", "list"]) == 0
    assert "2 truncated by Alertmanager" in capsys.readouterr().out
    assert main(["--config", str(config), "alerts", "show", out["id"]]) == 0
    assert "2 truncated by Alertmanager (max_alerts)" in capsys.readouterr().out


# -- round 1 (10, 12) ------------------------------------------------------------------------------------------------


def test_the_group_count_includes_items_not_read_as_alerts(tmp_path: Path) -> None:
    items: list[Any] = [_alert("KubeNodeNotReady", "resolved", node=f"w{i}") for i in range(600)] + ["junk"]
    text = json.dumps({"version": "4", "status": "firing", "truncatedAlerts": 2, "alerts": items})
    body = _report(tmp_path, text)
    s = body["summary"]
    assert s["alerts"] == 500 and s["alertsInGroup"] == 603 and s["truncatedByAlertmanager"] == 2
    assert s["alertsNotRead"] == 101
    assert any("500 of 603" in c and "101 not read" in c and "2 truncated" in c for c in body["caveats"])


def test_a_truncated_count_over_the_cap_is_named_apart_from_a_type_error(tmp_path: Path) -> None:
    huge = _report(tmp_path, _payload(_alert("A", namespace="shop"), truncatedAlerts=10**9))
    why = _truncated_entries(huge)[0]["why"]
    assert "exceeds the cap" in why and "1,000,000" in why and "not a non-negative integer" not in why
    assert huge["summary"]["truncatedByAlertmanager"] is None and huge["summary"]["complete"] is False
    typed = _report(tmp_path, _payload(_alert("A", namespace="shop"), truncatedAlerts="2"))
    assert "not a non-negative integer" in _truncated_entries(typed)[0]["why"]
    ok = _report(tmp_path, _payload(_alert("A", namespace="shop"), truncatedAlerts=1_000_000))
    assert ok["summary"]["truncatedByAlertmanager"] == 1_000_000
