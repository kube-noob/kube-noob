from __future__ import annotations

import os
from pathlib import Path

import pytest

from kube_noob.config import Settings, load_settings

FIXTURES = Path(__file__).parent / "fixtures"


def _escape(text: str, prop: bool = False) -> str:
    out = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return out.replace(":", "%3A").replace(",", "%2C") if prop else out


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    """The false-pass benchmark's table (per defect class and per source branch: cases, enforced, waiting for a
    merge, failed), when its cases ran; and on GitHub Actions each failure as an error annotation (the runner's log
    host is not always readable)."""
    from tests.falsepass import harness as falsepass

    outcomes = terminalreporter.config.stash.get(falsepass.STASH_KEY, None)
    if outcomes:
        terminalreporter.ensure_newline()
        for line in falsepass.summary_lines(outcomes):
            terminalreporter.write_line(line)
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for report in terminalreporter.stats.get("failed", []) + terminalreporter.stats.get("error", []):
        crash = getattr(report.longrepr, "reprcrash", None)
        root = str(terminalreporter.config.rootpath)
        where = f"file={_escape(os.path.relpath(crash.path, root), True)},line={crash.lineno}," if crash else ""
        detail = str(crash.message if crash is not None else report.longrepr)[:1500]
        title = _escape(f"pytest {report.nodeid}", True)
        terminalreporter.write_line(f"::error {where}title={title}::{_escape(detail)}")


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in (
        "KUBE_NOOB_CONFIG",
        "KUBE_NOOB_WEB_ENABLED",
        "KUBE_NOOB_CLUSTER_ENABLED",
        "KUBE_NOOB_HTTP_TOKEN",
        "KUBE_NOOB_LLM_PROVIDER",
        "KUBE_NOOB_LLM_MODEL",
        "KUBE_NOOB_DEFAULT_PLATFORM",
        "KUBE_NOOB_OFFLINE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("kube_noob.config.SYSTEM_CONFIG", tmp_path / "no-system-config.yaml")
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = load_settings()
    return s


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")
