"""Scripted demos: at least 5 offline scenarios, each fast, never touching the network or the user's data."""

from __future__ import annotations

import json
import socket
import time
import tomllib
from pathlib import Path
from typing import Any

import pytest

from kube_noob import demo
from kube_noob.cli import main
from kube_noob.config import load_settings

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any, **__: Any) -> None:
        raise AssertionError("a demo tried to open a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_demo_list(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "--list", "--format", "json"]) == 0
    names = [d["name"] for d in json.loads(capsys.readouterr().out)]
    assert len(names) >= 5 and {"audit", "diagnose", "learn", "doctor"} <= set(names)


@pytest.mark.parametrize("name", list(demo.SCENARIOS))
def test_each_demo_runs_offline_fast_and_isolated(name: str, no_network: None) -> None:
    s = load_settings(overrides={"webEnabled": True, "cluster": {"enabled": True}})
    lines: list[str] = []
    start = time.monotonic()
    demo.run(name, s, lines.append)
    assert time.monotonic() - start < 10
    text = "\n".join(lines)
    assert "$ kube-noob" in text and "Traceback" not in text
    assert not (s.data_dir / "learning.json").exists() and not (s.data_dir / "progress").exists()


def test_examples_ship_in_the_wheel() -> None:
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    force = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert force["examples"] == "kube_noob/data/examples"
    assert {"insecure-deployment.yaml", "events-scc.txt", "blueprint.yaml"} <= {
        p.name for p in demo.examples_dir().iterdir()
    }


def test_protocol_runs_all_seven_steps_in_order() -> None:
    from kube_noob.audit.protocol import run_protocol

    out = run_protocol(
        "deploy orders-api",
        blueprint={"name": "orders-api", "namespace": "shop", "image": "quay.io/x/y:1.0.0", "platform": "openshift"},
    )
    assert list(out["steps"]) == ["clarify", "validate", "research", "audit", "calibrate", "generate", "redTeam"]


def test_every_scenario_has_a_recorded_tape() -> None:
    tapes = {p.stem: p.read_text() for p in (ROOT / "demos").glob("*.tape")}
    for name in demo.SCENARIOS:
        assert name in tapes, f"demos/{name}.tape missing"
        assert f"Output demos/out/{name}.gif" in tapes[name] and f'Type "kube-noob demo {name}"' in tapes[name]
    assert 'Type "kube-noob demo --list"' in tapes["tour"]


def test_cli_exits_quietly_when_the_reader_goes_away() -> None:
    import subprocess
    import sys

    proc = subprocess.Popen(
        [sys.executable, "-m", "kube_noob", "demo", "all"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None and proc.stderr is not None
    first = proc.stdout.readline()
    proc.stdout.close()
    err = proc.stderr.read()
    proc.wait(timeout=60)
    assert first.startswith("== kube-noob demo") and "Traceback" not in err
