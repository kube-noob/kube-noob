"""`scripts/brew_formula.py` asked PyPI once, and one dropped connection failed a pull request (G436).

On 2026-11-27 the `plugin` job's `brew_formula.py --check` died on `SSL: UNEXPECTED_EOF_WHILE_READING` reading
PyPI's JSON: a transient transport error, reported as a failed check on a change that had nothing to do with the
formula. One retry, and a failure that is still loud when both attempts fail -- a check that swallowed the error
would be a formula nobody compared reading as one that matches.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("brew_formula_under_test", ROOT / "scripts" / "brew_formula.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


brew = _load()
EOF = urllib.error.URLError("[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1010)")


def _urlopen(answers: list[Any], calls: list[str]) -> Any:
    def urlopen(url: str, timeout: float = 0) -> Any:
        assert timeout > 0, "a read with no timeout hangs the job instead of failing it"
        calls.append(url)
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return io.BytesIO(answer)

    return urlopen


def test_a_transient_error_reading_pypi_is_retried_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        brew.urllib.request, "urlopen", _urlopen([EOF, json.dumps({"info": {"version": "1.2.3"}}).encode()], calls)
    )
    monkeypatch.setattr(brew, "RETRY_PAUSE", 0)
    assert brew._get_json("https://pypi.org/pypi/kube-noob/json") == {"info": {"version": "1.2.3"}}
    assert len(calls) == 2


def test_two_failures_are_still_a_loud_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(brew.urllib.request, "urlopen", _urlopen([EOF, EOF, b"{}"], calls))
    monkeypatch.setattr(brew, "RETRY_PAUSE", 0)
    with pytest.raises(urllib.error.URLError, match="UNEXPECTED_EOF"):
        brew._get_json("https://pypi.org/pypi/kube-noob/json")
    assert len(calls) == 2, "one retry, not a loop"


def test_a_404_is_an_answer_and_is_not_asked_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    """The release's homebrew job polls for a version PyPI does not serve yet; that 404 is the answer it waits on."""
    calls: list[str] = []
    gone = urllib.error.HTTPError("https://pypi.org/pypi/kube-noob/9.9.9/json", 404, "Not Found", {}, None)  # type: ignore[arg-type]
    monkeypatch.setattr(brew.urllib.request, "urlopen", _urlopen([gone, b"{}"], calls))
    monkeypatch.setattr(brew, "RETRY_PAUSE", 0)
    with pytest.raises(urllib.error.HTTPError):
        brew._get_json("https://pypi.org/pypi/kube-noob/9.9.9/json")
    assert len(calls) == 1


def test_the_sdist_download_is_retried_the_same_way(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(brew.urllib.request, "urlopen", _urlopen([EOF, b"bytes"], calls))
    monkeypatch.setattr(brew, "RETRY_PAUSE", 0)
    assert brew._read("https://files.pythonhosted.org/packages/x/kube_noob-1.2.3.tar.gz", 120) == b"bytes"
    assert len(calls) == 2
    src = (ROOT / "scripts" / "brew_formula.py").read_text(encoding="utf-8")
    assert src.count("urllib.request.urlopen(") == 1, "every read goes through the one function that retries"
