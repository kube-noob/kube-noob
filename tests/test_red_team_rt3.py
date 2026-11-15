"""Red team RT3: a directory of manifests that is not all readable.

``audit -f DIR`` and ``gate -f DIR`` are the CI surfaces. Both walked the directory, read every ``.yaml`` as UTF-8
and concatenated the lot into one document before parsing, so a single file that is not valid UTF-8 or not valid
YAML decided the outcome for the whole directory - and decided it without naming itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob.cli import main

GOOD = """apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
    - name: c
      image: nginx:latest
      securityContext:
        privileged: true
"""

SECOND = GOOD.replace("name: p", "name: q").replace("nginx", "busybox")


def _dir(tmp_path: Path, **files: bytes | str) -> Path:
    d = tmp_path / "manifests"
    d.mkdir()
    for name, body in files.items():
        p = d / name.replace("_", ".")
        p.write_bytes(body if isinstance(body, bytes) else body.encode())
    return d


def test_a_crash_never_wears_the_exit_code_of_a_policy_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """RT3-1. ``gate`` exits 1 for findings at or above ``--fail-on``. A NUL byte in one file used to raise
    yaml.reader.ReaderError out of the command, which also left 1: a pipeline then reported policy violations for a
    gate that had audited nothing. The two outcomes must not share an exit code."""
    d = _dir(tmp_path, good_yaml=GOOD, blob_yaml=b"\x00\x01binary\xff")
    code = main(["gate", "-f", str(d), "--fail-on", "never"])
    err = capsys.readouterr().err
    assert code == 5, f"expected 5 (unreadable evidence), got {code}"
    assert "blob.yaml" in err
    assert "Traceback" not in err and "ReaderError" not in err


def test_an_unreadable_file_is_named_not_located_in_a_concatenation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """RT3-2. The YAML error pointed at a line of the concatenated string, which is no line of any file the user can
    open. The file that could not be parsed has to be named."""
    d = _dir(tmp_path, good_yaml=GOOD, broken_yaml="apiVersion: v1\nkind: Pod\nmetadata:\n  labels: {a: b\n")
    code = main(["audit", "-f", str(d), "--fail-on", "never"])
    err = capsys.readouterr().err
    assert code == 5
    assert "broken.yaml" in err
    assert "<unicode string>" not in err


def test_one_bad_file_does_not_hide_the_findings_in_the_good_ones(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """RT3-3. Refusing the whole directory over one file meant the real violations in the other files were never
    reported at all. With --skip-unreadable the readable files are audited and the skipped ones stay named in
    `unreadable` in every format. The flag is the caller saying "decide without that file", so the exit code is
    the verdict's and not 5 -- here 0, because the files that were read are clean at `--fail-on never` (the
    exit-code section of AGENTS.md states the rule; without the flag the same directory is 5, above)."""
    d = _dir(tmp_path, good_yaml=GOOD, second_yaml=SECOND, blob_yaml=b"\x00\xff")
    code = main(["audit", "-f", str(d), "--skip-unreadable", "--fail-on", "never", "--format", "json"])
    out = capsys.readouterr()
    assert code == 0, out.err
    report = json.loads(out.out)
    assert report["findings"], "the readable manifests were audited"
    assert [u["path"] for u in report["unreadable"]] == ["blob.yaml"]
    assert report["unreadable"][0]["why"]


def test_skip_unreadable_still_fails_on_severity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """RT3-3b. Skipping an unreadable file must not weaken --fail-on for the files that were read."""
    d = _dir(tmp_path, good_yaml=GOOD, blob_yaml=b"\x00\xff")
    code = main(["audit", "-f", str(d), "--skip-unreadable", "--fail-on", "high"])
    capsys.readouterr()
    assert code == 1


def test_a_clean_directory_is_unchanged(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """RT3 regression: nothing above may shift the result for a directory that reads fine."""
    d = _dir(tmp_path, good_yaml=GOOD, second_yaml=SECOND)
    assert main(["audit", "-f", str(d), "--fail-on", "never", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] and report.get("unreadable") == []
    assert main(["gate", "-f", str(d), "--fail-on", "never"]) == 0
    capsys.readouterr()


def test_a_directory_with_nothing_to_audit_says_so(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """RT3-4. An empty directory, or one whose only YAML could not be read, is not a clean audit."""
    empty = _dir(tmp_path, notes_txt="not a manifest")
    assert main(["audit", "-f", str(empty), "--fail-on", "never"]) != 0
    assert "no" in capsys.readouterr().err.lower()
