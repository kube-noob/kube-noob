"""SAST1 red team (2026-10-28): each reproduced finding, fixed, with the case that showed it.

The worst were fail-open paths: a high finding in a file the image really ships was "not shipped" (absolute
Containerfile path, no gate context, RUN --mount=type=bind, a BOM, a tab), so ``--fail-on high`` passed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main
from kube_noob.code import deps, sarif, ship
from kube_noob.code.sarif import CodeFinding, Location
from tests import bounds

#: Measured; re-measure with KUBE_NOOB_TEST_BOUNDS_REPORT=1 (tests/bounds.py).
HONEST_STAGES = 0.006  #: fifty build stages through `where` and `source_of`
HONEST_MERGE = 0.45  #: 40,000 then 20,000 findings through `sarif.merge`
HONEST_LONG_LINE = 0.001  #: one 40,000-space requirements line through `deps.find`


def _sarif(
    path: str, *, line: int = 9, cwe: int = 78, message: str = "subprocess call with shell=True", tool: str = "Bandit"
) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool,
                            "rules": [{"id": "B602", "properties": {"tags": ["security", f"external/cwe/cwe-{cwe}"]}}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "B602",
                            "level": "error",
                            "message": {"text": message},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}
                            ],
                            "properties": {"issue_severity": "HIGH"},
                        }
                    ],
                }
            ],
        }
    )


def _repo(tmp: Path, files: dict[str, str | bytes], finding: str) -> Path:
    for rel, data in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    (tmp / "bandit.sarif").write_text(_sarif(finding))
    return tmp


def _code(repo: Path, *build: str) -> int:
    args = ["code", "report", "--repo", str(repo), "-s", str(repo / "bandit.sarif"), "--fail-on", "high"]
    for b in build:
        args += ["-c", b]
    return main(args)


def _gate(repo: Path, monkeypatch: pytest.MonkeyPatch, *containerfiles: str, extra: tuple[str, ...] = ()) -> int:
    monkeypatch.chdir(repo)
    args = ["gate", "--sarif-report", "bandit.sarif", "--fail-on", "high", *extra]
    for c in containerfiles:
        args += ["--containerfile", c]
    return main(args)


def _where(text: str, path: str, context: str = ".", ignore: str = "") -> list[ship.Shipped]:
    return ship.where([ship.parse_build(ship.Build("Containerfile", text, "img", context, ignore))], path)


def test_rt1_absolute_containerfile_and_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(
        tmp_path,
        {"web/Containerfile": "FROM python:3.12\nCOPY app/ ./app/\n", "web/app/views.py": "x\n"},
        "web/app/views.py",
    )
    assert _code(repo, "web/Containerfile") == 1
    assert _code(repo, f"{repo}/web/Containerfile") == 1
    assert _code(repo, f"{repo}/web/Containerfile,context={repo}/web") == 1
    capsys.readouterr()
    assert _gate(repo, monkeypatch, f"{repo}/web/Containerfile") == 1
    assert "not shipped" not in capsys.readouterr().out
    with pytest.raises(ship.ShipError, match="absolute"):
        ship.parse_build(ship.Build("Containerfile", "FROM x\n", "", "/abs/ctx"))


def test_rt2_gate_takes_a_build_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(
        tmp_path,
        {"deploy/Containerfile": "FROM python:3.12\nCOPY src/ /app/src/\n", "src/app/views.py": "x\n"},
        "src/app/views.py",
    )
    assert _gate(repo, monkeypatch, "deploy/Containerfile") == 0  # its own directory as context: src/ is not in it
    assert _gate(repo, monkeypatch, "deploy/Containerfile=shop/web:1,context=.") == 1
    assert "in shipped code" in capsys.readouterr().out


def test_rt3_run_mount_bind_builds_the_image(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dockerfile = (
        "FROM golang:1.23 AS build\nWORKDIR /src\n"
        "RUN --mount=type=cache,target=/go/pkg/mod --mount=type=bind,target=. go build -o /bin/server .\n"
        "FROM gcr.io/distroless/static\nCOPY --from=build /bin/server /bin/\n"
    )
    repo = _repo(tmp_path, {"Dockerfile": dockerfile, "main.go": "package main\n"}, "main.go")
    assert [s.how for s in _where(dockerfile, "main.go")] == ["built"]
    assert _gate(repo, monkeypatch, "Dockerfile") == 1
    assert _code(repo, "Dockerfile=shop/server:1") == 1
    from_stage = (
        "FROM node AS deps\nCOPY package.json .\nFROM node\nRUN --mount=type=bind,from=deps,target=/d cp -r /d .\n"
    )
    assert [s.how for s in _where(from_stage, "package.json")] == ["built"]
    secret_only = "FROM python\nRUN --mount=type=secret,id=x --mount=type=cache,target=/c make\n"
    assert _where(secret_only, "main.py") == []


def test_rt4_byte_order_mark(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = "FROM golang AS build\nCOPY . .\nRUN go build -o /out/app\nFROM scratch\nCOPY --from=build /out/app /app\n"
    repo = _repo(tmp_path, {"Dockerfile": b"\xef\xbb\xbf" + text.encode(), "main.go": "package main\n"}, "main.go")
    assert _gate(repo, monkeypatch, "Dockerfile") == 1
    assert [s.how for s in _where("﻿" + text, "main.go")] == ["built"]


@pytest.mark.parametrize(
    "text",
    [
        "FROM python\nCOPY\tapp/ ./app/\n",
        "FROM python\nCOPY --chown=1001:0\tapp/ ./app/\n",
        "FROM python\nENV NOTE=x<<EOF\nCOPY app/ ./app/\n",
        "FROM python\nRUN echo $((1<<SHIFT))\nCOPY app/ ./app/\n",
        "FROM python\nRUN <<EOF\necho hi\nEOF\nCOPY app/ ./app/\n",
        'FROM python\nCOPY --chown="1001:0" app/ ./app/\n',
    ],
)
def test_rt5_parser_matches_buildkit(text: str) -> None:
    (shipped,) = _where(text, "app/views.py")
    assert shipped.how == "copied" and shipped.image_path == "/app/views.py"


def test_rt5_heredoc_copy_takes_nothing_from_the_context() -> None:
    assert _where("FROM python\nCOPY <<EOF /app/views.py\nprint(1)\nEOF\n", "app/views.py") == []


def test_rt6_unmappable_paths_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cf = "FROM node\nCOPY web/ /srv/\n"
    repo = _repo(tmp_path, {"Containerfile": cf, "web/server.js": "x\n"}, "file:///usr/src/app/web/server.js")
    assert _gate(repo, monkeypatch, "Containerfile") == 1
    out = capsys.readouterr().out
    assert "shipping unknown" in out and "source root" in out
    assert _code(repo, "Containerfile") == 1
    assert "whose shipping is not known" in capsys.readouterr().out
    assert _gate(repo, monkeypatch, "Containerfile", extra=("--source-root", "/usr/src/app")) == 1  # shipped
    (repo / "bandit.sarif").write_text(_sarif("./app/views.py"))  # scanned from web/: no such file at the root
    (repo / "web" / "app").mkdir()
    (repo / "web" / "app" / "views.py").write_text("x\n")
    assert _gate(repo, monkeypatch, "Containerfile") == 1
    assert "no such file in the repository" in capsys.readouterr().out
    (repo / "bandit.sarif").write_text(_sarif("tools/seed.py"))
    (repo / "tools").mkdir()
    (repo / "tools" / "seed.py").write_text("x\n")
    assert _gate(repo, monkeypatch, "Containerfile") == 0  # a real file no image ships still passes


def test_rt7_many_stages_are_linear() -> None:
    lines = ["FROM busybox AS s0", "COPY app/ /app/"]
    for k in range(1, 50):
        lines.append(f"FROM busybox AS s{k}")
        lines += [f"COPY --from=s{j} /app /app" for j in range(k)]
    text = "\n".join(lines) + "\n"
    b = ship.parse_build(ship.Build("Containerfile", text, "img"))
    # CUBIC_RISK, not LINEAR: fifty stages is 1,225 `COPY --from` lines, and `where`/`source_of` walking them per
    # stage is quadratic in that, which is a thousandfold rather than a hundredfold. With LINEAR the ceiling this
    # helper derives under coverage on a shared runner (2.06 s) exceeds its own detection threshold (0.6 s), so
    # `VacuousBound` fires in CI -- the helper refusing a shape that could not catch what it names.
    with bounds.bounded(bounds.CUBIC_RISK, honest_seconds=HONEST_STAGES, guards="fifty build stages"):
        assert ship.where([b], "app/views.py")
        assert ship.source_of(b, "/app/views.py") == [("app/views.py", 2)]


def _finding(rule: str, cwe: tuple[int, ...] = ()) -> CodeFinding:
    src = [{"tool": "Semgrep", "ruleId": rule, "severity": "high"}]
    return CodeFinding("Semgrep", rule, rule, "m", "high", "x", True, cwe, Location("a.py", 1), rule, sources=src)


def test_rt8_merge_is_linear() -> None:
    many = [_finding(f"rule-{i}") for i in range(40_000)]
    shared = [_finding(f"rule-{i}", (78,)) for i in range(20_000)]
    with bounds.bounded(bounds.LINEAR, honest_seconds=HONEST_MERGE, guards="60,000 findings through merge"):
        assert len(sarif.merge(many)) == 40_000
        (one,) = sarif.merge(shared)
        assert len(one.sources) == 20_000
    a, b, c = _finding("r1", (89,)), _finding("r2", (79,)), _finding("r3", (89, 79))
    merged = sarif.merge([a, b, c])
    assert len(merged) == 2 and merged[0].cwe == (79, 89)  # c joins the first finding it shares a CWE with


def test_rt9_dependency_lines() -> None:
    pom = "\n".join(
        [
            "<project>",  # 1
            "  <dependencies>",
            "    <dependency>",
            "      <groupId>com.example</groupId>",
            "      <artifactId>client</artifactId>",
            "      <exclusions>",
            "        <exclusion>",
            "          <groupId>org.yaml</groupId>",
            "          <artifactId>snakeyaml</artifactId>",  # 9: excluded, not declared
            "        </exclusion>",
            "      </exclusions>",
            "    </dependency>",
            "    <dependency>",
            "      <groupId>other.group</groupId>",
            "      <artifactId>snakeyaml</artifactId>",  # 15: another group
            "    </dependency>",
            "    <dependency><groupId>org.yaml</groupId>",
            "      <artifactId>snakeyaml</artifactId>",  # 18
            "    </dependency>",
            "  </dependencies>",
            "</project>",
        ]
    )
    (hit,) = deps.find({"worker/pom.xml": pom}, "maven", "org.yaml:snakeyaml")
    assert hit.line == 18
    package = (
        '{\n  "name": "ui",\n  "scripts": {\n    "serve": "serve -s build"\n  },\n'
        '  "dependencies": {\n    "serve": "14.0.0"\n  }\n}\n'
    )
    assert deps.find({"ui/package.json": package}, "npm", "serve")[0].line == 7
    lock = (
        '{\n  "packages": {\n    "node_modules/express": {\n      "dependencies": {\n        "qs": "6.11.0"\n'
        '      }\n    },\n    "node_modules/qs": {\n      "version": "6.11.0"\n    }\n  }\n}\n'
    )
    assert deps.find({"api/package-lock.json": lock}, "npm", "qs")[0].line == 8
    v1 = (
        '{\n  "dependencies": {\n    "express": {\n      "requires": {\n        "qs": "^6"\n      }\n    },\n'
        '    "qs": {\n'
    )
    assert (
        deps.find({"api/package-lock.json": v1 + '      "version": "6.1.0"\n    }\n  }\n}\n'}, "npm", "qs")[0].line == 8
    )


def test_rt10_copy_glob_does_not_cross_slashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = "FROM python\nCOPY *.py /app/\n"
    assert _where(text, "tests/test_db.py") == [] and _where(text, "tools/deep/seed.py") == []
    assert [s.image_path for s in _where(text, "app.py")] == ["/app/app.py"]
    assert [s.image_path for s in _where("FROM python\nCOPY src/*/main.py /app/\n", "src/a/main.py")] == [
        "/app/main.py"
    ]
    repo = _repo(tmp_path, {"Containerfile": text, "app.py": "x\n", "tests/test_db.py": "x\n"}, "tests/test_db.py")
    assert _gate(repo, monkeypatch, "Containerfile") == 0


def test_rt11_dockerfile_specific_ignore(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        {
            ".dockerignore": "admin/\n",
            "admin.Dockerfile": "FROM node\nCOPY admin/ /srv/\n",
            "admin.Dockerfile.dockerignore": "*.md\n",
            "admin/server.js": "x\n",
        },
        "admin/server.js",
    )
    assert _code(repo, "admin.Dockerfile=shop/admin:1,context=.") == 1
    (repo / "admin.Dockerfile.dockerignore").unlink()
    assert _code(repo, "admin.Dockerfile=shop/admin:1,context=.") == 0  # the root .dockerignore leaves admin/ out


def test_rt12_no_backtracking_on_long_lines() -> None:
    line = "requests" + " " * 40_000 + "x"
    with bounds.bounded(bounds.BACKTRACKING, honest_seconds=HONEST_LONG_LINE, guards="a 40,000-space dependency line"):
        assert deps.find({"requirements.txt": line}, "pypi", "requests") == []
        assert deps.find({"pyproject.toml": f'"{line}"'}, "pypi", "requests") == []
    assert deps.find({"requirements.txt": "requests [security] ==2.0\n"}, "pypi", "requests")[0].line == 1


def test_rt13_invalid_ignore_patterns_do_not_crash(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.build import containerfile as cf

    bad: list[str] = []
    rules = cf.ignore_rules("[]\n[!]\n[z-a].py\n*.md\n", bad)
    assert len(rules) == 1 and bad == ["[]", "[!]", "[z-a].py"]
    repo = _repo(
        tmp_path,
        {".dockerignore": "[]\n[!]\n", "Containerfile": "FROM python\nCOPY app/ /app/\n", "app/views.py": "x\n"},
        "app/views.py",
    )
    assert _code(repo, "Containerfile") == 1
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path / "data")}))
    out = kit.code_report(
        tk.CodeReportIn(
            sarif=[_sarif("app/views.py")],
            containerfiles=[tk.CodeBuildIn(path="Containerfile", text="FROM python\nCOPY app/ /app/\n", ignore="[]")],
        )
    )
    assert out["counts"]["shipped"] == 1


@pytest.mark.parametrize("uri", ["web/app%0Aforged%1B[2J.py", "web/app%00.py", "web/%E2%80%AEevil.py"])
def test_rt14_decoded_control_characters(uri: str) -> None:
    (f,) = sarif.parse(_sarif(uri)).findings
    assert not any(ch in f.location.path for ch in "\n\x00\x1b\u202e") and not f.location.resolved


def test_rt15_lone_surrogate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = _sarif("app/views.py", message="bad \ud800 message")
    (f,) = sarif.parse(text).findings
    assert f.message == "bad ? message" and f.fingerprint.startswith("kube-noob:")
    repo = _repo(tmp_path, {"Containerfile": "FROM python\nCOPY app/ /app/\n", "app/views.py": "x\n"}, "app/x.py")
    (repo / "bandit.sarif").write_text(text)
    assert _gate(repo, monkeypatch, "Containerfile", extra=("--summary", "summary.md")) == 1
    assert (repo / "summary.md").read_text(encoding="utf-8")


def test_rt16_insight_reads_sarif_without_schema(tmp_path: Path) -> None:
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings
    from kube_noob.insight import insight

    doc: dict[str, Any] = json.loads(_sarif("app/views.py"))
    assert "$schema" not in doc
    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    seen = insight(kit, json.dumps(doc))
    assert "code" in seen["ran"] and any("CWE-78" in json.dumps(f) for f in seen["findings"])
