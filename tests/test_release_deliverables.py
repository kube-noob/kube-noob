"""A release is shipped when every deliverable it promises is seen where it is served (G436).

In one session the scan video was attached to v0.11.0 and never appeared on kube-noob.com/videos/, the mechanisms
page was live with nothing linking to it, the formula on main served the previous version, and v0.11.1's release
carried no video for hours -- and `release-ready` said nothing about any of them, because it asks whether the
release RUN succeeded, not whether what the run promises can be fetched. Every one was knowable from the
repository's own sources of truth.

`scripts/release_deliverables.py` derives the list from those sources (the two workflows, videos.json, the tapes,
server.json, the lessons) and reads each deliverable where it is served. These tests never touch the network: the
module's one `fetch` is replaced by a world built here, and the list is checked against an independent reading of
the same files so that the two cannot drift.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import quote

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release_deliverables.py"
API = "https://api.github.com/repos/kube-noob/kube-noob"
SITE = "https://kube-noob.com"
PYPI = "https://pypi.org/pypi/kube-noob/json"
REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
SHA = "4ca8c0906f90c4d51c3ebff53a12b2cb154cfc52"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("release_deliverables", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mod = _load()
VERSION: str = mod.tree_version(ROOT)


@pytest.fixture(scope="module")
def plan() -> Any:
    return mod.derive(ROOT, VERSION)


def _resp(status: int, body: Any = b"", headers: dict[str, str] | None = None) -> Any:
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    elif isinstance(body, str):
        body = body.encode()
    return mod.Response(status, body, headers or {})


def _world(plan: Any, version: str = VERSION) -> dict[str, Any]:
    """Every URL the ledger reads, answering as a release that got everywhere would."""
    sdist = f"https://files.pythonhosted.org/packages/aa/bb/cc/kube_noob-{version}.tar.gz"
    home = (
        '<nav class="main" id="main-nav" aria-label="Main"><a href="/start/">Start</a>'
        '<a href="/learn/mechanisms/">Learn</a><a href="/videos/">Videos</a></nav>'
        f'<script type="application/ld+json">{{"softwareVersion":"{version}"}}</script>'
        f'<span class="pill">kube-noob {version} · 100 rules</span>'
        f"<footer><span>kube-noob {version} · Apache-2.0</span></footer>"
    )
    cards = "".join(
        f'<div class="video-card"><video poster="/videos/kube-noob-{v}.jpg" src="/videos/kube-noob-{v}.mp4">'
        f'<track src="/videos/kube-noob-{v}.vtt"></video></div>'
        for v in plan.videos
    )
    lessons = "".join(
        f'<li class="lesson" id="{lsn.id}"><h3 class="lesson-title">{lsn.title}</h3>'
        f'<a href="{lsn.id}/example-1/">walk</a></li>'
        for lsn in plan.lessons
    )
    world: dict[str, Any] = {
        PYPI: _resp(
            200,
            {
                "info": {"version": version},
                "releases": {
                    version: [
                        {"packagetype": "sdist", "filename": f"kube_noob-{version}.tar.gz", "url": sdist},
                        {"packagetype": "bdist_wheel", "filename": f"kube_noob-{version}-py3-none-any.whl"},
                    ]
                },
            },
        ),
        f"{API}/releases/tags/v{version}": _resp(200, {"id": 7, "tag_name": f"v{version}", "draft": False}),
        f"{API}/releases/7/assets?per_page=100&page=1": _resp(
            200, [{"name": name, "state": "uploaded", "size": 10} for name in plan.assets]
        ),
        f"{API}/contents/Formula/kube-noob.rb?ref=main": _resp(
            200, f'class KubeNoob < Formula\n  url "{sdist}"\n  sha256 "00"\nend\n'
        ),
        "https://ghcr.io/token?scope=repository:kube-noob/kube-noob:pull": _resp(200, {"token": "anon-image"}),
        "https://ghcr.io/token?scope=repository:kube-noob/charts/kube-noob:pull": _resp(200, {"token": "anon-chart"}),
        f"https://ghcr.io/v2/kube-noob/charts/kube-noob/manifests/{plan.chart_version}": _resp(
            200, {"schemaVersion": 2}, {"Docker-Content-Digest": "sha256:c"}
        ),
        f"{REGISTRY}?search={quote(plan.registry_name, safe='')}&limit=100": _resp(
            200, {"servers": [{"server": {"name": plan.registry_name, "version": version}}], "metadata": {"count": 1}}
        ),
        f"{SITE}/": _resp(200, home),
        f"{SITE}/videos/": _resp(200, f"<main>{cards}</main><footer>kube-noob {version}</footer>"),
        f"{SITE}/learn/mechanisms/": _resp(
            200, f"<ul>{lessons}</ul><footer><p>Built from kube-noob {version}. Every example</p></footer>"
        ),
    }
    for tag in plan.image_tags:
        world[f"https://ghcr.io/v2/kube-noob/kube-noob/manifests/{tag}"] = _resp(
            200, {"schemaVersion": 2}, {"Docker-Content-Digest": "sha256:i"}
        )
    for v in plan.videos:
        world[f"{SITE}/videos/kube-noob-{v}.mp4"] = _resp(200, b"", {"Content-Length": "1000"})
    for lsn in plan.lessons:
        world[f"{SITE}/learn/mechanisms/{lsn.id}/example-1/"] = _resp(
            200, f"<title>{lsn.title} - kube-noob mechanism walk</title>"
        )
    return world


class _Fetch:
    """Stands in for the module's one fetch. A URL the world does not hold is a test that forgot something."""

    def __init__(self, world: dict[str, Any]) -> None:
        self.world = world
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    def __call__(self, url: str, *, headers: dict[str, str] | None = None, method: str = "GET", **_: Any) -> Any:
        self.calls.append((method, url, dict(headers or {})))
        if url not in self.world:
            raise AssertionError(f"the ledger read {url}, which this test's world does not hold")
        answer = self.world[url]
        if isinstance(answer, Exception):
            raise answer
        return answer


def _rows(plan: Any, world: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    return {row.id: row for row in mod.check(plan, fetch=_Fetch(world), **kwargs)}


def _main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], world: dict[str, Any], *argv: str
) -> tuple[int, str]:
    """Run the command as a person would, on this checkout standing in for the tagged tree."""
    monkeypatch.setattr(mod, "fetch", _Fetch(world))
    monkeypatch.setattr(mod, "_git", lambda _root, *_args: SHA)
    code = mod.main(["--version", VERSION, *argv])
    return code, capsys.readouterr().out


# ----- the list is derived, and the derivation is pinned to the files it reads -----


def _videos_yml() -> dict[str, Any]:
    spec: dict[str, Any] = yaml.safe_load((ROOT / ".github/workflows/videos.yml").read_text(encoding="utf-8"))
    return spec


def test_the_video_list_is_videos_json_plus_walkthrough_and_videos_yml_renders_exactly_that(plan: Any) -> None:
    """The statement the whole video half of the ledger rests on, read from the workflow so the two cannot drift."""
    matrix = _videos_yml()["jobs"]["render"]["strategy"]["matrix"]["video"]
    scripted = list(json.loads((ROOT / "demos/video/stage/videos.json").read_text(encoding="utf-8"))["videos"])
    assert sorted(matrix) == sorted([*scripted, "walkthrough"]), (
        "videos.yml's matrix is no longer videos.json plus the walkthrough; the ledger's video list is wrong"
    )
    assert sorted(plan.videos) == sorted(matrix)
    assert len(plan.videos) >= 6


def test_the_assets_are_what_release_yml_and_videos_yml_upload(plan: Any) -> None:
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    upload = next(
        s["run"] for s in release["jobs"]["github-release"]["steps"] if s.get("name") == "Create GitHub release"
    )
    assert "assets=(dist/* assets/* demos/*.gif chart/*.tgz skill/*.zip)" in upload, (
        "release.yml uploads something else now; teach scripts/release_deliverables.py what the new glob holds"
    )
    assets = set(plan.assets)
    # What v0.11.0's release page actually carried, with the version swapped: names read from GitHub, not guessed.
    for name in (
        f"kube_noob-{VERSION}-py3-none-any.whl",
        f"kube_noob-{VERSION}.tar.gz",
        f"kube-noob-{VERSION}.tgz",
        f"kube-noob-skill-{VERSION}.zip",
        f"kubectl-noob-v{VERSION}.tar.gz",
        "sbom.spdx.json",
        "SHA256SUMS-videos.txt",
        "sidecar-transcript-4.22.txt",
        "youtube-description.txt",
        "youtube-thumbnail.jpg",
        "youtube-thumbnail.png",
    ):
        assert name in assets, f"{name} is on every release page and not in the derived list"
    for tape in (ROOT / "demos").glob("*.tape"):
        assert f"{tape.stem}.gif" in assets
    for video in _videos_yml()["jobs"]["render"]["strategy"]["matrix"]["video"]:
        for suffix in ("-4k.mp4", "-1080p.mp4", ".jpg", ".vtt"):
            assert f"kube-noob-{video}{suffix}" in assets
    tapes = len(list((ROOT / "demos").glob("*.tape")))
    assert len(assets) == 11 + tapes + 4 * len(plan.videos), sorted(assets)
    assert list(plan.assets) == sorted(plan.assets), "the order is not deterministic"
    assert plan.problems == ()


def test_the_image_the_chart_and_the_registry_name_come_from_the_files_that_publish_them(plan: Any) -> None:
    major_minor = ".".join(VERSION.split(".")[:2])
    assert plan.image == "kube-noob/kube-noob" and plan.image_tags == (VERSION, major_minor)
    assert plan.chart == "kube-noob/charts/kube-noob"
    chart = yaml.safe_load((ROOT / "deploy/helm/kube-noob/Chart.yaml").read_text(encoding="utf-8"))
    assert plan.chart_version == str(chart["version"])
    assert plan.registry_name == json.loads((ROOT / "server.json").read_text(encoding="utf-8"))["name"]
    assert [lsn.id for lsn in plan.lessons] == sorted(lsn.id for lsn in plan.lessons)
    assert len(plan.lessons) >= 6 and all(lsn.title and lsn.walk for lsn in plan.lessons)


def _tree(tmp_path: Path) -> Path:
    for rel in (
        ".github/workflows/release.yml",
        ".github/workflows/videos.yml",
        "demos/video/stage/videos.json",
        "server.json",
        "pyproject.toml",
        "deploy/helm/kube-noob/Chart.yaml",
        "src/kube_noob/__init__.py",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, tmp_path / rel)
    for tape in (ROOT / "demos").glob("*.tape"):
        shutil.copy(tape, tmp_path / "demos" / tape.name)
    return tmp_path


def test_adding_a_video_to_videos_json_adds_rows(tmp_path: Path, plan: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mod, "lessons", lambda _tree: plan.lessons)
    tree = _tree(tmp_path)
    scripts = tree / "demos/video/stage/videos.json"
    data = json.loads(scripts.read_text(encoding="utf-8"))
    data["videos"]["upgrade"] = {"title": "t", "scenes": []}
    scripts.write_text(json.dumps(data), encoding="utf-8")
    grown = mod.derive(tree, VERSION)
    assert "upgrade" in grown.videos
    new = set(grown.assets) - set(plan.assets)
    assert new == {f"kube-noob-upgrade{s}" for s in ("-4k.mp4", "-1080p.mp4", ".jpg", ".vtt")}
    rows = _rows(grown, _world(plan))
    assert rows["github-release:asset:kube-noob-upgrade-4k.mp4"].state == mod.MISSING
    assert rows["website:video-card:upgrade"].state == mod.MISSING
    # videos.yml was not taught to render it, and a list the two files disagree on is not a list to check off.
    drift = rows["ledger:video-list"]
    assert drift.state == mod.NOT_KNOWN and "upgrade" in drift.reason


def test_an_upload_this_checker_does_not_recognise_is_not_known_never_dropped(
    tmp_path: Path, plan: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new glob in release.yml is a new deliverable. Reading the old five and saying `delivered` would be the
    hand-written list this script exists to replace."""
    monkeypatch.setattr(mod, "lessons", lambda _tree: plan.lessons)
    tree = _tree(tmp_path)
    wf = tree / ".github/workflows/release.yml"
    text = wf.read_text(encoding="utf-8")
    assert "skill/*.zip)" in text
    wf.write_text(text.replace("skill/*.zip)", "skill/*.zip notes/*.md)"), encoding="utf-8")
    odd = mod.derive(tree, VERSION)
    assert any("notes/*.md" in reason for _id, reason in odd.problems), odd.problems
    rows = _rows(odd, _world(plan))
    assert any(r.state == mod.NOT_KNOWN and "notes/*.md" in r.reason for r in rows.values())
    assert mod.exit_code(list(rows.values())) == 5


# ----- the three answers -----


def test_everything_delivered_is_exit_0(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = _main(monkeypatch, capsys, _world(plan))
    assert code == 0, out
    lines = [line for line in out.splitlines() if line.startswith(("delivered", "MISSING", "not known"))]
    assert len(lines) >= 70 and all(line.startswith("delivered") for line in lines), out
    assert PYPI in out and "shipped" in out.splitlines()[-1]


def test_one_missing_video_card_is_exit_1_and_the_row_is_named(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """v0.11.0: the scan video was on the release page and the Videos page had no card for it."""
    world = _world(plan)
    page = world[f"{SITE}/videos/"].body.decode()
    card = re.search(r'<div class="video-card"><video poster="/videos/kube-noob-scan\.jpg".*?</div>', page)
    assert card
    world[f"{SITE}/videos/"] = _resp(200, page.replace(card.group(0), ""))
    code, out = _main(monkeypatch, capsys, world)
    assert code == 1, out
    missing = [line for line in out.splitlines() if line.startswith("MISSING")]
    assert len(missing) == 1 and "website:video-card:scan" in missing[0] and f"{SITE}/videos/" in missing[0], out


def test_a_card_whose_file_is_a_404_is_missing_too(plan: Any) -> None:
    """The first shape of the same defect: the page named the video and the file was a 404."""
    world = _world(plan)
    world[f"{SITE}/videos/kube-noob-scan.mp4"] = _resp(404)
    row = _rows(plan, world)["website:video-card:scan"]
    assert row.state == mod.MISSING and "404" in row.seen


def test_a_pypi_timeout_is_not_known_and_exit_5(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = _world(plan)
    world[PYPI] = mod.FetchError("timed out")
    code, out = _main(monkeypatch, capsys, world)
    assert code == 5, out
    open_rows = [line for line in out.splitlines() if line.startswith(("MISSING", "not known"))]
    assert len(open_rows) == 1 and open_rows[0].startswith("not known") and " pypi " in open_rows[0], out
    assert "timed out" in open_rows[0]


@pytest.mark.parametrize(
    "answer",
    [
        _resp(200, b"<html>gateway</html>"),
        _resp(200, {"servers": None}),
        _resp(200, ["io.github.kube-noob/kube-noob"]),
        _resp(200, {"servers": [["not", "an", "entry"]]}),
        _resp(503, b"busy"),
    ],
    ids=["not-json", "servers-null", "a-list", "entries-not-objects", "http-503"],
)
def test_a_malformed_answer_from_the_registry_is_not_known(plan: Any, answer: Any) -> None:
    world = _world(plan)
    url = f"{REGISTRY}?search={quote(plan.registry_name, safe='')}&limit=100"
    world[url] = answer
    row = _rows(plan, world)["mcp-registry"]
    assert row.state == mod.NOT_KNOWN and row.reason, row


def test_a_registry_that_lists_another_version_is_asked_for_this_one_before_it_is_called_missing(plan: Any) -> None:
    """A search that returns only the latest must not make an older release read as never published."""
    world = _world(plan)
    url = f"{REGISTRY}?search={quote(plan.registry_name, safe='')}&limit=100"
    exact = f"{REGISTRY}/{quote(plan.registry_name, safe='')}/versions/{VERSION}"
    world[url] = _resp(200, {"servers": [{"server": {"name": plan.registry_name, "version": "9.9.9"}}]})
    world[exact] = _resp(200, {"server": {"name": plan.registry_name, "version": VERSION}})
    assert _rows(plan, world)["mcp-registry"].state == mod.DELIVERED
    world[exact] = _resp(404)
    row = _rows(plan, world)["mcp-registry"]
    assert row.state == mod.MISSING and "9.9.9" in row.seen
    world[exact] = mod.FetchError("reset")
    assert _rows(plan, world)["mcp-registry"].state == mod.NOT_KNOWN


def test_a_404_on_something_that_should_exist_is_missing(plan: Any) -> None:
    world = _world(plan)
    # an asset the release page does not carry -- v0.11.1 for hours: 18 assets, no mp4
    world[f"{API}/releases/7/assets?per_page=100&page=1"] = _resp(
        200, [{"name": n, "state": "uploaded", "size": 10} for n in plan.assets if not n.endswith(".mp4")]
    )
    first = plan.lessons[0]
    world[f"{SITE}/learn/mechanisms/{first.id}/example-1/"] = _resp(404)
    world[f"https://ghcr.io/v2/kube-noob/kube-noob/manifests/{VERSION}"] = _resp(404, {"errors": []})
    rows = _rows(plan, world)
    mp4 = [n for n in plan.assets if n.endswith(".mp4")]
    assert len(mp4) == 2 * len(plan.videos)
    for name in mp4:
        assert rows[f"github-release:asset:{name}"].state == mod.MISSING
    assert rows[f"website:walk:{first.id}"].state == mod.MISSING
    assert rows[f"image:{VERSION}"].state == mod.MISSING
    assert mod.exit_code(list(rows.values())) == 1
    open_ids = {i for i, r in rows.items() if r.state != mod.DELIVERED}
    assert open_ids == {*(f"github-release:asset:{n}" for n in mp4), f"website:walk:{first.id}", f"image:{VERSION}"}

    # the release itself is a 404: it and every asset are MISSING, none of them `not known`
    world[f"{API}/releases/tags/v{VERSION}"] = _resp(404, {"message": "Not Found"})
    rows = _rows(plan, world)
    assert rows["github-release"].state == mod.MISSING
    assert all(rows[f"github-release:asset:{n}"].state == mod.MISSING for n in plan.assets)


def test_an_asset_still_uploading_or_empty_is_not_delivered(plan: Any) -> None:
    world = _world(plan)
    listing = [{"name": n, "state": "uploaded", "size": 10} for n in plan.assets]
    listing[0] = {**listing[0], "state": "starter"}
    listing[1] = {**listing[1], "size": 0}
    world[f"{API}/releases/7/assets?per_page=100&page=1"] = _resp(200, listing)
    rows = _rows(plan, world)
    assert rows[f"github-release:asset:{plan.assets[0]}"].state == mod.MISSING
    assert rows[f"github-release:asset:{plan.assets[1]}"].state == mod.MISSING


def test_every_page_of_assets_is_read(plan: Any) -> None:
    world = _world(plan)
    full = [{"name": f"filler-{i}", "state": "uploaded", "size": 1} for i in range(100)]
    world[f"{API}/releases/7/assets?per_page=100&page=1"] = _resp(200, full)
    world[f"{API}/releases/7/assets?per_page=100&page=2"] = _resp(
        200, [{"name": n, "state": "uploaded", "size": 10} for n in plan.assets]
    )
    rows = _rows(plan, world)
    assert all(rows[f"github-release:asset:{n}"].state == mod.DELIVERED for n in plan.assets)
    world[f"{API}/releases/7/assets?per_page=100&page=2"] = mod.FetchError("reset")
    rows = _rows(plan, world)
    assert all(rows[f"github-release:asset:{n}"].state == mod.NOT_KNOWN for n in plan.assets), (
        "a page that could not be read made the assets on it MISSING"
    )


@pytest.mark.parametrize(
    ("url", "answer", "row_id"),
    [
        (PYPI, _resp(200, {"info": {}}), "pypi"),
        (PYPI, _resp(200, b"not json"), "pypi"),
        (PYPI, _resp(500), "pypi"),
        (f"{API}/releases/tags/v{VERSION}", _resp(200, {"tag_name": f"v{VERSION}"}), "github-release"),
        (f"{API}/releases/tags/v{VERSION}", _resp(403, {"message": "rate limit"}), "github-release"),
        (
            f"{API}/releases/7/assets?per_page=100&page=1",
            _resp(200, {"message": "x"}),
            "github-release:asset:sbom.spdx.json",
        ),
        (f"{API}/contents/Formula/kube-noob.rb?ref=main", _resp(200, "class KubeNoob < Formula\nend\n"), "homebrew"),
        ("https://ghcr.io/token?scope=repository:kube-noob/kube-noob:pull", _resp(200, {}), f"image:{VERSION}"),
        (f"https://ghcr.io/v2/kube-noob/kube-noob/manifests/{VERSION}", _resp(200, b"<html>"), f"image:{VERSION}"),
        (f"{SITE}/", _resp(200, "<html><body>maintenance</body></html>"), "website:version:home"),
        (f"{SITE}/", _resp(200, "<html><body>maintenance</body></html>"), "website:nav:mechanisms"),
        (f"{SITE}/learn/mechanisms/", _resp(200, "<html>soon</html>"), "website:version:mechanisms"),
        (f"{SITE}/videos/", mod.FetchError("403 from the proxy"), "website:video-card:walkthrough"),
    ],
)
def test_an_answer_of_an_unexpected_shape_is_not_known(plan: Any, url: str, answer: Any, row_id: str) -> None:
    world = _world(plan)
    world[url] = answer
    row = _rows(plan, world)[row_id]
    assert row.state == mod.NOT_KNOWN and row.reason, row


def test_the_formula_on_main_serving_the_previous_version_is_missing(plan: Any) -> None:
    """v0.11.1 today: PyPI has it and main's formula says 0.11.0 until #153 lands."""
    world = _world(plan)
    old = 'class KubeNoob < Formula\n  url "https://files.pythonhosted.org/packages/3a/29/x/kube_noob-0.1.0.tar.gz"\nend\n'
    world[f"{API}/contents/Formula/kube-noob.rb?ref=main"] = _resp(200, old)
    row = _rows(plan, world)["homebrew"]
    assert row.state == mod.MISSING and "0.1.0" in row.seen
    world[f"{API}/contents/Formula/kube-noob.rb?ref=main"] = _resp(404)
    assert _rows(plan, world)["homebrew"].state == mod.MISSING


def test_a_formula_naming_this_version_at_another_url_than_pypi_serves_is_missing(plan: Any) -> None:
    world = _world(plan)
    other = f'  url "https://files.pythonhosted.org/packages/zz/zz/zz/kube_noob-{VERSION}.tar.gz"\n'
    world[f"{API}/contents/Formula/kube-noob.rb?ref=main"] = _resp(200, other)
    row = _rows(plan, world)["homebrew"]
    assert row.state == mod.MISSING and "PyPI" in row.seen


def test_a_site_stating_another_version_is_missing(plan: Any) -> None:
    world = _world(plan)
    world[f"{SITE}/"] = _resp(200, world[f"{SITE}/"].body.decode().replace(VERSION, "0.1.0"))
    mech = world[f"{SITE}/learn/mechanisms/"].body.decode()
    world[f"{SITE}/learn/mechanisms/"] = _resp(
        200, mech.replace(f"Built from kube-noob {VERSION}", "Built from kube-noob 0.1.0")
    )
    rows = _rows(plan, world)
    assert rows["website:version:home"].state == mod.MISSING and "0.1.0" in rows["website:version:home"].seen
    assert rows["website:version:mechanisms"].state == mod.MISSING


def test_a_mechanisms_page_nothing_links_to_is_missing(plan: Any) -> None:
    """/learn/mechanisms/ was live and the main nav did not name it."""
    world = _world(plan)
    home = world[f"{SITE}/"].body.decode()
    world[f"{SITE}/"] = _resp(200, home.replace('<a href="/learn/mechanisms/">Learn</a>', ""))
    row = _rows(plan, world)["website:nav:mechanisms"]
    assert row.state == mod.MISSING
    # a link elsewhere on the page is not the main nav
    world[f"{SITE}/"] = _resp(
        200, home.replace('<a href="/learn/mechanisms/">Learn</a>', "") + '<p><a href="/learn/mechanisms/">x</a></p>'
    )
    assert _rows(plan, world)["website:nav:mechanisms"].state == mod.MISSING


def test_a_lesson_the_site_does_not_show_is_missing(plan: Any) -> None:
    world = _world(plan)
    gone = plan.lessons[-1]
    page = world[f"{SITE}/learn/mechanisms/"].body.decode()
    world[f"{SITE}/learn/mechanisms/"] = _resp(200, page.replace(f'<h3 class="lesson-title">{gone.title}</h3>', ""))
    rows = _rows(plan, world)
    assert rows[f"website:lesson:{gone.id}"].state == mod.MISSING
    assert rows[f"website:lesson:{plan.lessons[0].id}"].state == mod.DELIVERED


def test_lessons_that_could_not_be_listed_are_one_not_known_row_not_zero_rows(plan: Any) -> None:
    import dataclasses

    blind = dataclasses.replace(plan, lessons=None, problems=(("website:lessons", "kube_noob could not be imported"),))
    rows = _rows(blind, _world(plan))
    assert rows["website:lessons"].state == mod.NOT_KNOWN
    assert not any(i.startswith(("website:lesson:", "website:walk:")) for i in rows)
    assert mod.exit_code(list(rows.values())) == 5


def test_missing_outranks_not_known_in_the_exit_code(plan: Any) -> None:
    world = _world(plan)
    world[PYPI] = mod.FetchError("timed out")
    world[f"{SITE}/videos/kube-noob-scan.mp4"] = _resp(404)
    assert mod.exit_code(list(_rows(plan, world).values())) == 1


def test_a_host_that_did_not_answer_is_not_asked_again_for_every_row(plan: Any) -> None:
    world = _world(plan)
    for url in list(world):
        if url.startswith(SITE):
            world[url] = mod.FetchError("403 from the proxy")
    fetch = _Fetch(world)
    rows = {r.id: r for r in mod.check(plan, fetch=fetch)}
    site_rows = [r for i, r in rows.items() if i.startswith("website:")]
    assert len(site_rows) >= 20 and all(r.state == mod.NOT_KNOWN for r in site_rows)
    assert len([c for c in fetch.calls if c[1].startswith(SITE)]) == 1, "one refused read is enough to know"


# ----- in flight is not MISSING, and it is not delivered either -----


def test_a_row_in_flight_is_not_known_and_named_as_in_flight(plan: Any) -> None:
    world = _world(plan)
    world[f"{SITE}/videos/"] = _resp(200, "<main></main>")
    world[f"https://ghcr.io/v2/kube-noob/kube-noob/manifests/{VERSION}"] = _resp(404)
    rows = _rows(plan, world, in_flight={"website": "the site was asked to rebuild in this run"})
    card = rows["website:video-card:scan"]
    assert card.state == mod.NOT_KNOWN and card.in_flight and "in flight" in card.reason
    assert rows[f"image:{VERSION}"].state == mod.MISSING, "only the group named is in flight"
    assert mod.exit_code(list(rows.values())) == 1
    del world[f"https://ghcr.io/v2/kube-noob/kube-noob/manifests/{VERSION}"]
    world.update({k: v for k, v in _world(plan).items() if "manifests" in k})
    rows = _rows(plan, world, in_flight={"website": "the site was asked to rebuild in this run"})
    assert mod.exit_code(list(rows.values())) == 5, "in flight is not shipped"


# ----- the fetch itself -----


def test_the_retry_succeeds_on_the_second_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []

    def attempt(url: str, headers: dict[str, str], method: str, timeout: float) -> Any:
        attempts.append(url)
        if len(attempts) == 1:
            raise urllib.error.URLError("EOF occurred in violation of protocol (_ssl.c:2427)")
        return mod.Response(200, b"ok", {})

    monkeypatch.setattr(mod, "_attempt", attempt)
    monkeypatch.setattr(mod, "RETRY_PAUSE", 0)
    assert mod.fetch("https://pypi.org/pypi/kube-noob/json").body == b"ok"
    assert len(attempts) == 2


def test_two_failures_are_a_fetch_error_and_there_is_no_third_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []

    def attempt(url: str, headers: dict[str, str], method: str, timeout: float) -> Any:
        attempts.append(url)
        raise TimeoutError("timed out")

    monkeypatch.setattr(mod, "_attempt", attempt)
    monkeypatch.setattr(mod, "RETRY_PAUSE", 0)
    with pytest.raises(mod.FetchError, match="timed out"):
        mod.fetch("https://pypi.org/pypi/kube-noob/json")
    assert len(attempts) == 2


def test_a_502_is_retried_once_and_a_404_is_an_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    statuses = [502, 200]
    monkeypatch.setattr(mod, "_attempt", lambda *_a: mod.Response(statuses.pop(0), b"", {}))
    monkeypatch.setattr(mod, "RETRY_PAUSE", 0)
    assert mod.fetch("https://x.invalid/").status == 200
    calls: list[int] = []

    def not_found(*_a: Any) -> Any:
        calls.append(1)
        return mod.Response(404, b"", {})

    monkeypatch.setattr(mod, "_attempt", not_found)
    assert mod.fetch("https://x.invalid/").status == 404 and len(calls) == 1


def test_every_read_has_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[float] = []

    def attempt(url: str, headers: dict[str, str], method: str, timeout: float) -> Any:
        seen.append(timeout)
        return mod.Response(200, b"", {})

    monkeypatch.setattr(mod, "_attempt", attempt)
    mod.fetch("https://x.invalid/")
    assert seen and 0 < seen[0] <= 60


def test_the_token_goes_to_the_github_api_only_and_is_never_printed(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "ghp_" + "s3cr3t" * 6
    monkeypatch.setenv("GH_TOKEN", secret)
    world = _world(plan)
    # an error that quotes the request, as a proxy's can
    world[PYPI] = mod.FetchError(f"refused: Authorization: Bearer {secret}")
    world[f"{SITE}/"] = mod.FetchError("refused anon-image")
    fetch = _Fetch(world)
    monkeypatch.setattr(mod, "fetch", fetch)
    monkeypatch.setattr(mod, "_git", lambda _root, *_args: SHA)
    for fmt in ("text", "json", "markdown"):
        mod.main(["--version", VERSION, "--format", fmt])
        out = capsys.readouterr()
        assert secret not in out.out + out.err and "anon-image" not in out.out + out.err and "anon-chart" not in out.out
    assert mod._headers(f"{API}/releases/tags/v{VERSION}")["Authorization"] == f"Bearer {secret}"
    for elsewhere in (
        PYPI,
        f"{SITE}/",
        "https://ghcr.io/token?scope=x",
        REGISTRY,
        "https://api.github.com.evil.example/",
    ):
        assert "Authorization" not in mod._headers(elsewhere), f"the token would be sent to {elsewhere}"
    ghcr = [headers for _m, url, headers in fetch.calls if "/manifests/" in url]
    assert ghcr and all(h.get("Authorization", "").startswith("Bearer anon-") for h in ghcr)


# ----- which tree the list was derived from -----


def test_a_checkout_that_is_not_the_tag_and_cannot_reach_it_is_not_known(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """main is ahead of the tag as soon as anything merges: a lesson added after v0.11.1 is not one v0.11.1's
    site owes anybody. A list derived from another tree is not this release's list."""
    world = _world(plan)
    world[f"{API}/commits/v{VERSION}"] = _resp(200, SHA)
    monkeypatch.setattr(mod, "fetch", _Fetch(world))
    monkeypatch.setattr(mod, "_git", lambda _root, *args: "f" * 40 if args == ("rev-parse", "HEAD") else None)
    code = mod.main(["--version", VERSION])
    out = capsys.readouterr().out
    assert code == 5, out
    row = next(line for line in out.splitlines() if " ledger:source " in line)
    assert row.startswith("not known") and "git fetch origin tag" in row


def test_a_checkout_at_the_tags_commit_is_the_releases_tree(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = _world(plan)
    world[f"{API}/commits/v{VERSION}"] = _resp(200, SHA)
    monkeypatch.setattr(mod, "fetch", _Fetch(world))
    monkeypatch.setattr(mod, "_git", lambda _root, *args: SHA if args == ("rev-parse", "HEAD") else None)
    assert mod.main(["--version", VERSION]) == 0, capsys.readouterr().out
    world[f"{API}/commits/v{VERSION}"] = _resp(404)
    monkeypatch.setattr(mod, "fetch", _Fetch(world))
    assert mod.main(["--version", VERSION]) == 1
    assert "MISSING    ledger:source" in capsys.readouterr().out, "a release with no tag is not a release"


def test_a_version_that_is_not_a_version_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        mod.main(["--version", "v0.11.1/../x"])
    assert stop.value.code == 2
    capsys.readouterr()


# ----- the formats -----


def test_the_json_format_carries_every_row_its_evidence_and_the_exit_code(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = _world(plan)
    world[f"{SITE}/videos/kube-noob-scan.mp4"] = _resp(404)
    world[PYPI] = mod.FetchError("timed out")
    code, out = _main(monkeypatch, capsys, world, "--format", "json")
    data = json.loads(out)
    assert code == 1 and data["exit"] == 1 and data["version"] == VERSION
    assert data["summary"] == {
        "delivered": len(data["rows"]) - 2,
        "in_flight": 0,
        "missing": 1,
        "not_known": 1,
        "shipped": False,
    }
    by_id = {r["id"]: r for r in data["rows"]}
    assert by_id["website:video-card:scan"]["state"] == "MISSING"
    assert by_id["website:video-card:scan"]["url"].startswith(SITE)
    assert by_id["pypi"]["state"] == "not known" and "timed out" in by_id["pypi"]["reason"]
    assert set(data["rows"][0]) == {"id", "deliverable", "state", "url", "seen", "reason", "in_flight"}
    again_code, again = _main(monkeypatch, capsys, world, "--format", "json")
    assert again == out and again_code == code, "the same world must print the same bytes"


def test_the_markdown_format_is_a_checklist_and_only_delivered_rows_are_ticked(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = _world(plan)
    world[f"{SITE}/videos/kube-noob-scan.mp4"] = _resp(404)
    world[PYPI] = mod.FetchError("timed out")
    code, out = _main(monkeypatch, capsys, world, "--format", "markdown")
    assert code == 1
    boxes = [line for line in out.splitlines() if line.startswith("- [")]
    ticked = [line for line in boxes if line.startswith("- [x] ")]
    assert len(boxes) >= 70 and all("**delivered**" in line for line in ticked)
    unticked = [line for line in boxes if line.startswith("- [ ] ")]
    assert len(ticked) + len(unticked) == len(boxes)
    assert any("**MISSING**" in line and "website:video-card:scan" in line for line in unticked)
    assert any("**not known**" in line and "`pypi`" in line for line in unticked)
    assert "Not shipped" in out and f"kube-noob {VERSION}" in out.splitlines()[0]


def test_a_saved_ledger_renders_again_without_a_read_and_keeps_its_exit_code(
    plan: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    world = _world(plan)
    world[f"{SITE}/videos/kube-noob-scan.mp4"] = _resp(404)
    code, out = _main(monkeypatch, capsys, world, "--format", "json")
    saved = tmp_path / "ledger.json"
    saved.write_text(out, encoding="utf-8")
    _code, direct = _main(monkeypatch, capsys, world, "--format", "markdown")

    def no_network(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("--render must not read anything")

    monkeypatch.setattr(mod, "fetch", no_network)
    assert mod.main(["--render", str(saved), "--format", "markdown"]) == code == 1
    assert capsys.readouterr().out == direct
    saved.write_text('{"rows": "none"}', encoding="utf-8")
    assert mod.main(["--render", str(saved)]) == 5, "a ledger that cannot be read is not a shipped release"
    capsys.readouterr()


# ----- wired in: the weekly report and the release's own summary -----


def _workflow(name: str) -> dict[str, Any]:
    spec: dict[str, Any] = yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))
    return spec


STUB_LEDGER = r"""
import json, os, sys
state = json.load(open(os.environ["STUB_LEDGER"]))
args = sys.argv[1:]
with open(os.environ["STUB_LEDGER"] + ".calls", "a") as f:
    f.write(json.dumps(args) + "\n")
if "--render" in args:
    saved = json.load(open(args[args.index("--render") + 1]))
    for r in saved["rows"]:
        print(("- [x] " if r["state"] == "delivered" else "- [ ] ") + "**" + r["state"] + "** `" + r["id"] + "`")
    sys.exit(saved["exit"])
runs = state["runs"]
n = sum(1 for _ in open(os.environ["STUB_LEDGER"] + ".calls")) - 1
rows = runs[min(n, len(runs) - 1)]
if rows is None:
    sys.stderr.write("Traceback: boom\n")
    sys.exit(4)
in_flight = [args[i + 1].split("=")[0] for i, a in enumerate(args) if a == "--in-flight"]
out = []
for rid, st in rows:
    flying = st == "MISSING" and rid.split(":")[0] in in_flight
    out.append({"id": rid, "state": "not known" if flying else st, "in_flight": flying})
code = 1 if any(r["state"] == "MISSING" for r in out) else 5 if any(r["state"] != "delivered" for r in out) else 0
print(json.dumps({"exit": code, "rows": out}))
sys.exit(code)
"""


def _release_step(tmp_path: Path, runs: list[Any], site: str = "success") -> tuple[int, str, str, list[list[str]]]:
    """Execute release.yml's own `deliverables` script over a stub ledger; returns its exit, output and summary."""
    job = _workflow("release.yml")["jobs"]["deliverables"]
    step = next(s for s in job["steps"] if "release_deliverables.py" in str(s.get("run", "")))
    work = tmp_path / "work"
    (work / "scripts").mkdir(parents=True)
    (work / "scripts" / "release_deliverables.py").write_text(STUB_LEDGER, encoding="utf-8")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"runs": runs}), encoding="utf-8")
    summary = tmp_path / "summary.md"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "sleep").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (bindir / "sleep").chmod(0o755)
    (bindir / "python").symlink_to(sys.executable)
    bash = shutil.which("bash")
    assert bash and shutil.which("jq"), "bash and jq run this step on the runner and are needed to execute it here"
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_REF_NAME": "v9.9.9",
        "GITHUB_STEP_SUMMARY": str(summary),
        "RUNNER_TEMP": str(tmp_path),
        "SITE_RESULT": site,
        "STUB_LEDGER": str(state),
    }
    done = subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
        check=False,
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    calls = [json.loads(x) for x in Path(str(state) + ".calls").read_text(encoding="utf-8").splitlines()]
    return (
        done.returncode,
        done.stdout + done.stderr,
        summary.read_text(encoding="utf-8") if summary.exists() else "",
        calls,
    )


DONE = [["pypi", "delivered"], ["website:video-card:scan", "delivered"]]
SITE_BEHIND = [["pypi", "delivered"], ["website:video-card:scan", "MISSING"]]
ASSET_GONE = [["github-release:asset:kube-noob-scan-4k.mp4", "MISSING"], ["website:video-card:scan", "MISSING"]]


def test_the_release_run_ends_by_writing_its_own_ledger_to_its_summary() -> None:
    spec = _workflow("release.yml")
    job = spec["jobs"]["deliverables"]
    publishers = {
        "publish-pypi",
        "image",
        "chart-publish",
        "publish-mcp-registry",
        "homebrew",
        "github-release",
        "videos",
        "site",
        "site-videos",
    }
    assert publishers <= set(job["needs"]), f"the ledger would run before {publishers - set(job['needs'])} finished"
    assert "always()" in job["if"] and "github.event_name == 'push'" in job["if"], (
        "a failed job upstream is exactly when the ledger is needed, and a dry run publishes nothing to check"
    )
    assert job["permissions"] == {"contents": "read"}
    assert not any(job_id for job_id, other in spec["jobs"].items() if "deliverables" in (other.get("needs") or [])), (
        "nothing may wait on the ledger: it reports a release, it does not hold one back"
    )


def test_a_release_that_got_everywhere_ticks_every_row_in_the_summary(tmp_path: Path) -> None:
    code, out, summary, calls = _release_step(tmp_path, [DONE])
    assert code == 0, out
    assert summary.count("- [x] ") == 2 and "- [ ]" not in summary
    assert calls[0][:2] == ["--version", "9.9.9"]


def test_a_site_still_rebuilding_does_not_fail_the_release_and_is_not_ticked(tmp_path: Path) -> None:
    code, out, summary, calls = _release_step(tmp_path, [SITE_BEHIND])
    assert code == 0, out
    assert "- [ ] **not known** `website:video-card:scan`" in summary, summary
    assert "in flight" in out and "::warning" in out
    assert len([c for c in calls if "--render" not in c]) > 1, "it must look again before settling for in flight"


def test_a_site_that_catches_up_while_the_job_waits_is_ticked(tmp_path: Path) -> None:
    code, out, summary, _calls = _release_step(tmp_path, [SITE_BEHIND, SITE_BEHIND, DONE])
    assert code == 0, out
    assert summary.count("- [x] ") == 2 and "::warning" not in out


def test_a_missing_asset_after_the_run_is_done_fails_the_job_and_names_the_row(tmp_path: Path) -> None:
    code, out, summary, _calls = _release_step(tmp_path, [ASSET_GONE])
    assert code == 1, out
    assert "github-release:asset:kube-noob-scan-4k.mp4" in out and "::error" in out
    assert "- [ ] **MISSING** `github-release:asset:kube-noob-scan-4k.mp4`" in summary


def test_a_site_that_was_never_asked_is_not_in_flight(tmp_path: Path) -> None:
    """In flight means something is on its way. With no dispatch, nothing is."""
    code, out, summary, calls = _release_step(tmp_path, [SITE_BEHIND], site="failure")
    assert code == 1, out
    assert "- [ ] **MISSING** `website:video-card:scan`" in summary
    assert not any("--in-flight" in c for c in calls)


def test_a_row_that_is_not_known_and_not_in_flight_fails_the_job(tmp_path: Path) -> None:
    code, out, _summary, _calls = _release_step(tmp_path, [[["pypi", "not known"]]])
    assert code == 1, out
    assert "pypi" in out and "NOT KNOWN" in out


def test_a_ledger_that_crashed_fails_the_job_and_says_nothing_was_checked(tmp_path: Path) -> None:
    code, out, summary, _calls = _release_step(tmp_path, [None])
    assert code == 1, out
    assert "NOT KNOWN" in out and "- [x]" not in summary


def test_the_weekly_report_runs_the_ledger_for_the_latest_release() -> None:
    spec = _workflow("release-ready.yml")
    ledger = spec["jobs"]["ledger"]
    script = "\n".join(str(s.get("run", "")) for s in ledger["steps"])
    assert "scripts/release_deliverables.py" in script and "gh release list" in script
    assert re.search(r"\bfetch\b.*refs/tags/\$\{tag\}", script) and "git -c" in script, (
        "the list is derived from the tag's tree, not from main's"
    )
    assert ledger["permissions"] == {"contents": "read"}
    ready = spec["jobs"]["ready"]
    assert "ledger" in ready["needs"] and "always()" in ready["if"], (
        "a ledger job that failed must reach the report as NOT KNOWN, not skip the report"
    )
    env = next(s for s in ready["steps"] if "run" in s)["env"]
    assert env["LEDGER_RC"] == "${{ needs.ledger.outputs.rc }}"
    assert env["LEDGER_TAG"] == "${{ needs.ledger.outputs.tag }}"


def test_the_maintainers_page_says_when_a_release_is_shipped() -> None:
    text = (ROOT / "MAINTENANCE.md").read_text(encoding="utf-8")
    assert "python scripts/release_deliverables.py" in text
    assert re.search(r"shipped when\s+`scripts/release_deliverables\.py`\s+exits 0", text), (
        "MAINTENANCE.md must state the definition: a release is shipped when the ledger exits 0"
    )
