#!/usr/bin/env python3
"""The deliverables ledger of a release: what it promised, and whether each thing is where it is served.

    python scripts/release_deliverables.py [--version X.Y.Z] [--format text|json|markdown]

A release is shipped when this exits 0. It derives the list from the repository's own sources of truth -- never
from a list written here, which would drift -- and reads each deliverable where a user would fetch it:

    PyPI             the version is served
    GitHub release   every asset release.yml and videos.yml upload: the wheel and sdist, the chart, the Agent
                     Skill, the krew archive, the SBOM, a GIF per demos/*.tape, and for every video in
                     demos/video/stage/videos.json plus the walkthrough its 4K and 1080p files, poster and captions
    Homebrew         Formula/kube-noob.rb on main points at this version's sdist
    the image        the tags release.yml pushes to GHCR exist
    the chart        the version is where chart-publish pushes it
    MCP Registry     the entry server.json names lists this version
    kube-noob.com    states this version; /videos/ has a card for every video; the main nav links
                     /learn/mechanisms/; that page shows every walkable lesson and each has its walk page

One row per deliverable, in a fixed order:

    delivered   it was read, and it is there
    MISSING     it was read, and it is not there (an HTTP 404 on something that should exist is this)
    not known   it could not be read, or the answer had a shape this script does not recognise, or the source the
                row is derived from could not be parsed. Never delivered, never MISSING.

Exit 0 only when every row is delivered; 1 when any row is MISSING; 5 when none is MISSING and any is not known
(the verdict was not reached). 2 is a usage error.

The list is derived from the TAG's tree, not from the checkout's: main is ahead of the tag as soon as anything
merges, and a lesson added after v0.11.1 is not one v0.11.1's website owes anybody. When the checkout is not the
tag's commit, the tag's files are read with `git archive`; when the tag is not fetched either, the first row says
so and is not known.

`--in-flight GROUP=REASON` is for the release run itself, which knows what it has only just asked for: a MISSING
row in that group is reported as not known (in flight), because a site that was asked to rebuild a minute ago and
has not finished is not a site that failed to. `--render FILE` prints a ledger saved with `--format json` again,
without a read, and exits with the code it was saved with.

Standard library only. Every read has a timeout and one retry; `GH_TOKEN` is sent to api.github.com when set and
is never printed.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import html
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPO = "kube-noob/kube-noob"
OWNER = REPO.split("/", maxsplit=1)[0]
API = f"https://api.github.com/repos/{REPO}"
PYPI = "https://pypi.org/pypi/{name}/json"
REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
SITE = "https://kube-noob.com"
GHCR = "https://ghcr.io"

DELIVERED, MISSING, NOT_KNOWN = "delivered", "MISSING", "not known"
TIMEOUT = 20.0
RETRY_PAUSE = 2.0
TRANSIENT_STATUS = frozenset({429, 500, 502, 503, 504})
VERSION_RE = re.compile(r"\d+\.\d+\.\d+\Z")
#: What the tag's tree is read for. `git archive` takes exactly these, so a tag that lacks one says so.
SOURCES = (
    ".github/workflows/release.yml",
    ".github/workflows/videos.yml",
    "demos",
    "deploy/helm/kube-noob/Chart.yaml",
    "pyproject.toml",
    "server.json",
    "src/kube_noob",
)

#: Values that must never reach stdout or stderr: the caller's token and the anonymous registry tokens.
_SECRETS: set[str] = set()


@dataclasses.dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str]

    def header(self, name: str) -> str:
        return next((v for k, v in self.headers.items() if k.lower() == name.lower()), "")


class FetchError(Exception):
    """A read that did not get an answer, after its retry."""


class _SameHostAuth(urllib.request.HTTPRedirectHandler):
    """Follow redirects, and drop Authorization when one leaves the host the credential was meant for."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urlsplit(newurl).hostname != urlsplit(req.full_url).hostname:
            new.headers.pop("Authorization", None)
            new.unredirected_hdrs.pop("Authorization", None)
        return new


def _attempt(url: str, headers: Mapping[str, str], method: str, timeout: float) -> Response:
    """One request. An HTTP error status is an answer and is returned; only a failure to get one raises."""
    if urlsplit(url).scheme != "https":
        raise FetchError(f"refusing a URL that is not https: {url}")
    request = urllib.request.Request(url, headers=dict(headers), method=method)  # noqa: S310 - https only, above
    opener = urllib.request.build_opener(_SameHostAuth)
    try:
        with opener.open(request, timeout=timeout) as resp:
            return Response(resp.status, resp.read(), dict(resp.headers.items()))
    except urllib.error.HTTPError as err:
        with contextlib.suppress(OSError):
            return Response(err.code, err.read(), dict(err.headers.items()))
        return Response(err.code, b"", {})


def _headers(url: str, headers: Mapping[str, str] | None = None) -> dict[str, str]:
    """What a request carries. GH_TOKEN goes to api.github.com and to no other host."""
    sent = {"User-Agent": "kube-noob-release-ledger", **(headers or {})}
    token = os.environ.get("GH_TOKEN", "")
    if token and urlsplit(url).hostname == "api.github.com":
        sent["Authorization"] = f"Bearer {token}"
    return sent


def fetch(
    url: str, *, headers: Mapping[str, str] | None = None, method: str = "GET", timeout: float = TIMEOUT
) -> Response:
    """The one way this script reads anything. One retry on a transient failure, then FetchError."""
    sent = _headers(url, headers)
    last = ""
    for attempt in (1, 2):
        try:
            answer = _attempt(url, sent, method, timeout)
        except FetchError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as err:
            last = f"{type(err).__name__}: {getattr(err, 'reason', None) or err}"
        else:
            if answer.status not in TRANSIENT_STATUS or attempt == 2:
                return answer
            last = f"HTTP {answer.status}"
        if attempt == 1:
            time.sleep(RETRY_PAUSE)
    raise FetchError(f"{last} (after one retry)")


Fetch = Callable[..., Response]


class _Reader:
    """Reads each URL once, and stops asking a host that did not answer: one refused read is enough to know."""

    def __init__(self, fetch_: Fetch) -> None:
        self._fetch = fetch_
        self._seen: dict[tuple[str, str, str], Response | FetchError] = {}
        self._dead: dict[str, str] = {}

    def get(self, url: str, *, headers: Mapping[str, str] | None = None, method: str = "GET") -> Response:
        key = (method, url, json.dumps(sorted((headers or {}).items())))
        host = urlsplit(url).hostname or ""
        if key not in self._seen:
            if host in self._dead:
                self._seen[key] = FetchError(f"{host} did not answer earlier in this run ({self._dead[host]})")
            else:
                try:
                    self._seen[key] = self._fetch(url, headers=dict(headers or {}), method=method)
                except FetchError as err:
                    self._dead[host] = str(err)
                    self._seen[key] = err
        answer = self._seen[key]
        if isinstance(answer, FetchError):
            raise answer
        return answer


@dataclasses.dataclass(frozen=True)
class Row:
    id: str
    deliverable: str
    state: str
    url: str = ""
    seen: str = ""
    reason: str = ""
    in_flight: bool = False

    @property
    def group(self) -> str:
        return self.id.split(":", maxsplit=1)[0]


@dataclasses.dataclass(frozen=True)
class Lesson:
    id: str
    title: str
    walk: bool  # it names a first example, so the site owes it a walk page


@dataclasses.dataclass(frozen=True)
class Plan:
    """What a release of `version` promises, as read from a tree. `problems` are sources that could not be read:
    each becomes a not-known row, so a derivation that failed is never a shorter list."""

    version: str
    pypi_name: str
    assets: tuple[str, ...]
    videos: tuple[str, ...]
    image: str
    image_tags: tuple[str, ...]
    chart: str
    chart_version: str
    registry_name: str
    lessons: tuple[Lesson, ...] | None
    problems: tuple[tuple[str, str], ...]


# ---------------------------------------------------------------------------------------------------------------
# Deriving the list
# ---------------------------------------------------------------------------------------------------------------


def tree_version(tree: Path) -> str:
    m = re.search(r'^__version__ = "([^"]+)"', (tree / "src/kube_noob/__init__.py").read_text(encoding="utf-8"), re.M)
    if not m:
        raise SystemExit("cannot find __version__ in src/kube_noob/__init__.py")
    return m.group(1)


_LESSONS_CODE = """
import json
from kube_noob.learn import mechanism
# A tree from before lessons named their examples (0.11.0 and earlier) promises no walk page.
examples = getattr(mechanism, "examples", lambda lesson: ())
print(json.dumps([
    {"id": i, "title": str(l.get("title") or ""), "walk": bool(examples(l))}
    for i, l in sorted(mechanism.lessons().items())
]))
"""


def lessons(tree: Path) -> tuple[Lesson, ...]:
    """The walkable lessons, asked of the tree's own code in a process of its own. Raises ValueError with why."""
    env = {**os.environ, "PYTHONPATH": str(tree / "src"), "KUBE_NOOB_LEARNING_ENABLED": "false"}
    try:
        done = subprocess.run(
            [sys.executable, "-c", _LESSONS_CODE], env=env, capture_output=True, text=True, timeout=120, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        raise ValueError(f"kube_noob.learn.mechanism.lessons() could not be run: {err}") from err
    if done.returncode != 0:
        last = (done.stderr.strip().splitlines() or ["no output"])[-1]
        raise ValueError(f"kube_noob.learn.mechanism.lessons() could not be run from {tree / 'src'}: {last}")
    try:
        found = tuple(Lesson(str(x["id"]), str(x["title"]), bool(x["walk"])) for x in json.loads(done.stdout))
    except (ValueError, KeyError, TypeError) as err:
        raise ValueError(f"kube_noob.learn.mechanism.lessons() printed something else: {err}") from err
    if not found or any(not lsn.id or not lsn.title for lsn in found):
        raise ValueError("kube_noob.learn.mechanism.lessons() returned no lesson, or one with no id or title")
    return found


def _one(pattern: str, text: str, what: str) -> str:
    found = re.findall(pattern, text, re.M)
    if len(set(found)) != 1:
        raise ValueError(f"{what}: expected one match of /{pattern}/ and found {len(set(found))}")
    return str(found[0])


def _release_assets(tree: Path, version: str, problems: list[tuple[str, str]]) -> set[str]:
    """Every name release.yml's `github-release` job uploads, glob by glob."""
    names: set[str] = set()
    try:
        text = (tree / ".github/workflows/release.yml").read_text(encoding="utf-8")
        globs = _one(r"^\s*assets=\(([^)\n]+)\)\s*$", text, "release.yml's upload list").split()
    except (OSError, ValueError) as err:
        problems.append(("github-release:assets", f"what release.yml uploads could not be read: {err}"))
        return names

    def dist() -> set[str]:
        pyproject = tomllib.loads((tree / "pyproject.toml").read_text(encoding="utf-8"))
        if "python -m build" not in text:
            raise ValueError("release.yml no longer runs `python -m build`")
        name = re.sub(r"[-_.]+", "_", str(pyproject["project"]["name"]))
        return {f"{name}-{version}-py3-none-any.whl", f"{name}-{version}.tar.gz"}

    def extra() -> set[str]:
        copied = re.findall(r"cp (\S+) assets/", text)
        archives = re.findall(r'--archive "assets/([^"]+)"', text)
        if not copied or not archives:
            raise ValueError("release.yml no longer copies the SBOM and builds the krew archive into assets/")
        out = {Path(c).name for c in copied} | {a.replace("$v", version) for a in archives}
        if any("$" in n for n in out):
            raise ValueError(f"a name under assets/ uses a variable this script does not know: {sorted(out)}")
        return out

    def gifs() -> set[str]:
        if 'for tape in demos/*.tape; do vhs "$tape"; done' not in text:
            raise ValueError("release.yml no longer renders one GIF per demos/*.tape")
        tapes = sorted((tree / "demos").glob("*.tape"))
        if not tapes:
            raise ValueError("no demos/*.tape in the tree")
        return {f"{t.stem}.gif" for t in tapes}

    def chart() -> set[str]:
        path = _one(r"helm package (\S+) -d chart/", text, "release.yml's helm package")
        meta = (tree / path / "Chart.yaml").read_text(encoding="utf-8")
        name = _one(r"^name:\s*(\S+)\s*$", meta, "Chart.yaml name")
        return {f"{name}-{_chart_version(tree)}.tgz"}

    def skill() -> set[str]:
        name = _one(r'--zip "skill/([^"]+)"', text, "release.yml's skill zip")
        out = name.replace("${GITHUB_REF_NAME#v}", version)
        if "$" in out:
            raise ValueError(f"the skill zip's name uses a variable this script does not know: {name}")
        return {out}

    known: dict[str, Callable[[], set[str]]] = {
        "dist/*": dist,
        "assets/*": extra,
        "demos/*.gif": gifs,
        "chart/*.tgz": chart,
        "skill/*.zip": skill,
    }
    for glob in globs:
        if glob not in known:
            problems.append(
                (
                    f"github-release:assets:{glob}",
                    f"release.yml uploads `{glob}` and this script does not know what that holds; "
                    "teach scripts/release_deliverables.py, because an upload nobody checks is not a delivered one",
                )
            )
            continue
        try:
            names |= known[glob]()
        except (OSError, ValueError, KeyError, TypeError) as err:
            problems.append((f"github-release:assets:{glob}", f"what `{glob}` holds could not be derived: {err}"))
    return names


def _video_assets(tree: Path, problems: list[tuple[str, str]]) -> tuple[tuple[str, ...], set[str]]:
    """The videos (videos.json plus the walkthrough) and every file videos.yml attaches for them."""
    try:
        text = (tree / ".github/workflows/videos.yml").read_text(encoding="utf-8")
        matrix = [v.strip() for v in _one(r"^\s*video:\s*\[([^\]\n]+)\]\s*$", text, "videos.yml's matrix").split(",")]
        data = json.loads((tree / "demos/video/stage/videos.json").read_text(encoding="utf-8"))
        scripted = list(data["videos"])
        if not scripted or not all(isinstance(v, str) and re.match(r"[a-z0-9][a-z0-9-]*\Z", v) for v in scripted):
            raise ValueError("videos.json has no videos, or one whose name is not a plain slug")
    except (OSError, ValueError, KeyError, TypeError) as err:
        problems.append(("github-release:videos", f"which videos a release renders could not be read: {err}"))
        return (), set()
    videos = tuple(sorted({*scripted, "walkthrough"}))
    if sorted(matrix) != list(videos):
        only_json = sorted(set(videos) - set(matrix))
        only_yml = sorted(set(matrix) - set(videos))
        problems.append(
            (
                "ledger:video-list",
                "videos.json plus the walkthrough is not what videos.yml renders: "
                f"scripted and not rendered {only_json}, rendered and not scripted {only_yml}",
            )
        )
        videos = tuple(sorted({*videos, *matrix}))
    names: set[str] = set()
    try:
        per_video = set(re.findall(r'"dist/kube-noob-\$VIDEO([-.][\w.-]+)"', text))
        per_video |= set(re.findall(r'cp "\$src/kube-noob-\$VIDEO(\.\w+)" dist/', text))
        if not {s for s in per_video if s.endswith(".mp4")} or ".jpg" not in per_video or ".vtt" not in per_video:
            raise ValueError(f"expected mp4 copies, a .jpg and a .vtt per video and read {sorted(per_video)}")
        once = _one(r"cp ((?:out/\S+ )+)dist/", text, "the walkthrough's YouTube files").split()
        sums = _one(r"sha256sum -- \* > (\S+?)\)", text, "the checksum file")
        transcript = _one(r"cp transcript/(\S+) dist/", text, "the sidecar transcript")
        if "gh release upload" not in text or "dist/*" not in text:
            raise ValueError("videos.yml no longer uploads dist/* to the release")
    except ValueError as err:
        problems.append(("github-release:videos", f"what videos.yml attaches could not be derived: {err}"))
        return videos, set()
    names |= {f"kube-noob-{v}{suffix}" for v in videos for suffix in per_video}
    names |= {Path(p).name for p in once} | {sums, transcript}
    return videos, names


def _chart_version(tree: Path) -> str:
    meta = (tree / "deploy/helm/kube-noob/Chart.yaml").read_text(encoding="utf-8")
    return _one(r'^version:\s*"?([^"\s]+)"?\s*$', meta, "Chart.yaml version")


def derive(tree: Path, version: str) -> Plan:
    """Read `tree` for everything a release of `version` promises."""
    problems: list[tuple[str, str]] = []
    assets = _release_assets(tree, version, problems)
    videos, video_assets = _video_assets(tree, problems)
    major, minor, _patch = version.split(".")

    image, image_tags = "", ()
    try:
        text = (tree / ".github/workflows/release.yml").read_text(encoding="utf-8")
        name = _one(r"^\s*IMAGE:\s*ghcr\.io/\$\{\{ github\.repository_owner \}\}/(\S+)\s*$", text, "the image name")
        patterns = re.findall(r"^\s*type=semver,pattern=(\S+)\s*$", text, re.M)
        tags = tuple(
            p.replace("{{version}}", version).replace("{{major}}", major).replace("{{minor}}", minor) for p in patterns
        )
        if not tags or any("{" in t for t in tags):
            raise ValueError(f"the image's tag patterns are not ones this script knows: {patterns}")
        image, image_tags = f"{OWNER}/{name}", tags
    except (OSError, ValueError) as err:
        problems.append(("image", f"which image and tags release.yml pushes could not be read: {err}"))

    chart, chart_version = "", ""
    try:
        text = (tree / ".github/workflows/release.yml").read_text(encoding="utf-8")
        pushed = re.search(r'helm push chart/(\S+)-\*\.tgz "oci://ghcr\.io/\$\{OWNER\}/([\w./-]+)"', text)
        if not pushed:
            raise ValueError("chart-publish's `helm push` is not the line this script knows")
        chart, chart_version = f"{OWNER}/{pushed.group(2)}/{pushed.group(1)}", _chart_version(tree)
    except (OSError, ValueError) as err:
        problems.append(("chart", f"where chart-publish pushes the chart could not be read: {err}"))

    pypi_name, registry_name = "", ""
    try:
        pypi_name = str(tomllib.loads((tree / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"])
    except (OSError, ValueError, KeyError, TypeError) as err:
        problems.append(("pypi", f"the package name could not be read from pyproject.toml: {err}"))
    try:
        registry_name = json.loads((tree / "server.json").read_text(encoding="utf-8"))["name"]
        if not isinstance(registry_name, str) or not registry_name:
            raise ValueError("server.json has no name")
    except (OSError, ValueError, KeyError, TypeError) as err:
        registry_name = ""
        problems.append(("mcp-registry", f"the registry name could not be read from server.json: {err}"))

    found: tuple[Lesson, ...] | None
    try:
        found = lessons(tree)
    except ValueError as err:
        found = None
        problems.append(("website:lessons", str(err)))

    return Plan(
        version=version,
        pypi_name=pypi_name,
        assets=tuple(sorted(assets | video_assets)),
        videos=videos,
        image=image,
        image_tags=image_tags,
        chart=chart,
        chart_version=chart_version,
        registry_name=registry_name,
        lessons=found,
        problems=tuple(problems),
    )


# ---------------------------------------------------------------------------------------------------------------
# Checking each deliverable where it is served
# ---------------------------------------------------------------------------------------------------------------


def _json(answer: Response) -> Any:
    try:
        return json.loads(answer.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as err:
        raise ValueError(f"HTTP {answer.status} with a body that is not JSON") from err


def _unknown(row_id: str, deliverable: str, url: str, why: object) -> Row:
    return Row(row_id, deliverable, NOT_KNOWN, url=url, reason=str(why))


def _status(row_id: str, deliverable: str, url: str, answer: Response, absent: str) -> Row | None:
    """The two answers every read shares: 404 is MISSING, anything but 200 is not known. None means 200."""
    if answer.status == 404:
        return Row(row_id, deliverable, MISSING, url=url, seen=f"HTTP 404: {absent}")
    if answer.status != 200:
        return _unknown(row_id, deliverable, url, f"HTTP {answer.status}, which is neither the thing nor its absence")
    return None


def _check_pypi(plan: Plan, read: _Reader) -> tuple[list[Row], str]:
    """Returns the row and the sdist URL PyPI serves for this version ("" when it is not known)."""
    what = f"PyPI serves {plan.pypi_name} {plan.version}"
    url = PYPI.format(name=plan.pypi_name)
    try:
        answer = read.get(url)
        if (row := _status("pypi", what, url, answer, "no such project")) is not None:
            return [row], ""
        releases = _json(answer)["releases"]
        if not isinstance(releases, dict) or not all(isinstance(v, list) for v in releases.values()):
            raise ValueError("`releases` is not a map of version to files")
        files = [f for f in releases.get(plan.version, []) if isinstance(f, dict) and not f.get("yanked")]
        names = sorted(str(f.get("filename")) for f in files)
    except FetchError as err:
        return [_unknown("pypi", what, url, err)], ""
    except (ValueError, KeyError, TypeError) as err:
        return [_unknown("pypi", what, url, f"unexpected shape: {err}")], ""
    if not files:
        have = ", ".join(sorted(releases)[-3:]) or "none"
        return [
            Row(
                "pypi",
                what,
                MISSING,
                url=url,
                seen=f"no file for {plan.version}; it lists {len(releases)} versions, last {have}",
            )
        ], ""
    sdist = next((str(f.get("url") or "") for f in files if f.get("packagetype") == "sdist"), "")
    return [Row("pypi", what, DELIVERED, url=url, seen=f"releases[{plan.version}]: {', '.join(names)}")], sdist


def _check_release(plan: Plan, read: _Reader) -> list[Row]:
    tag = f"v{plan.version}"
    what = f"GitHub release {tag} exists"
    url = f"{API}/releases/tags/{tag}"

    def assets(state: str, url: str = "", seen: str = "", reason: str = "") -> list[Row]:
        return [
            Row(f"github-release:asset:{n}", f"{tag} carries {n}", state, url=url, seen=seen, reason=reason)
            for n in plan.assets
        ]

    try:
        answer = read.get(url, headers={"Accept": "application/vnd.github+json"})
    except FetchError as err:
        return [
            _unknown("github-release", what, url, err),
            *assets(NOT_KNOWN, url=url, reason=f"the release could not be read: {err}"),
        ]
    if answer.status == 404:
        return [
            Row("github-release", what, MISSING, url=url, seen="HTTP 404: there is no such release"),
            *assets(MISSING, url=url, seen="HTTP 404: there is no such release"),
        ]
    try:
        if answer.status != 200:
            raise ValueError(f"HTTP {answer.status}, which is neither the release nor its absence")
        data = _json(answer)
        release_id = data["id"]
        if not isinstance(release_id, int) or data.get("tag_name") != tag:
            raise ValueError("no integer `id`, or `tag_name` is not this tag")
    except (ValueError, KeyError, TypeError) as err:
        why = f"unexpected shape: {err}"
        return [
            _unknown("github-release", what, url, why),
            *assets(NOT_KNOWN, url=url, reason=f"the release could not be read: {why}"),
        ]
    if data.get("draft"):
        rows = [Row("github-release", what, MISSING, url=url, seen="it is a draft, which nobody can see")]
    else:
        rows = [
            Row(
                "github-release",
                what,
                DELIVERED,
                url=url,
                seen=f"id {release_id}, published {data.get('published_at')}",
            )
        ]

    listing = f"{API}/releases/{release_id}/assets?per_page=100&page="
    have: dict[str, dict[str, Any]] = {}
    try:
        for page in range(1, 21):
            answer = read.get(f"{listing}{page}", headers={"Accept": "application/vnd.github+json"})
            if answer.status != 200:
                raise ValueError(f"HTTP {answer.status} on page {page} of the assets")
            items = _json(answer)
            if not isinstance(items, list) or not all(
                isinstance(i, dict) and isinstance(i.get("name"), str) for i in items
            ):
                raise ValueError(f"page {page} of the assets is not a list of named assets")
            have.update({i["name"]: i for i in items})
            if len(items) < 100:
                break
        else:
            raise ValueError("more than 2000 assets; this script stopped reading")
    except (FetchError, ValueError) as err:
        return [*rows, *assets(NOT_KNOWN, url=f"{listing}1", reason=f"the asset list could not be read: {err}")]
    seen_all = f"not among the {len(have)} assets on the release"
    for name in plan.assets:
        row_id, label = f"github-release:asset:{name}", f"{tag} carries {name}"
        asset = have.get(name)
        if asset is None:
            rows.append(Row(row_id, label, MISSING, url=f"{listing}1", seen=seen_all))
        elif asset.get("state") != "uploaded" or not isinstance(asset.get("size"), int) or asset["size"] <= 0:
            rows.append(
                Row(
                    row_id,
                    label,
                    MISSING,
                    url=f"{listing}1",
                    seen=f"state {asset.get('state')!r}, size {asset.get('size')!r}: not a finished upload",
                )
            )
        else:
            rows.append(Row(row_id, label, DELIVERED, url=f"{listing}1", seen=f"uploaded, {asset['size']} bytes"))
    return rows


def _check_homebrew(plan: Plan, read: _Reader, pypi_sdist: str) -> list[Row]:
    what = f"Formula/kube-noob.rb on main points at the {plan.version} sdist"
    url = f"{API}/contents/Formula/kube-noob.rb?ref=main"
    try:
        answer = read.get(url, headers={"Accept": "application/vnd.github.raw+json"})
    except FetchError as err:
        return [_unknown("homebrew", what, url, err)]
    if (row := _status("homebrew", what, url, answer, "main has no Formula/kube-noob.rb")) is not None:
        return [row]
    text = answer.body.decode("utf-8", "replace")
    m = re.search(r'^\s*url "(\S+/kube_noob-(\d+\.\d+\.\d+)\.tar\.gz)"', text, re.M)
    if not m:
        return [_unknown("homebrew", what, url, 'unexpected shape: no `url ".../kube_noob-<version>.tar.gz"` line')]
    if m.group(2) != plan.version:
        return [
            Row(
                "homebrew",
                what,
                MISSING,
                url=url,
                seen=f"the formula serves {m.group(2)}: `brew install kube-noob` installs that",
            )
        ]
    if pypi_sdist and m.group(1) != pypi_sdist:
        return [
            Row(
                "homebrew",
                what,
                MISSING,
                url=url,
                seen=f"it names {m.group(1)}, and PyPI serves the sdist at {pypi_sdist}",
            )
        ]
    compared = "the URL PyPI serves" if pypi_sdist else "by version only; PyPI's URL was not known to compare"
    return [Row("homebrew", what, DELIVERED, url=url, seen=f"url .../kube_noob-{m.group(2)}.tar.gz ({compared})")]


def _ghcr_manifest(row_id: str, what: str, repository: str, tag: str, read: _Reader) -> Row:
    """One tag of one GHCR repository, read anonymously: the manifest is there (200) or it is not (404)."""
    token_url = f"{GHCR}/token?scope=repository:{repository}:pull"
    url = f"{GHCR}/v2/{repository}/manifests/{tag}"
    accept = ", ".join(
        (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
    )
    try:
        answer = read.get(token_url)
        if answer.status != 200:
            # GHCR answers 401/403/404 here for a package that is private or was never pushed, and cannot say which.
            return _unknown(row_id, what, token_url, f"HTTP {answer.status} from the anonymous token endpoint")
        token = _json(answer).get("token")
        if not isinstance(token, str) or not token:
            raise ValueError("no `token` in the token endpoint's answer")
        _SECRETS.add(token)
        answer = read.get(url, headers={"Authorization": f"Bearer {token}", "Accept": accept})
        if (row := _status(row_id, what, url, answer, "no such tag")) is not None:
            return row
        if _json(answer).get("schemaVersion") != 2:
            raise ValueError("the manifest has no schemaVersion 2")
    except FetchError as err:
        return _unknown(row_id, what, url, err)
    except (ValueError, AttributeError) as err:
        return _unknown(row_id, what, url, f"unexpected shape: {err}")
    digest = answer.header("Docker-Content-Digest") or "no digest header"
    return Row(row_id, what, DELIVERED, url=url, seen=f"manifest present ({digest})")


def _check_registry(plan: Plan, read: _Reader) -> list[Row]:
    what = f"the MCP Registry lists {plan.registry_name} {plan.version}"
    name = quote(plan.registry_name, safe="")
    url = f"{REGISTRY}?search={name}&limit=100"
    versions: set[str] = set()
    try:
        page_url = url
        for _page in range(20):
            answer = read.get(page_url, headers={"Accept": "application/json"})
            if answer.status != 200:
                raise ValueError(f"HTTP {answer.status}")
            data = _json(answer)
            entries = data["servers"] if isinstance(data, dict) else None
            if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
                raise ValueError("`servers` is not a list of entries")
            for entry in entries:
                server = entry.get("server", entry)
                if not isinstance(server, dict) or not isinstance(server.get("name"), str):
                    raise ValueError("an entry has no `name`")
                if server["name"] == plan.registry_name:
                    versions.add(str(server.get("version")))
            meta = data.get("metadata")
            cursor = (meta.get("nextCursor") or meta.get("next_cursor")) if isinstance(meta, dict) else None
            if plan.version in versions or not cursor:
                break
            page_url = f"{url}&cursor={quote(str(cursor), safe='')}"
    except FetchError as err:
        return [_unknown("mcp-registry", what, url, err)]
    except (ValueError, KeyError, TypeError) as err:
        return [_unknown("mcp-registry", what, url, f"unexpected shape: {err}")]
    if plan.version in versions:
        return [Row("mcp-registry", what, DELIVERED, url=url, seen=f"an entry with version {plan.version}")]
    listed = f"the search lists {', '.join(sorted(versions)) or 'no version of it'}"
    # A search may answer with the latest version only, so an older release is asked for by name before it is
    # called MISSING.
    exact = f"{REGISTRY}/{name}/versions/{quote(plan.version, safe='')}"
    try:
        answer = read.get(exact, headers={"Accept": "application/json"})
        if answer.status == 404:
            return [Row("mcp-registry", what, MISSING, url=exact, seen=f"HTTP 404, and {listed}")]
        if answer.status != 200:
            raise ValueError(f"HTTP {answer.status}")
        data = _json(answer)
        server = data.get("server", data) if isinstance(data, dict) else None
        if (
            not isinstance(server, dict)
            or server.get("name") != plan.registry_name
            or server.get("version") != plan.version
        ):
            raise ValueError("the entry is not this name and version")
    except FetchError as err:
        return [_unknown("mcp-registry", what, exact, f"{listed}, and the entry itself could not be read: {err}")]
    except (ValueError, KeyError, TypeError) as err:
        return [_unknown("mcp-registry", what, exact, f"{listed}, and the entry itself: unexpected shape: {err}")]
    return [Row("mcp-registry", what, DELIVERED, url=exact, seen=f"the entry for version {plan.version}")]


def _page(read: _Reader, url: str) -> tuple[str | None, str, str]:
    """A site page as (text, state, why): text when it was read, else the state every row on it takes."""
    try:
        answer = read.get(url)
    except FetchError as err:
        return None, NOT_KNOWN, str(err)
    if answer.status == 404:
        return None, MISSING, "HTTP 404: the page does not exist"
    if answer.status != 200:
        return None, NOT_KNOWN, f"HTTP {answer.status}, which is neither the page nor its absence"
    return answer.body.decode("utf-8", "replace"), DELIVERED, ""


def _no_page(row_id: str, what: str, url: str, state: str, why: str) -> Row:
    return Row(row_id, what, state, url=url, seen=why) if state == MISSING else _unknown(row_id, what, url, why)


def _stated(row_id: str, what: str, url: str, found: list[str], version: str, where: str) -> Row:
    stated = sorted(set(found))
    if not stated:
        return _unknown(row_id, what, url, f"unexpected shape: the page has no {where}")
    if stated != [version]:
        return Row(row_id, what, MISSING, url=url, seen=f"it states {', '.join(stated)}")
    return Row(row_id, what, DELIVERED, url=url, seen=f"{len(found)} statement(s) of {version} and no other version")


def _check_site(plan: Plan, read: _Reader) -> list[Row]:
    rows: list[Row] = []
    version = plan.version

    home_url = f"{SITE}/"
    home, state, why = _page(read, home_url)
    what_version = f"kube-noob.com states {version}"
    what_nav = "the main nav on kube-noob.com links /learn/mechanisms/"
    if home is None:
        rows += [
            _no_page("website:version:home", what_version, home_url, state, why),
            _no_page("website:nav:mechanisms", what_nav, home_url, state, why),
        ]
    else:
        found = re.findall(r"\bkube-noob (\d+\.\d+\.\d+)\b", home) + re.findall(
            r'"softwareVersion"\s*:\s*"([^"]+)"', home
        )
        rows.append(
            _stated(
                "website:version:home", what_version, home_url, found, version, "`kube-noob X.Y.Z` or softwareVersion"
            )
        )
        navs = [
            body
            for tag, body in re.findall(r"<nav\b([^>]*)>(.*?)</nav>", home, re.S)
            if re.search(r"\bmain\b", tag, re.I)
        ]
        if not navs:
            rows.append(
                _unknown(
                    "website:nav:mechanisms", what_nav, home_url, "unexpected shape: the page has no <nav> marked main"
                )
            )
        elif any(re.search(r'href="/learn/mechanisms/"', nav) for nav in navs):
            rows.append(
                Row(
                    "website:nav:mechanisms",
                    what_nav,
                    DELIVERED,
                    url=home_url,
                    seen='the main nav has href="/learn/mechanisms/"',
                )
            )
        else:
            links = sorted(set(re.findall(r'href="([^"]+)"', " ".join(navs))))
            rows.append(
                Row(
                    "website:nav:mechanisms",
                    what_nav,
                    MISSING,
                    url=home_url,
                    seen=f"the main nav links {', '.join(links) or 'nothing'}",
                )
            )

    videos_url = f"{SITE}/videos/"
    page, state, why = _page(read, videos_url)
    for video in plan.videos:
        row_id, what = f"website:video-card:{video}", f"kube-noob.com/videos/ has a card for the {video} video"
        src = f"/videos/kube-noob-{video}.mp4"
        if page is None:
            rows.append(_no_page(row_id, what, videos_url, state, why))
        elif f'src="{src}"' not in page:
            cards = sorted(set(re.findall(r'src="/videos/kube-noob-([\w-]+)\.mp4"', page)))
            rows.append(
                Row(
                    row_id,
                    what,
                    MISSING,
                    url=videos_url,
                    seen=f'no src="{src}"; the page has cards for {", ".join(cards) or "nothing"}',
                )
            )
        else:
            file_url = f"{SITE}{src}"
            try:
                answer = read.get(file_url, method="HEAD")
            except FetchError as err:
                rows.append(
                    _unknown(row_id, what, file_url, f"the card is there and its file could not be read: {err}")
                )
                continue
            if (row := _status(row_id, what, file_url, answer, "the card is there and its file is not")) is not None:
                rows.append(row)
            else:
                rows.append(Row(row_id, what, DELIVERED, url=videos_url, seen=f'src="{src}", and the file answers 200'))

    mech_url = f"{SITE}/learn/mechanisms/"
    page, state, why = _page(read, mech_url)
    what_built = f"kube-noob.com/learn/mechanisms/ is built from {version}"
    if page is None:
        rows.append(_no_page("website:version:mechanisms", what_built, mech_url, state, why))
    else:
        found = re.findall(r"Built from kube-noob (\d+\.\d+\.\d+)", page)
        rows.append(
            _stated("website:version:mechanisms", what_built, mech_url, found, version, "`Built from kube-noob X.Y.Z`")
        )
    for lesson in plan.lessons or ():
        row_id, what = (
            f"website:lesson:{lesson.id}",
            f"kube-noob.com/learn/mechanisms/ shows the lesson “{lesson.title}”",
        )
        if page is None:
            rows.append(_no_page(row_id, what, mech_url, state, why))
        elif re.search(rf">\s*{re.escape(html.escape(lesson.title, quote=False))}\s*<", page):
            rows.append(Row(row_id, what, DELIVERED, url=mech_url, seen="the title is on the page"))
        else:
            rows.append(Row(row_id, what, MISSING, url=mech_url, seen="no element on the page has that title"))
    for lesson in plan.lessons or ():
        if not lesson.walk:
            continue
        row_id, what = (
            f"website:walk:{lesson.id}",
            f"kube-noob.com has the walk page of “{lesson.title}”, first example",
        )
        walk_url = f"{mech_url}{lesson.id}/example-1/"
        walk, wstate, wwhy = _page(read, walk_url)
        if walk is None:
            rows.append(_no_page(row_id, what, walk_url, wstate, wwhy))
        elif html.escape(lesson.title, quote=False) not in walk:
            rows.append(
                _unknown(row_id, what, walk_url, "unexpected shape: the page answers 200 and does not name the lesson")
            )
        else:
            rows.append(Row(row_id, what, DELIVERED, url=walk_url, seen="HTTP 200, and the page names the lesson"))
    return rows


def check(plan: Plan, *, fetch: Fetch | None = None, in_flight: Mapping[str, str] | None = None) -> list[Row]:
    """One row per deliverable in `plan`, in a fixed order, each read through `fetch`."""
    read = _Reader(fetch or globals()["fetch"])
    rows: list[Row] = []
    sdist = ""
    if plan.pypi_name:
        pypi_rows, sdist = _check_pypi(plan, read)
        rows += pypi_rows
    rows += _check_release(plan, read)
    rows += _check_homebrew(plan, read, sdist)
    for tag in plan.image_tags:
        floating = "" if tag == plan.version else " (a floating tag: it moves to each later patch release)"
        rows.append(
            _ghcr_manifest(
                f"image:{tag}", f"the image ghcr.io/{plan.image}:{tag} exists{floating}", plan.image, tag, read
            )
        )
    if plan.chart:
        what = f"the chart oci://ghcr.io/{plan.chart}:{plan.chart_version} is published"
        rows.append(_ghcr_manifest("chart", what, plan.chart, plan.chart_version, read))
    if plan.registry_name:
        rows += _check_registry(plan, read)
    rows += _check_site(plan, read)
    # A source that could not be read is a row, so a derivation that failed is never a shorter ledger.
    rows += [
        Row(row_id, "the list of deliverables could be derived", NOT_KNOWN, reason=reason)
        for row_id, reason in plan.problems
    ]
    flying = dict(in_flight or {})
    return [
        dataclasses.replace(
            r, state=NOT_KNOWN, in_flight=True, reason=f"in flight ({flying[r.group]}); last seen: {r.seen}"
        )
        if r.state == MISSING and r.group in flying
        else r
        for r in rows
    ]


def exit_code(rows: list[Row]) -> int:
    if any(r.state == MISSING for r in rows):
        return 1
    if not rows or any(r.state != DELIVERED for r in rows):
        return 5
    return 0


# ---------------------------------------------------------------------------------------------------------------
# Which tree
# ---------------------------------------------------------------------------------------------------------------


def _git(root: Path, *args: str) -> str | None:
    try:
        done = subprocess.run(
            ["git", "-C", str(root), *args],  # noqa: S607 - git on PATH
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = done.stdout.strip()
    return out if done.returncode == 0 and out else None


def _archive(root: Path, commit: str, into: Path) -> None:
    done = subprocess.run(
        ["git", "-C", str(root), "archive", "--format=tar", commit, "--", *SOURCES],  # noqa: S607 - git on PATH
        capture_output=True,
        timeout=120,
        check=False,
    )
    if done.returncode != 0:
        raise ValueError((done.stderr.decode("utf-8", "replace").strip().splitlines() or ["git archive failed"])[-1])
    with tarfile.open(fileobj=io.BytesIO(done.stdout)) as tar:
        tar.extractall(into, filter="data")


@contextlib.contextmanager
def source_tree(root: Path, version: str, fetch_: Fetch) -> Iterator[tuple[Path, Row]]:
    """The tree the list is derived from, and the row that says whether it is the release's own."""
    tag = f"v{version}"
    what = f"the list below is derived from the tree of {tag}"
    head = _git(root, "rev-parse", "HEAD")
    commit = _git(root, "rev-parse", "--quiet", "--verify", f"refs/tags/{tag}^{{commit}}")
    if head and commit and head == commit:
        yield root, Row("ledger:source", what, DELIVERED, seen=f"this checkout is {tag} ({commit[:12]})")
        return
    if commit:
        with tempfile.TemporaryDirectory(prefix="kube-noob-ledger-") as tmp:
            try:
                _archive(root, commit, Path(tmp))
            except (OSError, ValueError, tarfile.TarError, subprocess.TimeoutExpired) as err:
                yield (
                    root,
                    _unknown(
                        "ledger:source",
                        what,
                        "",
                        f"{tag} ({commit[:12]}) could not be read with git archive ({err}), "
                        f"so the list was derived from this checkout ({(head or 'unknown')[:12]}) instead",
                    ),
                )
                return
            yield (
                Path(tmp),
                Row(
                    "ledger:source",
                    what,
                    DELIVERED,
                    seen=f"{tag} ({commit[:12]}) read with git archive; this checkout is {(head or 'unknown')[:12]}",
                ),
            )
        return
    url = f"{API}/commits/{tag}"
    fix = f"so the list was derived from this checkout instead. Fetch the tag and run again: git fetch origin tag {tag}"
    try:
        answer = fetch_(url, headers={"Accept": "application/vnd.github.sha"})
    except FetchError as err:
        yield (
            root,
            _unknown(
                "ledger:source", what, url, f"{tag} is not fetched here and its commit could not be read ({err}), {fix}"
            ),
        )
        return
    remote = answer.body.decode("ascii", "replace").strip()
    if answer.status in (404, 422):
        yield root, Row("ledger:source", what, MISSING, url=url, seen=f"HTTP {answer.status}: there is no tag {tag}")
    elif answer.status != 200 or not re.fullmatch(r"[0-9a-f]{40}", remote):
        yield (
            root,
            _unknown(
                "ledger:source",
                what,
                url,
                f"{tag} is not fetched here and its commit came back as HTTP {answer.status} "
                f"in a shape that is not a commit id, {fix}",
            ),
        )
    elif head == remote:
        yield root, Row("ledger:source", what, DELIVERED, url=url, seen=f"this checkout is {tag} ({remote[:12]})")
    else:
        yield (
            root,
            _unknown(
                "ledger:source",
                what,
                url,
                f"this checkout is {(head or 'not a git checkout')[:12]}, {tag} is {remote[:12]} "
                f"and is not fetched here, {fix}",
            ),
        )


# ---------------------------------------------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------------------------------------------


def _clean(text: str) -> str:
    held = {os.environ.get(name, "") for name in ("GH_TOKEN", "GITHUB_TOKEN")} | _SECRETS
    for secret in sorted(held - {""}, key=len, reverse=True):
        text = text.replace(secret, "***")
    return " ".join(text.split())


def _summary(rows: list[Row]) -> dict[str, Any]:
    return {
        "delivered": sum(r.state == DELIVERED for r in rows),
        "in_flight": sum(r.in_flight for r in rows),
        "missing": sum(r.state == MISSING for r in rows),
        "not_known": sum(r.state == NOT_KNOWN for r in rows),
        "shipped": exit_code(rows) == 0,
    }


def _verdict(rows: list[Row]) -> str:
    s = _summary(rows)
    counts = f"{s['delivered']} delivered, {s['missing']} MISSING, {s['not_known']} not known"
    if s["in_flight"]:
        counts += f" ({s['in_flight']} of them in flight)"
    code = exit_code(rows)
    word = {0: "shipped", 1: "NOT shipped", 5: "not known whether it shipped"}[code]
    return f"{counts}: {word} (exit {code})"


def render(version: str, rows: list[Row], fmt: str) -> str:
    rows = [
        dataclasses.replace(
            r, deliverable=_clean(r.deliverable), url=_clean(r.url), seen=_clean(r.seen), reason=_clean(r.reason)
        )
        for r in rows
    ]
    if fmt == "json":
        doc = {
            "exit": exit_code(rows),
            "rows": [
                {k: getattr(r, k) for k in ("id", "deliverable", "state", "url", "seen", "reason", "in_flight")}
                for r in rows
            ],
            "summary": _summary(rows),
            "version": version,
        }
        return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if fmt == "markdown":
        head = {0: "**Shipped.**", 1: "**Not shipped.**", 5: "**Not known whether it shipped.**"}[exit_code(rows)]
        lines = [f"## kube-noob {version}: deliverables ledger", "", f"{head} {_verdict(rows)}", ""]
        for r in rows:
            detail = " — ".join(x for x in (r.reason or r.seen, r.url) if x)
            lines.append(
                f"- [{'x' if r.state == DELIVERED else ' '}] **{r.state}** `{r.id}` {r.deliverable}"
                + (f" — {detail}" if detail else "")
            )
        return "\n".join(lines) + "\n"
    lines = [f"kube-noob {version}: deliverables ledger"]
    for r in rows:
        lines.append(" | ".join(x for x in (f"{r.state:<9}  {r.id}  {r.deliverable}", r.url, r.reason or r.seen) if x))
    lines.append(_verdict(rows))
    return "\n".join(lines) + "\n"


def _saved(path: Path) -> tuple[str, list[Row]]:
    """A ledger written with --format json. One that cannot be read back is one not-known row, never an empty list."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        rows = [
            Row(
                str(r["id"]),
                str(r.get("deliverable", "")),
                str(r["state"]),
                str(r.get("url", "")),
                str(r.get("seen", "")),
                str(r.get("reason", "")),
                bool(r.get("in_flight")),
            )
            for r in doc["rows"]
        ]
        if not rows or any(r.state not in (DELIVERED, MISSING, NOT_KNOWN) for r in rows):
            raise ValueError("no rows, or a row in a state this script does not know")
        return str(doc.get("version", "")), rows
    except (OSError, ValueError, KeyError, TypeError) as err:
        return "", [
            _unknown("ledger:saved", "the saved ledger could be read", str(path), f"{type(err).__name__}: {err}")
        ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--version", help="the release to check (default: this checkout's __version__)")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument(
        "--in-flight",
        action="append",
        default=[],
        metavar="GROUP=REASON",
        help="report a MISSING row of GROUP as not known (in flight)",
    )
    parser.add_argument("--render", metavar="FILE", help="print a ledger saved with --format json; reads nothing")
    args = parser.parse_args(argv)
    if args.render:
        version, rows = _saved(Path(args.render))
        sys.stdout.write(render(version, rows, args.format))
        return exit_code(rows)
    version = args.version or tree_version(ROOT)
    if not VERSION_RE.match(version):
        parser.error(f"--version is X.Y.Z, without the v: {version!r}")
    flying: dict[str, str] = {}
    for item in args.in_flight:
        group, _, reason = item.partition("=")
        flying[group] = reason or "its producer was still running"
    with source_tree(ROOT, version, fetch) as (tree, source_row):
        plan = derive(tree, version)
        rows = [source_row, *check(plan, fetch=fetch, in_flight=flying)]
    sys.stdout.write(render(version, rows, args.format))
    return exit_code(rows)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
