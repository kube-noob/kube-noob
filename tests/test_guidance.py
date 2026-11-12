"""docs/guidance.md is the contract: every rule names its checks, and every named check must exist."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROW = re.compile(r"^\| (G\d{2,3}) \| (.+?) \| (.+) \|$")
REF = re.compile(r"`([^`]+)`")


def _rows() -> list[tuple[str, str, list[str]]]:
    rows = []
    for line in (ROOT / "docs/guidance.md").read_text().splitlines():
        m = ROW.match(line)
        if m:
            refs = [r for r in REF.findall(m.group(3)) if r.startswith(("tests/", "ci:"))]
            rows.append((m.group(1), m.group(2), refs))
    return rows


def _tests_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {n.name for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}


def _ci_names() -> set[str]:
    names: set[str] = set()
    for wf in (ROOT / ".github/workflows").glob("*.yml"):
        doc = yaml.safe_load(wf.read_text())
        for job_id, job in (doc.get("jobs") or {}).items():
            names.add(job_id)
            names.update(str(s["name"]) for s in job.get("steps", []) if "name" in s)
    return names


def test_every_rule_has_existing_checks() -> None:
    rows = _rows()
    assert len(rows) >= 20
    ids = [r[0] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate guidance ids"
    ci = _ci_names()
    missing = []
    for gid, _, refs in rows:
        assert refs, f"{gid} has no enforcing check"
        for ref in refs:
            if ref.startswith("ci:"):
                if ref[3:] not in ci:
                    missing.append(f"{gid}: CI step/job {ref[3:]!r}")
                continue
            file, _, name = ref.partition("::")
            path = ROOT / file
            if not path.is_file() or name not in _tests_in(path):
                missing.append(f"{gid}: {ref}")
    assert missing == []


def test_docs_are_concise_and_linked() -> None:
    readme = (ROOT / "README.md").read_text()
    assert len(readme.split()) < 600
    for doc in ("docs/use-cases.md", "docs/learning.md", "docs/guidance.md"):
        assert (ROOT / doc).is_file() and doc in readme, doc
    assert "kube-noob demo" in readme and "kube-noob doctor" in readme
    use_cases = (ROOT / "docs/use-cases.md").read_text()
    assert all(f"kube-noob demo {d}" in use_cases for d in ("learn", "audit", "diagnose", "doctor"))
    assert "getting_started" in use_cases


def test_every_file_the_readme_tells_a_stranger_to_run_exists() -> None:
    """The README led with two runnable commands and the second one was `policy explain -f denial.txt`. No such
    file ships, so the first thing a stranger copied answered `error: no such file: denial.txt`. A command in the
    README is a promise; every path it passes to -f has to be in the repository.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    refs = re.findall(r"kube-noob [^\n`]*?-f (?!-)(\S+)", readme)
    assert refs, "the README passes no -f paths, so this test proves nothing"
    missing = [r for r in refs if not (ROOT / r).exists() and "<" not in r and not r.startswith(("your-", "my-"))]
    assert missing == [], (
        f"the README runs these paths and they do not ship: {missing}. Either add the file, or name it so the "
        "reader can see it is theirs to supply (your-manifests/, <manifest.yaml>)."
    )


_AI_CLAIMS = [
    re.compile(r"(?i)\boffline AI\b"),
    re.compile(r"(?i)\bkube-noob (is|as) an? [^.\n|]{0,60}?\b(assistant|chatbot|agent|AI)\b"),
    re.compile(r"(?i)\b(debugging|audit|learning) agent\b"),
    re.compile(r"(?i)\bmine runs\b"),
]


def test_positioning_says_no_ai_inside_and_never_claims_otherwise() -> None:
    """kube-noob calls no model; the AI is the client (Claude, Lightspeed) or the optional `kube-noob ask`."""
    for doc in ("README.md", "plugin/kube-noob/README.md", "docs/use-cases.md", "PRIVACY.md"):
        assert "no AI inside" in (ROOT / doc).read_text().replace("No AI inside", "no AI inside"), doc
    copy = [
        ROOT / "README.md",
        ROOT / "PRIVACY.md",
        ROOT / "pyproject.toml",
        ROOT / "server.json",
        ROOT / ".claude-plugin" / "marketplace.json",
        ROOT / "plugin" / "kube-noob" / ".claude-plugin" / "plugin.json",
        ROOT / "plugin" / "kube-noob" / "README.md",
        ROOT / "deploy" / "helm" / "kube-noob" / "README.md",
        ROOT / "deploy" / "helm" / "kube-noob" / "Chart.yaml",
        ROOT / "src" / "kube_noob" / "__init__.py",
        ROOT / "src" / "kube_noob" / "cli.py",
        *sorted((ROOT / "docs").glob("*.md")),
        *sorted((ROOT / "plugin" / "kube-noob" / "skills").glob("*/SKILL.md")),
        *sorted((ROOT / "demos").glob("*.md")),
        *sorted((ROOT / "demos" / "video").glob("*.html")),
    ]
    found = [
        f"{path.relative_to(ROOT)}: {m.group(0)!r}"
        for path in copy
        for rx in _AI_CLAIMS
        for m in rx.finditer(path.read_text())
    ]
    assert found == []


def test_privacy_policy_lists_every_destination() -> None:
    from kube_noob.config import DEFAULT_ALLOWED_DOMAINS

    privacy = (ROOT / "PRIVACY.md").read_text()
    for domain in DEFAULT_ALLOWED_DOMAINS:
        assert re.search(rf"(?<![\w.-]){re.escape(domain)}(?![\w-])", privacy), domain
    for destination in ("API server", "The model you configure", "Public GitHub", "Jira"):
        assert destination in privacy, destination
    assert "no telemetry" in privacy.lower() and "uv.lock" in privacy


def test_readme_numbers_match_the_code() -> None:
    """The counts the README quotes (rules, playbooks, red-team scenarios, tracks, lessons) stay true."""
    from kube_noob.audit.engine import list_rules
    from kube_noob.audit.redteam import SCENARIOS
    from kube_noob.debug.playbooks import PLAYBOOKS
    from kube_noob.learn.tutor import curriculum

    readme = (ROOT / "README.md").read_text()
    tracks = curriculum()["tracks"]
    lessons = sum(len(t.get("lessons", [])) for t in tracks)
    assert f"{len(list_rules())} rules" in readme
    assert f"{len(PLAYBOOKS)} offline playbooks" in readme
    assert f"{len(SCENARIOS)} red-team scenarios" in readme
    assert f"{len(tracks)} tracks, {lessons} lessons" in readme


def test_the_website_queue_states_the_real_numbers() -> None:
    """docs/website-updates.md is the list of what the site says differently, so its own figures must be true.

    A tracker whose numbers have drifted sends someone to publish a stale count on the website -- the same defect
    the compliance document had when it said "The 78 audit rules" with 89 in the code (G206), one step further
    from the code and therefore harder to notice.
    """
    from kube_noob import __version__
    from kube_noob.audit.controls import RULE_CONTROLS
    from kube_noob.audit.engine import list_rules
    from kube_noob.audit.redteam import SCENARIOS
    from kube_noob.config import load_settings
    from kube_noob.debug.playbooks import PLAYBOOKS
    from kube_noob.learn.tutor import curriculum
    from kube_noob.toolkit import Toolkit

    queue = (ROOT / "docs" / "website-updates.md").read_text(encoding="utf-8")
    tracks = curriculum()["tracks"]
    expected = [
        f"version {__version__}",
        f"{len(list_rules())} rules",
        f"{len({c for cs in RULE_CONTROLS.values() for c in cs})} NIST SP 800-53 Rev. 5 controls",
        f"{len(PLAYBOOKS)} offline playbooks",
        f"{len(SCENARIOS)} red-team scenarios",
        f"{len(tracks)} tracks with {sum(len(t.get('lessons', [])) for t in tracks)} lessons",
        f"{len(Toolkit(load_settings()).specs())} MCP tools",
    ]
    for fact in expected:
        assert fact in queue, fact
