#!/usr/bin/env python3
"""Build kube-noob as an Agent Skill: a folder (or a ZIP for claude.ai) that runs kube-noob's tools offline.

The skill is `skill/kube-noob/` plus, at build time, the readable server source the Claude plugin already ships
(`plugin/kube-noob/server/kube_noob`, kept current by scripts/sync_plugin_server.py), so the skill and the plugin
run the same code:

    kube-noob/
      SKILL.md               instructions (hand-written; checked here)
      scripts/kn.py          the runner: one tool per call, JSON out (kube_noob.tool_runner, as the MCP server)
      scripts/kube_noob/     the bundled server source, copied at build time
      references/tools.md    every tool and its arguments, generated from the code (--write)
      LICENSE

Usage:
  python scripts/build_skill.py --check        exit 1 if SKILL.md breaks the Agent Skills rules, tools.md is
                                               stale, or the dependency pins disagree with plugin/kube-noob/uv.lock
  python scripts/build_skill.py --write        regenerate skill/kube-noob/references/tools.md
  python scripts/build_skill.py --out DIR      write the complete skill folder to DIR (named kube-noob)
  python scripts/build_skill.py --zip FILE     write the ZIP to upload in claude.ai (the folder at its top level)

Rules checked (Agent Skills specification and the claude.ai guide, 2026-10-29): `name` and `description` are the
only frontmatter fields; the name is lowercase letters, digits and hyphens, at most 64 characters, matches the folder
and contains neither "anthropic" nor "claude"; the description is 1 to 1,024 characters without XML tags; SKILL.md
stays under 500 lines; every file under 256 KiB and at most 512 files (the plugin directory's limits, so the skill
can also ship in a plugin).
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NAME = "kube-noob"
SKILL = ROOT / "skill" / NAME
SERVER = ROOT / "plugin" / "kube-noob" / "server" / "kube_noob"
REFERENCE = Path("references") / "tools.md"
MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 512
MAX_LINES = 500
_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_TOOL_WORD = re.compile(r"`([a-z]+(?:_[a-z]+)+)`")
_SKIP = frozenset({"__pycache__", ".pytest_cache"})
PLUGIN_LOCK = ROOT / "plugin" / "kube-noob" / "uv.lock"
# The three libraries the skill asks the model to install when they are missing. The left name is the name in
# plugin/kube-noob/uv.lock, the right one is the name pip installs. Nothing else in the lock is quoted to the user,
# so nothing else is read from it.
PINNED = (("pydantic", "pydantic"), ("pyyaml", "PyYAML"), ("jsonschema", "jsonschema"))
PIN_FILES = (Path("SKILL.md"), Path("scripts") / "kn.py")
_PIN = re.compile(r"\b(pydantic|PyYAML|jsonschema)==([0-9][^\s`'\")]*)")


def lock_pins() -> dict[str, str]:
    """``{pip name: version}`` for the three libraries, read off plugin/kube-noob/uv.lock.

    The lock is the one source of truth for these versions: dependabot bumps it, so a copy of the number anywhere
    else is a second source that goes stale the moment the lock moves and says nothing (class 9). ``--write``
    rewrites the copies from here and ``--check`` refuses when they disagree.
    """
    text = PLUGIN_LOCK.read_text(encoding="utf-8")
    pins: dict[str, str] = {}
    for lock_name, pip_name in PINNED:
        found = re.search(rf'^name = "{re.escape(lock_name)}"\nversion = "([^"]+)"', text, re.M)
        if found is None:
            raise ValueError(f"{PLUGIN_LOCK.relative_to(ROOT)} pins no version for {lock_name}")
        pins[pip_name] = found.group(1)
    return pins


def rewrite_pins(pins: dict[str, str]) -> list[Path]:
    """Rewrite every ``name==version`` in the skill's two hand-written files. Returns the files that changed."""
    changed = []
    for rel in PIN_FILES:
        before = (SKILL / rel).read_text(encoding="utf-8")
        after = _PIN.sub(lambda m: f"{m.group(1)}=={pins[m.group(1)]}", before)
        if after != before:
            (SKILL / rel).write_text(after, encoding="utf-8")
            changed.append(rel)
    return changed


def pin_problems() -> list[str]:
    try:
        pins = lock_pins()
    except (OSError, ValueError) as exc:
        return [str(exc)]
    problems = []
    for rel in PIN_FILES:
        try:
            text = (SKILL / rel).read_text(encoding="utf-8")
        except OSError as exc:
            problems.append(str(exc))
            continue
        seen = set(_PIN.findall(text))
        # An absent pin is not a matching pin: a file that quotes none of the three would otherwise pass this
        # check while telling the model to install nothing, which is the defect this project refuses.
        for pip_name, version in pins.items():
            if (pip_name, version) not in seen:
                quoted = sorted(v for n, v in seen if n == pip_name)
                problems.append(
                    f"{rel.as_posix()} should pin {pip_name}=={version} from "
                    f"{PLUGIN_LOCK.relative_to(ROOT)} but pins {quoted or 'nothing'}: "
                    f"run python scripts/build_skill.py --write"
                )
    return problems


def _frontmatter(text: str) -> tuple[dict[str, Any], str]:
    import yaml

    if not text.startswith("---\n"):
        raise ValueError("SKILL.md must start with YAML frontmatter")
    front, sep, body = text[4:].partition("\n---\n")
    if not sep:
        raise ValueError("SKILL.md frontmatter is not closed with ---")
    meta = yaml.safe_load(front)
    if not isinstance(meta, dict):
        raise ValueError("SKILL.md frontmatter is not a mapping")
    return meta, body


_REFERENCE_PROGRAM = r"""
import sys
sys.path.insert(0, sys.argv[1])
from kube_noob import toolkit
from kube_noob.config import load_settings

kit = toolkit.Toolkit(load_settings(overrides={"offline": True, "webEnabled": False, "cluster": {"enabled": False}}))
lines = [
    "# kube-noob tools",
    "",
    "Generated by scripts/build_skill.py from the bundled server code; run any of them with",
    "`python3 -I scripts/kn.py TOOL '<json arguments>'`. Arguments marked * are required.",
    "",
]
for spec in sorted(kit.specs(), key=lambda s: s.name):
    schema = spec.model.model_json_schema()
    required = set(schema.get("required") or [])
    lines += [f"## {spec.name}", "", f"{spec.title}. {' '.join(spec.description.split())}", ""]
    props = schema.get("properties") or {}
    for key in sorted(props):
        prop = props[key]
        kind = prop.get("type") or "/".join(
            sorted({str(a.get("type", "object")) for a in prop.get("anyOf", []) if isinstance(a, dict)})
        )
        desc = " ".join(str(prop.get("description") or "").split())
        star = "*" if key in required else ""
        lines.append(f"- `{key}`{star} ({kind or 'any'})" + (f": {desc}" if desc else ""))
    if not props:
        lines.append("- no arguments")
    lines.append("")
sys.stdout.write("\n".join(lines))
"""


def reference_text() -> str:
    """Every tool the skill runs, with its arguments, generated by the bundled server copy itself (the plugin leaves
    out the must-gather reader and the Containerfile audit, so the skill does too). Sorted, no dates."""
    import subprocess

    out = subprocess.run(
        [sys.executable, "-I", "-c", _REFERENCE_PROGRAM, str(SERVER.parent)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip().splitlines()[-1] if out.stderr.strip() else "reference failed")
    return out.stdout


def check() -> list[str]:
    problems: list[str] = []
    try:
        meta, body = _frontmatter((SKILL / "SKILL.md").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [str(exc)]
    if set(meta) != {"name", "description"}:
        problems.append(f"frontmatter fields must be exactly name and description, found {sorted(meta)}")
    name, desc = str(meta.get("name") or ""), str(meta.get("description") or "")
    if not _NAME.match(name) or len(name) > 64 or name != SKILL.name or {"anthropic", "claude"} & set(name.split("-")):
        problems.append(f"invalid skill name {name!r} (lowercase, digits, hyphens; <= 64; matches the folder)")
    if not 0 < len(desc) <= 1024 or re.search(r"<[^>]+>", desc):
        problems.append(f"description must be 1-1024 characters without XML tags (is {len(desc)})")
    if len(body.splitlines()) >= MAX_LINES:
        problems.append(f"SKILL.md body has {len(body.splitlines())} lines; keep it under {MAX_LINES}")
    if "${CLAUDE_SKILL_DIR}/scripts/kn.py" not in body:
        problems.append("SKILL.md must run the runner as ${CLAUDE_SKILL_DIR}/scripts/kn.py")
    known = (
        set(re.findall(r"^## (\S+)$", (SKILL / REFERENCE).read_text(encoding="utf-8"), re.M))
        if (SKILL / REFERENCE).is_file()
        else set()
    )
    for word in sorted(set(_TOOL_WORD.findall(body)) - known):
        problems.append(f"SKILL.md names `{word}`, which is not a kube-noob tool")
    try:
        current = reference_text()
    except Exception as exc:  # noqa: BLE001 - report, do not crash the check
        problems.append(f"cannot generate {REFERENCE}: {exc}")
    else:
        if not (SKILL / REFERENCE).is_file() or (SKILL / REFERENCE).read_text(encoding="utf-8") != current:
            problems.append(f"{REFERENCE} is stale: run python scripts/build_skill.py --write")
    if not (SKILL / "scripts" / "kn.py").is_file():
        problems.append("scripts/kn.py is missing")
    else:
        problems.extend(pin_problems())
    if not SERVER.is_dir():
        problems.append(f"{SERVER.relative_to(ROOT)} is missing: run python scripts/sync_plugin_server.py")
    return problems


def _files(base: Path) -> list[Path]:
    return sorted(p for p in base.rglob("*") if p.is_file() and not _SKIP & set(p.relative_to(base).parts))


def build(out: Path) -> Path:
    """Write the complete skill folder to ``out`` (which must be named kube-noob and must not exist yet)."""
    if out.name != NAME:
        raise ValueError(f"the skill folder must be named {NAME}")
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(parents=True)
    for rel in (Path("SKILL.md"), Path("scripts") / "kn.py", REFERENCE):
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SKILL / rel, out / rel)
    shutil.copyfile(ROOT / "LICENSE", out / "LICENSE")
    for src in _files(SERVER):
        dst = out / "scripts" / "kube_noob" / src.relative_to(SERVER)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    files = _files(out)
    if len(files) > MAX_FILES:
        raise ValueError(f"the skill has {len(files)} files; the limit is {MAX_FILES}")
    big = [str(p.relative_to(out)) for p in files if p.stat().st_size > MAX_FILE_BYTES]
    if big:
        raise ValueError(f"files over {MAX_FILE_BYTES} bytes: {', '.join(big)}")
    return out


def build_zip(target: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        folder = build(Path(tmp) / NAME)
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in _files(folder):
                info = zipfile.ZipInfo(f"{NAME}/{f.relative_to(folder).as_posix()}", date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                zf.writestr(info, f.read_bytes())
    return target


def main(argv: list[str]) -> int:
    if argv[:1] == ["--check"]:
        problems = check()
        for p in problems:
            print(f"skill: {p}", file=sys.stderr)
        return 1 if problems else 0
    if argv[:1] == ["--write"]:
        (SKILL / REFERENCE).parent.mkdir(parents=True, exist_ok=True)
        (SKILL / REFERENCE).write_text(reference_text(), encoding="utf-8")
        for rel in rewrite_pins(lock_pins()):
            print(f"skill: rewrote the dependency pins in {rel.as_posix()} from {PLUGIN_LOCK.relative_to(ROOT)}")
        return 0
    if len(argv) == 2 and argv[0] == "--out":
        print(build(Path(argv[1])))
        return 0
    if len(argv) == 2 and argv[0] == "--zip":
        print(build_zip(Path(argv[1])))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
