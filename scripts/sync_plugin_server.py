#!/usr/bin/env python3
"""Copy the kube-noob stdio MCP server into the Claude plugin, so the plugin runs readable, locked code.

The plugin (plugin/kube-noob) does not download kube-noob at start-up. It ships:

- server/kube_noob/      the modules the stdio MCP server imports, copied unchanged from src/kube_noob, plus the
                         package data and examples/ under data/examples (as in the wheel)
- server/kube_noob_plugin.py   the entry point .mcp.json runs (stdio MCP server only)
- pyproject.toml         generated here: the runtime dependencies of the server, minus the LLM SDK it never uses
- uv.lock                every dependency pinned with its registry source and hashes (`uv lock`, see below)

Which modules ship is computed, not listed: every kube_noob module reachable by `import` from
kube_noob.server.stdio. So the CLI, the optional model agent, the HTTP service (bearer token) and the corpus builders
(GitHub and Jira tokens) are not in the plugin, and nothing in it reads a credential. The one import not followed is
kube_noob.debug.backends (kubeconfig and ServiceAccount token), which get_backend reaches only when cluster access is
enabled; the plugin turns cluster access off.

The plugin directory reads files up to 256 KiB and at most 512 files per plugin; --check enforces both, and that
every file except the listing icon is UTF-8 text.

Usage:
  python scripts/sync_plugin_server.py           write the copy and pyproject.toml
  python scripts/sync_plugin_server.py --check   exit 1 if the plugin copy is stale or breaks a limit (CI)

After a dependency change, refresh the lock:
  uv lock --project plugin/kube-noob --default-index https://pypi.org/simple
"""

from __future__ import annotations

import ast
import filecmp
import re
import shutil
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = Path("plugin/kube-noob")
VENDORED = PLUGIN / "server" / "kube_noob"
ENTRY = "kube_noob.server.stdio"
# The plugin's PreToolUse hook (hooks/hooks.json runs hooks/kube_noob_hook.py) imports kube_noob.hook, which reaches
# kube_noob.verify and the gate's audit. Followed like the server, under the same guards: it renders no chart (helm
# is guarded out) and reads nothing outside the working tree the hook input names.
ENTRIES = (ENTRY, "kube_noob.hook")
# Reached only through kube_noob.debug.cluster.get_backend after it checks that cluster access is enabled; the RHACS
# Central reader (the only code that reads its API token), imported only by the rhacs_compare_live tool; and the
# Containerfile and image audit, whose detectors spell out download-and-execute and credential patterns that a plugin
# reviewer should not have to read past (the CLI and the service keep them); and the Red Hat VEX fetcher and archive
# reader (network and a zstd subprocess; the plugin keeps the pure CSAF parser, kube_noob.vuln.csaf); and the kernel
# FIPS flag reader (a file outside the plugin's own folders, flagged by the plugin directory's scan).
GUARDED_IMPORTS = frozenset(
    {
        "kube_noob.debug.backends",
        "kube_noob.rhacs_central",
        "kube_noob.build.containerfile",
        "kube_noob.build.image",
        # SAST assessment follows findings into images with the Containerfile parser above, so it goes with it
        # (the plugin then does not offer code_report rather than offering a tool that cannot import).
        "kube_noob.code.assess",
        "kube_noob.code.ship",
        "kube_noob.code.builds",
        # Rendering a chart runs the `helm` binary: the CLI's helm-audit and the gate do; the plugin never does.
        "kube_noob.generate.helm_render",
        # The hook's no-fork path starts a fresh interpreter; the plugin starts no program (it falls back to a thread).
        "kube_noob.hook_spawn",
        # The plugin makes no network calls of its own: no web_fetch, so no HTTP client module; and it serves stdio
        # only, so no REST routes.
        "kube_noob.net",
        "kube_noob.server.rest",
        "kube_noob.sources.advisories",
        "kube_noob.host_fips",
        # Must-gather analysis reads paths on the user's machine: the CLI and the stdio server offer it; the Claude
        # plugin does not (the directory asks plugins not to read the user's files on their own).
        "kube_noob.mustgather",
        "kube_noob.mustgather.analyse",
        "kube_noob.mustgather.ingest",
        "kube_noob.mustgather.report",
        "kube_noob.mustgather.sample",
        # The operator inventory's must-gather reader, for the same reason; the inventory itself
        # (kube_noob.operators: manifests handed to it, and the live read when cluster access is on) ships.
        "kube_noob.mustgather.operators",
    }
)
# LLM SDKs never ship in the plugin, even if one returns to the core dependencies; the plugin runs the MCP server only.
# httpx and uvicorn belong to the web client and the HTTP service, and neither ships here: the stdio server imports
# neither, so declaring them made a user install packages for nothing and gave a reviewer two more to account for.
# (They remain in the resolved tree because the MCP SDK itself needs them; what changes is what the plugin claims.)
EXCLUDED_DEPENDENCIES = frozenset({"anthropic", "openai", "httpx", "uvicorn"})
# Imported directly by the bundled server but reached only through another package's requirements in the repository's
# own pyproject. A direct import belongs in the manifest: otherwise an upgrade that drops one of these from its
# parent's requirements breaks the plugin, and nothing would have said so.
ADDED_DEPENDENCIES = ("anyio>=4.5", "mcp-types>=0.2", "pydantic-core>=2.33")
MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 512
BINARY_ALLOWED = frozenset({Path(".claude-plugin/icon.png")})
_SKIP_PARTS = frozenset({"__pycache__", ".venv", ".pytest_cache"})
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def _dep_name(requirement: str) -> str:
    m = _NAME.match(requirement.strip())
    if not m:
        raise ValueError(f"cannot parse requirement {requirement!r}")
    return m.group(0).lower().replace("_", "-")


def _version(root: Path) -> str:
    m = re.search(r'__version__ = "([^"]+)"', (root / "src/kube_noob/__init__.py").read_text(encoding="utf-8"))
    if not m:
        raise ValueError("cannot find __version__ in src/kube_noob/__init__.py")
    return m.group(1)


def plugin_pyproject(root: Path = ROOT) -> str:
    """The plugin's pyproject.toml, derived from the repository's so the two can never disagree."""
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    deps = sorted(
        [d for d in project["dependencies"] if _dep_name(d) not in EXCLUDED_DEPENDENCIES] + list(ADDED_DEPENDENCIES),
        key=lambda d: _dep_name(d).lower(),
    )
    lines = [
        "# Generated by scripts/sync_plugin_server.py from the repository pyproject.toml. Do not edit by hand.",
        "# The plugin runs the readable server source in server/ with the dependencies below, pinned with hashes",
        "# in uv.lock. It never installs kube-noob from a package index and never installs an LLM SDK.",
        "[project]",
        'name = "kube-noob-plugin"',
        f'version = "{_version(root)}"',
        'description = "Runtime for the kube-noob Claude plugin: the bundled MCP server and its locked dependencies."',
        f'requires-python = "{project["requires-python"]}"',
        'license = "Apache-2.0"',
        "dependencies = [",
        *(f'  "{d}",' for d in deps),
        "]",
        "",
        "[tool.uv]",
        "package = false",
        "",
    ]
    return "\n".join(lines)


def _module_files(src: Path) -> dict[str, Path]:
    """Dotted module name -> file, for every module under src/kube_noob."""
    out: dict[str, Path] = {}
    for path in sorted(src.rglob("*.py")):
        if _SKIP_PARTS.intersection(path.parts):
            continue
        parts = list(path.relative_to(src.parent).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        out[".".join(parts)] = path
    return out


def _imports(module: str, path: Path) -> set[str]:
    """kube_noob names imported anywhere in the module (top level or inside functions)."""
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")[: len(package.split(".")) - (node.level - 1)]
                target = ".".join([*base, *([node.module] if node.module else [])])
            else:
                target = node.module or ""
            names.add(target)
            names.update(f"{target}.{a.name}" for a in node.names)
    return {n for n in names if n == "kube_noob" or n.startswith("kube_noob.")}


def plugin_modules(root: Path = ROOT) -> set[str]:
    """Every kube_noob module the stdio MCP server or the plugin's hook can import, minus the guarded ones."""
    files = _module_files(root / "src" / "kube_noob")
    seen: set[str] = set()
    stack = list(ENTRIES)
    while stack:
        mod = stack.pop()
        if mod in seen or mod in GUARDED_IMPORTS:
            continue
        seen.add(mod)
        parts = mod.split(".")
        stack.extend(".".join(parts[:i]) for i in range(1, len(parts)))
        for imported in _imports(mod, files[mod]):
            target = imported
            while target and target not in files:
                target = target.rpartition(".")[0]
            if target:
                stack.append(target)
    return seen


def _expected_tree(root: Path) -> dict[Path, Path]:
    """Relative path inside VENDORED -> source file."""
    src = root / "src" / "kube_noob"
    files = _module_files(src)
    modules = plugin_modules(root)
    out: dict[Path, Path] = {files[m].relative_to(src): files[m] for m in sorted(modules)}
    for path in sorted(src.rglob("*")):
        if not path.is_file() or path.suffix in {".py", ".pyc", ".pyo"} or _SKIP_PARTS.intersection(path.parts):
            continue
        package = path.parent
        while not (package / "__init__.py").is_file():
            package = package.parent
        dotted = ".".join(package.relative_to(src.parent).parts)
        if dotted in modules:
            out[path.relative_to(src)] = path
    for path in sorted((root / "examples").iterdir()):
        if path.is_file():
            out[Path("data") / "examples" / path.name] = path
    return out


def _limit_problems(root: Path) -> list[str]:
    plugin = root / PLUGIN
    problems: list[str] = []
    files = [p for p in plugin.rglob("*") if p.is_file() and not _SKIP_PARTS.intersection(p.parts)]
    if len(files) >= MAX_FILES:
        problems.append(f"{PLUGIN} has {len(files)} files; the plugin directory reads at most {MAX_FILES}")
    for path in files:
        rel = path.relative_to(plugin)
        if path.stat().st_size > MAX_FILE_BYTES:
            problems.append(f"over {MAX_FILE_BYTES // 1024} KiB: {PLUGIN / rel}")
        if rel in BINARY_ALLOWED:
            continue
        try:
            path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"not UTF-8 text: {PLUGIN / rel}")
    return problems


def check(root: Path = ROOT) -> list[str]:
    """Problems that make the plugin copy differ from the source or break a directory limit; empty when fine."""
    problems: list[str] = []
    dest = root / VENDORED
    expected = _expected_tree(root)
    actual = (
        {
            p.relative_to(dest)
            for p in dest.rglob("*")
            if p.is_file() and not _SKIP_PARTS.intersection(p.parts) and p.suffix not in {".pyc", ".pyo"}
        }
        if dest.is_dir()
        else set()
    )
    for rel in sorted(set(expected) - actual):
        problems.append(f"missing in plugin: {VENDORED / rel}")
    for rel in sorted(actual - set(expected)):
        problems.append(f"not needed by the stdio server: {VENDORED / rel}")
    for rel in sorted(set(expected) & actual):
        if not filecmp.cmp(expected[rel], dest / rel, shallow=False):
            problems.append(f"differs from its source: {VENDORED / rel}")
    pyproject = root / PLUGIN / "pyproject.toml"
    if not pyproject.is_file() or pyproject.read_text(encoding="utf-8") != plugin_pyproject(root):
        problems.append(f"stale: {PLUGIN / 'pyproject.toml'}")
    if not (root / PLUGIN / "uv.lock").is_file():
        problems.append(f"missing: {PLUGIN / 'uv.lock'}")
    problems.extend(_limit_problems(root))
    return problems


def sync(root: Path = ROOT) -> None:
    dest = root / VENDORED
    if dest.exists():
        shutil.rmtree(dest)
    for rel, source in _expected_tree(root).items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    (root / PLUGIN / "pyproject.toml").write_text(plugin_pyproject(root), encoding="utf-8")


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print(__doc__)
        return 2
    if argv == ["--check"]:
        problems = check()
        for p in problems:
            print(p)
        if problems:
            print("Fix: python scripts/sync_plugin_server.py, then commit plugin/kube-noob", file=sys.stderr)
            return 1
        print("plugin server copy is in sync with src/ and examples/, and within the directory's limits")
        return 0
    sync()
    problems = check()
    for p in problems:
        print(p)
    print(f"synced {VENDORED} ({len(plugin_modules())} modules) and {PLUGIN / 'pyproject.toml'}")
    return 1 if any(not p.startswith("missing: ") for p in problems) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
