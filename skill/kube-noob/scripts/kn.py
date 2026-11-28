#!/usr/bin/env python3
"""kube-noob as an Agent Skill: run one kube-noob tool and print its JSON result.

    python3 -I kn.py check                     Python version and the three libraries the skill needs
    python3 -I kn.py tools                     every tool, with what it does
    python3 -I kn.py schema TOOL               the tool's arguments, as a JSON schema
    python3 -I kn.py TOOL [ARGS] [--text-file FIELD=PATH ...]
                                               run the tool; ARGS is a JSON object, @file.json or - (stdin);
                                               --text-file puts a file's text in one string field

The tools are the ones kube-noob's MCP server offers, run through the same code path (kube_noob.tool_runner): the
same validation, the same answers, the same cleaning of text shaped like instructions to a model. It runs offline:
the offline lock is on, web lookups and cluster access are off and no model is called, whatever a config file or
KUBE_NOOB_* variable says, and team memory is off. It reads the files named with --text-file or @file.json and
keeps learning progress in kube-noob's data folder (KUBE_NOOB_DATA_DIR, else ~/.local/share/kube-noob). Exit 0 with the
result, 2 with {"error": ...} for a bad call or a bad config, 3 when a library is missing, 1 with {"error": ...} for
an internal failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
MAX_INPUT_BYTES = 5 * 1024 * 1024  # the same cap kube-noob puts on manifests and pasted text
# The versions plugin/kube-noob/uv.lock pins, installed only when one is missing. Generated: do not edit by
# hand -- `python scripts/build_skill.py --write` rewrites these from the lock and `--check` refuses a mismatch.
NEEDED = (
    ("pydantic", "pydantic==2.14.4"),
    ("yaml", "PyYAML==6.0.4"),
    ("jsonschema", "jsonschema==4.26.0"),
)
# Settings the skill always runs with: these override the config file and the KUBE_NOOB_* variables.
OFFLINE = {
    "offline": True,
    "webEnabled": False,
    "cluster": {"enabled": False},
    "llm": {"provider": "none"},
    "memory": {"paths": []},
}


def _emit(value: Any, code: int = 0) -> int:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")
    return code


def _error(message: str, code: int, tool: str = "") -> int:
    """An error as JSON. Messages can quote the caller's text, so they are cleaned like results."""
    out: dict[str, Any] = {"error": message}
    if tool:
        out["tool"] = tool
    try:
        from kube_noob import sanitize

        out = sanitize.result(out)
    except ImportError:  # the libraries are missing: the message quotes nothing from the caller
        pass
    return _emit(out, code)


def _missing() -> list[str]:
    import importlib.util

    return [pip for mod, pip in NEEDED if importlib.util.find_spec(mod) is None]


def _kit() -> Any:
    if str(HERE) not in sys.path[:1]:
        sys.path.insert(0, str(HERE))
    import kube_noob

    loaded = Path(kube_noob.__file__).resolve().parent
    if loaded != HERE / "kube_noob":
        raise RuntimeError(f"expected the bundled kube-noob in {HERE / 'kube_noob'}, loaded {loaded}")
    from kube_noob import toolkit
    from kube_noob.config import load_settings

    return toolkit.Toolkit(load_settings(overrides=OFFLINE))


def _read(path: str) -> str:
    # Read at most one byte past the cap, whatever the file is: a pipe, /dev/stdin or a device has no size to trust.
    try:
        with Path(path).expanduser().open("rb") as fh:
            data = fh.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror or exc}") from None
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"{path} is larger than {MAX_INPUT_BYTES} bytes")
    return data.decode("utf-8", errors="replace")


def _arguments(rest: list[str]) -> dict[str, Any]:
    args: dict[str, Any] = {}
    files: list[tuple[str, str]] = []
    positional: list[str] = []
    it = iter(rest)
    for item in it:
        if item == "--text-file":
            pair = next(it, "")
            field, sep, path = pair.partition("=")
            if not sep or not field or not path:
                raise ValueError("--text-file needs FIELD=PATH")
            files.append((field, path))
        else:
            positional.append(item)
    if len(positional) > 1:
        raise ValueError("give the arguments as one JSON object, @file.json or -")
    if positional:
        raw = positional[0]
        if raw == "-":
            raw = sys.stdin.read(MAX_INPUT_BYTES + 1)
        elif raw.startswith("@"):
            raw = _read(raw[1:])
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError(f"the arguments are larger than {MAX_INPUT_BYTES} bytes")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if not isinstance(parsed, dict):
            raise ValueError("the arguments are not a JSON object")
        args.update(parsed)
    for field, path in files:
        args[field] = _read(path)
    return args


def main(argv: list[str]) -> int:
    if sys.version_info < (3, 11):  # noqa: UP036 - the skill runs on whatever Python the sandbox has
        return _emit({"error": f"kube-noob needs Python 3.11 or later, found {sys.version.split()[0]}"}, 3)
    if not argv or argv[0] in {"-h", "--help", "help"}:
        sys.stdout.write(__doc__ or "")
        return 0
    missing = _missing()
    if argv[0] == "check":
        out = {"ok": not missing, "python": sys.version.split()[0], "missing": missing}
        if missing:
            out["install"] = "python3 -m pip install " + " ".join(missing)
        return _emit(out, 3 if missing else 0)
    if missing:
        return _emit({"error": "missing libraries", "missing": missing, "install": "run: kn.py check"}, 3)
    try:
        kit = _kit()
    except RuntimeError as exc:  # another kube-noob would have been imported: refuse, do not run it
        return _error(str(exc), 2)
    except Exception as exc:  # noqa: BLE001 - a bad config file or variable is the caller's to fix
        return _error(f"kube-noob config: {str(exc)[:2000]}", 2)
    specs = {s.name: s for s in kit.specs()}
    if argv[0] == "tools":
        rows = [
            {"name": s.name, "title": s.title, "readOnly": s.read_only, "description": s.description}
            for s in sorted(specs.values(), key=lambda s: s.name)
        ]
        return _emit({"tools": rows})
    if argv[0] == "schema":
        name = argv[1] if len(argv) > 1 else ""
        if name not in specs:
            return _error(f"unknown tool {name[:100]!r}; run: kn.py tools", 2)
        return _emit(specs[name].model.model_json_schema())
    name = argv[0]
    if name not in specs:
        return _error(f"unknown tool {name[:100]!r}; run: kn.py tools", 2)
    from pydantic import ValidationError

    from kube_noob import tool_runner
    from kube_noob.errors import KubeNoobError
    from kube_noob.knowledge_status import line as knowledge_line

    try:
        args = _arguments(argv[1:])
        result = tool_runner.call(specs[name], args, knowledge_line(kit.settings.data_dir))
    except ValidationError as exc:
        from kube_noob.errors import refused_arguments

        return _error(f"invalid arguments: {refused_arguments(exc)[:2000]}", 2, name)
    except (KubeNoobError, ValueError, KeyError) as exc:
        detail = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        return _error(str(detail)[:2000], 2, name)
    except Exception as exc:  # noqa: BLE001 - JSON out whatever happens, as the MCP server answers an opaque error
        return _error(f"internal error ({type(exc).__name__})", 1, name)
    return _emit(result)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
