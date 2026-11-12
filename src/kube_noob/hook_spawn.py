"""The pre-action hook's check in a fresh interpreter, for systems with no fork (G280).

``kube_noob.hook`` runs the check in a child process so it can be killed at the budget; on POSIX it forks, and where
there is no fork it starts this interpreter again on the same code. Kept apart from ``kube_noob.hook`` so the Claude
plugin, which starts no program, ships no subprocess call (``scripts/sync_plugin_server.py`` leaves this out).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_CHILD = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from kube_noob import hook, sanitize\n"
    "doc = sanitize.loads_bounded(sys.stdin.buffer.read())\n"
    "opts = hook.Options(**doc['options']) if doc['options'] else None\n"
    "sys.stdout.write(json.dumps(hook.run(doc['raw'].encode('latin-1'), doc['env'], options=opts)))\n"
)


def run_spawned(raw: bytes, env: dict[str, str], options: dict[str, Any] | None, limit: float) -> bytes | None:
    """The child's JSON answer, b"" when it failed, or None when it was killed at ``limit`` seconds."""
    package_parent = str(Path(__file__).resolve().parent.parent)
    request = json.dumps({"raw": raw.decode("latin-1"), "env": env, "options": options}).encode()
    proc = subprocess.Popen(  # this interpreter, a fixed program, no shell
        [sys.executable, "-I", "-B", "-c", _CHILD, package_parent], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    try:
        stdout, _ = proc.communicate(request, timeout=limit)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None
    return stdout if proc.returncode == 0 else b""
