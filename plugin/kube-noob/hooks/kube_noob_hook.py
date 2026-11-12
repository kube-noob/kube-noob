"""The kube-noob plugin's PreToolUse hook, run by hooks/hooks.json with ``uv run --frozen --isolated``.

It loads the readable server copy in ``../server/kube_noob`` (the same code the MCP server runs) and calls
``kube_noob.hook.plugin_main``: it does nothing until the user turns on the plugin's ``verify_cluster_commands``
option, and then runs ``kube-noob verify`` before a Bash command that changes cluster state and blocks it (exit 2)
unless the answer is allow. It never runs the command, never reads outside the working directory the hook input
names, makes no network call and reads no credential.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent / "server"


def main() -> int:
    # Off unless the user opted in; checked before anything is imported, so a plugin that is installed and not
    # opted in never blocks a command, whatever state its bundled code is in. kube_noob.hook.plugin_main checks it
    # again with the same rule.
    if os.environ.get("CLAUDE_PLUGIN_OPTION_VERIFY_CLUSTER_COMMANDS", "").strip().lower() not in {
        "true",
        "1",
        "yes",
        "on",
    }:
        return 0
    if str(SERVER) not in sys.path[:1]:
        sys.path.insert(0, str(SERVER))
    try:
        import kube_noob
        from kube_noob.hook import plugin_main
    except Exception as exc:  # noqa: BLE001 - a hook that cannot load blocks rather than passes
        sys.stderr.write(f"kube-noob hook: could not load the bundled code ({type(exc).__name__}); blocked.\n")
        return 2
    if Path(kube_noob.__file__).resolve().parent != SERVER / "kube_noob":
        sys.stderr.write(f"kube-noob hook: expected the bundled code in {SERVER / 'kube_noob'}; blocked.\n")
        return 2
    return plugin_main()


if __name__ == "__main__":
    raise SystemExit(main())
