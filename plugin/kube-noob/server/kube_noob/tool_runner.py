"""Run one kube-noob tool the way every surface does.

Validate the arguments against the tool's model, call it, stamp ``knowledgeAsOf`` and neutralise text shaped like
instructions to a model (``kube_noob.sanitize``). The MCP server, its REST routes and the Agent Skill runner
(``skill/kube-noob/scripts/kn.py``) all call this, so a tool answers the same everywhere. It imports neither the MCP
SDK nor the HTTP stack, so the skill runs with pydantic, PyYAML and jsonschema only.
"""

from __future__ import annotations

from typing import Any

from kube_noob import limits, sanitize
from kube_noob.toolkit import ToolSpec


def call(spec: ToolSpec, kwargs: dict[str, Any], knowledge: str) -> dict[str, Any]:
    """The tool's result for ``kwargs``. Raises pydantic's ValidationError for bad arguments and the tool's own errors
    (KubeNoobError, ValueError, KeyError) unchanged: each surface turns them into its own error shape."""
    # The arguments came in a request, whoever started this process: `kube-noob serve` is a command-line command,
    # and the command line reads far more from its own files than one request may carry (`kube_noob.limits`).
    with limits.request():
        validated = spec.model.model_validate(kwargs)
        result: dict[str, Any] = spec.fn(validated)
    if isinstance(result, dict):
        # Every answer says how current kube-noob's knowledge is, so the model can tell the user.
        result.setdefault("knowledgeAsOf", knowledge)
        # Text from outside (events, logs, tickets, memory, pages) is data: shapes that try to steer the calling
        # model are neutralised and flagged before the result leaves kube-noob.
        result = sanitize.result(result)
    return result
