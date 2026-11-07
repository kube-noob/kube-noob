"""kube-noob: Kubernetes / Helm / OpenShift / ROSA HCP / StackRox expertise as deterministic tools for learning,
manifest audit and debugging. There is no AI inside: Claude, OpenShift Lightspeed or any MCP client calls the tools,
and the CLI runs them with no model at all. Only the optional ``kube-noob ask`` agent calls a model you configure.

The package is usable as:
  * an MCP server (``kube-noob mcp`` over stdio, ``kube-noob serve`` over streamable HTTP),
  * a CLI (``kube-noob audit|generate|diagnose|learn|ask ...``),
  * an OpenShift sidecar / standalone service (see ``deploy/``).

Web access is disabled by default (``webEnabled: false``); every answer is grounded in the
local knowledge base and corpus unless the operator explicitly opts in.
"""

__version__ = "0.9.1"

__all__ = ["__version__"]
