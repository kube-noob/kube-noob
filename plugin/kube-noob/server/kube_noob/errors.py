"""Exception hierarchy. Every error carries an actionable message for humans and agents."""

from __future__ import annotations


class KubeNoobError(Exception):
    """Base class for all kube-noob errors."""


class ConfigError(KubeNoobError):
    """Invalid or contradictory configuration."""


class WebDisabledError(KubeNoobError):
    """Raised when code attempts outbound web access while it is disabled or locked."""

    def __init__(self, purpose: str, reason: str | None = None) -> None:
        super().__init__(
            reason
            or (
                f"Outbound web access for '{purpose}' is disabled (webEnabled: false). "
                "kube-noob answers from its local knowledge base by default. To allow web access set "
                "`webEnabled: true` in your config or export KUBE_NOOB_WEB_ENABLED=true."
            )
        )
        self.purpose = purpose


class WebContentRejectedError(KubeNoobError):
    """Raised when a web response is not readable text (archives, binaries, scripts are never fetched)."""


class DomainNotAllowedError(KubeNoobError):
    """Raised when a web request targets a host outside the configured allowlist."""

    def __init__(self, host: str) -> None:
        super().__init__(
            f"Host '{host}' is not in web.allowedDomains. Add it to the allowlist in kube-noob.yaml "
            "if it is a trusted documentation source."
        )
        self.host = host


class ManifestError(KubeNoobError):
    """Input manifests could not be parsed safely."""


class ClusterAccessError(KubeNoobError):
    """Live cluster access is disabled, unavailable, or the request was refused by the guard."""


class ClarificationNeeded(KubeNoobError):
    """The request is missing parameters that would make the output unsafe or wrong."""

    def __init__(self, questions: list[str]) -> None:
        super().__init__("Clarification needed: " + " | ".join(questions))
        self.questions = questions


class ProviderError(KubeNoobError):
    """The configured LLM provider is unavailable or misconfigured."""


class TierDisabledError(KubeNoobError):
    """A capability tier beyond read-only is off; the message names the switch that turns it on."""


class ApprovalError(KubeNoobError):
    """A change was attempted without a valid approval: missing, for another action or tier, expired or reused."""


class StoredStateError(KubeNoobError):
    """kube-noob's own stored state (a file in its data directory) is missing, damaged or unusable. Not the caller's
    input: the HTTP routes answer 500 with this message rather than 400."""


class ServerBusy(KubeNoobError):
    """The server is already doing as much of this work as it allows at once, and waiting for a turn took longer than
    its bound. Nothing about the request is wrong: retry later. The REST routes answer 503 with ``Retry-After``."""
