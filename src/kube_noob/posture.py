"""Security posture report: what kube-noob can reach with the effective configuration.

Used by ``kube-noob doctor`` and the ``config_status`` tool so an operator can prove the boundary instead of trusting
the defaults. A *conflict* means the configuration asks for something the offline lock forbids; the lock still wins,
but the operator should fix the configuration so intent and behaviour match.
"""

from __future__ import annotations

from typing import Any

from kube_noob.config import Settings, is_local_url


def _model_posture(provider: str, base_url: str | None) -> dict[str, Any]:
    if provider == "none":
        return {"provider": "none", "endpoint": None, "local": True}
    if provider == "anthropic":
        return {"provider": provider, "endpoint": base_url or "https://api.anthropic.com", "local": False}
    return {"provider": provider, "endpoint": base_url, "local": is_local_url(base_url)}


def crypto_posture() -> dict[str, Any]:
    """What `doctor` can observe about FIPS 140 (SC-13), and nothing it cannot.

    Three reads: the kernel flag ``/proc/sys/crypto/fips_enabled`` (``1`` is on; unreadable is None), OpenSSL's own
    FIPS mode as the ``_hashlib`` module linked against it reports it (``_hashlib.get_fips_mode()``), and the
    OpenSSL version string Python was built against (``ssl.OPENSSL_VERSION``); plus which SHA-256 this process
    runs (OpenSSL's through ``_hashlib``, or CPython's own ``_sha2``). The primitives the code calls are listed in
    ``algorithms``. Whether any of these modules is CMVP-validated: that is a property of the module, its version
    and its operating environment, which the operator evidences with the module name, version and certificate.
    This function makes no such claim, and ``fipsMode`` is the flags' reading, not a validation status (G292).
    """
    import hashlib
    import ssl

    kernel: bool | None = None
    kernel_note = ""
    try:
        from kube_noob.host_fips import kernel_fips
    except ImportError:  # the Claude plugin reads nothing from the machine: OpenSSL's own mode is still reported
        kernel_note = "not read by the Claude plugin; run kube-noob doctor for the kernel flag"
    else:
        kernel = kernel_fips()
    openssl: bool | None = None
    try:
        import _hashlib

        openssl = bool(_hashlib.get_fips_mode())
    except (ImportError, AttributeError, ValueError):
        openssl = None
    if openssl or (kernel and openssl is None):
        mode = "on"
    elif kernel is None and openssl is None:
        mode = "unknown"
    else:
        mode = "off"
    return {
        "fipsMode": mode,
        "kernelFipsEnabled": kernel,
        "opensslFipsMode": openssl,
        "openssl": ssl.OPENSSL_VERSION,
        "sha256Backend": (
            "OpenSSL (_hashlib)" if type(hashlib.sha256()).__module__ == "_hashlib" else "CPython built-in (_sha2)"
        ),
        "algorithms": (
            "SHA-256 (integrity, ids) and PBKDF2-HMAC-SHA256 (sealed Jira snapshot key) through hashlib; "
            "HMAC constant-time compare of the HTTP bearer token; TLS through Python's ssl module; AES-256-GCM "
            "for sealing a Jira snapshot through the cryptography package, whose wheel carries its own OpenSSL "
            "build; no MD5, SHA-1 or custom crypto"
        ),
        **({"kernelFipsNote": kernel_note} if kernel_note else {}),
    }


def posture(s: Settings) -> dict[str, Any]:
    from kube_noob import __version__
    from kube_noob.toolkit import READABLE_CONTENT_TYPES

    conflicts: list[str] = []
    warnings: list[str] = []
    if s.web_locked:
        conflicts.append(
            "webEnabled is true (config file, environment or --web-enabled) but the offline lock is on; web access "
            "stays off. Remove webEnabled or the lock so the configuration states what actually happens."
        )

    if s.web_enabled:
        web: dict[str, Any] = {
            "web": "on",
            "allowedDomains": s.web.allowed_domains,
            "methods": ["GET"],
            "schemes": ["https"],
            "contentTypes": sorted(READABLE_CONTENT_TYPES),
            "maxBytes": s.web.max_bytes,
            "writesToDisk": False,
            "executesContent": False,
        }
    else:
        web = {"web": "locked-off" if s.offline else "off"}
    web["corpusDownloads"] = "blocked" if s.offline else "only with --online or webEnabled"

    model = _model_posture(s.llm.provider, s.llm.base_url)
    model["usedBy"] = "kube-noob ask / train bench only; the MCP server never calls a model"
    if s.offline and not model["local"]:
        model["allowedByLock"] = False
        warnings.append(
            f"llm.provider {s.llm.provider!r} is not local, so `kube-noob ask` refuses under the offline lock. Set "
            "llm.provider: none, or openai-compatible with a loopback or *.svc llm.baseUrl."
        )
    judge = _model_posture(s.judge.provider, s.judge.base_url)
    if s.offline and not judge["local"]:
        warnings.append(f"judge.provider {s.judge.provider!r} is not local and will refuse under the offline lock.")

    from kube_noob import tiers

    conflicts += tiers.conflicts(s)
    learning = s.data_dir / "learning.json"
    memory = memory_posture(s)
    warnings += [f"memory path {m['path']}: {m['error']}" for m in memory if m.get("error")]
    return {
        "version": __version__,
        "configFile": str(s.source_path) if s.source_path else None,
        "offlineLock": s.offline,
        "network": web,
        "cluster": {
            "enabled": s.cluster.enabled,
            "access": "read-only get/logs/events with the current identity; Secrets refused; values redacted"
            if s.cluster.enabled
            else "none",
            "backend": s.cluster.backend if s.cluster.enabled else None,
        },
        "tiers": tiers.describe(s),
        "model": model,
        "judge": judge,
        "dataDir": {"path": str(s.data_dir), "exists": s.data_dir.is_dir(), "learningFile": str(learning)},
        "memory": memory,
        "telemetry": "none",
        "crypto": crypto_posture(),
        "conflicts": conflicts,
        "warnings": warnings,
        "status": "conflict" if conflicts else "ok",
    }


def memory_posture(s: Settings) -> list[dict[str, Any]]:
    """Each configured memory repository: entry counts, or why it cannot be read. Read-only."""
    from kube_noob.memory.repo import load_repo

    out: list[dict[str, Any]] = []
    for path in s.memory.paths:
        row: dict[str, Any] = {"path": str(path)}
        try:
            loaded = load_repo(path)
        except (OSError, ValueError) as exc:
            row["error"] = str(exc)
        else:
            entries = [x.entry for x in loaded if x.entry is not None]
            row.update(
                entries=len(loaded),
                approved=sum(1 for e in entries if e.status == "approved"),
                proposed=sum(1 for e in entries if e.status == "proposed"),
                unreadable=len(loaded) - len(entries),
            )
        out.append(row)
    return out


def render_text(p: dict[str, Any]) -> str:
    net = p["network"]
    lines = [
        f"kube-noob {p['version']} posture: {p['status'].upper()}",
        f"  offline lock   {'ON' if p['offlineLock'] else 'off'}",
        f"  web            {net['web']}"
        + (f" (GET-only HTTPS to {', '.join(net['allowedDomains'])})" if net["web"] == "on" else ""),
        f"  corpus         {net['corpusDownloads']}",
        f"  cluster        {'read-only' if p['cluster']['enabled'] else 'none'}",
        f"  agent model    {p['model']['provider']}"
        + (f" -> {p['model']['endpoint']}" if p["model"]["endpoint"] else "")
        + (" (local)" if p["model"]["local"] else " (remote)"),
        *(
            f"  tier {t['tier']}         {'ON ' if t['enabled'] else 'off'} {t['name']} ({t['switch']})"
            + (f"; needs {t['rbac']}" if t["enabled"] else "")
            for t in p.get("tiers", [])
        ),
        f"  data dir       {p['dataDir']['path']}",
        *(
            f"  memory         {m['path']}: "
            + (
                f"{m['entries']} entries ({m['approved']} approved, {m['proposed']} proposed)"
                if "error" not in m
                else "unreadable"
            )
            for m in p.get("memory", [])
        ),
        *(["  memory         none (memory.paths)"] if not p.get("memory") else []),
        f"  telemetry      {p['telemetry']}",
        f"  FIPS mode      {p['crypto']['fipsMode']} ({p['crypto']['openssl']})",
        f"  sha256 backend {p['crypto']['sha256Backend']}",
        f"  config file    {p['configFile'] or 'none (defaults + environment)'}",
    ]
    lines += [f"CONFLICT: {c}" for c in p["conflicts"]]
    lines += [f"warning: {w}" for w in p["warnings"]]
    return "\n".join(lines)
