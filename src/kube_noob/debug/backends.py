"""Backends that reach a live cluster, read-only, once cluster access is enabled.

  * ``KubectlBackend`` - shells out to ``kubectl``/``oc`` (argv list, never a shell) using the operator's kubeconfig.
  * ``InClusterBackend`` - talks to the API server with the pod's ServiceAccount token (sidecar mode).

Both use the allowlist, argument validation and redaction in ``kube_noob.debug.cluster``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx

from kube_noob.config import Settings
from kube_noob.debug.cluster import (
    _CONTAINER,
    _FIELD_SELECTOR,
    _NAME,
    _SELECTOR,
    Backend,
    BackendReadError,
    _check,
    _list_hint,
    _redact_obj,
    redact_text,
    resolve_resource,
)
from kube_noob.errors import ClusterAccessError
from kube_noob.net import USER_AGENT

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class InClusterReadError(BackendReadError):
    """An HTTP error from the API server, with the status it sent: the classifier decides from the status and the
    body, never from a path that echoes a namespace or a name (G279)."""

    def __init__(self, path: str, *, status: int, body: str = "") -> None:
        if status == 403:
            shown = (
                f"Forbidden by RBAC: GET {path}. Grant the sidecar's ServiceAccount read access "
                "(see deploy/helm values rbac.*)."
            )
        elif status == 404:
            shown = f"Not found: GET {path}"
        else:
            shown = f"API error {status} for GET {path}: {body[:300]}"
        super().__init__(shown, status=status, body=body)


# The lines kubectl and oc write for their own failure (kubectl/pkg/cmd/util/helpers.go v1.35.0: checkErr's
# "error: ", StandardErrorMessage's "Error from server" and "Unable to connect to the server").
_ERROR_LINES = ("error: ", "Error from server", "Unable to connect to the server")
_KLOG_PREFIX = re.compile(r"^[EWI]\d{4} [\d:.]+\s+\d+ [\w.]+:\d+\] ")


def _stderr_for_message(stderr: str) -> str:
    """kubectl's own error line first, then each distinct warning once. kubectl logs one memcache warning per
    aggregated API it could not discover, several times over, BEFORE its error; the message keeps 800 characters,
    so on a cluster whose metrics API was down the line that said what failed was the part cut off (G279)."""
    lines = [ln.strip() for ln in stderr.strip().splitlines() if ln.strip()]
    first = [ln for ln in lines if ln.startswith(_ERROR_LINES)]
    rest: list[str] = []
    seen: set[str] = set()
    for ln in lines:
        if ln.startswith(_ERROR_LINES):
            continue
        key = _KLOG_PREFIX.sub("", ln)
        if key not in seen:
            seen.add(key)
            rest.append(key)
    return "\n".join(first + rest)


def cluster_client(base_url: str, token: str, ca_file: str, timeout: float) -> httpx.Client:
    """Client for the in-cluster Kubernetes API (sidecar mode). Not web access: it only talks to the API server
    the pod runs against, verifies it with the ServiceAccount CA, never follows redirects and ignores proxy env."""
    return httpx.Client(
        base_url=base_url,
        timeout=timeout,
        verify=ca_file,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": USER_AGENT, "Authorization": f"Bearer {token}", "Accept": "application/json"},
    )


class KubectlBackend:
    def __init__(self, binary: str, context: str | None, timeout: float) -> None:
        path = shutil.which(binary)
        if path is None:
            raise ClusterAccessError(f"'{binary}' not found on PATH. Install it or set cluster.backend.")
        self.binary = path
        self.name = binary
        self.context = context
        self.timeout = timeout
        if context is not None:
            _check(context, re.compile(r"^[A-Za-z0-9._:/@-]{1,253}$"), "context")

    def _run(self, args: list[str]) -> str:
        argv = [self.binary, *args, "--request-timeout", f"{int(self.timeout)}s"]
        if self.context:
            argv += ["--context", self.context]
        try:
            # bytes, decoded with replacement: a byte that is not UTF-8 on either stream is part of a failed or odd
            # answer, not a UnicodeDecodeError that escapes every caller (G279)
            proc = subprocess.run(
                argv, capture_output=True, timeout=self.timeout + 5, check=False, stdin=subprocess.DEVNULL
            )
        except subprocess.TimeoutExpired as exc:
            raise ClusterAccessError(f"{self.name} timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace")
            # The shown message is cut at 800 characters; the classifier reads the whole stderr (redacted), so a
            # discovery warning about this resource's own group that comes after seven others still counts.
            raise BackendReadError(
                f"{self.name} {' '.join(args[:3])} failed: {redact_text(_stderr_for_message(stderr))[:800]}",
                stderr=redact_text(stderr),
            )
        try:
            return proc.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:  # an answer that is not UTF-8 is not an answer kube-noob can read
            raise BackendReadError(f"{self.name} {' '.join(args[:3])}: the answer was not UTF-8") from exc

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]:
        plural, rdef = resolve_resource(resource)
        _check(name, _NAME, "name")
        _check(namespace, _NAME, "namespace")
        _check(selector, _SELECTOR, "label selector")
        _check(field_selector, _FIELD_SELECTOR, "field selector")
        group = rdef.group_version.split("/")[0] if "/" in rdef.group_version else ""
        args = ["get", f"{plural}.{group}" if group else plural]
        if name:
            args.append(name)
        if rdef.namespaced:
            args += ["--namespace", namespace] if namespace else ["--all-namespaces"]
        if selector:
            args += ["--selector", selector]
        if field_selector:
            args += ["--field-selector", field_selector]
        args += ["--output", "json"]
        out = self._run(args)
        try:
            data = json.loads(out or "{}")
        except ValueError as exc:
            raise BackendReadError(
                f"{self.name} get {args[1]}: the answer was not JSON ({redact_text(out.strip()[:120])!r})"
            ) from exc
        return _redact_obj(data, _list_hint(data, plural))  # type: ignore[no-any-return]

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str:
        _check(namespace, _NAME, "namespace")
        _check(pod, _NAME, "pod")
        _check(container, _CONTAINER, "container")
        args = ["logs", pod, "--namespace", namespace, f"--tail={int(tail)}"]
        if container:
            args += ["--container", container]
        if previous:
            args.append("--previous")
        return redact_text(self._run(args))

    def version(self) -> dict[str, Any]:
        return json.loads(self._run(["version", "--output", "json"]))  # type: ignore[no-any-return]


class InClusterBackend:
    name = "in-cluster"

    def __init__(self, timeout: float) -> None:
        host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        token_file, ca_file = SA_DIR / "token", SA_DIR / "ca.crt"
        if not host or not token_file.is_file() or not ca_file.is_file():
            raise ClusterAccessError(
                "Not running in a pod with a mounted ServiceAccount token; use backend "
                "'kubectl' or 'oc' outside the cluster."
            )
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        self.timeout = timeout
        self._base = f"https://{host}:{port}"
        self._token_file = token_file
        self._ca = str(ca_file)

    def _get(self, path: str, params: dict[str, Any] | None = None, as_text: bool = False) -> Any:
        token = self._token_file.read_text(encoding="utf-8").strip()  # re-read: projected tokens rotate
        with cluster_client(self._base, token, self._ca, self.timeout) as c:
            resp = c.get(path, params=params)
        if resp.status_code >= 400:
            raise InClusterReadError(path, status=resp.status_code, body=redact_text(resp.text[:4000]))
        if as_text:
            return resp.text
        try:
            return resp.json()
        except ValueError as exc:
            raise BackendReadError(f"GET {path}: the answer was not JSON") from exc

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]:
        plural, rdef = resolve_resource(resource)
        _check(name, _NAME, "name")
        _check(namespace, _NAME, "namespace")
        _check(selector, _SELECTOR, "label selector")
        _check(field_selector, _FIELD_SELECTOR, "field selector")
        params: dict[str, Any] = {}
        if selector:
            params["labelSelector"] = selector
        if field_selector:
            params["fieldSelector"] = field_selector
        data = self._get(rdef.path(namespace, name), params)
        return _redact_obj(data, _list_hint(data, plural))  # type: ignore[no-any-return]

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str:
        _check(namespace, _NAME, "namespace")
        _check(pod, _NAME, "pod")
        _check(container, _CONTAINER, "container")
        params: dict[str, Any] = {"tailLines": int(tail), "previous": str(previous).lower()}
        if container:
            params["container"] = container
        return redact_text(self._get(f"/api/v1/namespaces/{namespace}/pods/{pod}/log", params, as_text=True))

    def version(self) -> dict[str, Any]:
        return {"serverVersion": self._get("/version")}


def select_backend(settings: Settings) -> Backend:
    """Pick the backend for enabled cluster access (``get_backend`` checks that it is enabled)."""
    b = settings.cluster.backend
    t = settings.cluster.timeout_seconds
    if b == "in-cluster" or (
        b == "auto" and (SA_DIR / "token").is_file() and os.environ.get("KUBERNETES_SERVICE_HOST")
    ):
        return InClusterBackend(t)
    if b in {"kubectl", "oc"}:
        return KubectlBackend(b, settings.cluster.context, t)
    for candidate in ("oc", "kubectl"):
        if shutil.which(candidate):
            return KubectlBackend(candidate, settings.cluster.context, t)
    raise ClusterAccessError("No cluster backend available: not in a pod and neither `oc` nor `kubectl` is on PATH.")
