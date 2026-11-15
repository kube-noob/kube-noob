"""Red Hat CSAF VEX statements for the products kube-noob covers, as redistributable corpus records (R5.5).

Red Hat publishes one CSAF VEX document per CVE at ``https://security.access.redhat.com/data/csaf/v2/vex/<year>/
<cve>.json`` under CC BY 4.0 ("Security Data", https://access.redhat.com/security/data, checked 2026-10-28), with
``changes.csv`` listing what changed (the CSAF 2.0 directory distribution). For each CVE kube-noob keeps the title,
severity, CVSS base score and, per product in the default set (OpenShift, RHACS, ACM and the layered products, RHEL
8 and 9 that their images build on), each component's status: fixed (with the erratum), known affected (with the
remediation category), known not affected (with the VEX justification flag) or under investigation. Matching a CVE
to an image (VUL1) reads these statements; search reads the summary text.

Every source is checked against the licence allow-list before anything is written: a source whose licence is not on
it stops the build. Fetching is paced (one request a second plus jitter), budgeted, HTTPS to one host only, and
blocked by the offline lock; ``--from-archive`` reads a downloaded archive offline.
"""

from __future__ import annotations

import csv
import io
import json
import random
import re
import subprocess
import tarfile
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from kube_noob.vuln.csaf import (  # noqa: F401 - re-exported: the corpus builder's API
    MAX_DOC,
    MAX_STATEMENTS,
    PRODUCTS,
    SOURCES,
    STATUS,
    AdvisoryError,
    Source,
    parse_vex,
    summary,
)

HOST = "security.access.redhat.com"
HOSTS = frozenset({HOST, "access.redhat.com"})  # Red Hat serves the same security data under both names
BASE = f"https://{HOST}/data/csaf/v2/vex"
MIN_DELAY = 1.0
MAX_CHANGES = 2_000_000  # bytes of changes.csv read
_CVE = re.compile(r"^CVE-(\d{4})-(\d{4,7})\Z")
_PATH = re.compile(r"^(\d{4})/cve-\d{4}-\d{4,7}\.json\Z")


def check_license(source: Source) -> None:
    from kube_noob.sources.db_bundle import LICENSES

    if source.license not in LICENSES:
        raise AdvisoryError(
            f"{source.source_id}: licence {source.license!r} is not on the allow-list ({', '.join(sorted(LICENSES))}); "
            "the build stops rather than ship it"
        )


# ---------------------------------------------------------------------------------------------------------------------
# Fetching


def vex_http(settings: Any) -> httpx.Client:
    """GET-only, HTTPS to the security data host only, through the single outbound choke point."""
    from kube_noob.errors import DomainNotAllowedError
    from kube_noob.net import Purpose, http_client

    client = http_client(settings, Purpose.SOURCES, allow_sources=True, timeout=60)

    def _guard(request: httpx.Request) -> None:
        if request.url.scheme != "https" or request.url.host not in HOSTS or request.method != "GET":
            raise DomainNotAllowedError(
                f"{request.method} {request.url.host} (advisories only read from {', '.join(sorted(HOSTS))})"
            )

    hooks = client.event_hooks
    client.event_hooks = {"request": [*hooks.get("request", []), _guard], "response": hooks.get("response", [])}
    return client


class VexClient:
    def __init__(
        self,
        client: httpx.Client,
        max_requests: int = 3000,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self.http = client
        self.max_requests = max_requests
        self.requests = 0
        self.sleep = sleep
        self.rng = rng or random.Random()  # noqa: S311 - jitter, not crypto

    def _get(self, path: str, limit: int) -> bytes | None:
        if self.requests >= self.max_requests:
            raise AdvisoryError(f"request budget of {self.max_requests} spent")
        if self.requests:
            self.sleep(MIN_DELAY + self.rng.random())
        for attempt in range(5):
            self.requests += 1
            try:
                with self.http.stream("GET", f"{BASE}/{path}") as resp:
                    if resp.status_code == 404:
                        return None
                    if resp.status_code in {429, 502, 503, 504} and attempt < 4:
                        wait = resp.headers.get("Retry-After", "")
                        self.sleep(min(float(wait), 300.0) if wait.isdigit() else 2.0**attempt * 5)
                        continue
                    if resp.status_code != 200:
                        raise AdvisoryError(f"GET {path}: HTTP {resp.status_code}")
                    body = bytearray()
                    for chunk in resp.iter_bytes():
                        body += chunk
                        if len(body) > limit:
                            raise AdvisoryError(f"GET {path}: larger than {limit} bytes")
                    return bytes(body)
            except httpx.TransportError as exc:
                if attempt == 4:
                    raise AdvisoryError(f"GET {path}: {exc}") from exc
                self.sleep(2.0**attempt * 5)
        raise AdvisoryError(f"GET {path}: still refused after retries")

    def document(self, cve: str) -> Any | None:
        m = _CVE.match(cve)
        if not m:
            raise AdvisoryError(f"not a CVE id: {cve!r}")
        body = self._get(f"{m.group(1)}/{cve.lower()}.json", MAX_DOC)
        if body is None:
            return None
        try:
            return json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise AdvisoryError(f"{cve}: the VEX document is not JSON ({body[:60]!r}...)") from exc

    def changed_since(self, since: str) -> list[str]:
        """CVE ids whose VEX changed after ``since`` (ISO 8601), newest first, from changes.csv."""
        body = self._get("changes.csv", MAX_CHANGES * 50)
        return changed_cves(body.decode("utf-8", errors="replace") if body else "", since)


def changed_cves(text: str, since: str) -> list[str]:
    out: list[str] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2 or not _PATH.match(row[0].strip()):
            continue
        if row[1].strip() > since:
            cve = Path(row[0].strip()).stem.upper()
            if cve not in out:
                out.append(cve)
    return out


def from_archive(path: Path) -> Iterator[Any]:
    """Every VEX document in a downloaded archive: a folder of ``<year>/<cve>.json``, a ``.tar`` or ``.tar.gz``, or
    a ``.tar.zst`` (read through the ``zstd`` program)."""
    if path.is_dir():
        for f in sorted(path.rglob("cve-*.json")):
            if f.stat().st_size <= MAX_DOC:
                yield json.loads(f.read_bytes())
        return
    if path.name.endswith(".zst"):
        import tempfile

        # The child's stderr is captured, not inherited: what it says reaches the terminal through kube-noob's own
        # error message and its output boundary, never straight from the child (G279). A file, not a pipe, so a
        # chatty child cannot fill a pipe nobody reads and stall.
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(["zstd", "-dc", "--", str(path)], stdout=subprocess.PIPE, stderr=err)  # noqa: S607
            if proc.stdout is None:  # pragma: no cover
                raise AdvisoryError("zstd produced no output")
            try:
                with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
                    yield from _members(tf)
            except tarfile.TarError:
                pass  # the exit status and stderr below say why
            finally:
                proc.stdout.close()
                status = proc.wait()
            if status != 0:
                err.seek(0)
                said = err.read(2000).decode("utf-8", "replace").strip()
                raise AdvisoryError(f"zstd could not read {path.name}" + (f": {said}" if said else ""))
        return
    with tarfile.open(path, "r:*") as tf:
        yield from _members(tf)


def _members(tf: tarfile.TarFile) -> Iterator[Any]:
    for m in tf:
        if not m.isfile() or not m.name.endswith(".json") or "cve-" not in m.name or m.size > MAX_DOC:
            continue
        fh = tf.extractfile(m)
        if fh is not None:
            try:
                yield json.loads(fh.read())
            except (ValueError, RecursionError):
                continue


def run(
    data_dir: Path,
    docs: Iterable[Any],
    products: Iterable[str] = PRODUCTS,
    now: datetime | None = None,
    replace: bool = False,
) -> dict[str, Any]:
    """Parse ``docs`` and merge their records into the ``redhat-vex`` shard (``replace`` starts it over)."""
    from kube_noob.sources.corpus import read_manifest, shard_paths, write_shard

    source = SOURCES["redhat-vex"]
    check_license(source)
    stamp = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    current: dict[str, dict[str, Any]] = {}
    if not replace and "redhat-vex" in (read_manifest(data_dir).get("shards") or {}):
        for path in shard_paths(data_dir, "redhat-vex"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    current[rec["cve"]] = rec
    seen = kept = bad = 0
    for doc in docs:
        seen += 1
        try:
            rec = parse_vex(doc, products, stamp)
        except (AdvisoryError, KeyError, TypeError, AttributeError):
            bad += 1
            continue
        if rec is not None:
            current[rec["cve"]] = rec
            kept += 1
    records = [current[k] for k in sorted(current)]
    if records:
        write_shard(data_dir, "redhat-vex", records)
    return {
        "source": source.source_id,
        "license": source.license,
        "documents": seen,
        "kept": kept,
        "malformed": bad,
        "cves": len(records),
        "retrievedAt": stamp,
    }
