"""Stored alert evidence reports: what ``POST /v1/alert-reports`` keeps, and ``GET /v1/alert-reports[/<id>]`` reads.

The HTTP server writes here and nothing else does: no MCP tool, no CLI command and not the stdio server. It is
kube-noob's own state in its own data directory, like the daily drift snapshots in ``<dataDir>/posture``, and never a
write to a cluster or to any other system.

How it stays safe and bounded:

* **Owner-only, atomic, never through a link.** ``<dataDir>/alert-reports`` is opened with ``O_NOFOLLOW`` and must be
  a directory this process owns (it is set to 0700); every file is created with ``O_EXCL | O_NOFOLLOW`` and mode
  0600 relative to that directory's descriptor and renamed into place, so a link planted at any name is replaced,
  never followed, and a reader never sees half a report.
* **Bounded retention.** After each write the newest ``maxReports`` are kept and any older than ``maxAgeDays`` are
  removed, oldest first; the number removed is returned and counted on ``/metrics``. A body is bounded by
  ``maxReportBytes`` before it is written (``kube_noob.alert_report``).
* **Unguessable, validated ids.** ``<UTC time>-<96 random bits>``; an id read back is checked against ``ID`` (``\\Z``,
  no separator) before it is used as a file name, so ``../`` or an encoded slash never reaches the file system.
* **Read back as untrusted.** Files are read with ``O_NOFOLLOW``, only when regular and under the size cap, parsed
  depth-bounded, and returned through the tool path, which cleans them again (``kube_noob.sanitize``).
* **Nothing about the caller.** A stored report holds the body and the receipt (id, times, duration, whether and why
  it was stored). No request header, no address and no credential is passed to this module at all.

If storing is off or fails (the directory is a link, not owned, unwritable or full), the POST still answers with the
report, ``stored: false`` and the reason: a report is never lost silently.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import errno
import hashlib
import json
import logging
import os
import re
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kube_noob.config import AlertReportSettings
from kube_noob.errors import KubeNoobError
from kube_noob.sanitize import MAX_JSON_DEPTH_FILE, loads_bounded

DIRNAME = "alert-reports"
RECORD_FORMAT = "kube-noob/alert-report-record/v1"
ID = re.compile(r"^(\d{8}T\d{6}\.\d{6}Z)-([0-9a-f]{24})\Z")
_REPORT = re.compile(r"^(\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{24})\.json\Z")
_SUMMARY = re.compile(r"^(\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{24})\.summary\.json\Z")
_TEMP = re.compile(r"^\.[0-9A-Za-z-]{1,80}\.tmp\Z")
MAX_SUMMARY_BYTES = 16_384
MAX_LIST = 200
SUMMARY_NAMES = 20
STALE_TEMP_SECONDS = 3600
_log = logging.getLogger("kube_noob.alert_store")


class StoreUnavailable(KubeNoobError):
    """Storing or reading is not possible here; the message says why and is safe to show the caller."""


def new_id(now: dt.datetime) -> str:
    return f"{now.astimezone(dt.UTC).strftime('%Y%m%dT%H%M%S.%fZ')}-{os.urandom(12).hex()}"


def valid_id(value: str) -> bool:
    return isinstance(value, str) and ID.match(value) is not None


def body_sha256(body: dict[str, Any]) -> str:
    from kube_noob.alert_report import canonical

    return hashlib.sha256(canonical(body)).hexdigest()


def _iso(when: dt.datetime) -> str:
    return when.astimezone(dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _id_time(report_id: str) -> dt.datetime | None:
    m = ID.match(report_id)
    if m is None:
        return None
    try:
        return dt.datetime.strptime(m.group(1), "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def _supported() -> bool:
    # os.replace takes the same directory descriptors as os.rename (renameat) but only rename is listed.
    return (
        {os.open, os.rename, os.unlink, os.stat} <= os.supports_dir_fd
        and os.listdir in os.supports_fd
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
    )


class AlertReportStore:
    """The directory of stored reports. Safe to share between request threads (one lock around each write)."""

    def __init__(self, data_dir: Path, settings: AlertReportSettings) -> None:
        self.root = Path(data_dir) / DIRNAME
        self.settings = settings
        self._lock = threading.Lock()

    # -- the directory -----------------------------------------------------------------------------------------
    def _open_dir(self, create: bool) -> int:
        if not _supported():
            raise StoreUnavailable("this platform cannot write a file without following links, so nothing is kept")
        if create:
            try:
                self.root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.mkdir(self.root, 0o700)
            except FileExistsError:
                pass
            except OSError as exc:
                raise StoreUnavailable(f"the data directory could not be written ({_why(exc)})") from None
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise StoreUnavailable("no report has been stored here") from None
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise StoreUnavailable(f"{DIRNAME} in the data directory is not a plain directory") from None
            raise StoreUnavailable(f"{DIRNAME} could not be opened ({_why(exc)})") from None
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            os.close(fd)
            raise StoreUnavailable(f"{DIRNAME} in the data directory belongs to another user")
        if stat.S_IMODE(st.st_mode) & 0o077:
            try:
                os.fchmod(fd, 0o700)
            except OSError as exc:
                os.close(fd)
                raise StoreUnavailable(f"{DIRNAME} could not be made owner-only ({_why(exc)})") from None
        return fd

    # -- writing -------------------------------------------------------------------------------------------------
    def _write(self, dfd: int, name: str, data: bytes) -> None:
        tmp = f".{name.removesuffix('.json')}-{os.urandom(4).hex()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=dfd)
            raise

    def save(self, record: dict[str, Any], now: dt.datetime) -> int:
        """Write one record and apply retention. Returns how many reports retention removed. Raises
        StoreUnavailable with the reason when the record cannot be kept."""
        report_id = str(record.get("id", ""))
        if not valid_id(report_id):
            raise StoreUnavailable("the report has no valid id")
        data = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(data) > self.settings.max_report_bytes + MAX_SUMMARY_BYTES:
            raise StoreUnavailable("the report is larger than alertReports.maxReportBytes allows")
        summary = json.dumps(_summary(record), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            dfd = self._open_dir(create=True)
            try:
                try:
                    self._write(dfd, f"{report_id}.json", data)
                    self._write(dfd, f"{report_id}.summary.json", summary.encode("utf-8")[:MAX_SUMMARY_BYTES])
                except OSError as exc:
                    # Both files or neither: a report the POST says was not stored must not be listed later.
                    for name in (f"{report_id}.json", f"{report_id}.summary.json"):
                        with contextlib.suppress(OSError):
                            os.unlink(name, dir_fd=dfd)
                    raise StoreUnavailable(f"the report could not be written ({_why(exc)})") from None
                return self._retain(dfd, now)
            finally:
                os.close(dfd)

    def _retain(self, dfd: int, now: dt.datetime) -> int:
        ids: set[str] = set()
        for name in os.listdir(dfd):
            m = _REPORT.match(name) or _SUMMARY.match(name)
            if m:
                ids.add(m.group(1))
            elif _TEMP.match(name):
                # A temporary file older than an hour is what a killed write leaves behind.
                with contextlib.suppress(OSError):
                    st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                    if time.time() - st.st_mtime > STALE_TEMP_SECONDS:
                        os.unlink(name, dir_fd=dfd)
        oldest_kept = now - dt.timedelta(days=self.settings.max_age_days)
        ordered = sorted(ids)  # the id starts with its UTC time, so name order is age order
        doomed = set(ordered[: max(0, len(ordered) - self.settings.max_reports)])
        doomed |= {i for i in ordered if (_id_time(i) or now) < oldest_kept}
        for report_id in sorted(doomed):
            for name in (f"{report_id}.json", f"{report_id}.summary.json"):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=dfd)
        return len(doomed)

    # -- reading -------------------------------------------------------------------------------------------------
    def _read(self, dfd: int, name: str, cap: int) -> Any:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        except FileNotFoundError:
            raise KeyError(name) from None
        except OSError as exc:
            raise StoreUnavailable(f"a stored report could not be opened ({_why(exc)})") from None
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
                raise StoreUnavailable("a stored file is not a regular file under the size limit; it was not read")
            raw = fh.read(cap + 1)
        try:
            return loads_bounded(raw.decode("utf-8"), MAX_JSON_DEPTH_FILE)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise StoreUnavailable("a stored file is not JSON; it was not read") from None

    def get(self, report_id: str) -> dict[str, Any]:
        """One stored record. KeyError when there is none with that id (or the id is not an id at all)."""
        if not valid_id(report_id):
            raise KeyError(f"no alert report {report_id[:80]!r}")
        try:
            dfd = self._open_dir(create=False)
        except StoreUnavailable:
            raise KeyError(f"no alert report {report_id}") from None
        try:
            data = self._read(dfd, f"{report_id}.json", self.settings.max_report_bytes + MAX_SUMMARY_BYTES)
        except KeyError:
            raise KeyError(f"no alert report {report_id}") from None
        finally:
            os.close(dfd)
        if not isinstance(data, dict) or data.get("format") != RECORD_FORMAT or data.get("id") != report_id:
            raise StoreUnavailable(f"the stored file for {report_id} is not an alert report; it was not returned")
        return data

    def newest(self, limit: int) -> dict[str, Any]:
        """The newest ``limit`` reports, newest first, from their small summary files. A report whose summary cannot
        be read is listed with ``unreadable`` rather than left out."""
        limit = max(1, min(limit, MAX_LIST))
        try:
            dfd = self._open_dir(create=False)
        except StoreUnavailable as exc:
            return {"reports": [], "total": 0, "note": str(exc)}
        try:
            ids = sorted({m.group(1) for n in os.listdir(dfd) if (m := _REPORT.match(n))}, reverse=True)
            rows: list[dict[str, Any]] = []
            for report_id in ids[:limit]:
                try:
                    row = self._read(dfd, f"{report_id}.summary.json", MAX_SUMMARY_BYTES)
                    if not isinstance(row, dict) or row.get("id") != report_id:
                        raise StoreUnavailable("not a summary")
                    rows.append(row)
                except (KeyError, StoreUnavailable):
                    rows.append({"id": report_id, "unreadable": "its summary file is missing or not readable"})
        finally:
            os.close(dfd)
        return {"reports": rows, "total": len(ids)}


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    report = record.get("report") or {}
    s = report.get("summary") or {}
    names = list(s.get("alertnames") or [])
    out = {
        "id": record.get("id"),
        "receivedAt": record.get("receivedAt"),
        "durationSeconds": record.get("durationSeconds"),
        "alerts": s.get("alerts"),
        "byVerdict": s.get("byVerdict"),
        "alertnames": names[:SUMMARY_NAMES],
    }
    if len(names) > SUMMARY_NAMES:
        out["alertnamesNotShown"] = len(names) - SUMMARY_NAMES
    return out


def _why(exc: OSError) -> str:
    """An OS error as its errno name only: the message can carry a path, and the caller does not need it."""
    name = errno.errorcode.get(exc.errno or 0)
    return f"{type(exc).__name__}{': ' + name if name else ''}"


@dataclass
class Receiver:
    """What ``POST /v1/alert-reports`` does after the ``alert_report`` tool has built the report: stamp the receipt
    (id, times, the receipt-to-report duration), keep the record if storing is on, and count it on ``/metrics``."""

    store: AlertReportStore
    enabled: bool

    @classmethod
    def from_settings(cls, settings: Any) -> Receiver:
        return cls(AlertReportStore(settings.data_dir, settings.alert_reports), settings.alert_reports.store)

    def __call__(self, result: dict[str, Any], started: float, received_at: dt.datetime) -> dict[str, Any]:
        from kube_noob.server import metrics

        body = result["report"]
        seconds = max(time.monotonic() - started, 0.0)
        record: dict[str, Any] = {
            "format": RECORD_FORMAT,
            "id": new_id(received_at),
            "receivedAt": _iso(received_at),
            "durationSeconds": round(seconds, 6),
            "bodySha256": result.get("bodySha256") or body_sha256(body),
            "stored": False,
            "report": body,
        }
        evicted = 0
        if not self.enabled:
            record["notStoredReason"] = "alertReports.store is false: this server keeps no report"
        else:
            record["stored"] = True
            try:
                evicted = self.store.save(record, received_at)
            except StoreUnavailable as exc:
                record["stored"] = False
                record["notStoredReason"] = str(exc)
                _log.warning("alert report %s not stored: %s", record["id"], exc)
            except Exception as exc:  # noqa: BLE001 - the report is answered whatever happened to the copy
                record["stored"] = False
                record["notStoredReason"] = f"the report could not be kept ({type(exc).__name__}); see the server log"
                _log.exception("alert report %s not stored", record["id"])
        metrics.REGISTRY.alert_report(seconds, "stored" if record["stored"] else "not-stored", evicted)
        out = {**record}
        if evicted:
            out["evicted"] = evicted
        if "knowledgeAsOf" in result:
            out["knowledgeAsOf"] = result["knowledgeAsOf"]
        return out
