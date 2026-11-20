"""CEPH1: Ceph health codes on Rook-Ceph and OpenShift Data Foundation, read-only, with explicit escalation.

The fixtures are written in the formats Ceph prints, at ceph/ceph eb3b634bccd18715735a74cf55808e98c5dbd04b:
- `ceph health detail`: HealthMonitor::get_health_status (src/mon/HealthMonitor.cc lines 545-614): the status and the
  summaries joined by "; ", then "[WRN] CODE: summary" per check with its detail lines indented by four spaces. The
  PG_NOT_DEEP_SCRUBBED fixture has the layout of the example in doc/rados/operations/health-checks.rst lines
  2089-2091 (detail line not indented) with values of our own: the docs are cited, never copied.
- summaries and detail lines as OSDMap::check_health (src/osd/OSDMap.cc 7950-8002) and PGMap::get_health_checks
  (src/mon/PGMap.cc 2625-2745, 3170-3185) compose them; MON_DOWN as HealthMonitor.cc 924-934 does.
- `ceph status`: Monitor::get_cluster_status (src/mon/Monitor.cc 3349-3358), one summary per line under "health:".
- JSON: health_check_t::dump (src/mon/health_check.h 54-70) inside "checks" (HealthMonitor.cc 531-545).
- the older detail layout without brackets shown in doc/cephfs/health-messages.rst lines 60-65 (our own values).
- the CephCluster status Rook writes (pkg/apis/ceph.rook.io/v1/types.go CephStatus, rook/rook 61a8fea1).
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path
from typing import Any

import pytest

from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug.diagnose import diagnose
from kube_noob.debug.steps import classify_step
from kube_noob.signals import catalogue, ceph, extract, for_text
from kube_noob.signals import core as ex
from tests import bounds

#: Measured: the five hostile inputs through the text scan and the health-output sniffer, catalogue already
#: loaded. Re-measure with KUBE_NOOB_TEST_BOUNDS_REPORT=1 (tests/bounds.py).
HONEST_CEPH_TEXT_SCAN = 0.35

ROOT = Path(__file__).resolve().parents[1]

HEALTH_DETAIL = """\
HEALTH_WARN 2 osds down; 1 host (2 osds) down; Reduced data availability: 12 pgs inactive; Degraded data redundancy: \
341/1023 objects degraded (33.333%), 48 pgs degraded, 48 pgs undersized
[WRN] OSD_DOWN: 2 osds down
    osd.3 (root=default,host=worker-2) is down
    osd.4 (root=default,host=worker-2) is down
[WRN] OSD_HOST_DOWN: 1 host (2 osds) down
    host worker-2 (root=default) (2 osds) is down
[WRN] PG_AVAILABILITY: Reduced data availability: 12 pgs inactive
    pg 2.5 is stuck inactive for 5m, current state undersized+degraded+peered, last acting [1]
[WRN] PG_DEGRADED: Degraded data redundancy: 341/1023 objects degraded (33.333%), 48 pgs degraded, 48 pgs undersized
    pg 2.5 is stuck undersized for 5m, current state undersized+degraded+peered, last acting [1]
"""

DAMAGE = """\
HEALTH_ERR 1/310 objects unfound (0.323%); 2 scrub errors; Possible data damage: 1 pg inconsistent
[WRN] OBJECT_UNFOUND: 1/310 objects unfound (0.323%)
    pg 3.1a has 1 unfound objects
[ERR] OSD_SCRUB_ERRORS: 2 scrub errors
[ERR] PG_DAMAGED: Possible data damage: 1 pg inconsistent
    pg 3.1a is active+clean+inconsistent, acting [0,2,1], 1 unfound
"""

DEEP_SCRUB = """\
HEALTH_WARN 214 pgs not deep-scrubbed in time
[WRN] PG_NOT_DEEP_SCRUBBED: 214 pgs not deep-scrubbed in time
pg 7.1c not deep-scrubbed since 2026-09-30T04:12:09.114238+0000
"""

OLD_LAYOUT = """\
$ ceph health detail
HEALTH_WARN 1 MDSs report slow metadata IOs; 1 MDSs report slow requests
MDS_SLOW_METADATA_IO 1 MDSs report slow metadata IOs
   mds.cephfs-b(mds.0): 2 slow metadata IOs are blocked > 30 secs, oldest blocked for 812 secs
MDS_SLOW_REQUEST 1 MDSs report slow requests
   mds.cephfs-b(mds.0): 9 slow requests are blocked > 30 secs
"""

STATUS = """\
  cluster:
    id:     477e46f1-ae41-4e43-9c8f-72c918ab0a20
    health: HEALTH_WARN
            1/3 mons down, quorum a,b
            1 osds down
            Reduced data availability: 3 pgs inactive
            Degraded data redundancy: 21/63 objects degraded (33.333%), 16 pgs degraded
            2 daemons have recently crashed
            clock skew detected on mon.c

  services:
    mon: 3 daemons, quorum a,b (age 2m), out of quorum: c
    osd: 3 osds: 2 up (since 2m), 3 in (since 1h)
"""

ONE_LINE = "HEALTH_WARN 3 nearfull osd(s); 2 pool(s) nearfull; noout flag(s) set; 1 MDSs report slow requests"

DETAIL_JSON = {
    "status": "HEALTH_ERR",
    "checks": {
        "OSD_FULL": {
            "severity": "HEALTH_ERR",
            "summary": {"message": "1 full osd(s)", "count": 1},
            "detail": [{"message": "osd.2 is full"}],
            "muted": False,
        },
        "POOL_FULL": {
            "severity": "HEALTH_WARN",
            "summary": {"message": "3 pool(s) full", "count": 3},
            "detail": [{"message": "pool 'ocs-storagecluster-cephblockpool' is full (no space)"}],
            "muted": False,
        },
        "RECENT_CRASH": {
            "severity": "HEALTH_WARN",
            "summary": {"message": "1 daemons have recently crashed", "count": 1},
            "muted": True,
        },
    },
    "mutes": [],
}

STATUS_JSON = {
    "fsid": "477e46f1-ae41-4e43-9c8f-72c918ab0a20",
    "health": {
        "status": "HEALTH_WARN",
        "checks": {
            "MON_CLOCK_SKEW": {
                "severity": "HEALTH_WARN",
                "summary": {"message": "clock skew detected on mon.b", "count": 1},
                "muted": False,
            }
        },
        "mutes": [],
    },
    "election_epoch": 12,
}

CEPHCLUSTER_YAML = """\
apiVersion: ceph.rook.io/v1
kind: CephCluster
metadata:
  name: ocs-storagecluster-cephcluster
  namespace: openshift-storage
status:
  ceph:
    health: HEALTH_WARN
    details:
      MDS_SLOW_REQUEST:
        message: 1 MDSs report slow requests
        severity: HEALTH_WARN
      MON_DISK_LOW:
        message: mon b is low on available space
        severity: HEALTH_WARN
  phase: Ready
"""

ODF_ALERT_TEXT = (
    "Got paged on our OpenShift Data Foundation cluster: CephOSDDiskNotResponding is firing for "
    "disk vdb on worker-1. What should I check?"
)

ODF_PAYLOAD = {
    "version": "4",
    "status": "firing",
    "receiver": "storage",
    "commonLabels": {"namespace": "openshift-storage"},
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "CephMonQuorumAtRisk", "severity": "critical", "namespace": "openshift-storage"},
            "annotations": {"message": "Storage quorum at risk", "description": "Storage cluster quorum is low."},
        }
    ],
}

# Commands whose usual use can lose data or the cluster map: never a catalogue step, fix or note.
DESTRUCTIVE = (
    r"\bosd\s+lost\b",
    r"\bmark_unfound_lost\b",
    r"\bosd\s+purge\b",
    r"\bosd\s+destroy\b",
    r"\bforce-recovery\b",
    r"\bforce-backfill\b",
    r"\bforce-create-pg\b",
    r"\bceph-objectstore-tool\b",
    r"\bceph-bluestore-tool\b",
    r"\bceph-volume\s+lvm\s+zap\b",
    r"\bmon\s+(?:remove|rm)\b",
    r"\bmonmaptool\b",
    r"\binject-monmap\b",
    r"\bcephfs-journal-tool\b",
    r"\bcephfs-data-scan\b",
    r"\bcephfs-table-tool\b",
    r"\bfs\s+(?:reset|rm|fail)\b",
    r"\bpool\s+(?:delete|rm)\b",
    r"\brados\s+(?:rm|purge)\b",
    r"\bauth\s+(?:rm|del)\b",
    r"\bwipe-rotating-service-keys\b",
    r"\bset-full-ratio\b",
    r"\bpg\s+repair\b",
    r"\bosd\s+(?:out|rm|crush\s+rm)\b",
)


@pytest.fixture
def kit(tmp_path: Path) -> tk.Toolkit:
    return tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path / "data")}))


def _codes(data: Any) -> dict[str, str]:
    return {s.name: s.detail for s in extract(data) if s.kind == "ceph_health"}


def _health(text: str, platform: str | None = None) -> dict[str, Any]:
    return dict(diagnose(text, platform=platform).as_dict()["cephHealth"])


def _entries(text: str, platform: str | None = None) -> list[dict[str, Any]]:
    return list(_health(text, platform)["entries"])


def _commands(entry: dict[str, Any]) -> list[str]:
    return [s["command"] for s in entry["readOnlyNextSteps"] + entry["diagnosticCommands"] if "command" in s]


def _all_commands(health: dict[str, Any]) -> list[str]:
    """The common steps, then every entry's and every alert's."""
    return [c for part in (health, *health["entries"], *health["alerts"]) for c in _commands(part)]


# --- recognition ------------------------------------------------------------------------------------------------
def test_health_detail_text_gives_each_code_with_its_severity() -> None:
    codes = _codes(HEALTH_DETAIL)
    assert set(codes) == {"OSD_DOWN", "OSD_HOST_DOWN", "PG_AVAILABILITY", "PG_DEGRADED"}
    assert codes["OSD_DOWN"].startswith("HEALTH_WARN 2 osds down")
    damage = _codes(DAMAGE)
    assert set(damage) == {"OBJECT_UNFOUND", "OSD_SCRUB_ERRORS", "PG_DAMAGED"}
    assert damage["PG_DAMAGED"].startswith("HEALTH_ERR")
    assert set(_codes(DEEP_SCRUB)) == {"PG_NOT_DEEP_SCRUBBED"}
    muted = "(MUTED ttl 59m, STICKY) [WRN] OSD_NEARFULL: 1 nearfull osd(s)\n    osd.2 is near full\n"
    assert set(_codes(muted)) == {"OSD_NEARFULL"}


def test_older_layout_and_codes_written_in_prose() -> None:
    assert set(_codes(OLD_LAYOUT)) == {"MDS_SLOW_METADATA_IO", "MDS_SLOW_REQUEST"}
    assert set(_codes("after the upgrade we keep seeing PG_DEGRADED and then OSD_DOWN, why?")) == {
        "PG_DEGRADED",
        "OSD_DOWN",
    }
    # The Prometheus metric the alerts read names the code too.
    assert set(_codes('ceph_health_detail{name="OSD_NEARFULL"} == 1')) == {"OSD_NEARFULL"}
    # Part of a longer identifier is not a code.
    assert _codes("MY_OSD_DOWN_FLAG=1 and XPG_DEGRADED") == {}


def test_ceph_status_summaries_map_to_codes() -> None:
    assert set(_codes(STATUS)) == {
        "MON_DOWN",
        "OSD_DOWN",
        "PG_AVAILABILITY",
        "PG_DEGRADED",
        "RECENT_CRASH",
        "MON_CLOCK_SKEW",
    }
    assert set(_codes(ONE_LINE)) == {"OSD_NEARFULL", "POOL_NEARFULL", "OSDMAP_FLAGS", "MDS_SLOW_REQUEST"}
    family = "    health: HEALTH_WARN\n            1 rack (6 osds) down\n            2 zones (8 osds) down\n"
    assert set(_codes(family)) == {"OSD_RACK_DOWN", "OSD_ZONE_DOWN"}
    # The same wording outside a Ceph health report is not a code.
    assert _codes("1 osds down is what my teammate said in standup") == {}


def test_json_forms_give_the_same_codes() -> None:
    detail = _codes(json.dumps(DETAIL_JSON))
    assert set(detail) == {"OSD_FULL", "POOL_FULL", "RECENT_CRASH"}
    assert detail["OSD_FULL"].startswith("HEALTH_ERR 1 full osd(s)")
    assert "muted" in detail["RECENT_CRASH"]
    assert set(_codes(DETAIL_JSON)) == set(detail)  # already parsed
    assert set(_codes(json.dumps(STATUS_JSON, indent=2))) == {"MON_CLOCK_SKEW"}
    assert set(_codes(CEPHCLUSTER_YAML)) == {"MDS_SLOW_REQUEST", "MON_DISK_LOW"}
    # What the first read-only step prints (kubectl's jsonpath writes a map as JSON) reads back as the same codes.
    details = '{"OSD_DOWN":{"message":"1 osds down","severity":"HEALTH_WARN"},"POOL_NEARFULL":{"message":"2 pool(s) '
    details += 'nearfull","severity":"HEALTH_WARN"}}'
    assert _codes(details) == {"OSD_DOWN": "HEALTH_WARN 1 osds down", "POOL_NEARFULL": "HEALTH_WARN 2 pool(s) nearfull"}
    assert _codes('{"name": "web", "replicas": 3}') == {} and _codes('{"OSD_DOWN": 1, "PG_DEGRADED": "x"}') == {}
    offline = {"MDS_ALL_DOWN": {"severity": "HEALTH_ERR", "message": "1 filesystem is offline"}}
    cluster = {"kind": "CephCluster", "status": {"ceph": {"health": "HEALTH_ERR", "details": offline}}}
    listed = {"apiVersion": "v1", "kind": "List", "items": [cluster]}
    assert set(_codes(json.dumps(listed))) == {"MDS_ALL_DOWN"}


def test_doc_and_alert_names_map_to_the_code_ceph_emits() -> None:
    # doc/cephfs/health-messages.rst heads these sections with the MDS_HEALTH_ enum names; the MDS emits
    # mds_metric_name() (src/messages/MMDSBeacon.h): MDS_READ_ONLY, MDS_CLIENT_LATE_RELEASE, MDS_CLIENT_RECALL_MANY.
    found = {
        s.name: s.detail for s in extract("we see MDS_HEALTH_READ_ONLY on the filesystem") if s.kind == "ceph_health"
    }
    assert set(found) == {"MDS_READ_ONLY"}
    assert ceph.canonical("MDS_HEALTH_CLIENT_LATE_RELEASE") == "MDS_CLIENT_LATE_RELEASE"
    assert ceph.canonical("BLUESTORE_FRAGMENTATION") == "BLUESTORE_FREE_FRAGMENTATION"
    rule = ceph.alert("CephFilesystemReadOnly")
    assert rule is not None and rule.watches == ["MDS_READ_ONLY"] and "MDS_HEALTH_READ_ONLY" in (rule.note or "")


def test_uncatalogued_codes_are_named_not_guessed() -> None:
    text = "HEALTH_WARN 1 stray daemon(s)\n[WRN] CEPHADM_STRAY_DAEMON: 1 stray daemon(s) not managed by cephadm\n"
    assert set(_codes(text)) == {"CEPHADM_STRAY_DAEMON"}
    out = diagnose(text).as_dict()["cephHealth"]
    assert out["entries"] == [] and out["notCatalogued"] == ["CEPHADM_STRAY_DAEMON"]


# --- alerts -----------------------------------------------------------------------------------------------------
def test_odf_alert_names_imply_codes_and_the_odf_namespace() -> None:
    signals = for_text(ODF_ALERT_TEXT)
    assert ("alert", "CephOSDDiskNotResponding") in {(s.kind, s.name) for s in signals}
    implied = [s for s in signals if s.kind == "ceph_health"]
    assert [s.name for s in implied] == ["OSD_DOWN"] and "CephOSDDiskNotResponding" in implied[0].source
    out = _health(ODF_ALERT_TEXT)
    assert out["platform"] == "openshift" and out["namespace"] == "openshift-storage"
    osd_down = out["entries"][0]
    assert osd_down["code"] == "OSD_DOWN" and osd_down["alerts"][0]["alert"] == "CephOSDDiskNotResponding"
    assert "openshift/runbooks" in osd_down["alerts"][0]["runbook"]
    # An ODF-only alert names ODF even when the text never says OpenShift.
    out = _health("CephDataRecoveryTakingTooLong fired at 3am")
    assert out["platform"] == "openshift" and [e["code"] for e in out["entries"]] == ["PG_DEGRADED"]
    # A Rook alert alone does not: it ships with upstream Rook too.
    assert _health("CephOSDDown fired at 3am")["platform"] == "kubernetes"


def test_alert_that_says_contact_support_gets_evidence_and_an_explicit_escalation(kit: tk.Toolkit) -> None:
    out = kit.diagnose(tk.DiagnoseIn(text=json.dumps(ODF_PAYLOAD)))
    health = out["cephHealth"]
    assert [e["code"] for e in health["entries"]] == ["MON_DOWN"]
    mon = health["entries"][0]
    assert mon["escalate"].startswith(ceph.STOP) and "Stop and involve storage support" in ceph.STOP
    assert health["readOnlyNextSteps"][0]["command"].startswith("oc get cephcluster -n openshift-storage")
    assert any("app=rook-ceph-mon" in c for c in _commands(mon))
    assert health["stop"] == ceph.STOP
    assert mon["alerts"][0]["alert"] == "CephMonQuorumAtRisk" and "support" in mon["alerts"][0]["note"]


def test_state_alerts_get_steps_to_find_the_code() -> None:
    out = _health("CephClusterWarningState has been firing for 2h on openshift-storage")
    assert out["entries"] == []
    [state] = out["alerts"]
    assert state["alert"] == "CephClusterWarningState" and "HEALTH_WARN" in state["meaning"]
    assert any(s["command"].endswith("ceph health detail") for s in state["diagnosticCommands"])


# --- advice -----------------------------------------------------------------------------------------------------
def test_causes_come_before_their_symptoms_and_steps_only_read() -> None:
    health = _health(HEALTH_DETAIL)
    entries = health["entries"]
    assert [e["code"] for e in entries] == ["OSD_DOWN", "OSD_HOST_DOWN", "PG_AVAILABILITY", "PG_DEGRADED"]
    for part in (health, *entries):
        assert all(classify_step(s["command"]) == "read" for s in part["readOnlyNextSteps"])
        assert all(classify_step(c["command"]) == "exec" and c["requiresApproval"] for c in part["diagnosticCommands"])
    for e in entries:
        assert e["meaning"] and e["likelyCauses"] and e["fix"] and e["source"]
        assert all(url.startswith("https://github.com/ceph/ceph/blob/eb3b634") for url in e["source"])
        assert e["diagnosticCommands"]
    assert entries[0]["severity"] == "HEALTH_WARN"
    assert health["diagnosticCommands"][0]["command"].endswith("ceph health detail")


def test_escalation_says_stop_and_never_shows_a_destructive_step() -> None:
    entries = {e["code"]: e for e in _entries(DAMAGE)}
    assert list(entries) == ["OSD_SCRUB_ERRORS", "PG_DAMAGED", "OBJECT_UNFOUND"]
    for code in ("OBJECT_UNFOUND", "PG_DAMAGED", "OSD_SCRUB_ERRORS"):
        assert entries[code]["escalate"].startswith(ceph.STOP), code
        for cmd in _commands(entries[code]):
            assert not any(re.search(rx, cmd) for rx in DESTRUCTIVE), cmd
    assert "kubectl exec -n rook-ceph deploy/rook-ceph-tools -- ceph pg 3.1a list_unfound" in _commands(
        entries["OBJECT_UNFOUND"]
    )
    for code in ("PG_AVAILABILITY", "MON_DOWN", "MDS_DAMAGE", "OSD_FULL", "DEVICE_HEALTH_TOOMANY"):
        entry = ceph.entry(code)
        assert entry is not None and entry.escalate, code
    nearfull = ceph.entry("OSD_NEARFULL")
    assert nearfull is not None and not nearfull.escalate


def _catalogue_texts() -> list[tuple[str, str]]:
    cat = ceph.catalogue()
    out: list[tuple[str, str]] = []
    for sid, step in cat.steps.items():
        out += [(f"step {sid}", step.run), (f"step {sid} why", step.why)]
    for c in cat.codes:
        out += [(c.code, t) for t in (c.meaning, c.fix, c.escalate or "", *c.causes, *(c.summary or []))]
    for a in cat.alerts:
        out += [(a.alert, a.note or "")]
    return out


def test_no_catalogue_text_contains_a_destructive_command() -> None:
    texts = _catalogue_texts()
    assert len(texts) > 500
    hits = [(where, rx) for where, text in texts for rx in DESTRUCTIVE if re.search(rx, text)]
    assert hits == []
    for planted in ("ceph osd lost 3 --yes-i-really-mean-it", "ceph pg 2.5 mark_unfound_lost revert"):
        with pytest.raises(ValueError, match="lose data"):
            ceph.Step(run=planted, why="a planted destructive step")
    with pytest.raises(ValueError, match="lose data"):
        ceph.Step(run="ceph osd tree", why="then run ceph osd purge 3")


def test_every_step_only_reads_and_never_prints_a_key() -> None:
    cat = ceph.catalogue()
    for sid, step in cat.steps.items():
        assert not re.search(r"\b(?:auth\s+(?:ls|get|export|print-key)|config-key|secret)", step.run), sid
        if step.run.startswith(("ceph ", "rados ")):
            assert ceph.READ_ONLY_TOOLBOX.match(step.run), sid
        else:
            assert step.run.startswith("oc ") and classify_step(step.run) == "read", sid
    for changing in (
        "ceph osd set noout",
        "ceph tell osd.3 injectargs --debug_osd=20",
        "oc delete pod -n {ns} -l app=rook-ceph-osd",
        "oc get secret -n {ns} rook-ceph-mon -o yaml",
        "ceph auth get client.admin",
        "oc get pods -n {ns}; oc delete pod x",
    ):
        with pytest.raises(ValueError):
            ceph.Step(run=changing, why="a step that must be refused")


# --- platforms and names ----------------------------------------------------------------------------------------
def test_platform_split() -> None:
    odf = _health("openshift-storage\n" + HEALTH_DETAIL)
    assert odf["platform"] == "openshift" and odf["namespace"] == "openshift-storage"
    assert odf["readOnlyNextSteps"][0]["command"] == (
        "oc get cephcluster -n openshift-storage -o jsonpath='{.status.ceph.details}'"
    )
    assert "oc exec -n openshift-storage deploy/rook-ceph-tools -- ceph health detail" in _all_commands(odf)
    assert "oc get storagecluster -n openshift-storage" in _all_commands(odf)
    rook = _health(HEALTH_DETAIL)  # no platform and no OpenShift words: plain Rook on Kubernetes
    assert rook["platform"] == "kubernetes" and rook["namespace"] == "rook-ceph"
    assert "kubectl exec -n rook-ceph deploy/rook-ceph-tools -- ceph health detail" in _all_commands(rook)
    assert not [c for c in _all_commands(rook) if c.startswith("oc ") or "storagecluster" in c]
    forced = _health("openshift-storage\n" + HEALTH_DETAIL, platform="kubernetes")
    assert all(c.startswith("kubectl ") for c in _all_commands(forced))
    given = _health(HEALTH_DETAIL, platform="openshift")
    assert "oc exec -n openshift-storage deploy/rook-ceph-tools -- ceph osd tree" in _all_commands(given)
    rosa = _health(HEALTH_DETAIL, platform="rosa-hcp")
    assert rosa["platform"] == "openshift" and rosa["namespace"] == "openshift-storage"
    upstream_on_ocp = _health("oc get pods -n rook-ceph\n" + HEALTH_DETAIL)
    assert upstream_on_ocp["platform"] == "openshift" and upstream_on_ocp["namespace"] == "rook-ceph"
    assert "enableCephTools" in given["note"] and "enableCephTools" not in rook["note"]


def test_commands_carry_names_from_the_input_and_never_hostile_ones() -> None:
    osd = _entries(HEALTH_DETAIL)[0]
    assert "kubectl logs -n rook-ceph deploy/rook-ceph-osd-3 --tail=200" in _commands(osd)
    pg = {e["code"]: e for e in _entries(HEALTH_DETAIL)}["PG_AVAILABILITY"]
    assert "kubectl exec -n rook-ceph deploy/rook-ceph-tools -- ceph pg 2.5 query" in _commands(pg)
    hostile = "[WRN] OSD_DOWN: 1 osds down\n    osd.3$(reboot) is down\n    pg 2.5;rm is stuck\n"
    cmds = _all_commands(_health(hostile))
    assert "kubectl logs -n rook-ceph deploy/rook-ceph-osd-<osd-id> --tail=200" in cmds
    assert not [c for c in cmds if re.search(r"[;$`|&()]", c)]


# --- surfaces ---------------------------------------------------------------------------------------------------
def test_mixed_paste_answers_ceph_and_the_pod_in_one_insight(kit: tk.Toolkit) -> None:
    paste = (
        "NAME                               READY   STATUS             RESTARTS   AGE\n"
        "rook-ceph-osd-3-7d9f8c6b5d-x2x9k   0/1     CrashLoopBackOff   14         1h\n"
        "rook-ceph-osd-4-6c8f7d5b4c-q8w7z   0/1     CrashLoopBackOff   14         1h\n\n" + HEALTH_DETAIL
    )
    out = kit.insight(tk.InsightIn(text=paste))
    kinds = {k["kind"] for k in out["kinds"]}
    assert {"ceph-health", "pod-status"} <= kinds
    sources = [f["source"] for f in out["findings"]]
    assert sources[0] == "ceph-health" and "playbook" in sources
    first = out["findings"][0]
    assert first["id"] == "OSD_DOWN" and first["cause"] and first["fix"] and first["diagnosticCommands"]
    assert out["readOnlyNextSteps"][0]["command"].startswith("kubectl get cephcluster -n rook-ceph")
    assert all(classify_step(s["command"]) == "read" for s in out["readOnlyNextSteps"] if "command" in s)


def test_insight_names_each_ceph_shape(kit: tk.Toolkit) -> None:
    from kube_noob.insight import recognise

    details = json.dumps({"OSD_DOWN": {"message": "1 osds down", "severity": "HEALTH_WARN"}})
    for text in (HEALTH_DETAIL, STATUS, ONE_LINE, json.dumps(DETAIL_JSON), json.dumps(STATUS_JSON), details):
        assert "ceph-health" in {k.kind for k in recognise(text)}, text[:40]
    for text in ("our ceph cluster is slow, any idea?", "HEALTH_WARN is what the dashboard says"):
        assert "ceph-health" not in {k.kind for k in recognise(text)}
    damaged = kit.insight(tk.InsightIn(text=DAMAGE, platform="openshift"))
    escalated = [f for f in damaged["findings"] if f.get("escalate")]
    assert [f["id"] for f in escalated] == ["OSD_SCRUB_ERRORS", "PG_DAMAGED", "OBJECT_UNFOUND"]


def test_cli_insight_and_signals_print_the_codes(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.cli import main

    assert main(["insight", DAMAGE]) == 0
    out = capsys.readouterr().out
    assert "ceph-health" in out and "OBJECT_UNFOUND" in out
    assert "escalate: Stop and involve storage support" in out
    assert "in the toolbox (needs approval): kubectl exec -n rook-ceph deploy/rook-ceph-tools -- ceph" in out
    assert main(["signals", HEALTH_DETAIL]) == 0
    assert "ceph_health     OSD_DOWN" in capsys.readouterr().out


def test_the_debug_bundle_shows_the_ceph_section() -> None:
    from kube_noob.debug.diagnose import bundle_markdown

    found = diagnose(DAMAGE, platform="openshift").as_dict()
    md = bundle_markdown({"target": "deployment/openshift-storage/rook-ceph-osd-3", "backend": "oc", **found})
    assert "## Ceph OBJECT_UNFOUND (HEALTH_WARN)" in md and f"**{ceph.STOP}**" in md
    assert "`oc exec -n openshift-storage deploy/rook-ceph-tools -- ceph pg 3.1a list_unfound`" in md


def test_mcp_signals_tool_cites_the_catalogue(kit: tk.Toolkit) -> None:
    out = kit.extract_signals(tk.SignalsIn(text=HEALTH_DETAIL))
    ids = {c["id"]: c for c in out["catalogue"]}
    assert "ceph_health:OSD_DOWN" in ids
    assert ids["ceph_health:OSD_DOWN"]["sources"][0].startswith("https://github.com/ceph/ceph/blob/eb3b634")


# --- bounds, determinism, precision ------------------------------------------------------------------------------
def test_hostile_and_oversized_input_is_bounded_and_fast() -> None:
    flood = "[WRN] OSD_DOWN: 1 osds down\n" * 60_000 + "[WRN] " + "A_" * 40_000 + ": x\n"
    blank = "\n" * 1_000_000 + "    health: HEALTH_WARN\n" + "            " * 100_000 + "\n"
    long_line = "    health: HEALTH_WARN\n            " + "1" * 3_000 + " osds down" + " x" * 200_000 + "\n"
    words = "ceph\n" + ("PG_DEGRADED_ " * 300 + "OSD_DOWN\n") * 2_000
    splits = "HEALTH_WARN " + "; " * 1_000_000
    ceph.catalogue()  # loaded once per process; the timer measures the scan
    with bounds.bounded(
        bounds.LINEAR, honest_seconds=HONEST_CEPH_TEXT_SCAN, guards="five hostile inputs through the text scan"
    ):
        for text in (flood, blank, long_line, words, splits):
            ceph.text_signals(text)
            ceph.looks_like_health_output(text)
    assert [s.name for s in extract(flood) if s.kind == "ceph_health"] == ["OSD_DOWN"]
    assert [s.name for s in extract(words) if s.kind == "ceph_health"] == ["OSD_DOWN"]
    many = {"status": "HEALTH_WARN", "checks": {f"CODE_{i}": {"severity": "HEALTH_WARN"} for i in range(5_000)}}
    # No clock on this one. It had `< 1.0` beside the cap assertion and failed at 1.0239 s and 1.0607 s on PR #77's
    # `test (3.11)` job, after the identical sha had gone 19 of 19 green on a workflow_dispatch run. The work is
    # 0.001 s measured here, so the budget had a thousandfold headroom and still lost: it measured a second of
    # descheduling. The cap it was beside is exact and is the whole contract -- `json_checks` reads MAX_CHECKS of
    # 5,000 entries and `extract` stops at MAX_SIGNALS -- and `tests/bounds.py` refuses a ceiling for work this
    # cheap: `SMALL_MULTIPLE` is a 25x regression, and no ceiling that survives a stall is below 25x of one
    # millisecond. The helper raises `VacuousBound` rather than letting a meaningless ceiling pass.
    assert len(ceph.json_checks(many) or []) == ceph.MAX_CHECKS and len(extract(many)) <= ex.MAX_SIGNALS
    weird = {"checks": {"osd_down; rm -rf /": {"severity": "HEALTH_WARN"}, "OSD_DOWN": "not a dict", "X": {}}}
    assert _codes(weird) == {}
    deep = '{"health": ' * 3_000 + '{"checks": {"OSD_DOWN": {"severity": "HEALTH_WARN"}}}' + "}" * 3_000
    assert isinstance(extract(deep), list)  # parsed or refused, never a crash (depends on the Python version)
    out = diagnose(flood[:400_000]).as_dict()["cephHealth"]
    assert [e["code"] for e in out["entries"]] == ["OSD_DOWN"]


def test_output_is_deterministic() -> None:
    lines = HEALTH_DETAIL.splitlines() + DAMAGE.splitlines()
    first = diagnose("\n".join(lines)).as_dict()["cephHealth"]
    for seed in range(4):
        shuffled = list(lines)
        random.Random(seed).shuffle(shuffled)
        again = diagnose("\n".join(shuffled)).as_dict()["cephHealth"]
        assert [e["code"] for e in again["entries"]] == [e["code"] for e in first["entries"]]
    assert diagnose("\n".join(lines)).as_dict()["cephHealth"] == first


def test_ceph_wording_is_not_read_as_an_etcd_phrase() -> None:
    """ "1 MDSs report slow requests" is MDS_SLOW_REQUEST, not etcd's "slow requests" (etcdGRPCRequestsSlow)."""
    out = diagnose("HEALTH_WARN 1 MDSs report slow requests").as_dict()
    assert [s["name"] for s in out["signals"]] == ["MDS_SLOW_REQUEST"] and out["diagnoses"] == []
    # Outside Ceph output the phrase still implies the etcd alert.
    assert "etcdGRPCRequestsSlow" in {s.name for s in for_text("etcd shows slow requests after the upgrade")}


@pytest.mark.parametrize(
    "text",
    [
        "our ceph cluster is slow, any idea?",
        "Ceph RBD PVC with RWX never binds: provisioning failed with unsupported capabilities",
        "rook-ceph-osd-0 is Pending: 0/3 nodes are available: 3 Insufficient memory.",
        "Warning  FailedMount  pod/db-0  MountVolume.MountDevice failed for volume pvc-1 : rpc error: "
        "code = Internal desc = rbd: map failed with error an error (exit status 22)",
        "HEALTH_WARN is what the dashboard says",
        "export OSD_DOWN_TIMEOUT=30",
    ],
)
def test_prose_about_ceph_without_a_code_gets_no_ceph_advice(text: str) -> None:
    assert _codes(text) == {}
    assert "cephHealth" not in diagnose(text).as_dict()


# --- the catalogue ----------------------------------------------------------------------------------------------
def test_catalogue_is_well_formed_and_cited() -> None:
    cat = ceph.catalogue()
    names = [c.code for c in cat.codes]
    assert len(names) == len(set(names)) and len(names) >= 110
    every = {n for c in cat.codes for n in (c.code, *c.also)}
    assert {"OSD_DOWN", "MON_DOWN", "PG_DEGRADED", "PG_AVAILABILITY", "OSD_NEARFULL", "MDS_SLOW_REQUEST"} <= every
    assert {"POOL_NEAR_FULL", "POOL_NEARFULL", "RECENT_CRASH", "MON_CLOCK_SKEW", "OSD_SCRUB_ERRORS"} <= every
    assert {"PG_DAMAGED", "OSD_HOST_DOWN", "OSD_ZONE_DOWN", "MDS_READ_ONLY"} <= every
    for c in cat.codes:
        assert len(c.meaning) <= 240 and c.meaning.endswith("."), c.code
        assert c.causes and c.steps and c.terms, c.code
        assert set(c.after) <= every, c.code
        assert c.doc or c.src, c.code
        assert catalogue.get("ceph_health", c.code) is not None, c.code
    alerts = [a.alert for a in cat.alerts]
    assert len(alerts) == len(set(alerts)) and len(alerts) >= 60
    for a in cat.alerts:
        assert set(a.watches) <= every, a.alert
        assert a.how == "state" or a.watches, a.alert
        e = catalogue.get("alert", a.alert)
        assert e is not None and e.health_codes == tuple(a.watches), a.alert
        assert all(s.startswith(("https://github.com/rook/rook/blob/61a8fea", "https://github.com/red-hat-storage/"))
                   for s in e.sources), a.alert  # fmt: skip
    data = ROOT / "src" / "kube_noob" / "data" / "ceph_health.yaml"
    assert data.stat().st_size < 256 * 1024
    assert cat.sources["ceph"].commit == "eb3b634bccd18715735a74cf55808e98c5dbd04b"


def test_the_catalogue_still_loads_when_the_faster_parser_refuses_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """G121: signals/ceph.py prefers libyaml for its start-up time, and libyaml versions disagree with PyYAML's own
    scanner about some documents -- one such disagreement took out diagnose and known_issues after 0.7.0, because
    both reach this catalogue. The data is now kept free of those shapes, and if a stricter parser still objects the
    tools degrade to the slower scanner rather than raising."""
    import yaml

    from kube_noob.signals import ceph

    class Refuses(yaml.SafeLoader):
        def get_single_data(self) -> Any:
            raise yaml.scanner.ScannerError(None, None, "found unexpected ':'", None)

    ceph.catalogue.cache_clear()
    monkeypatch.setattr(ceph, "_LOADER", Refuses)
    assert len(ceph.catalogue().codes) > 100

    # with no faster parser to fall back from, a refusal is a bug in our own data and must surface
    ceph.catalogue.cache_clear()
    monkeypatch.setattr(yaml, "SafeLoader", Refuses)
    monkeypatch.setattr(ceph, "_LOADER", Refuses)
    with pytest.raises(yaml.YAMLError):
        ceph.catalogue()
    ceph.catalogue.cache_clear()
