"""OpenShift update risks from the public update graph, evaluated offline (backlog UPG1).

Real risks used below, all from https://github.com/openshift/cincinnati-graph-data at commit
7572174a551561c30e07e9b5ca6f156ef5cd513c (2026-10-29), files under ``blocked-edges/``:

- 4.21.4-EtcdStorageVersion3Migration.yaml (``type: Always``, ``from: 4[.]20[.]([0-9]|1[0-4])[+].*``)
- 4.20.12-HyperShiftRedundantRouter.yaml (PromQL on cluster_installer invoker="hypershift",
  ``from: ^4[.]19[.]([0-9]|1[0-7])[+].*$``)
- 4.20.12-ARO420UDRWorkerNodesFail.yaml (PromQL on cluster_operator_conditions name="aro")
- 4.19.0-InvalidArchitectureValueOfMachinesetsAnnotation.yaml (PromQL ``type="AWS|GCP"``: an exact-match label
  matcher whose value is no platform type, so it is left to the cluster)
- 4.21.0-SigstoreSignatureMirroring.yaml (PromQL on apiserver_storage_objects, ``fixedIn: 4.21.1``,
  ``from: 4[.]20[.]12[+].*``)
- 4.22.17-MultiArchPayloadMissingOpenVSwitch.yaml (PromQL: every cluster whose invoker is not "hypershift",
  ``fixedIn: 4.22.18``)
- 4.19.0-AlertmanagerV1NotSupported.yaml (``from: ^4[.]18[.]1[6-8][+].*$``)
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kube_noob import toolkit as tk
from kube_noob import upgrade_risks as ur
from kube_noob.cli import main as cli_main
from kube_noob.config import load_settings
from kube_noob.debug.steps import classify_step, split_comment
from kube_noob.knowledge_status import line, status
from tests import bounds

#: Measured: one backtracking bomb against the linear engine.
#: Re-measure with KUBE_NOOB_TEST_BOUNDS_REPORT=1 (tests/bounds.py).
HONEST_BOMB = 0.001

DATA = Path(ur.__file__).parent / "data" / "upgrade_risks"
COMMIT = "7572174a551561c30e07e9b5ca6f156ef5cd513c"
BLOB = f"https://github.com/openshift/cincinnati-graph-data/blob/{COMMIT}/blocked-edges/"


def _names(out: dict[str, Any]) -> list[str]:
    return sorted(r["name"] for r in out["risks"])


def _by_name(out: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["name"]: r for r in out["risks"]}


# ---------------------------------------------------------------- the vendored index


def test_vendored_index_is_dated_pinned_cited_and_fits_the_plugin_limits() -> None:
    files = sorted(DATA.glob("*.json"))
    assert len(files) >= 2, "run scripts/vendor_upgrade_risks.py"
    kept = 0
    for f in files:
        raw = f.read_bytes()
        assert len(raw) < 200 * 1024, f.name  # shards under 200 KiB; the plugin directory refuses 256 KiB
        doc = json.loads(raw.decode("utf-8"))
        assert doc["commit"] == COMMIT and doc["license"] == "Apache-2.0" and doc["schemaVersion"] == "1.1.0"
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", doc["retrievedAt"]) and "Red Hat" in doc["attribution"]
        assert doc["scope"]["minTarget"] == "4.18" and doc["scope"]["skippedMalformed"] == []
        kept = doc["scope"]["kept"]
        for r in doc["records"]:
            assert set(r) <= {"to", "from", "url", "name", "message", "fixedIn", "matchingRules", "source"}, r
            major, minor, _ = (int(p) for p in r["to"].split("."))
            assert (major, minor) >= (4, 18) and r["source"] == f"blocked-edges/{r['to']}-{r['name']}.yaml"
    idx = ur.get_index()
    assert len(idx.records) == kept > 300
    k = idx.knowledge()
    assert k["upgradeRisksAsOf"] == json.loads(files[0].read_text())["retrievedAt"]
    assert k["commit"] == COMMIT and k["minTarget"] == "4.18" and k["newestTarget"] == "4.22.17"


def test_every_vendored_from_pattern_compiles_and_agrees_with_search_semantics() -> None:
    """Cincinnati applies ``from`` with Rust's ``Regex::is_match`` (unanchored) to the version with its architecture
    suffix; the safe engine must give the same answer as a regex search for every vendored pattern."""
    versions = [f"4.{y}.{z}" for y in range(16, 23) for z in (0, 1, 2, 9, 10, 11, 12, 14, 15, 16, 17, 18, 21, 120)]
    patterns = sorted({r["from"] for r in ur.get_index().records})
    for pattern in patterns:
        rx = ur.compile_from(pattern)
        for v in versions:
            for arch in ur.ARCHITECTURES:
                s = f"{v}+{arch}"
                assert rx.search(s) == bool(re.search(pattern, s)), (pattern, s)


# ---------------------------------------------------------------- real risks on real edges


def test_the_example_edge_has_the_etcd_migration_risk_that_always_applies() -> None:
    out = ur.risks("4.20.3", "4.21.4")
    assert _names(out) == ["EtcdStorageVersion3Migration"]
    r = out["risks"][0]
    assert r["verdict"] == "applies" and r["url"] == "https://redhat.atlassian.net/browse/CNTRLPLANE-3074"
    assert r["message"].startswith("Updating from etcd 3.5.25 or older to 3.6")
    assert r["source"] == BLOB + "4.21.4-EtcdStorageVersion3Migration.yaml"
    assert "fixedIn" not in r and out["counts"] == {"applies": 1, "check": 0, "cannot evaluate offline": 0}
    assert out["covered"] is True and out["edge"] == {"from": "4.20.3", "to": "4.21.4", "architecture": None}


def test_promql_risks_say_which_fact_decides_them_and_how_to_read_it() -> None:
    out = _by_name(ur.risks("4.19.5", "4.20.12"))
    assert sorted(out) == ["ARO420UDRWorkerNodesFail", "HyperShiftRedundantRouter"]
    hcp = out["HyperShiftRedundantRouter"]
    assert hcp["verdict"] == "check"
    assert hcp["appliesWhen"] == 'the invoker is "hypershift" (hosted control planes)'
    assert "openshift-install" in hcp["decidedBy"] and "cluster_installer" in hcp["decidedBy"]
    assert hcp["readOnlyCommands"] == [
        "oc get configmap openshift-install -n openshift-config -o jsonpath='{.data.invoker}'",
        "oc get configmap openshift-install-manifests -n openshift-config -o jsonpath='{.data.invoker}'",
    ]
    assert 'cluster_installer{_id="",invoker="hypershift"}' in hcp["promql"]
    aro = out["ARO420UDRWorkerNodesFail"]
    assert aro["verdict"] == "check" and aro["appliesWhen"] == "ClusterOperator aro exists"
    assert aro["readOnlyCommands"] == ["oc get clusteroperator aro"]
    assert aro["mustGather"] == ["cluster-scoped-resources/config.openshift.io/clusteroperators/aro.yaml"]


def test_a_mixed_edge_keeps_every_verdict_and_never_guesses_a_query() -> None:
    out = ur.risks("4.18.5", "4.19.0")
    risks = _by_name(out)
    assert sorted(risks) == [
        "AROMissingInternalLBSAN",
        "ConsoleEnabledTargetDownAlert",
        "HCPMetallbCNOCannotDeployFRRK8S",
        "HCPServiceHealthCheckDisruption",
        "IPsecLargeClusterConnectivity",
        "InvalidArchitectureValueOfMachinesetsAnnotation",
        "NoCloudConfConfigMap",
        "OldBootImagesComposeFSvsGrubProbe",
        "VSphereStorageMountIssues",
    ]
    console = risks["ConsoleEnabledTargetDownAlert"]
    assert console["verdict"] == "check" and console["fixedIn"] == "4.19.1"
    assert console["appliesWhen"] == "the Console capability is enabled"
    vsphere = risks["VSphereStorageMountIssues"]
    assert vsphere["appliesWhen"] == "the platform type is VSphere or None"
    assert vsphere["readOnlyCommands"] == ["oc get infrastructure cluster -o jsonpath='{.status.platformStatus.type}'"]
    assert vsphere["mustGather"] == ["cluster-scoped-resources/config.openshift.io/infrastructures/cluster.yaml"]
    # `type="AWS|GCP"` is an exact match in PromQL: no platform type has that value, so it is not translated
    literal = risks["InvalidArchitectureValueOfMachinesetsAnnotation"]
    assert literal["verdict"] == "cannot evaluate offline" and 'type="AWS|GCP"' in literal["promql"]
    assert "readOnlyCommands" not in literal
    for name in ("HCPServiceHealthCheckDisruption", "IPsecLargeClusterConnectivity", "NoCloudConfConfigMap"):
        assert risks[name]["verdict"] == "cannot evaluate offline", name
    raw = {r["source"]: r for r in ur.get_index().records}
    for r in out["risks"]:  # the PromQL is shown exactly as upstream wrote it
        rule = raw[r["source"].removeprefix(BLOB.removesuffix("blocked-edges/"))]["matchingRules"][0]
        assert r["promql"] == rule["promql"]["promql"]
    assert [r["verdict"] for r in out["risks"]] == sorted(
        (r["verdict"] for r in out["risks"]), key=["applies", "check", "cannot evaluate offline"].index
    )


def test_fixed_in_and_the_not_hosted_control_planes_shape() -> None:
    out = ur.risks("4.20.12", "4.21.0")
    risks = _by_name(out)
    assert sorted(risks) == ["EtcdStorageVersion3Migration", "ShortNameImageReferences", "SigstoreSignatureMirroring"]
    assert risks["SigstoreSignatureMirroring"]["fixedIn"] == "4.21.1"
    assert risks["SigstoreSignatureMirroring"]["verdict"] == "cannot evaluate offline"
    ovs = ur.risks("4.21.3", "4.22.17")["risks"]
    assert [(r["name"], r["verdict"], r["fixedIn"]) for r in ovs] == [
        ("MultiArchPayloadMissingOpenVSwitch", "check", "4.22.18")
    ]
    assert ovs[0]["appliesWhen"] == 'the invoker is not "hypershift" (hosted control planes)'


def test_node_label_platform_and_egress_ip_shapes() -> None:
    risks = _by_name(ur.risks("4.17.10", "4.18.1"))
    assert risks["NonZonalAzureMachineSetScaling"]["appliesWhen"] == "the platform type is Azure"
    egress = risks["OVNEgressIPFailure"]
    assert egress["appliesWhen"] == "at least one egress IP is assigned to a node"
    assert egress["readOnlyCommands"] == ["oc get egressips.k8s.ovn.org"]
    labels = [
        r
        for r in ur.get_index().records
        if "kube_node_labels" in json.dumps(r.get("matchingRules")) and "topk(1," in json.dumps(r["matchingRules"])
    ]
    seen = {ur.evaluate(r["matchingRules"]).get("appliesWhen") for r in labels}
    assert {
        "at least one node has kubernetes.io/arch=s390x",
        "at least one node has node.openshift.io/os_id=rhel",
    } <= seen


# ---------------------------------------------------------------- edges that do not match


def test_non_matching_edges_and_targets_outside_the_snapshot() -> None:
    assert _names(ur.risks("4.19.20", "4.20.12")) == ["ARO420UDRWorkerNodesFail"]  # 4.19.20 is past [0-9]|1[0-7]
    quiet = ur.risks("4.20.6", "4.20.7")
    assert quiet["risks"] == [] and quiet["covered"] is True
    assert "No risk is declared" in quiet["note"] and COMMIT[:12] in quiet["note"]
    old = ur.risks("4.16.1", "4.17.2")
    assert old["risks"] == [] and old["covered"] is False and "4.18 and later" in old["note"]
    new = ur.risks("4.22.17", "4.23.1")
    assert new["risks"] == [] and new["covered"] is False and "newer than" in new["note"]
    for out in (quiet, old, new):
        assert "channel" in out["channelNote"]


def test_a_version_that_matches_from_only_partially_does_not_match() -> None:
    # `4[.]20[.]([0-9]|1[0-4])[+].*`: 4.20.15 starts like 4.20.1 but is not in the declared range
    assert ur.risks("4.20.15", "4.21.4")["risks"] == []
    # `4[.]20[.]12[+].*`: 4.20.1 is a prefix of 4.20.12 and 4.20.120 extends it; neither is 4.20.12
    for current in ("4.20.1", "4.20.120"):
        assert "SigstoreSignatureMirroring" not in _names(ur.risks(current, "4.21.0")), current
    # `^4[.]18[.]1[6-8][+].*$`
    assert "AlertmanagerV1NotSupported" in _names(ur.risks("4.18.16", "4.19.0"))
    for current in ("4.18.1", "4.18.160", "4.18.6"):
        assert "AlertmanagerV1NotSupported" not in _names(ur.risks(current, "4.19.0")), current


def test_unanchored_patterns_match_as_the_update_service_matches_them() -> None:
    """4.18.1-LabeledMachineConfigAndContainerRuntimeConfigBlocksMCO.yaml has
    ``from: 4[.](17[.](1[01]|0-.*|[0-9])|18.0-(ec[.].*|rc[.][0-3]))``: no ``[+].*`` tail, so a full match of
    4.17.5+amd64 fails, but Cincinnati's unanchored search covers 4.17.5, and every other 4.17.z too (``[0-9]``
    matches its first digit: it finds 4.17.1 in 4.17.15). That is the edge the update service serves, so it is the
    answer."""
    name = "LabeledMachineConfigAndContainerRuntimeConfigBlocksMCO"
    for current in ("4.17.5", "4.17.11", "4.17.15", "4.17.20"):
        assert name in _names(ur.risks(current, "4.18.1")), current
    assert name not in _names(ur.risks("4.16.30", "4.18.1"))


# ---------------------------------------------------------------- hostile data and input


def _record(frm: str, rules: list[dict[str, Any]] | None = None, name: str = "Synthetic") -> dict[str, Any]:
    return {
        "to": "4.21.4",
        "from": frm,
        "name": name,
        "url": "https://example.invalid/risk",
        "message": "synthetic",
        "matchingRules": [{"type": "Always"}] if rules is None else rules,
        "source": f"blocked-edges/4.21.4-{name}.yaml",
    }


META = {"retrievedAt": "2026-10-29", "commit": "0" * 40, "commitDate": "2026-10-29T00:00:00+00:00"}


@pytest.mark.parametrize(
    "pattern",
    [
        r"^4[.]20[.](?=3)",  # look-ahead
        r"^(4)[.]20[.]\1",  # back-reference
        r"(?i)^4[.]20",  # inline flags
        r"\b4[.]20",  # word boundary
        "4" * 300,  # longer than the bound
        r"^4[.]20[.]3{1000}",  # counted repetition beyond the bound
        r"((((4{20}){20}){20}){20})",  # expands past the state bound
        r"^4[.]20[.](3",  # unbalanced
        r"^4[.]20[.]3**",  # a quantifier on a quantifier
        r"[z-a]",  # reversed range
    ],
)
def test_hostile_from_patterns_are_refused_and_reported(pattern: str) -> None:
    with pytest.raises(ur.PatternError):
        ur.compile_from(pattern)
    out = ur.Index([_record(pattern)], META).risks("4.20.3", "4.21.4")
    [r] = out["risks"]
    assert r["verdict"] == "cannot evaluate offline" and "from" in r["reason"] and r["fromEvaluated"] is False
    assert len(r["from"]) <= ur.MAX_PATTERN + 3


def test_the_safe_engine_agrees_with_a_regex_search_on_random_patterns() -> None:
    """Differential check on random patterns of the subset (fixed seed). Groups get only bounded quantifiers here
    because Python's backtracking engine, the reference, does not finish on some nested unbounded ones."""
    rng = random.Random(20261029)
    atoms = ["4", "1", "2", "0", ".", "[.]", "[+]", "[0-9]", "[1-3]", "[^4]", r"\d", r"\.", r"\+", "a", "m"]

    def gen(depth: int = 0) -> str:
        parts = []
        for _ in range(rng.randint(1, 4)):
            roll = rng.random()
            if roll < 0.15 and depth < 3:
                body = gen(depth + 1) + ("|" + gen(depth + 1) if rng.random() < 0.5 else "")
                parts.append(rng.choice(["(", "(?:"]) + body + ")" + rng.choice(["", "?", "{2}", "{0,2}", "??"]))
            elif roll < 0.2:
                parts.append(rng.choice(["^", "$"]))
            else:
                parts.append(rng.choice(atoms) + rng.choice(["", "", "*", "+", "?", "{2}", "{0,2}", "{1,}", "*?"]))
        return "".join(parts)

    texts = ["4.20.3+amd64", "4.17.15+s390x", "4.2+", "", "44.1.0+multi", "a", "1.2.3"]
    checked = 0
    for _ in range(1500):
        pattern = gen()
        try:
            reference = re.compile(pattern)
            rx = ur.compile_from(pattern)
        except (re.error, ur.PatternError):
            continue
        for t in texts:
            assert rx.search(t) == bool(reference.search(t)), (pattern, t)
        checked += 1
    assert checked > 1400


def test_backtracking_bombs_are_linear() -> None:
    """Patterns that take exponential time in a backtracking engine run in time linear in the input here."""
    for pattern in (r"^(([0-9]|[0-9.])+)+x$", r"^(4|4.|4.2|4.20|[0-9.]+)*z", r"(.*.*.*.*.*.*.*.*.*.*)*q"):
        rx = ur.compile_from(pattern)
        with bounds.bounded(bounds.BACKTRACKING, honest_seconds=HONEST_BOMB, guards=f"the bomb {pattern}"):
            assert rx.search("4.20.3000000+ppc64le") is False


def test_oversized_and_malformed_versions_are_refused() -> None:
    for bad in ("4.20.3" * 1000, "4.20", "v4.20.3", "4.20.03", "٤.٢٠.٣", "4.20.3+amd64", "4.20.3 x"):
        with pytest.raises(ValueError):
            ur.risks(bad, "4.21.4")
        with pytest.raises(ValidationError):
            tk.UpgradeRisksIn(current=bad, target="4.21.4")
    with pytest.raises(ValueError):  # the library takes no trailing newline (`$` would have let it through)
        ur.risks("4.20.3\n", "4.21.4")
    assert tk.UpgradeRisksIn(current=" 4.20.3\n", target="4.21.4").current == "4.20.3"  # the model strips it first
    with pytest.raises(ValueError, match="newer"):
        ur.risks("4.21.4", "4.20.3")
    with pytest.raises(ValidationError):
        tk.UpgradeRisksIn(current="4.21.4", target="4.21.4")
    with pytest.raises(ValidationError):
        tk.UpgradeRisksIn.model_validate({"current": "4.20.3", "target": "4.21.4", "channel": "stable-4.21"})
    with pytest.raises(ValidationError):
        tk.UpgradeRisksIn(current="4.20.3", target="4.21.4", arch="x86_64")  # type: ignore[arg-type]


def test_promql_outside_the_known_shapes_is_shown_verbatim_never_translated() -> None:
    known = (  # 4.20.12-HyperShiftRedundantRouter.yaml, on one line
        'group by (_id, invoker) (cluster_installer{_id="",invoker="hypershift"}) '
        'or 0 * group by (_id, invoker) (cluster_installer{_id=""})'
    )
    assert ur.translate(known) is not None
    near_misses = [
        known.replace("invoker=", "invoker=~", 1),  # a regex matcher where the shape has an exact one
        known.replace(" or ", " OR "),  # PromQL keywords are case-insensitive; the shapes are not
        known + " > 0",  # anything added changes the meaning
        known.replace('"hypershift"', '"hyper\\"shift"'),  # escapes in a value
        known.replace('"hypershift"', '"hyper shift"'),  # a value that is not a name
        'max(cluster_version_capability{name="Console"}) # comment',
        "x" * 5000,
    ]
    for q in near_misses:
        assert ur.translate(q) is None, q
        v = ur.evaluate([{"type": "PromQL", "promql": {"promql": q}}])
        assert v["verdict"] == "cannot evaluate offline" and v["promql"] == q


def test_matching_rules_are_walked_as_the_cluster_walks_them() -> None:
    assert ur.evaluate([])["verdict"] == "applies"  # a blocked edge without conditions
    assert ur.evaluate([{"type": "Fleet", "fleet": {"doesNotMatch": ["ARO-HCP"]}}])["verdict"] == (
        "cannot evaluate offline"
    )
    assert ur.evaluate([{"type": "FutureType"}, {"type": "Always"}])["verdict"] == "applies"
    only_unknown = ur.evaluate([{"type": "FutureType"}])
    assert only_unknown["verdict"] == "applies" and "not recommended" in only_unknown["reason"]
    first = ur.evaluate(
        [
            {"type": "PromQL", "promql": {"promql": 'max(cluster_version_capability{name="Console"})'}},
            {"type": "Fleet", "fleet": {"doesNotMatch": ["ARO-HCP"]}},
        ]
    )
    assert first["verdict"] == "check" and first["otherRules"] == [
        {"type": "Fleet", "fleet": {"doesNotMatch": ["ARO-HCP"]}}
    ]


def test_architecture_specific_patterns_say_which_architectures() -> None:
    idx = ur.Index([_record(r"4[.]20[.].*[+]s390x", name="S390xOnly"), _record(r".*", name="Everywhere")], META)
    out = idx.risks("4.20.3", "4.21.4")
    risks = _by_name(out)
    assert risks["S390xOnly"]["architectures"] == ["s390x"] and "architectures" not in risks["Everywhere"]
    assert _names(idx.risks("4.20.3", "4.21.4", "amd64")) == ["Everywhere"]
    assert _names(idx.risks("4.20.3", "4.21.4", "s390x")) == ["Everywhere", "S390xOnly"]


def test_every_suggested_command_is_read_only_and_paste_safe() -> None:
    commands = set()
    for r in ur.get_index().records:
        v = ur.evaluate(r.get("matchingRules", []))
        commands.update(v.get("readOnlyCommands", []))
    assert len(commands) >= 5
    for c in commands:
        assert classify_step(c) == "read" and split_comment(c)[1] is None and "\n" not in c, c
        assert "secret" not in c.lower(), c


def test_output_is_deterministic_whatever_the_record_order() -> None:
    a = json.dumps(ur.risks("4.18.5", "4.19.0"), sort_keys=True)
    assert a == json.dumps(ur.risks("4.18.5", "4.19.0"), sort_keys=True)
    records = list(ur.get_index().records)
    random.Random(7).shuffle(records)
    shuffled = ur.Index(records, ur.get_index().meta)
    assert json.dumps(shuffled.risks("4.18.5", "4.19.0"), sort_keys=True) == a


# ---------------------------------------------------------------- surfaces


def test_tool_cli_and_knowledge_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    spec = {s.name: s for s in kit.specs()}["upgrade_risks"]
    assert spec.read_only and not spec.open_world and spec.tier is None
    assert spec.model.model_json_schema()["additionalProperties"] is False
    out = spec.fn(tk.UpgradeRisksIn(current="4.20.3", target="4.21.4"))
    assert _names(out) == ["EtcdStorageVersion3Migration"]

    assert cli_main(["upgrade-risks", "--from", "4.20.3", "--to", "4.21.4"]) == 0
    text = capsys.readouterr().out
    assert "APPLIES" in text and "EtcdStorageVersion3Migration" in text and COMMIT[:12] in text
    assert cli_main(["upgrade-risks", "--from", "4.19.5", "--to", "4.20.12", "--format", "json"]) == 0
    assert _names(json.loads(capsys.readouterr().out)) == ["ARO420UDRWorkerNodesFail", "HyperShiftRedundantRouter"]
    assert cli_main(["upgrade-risks", "--from", "4.20", "--to", "4.21.4"]) == 2
    assert "x.y.z" in capsys.readouterr().err

    st = status(tmp_path)
    assert st["upgradeRisksAsOf"] == ur.get_index().knowledge()["upgradeRisksAsOf"]
    assert st["note"].startswith("Built-in knowledge reviewed") and "update risks" in st["note"]
    assert "update risks as of" in line(tmp_path)


def test_mcp_result_carries_the_knowledge_date(tmp_path: Path) -> None:
    import anyio
    from mcp import Client

    from kube_noob.server.mcp_app import build_server

    server = build_server(load_settings(overrides={"dataDir": str(tmp_path)}))

    async def run() -> Any:
        async with Client(server) as c:
            return await c.call_tool("kubenoob_upgrade_risks", {"current": "4.20.3", "target": "4.21.4"})

    res = anyio.run(run)
    assert not res.is_error
    data = res.structured_content or json.loads(res.content[0].text)
    payload = data.get("result", data)
    assert payload["knowledgeAsOf"].startswith("knowledge as of ") and "update risks as of" in payload["knowledgeAsOf"]
    assert [r["name"] for r in payload["risks"]] == ["EtcdStorageVersion3Migration"]
