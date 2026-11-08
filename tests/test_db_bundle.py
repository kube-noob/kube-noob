"""DB1: the public kube-noob-db bundle holds only what may be shared, is checked as a gate, imports whole or not at
all, and seeds pods when a newer image rolls out (requirements R1.3)."""

from __future__ import annotations

import io
import json
import re
import shutil
import tarfile
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

from kube_noob import known_issues as ki
from kube_noob.cli import main
from kube_noob.sources import db_bundle
from kube_noob.sources.corpus import read_manifest, write_shard

ROOT = Path(__file__).resolve().parents[1]
BUILT = datetime(2026, 10, 28, 6, 0, tzinfo=UTC)


def _rec(i: str, source: str, lic: str, redistributable: bool, text: str = "Pods and Services.") -> dict[str, Any]:
    return {
        "id": i,
        "title": i,
        "text": text,
        "sourceId": source,
        "license": lic,
        "redistributable": redistributable,
        "url": f"https://example.com/{i}",
    }


def _data(tmp: Path) -> Path:
    data = tmp / "data"
    if data.is_dir():
        return data
    write_shard(
        data, "k8s-docs", [_rec("k1", "k8s-docs", "CC-BY-4.0", True), _rec("k2", "k8s-docs", "CC-BY-4.0", True)]
    )
    write_shard(data, "history", [_rec("h1", "history:openshift", "facts derived from public Git metadata", True)])
    write_shard(data, "awesome-kubernetes", [_rec("a1", "awesome-kubernetes", "CC-BY-NC-4.0", False)])
    write_shard(
        data, "jira-ocpbugs", [_rec("j1", "jira:OCPBUGS", "Red Hat Jira (public)", False, "PRIVATE-TICKET-BODY")]
    )
    write_shard(
        data,
        "jira-insights",
        [_rec("i1", "jira-insights:OCPBUGS", "aggregate statistics derived by kube-noob", True, "counts")],
    )
    kdir = data / "known_issues"
    kdir.mkdir()
    src = resources.files("kube_noob").joinpath("data", "known_issues", "openshift-4.21-known-1.json")
    doc = json.loads(src.read_text(encoding="utf-8"))
    doc["retrievedAt"] = "2099-01-01"  # newer than the bundled snapshot, so the index prefers it
    (kdir / "openshift-4.21-known-1.json").write_text(json.dumps(doc), encoding="utf-8")
    return data


def _members(archive: Path) -> dict[str, bytes]:
    with tarfile.open(archive, "r:gz") as tf:
        return {m.name: tf.extractfile(m).read() for m in tf.getmembers() if m.isfile()}  # type: ignore[union-attr]


def _retar(archive: Path, files: dict[str, bytes], out: Path, extra: list[tarfile.TarInfo] | None = None) -> Path:
    with tarfile.open(out, "w:gz") as tf:
        for name, body in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
        for info in extra or []:
            tf.addfile(info)
    return out


def test_the_bundle_ships_only_what_may_be_shared(tmp_path: Path) -> None:
    data = _data(tmp_path)
    out = db_bundle.build(data, tmp_path / "dist" / "kube-noob-db.tgz", BUILT)
    assert out["shards"] == ["history", "k8s-docs"] and out["records"] == 3 and out["knownIssueFiles"] == 1
    assert out["leftOut"] == ["awesome-kubernetes", "jira-insights", "jira-ocpbugs"]
    assert out["licenses"] == {"CC-BY-4.0": 2, "facts derived from public Git metadata": 1}
    files = _members(Path(out["bundle"]))
    assert sorted(files) == [
        "ATTRIBUTION.md",
        "MANIFEST.json",
        "history.jsonl",
        "k8s-docs.jsonl",
        "known_issues/openshift-4.21-known-1.json",
    ]
    blob = b"".join(files.values())
    assert b"PRIVATE-TICKET-BODY" not in blob and b"jira:" not in blob and b"jira-insights" not in blob
    attribution = files["ATTRIBUTION.md"].decode()
    assert "The Kubernetes Authors, CC BY 4.0" in attribution and "OpenShift release notes" in attribution
    manifest = json.loads(files["MANIFEST.json"])
    assert (
        manifest["bundle"]["format"] == "kube-noob-db/1"
        and manifest["bundle"]["builtAt"] == "2026-10-28T06:00:00+00:00"
    )
    assert set(manifest["shards"]) == {"history", "k8s-docs"}
    again = db_bundle.build(data, tmp_path / "again.tgz", BUILT)
    assert again["sha256"] == out["sha256"]  # reproducible: same data, same bytes
    assert oct(Path(out["bundle"]).stat().st_mode & 0o777) == "0o644"  # public: the image's users can read it
    assert db_bundle.check_archive(Path(out["bundle"])) == []


def test_a_shard_marked_shareable_with_a_private_record_is_refused(tmp_path: Path) -> None:
    data = _data(tmp_path)
    write_shard(
        data, "k8s-docs", [_rec("k1", "k8s-docs", "CC-BY-4.0", True), _rec("x", "k8s-docs", "CC-BY-4.0", False)]
    )
    manifest = read_manifest(data)
    manifest["shards"]["k8s-docs"]["redistributable"] = True  # a manifest that lies about its records
    (data / "corpus" / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(db_bundle.BundleError, match="record 'x' is not redistributable"):
        db_bundle.build(data, tmp_path / "x.tgz", BUILT)
    assert not (tmp_path / "x.tgz").exists()


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda f: f.update({"k8s-docs.jsonl": f["k8s-docs.jsonl"] + b"\n"}), "k8s-docs.jsonl: checksum mismatch"),
        (lambda f: f.update({"notes.txt": b"hi"}), "notes.txt: not listed in MANIFEST.json"),
        (lambda f: f.pop("ATTRIBUTION.md"), "ATTRIBUTION.md is missing"),
        (lambda f: f.pop("history.jsonl"), "history.jsonl: listed but missing"),
        (lambda f: f.update({"MANIFEST.json": b'{"shards": {}}'}), "is not a kube-noob-db/1 manifest"),
    ],
)
def test_the_gate_catches_every_broken_rule(tmp_path: Path, change: Any, problem: str) -> None:
    built = Path(db_bundle.build(_data(tmp_path), tmp_path / "ok.tgz", BUILT)["bundle"])
    files = _members(built)
    change(files)
    bad = _retar(built, files, tmp_path / "bad.tgz")
    assert any(problem in p for p in db_bundle.check_archive(bad)), db_bundle.check_archive(bad)


def _with_shard(tmp_path: Path, name: str, recs: list[dict[str, Any]], marked: bool = True) -> Path:
    import hashlib

    built = Path(db_bundle.build(_data(tmp_path), tmp_path / "ok.tgz", BUILT)["bundle"])
    files = _members(built)
    body = "".join(json.dumps(r) + "\n" for r in recs).encode()
    files[f"{name}.jsonl"] = body
    manifest = json.loads(files["MANIFEST.json"])
    manifest["shards"][name] = {
        "file": f"{name}.jsonl",
        "sha256": hashlib.sha256(body).hexdigest(),
        "redistributable": marked,
        "records": len(recs),
    }
    files["MANIFEST.json"] = json.dumps(manifest).encode()
    return _retar(built, files, tmp_path / "bad.tgz")


def test_jira_data_and_unshareable_licenses_fail_the_gate(tmp_path: Path) -> None:
    jira = _with_shard(tmp_path, "jira-rox", [_rec("r1", "jira:ROX", "CC-BY-4.0", True)])
    problems = db_bundle.check_archive(jira)
    assert any("Jira data never goes into the public bundle" in p for p in problems)
    assert any("comes from Jira" in p for p in problems)
    nc = _with_shard(tmp_path, "nc", [_rec("n1", "awesome", "CC-BY-NC-4.0", True)])
    assert any("not on the allow-list" in p for p in db_bundle.check_archive(nc))
    private = _with_shard(tmp_path, "priv", [_rec("p1", "org:wiki", "Apache-2.0", False)], marked=False)
    problems = db_bundle.check_archive(private)
    assert any("marked not redistributable" in p for p in problems)
    assert any("record 'p1' is not redistributable" in p for p in problems)


def test_links_traversal_and_bombs_are_refused(tmp_path: Path) -> None:
    built = Path(db_bundle.build(_data(tmp_path), tmp_path / "ok.tgz", BUILT)["bundle"])
    files = _members(built)
    link = tarfile.TarInfo("evil.jsonl")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    assert any(
        "not a regular file" in p for p in db_bundle.check_archive(_retar(built, files, tmp_path / "l.tgz", [link]))
    )
    up = dict(files)
    up["../escape.jsonl"] = b"{}"
    assert db_bundle.check_archive(_retar(built, up, tmp_path / "u.tgz"))  # refused by the extraction filter
    assert not (tmp_path / "escape.jsonl").exists()
    many = {f"x{i}.jsonl": b"" for i in range(db_bundle.MAX_MEMBERS + 1)}
    assert any("more than" in p for p in db_bundle.check_archive(_retar(built, many, tmp_path / "m.tgz")))
    garbage = tmp_path / "g.tgz"
    garbage.write_bytes(b"not a tarball")
    assert any("not a readable .tgz" in p for p in db_bundle.check_archive(garbage))


def test_import_is_whole_or_nothing_and_feeds_the_known_issue_index(tmp_path: Path) -> None:
    built = Path(db_bundle.build(_data(tmp_path), tmp_path / "ok.tgz", BUILT)["bundle"])
    pod = tmp_path / "pod"
    bad = _with_shard(tmp_path, "jira-rox", [_rec("r1", "jira:ROX", "CC-BY-4.0", True)])
    with pytest.raises(db_bundle.BundleError, match="nothing imported"):
        db_bundle.import_bundle(bad, pod)
    assert not (pod / "corpus").exists() and not (pod / "known_issues").exists()
    out = db_bundle.import_bundle(built, pod)
    assert sorted(out["imported"]) == ["history", "k8s-docs"] and out["knownIssueFiles"] == 1
    assert set(read_manifest(pod)["shards"]) == {"history", "k8s-docs"}
    assert ki.get_index(pod).meta["retrievedAt"] == "2099-01-01"
    assert json.loads((pod / "corpus" / "DB_SEED.json").read_text())["builtAt"] == "2026-10-28T06:00:00+00:00"


def test_pods_import_a_newer_bundle_on_start_and_skip_an_older_one(tmp_path: Path) -> None:
    data = _data(tmp_path)
    pod = tmp_path / "pod"
    assert db_bundle.seed_on_start(pod) is None  # no seed folder
    seed = pod / "seed-db"
    db_bundle.build(data, seed / "kube-noob-db.tgz", BUILT)
    first = db_bundle.seed_on_start(pod)
    assert first and first["bundle"]["builtAt"] == "2026-10-28T06:00:00+00:00"
    assert db_bundle.seed_on_start(pod) is None  # the same bundle: nothing to do
    shutil.rmtree(seed)
    db_bundle.build(data, seed / "kube-noob-db.tgz", datetime(2026, 10, 27, tzinfo=UTC))
    assert db_bundle.seed_on_start(pod) is None  # older than what the pod has
    shutil.rmtree(seed)
    db_bundle.build(data, seed / "kube-noob-db.tgz", datetime(2026, 10, 29, tzinfo=UTC))
    newer = db_bundle.seed_on_start(pod)
    assert newer and newer["bundle"]["builtAt"] == "2026-10-29T00:00:00+00:00"


def test_a_shard_over_the_member_cap_is_written_as_parts_and_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Red Hat VEX shard outgrew `MAX_MEMBER`. Raising the cap would fail again next quarter. A shard is
    written as `<name>.jsonl`, `<name>-2.jsonl`, ... each under the cap, and a read puts the parts back together.
    A later write that fits in one file removes the parts it no longer uses, including from the manifest."""
    from kube_noob.sources import corpus
    from kube_noob.vuln import vex

    assert corpus.PART_MAX < db_bundle.MAX_MEMBER
    monkeypatch.setattr(corpus, "PART_MAX", 80)
    records = []
    for i in range(4):
        records.append(
            {
                "id": f"vex-{i}",
                "title": f"CVE-2099-100{i}",
                "text": "x" * 40,
                "sourceId": "redhat-vex",
                "license": "CC-BY-4.0",
                "redistributable": True,
                "url": "https://access.redhat.com/security/data",
                "cve": f"CVE-2099-100{i}",
                "statements": [{"component": "nginx", "status": "fixed", "cpe": "cpe:/a:redhat:openshift:4"}],
            }
        )
    entry = write_shard(tmp_path, "redhat-vex", records)
    assert entry["parts"] > 1 and entry["records"] == 4
    files = sorted((tmp_path / "corpus").glob("redhat-vex*.jsonl"))
    assert len(files) == entry["parts"]
    assert all(p.stat().st_size <= db_bundle.MAX_MEMBER for p in files)
    built = db_bundle.build(tmp_path, tmp_path / "kube-noob-db.tgz")
    assert built["records"] == 4 and "redhat-vex" in built["shards"]
    assert set(vex.load(tmp_path).by_cve) == {f"CVE-2099-100{i}" for i in range(4)}
    monkeypatch.setattr(corpus, "PART_MAX", 10_000_000)
    write_shard(tmp_path, "redhat-vex", records[:1])
    assert [p.name for p in (tmp_path / "corpus").glob("redhat-vex*.jsonl")] == ["redhat-vex.jsonl"]
    assert set(read_manifest(tmp_path)["shards"]) == {"redhat-vex"}


def test_cli_bundle_check_import_and_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = _data(tmp_path)
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(data))
    out = tmp_path / "dist" / "kube-noob-db.tgz"
    assert main(["corpus", "db-bundle", "-o", str(out)]) == 0
    text = capsys.readouterr().out
    assert "3 records in 2 shards, 1 known-issue files" in text
    assert "left out (not redistributable or Jira): awesome-kubernetes, jira-insights, jira-ocpbugs" in text
    assert main(["corpus", "db-check", str(out)]) == 0
    assert capsys.readouterr().out.strip() == f"{out}: ok"
    bad = _with_shard(tmp_path, "jira-rox", [_rec("r1", "jira:ROX", "CC-BY-4.0", True)])
    assert main(["corpus", "db-check", str(bad), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert main(["corpus", "db-check", str(tmp_path / "missing.tgz")]) == 2
    pod = tmp_path / "pod"
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(pod))
    assert main(["corpus", "import", str(out), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["bundle"]["format"] == "kube-noob-db/1"
    served = tmp_path / "served"
    db_bundle.build(data, served / "seed-db" / "kube-noob-db.tgz", BUILT)
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(served))
    ran: list[str] = []
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: ran.append("uvicorn"))
    main(["serve", "--allow-unauthenticated"])
    assert ran == ["uvicorn"] and set(read_manifest(served)["shards"]) == {"history", "k8s-docs"}
    assert "kube-noob-db imported from" in capsys.readouterr().err


def test_the_chart_pins_the_image_by_digest() -> None:
    values = yaml.safe_load((ROOT / "deploy/helm/kube-noob/values.yaml").read_text())
    schema = json.loads((ROOT / "deploy/helm/kube-noob/values.schema.json").read_text())
    validator = jsonschema.Draft7Validator(schema)
    validator.validate(values)
    assert values["db"] == {
        "enabled": False,
        "image": {"repository": "ghcr.io/kube-noob/kube-noob-db", "digest": ""},
        "path": "/kube-noob-db/kube-noob-db.tgz",
        "sizeLimit": "2Gi",
    }
    for bad in ({"tag": "latest"}, {"digest": "latest"}):
        v = yaml.safe_load(yaml.safe_dump(values))
        v["db"]["image"].update(bad)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(v)
    dep = (ROOT / "deploy/helm/kube-noob/templates/deployment.yaml").read_text()
    assert 'regexMatch "^sha256:[a-f0-9]{64}$"' in dep
    assert '"{{ .Values.db.image.repository }}@{{ .Values.db.image.digest }}"' in dep
    cf = (ROOT / "Containerfile.db").read_text()
    assert "USER 1001" in cf and "COPY --chown=0:0 --chmod=0444 dist/kube-noob-db/kube-noob-db.tgz" in cf
    wf = yaml.safe_load((ROOT / ".github/workflows/db-image.yml").read_text())
    assert wf["permissions"] == {"contents": "read"} and "permissions" not in wf["jobs"]["db"]
    steps = [s.get("name", "") for s in wf["jobs"]["db"]["steps"]]
    assert "Gate: nothing private, nothing unlicensed" in steps and "Gate the image's own copy" in steps
    assert steps[0] == "Start at a random offset (scheduled runs)"
    publish = wf["jobs"]["publish"]
    assert publish["if"] == "vars.DB_IMAGE_PUBLISH == 'true' && github.ref == 'refs/heads/main'"
    names = [s.get("name", "") for s in publish["steps"]]
    assert names.index("Gate again: the archive this job pushes") < names.index("Keyless-sign the image (Sigstore)")
    assert "Gate the pushed image" in names
    for job in wf["jobs"].values():
        for step in job["steps"]:
            uses = step.get("uses", "")
            assert not uses or re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", uses), uses  # every action pinned by SHA
