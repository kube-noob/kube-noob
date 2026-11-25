"""Every exit code a published table documents has an input that produces it, and produces exactly it.

`test_directory_plugin` runs each documented command once and asserts its code is one the row admits. That is
necessary and not sufficient, and G384 measured why: every one of the 52 rows admits `0`, because `0` is a real
outcome of all 52 commands, and each row runs on ONE input. So a build in which every command returned 0 passed
all 52 rows -- verified there by wrapping `cli.main` to return 0 and watching `52 passed`.

The gap is the nonzero half. A row saying `1` = denied passes while the command returns 0 on its fixture, which
is how `rhacs compare` carried `always 0` for months against a `return 1 if out["unexplained"] else 0`: its
fixture has no unexplained policy, so nothing ever drove the 1.

So this file inverts the question. For each (command, code) the tables document, it names an input chosen to
produce THAT code and asserts equality, not membership. A documented code with no input here fails, because a
contract nothing exercises is a contract nothing holds -- the same rule the product applies to its own verdicts,
turned on its own table.

The file also runs the question backwards. A row that documents a code nothing drives is one hole; an input that
produces a code NO row documents is the other, and it is the one G206 and G237 keep finding -- a check that walks
only from the table to the code passes while the command returns a fifth thing the reader's gate has never heard
of. `protocol review` on a directory holding one unreadable file returns 5, and both tables said `0`, `1`, `3`.

No exemption is left. The one that was here claimed `ticket` could not reach 0 without `--online`, and that was
false: `sources.jira.sync_projects` takes a client, so a fake one seeds the local copy offline and the 0 is
driven like every other code. An exemption is an assertion about the product that nothing measures, so the list
is asserted empty and re-opening it has to be a deliberate edit to this file.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LITE = ROOT / "plugin" / "kube-noob-skills"
EXAMPLE = str(ROOT / "examples" / "insecure-deployment.yaml")

#: A code in a documented column, as `test_directory_plugin` reads it: the tables MARK every code they commit to.
_CODE = re.compile(r"`(141|[0-5])`")

#: Codes no offline input can reach, with the reason. Empty, and `test_the_exemption_list_is_empty` keeps it that
#: way: the only entry it ever held was wrong about the product. Checked against the tables below too, so a row
#: that stops documenting one of these would stop excusing it.
EXEMPT: dict[tuple[str, int], str] = {}


def _by_skill() -> dict[str, dict[str, set[int]]]:
    """Skill -> command -> the codes THAT skill's row marks.

    Per skill, not pooled. A reader has one SKILL.md in front of them, so a code `kubernetes-core` omits is
    undocumented for everyone using `kubernetes-core`, however plainly `openshift-platform` spells it out.
    Measured: with the codes pooled, deleting the whole clause from one skill's rows left the suite green.
    """

    def section(text: str, heading: str) -> str:
        i = text.find(f"\n{heading}\n")
        assert i >= 0, heading
        j = text.find("\n## ", i + len(heading) + 2)
        return text[i : j if j >= 0 else len(text)]

    out: dict[str, dict[str, set[int]]] = {}
    for p in sorted(LITE.glob("skills/*/SKILL.md")):
        rows: dict[str, set[int]] = {}
        for line in section(p.read_text(encoding="utf-8"), "## Which command").splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) != 4 or not cells[0].startswith("`"):
                continue
            rows.setdefault(cells[0].strip("`"), set()).update(int(m) for m in _CODE.findall(cells[1]))
        if rows:
            out[p.parent.name] = rows
    assert len(out) >= 5, f"read {len(out)} skills; the tables were not read, so this file measures nothing"
    return out


def _documented() -> dict[str, set[int]]:
    """Command -> every code any published skill marks for it.

    The pooled view, for the coverage direction only: a code documented ANYWHERE needs an input here. For the
    other direction -- is the code a command returns written down -- use `_by_skill`, because pooling hides a
    row that omits it.
    """
    out: dict[str, set[int]] = {}
    for rows in _by_skill().values():
        for command, codes in rows.items():
            out.setdefault(command, set()).update(codes)
    assert len(out) >= 30, f"found {len(out)} commands; the tables were not read, so this file measures nothing"
    return out


# --- the inputs ------------------------------------------------------------------------------------------------

HARDENED = """\
apiVersion: v1
kind: Pod
metadata: {name: ok, namespace: shop}
spec:
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: c
      image: registry.example.com/c@sha256:2222222222222222222222222222222222222222222222222222222222222222
      readinessProbe: {httpGet: {path: /h, port: 8080}}
      livenessProbe: {httpGet: {path: /h, port: 8080}}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        capabilities: {drop: ["ALL"]}
      resources: {limits: {cpu: "1", memory: 256Mi}, requests: {cpu: 100m, memory: 128Mi}}
"""

#: The API server refuses this document, so `fix` refuses it too: 4, which is not 1 (G382).
DUP_KEY = """\
apiVersion: v1
kind: Pod
metadata: {name: d, namespace: s}
metadata: {name: e, namespace: s}
spec: {containers: [{name: c, image: x}]}
"""

#: An object under a group no rule reads. It is HERE and unjudged, which is what withholds a pass.
REFUSED_CRB = """\
apiVersion: rbac.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: everyone-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: Group, apiGroup: rbac.authorization.k8s.io, name: "system:authenticated"}]
"""

#: An internet-facing privileged workload whose ServiceAccount is cluster-admin: eight ranked paths, top score 30.
#: `examples/insecure-deployment.yaml` ranks ZERO paths, so `--fail-above` can never fire on it -- a test that
#: drove the 1 from that file would have passed while proving nothing.
ATTACK_PATH = """\
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 80, targetPort: 8080}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      serviceAccountName: web
      hostPID: true
      containers:
        - name: web
          image: registry.example.com/web:latest
          ports: [{containerPort: 8080}]
          securityContext: {privileged: true}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: web, namespace: shop}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: web-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: web, namespace: shop}]
"""

#: A worked answer that PASSES `k8s-ex-hardened-deployment`. It is here and not in `examples/`, on purpose:
#: `examples/exercise-answer.yaml` is deliberately a first attempt ("Grade it, read the feedback, fix,
#: resubmit"), so it drives the 1 and must keep failing. Nothing shipped drives the 0.
PASSING_ANSWER = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: demo}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: web
          image: nginxinc/nginx-unprivileged:1.27.2
          ports: [{name: http, containerPort: 8080}]
          readinessProbe: {httpGet: {path: /, port: http}, periodSeconds: 10}
          livenessProbe: {httpGet: {path: /, port: http}, periodSeconds: 20}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            seccompProfile: {type: RuntimeDefault}
            capabilities: {drop: ["ALL"]}
          resources: {limits: {cpu: "1", memory: 256Mi}, requests: {cpu: 100m, memory: 128Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: demo}
spec: {selector: {app: web}, ports: [{name: http, port: 80, targetPort: http}]}
"""


#: A document no parser accepts. Not a missing path, which is a usage error (2), and not an object of a shape no
#: rule reads, which is a refusal the audit reports: this one cannot be turned into objects at all.
TRUNCATED = "a: [unclosed\n"


def _unreadable(d: Path, name: str = "truncated.yaml") -> str:
    """One named file that cannot be read. A command handed this refuses the input itself: 4."""
    where = d / "unreadable"
    where.mkdir(parents=True, exist_ok=True)
    return _write(where, name, TRUNCATED)


def _refused_dir(d: Path, name: str, readable: str) -> str:
    """A directory holding one readable object and one that cannot be read.

    This is the other half of the contract and a different answer. The command DID read something, so it is not
    refusing the input; it refuses to answer about the rest on evidence it knows is partial: 5. Measured uniform
    across audit, validate, fix, protocol and policy reach -- 4 for the named file, 5 for the directory.
    """
    where = d / name
    where.mkdir(parents=True, exist_ok=True)
    (where / "ok.yaml").write_text(readable, encoding="utf-8")
    (where / "truncated.yaml").write_text(TRUNCATED, encoding="utf-8")
    return str(where)


def _seeded_jira(d: Path) -> tuple[str, str]:
    """A local Jira copy, built offline from a fake client, and a key that is in it.

    `sync_projects` takes the client, so nothing here touches the network: this is the measurement that the old
    `("ticket", 0)` exemption was wrong about.
    """
    from kube_noob.sources.jira import sync_projects
    from tests.test_tickets import BASE, MIRROR, NOW, OVN, ROUTER, ROUTER_DUP, SENSOR, FakeJira, _client

    data = d / "jira-copy"
    data.mkdir(parents=True, exist_ok=True)
    fake = FakeJira({"OCPBUGS": [ROUTER, MIRROR, OVN, ROUTER_DUP], "ROX": [SENSOR]})
    sync_projects(_client(fake, []), ["OCPBUGS", "ROX"], data, BASE, NOW)
    return str(data), str(ROUTER["key"])


def _write(d: Path, name: str, body: str) -> str:
    p = d / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return str(p)


def _generated(d: Path, which: str) -> Path:
    """One of the fixture trees `tests/fixtures/<which>/generate.py` builds."""
    out = d / which
    subprocess.run([sys.executable, str(ROOT / "tests" / "fixtures" / which / "generate.py"), str(out)], check=True)
    return out


def _helm_stub(d: Path, rendered: str) -> tuple[str, dict[str, str]]:
    """A chart plus a `helm` on PATH that renders `rendered`, OUTSIDE the chart (`helm_binary` refuses one in it)."""
    chart = d / "chart"
    chart.mkdir(parents=True, exist_ok=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: web\nversion: 0.1.0\n", encoding="utf-8")
    doc = _write(d, "rendered.yaml", rendered)
    bindir = d / "helmbin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "helm"
    stub.write_text(f"#!/bin/sh\ncat '{doc}'\n", encoding="utf-8")
    stub.chmod(0o755)
    return str(chart), {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}


def _rhacs_unexplained(d: Path) -> str:
    """A one-policy export whose criterion names a field this build does not know: `unexplained` is 1, so exit 1."""
    src = json.loads((ROOT / "tests" / "fixtures" / "rhacs" / "default-policies-export.json").read_text("utf-8"))
    policy = json.loads(json.dumps(src["policies"][0]))
    for group in policy.get("policySections") or ():
        for pg in group.get("policyGroups") or ():
            pg["fieldName"] = "A Field From A Newer RHACS"
    policy["name"] = "Uses a field from a newer RHACS"
    return _write(d, "rhacs-newer.json", json.dumps({**src, "policies": [policy]}))


def _partial_must_gather(d: Path) -> str:
    """A must-gather with its `namespaces` tree removed: complete enough to read, not complete enough to finish."""
    whole = _generated(d, "must-gather")
    partial = d / "mg-partial"
    shutil.copytree(whole, partial)
    gather = next(p for p in partial.iterdir() if p.is_dir())
    image = next(p for p in gather.iterdir() if p.is_dir())
    shutil.rmtree(image / "namespaces")
    return str(partial)


#: (command, code) -> the argv tail and any env that produces exactly that code. Built per test, because several
#: inputs are generated. A command whose only documented code is 0 is driven by `test_directory_plugin`'s own
#: fixture; this table carries it too, so the coverage check below can be strict rather than partial.
def _inputs(d: Path) -> dict[tuple[str, int], tuple[list[str], dict[str, str]]]:
    hardened = _write(d, "hardened.yaml", HARDENED)
    refused = _write(d, "refused.yaml", HARDENED + "---\n" + REFUSED_CRB)
    paths = _write(d, "paths.yaml", ATTACK_PATH)
    none: dict[str, str] = {}
    chart_ok, env_ok = _helm_stub(d / "ok", HARDENED)
    chart_bad, env_bad = _helm_stub(d / "bad", (ROOT / "examples" / "insecure-deployment.yaml").read_text("utf-8"))
    cf = ROOT / "tests" / "fixtures" / "containerfile"
    build = ["build", "audit", "-f", str(cf / "KN-B001.bad.Containerfile"), "--context", str(cf)]
    netpol = ["policy", "reach", "-f", str(ROOT / "examples" / "netpol-shop.yaml"), "--from", "web/frontend"]
    mg = str(_generated(d, "must-gather"))
    unreadable = _unreadable(d)
    # Directories, not files. `cli._partial_input` reads a directory as the whole namespace, and only a whole
    # namespace lets the policy hop be judged -- from one file it is `cannot judge` and every walk is a 5, so a
    # single-file fixture could never drive the 0 or the 1 (G394).
    mech = ROOT / "tests" / "fixtures" / "mechanism"
    mech_refused = _refused_dir(d, "refused-mechanism", (mech / "complete" / "bundle.yaml").read_text("utf-8"))
    refused_dir = _refused_dir(d, "refused-manifests", HARDENED)
    refused_netpol = _refused_dir(d, "refused-netpol", (ROOT / "examples" / "netpol-shop.yaml").read_text("utf-8"))
    jira_copy, in_copy = _seeded_jira(d)
    return {
        ("audit", 0): (["audit", "-f", hardened], none),
        ("audit", 1): (["audit", "-f", EXAMPLE], none),
        ("audit", 4): (["audit", "-f", unreadable], none),
        ("audit", 5): (["audit", "-f", refused_dir], none),
        ("validate", 0): (["validate", "-f", hardened], none),
        ("validate", 1): (["validate", "-f", str(ROOT / "tests" / "fixtures" / "bad-bundle.yaml")], none),
        ("validate", 4): (["validate", "-f", unreadable], none),
        ("validate", 5): (["validate", "-f", refused_dir], none),
        ("fix", 0): (["fix", "-f", hardened, "-o", str(d / "f0.yaml")], none),
        ("fix", 1): (["fix", "-f", EXAMPLE, "-o", str(d / "f1.yaml")], none),
        ("fix", 4): (["fix", "-f", _write(d, "dup.yaml", DUP_KEY), "-o", str(d / "f4.yaml")], none),
        ("fix", 5): (["fix", "-f", refused_dir, "-o", str(d / "f5.yaml")], none),
        ("protocol", 0): (["protocol", "review", "-f", hardened], none),
        ("protocol", 1): (["protocol", "review", "-f", EXAMPLE], none),
        ("protocol", 3): (["protocol", "review"], none),
        ("protocol", 4): (["protocol", "review", "-f", unreadable], none),
        ("protocol", 5): (["protocol", "review", "-f", refused_dir], none),
        ("generate", 0): (
            ["generate", "--blueprint", str(ROOT / "examples" / "blueprint.yaml"), "-o", str(d / "g.yaml")],
            none,
        ),
        ("generate", 3): (["generate", "--name", "x", "--namespace", "y", "--image", "z:1", "--expose", "route"], none),
        ("policy reach", 0): ([*netpol, "--to", "shop/orders-api", "--port", "8080"], none),
        ("policy reach", 1): ([*netpol, "--to", "shop/orders-api", "--port", "9999"], none),
        ("policy reach", 4): (
            [
                "policy",
                "reach",
                "-f",
                unreadable,
                "--from",
                "web/frontend",
                "--to",
                "shop/orders-api",
                "--port",
                "8080",
            ],
            none,
        ),
        ("policy reach", 5): (
            [
                "policy",
                "reach",
                "-f",
                refused_netpol,
                "--from",
                "web/frontend",
                "--to",
                "shop/orders-api",
                "--port",
                "8080",
            ],
            none,
        ),
        ("posture reach", 0): (["posture", "reach", "deployment/orders-api", "-n", "shop", "-f", EXAMPLE], none),
        ("posture reach", 2): (["posture", "reach", "deployment/nope", "-n", "shop", "-f", EXAMPLE], none),
        ("posture reach", 4): (
            ["posture", "reach", "deployment/orders-api", "-n", "shop", "-f", unreadable],
            none,
        ),
        ("posture reach", 5): (
            [
                "posture",
                "reach",
                "deployment/orders-api",
                "-n",
                "shop",
                "-f",
                _write(
                    d,
                    "reach5.yaml",
                    (ROOT / "examples" / "insecure-deployment.yaml").read_text("utf-8") + "---\n" + REFUSED_CRB,
                ),
                "--require-complete",
            ],
            none,
        ),
        ("posture scan", 0): (["posture", "scan", "-f", paths], none),
        ("posture scan", 1): (["posture", "scan", "-f", paths, "--fail-above", "1"], none),
        ("posture scan", 4): (["posture", "scan", "-f", unreadable], none),
        ("posture scan", 5): (["posture", "scan", "-f", refused, "--fail-above", "90"], none),
        ("build audit", 0): (build, none),
        ("build audit", 1): ([*build, "--fail-on", "low"], none),
        ("helm-audit", 0): (["helm-audit", chart_ok], env_ok),
        ("helm-audit", 1): (["helm-audit", chart_bad], env_bad),
        ("helm-audit", 4): (["helm-audit", chart_ok], {"PATH": "/nonexistent"}),
        ("must-gather analyze", 0): (["must-gather", "analyze", mg], none),
        ("must-gather analyze", 5): (["must-gather", "analyze", _partial_must_gather(d), "--require-complete"], none),
        ("rhacs compare", 0): (
            ["rhacs", "compare", "-f", str(ROOT / "tests" / "fixtures" / "rhacs" / "default-policies-export.json")],
            none,
        ),
        ("rhacs compare", 1): (["rhacs", "compare", "-f", _rhacs_unexplained(d)], none),
        ("learn mechanism", 0): (
            ["learn", "mechanism", "mech-net-request-to-pod", "-f", str(mech / "complete")],
            none,
        ),
        ("learn mechanism", 1): (
            ["learn", "mechanism", "mech-net-request-to-pod", "-f", str(mech / "broken")],
            none,
        ),
        ("learn mechanism", 4): (
            ["learn", "mechanism", "mech-net-request-to-pod", "-f", unreadable],
            none,
        ),
        ("learn mechanism", 5): (
            ["learn", "mechanism", "mech-net-request-to-pod", "-f", mech_refused],
            none,
        ),
        ("learn progress", 0): (["learn", "progress"], none),
        ("ticket", 0): (["ticket", in_copy], {"KUBE_NOOB_DATA_DIR": jira_copy}),
        ("ticket", 1): (["ticket", "OCPBUGS-999999"], none),
        ("learn submit", 0): (
            ["learn", "submit", "k8s-ex-hardened-deployment", "-f", _write(d, "pass.yaml", PASSING_ANSWER)],
            none,
        ),
        ("learn submit", 1): (
            ["learn", "submit", "k8s-ex-hardened-deployment", "-f", str(ROOT / "examples" / "exercise-answer.yaml")],
            none,
        ),
    }


def _run(argv: list[str], extra: dict[str, str]) -> int:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), **extra}
    return subprocess.run(
        [sys.executable, "-m", "kube_noob", *argv],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    ).returncode


# --- the checks ------------------------------------------------------------------------------------------------


def test_every_documented_nonzero_code_has_an_input_that_produces_it(tmp_path: Path) -> None:
    """The coverage rule. A code nothing drives is a contract nothing holds."""
    have = set(_inputs(tmp_path)) | set(EXEMPT)
    want = {(cmd, code) for cmd, codes in _documented().items() for code in codes if code != 0}
    missing = sorted(want - have)
    assert not missing, (
        f"these documented codes have no input: {missing}. Add one to `_inputs`, or to EXEMPT with the reason "
        "no offline input can reach it."
    )


#: Codes a row is not asked to repeat, because they are not that command's answer about its subject. `2` is a
#: usage or config error -- the command never ran -- and `141` is a closed pipe. Both are in the contract once,
#: for every command, and a row that listed them would say nothing a reader does not already know. `4` and `5`
#: are NOT in here: they are answers about the input, they change what a gate must do, and they belong in the row.
_UNIVERSAL = frozenset({2, 141})


def test_every_code_an_input_produces_is_documented(tmp_path: Path) -> None:
    """The question backwards.

    The coverage rule above walks from the table to the code: a documented code with no input fails. That is one
    direction, and it is the direction G206 and G237 keep catching -- it passes while a command returns a code no
    row mentions, and a reader's gate meets a number its table has never heard of and has to guess.

    `protocol review` on a directory holding one unreadable file returns 5 -- evidence incomplete, no answer
    attempted -- and both published tables said `0` ready, `1` blocked, `3` needs clarification. Nothing here
    looked, because `_inputs` keys are written by hand and only ever compared against the code they produce.
    """
    inputs = _inputs(tmp_path)
    produced = {(cmd, code) for (cmd, code) in inputs if code not in _UNIVERSAL}
    undocumented = sorted(
        f"{skill}: `{cmd}` produces {code} on `kube-noob {' '.join(inputs[(cmd, code)][0])}`, and its row there "
        f"documents only {sorted(rows[cmd]) or 'nothing'}"
        for skill, rows in _by_skill().items()
        for (cmd, code) in produced
        if cmd in rows and code not in rows[cmd]
    )
    assert produced, "no input produces a command-specific code, so this check would measure nothing"
    assert not undocumented, "\n".join(undocumented)


def test_every_command_driven_here_has_a_row_somewhere(tmp_path: Path) -> None:
    """A command with NO row is invisible to the check above, which is the defect it exists to stop.

    The sweep walks each skill's rows and asks whether the code is in them. A command no skill lists at all has
    no row to walk, so it is skipped -- an absence reading as nothing to verify. `learn mechanism` shipped that
    way: four codes, `0` and `1` and `4` and `5`, and no published table routed to it at all; so did
    `learn progress`.
    """
    somewhere = set().union(*(set(rows) for rows in _by_skill().values()))
    driven = {cmd for cmd, _code in _inputs(tmp_path)}
    unrouted = sorted(driven - somewhere)
    assert not unrouted, (
        f"these commands are driven here and no published table has a row for them: {unrouted}. A reader cannot "
        "reach a command no skill names, and the exit-code sweep cannot see one either."
    )


def test_the_refused_input_codes_are_in_the_rows() -> None:
    """The repair, pinned to the tables rather than to the sweep that found it.

    The sweep above is general, and a general check can be neutered without any single row changing -- widen
    `_UNIVERSAL`, drop a term from the comprehension, and eleven published rows go quietly back to saying `0` or
    `1` about a command that returns 4 and 5. So this names the measurement: a refused input is 4, a directory
    holding one is 5, uniform across the five manifest readers, and 4 reaches both posture commands as well.
    """
    assert not ({4, 5} & _UNIVERSAL), "4 and 5 are answers about the input; a row has to carry them"
    by_skill = _by_skill()
    for command, codes in {
        "audit": {4, 5},
        "validate": {4, 5},
        "fix": {4, 5},
        "protocol": {4, 5},
        "policy reach": {4, 5},
        "posture scan": {4, 5},
        "posture reach": {4, 5},
    }.items():
        carried = [(skill, sorted(codes - rows[command])) for skill, rows in by_skill.items() if command in rows]
        assert carried, f"no skill has a row for `{command}` any more; this control is measuring nothing"
        short = [f"{skill} omits {missing}" for skill, missing in carried if missing]
        assert not short, (
            f"`{command}` returns 4 on a refused input and 5 on a directory holding one, and these rows do not "
            f"say so: {short}. A gate reading one of them meets a code its table has never heard of."
        )


def test_the_exemption_list_is_empty(tmp_path: Path) -> None:
    """An exemption is a claim about the product that nothing measures.

    The one entry this list ever held said `ticket` could not reach 0 offline because the local Jira copy needs
    `corpus jira --online`. `sync_projects` takes its client, so a fake one seeds the copy with no network at
    all, and the 0 is driven below like every other code. The claim was simply wrong, and the stale-exemption
    check could not see it: that check asks whether the ROW still documents the code, never whether the reason
    is true.

    So the list stays empty, and re-opening it is a deliberate edit here rather than a quiet dict entry -- the
    author deletes this test and, in doing so, says in the diff what they measured.
    """
    assert not EXEMPT, f"an exemption is a claim nothing measures; these are open: {sorted(EXEMPT)}"
    assert ("ticket", 0) in _inputs(tmp_path), "the input that disproved the old exemption has to stay driven"


def test_no_exemption_outlives_the_row_that_needs_it() -> None:
    """An exemption for a code the tables no longer document is an excuse for nothing, and would hide the next one."""
    documented = {(cmd, code) for cmd, codes in _documented().items() for code in codes}
    stale = sorted(k for k in EXEMPT if k not in documented)
    assert not stale, f"EXEMPT covers codes no row documents any more: {stale}"
    assert all(reason.strip() for reason in EXEMPT.values()), "every exemption states why"


def test_each_input_produces_exactly_the_code_it_is_for(tmp_path: Path) -> None:
    """Equality, not membership.

    `rhacs compare` is why: its row said `always 0` against a command that returns 1 when a policy is
    unexplained, and the fixture `test_directory_plugin` runs it on has none -- so membership passed for months
    while the row was wrong.
    """
    wrong: list[str] = []
    for (command, code), (argv, env) in sorted(_inputs(tmp_path).items()):
        got = _run(argv, env)
        if got != code:
            wrong.append(f"{command}: documented {code}, got {got} from `kube-noob {' '.join(argv)}`")
    assert not wrong, "\n".join(wrong)


def test_the_zero_is_driven_for_every_command_whose_nonzero_code_is_driven(tmp_path: Path) -> None:
    """Driving only the nonzero half would leave the inverse hole: a build that returned 1 everywhere.

    Each command that has a nonzero input here also has one for 0, so the pair pins both ends of its contract
    rather than one.
    """
    have = set(_inputs(tmp_path))
    nonzero = {cmd for cmd, code in have if code != 0}
    missing = sorted(cmd for cmd in nonzero if (cmd, 0) not in have and (cmd, 0) not in EXEMPT)
    assert not missing, f"these drive a nonzero code and never 0: {missing}"
    assert nonzero, "no command drives a nonzero code, so this file would measure nothing"
