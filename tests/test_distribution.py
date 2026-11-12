"""Release metadata must agree across PyPI, the MCP Registry, the Claude plugin, the image and the chart."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from kube_noob import __version__

ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "io.github.kube-noob/kube-noob"


def test_mcp_registry_metadata() -> None:
    server = json.loads((ROOT / "server.json").read_text())
    assert server["name"] == SERVER_NAME and server["version"] == __version__
    assert server["packages"][0]["identifier"] == "kube-noob" and server["packages"][0]["version"] == __version__
    assert len(server["description"]) <= 100
    readme = (ROOT / "README.md").read_text()
    assert re.search(rf"mcp-name: {re.escape(SERVER_NAME)}(\s|-->)", readme), "PyPI ownership marker missing"
    assert f'io.modelcontextprotocol.server.name="{SERVER_NAME}"' in (ROOT / "Containerfile").read_text()


def test_plugin_pins_the_release() -> None:
    import tomllib

    plugin = json.loads((ROOT / "plugin/kube-noob/.claude-plugin/plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    assert plugin["version"] == __version__
    assert {p["version"] for p in market["plugins"]} == {__version__}, "every marketplace entry is this release"
    assert {p["name"] for p in market["plugins"]} == {"kube-noob", "kube-noob-skills"}
    assert tomllib.loads((ROOT / "plugin/kube-noob/pyproject.toml").read_text())["project"]["version"] == __version__
    lock = tomllib.loads((ROOT / "plugin/kube-noob/uv.lock").read_text())
    assert next(p for p in lock["package"] if p["name"] == "kube-noob-plugin")["version"] == __version__
    assert (ROOT / "plugin/kube-noob/LICENSE").read_text() == (ROOT / "LICENSE").read_text()
    assert len((ROOT / "plugin/kube-noob/README.md").read_text().split()) >= 40
    pins = re.findall(r"kube-noob==(\d+\.\d+\.\d+)", (ROOT / "README.md").read_text())
    assert pins and set(pins) == {__version__}, "README.md uvx pin for other MCP clients"


def test_the_plugin_asks_the_user_for_nothing_and_reads_nothing_from_their_machine() -> None:
    """The plugin directory's review prefers a value the user is asked for (a ``userConfig`` option) over one the
    server reads out of the machine's environment. kube-noob's plugin needs neither, and that is the stronger answer:
    it starts the server with the web, the cluster and the model off, so the configuration that reads a provider key,
    an RHACS token or a GitHub token (``apiKeyEnv``, ``rhacs.tokenEnv``, ``ci.githubTokenEnv`` in kube_noob.config) is
    unreachable from it, and ``scripts/sync_plugin_server.py`` leaves ``kube_noob.mustgather`` out of the copy
    entirely, so the one tool that reads the user's own files is not there to configure. An option asking for a folder
    of their files would be asking for access the plugin deliberately does not have."""
    plugin = json.loads((ROOT / "plugin/kube-noob/.claude-plugin/plugin.json").read_text())
    mcp = json.loads((ROOT / "plugin/kube-noob/.mcp.json").read_text())
    env = mcp["mcpServers"]["kube-noob"]["env"]
    assert env["KUBE_NOOB_WEB_ENABLED"] == "false"
    assert env["KUBE_NOOB_CLUSTER_ENABLED"] == "false"
    assert env["KUBE_NOOB_LLM_PROVIDER"] == "none"
    # The reason for the one set of options (G280): the plugin's PreToolUse hook blocks kubectl, oc and helm changes
    # that `kube-noob verify` does not allow, and a plugin update must not start blocking anybody's commands on its
    # own. So the hook is off until the user turns `verify_cluster_commands` on, and it needs the platform and
    # version the check targets. A switch, a platform name and a version: no folder, no file, no credential.
    options = plugin.get("userConfig", {})
    assert set(options) <= {"verify_cluster_commands", "verify_platform", "verify_version"}, set(options)
    assert options["verify_cluster_commands"] == {
        **options["verify_cluster_commands"],
        "type": "boolean",
        "default": False,
    }
    assert all(o["type"] in {"boolean", "string"} and not o.get("sensitive") for o in options.values())
    excluded = (ROOT / "scripts" / "sync_plugin_server.py").read_text()
    assert '"kube_noob.mustgather"' in excluded, "the plugin must not ship the tool that reads the user's own files"
    assert not (ROOT / "plugin/kube-noob/server/kube_noob/mustgather").exists()
    referenced = set(re.findall(r"\$\{user_config\.([A-Za-z0-9_]+)\}", json.dumps(mcp)))
    assert referenced == set(), f"{referenced} is asked of the user but plugin.json declares no userConfig"
    secrets = [k for k in env if k.endswith("_API_KEY") or "TOKEN" in k or "SECRET" in k or "PASSWORD" in k]
    assert secrets == [], f"the plugin server is started with a secret-bearing variable: {secrets}"


def test_chart_and_image_versions() -> None:
    chart = yaml.safe_load((ROOT / "deploy/helm/kube-noob/Chart.yaml").read_text())
    assert chart["appVersion"] == __version__ and chart["annotations"]["charts.openshift.io/name"] == "kube-noob"
    containerfile = (ROOT / "Containerfile").read_text()
    for label in ("name=", "vendor=", "version=", "release=", "summary=", "description=", "maintainer="):
        assert re.search(rf"^(LABEL)?\s+{label}", containerfile, re.MULTILINE), label
    assert "COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /licenses/" in containerfile


def test_image_build_context_has_every_wheel_input() -> None:
    """The Containerfile builds the wheel itself, so it must copy every path the wheel force-includes."""
    import tomllib

    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    wheel = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]
    containerfile = (ROOT / "Containerfile").read_text()
    ignored = (ROOT / ".dockerignore").read_text().split()
    for src in list(wheel.get("force-include", {})) + [p.split("/")[0] for p in wheel["packages"]]:
        assert re.search(rf"^COPY .*\b{re.escape(src)}\b", containerfile, re.MULTILINE), src
        assert src not in ignored, src


def test_scheduled_cadences_and_rox_corpus_scope() -> None:
    """Weekly risk review; the Jira main copy every other day by default (daily with JIRA_EVERY_DAYS=1), continuing
    the previous encrypted copy and failing rather than replacing it when that copy does not decrypt, with a
    reconciliation summary; the docs corpus weekly; and a Red Hat Jira copy that covers ROX (every version, so RHACS
    4.10 onward included) with room for well over 1000 issues."""
    import yaml

    wf = ROOT / ".github" / "workflows"
    risk = yaml.safe_load((wf / "risk-review.yml").read_text())
    corpus_text = (wf / "corpus-refresh.yml").read_text()
    corpus = yaml.safe_load(corpus_text)
    triggers = risk.get("on") or risk.get(True)
    assert re.fullmatch(r"\d+ \d+ \* \* \d", triggers["schedule"][0]["cron"])
    ctriggers = corpus.get("on") or corpus.get(True)
    crons = [s["cron"] for s in ctriggers["schedule"]]
    assert re.fullmatch(r"\d+ \d+ \* \* \*", crons[0]) and re.fullmatch(r"\d+ \d+ \* \* \d", crons[1])
    assert f"github.event.schedule == '{crons[1]}'" in corpus_text  # the weekly run is the full one
    assert "vars.JIRA_EVERY_DAYS || '2'" in corpus_text and "1|2)" in corpus_text
    assert "Refusing to start a new copy" in corpus_text
    assert "Refuse to publish a smaller Jira copy" in corpus_text
    assert "baseline-tickets.txt" in corpus_text
    assert corpus["permissions"] == {"contents": "read", "actions": "read"}
    assert corpus["concurrency"] == {"group": "corpus-refresh", "cancel-in-progress": False}
    steps = corpus["jobs"]["corpus"]["steps"]
    restore = next(s for s in steps if s.get("name", "").startswith("Restore the previous main copy"))
    assert "-n jira-main-copy-encrypted" in restore["run"] and "openssl enc -d -aes-256-cbc -pbkdf2" in restore["run"]
    assert "kube-noob corpus import previous/jira-snapshot.tgz" in restore["run"]
    assert "rm -f previous/jira-snapshot.tgz" in restore["run"]  # the plain copy never lingers
    recon = next(s for s in steps if s.get("name", "").startswith("Reconciliation"))
    assert "kube-noob corpus jira-changes --since 2d" in recon["run"] and "GITHUB_STEP_SUMMARY" in recon["run"]
    enc = next(s for s in steps if s.get("name", "").startswith("Encrypt the Jira main copy"))
    assert "kube-noob corpus jira-snapshot -o jira-snapshot.tgz" in enc["run"] and "rm jira-snapshot.tgz" in enc["run"]
    uploads = {s["with"]["name"]: s["with"] for s in steps if "upload-artifact" in s.get("uses", "")}
    assert uploads["jira-main-copy-encrypted"]["path"] == "jira-snapshot.tgz.enc"  # never the plain snapshot
    assert uploads["corpus-full-encrypted"]["path"] == "corpus-full.tgz.enc"
    uploaded = [line.strip() for u in uploads.values() for line in str(u["path"]).splitlines()]
    assert not any(path.endswith(".tgz") for path in uploaded), uploaded  # nothing unencrypted
    from kube_noob.jira_catalog import DEFAULT_PROJECTS

    assert '--projects "$JIRA_PROJECTS"' in corpus_text and "inputs.jira_projects || 'default'" in corpus_text
    assert "ROX" in DEFAULT_PROJECTS and "OCPBUGS" in DEFAULT_PROJECTS
    assert int(re.search(r"jira_max_requests \|\| '(\d+)'", corpus_text).group(1)) >= 1000  # x100 issues each


def test_ships_as_mcp_plugin_cli_and_openshift_service() -> None:
    import tomllib

    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert cfg["project"]["scripts"]["kube-noob"] == "kube_noob.cli:main"
    assert cfg["project"]["scripts"]["noob"] == "kube_noob.cli:main", "the short form runs the same CLI"
    assert (ROOT / "plugin/kube-noob/.mcp.json").is_file() and (ROOT / ".claude-plugin/marketplace.json").is_file()
    assert (ROOT / "deploy/helm/kube-noob/Chart.yaml").is_file()
    assert "kube-noob" in (ROOT / "deploy/sidecar/app-with-kube-noob-sidecar.yaml").read_text()


def test_chart_egress_firewall_mirrors_the_web_allowlist() -> None:
    from kube_noob.config import DEFAULT_ALLOWED_DOMAINS

    values = yaml.safe_load((ROOT / "deploy/helm/kube-noob/values.yaml").read_text())
    assert values["egressFirewall"]["enabled"] is False, "EgressFirewall is namespace-wide, so it must be opt-in"
    assert values["egressFirewall"]["defaultDomains"] == list(DEFAULT_ALLOWED_DOMAINS)
    assert values["egressFirewall"]["denyCIDRs"] == ["0.0.0.0/0"]
    template = (ROOT / "deploy/helm/kube-noob/templates/egressfirewall.yaml").read_text()
    assert "name: default" in template and "not (.Values.config.offline" in template
    assert "provider: none" in (ROOT / "deploy/helm/kube-noob/templates/configmap.yaml").read_text()


def test_sidecar_is_loopback_only_with_dns_only_egress() -> None:
    docs = list(yaml.safe_load_all((ROOT / "deploy/sidecar/app-with-kube-noob-sidecar.yaml").read_text()))
    dep = next(d for d in docs if d["kind"] == "Deployment")
    kn = next(c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "kube-noob")
    assert kn["args"][kn["args"].index("--host") + 1] == "127.0.0.1" and "ports" not in kn
    env = {e["name"]: e["value"] for e in kn["env"]}
    assert env["KUBE_NOOB_WEB_ENABLED"] == "false" and env["KUBE_NOOB_LLM_PROVIDER"] == "none"
    assert kn["resources"] == {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}
    svc = next(d for d in docs if d["kind"] == "Service")
    assert all(p["targetPort"] != 8080 for p in svc["spec"]["ports"])
    pol = next(d for d in docs if d["kind"] == "NetworkPolicy")
    assert pol["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert [p["port"] for rule in pol["spec"]["egress"] for p in rule["ports"]] == [5353, 5353]


def test_homebrew_formula_installs_hash_pinned_wheels() -> None:
    """Homebrew builds offline: every file is a sha256-checked resource; install is pip --no-index of those wheels."""
    formula = (ROOT / "Formula/kube-noob.rb").read_text()
    assert re.search(r'url "https://files\.pythonhosted\.org/packages/[^"]+/kube_noob-\d+\.\d+\.\d+\.tar\.gz"', formula)
    resources = re.findall(r'resource "([^"]+)" do\n\s+url "([^"]+)"\n\s+sha256 "([0-9a-f]{64})"', formula)
    assert len(resources) == formula.count('resource "') and len(resources) > 30
    assert all(url.startswith("https://files.pythonhosted.org/") and url.endswith(".whl") for _, url, _ in resources)
    assert {"kube-noob", "mcp", "pydantic", "pydantic-core", "pyyaml"} <= {name for name, _, _ in resources}
    assert '"install", "--no-index", "--no-deps"' in formula and '"check"' in formula
    assert 'depends_on "python@3.13"' in formula and "depends_on arch: :arm64" in formula and "test do" in formula


def test_homebrew_install_is_documented_tested_and_never_ahead_of_the_package() -> None:
    """Users run `brew tap ...` then `brew install kube-noob`: the README, the install guide and the CI job that
    installs from the public tap use those exact commands, and the formula is never newer than the package."""
    from packaging.version import Version

    import kube_noob

    tap = "brew tap kube-noob/kube-noob https://github.com/aashishmahajan/kube-noob"
    brew_wf = (ROOT / ".github/workflows/brew.yml").read_text()
    for text in ((ROOT / "README.md").read_text(), (ROOT / "docs/install.md").read_text(), brew_wf):
        assert tap in text and "brew install kube-noob" in text
        assert "brew trust --formula kube-noob/kube-noob/kube-noob" in text, "Homebrew 6 needs tap trust"
    jobs = yaml.safe_load(brew_wf)["jobs"]
    assert "public-tap" in jobs and "kube-noob --version" in str(jobs["public-tap"])
    formula = (ROOT / "Formula/kube-noob.rb").read_text()
    m = re.search(r'^  url ".*/kube_noob-([0-9][0-9.]*)\.tar\.gz"', formula, re.MULTILINE)
    assert m, "formula has no sdist url"
    assert Version(m.group(1)) <= Version(kube_noob.__version__)
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]
    assert release["homebrew"]["needs"] == "publish-pypi"
    assert release["brew"]["uses"] == "./.github/workflows/brew.yml"


def test_no_source_file_is_ignored_by_git() -> None:
    """A .gitignore pattern such as build/ once hid the kube_noob.build package from commits and from the wheel."""
    import shutil
    import subprocess

    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "src", "plugin", "tests", "scripts"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    hidden = [p for p in out if "__pycache__" not in p and not p.endswith((".pyc", ".DS_Store"))]
    assert hidden == [], f"ignored by .gitignore, so never committed or packaged: {hidden[:10]}"


# Addresses that belong in a public repository: placeholders, the upstream addresses a knowledge page quotes, and
# the fixture people in tests/fixtures, who are invented and use the RFC 2606 reserved domains.
_PUBLISHABLE_MAIL = re.compile(
    # RFC 2606 reserved names only -- example.com/.org/.net and anything under them, and the .example TLD. An
    # earlier \b after "example" also admitted example.io, example.co.uk and example-corp.com, none of which are
    # reserved. GitHub's no-reply form is allowed by its full domain, not by a bare "noreply@", which admitted
    # a bare "noreply@" prefix, which admitted that local part at any domain. The two upstream role addresses a
    # knowledge page and a CVE fixture quote are allowed by their exact value.
    r"(?i)(?:@(?:[a-z0-9-]+\.)*example\.(?:com|org|net)$|@(?:[a-z0-9-]+\.)*example$"
    r"|@users\.noreply\.github\.com$|^noreply@anthropic\.com$"
    r"|^aws-verification@amazon\.com$|^secalert@redhat\.com$)"
)
# A local part that follows / or : is a path or a URL credential, not an address, and a domain whose first label
# starts with a digit is a version string: pkg:rpm/redhat/nginx@1.26.1-2.el9.ngx is not mail.
_MAIL = re.compile(r"(?<![/:\w.-])([A-Za-z0-9._%+-]+@[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24})\b")
# Files whose contents are hashes, not prose.
_NOT_PROSE = {".lock", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".woff2", ".zip", ".gz", ".tgz", ".svg", ".ico"}


def test_no_real_address_is_published_in_the_repository() -> None:
    """`docs/openshift-release.md` told the reader to run `git config --global user.email` and filled the command
    in with the maintainer's own address. A public Apache-2.0 repository is a scraping target, and an address in a
    document cannot be withdrawn once a fork or an archive has it. Instructions name a placeholder; the person
    supplies the value when they run the command.

    Git's own commit metadata is a separate matter -- rewriting published history is worse than the exposure -- so
    this test reads tracked file contents only.
    """
    import shutil
    import subprocess

    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    # Every tracked file, not a hand-picked subset: the earlier version covered 452 of 968 and so missed
    # pyproject.toml (which ships to PyPI), the plugin manifest (which ships to the directory) and examples/.
    tracked = subprocess.run(
        ["git", "ls-files"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    found: list[str] = []
    for rel in tracked:
        path = ROOT / rel
        if not path.is_file() or path.suffix in _NOT_PROSE:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for hit in _MAIL.findall(line):
                if not _PUBLISHABLE_MAIL.search(hit):
                    found.append(f"{rel}:{n}: {hit.split('@')[0][:2]}...@{hit.split('@')[-1]}")
    assert found == [], (
        f"a real-looking address is published in a tracked file; use a placeholder the reader fills in: {found[:5]}"
    )


def test_the_private_build_queue_is_not_published() -> None:
    """`.claude/loop/` is the build queue the `build-loop` skill reads: an unreleased backlog with the product's
    own moat notes in it. Three of its files were tracked in the public repository, so anyone reading the repo read
    the roadmap. It stays on disk and out of git.
    """
    import shutil
    import subprocess

    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    tracked = subprocess.run(
        ["git", "ls-files", ".claude"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    leaked = [p for p in tracked if p.startswith(".claude/loop/")]
    assert leaked == [], f"the private build queue is tracked in a public repository: {leaked}"


# A bundled YAML file is parsed by whatever YAML parser the machine running kube-noob happens to have: the pure-Python
# PyYAML scanner, or libyaml through CSafeLoader (which signals/ceph.py and mustgather/analyse.py prefer for its
# start-up time). Those two do not agree on every document. `src: [healthmon:885]` in data/ceph_health.yaml parses as
# the string "healthmon:885" under the PyYAML scanners this repository's CI happens to have, and under the stricter
# libyaml in the browser runtime (Pyodide) it raises "found unexpected ':'" -- which took out `diagnose` and
# `known_issues` on kube-noob.com's playground and in the plugin on any machine with that libyaml, after 0.7.0 shipped
# the Ceph catalogue. A colon inside an unquoted scalar in a flow collection is ambiguous (it reads as a single-pair
# mapping), so the fix is to quote it and the guard is this test, which reads the text rather than trusting whichever
# parser is installed here.
# `key: value` inside {} is an ordinary flow mapping and portable; the hazard is a colon with no space after it, which
# a flow context may read as a single-pair mapping instead of as part of the scalar. The tokens come from PyYAML's own
# scanner rather than a regular expression, so a bracket inside prose (a folded block scalar, a quoted string) is not
# mistaken for a flow collection.
_GLUED_COLON = re.compile(r":(?!\s|$)")


def _ambiguous_flow_scalars(text: str) -> list[tuple[int, str]]:
    """Every colon inside a flow collection that is not followed by a space.

    One rule, because libyaml versions disagree on which of these they refuse and bundled data has to satisfy all of
    them: the 0.2.5 here accepts `[k:1]` and refuses `[k:]`, while the 0.1.7 in the browser runtime refuses
    `[healthmon:885]` as well. PyYAML resolves the same text two ways -- `[healthmon:885]` stays one plain scalar,
    `[k:1]` and `[k:]` become a single-pair mapping -- so both are checked: the scalar by its text, the mapping by
    the character after its value indicator. `[k: 1]` and `{k: }`, where the colon is followed by a space, are
    ordinary portable YAML and are left alone.
    """
    out: list[tuple[int, str]] = []
    stack: list[str] = []
    for token in yaml.scan(text, Loader=yaml.SafeLoader):
        if isinstance(token, yaml.tokens.FlowSequenceStartToken | yaml.tokens.FlowMappingStartToken):
            stack.append("flow")
        elif isinstance(token, yaml.tokens.FlowSequenceEndToken | yaml.tokens.FlowMappingEndToken):
            if stack:
                stack.pop()
        elif stack and isinstance(token, yaml.tokens.ValueToken):
            after = text[token.end_mark.index : token.end_mark.index + 1]
            if after and not after.isspace():
                out.append((token.start_mark.line + 1, f"a colon glued to {after!r} in a flow collection"))
        elif (
            stack
            and isinstance(token, yaml.tokens.ScalarToken)
            and token.style is None
            and _GLUED_COLON.search(token.value)
        ):
            out.append((token.start_mark.line + 1, token.value))
    return out


def _yaml_front_matter(text: str) -> str:
    """The YAML block at the top of a knowledge document, exactly as knowledge/store.py parses it at runtime.

    The offset has to match `parse_front_matter`: searching from 3 instead of 4 ends the block at the opening `---`
    of a document whose first body line is `---`, and the test would then scan an empty string.
    """
    if not text.startswith("---\n"):
        return ""
    end = text.find("\n---", 4)
    return text[4:end] if end > 0 else ""


def test_bundled_yaml_parses_under_every_yaml_parser() -> None:
    roots = (
        ROOT / "src" / "kube_noob",
        ROOT / "plugin" / "kube-noob" / "server" / "kube_noob",
        ROOT / "examples",
    )
    documents: list[tuple[str, str]] = []
    for root in roots:
        for suffix in ("*.yaml", "*.yml"):
            documents += [(str(p.relative_to(ROOT)), p.read_text(encoding="utf-8")) for p in sorted(root.rglob(suffix))]
        # a knowledge document's front matter is YAML that knowledge/store.py parses at runtime like any other
        for path in sorted(root.rglob("*.md")):
            front = _yaml_front_matter(path.read_text(encoding="utf-8"))
            if front:
                documents.append((f"{path.relative_to(ROOT)} (front matter)", front))
    assert len(documents) > 50, f"only {len(documents)} bundled documents found: this test would pass by doing nothing"
    loaders = [getattr(yaml, name) for name in ("CSafeLoader", "SafeLoader") if hasattr(yaml, name)]
    ambiguous: list[str] = []
    for name, text in documents:
        for number, scalar in _ambiguous_flow_scalars(text):
            ambiguous.append(f"{name}:{number}: {scalar}")
        # cheap, and no more than that: the libyaml on this machine accepts [x:1], so it would not have caught the
        # incident above. The scanner check is what guards it; this only catches a file that is broken everywhere.
        for loader in loaders:
            list(yaml.load_all(text, Loader=loader))
    assert ambiguous == [], (
        "quote these scalars: a colon in an unquoted scalar inside [] or {} is ambiguous, and a stricter "
        f"libyaml than this machine's refuses the file ({len(ambiguous)} found): {ambiguous[:6]}"
    )


def test_the_release_job_survives_a_release_the_maintainer_made_first() -> None:
    """`gh release create` fails when the release already exists, and a maintainer creating it by hand -- to write
    their own notes, or because a tag push looked like it did nothing -- is an ordinary thing to do. It happened on
    v0.7.1: the release existed, `github-release` failed, and `videos` and `site` were skipped behind it, so the
    release carried no wheel, no chart and no videos, and kube-noob.com was never told the version had changed. The
    step has to attach the assets either way; only the notes differ.
    """
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]
    steps = release["github-release"]["steps"]
    publish = next(s for s in steps if "release" in str(s.get("name", "")).lower() and "run" in s)
    script = publish["run"]
    assert "gh release upload" in script, "the step cannot attach assets to a release that already exists"
    assert "gh release create" in script, "the step must still create the release when there is none"
    assert "--clobber" in script, "re-running the job must replace an asset rather than fail on it"
    # The two paths are chosen, not both attempted: `create` on an existing release is an error, not a no-op.
    assert "gh release view" in script or "if " in script, "the step must branch on whether the release exists"

    for job in ("videos", "site"):
        assert release[job]["needs"] == "github-release" or "github-release" in release[job]["needs"], (
            f"{job} no longer waits for github-release; the ordering is what keeps the Videos page honest"
        )


def test_the_package_points_at_the_website() -> None:
    """A stranger arrives at PyPI, Homebrew or the GitHub page, not at kube-noob.com. Nothing linked it: not
    `project.urls`, not the README, not the plugin manifest, not the chart. The site is where the demos, the videos
    and the browsable rules live, and it was reachable only by already knowing the address."""
    import tomllib

    urls = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["urls"]
    site = re.compile(r"\bkube-noob\.com\b")
    assert any(site.search(u) for u in urls.values()), f"no project URL points at the site: {urls}"
    assert site.search((ROOT / "README.md").read_text(encoding="utf-8")), "the README never names the site"


def test_nothing_promises_an_artefact_that_has_never_published() -> None:
    """`docs/use-cases.md` told users the public `kube-noob-db` image is "rebuilt daily" and gave them cosign and
    helm commands for it. The `db-image` workflow has failed on every scheduled run since it was added and has
    never published anything. Documenting a thing that does not exist is worse than not having it: the reader
    spends their time before they find out."""
    # Scoped to use-cases.md, this test let the same sentence survive in the chart's values.yaml, which the site
    # republishes at /reference/helm-values/ -- so the claim stayed live on kube-noob.com after it was "fixed".
    # G147: a test that polices a rule is itself a claim, and it is checked by trying to evade it.
    records_the_history = {
        # These three quote the phrase in order to record that it was wrong, which is the opposite of promising it.
        "CHANGELOG.md",
        "docs/guidance.md",
        "tests/test_distribution.py",
    }
    import shutil
    import subprocess

    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout to list tracked files")
    tracked = subprocess.run(
        ["git", "ls-files"],  # noqa: S607 - the repository's own checkout, as the sibling sweeps here do
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    offenders = []
    for rel in tracked:
        if rel in records_the_history or rel.startswith("plugin/kube-noob/server/"):
            continue  # the plugin copy is generated from src/ by sync_plugin_server.py
        path = ROOT / rel
        if not path.is_file() or path.suffix not in {".md", ".py", ".yaml", ".yml", ".json", ".txt", ".html"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "rebuilt daily" in text:
            offenders.append(rel)
    assert not offenders, "these promise a daily rebuild of an image that has never published: " + ", ".join(
        sorted(offenders)
    )


def test_the_release_installs_dependencies_before_importing_the_package() -> None:
    """v0.8.0's release died at `krew_manifest.py --check` with `No module named 'yaml'`, after publishing
    nothing (PyPI returned 404 for 0.8.0, so the version was not burned).

    The shape is worth keeping. `build-dist` calls `setup-python` twice: once for the build, then again to match
    the publish action's interpreter. Everything after that second switch runs on a fresh Python with no project
    dependencies, and `krew_manifest.py` began importing the rule catalogue in #42 -- after v0.7.1 -- so the
    release path imported `kube_noob` for the first time on an interpreter that could not. The last few releases
    passing is exactly what made it invisible.

    This asserts the ordering rather than the symptom: after the last interpreter switch, nothing may import the
    package until something has installed its dependencies (G228).
    """
    import yaml

    root = Path(__file__).resolve().parents[1]
    job = yaml.safe_load((root / ".github/workflows/release.yml").read_text())["jobs"]["build-dist"]
    steps = job["steps"]

    def _is_setup_python(s: dict[str, object]) -> bool:
        return str(s.get("uses", "")).startswith("actions/setup-python@")

    def _installs_deps(s: dict[str, object]) -> bool:
        run = str(s.get("run", ""))
        return "pip install" in run and "requirements.lock" in run

    def _imports_the_package(s: dict[str, object]) -> bool:
        run = str(s.get("run", ""))
        return "krew_manifest.py" in run or "from kube_noob" in run or "import kube_noob" in run

    last_switch = max(i for i, s in enumerate(steps) if _is_setup_python(s))
    installs = [i for i, s in enumerate(steps) if _installs_deps(s) and i > last_switch]
    importers = [i for i, s in enumerate(steps) if _imports_the_package(s) and i > last_switch]
    assert importers, "no step imports the package; this guard has lost its subject"
    assert installs, "nothing installs the runtime dependencies after the interpreter switch"
    assert min(installs) < min(importers), (
        f"step {min(importers)} imports kube_noob before step {min(installs)} installs its dependencies"
    )
