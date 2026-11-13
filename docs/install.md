# Install kube-noob

kube-noob needs Python 3.11.4 or newer. macOS's built-in `python3` (from the Xcode Command Line Tools) is 3.9, so a
plain `pip install` there fails. Homebrew and uv bring their own Python (uv downloads one when yours is too old), and
pipx installed with Homebrew uses Homebrew's.

| Method | Commands | Upgrade |
|---|---|---|
| Homebrew (Apple silicon macOS, Linux) | `brew tap kube-noob/kube-noob https://github.com/kube-noob/kube-noob`, then `brew trust --formula kube-noob/kube-noob/kube-noob`, then `brew install kube-noob` | `brew update && brew upgrade kube-noob` |
| uv (downloads a Python if yours is too old) | `uv tool install kube-noob` | `uv tool upgrade kube-noob` |
| pipx | `pipx install kube-noob` | `pipx upgrade kube-noob` |
| pip, in a virtual environment | `python3.13 -m venv ~/.venvs/kube-noob`, then `~/.venvs/kube-noob/bin/pip install kube-noob` | `~/.venvs/kube-noob/bin/pip install -U kube-noob` |
| Container | `podman run --rm ghcr.io/kube-noob/kube-noob:0.9 --version` | pull the new tag |
| Claude Code plugin | `/plugin marketplace add kube-noob/kube-noob`, then `/plugin install kube-noob@kube-noob` | `/plugin marketplace update kube-noob` |
| Claude Code plugin, knowledge only | `/plugin marketplace add kube-noob/kube-noob`, then `/plugin install kube-noob-skills@kube-noob` | `/plugin marketplace update kube-noob` |

`kube-noob-skills` is the same seven skills with **no MCP server and no code in the plugin at all**: the knowledge,
without the audit, validation and diagnosis tools. Install `kube-noob@kube-noob` instead unless you specifically want
a plugin that runs nothing. It exists because the Claude plugin directory accepts a plugin carrying a local MCP server
only from a Verified organization, and there is no way to apply to become one.

The tap is needed because kube-noob is not in Homebrew's main catalogue; after `brew tap`, `brew install kube-noob`
finds it. Homebrew 6 and later also refuse formulae from third-party taps until you trust them; `brew trust
--formula` trusts only this one formula ([Homebrew: Tap Trust](https://docs.brew.sh/Tap-Trust)). Get uv or pipx with `brew install uv` or `brew install pipx`.

Every method installs two commands: `kube-noob` and its short form `noob` (from 0.2.3). The PyPI package named
`noob` is an unrelated graph library that also installs a `noob` command; if you have it, use `kube-noob`.

Check what you are running:

```bash
kube-noob --version
which -a kube-noob
```

`which -a` lists every `kube-noob` on your `PATH`. If it prints more than one, an older install is shadowing the new
one: remove it with the tool that installed it (`pipx uninstall kube-noob`, `uv tool uninstall kube-noob` or
`brew uninstall kube-noob`).

## Agent Skill

The same tools as the MCP server, as an [Agent Skill](https://claude.com/docs/skills/how-to): a folder with
`SKILL.md`, a runner (`scripts/kn.py`, one tool per call, JSON out) and the readable server source the Claude plugin
ships. Use it where no MCP server runs: chat on claude.ai (the plugin's local MCP server runs in Claude Code and
Cowork only) and the Claude API's code execution. It runs with the offline lock on and needs Python 3.11 or later
with pydantic, PyYAML and jsonschema; `kn.py check` says which are missing. The runner in a built skill is
`skill/kube-noob/scripts/kn.py` (the folder the zip unpacks as `kube-noob/`).

| Where | Install |
|---|---|
| claude.ai (Pro, Max, Team, Enterprise, with code execution on) | Download `kube-noob-skill-<version>.zip` from the GitHub release (from 0.7.0), then upload it under **Customize > Skills** and turn it on |
| Claude Code | Unzip it into `~/.claude/skills/` (so the file is `~/.claude/skills/kube-noob/SKILL.md`), or install the plugin instead, which also gives the MCP tools |
| From a checkout | `python scripts/build_skill.py --zip kube-noob-skill.zip` or `--out ~/.claude/skills/kube-noob` |

Run it yourself to see what Claude sees:

```bash
python3 -I -B skill/kube-noob/scripts/kn.py check
python3 -I -B skill/kube-noob/scripts/kn.py tools
python3 -I -B skill/kube-noob/scripts/kn.py insight '{"text": "0/3 nodes are available: 3 Insufficient memory"}'
python3 -I -B skill/kube-noob/scripts/kn.py audit_manifests --text-file manifests=app.yaml
```

## Offline install, verified

Installing and running without a network is a transcript in this repository's CI, not a sentence here. Every run of
`ci.yml` has an `airgap` job that takes the wheel the `publishable` job just built, downloads the dependency wheels
that `requirements.lock` pins (hashes checked; this is the one step with network), and then, inside a network
namespace with no interface and no route (`unshare -rn`), installs from that directory only (`pip install
--no-index --find-links <dir> --require-hashes -r requirements.lock`, then the kube-noob wheel with `--no-deps`) and
runs four workflows with their exit codes asserted: `kube-noob doctor` (0), `kube-noob audit -f
insecure-deployment.yaml` (1: findings at high, from the copy the wheel carries), `kube-noob must-gather analyze` on
the bundled sample (0), and one `tools/list` request to `kube-noob mcp` over stdio (0). Before the four, the namespace
is proved on itself: a DNS lookup and a TCP connect must both fail, or the run stops without a verdict. The same
script, `scripts/airgap_check.sh`, runs the four checks against the locally built wheel in `scripts/check.sh`.

To repeat it at your site, with a mirrored index or a directory of wheels you carried in:

```bash
scripts/airgap_check.sh prepare /path/to/wheels
scripts/airgap_check.sh verify /path/to/wheels
```

`prepare` needs network (or point `pip` at your mirror with `PIP_INDEX_URL`); `verify` needs none and refuses to run
outside a namespace it can create (`unshare -rn`, else `sudo unshare -n`), with exit 2 and a message rather than a
pass. Exit 0 is every check passed; 1 names the check that failed and keeps its output.

What this establishes: with the wheels already on local disk, the install and these four workflows need no network
and make no network attempt that could succeed. What it does not establish: how the wheels got there -- the mirrored
index, the signed bundle, and `gh attestation verify dist/kube_noob-*.whl --repo kube-noob/kube-noob` before the
wheel is trusted (see [SECURITY.md](../SECURITY.md)) are the operator's steps; anything the four checks do not
exercise (live cluster access, the HTTP service, web access when enabled); and, without `strace`, a network attempt
that was made, failed in the namespace and was tolerated silently -- the namespace makes every attempt fail, it does
not see one that the code chose to ignore.

## Errors and fixes

| You see | Why | Fix |
|---|---|---|
| `No available formula with the name "kube-noob"` | The tap is not added | `brew tap kube-noob/kube-noob https://github.com/kube-noob/kube-noob`, then `brew trust --formula kube-noob/kube-noob/kube-noob`, then `brew install kube-noob` |
| `Refusing to load formula kube-noob/kube-noob/kube-noob from untrusted tap` | Homebrew 6 requires trust for third-party taps | `brew trust --formula kube-noob/kube-noob/kube-noob`, then `brew install kube-noob` |
| `brew tap` lists `aashishmahajan/kube-noob` | You tapped it under the name these instructions used before the project moved into the `kube-noob` organisation, so two taps carry the same formula | `brew uninstall kube-noob`, then `brew untap aashishmahajan/kube-noob`, then the three commands in the first row |
| `Requires-Python >=3.11.4` and `No matching distribution found for kube-noob` | Your `python3` is older than 3.11.4 (3.11.0 through 3.11.3 are not enough) | Use Homebrew, uv or pipx above, or a virtual environment made with Python 3.11.4+ |
| `error: externally-managed-environment` | Homebrew's or the system's Python refuses packages installed into it (PEP 668) | Use pipx, uv or a virtual environment; do not add `--break-system-packages` |
| `zsh: command not found: pip` | macOS has no `pip` command, only `pip3` | Use pipx or uv, or `python3 -m pip` inside a virtual environment |
| `command not found: kube-noob` after pipx or uv | Their bin folder is not on your `PATH` yet | `pipx ensurepath` or `uv tool update-shell`, then open a new terminal |
| An old version after upgrading | Another install comes first on `PATH` | `which -a kube-noob` and remove the older one |
