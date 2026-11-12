# Install kube-noob

kube-noob needs Python 3.11.4 or newer. macOS's built-in `python3` (from the Xcode Command Line Tools) is 3.9, so a
plain `pip install` there fails. Homebrew and uv bring their own Python (uv downloads one when yours is too old), and
pipx installed with Homebrew uses Homebrew's.

| Method | Commands | Upgrade |
|---|---|---|
| Homebrew (Apple silicon macOS, Linux) | `brew tap kube-noob/kube-noob https://github.com/aashishmahajan/kube-noob`, then `brew trust --formula kube-noob/kube-noob/kube-noob`, then `brew install kube-noob` | `brew update && brew upgrade kube-noob` |
| uv (downloads a Python if yours is too old) | `uv tool install kube-noob` | `uv tool upgrade kube-noob` |
| pipx | `pipx install kube-noob` | `pipx upgrade kube-noob` |
| pip, in a virtual environment | `python3.13 -m venv ~/.venvs/kube-noob`, then `~/.venvs/kube-noob/bin/pip install kube-noob` | `~/.venvs/kube-noob/bin/pip install -U kube-noob` |
| Container | `podman run --rm ghcr.io/kube-noob/kube-noob:0.9 --version` | pull the new tag |
| Claude Code plugin | `/plugin marketplace add kube-noob/kube-noob`, then `/plugin install kube-noob@kube-noob` | `/plugin marketplace update kube-noob` |
| Claude Code plugin, CLI-driven | `/plugin marketplace add kube-noob/kube-noob`, then `/plugin install kube-noob-skills@kube-noob`, plus the CLI by any method above | `/plugin marketplace update kube-noob` |

`kube-noob-skills` is the same seven skills with **no MCP server and no code in the plugin at all**. Its skills run
the kube-noob CLI you installed, through Claude's Bash tool, with `--format json`. It exists because the Claude plugin
directory accepts a plugin carrying a local MCP server only from a Verified organization, and there is no way to
apply to become one. See [which install, and what can run](#which-install-and-what-can-run).

## Which install, and what can run

kube-noob is one engine. What changes from one place to another is how Claude, or you, reach it.

| Where you are | What you install | What can run |
|---|---|---|
| Claude Code, from this repository's marketplace | `/plugin marketplace add kube-noob/kube-noob`, then `/plugin install kube-noob@kube-noob` | The full plugin: its own stdio MCP server, bundled as readable source and started with `uv run --frozen`, and seven skills that call its tools. Needs uv |
| Claude Code, from the Claude plugin directory (once `kube-noob-skills` is listed) | `kube-noob-skills`, and the CLI: `pipx install 'kube-noob>=0.9.3'` (0.9.3 is the first release the skills work with) | The seven skills check `kube-noob --version`, then run the CLI through the Bash tool on a private folder, offline, under your permission settings, with `KUBE_NOOB_FOR_MODEL=1` so the output is cleaned for Claude. With no CLI they say nothing was audited and give the install command |
| Claude Desktop | `{"mcpServers": {"kube-noob": {"command": "uvx", "args": ["--from", "kube-noob==0.9.2", "kube-noob", "mcp"]}}}` in its MCP server configuration | The MCP server over stdio, every tool |
| claude.ai chat | The [Agent Skill](#agent-skill) zip, uploaded under **Customize > Skills** | The tools in claude.ai's code sandbox, offline. The directory plugin's skills load in chat too, but chat has no shell on your machine: they give you the command and read the output you paste |
| Any MCP client | The CLI by any method above, then the client pointed at `kube-noob mcp` | The MCP server over stdio, every tool |
| Plain kubectl | `kubectl-noob` on your `PATH`: [kubectl, without krew](#kubectl-without-krew) today, and through krew once the krew-index pull request ([krew/SUBMIT.md](../krew/SUBMIT.md)) merges | `kubectl noob` passes every argument to the kube-noob CLI unchanged (`kubectl noob audit -f k8s/` is `kube-noob audit -f k8s/`), and, when kube-noob is not on `PATH` but uv is, downloads the pinned release through `uvx` |

The directory plugin cannot carry the engine itself: the directory accepts Markdown, JSON and images from an
organization that is not Verified, and refuses a local MCP server and every other file type. A remote MCP server
pointed at your own `kube-noob serve` would be admissible, and is not shipped; [SECURITY.md](../SECURITY.md#the-directory-plugin-and-a-remote-server)
says why.

## kubectl, without krew

`kubectl` runs any executable on your `PATH` named `kubectl-<name>` as `kubectl <name>`, so the krew plugin works
before it is in krew-index. Download the release asset, check it against the digest in that release's krew manifest,
and put the script on your `PATH` (`~/.local/bin` here; use any directory on yours):

```bash
curl -fsSLO https://github.com/kube-noob/kube-noob/releases/download/v0.9.2/kubectl-noob-v0.9.2.tar.gz && want=$(curl -fsSL https://raw.githubusercontent.com/kube-noob/kube-noob/v0.9.2/krew/noob.yaml | sed -n 's/^ *sha256: //p') && test -n "$want" && if command -v sha256sum >/dev/null 2>&1; then echo "$want  kubectl-noob-v0.9.2.tar.gz" | sha256sum -c -; else echo "$want  kubectl-noob-v0.9.2.tar.gz" | shasum -a 256 -c -; fi && mkdir -p ~/.local/bin && tar -xzf kubectl-noob-v0.9.2.tar.gz -C ~/.local/bin kubectl-noob && kubectl noob --version
```

It is one line so that a failed step stops it: the archive is extracted only after the digest check printed `OK`, with
`sha256sum` where it exists and `shasum` (macOS) where it does not. What the check proves is narrow: the asset you
downloaded is the one the manifest at that release tag names, so a swapped or corrupted release asset is refused. It
does not prove anything about the repository itself, or about a tag that was moved, because the digest comes from the
same place. The manifest is read at the release's own tag because the one on `main` describes the archive the next
release will build. The script needs kube-noob on `PATH` or uv installed, and says so when it has neither; with only uv,
it downloads the pinned kube-noob release through `uvx` the first time it runs.

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

## Errors and fixes

| You see | Why | Fix |
|---|---|---|
| `No available formula with the name "kube-noob"` | The tap is not added | `brew tap kube-noob/kube-noob https://github.com/aashishmahajan/kube-noob`, then `brew trust --formula kube-noob/kube-noob/kube-noob`, then `brew install kube-noob` |
| `Refusing to load formula aashishmahajan/kube-noob/kube-noob from untrusted tap` | Homebrew 6 requires trust for third-party taps | `brew trust --formula kube-noob/kube-noob/kube-noob`, then `brew install kube-noob` |
| `Requires-Python >=3.11.4` and `No matching distribution found for kube-noob` | Your `python3` is older than 3.11.4 (3.11.0 through 3.11.3 are not enough) | Use Homebrew, uv or pipx above, or a virtual environment made with Python 3.11.4+ |
| `error: externally-managed-environment` | Homebrew's or the system's Python refuses packages installed into it (PEP 668) | Use pipx, uv or a virtual environment; do not add `--break-system-packages` |
| `zsh: command not found: pip` | macOS has no `pip` command, only `pip3` | Use pipx or uv, or `python3 -m pip` inside a virtual environment |
| `command not found: kube-noob` after pipx or uv | Their bin folder is not on your `PATH` yet | `pipx ensurepath` or `uv tool update-shell`, then open a new terminal |
| An old version after upgrading | Another install comes first on `PATH` | `which -a kube-noob` and remove the older one |
