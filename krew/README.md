# The krew plugin

`kubectl krew install noob` is not live yet: the plugin and its manifest are built and tested here, but adding it
to [krew-index](https://github.com/kubernetes-sigs/krew-index) is a pull request against someone else's
repository and the manifest has to name a published release asset. Both are owner actions, so nothing in the
README advertises the plugin until the index PR merges.

## What is in here

| File | What it is |
|---|---|
| `kubectl-noob.in` | The source of the entry-point script. `__VERSION__` is substituted at build time |
| `kubectl-noob` | Generated, committed, and the file that actually ships inside the archive, beside the repository's `LICENSE` |
| `noob.yaml` | Generated krew-index manifest. Its `sha256` is the digest of the archive built from the script and the licence |
| `SUBMIT.md` | The owner's steps for the krew-index pull request, with the checks it has to pass |

Both generated files are written by `scripts/krew_manifest.py`, and `tests/test_krew.py` fails if either is stale,
if the manifest's digest is not the archive's digest, or if the script stops forwarding its arguments unchanged.

The script is a passthrough on purpose: every argument goes to the kube-noob CLI as given, so there is no verb
table to drift when a subcommand moves. What it adds is the fallback -- if `kube-noob` is not on `PATH` but `uv`
is, it runs the pinned release through `uvx`, so the plugin works on a machine with no Python environment set up.
The pin is the plugin's own version, so `kubectl noob --version` agrees with what krew installed.

## Why one platform entry and no architecture matrix

The plugin is a POSIX shell script, so there is nothing per-architecture to publish. The manifest selects
`os in (darwin, linux)` with a single archive. Windows is not claimed, because the script is not a Windows
executable.

## Why the archive is byte-reproducible

The manifest states a digest, so the digest has to be a property of the script rather than of the machine that
packed it. The archive fixes each member's name, mode, mtime, uid, gid and user name, and gzips with no timestamp.
Without that, every release would produce a different hash for identical content and `--check` could never pass.

## Releasing it (owner)

The release workflow already checks the manifest and builds `dist/kubectl-noob-v<version>.tar.gz`, asserting that
its digest matches the manifest. The krew-index pull request, the checks it has to pass and the order to do it in
are in [SUBMIT.md](SUBMIT.md). In short: from G276 the archive carries `LICENSE`, as krew's pre-submit checklist
asks, so the manifest on `main` describes an archive no release has published yet, and the pull request waits for
the next release. Until then `kubectl noob` works without krew: [docs/install.md](../docs/install.md#kubectl-without-krew).

Both `noob` and `kube-noob` were unclaimed in krew-index when this was written (`plugins/noob.yaml` and
`plugins/kube-noob.yaml` both 404). `noob` is the name used here, because krew runs the plugin as
`kubectl <name>` and `kubectl noob audit` reads better than `kubectl kube-noob audit`.
