# Submitting `noob` to krew-index (owner only)

Opening a pull request against `kubernetes-sigs/krew-index` is the owner's step: it is someone else's repository, it
needs the Kubernetes CLA signed by the person who opens it, and it names a published release asset. Until it merges,
`kubectl noob` works without krew: see [docs/install.md](../docs/install.md#kubectl-without-krew).

Everything below was checked on 2026-11-12 against the sources named beside it. Where a source says nothing, this file
says so instead of guessing.

## Submit after the next release, not v0.9.2

krew's pre-submit checklist says: "Adopt an open source license, and add it to your plugin archive file" and "Make
sure to extract the LICENSE file during the plugin installation"
([new plugin](https://krew.sigs.k8s.io/docs/developer-guide/release/new-plugin/)). The v0.9.2 asset
`kubectl-noob-v0.9.2.tar.gz` (sha256 `5c7219b5...a004`, the digest in `krew/noob.yaml` at tag `v0.9.2`) holds the
script alone. From G276, `scripts/krew_manifest.py` packs `LICENSE` beside the script, and the manifest names no
`files`, so krew extracts both. No release has published that archive yet, which is why `krew/noob.yaml` on `main`
carries a digest no published asset has: it describes the archive the next release builds. The release workflow
builds it with `scripts/krew_manifest.py --archive` and fails if its digest is not the manifest's.

The same release also carries two other fixes the krew guides ask for: the manifest's `description` no longer lists
commands ("Avoid including a list of commands or options for your plugin",
[plugin manifest](https://krew.sigs.k8s.io/docs/developer-guide/plugin-manifest/)), and the script's install hint no
longer names a Homebrew tap the install guide does not document.

## What krew-index checks

- File: `plugins/noob.yaml`. "'name' must match the filename of the manifest" (plugin manifest guide); the manifest's
  `metadata.name` is `noob`.
- CI (`.github/workflows/ci.yml`, job "Validate plugin manifests"): installs kubectl v1.18.8 and krew v0.4.5, builds
  `sigs.k8s.io/krew/cmd/validate-krew-manifest` at v0.4.5, and runs it on every added or modified file under
  `plugins/`. It was not run here: building it needs the Go module proxy, which this environment cannot reach.
- Naming ([naming guide](https://krew.sigs.k8s.io/docs/developer-guide/develop/naming-guide/)): lowercase with hyphens,
  no `kube-` or `kubernetes-` prefix (so `kube-noob` cannot be the name), and not a generic or overloaded word. `noob`
  meets the first two; a reviewer may still call it generic. If one does, the answer is a more specific name, not an
  argument.
- Acceptance: "The decision criteria for plugins accepted to the centralized repository are evaluated on a
  case-by-case basis" (krew-index README). A plugin that is refused can be served from a custom index
  ([custom indexes](https://krew.sigs.k8s.io/docs/developer-guide/custom-indexes/)).
- The pull request template asks you to read the naming guide and to confirm the plugin installs locally from a
  manifest and an archive.
- PR title: neither the krew-index README, its CONTRIBUTING, its pull request template nor the krew developer guide
  states a convention. "Add noob plugin" below is plain, not a rule.
- CLA: "Kubernetes projects require that you sign a Contributor License Agreement (CLA) before we can accept your pull
  requests" (krew-index CONTRIBUTING). Sign it with the GitHub account that opens the pull request.

## Steps

1. Publish the next release the usual way ([docs/operations.md](../docs/operations.md)).

2. Check the published asset against the manifest at that release's tag, and that it holds the licence. `V` is the
   latest release:

```bash
V=$(gh release view --repo kube-noob/kube-noob --json tagName --jq .tagName | sed 's/^v//') && curl -fsSLO "https://github.com/kube-noob/kube-noob/releases/download/v$V/kubectl-noob-v$V.tar.gz" && curl -fsSL "https://raw.githubusercontent.com/kube-noob/kube-noob/v$V/krew/noob.yaml" -o noob.yaml && echo "$(sed -n 's/^ *sha256: //p' noob.yaml)  kubectl-noob-v$V.tar.gz" | shasum -a 256 -c - && tar -tzf "kubectl-noob-v$V.tar.gz"
```

   It has to print `OK`, then `kubectl-noob` and `LICENSE`. Stop if it prints anything else.

3. On a machine with kubectl and krew, install from that manifest and archive, as the pull request template asks
   ([testing locally](https://krew.sigs.k8s.io/docs/developer-guide/testing-locally/)), then remove it again with
   krew's uninstall command:

```bash
kubectl krew install --manifest=noob.yaml --archive="kubectl-noob-v$V.tar.gz" && kubectl noob --version
```

4. Sign the Kubernetes CLA, if this GitHub account has not.

5. Fork krew-index, add `plugins/noob.yaml` from the release tag on a branch, and open the pull request. Nothing here
   needs a local clone:

```bash
V=$(gh release view --repo kube-noob/kube-noob --json tagName --jq .tagName | sed 's/^v//') && me=$(gh api user --jq .login) && gh repo fork kubernetes-sigs/krew-index --clone=false --default-branch-only && gh api -X POST "repos/$me/krew-index/git/refs" -f ref=refs/heads/add-noob -f sha="$(gh api repos/kubernetes-sigs/krew-index/git/ref/heads/master --jq .object.sha)" && gh api -X PUT "repos/$me/krew-index/contents/plugins/noob.yaml" -f message="Add noob plugin" -f branch=add-noob -f content="$(gh api "repos/kube-noob/kube-noob/contents/krew/noob.yaml?ref=v$V" --jq .content | tr -d '\n')" && gh pr create --repo kubernetes-sigs/krew-index --base master --head "$me:add-noob" --title "Add noob plugin" --body "kube-noob: offline Kubernetes and OpenShift manifest audit, NetworkPolicy reachability and must-gather reader. No AI inside. Apache-2.0; the licence is in the archive. The plugin is a POSIX shell passthrough to the kube-noob CLI, with a pinned uvx fallback so it works without a Python environment. Tested with kubectl krew install --manifest --archive against the release asset."
```

6. Watch the "Validate plugin manifests" check on the pull request. A digest failure there means the manifest and the
   asset disagree: rerun step 2 rather than editing the manifest by hand. `scripts/krew_manifest.py` is the only thing
   that writes it.

## After it merges

Update `krew/README.md` and `docs/install.md`, which say the plugin is not in the index yet, and add the krew route to
the README's install section.
