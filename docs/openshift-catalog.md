# Getting kube-noob into OpenShift's catalogs

The fastest credible route is the community tier of the OpenShift Helm charts repository: the chart then appears in
every cluster's console Helm catalog under the "Community" source. Researched 2026-10-27; sources at the end.

| Route | Who can submit | Effort | Where it shows | Status for kube-noob |
|---|---|---|---|---|
| OpenShift Helm charts, community | Anyone listed in the chart's OWNERS file | 1 to 2 days plus a manual review | Console Helm catalog, "Community" | Ready: chart lints with defaults, has a README, schema and test; released as `.tgz` and OCI |
| Artifact Hub | Anyone | Hours | artifacthub.io (search, not the console) | Ready once the OCI chart is published by a release |
| Community operator (Software Catalog, OLM) | Anyone, with DCO sign-off | 1 to 2 weeks (Helm-based operator, bundle, file-based catalog) | Console Software Catalog | Later: only if you want OLM-managed installs |
| Red Hat certification (Partner Connect) | Companies | Weeks | "Certified" badge | Later: needs a company account |
| OpenShift AI MCP catalog | Curated by Red Hat; no public submission path found | n/a | OpenShift AI | Watch; contact Red Hat when there is traction |
| Red Hat Marketplace | Closed on 1 April 2025 | n/a | n/a | Not an option |

OpenShift Lightspeed has no catalog: a cluster admin adds kube-noob in `OLSConfig.spec.mcpServers` ([openshift.md](openshift.md)).

## Submit the Helm chart (community)

1. Tag a release. The release workflow lints and packages the chart, pushes it to `oci://ghcr.io/kube-noob/charts`,
   signs it, and attaches `kube-noob-<version>.tgz` to the GitHub release.
2. Fork `openshift-helm-charts/charts` and open a first pull request that adds only
   `charts/community/kube-noob/kube-noob/OWNERS`, a copy of
   [deploy/openshift-catalog/OWNERS](../deploy/openshift-catalog/OWNERS). Sign off the commit (`git commit -s`).
3. After it merges, open a second pull request that adds `charts/community/kube-noob/kube-noob/<version>/` with the
   release's `kube-noob-<version>.tgz`. The pipeline runs chart-verifier with the community profile (helm-lint is the
   one mandatory check) and then waits for a manual approval.
4. Once merged, the chart is in the index the OpenShift console reads, under Helm charts, source "Community".

Commands for steps 2 and 3 (GitHub CLI; replace the version in step 3 with the newest release):

```bash
gh repo fork openshift-helm-charts/charts --clone=false
gh repo clone aashishmahajan/charts ~/openshift-helm-charts -- --depth 1
cd ~/openshift-helm-charts
git switch -c kube-noob-owners
mkdir -p charts/community/kube-noob/kube-noob
curl -fsSL https://raw.githubusercontent.com/aashishmahajan/kube-noob/main/deploy/openshift-catalog/OWNERS -o charts/community/kube-noob/kube-noob/OWNERS
git add charts/community/kube-noob/kube-noob/OWNERS
git commit -s -m "Add OWNERS for the kube-noob community chart"
git push -u origin kube-noob-owners
gh pr create --repo openshift-helm-charts/charts --head aashishmahajan:kube-noob-owners --title "Add OWNERS for the kube-noob community chart" --body "Adds the OWNERS file for the kube-noob community chart (Apache-2.0, https://github.com/aashishmahajan/kube-noob). The chart follows in a separate pull request."
```

After the OWNERS pull request merges:

```bash
cd ~/openshift-helm-charts
git switch main
git pull --ff-only https://github.com/openshift-helm-charts/charts main
git switch -c kube-noob-0.9.1
mkdir -p charts/community/kube-noob/kube-noob/0.9.1
gh release download v0.9.1 --repo kube-noob/kube-noob --pattern "kube-noob-0.9.1.tgz" --dir charts/community/kube-noob/kube-noob/0.9.1
git add charts/community/kube-noob/kube-noob/0.9.1
git commit -s -m "Add kube-noob 0.9.1 community chart"
git push -u origin kube-noob-0.9.1
gh pr create --repo openshift-helm-charts/charts --head aashishmahajan:kube-noob-0.9.1 --title "Add kube-noob 0.9.1 community chart" --body "kube-noob 0.9.1: audit, debugging and learning tools for Kubernetes and OpenShift as an MCP server. Runs under restricted-v2 with NetworkPolicies; signed OCI copy at oci://ghcr.io/kube-noob/charts/kube-noob."
```

To check locally before submitting, run chart-verifier with the community profile on the packaged chart (command in
the action items of the release checklist, [release-readiness.md](release-readiness.md)).

## Sources

- OpenShift Helm charts submission guide: https://github.com/openshift-helm-charts/charts/blob/main/docs/README.md
- chart-verifier checks and profiles: https://github.com/redhat-certification/chart-verifier/blob/main/docs/helm-chart-checks.md
- Community charts already listed by individuals (index): https://github.com/openshift-helm-charts/charts/blob/gh-pages/index.yaml
- Helm charts in the console: https://docs.redhat.com/en/documentation/openshift_dedicated/4/html/applications/working-with-helm-charts
- Community operators pipeline: https://redhat-openshift-ecosystem.github.io/operator-pipelines/users/contributing-prerequisites/
- Red Hat Marketplace sunset: https://access.redhat.com/articles/7130828
- OpenShift AI MCP catalog: https://www.redhat.com/en/blog/mcp-catalog-here-discover-deploy-and-connect-red-hat-openshift-ai
- Artifact Hub repositories: https://artifacthub.io/docs/topics/repositories/
