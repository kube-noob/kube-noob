# Third-party notices and attribution

kube-noob bundles derived data and links to public sources. Licenses were verified from each upstream LICENSE file on
2026-10-27.

## Bundled in the package

| Material | Upstream | License | Where |
|---|---|---|---|
| Kubernetes v1.35.0 JSON schema definitions (made strict, descriptions removed) | yannh/kubernetes-json-schema (generated from kubernetes/kubernetes OpenAPI) | Apache-2.0 | `src/kube_noob/schemas/data/kubernetes-v1.35.0-definitions-*.json` |
| Route, SecurityContextConstraints schemas | datreeio/CRDs-catalog @3eb90d47 (from openshift/api) | MIT (catalog), Apache-2.0 (openshift/api) | `schemas/data/crds/` |
| HTTPRoute, Gateway schemas | datreeio/CRDs-catalog @3eb90d47 (from kubernetes-sigs/gateway-api) | MIT, Apache-2.0 | `schemas/data/crds/` |
| EgressFirewall schema | openshift/cluster-network-operator @a1b26444 | Apache-2.0 | `schemas/data/crds/` |
| Central, SecuredCluster schemas | stackrox/stackrox @3373dee4 | Apache-2.0 | `schemas/data/crds/` |
| RHACS default policy names (references only) | stackrox/stackrox `pkg/defaults/policies/files` | Apache-2.0 | `audit/rules.py` |
| OpenShift 4.20, 4.21 and 4.22 release notes: known and fixed issues (text, issue ids, versions) | openshift/openshift-docs, branches enterprise-4.20 to enterprise-4.22 (commits in each file) | Apache-2.0 | `src/kube_noob/data/known_issues/*.json` |
| OpenShift update risks (conditional updates) for targets 4.18 and later: `to`, `from`, `url`, `name`, `message`, `fixedIn`, `matchingRules` of 356 `blocked-edges/*.yaml` files, with each file's path | openshift/cincinnati-graph-data @7572174a551561c30e07e9b5ca6f156ef5cd513c (2026-10-29), "OpenShift update graph data (c) Red Hat, Inc. and contributors" | Apache-2.0 | `src/kube_noob/data/upgrade_risks/*.json` |
| Ceph health check catalogue: health code names, the summary wording `ceph status` prints, and the Rook and ODF alert names, rule lines and runbook links (meanings, causes, fixes and steps are kube-noob's own words) | ceph/ceph @eb3b634b (`doc/rados/operations/health-checks.rst`, `doc/cephfs/health-messages.rst` and the source files cited per entry); rook/rook @61a8fea1 `deploy/charts/rook-ceph-cluster/prometheus/localrules.yaml`; red-hat-storage/ocs-operator @731e93be `internal/controller/storagecluster/prometheus/localcephrules.yaml` | Ceph docs CC BY-SA 3.0 (cited by section and line, not copied); Ceph code LGPL-2.1 or LGPL-3 (names and message wording cited, no code copied); Rook and ocs-operator Apache-2.0 | `src/kube_noob/data/ceph_health.yaml` |

| FedRAMP 20x Key Security Indicators: the 46 indicator ids, their names, their families and the NIST control ids each one cites (no indicator statement text is shipped) | FedRAMP/rules `fedramp-consolidated-rules.json`, version 2026.11.02.01 (`last_updated` 2026-11-02), sha256 `782faecae3eee4aa2aa9d32cdb0de4c929524f2e41dc1f3d143a94a9ca64c4e3`, retrieved 2026-11-05 | A work of the US Government (FedRAMP, GSA), not subject to US copyright (17 U.S.C. 105). Verified 2026-11-05: the repository has no `LICENSE` or `LICENSE.md` (both 404 on `main`) and its README states no licence, so this is the basis recorded rather than one quoted | `src/kube_noob/audit/fedramp.py` (generated); the vendored extract, which includes the statements and is not packaged, is `vendor/fedramp/fedramp-ksi.json` |
| DISA Kubernetes STIG Version 2 Release 6 (published 2026-02-12): the 92 Group/Vuln ids, rule ids, STIG ids, severities and rule titles (no check, fix or discussion text is shipped; the one-line check summaries are kube-noob's own words) | DISA's benchmark, listed by NIST NCP at https://ncp.nist.gov/checklist/revision/6655; parsed from the metadata tags of MITRE SAF's InSpec profiles mitre/k8s-cluster-stig-baseline @e88e074e5732b6fd74f1a81cab62b45f237b61cd and mitre/k8s-node-stig-baseline @be9be05bb2f402f099c40e6803b7fa2de0291b74 (sha256 over the control files `b2524d154e5a3f9aa017248d5274b4bbc5d72d1b59bc3044464885dd4301f5c1`), retrieved 2026-11-28, because neither ncp.nist.gov nor public.cyber.mil could be read that day | The STIG is a work of the US Government (DISA), not subject to US copyright (17 U.S.C. 105); the MITRE profiles are Apache-2.0 (their `LICENSE.md`), and none of their test code is copied | `src/kube_noob/data/stig/kubernetes-stig.yaml`; the mapping beside it, `crosswalk.yaml`, and `docs/stig.md` are kube-noob's own |
| MITRE ATT&CK for Containers technique ids, names and tactics (18 techniques) | mitre-attack/attack-stix-data `enterprise-attack/enterprise-attack.json` @c2494b29dd268c46a5d0ea0990553e4327cd2253 (Enterprise ATT&CK 20.0) | ATT&CK Terms of Use (below) | `src/kube_noob/vuln/attack.py` |
| The lesson player of `kube-noob learn mechanism --format html`: the isometric drawing helpers, the scene geometry (world box, floor plate, cable routing, camera framing), the sequence diagram, the stylesheet's dark and light tokens and component rules, the icon paths and the playback timings, ported from TypeScript, TSX and CSS to Python, CSS and plain JavaScript | joesabbagh1/kubelearn @02edc5a486b964b31711a8b07edcdac594cc9594 (2026-11-26), "KubeLearn", `src/iso/iso.ts`, `src/scene/world.ts`, `src/components/Stage.tsx`, `src/components/SequenceView.tsx`, `src/components/Icon.tsx`, `src/playback.ts`, `src/index.css` | MIT (notice below) | `src/kube_noob/learn/iso.py`, `src/kube_noob/learn/mechanism_scene.py`, `src/kube_noob/learn/mechanism_player.py`, `src/kube_noob/learn/mechanism_html.py`; every page the command writes carries the credit "Player design ported from KubeLearn by Joe Sabbagh, MIT" as text |

Exact source URLs and upstream SHA-256 digests: `src/kube_noob/schemas/data/PROVENANCE.json`.

MITRE ATT&CK: "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation." Licence (https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt): "The MITRE
Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research,
development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce
MITRE's copyright designation and this license in any such copy." The same licence file carries MITRE's disclaimers
(ATT&CK does not enumerate all possibilities, and is provided as is); every threat model kube-noob writes carries the
copyright designation.

KubeLearn (https://github.com/joesabbagh1/kubelearn), the lesson player ported above:

```
MIT License

Copyright (c) 2026 Joe Sabbagh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

What kube-noob changed in the port: no web font (the page fetches nothing), no green for a kind of object (on that
page green means a hop holds), a marker drawn only for a hop a rule read, and every thing no manifest holds drawn
dashed and labelled. The lessons' text, the walk and its verdicts are kube-noob's own.

## Test fixtures (in the repository, not in the package)

| Material | Upstream | License | Where |
|---|---|---|---|
| OpenShift's etcd static pod manifest, unmodified below a provenance header | openshift/cluster-etcd-operator `bindata/etcd/pod.yaml` @f3a37e434b476fe7da5d3cdc2c893d1f594a5480 (release-4.18) | Apache-2.0 | `tests/fixtures/control-plane/openshift-etcd-pod.yaml` |
| RHACS default policies (89 policies as an export, `exclusions` removed) | stackrox/stackrox `pkg/defaults/policies/files` @dce8fb594ee287a5386fece8be1df3ee1adedc72 | Apache-2.0 | `tests/fixtures/rhacs/default-policies-export.json` |
| RPM version comparison vectors (91 cases) | rpm-software-management/rpm `tests/rpmvercmp.at` @4f7be32ef288a231893dd4c45d4ef36584e3d4b6 | facts used as test data (rpm is GPL-2.0-or-later / LGPL-2.0-or-later; no code copied) | `tests/test_vuln.py` |
| Legacy Kyverno policy snippets (require-labels, disallow-latest-tag, add-network-policy, cleanup-bare-pods, adapted and trimmed; the rest original) | kyverno/policies branch release-1.19 @282e77f6d54e1e1a636190ff2dacc3d02c2d689c; the deny example follows kyverno/website `guides/migration-to-cel.md` @b0131526d7d8d6e4fa80856adb75aa4d7b2f4c89 | Apache-2.0 | `tests/fixtures/kyverno-migrate/` (each file names its source) |
| Scanner report, SBOM, VEX and KEV shapes (synthetic CVE-2099-* data) | written to the field names in aquasecurity/trivy, anchore/grype, anchore/syft, stackrox/stackrox protos, Red Hat CSAF VEX and cisagov/kev-data | original fixtures, Apache-2.0 | `tests/fixtures/vuln/generate.py` |
| Ceph health output shapes (synthetic `ceph health detail`, `ceph status` and their JSON, a Rook CephCluster status) | written to the formats in ceph/ceph `src/mon/HealthMonitor.cc`, `src/mon/Monitor.cc`, `src/mon/health_check.h` @eb3b634b and rook/rook `pkg/apis/ceph.rook.io/v1/types.go` @61a8fea1 | original fixtures, Apache-2.0 | `tests/test_ceph_health.py`, `tests/fixtures/insight/cases.py` |

## Knowledge base

The built-in knowledge docs (`src/kube_noob/data/knowledge/`) are original text (Apache-2.0) that summarise and cite:
Kubernetes documentation (CC BY 4.0, (c) The Kubernetes Authors), Red Hat OpenShift / ROSA documentation
(docs.redhat.com, CC BY-SA 3.0; source repository openshift/openshift-docs, Apache-2.0), Red Hat Cloud Experts
(rh-mobb/documentation, Apache-2.0), openshift/hypershift and openshift/rosa (Apache-2.0), Helm documentation
(helm/helm-www, MIT, (c) 2017 Microsoft Corporation), stackrox/stackrox (Apache-2.0), Kyverno documentation and
policy library (kyverno/website and kyverno/policies, Apache-2.0), OPA Gatekeeper and Open Policy Agent documentation
(open-policy-agent/gatekeeper and open-policy-agent/opa, Apache-2.0), and Rook documentation (rook/rook, Apache-2.0).

## Corpus sources (downloaded by the user / CI, not bundled)

See `src/kube_noob/sources/registry.py`. Sources with non-commercial (ramitsurana/awesome-kubernetes, CC BY-NC 4.0),
copyleft (ansible-collections/kubernetes.core, GPL-3.0) or no license (magnologan/awesome-k8s-security) terms are never
redistributed; Red Hat Jira issue content is used for local retrieval and evaluation only.

## Brand fonts (in the repository, not in the package)

Unmodified web fonts from the upstream release archives, used by the video renders and the brand pages; sources and
SHA-256 sums in `docs/brand/fonts/PROVENANCE.json`, licence texts next to the fonts.

| Material | Upstream | License | Where |
|---|---|---|---|
| Inter 4.1 (`InterVariable.woff2`) | [rsms/inter](https://github.com/rsms/inter) release v4.1 | SIL Open Font License 1.1 | `docs/brand/fonts/` |
| JetBrains Mono 2.304 (Regular, Medium, SemiBold `.woff2`) | [JetBrains/JetBrainsMono](https://github.com/JetBrains/JetBrainsMono) release v2.304 | SIL Open Font License 1.1 | `docs/brand/fonts/` |

## Used to make the demo videos (downloaded at render time, not bundled)

| Material | Upstream | License | Used by |
|---|---|---|---|
| Kokoro-82M voice model and voice pack (`kokoro-v1.0.onnx`, `voices-v1.0.bin`, sha256-pinned) | hexgrad/Kokoro-82M, packaged by thewh1teagle/kokoro-onnx | Apache-2.0 (model), MIT (kokoro-onnx) | `demos/video/audio_kit.py` (default voice) |
| Piper LibriTTS "high" voice (sha256-pinned) | rhasspy/piper | CC BY 4.0 | `demos/video/audio_kit.py --engine piper`, credited on the end card |

The music and sound effects in the videos are generated by `demos/video/audio_kit.py`; no samples are used.

## Trademarks

Kubernetes and Helm are trademarks of The Linux Foundation. Red Hat, OpenShift, Red Hat Advanced Cluster Security and
StackRox are trademarks of Red Hat, Inc. AWS and ROSA-related names are trademarks of Amazon.com, Inc. or its
affiliates. kube-noob is an independent project, not affiliated with or endorsed by these organizations.

## The website (kube-noob.com)

The website is built from this repository's releases by a separate site repository; its own third-party
notices are published at https://kube-noob.com/notices/.
