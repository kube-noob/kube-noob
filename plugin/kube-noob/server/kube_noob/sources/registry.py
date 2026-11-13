"""Registry of public sources that kube-noob learns from, with license and attribution.

``redistributable`` decides whether derived records may ship in published artifacts (container images, datasets).
Rules: permissive (Apache-2.0, MIT, BSD) and CC-BY -> True with attribution; NonCommercial, copyleft (GPL) or unknown
terms -> False (still usable for local retrieval). Licenses were verified from each repository's LICENSE file.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GitSource:
    source_id: str
    repo: str
    sparse_paths: tuple[str, ...]
    include: tuple[str, ...]
    license: str
    redistributable: bool
    attribution: str
    exclude: tuple[str, ...] = ()
    ref: str | None = None
    min_chars: int = 200


GIT_SOURCES: tuple[GitSource, ...] = (
    GitSource(
        "k8s-docs",
        "kubernetes/website",
        ("content/en/docs/concepts", "content/en/docs/tasks", "content/en/docs/reference/using-api"),
        ("content/en/docs/*.md",),
        "CC-BY-4.0",
        True,
        "Kubernetes Documentation (c) The Kubernetes Authors, CC BY 4.0, https://kubernetes.io/docs/",
    ),
    GitSource(
        "ocp-docs",
        "openshift/openshift-docs",
        (
            "modules/nw-*",
            "modules/storage-*",
            "modules/security-context-constraints-*",
            "modules/rosa-*",
            "modules/hcp-*",
            "modules/persistent-storage-*",
            "modules/understanding-*",
            "modules/nodes-*",
            "modules/op-*",
            "modules/support-*",
            "modules/troubleshooting-*",
        ),
        ("modules/*.adoc",),
        "Apache-2.0",
        True,
        "OpenShift documentation source (c) Red Hat, Inc. and contributors, Apache-2.0, "
        "https://github.com/openshift/openshift-docs",
    ),
    GitSource(
        "rosa-experts",
        "rh-mobb/documentation",
        ("content/rosa", "content/misc"),
        ("content/*.md",),
        "Apache-2.0",
        True,
        "Red Hat Cloud Experts / MOBB documentation, Apache-2.0, https://cloud.redhat.com/experts/",
    ),
    GitSource(
        "hypershift-docs",
        "openshift/hypershift",
        ("docs/content",),
        ("docs/content/*.md",),
        "Apache-2.0",
        True,
        "HyperShift (Hosted Control Planes) documentation, Apache-2.0, https://github.com/openshift/hypershift",
    ),
    GitSource(
        "rosa-cli",
        "openshift/rosa",
        ("README.md", "docs"),
        ("README.md", "docs/*.md"),
        "Apache-2.0",
        True,
        "ROSA CLI, Apache-2.0, https://github.com/openshift/rosa",
        min_chars=100,
    ),
    GitSource(
        "tf-rosa-hcp",
        "terraform-redhat/terraform-rhcs-rosa-hcp",
        ("README.md", "examples", "modules"),
        ("README.md", "examples/*.tf", "examples/*.md", "modules/*.md"),
        "Apache-2.0",
        True,
        "Terraform RHCS ROSA HCP module (c) Red Hat, Apache-2.0, "
        "https://github.com/terraform-redhat/terraform-rhcs-rosa-hcp",
    ),
    GitSource(
        "helm-docs",
        "helm/helm-www",
        ("docs",),
        ("docs/*.md", "docs/*.mdx"),
        "MIT",
        True,
        "Helm documentation (c) The Helm Authors, MIT, https://helm.sh/docs/",
        exclude=("docs/_*", "*/_*"),
    ),
    GitSource(
        "stackrox-policies",
        "stackrox/stackrox",
        ("pkg/defaults/policies/files",),
        ("pkg/defaults/policies/files/*.json",),
        "Apache-2.0",
        True,
        "StackRox default policies (c) StackRox / Red Hat, Apache-2.0, https://github.com/stackrox/stackrox",
        min_chars=50,
    ),
    GitSource(
        "stackrox-changelog",
        "stackrox/stackrox",
        ("CHANGELOG.md",),
        ("CHANGELOG.md",),
        "Apache-2.0",
        True,
        "StackRox CHANGELOG, Apache-2.0, https://github.com/stackrox/stackrox",
    ),
    GitSource(
        "gitops-catalog",
        "redhat-cop/gitops-catalog",
        ("README.md", "*/README.md"),
        ("*README.md",),
        "Apache-2.0",
        True,
        "Red Hat CoP GitOps catalog, Apache-2.0, https://github.com/redhat-cop/gitops-catalog",
    ),
    GitSource(
        "efs-csi",
        "kubernetes-sigs/aws-efs-csi-driver",
        ("docs", "README.md", "examples/kubernetes"),
        ("docs/*.md", "README.md", "examples/kubernetes/*.md", "examples/kubernetes/*.yaml"),
        "Apache-2.0",
        True,
        "AWS EFS CSI driver, Apache-2.0, https://github.com/kubernetes-sigs/aws-efs-csi-driver",
    ),
    GitSource(
        "k8s-examples",
        "kubernetes/examples",
        ("README.md", "*/README.md"),
        ("*README.md",),
        "Apache-2.0",
        True,
        "Kubernetes examples, Apache-2.0, https://github.com/kubernetes/examples",
    ),
    GitSource(
        "ckad-exercises",
        "dgkanatsios/CKAD-exercises",
        ("*.md",),
        ("*.md",),
        "MIT",
        True,
        "CKAD exercises (c) Dimitris-Ilias Gkanatsios, MIT, https://github.com/dgkanatsios/CKAD-exercises",
    ),
    GitSource(
        "k8s-hard-way",
        "kelseyhightower/kubernetes-the-hard-way",
        ("docs", "README.md"),
        ("docs/*.md", "README.md"),
        "Apache-2.0",
        True,
        "Kubernetes The Hard Way (c) Kelsey Hightower, Apache-2.0, "
        "https://github.com/kelseyhightower/kubernetes-the-hard-way",
    ),
    GitSource(
        "casl-ansible",
        "redhat-cop/casl-ansible",
        ("README.md", "docs", "playbooks"),
        ("README.md", "docs/*.md", "playbooks/*.md"),
        "Apache-2.0",
        True,
        "Red Hat CoP casl-ansible, Apache-2.0, https://github.com/redhat-cop/casl-ansible",
    ),
    GitSource(
        "ansible-k8s-core",
        "ansible-collections/kubernetes.core",
        ("README.md", "docs"),
        ("README.md", "docs/*.rst", "docs/*.md"),
        "GPL-3.0-or-later",
        False,
        "kubernetes.core Ansible collection, GPL-3.0 (local retrieval only; not redistributed), "
        "https://github.com/ansible-collections/kubernetes.core",
    ),
    GitSource(
        "awesome-kubernetes",
        "ramitsurana/awesome-kubernetes",
        ("README.md", "docs"),
        ("README.md", "docs/*.md"),
        "CC-BY-NC-4.0",
        False,
        "Awesome Kubernetes (c) Ramit Surana, CC BY-NC 4.0 (non-commercial: local retrieval only)",
    ),
)

# Repositories whose release history (tags) kube-noob tracks for version timelines.
HISTORY_REPOS: dict[str, str] = {
    "kubernetes": "kubernetes/kubernetes",
    "helm": "helm/helm",
    "stackrox": "stackrox/stackrox",
    "rosa-cli": "openshift/rosa",
    "hypershift": "openshift/hypershift",
    "terraform-rosa-hcp": "terraform-redhat/terraform-rhcs-rosa-hcp",
}


def by_id(source_id: str) -> GitSource:
    for s in GIT_SOURCES:
        if s.source_id == source_id:
            return s
    raise KeyError(f"unknown source {source_id!r}; known: {', '.join(s.source_id for s in GIT_SOURCES)}")
