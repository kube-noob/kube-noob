"""Static platform knowledge: API groups, kind -> apiVersion catalog, removed APIs, OCP<->Kubernetes
version map, storage provisioner capabilities.

Every table carries the source it was verified against (``SOURCES`` keys) so findings can credit it.
Update procedure: change the table, update the matching ``SOURCES`` entry, run ``pytest tests/test_catalog.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Platform = Literal["kubernetes", "openshift", "rosa-classic", "rosa-hcp"]
PLATFORMS: tuple[Platform, ...] = ("kubernetes", "openshift", "rosa-classic", "rosa-hcp")
OPENSHIFT_FAMILY: frozenset[str] = frozenset({"openshift", "rosa-classic", "rosa-hcp"})
ROSA_FAMILY: frozenset[str] = frozenset({"rosa-classic", "rosa-hcp"})


@dataclass(frozen=True)
class Citation:
    source_id: str
    title: str
    url: str
    license: str = "unknown"
    version: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "sourceId": self.source_id,
            "title": self.title,
            "url": self.url,
            "license": self.license,
            "version": self.version,
        }


SOURCES: dict[str, Citation] = {
    "k8s-deprecation-guide": Citation(
        "k8s-deprecation-guide",
        "Kubernetes Deprecated API Migration Guide",
        "https://kubernetes.io/docs/reference/using-api/deprecation-guide/",
        "CC-BY-4.0",
    ),
    "k8s-pss": Citation(
        "k8s-pss",
        "Kubernetes Pod Security Standards",
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "CC-BY-4.0",
    ),
    "k8s-probes": Citation(
        "k8s-probes",
        "Configure Liveness, Readiness and Startup Probes",
        "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
        "CC-BY-4.0",
    ),
    "k8s-resources": Citation(
        "k8s-resources",
        "Resource Management for Pods and Containers",
        "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
        "CC-BY-4.0",
    ),
    "k8s-pv-access-modes": Citation(
        "k8s-pv-access-modes",
        "Persistent Volumes - Access Modes",
        "https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes",
        "CC-BY-4.0",
    ),
    "k8s-storageclass-binding": Citation(
        "k8s-storageclass-binding",
        "Storage Classes - Volume Binding Mode",
        "https://kubernetes.io/docs/concepts/storage/storage-classes/#volume-binding-mode",
        "CC-BY-4.0",
    ),
    "k8s-admission-webhook-failure-policy": Citation(
        "k8s-admission-webhook-failure-policy",
        "Dynamic Admission Control: failure policy",
        "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy",
        "CC-BY-4.0",
    ),
    # The control-plane rules (KN-S037..KN-S041, G272): upstream source files at the commit they were read at
    # (2026-11-11). Code, so Apache-2.0; linked, not copied.
    "k8s-apiservice-types": Citation(
        "k8s-apiservice-types",
        "kube-aggregator apiregistration/v1 APIServiceSpec (insecureSkipTLSVerify, caBundle, service)",
        "https://github.com/kubernetes/kubernetes/blob/fba15ecefa95cd275b3e6d8dd68b983e976e40dd/staging/src/k8s.io/"
        "kube-aggregator/pkg/apis/apiregistration/v1/types.go",
        "Apache-2.0",
    ),
    "k8s-apiserver-authn-options": Citation(
        "k8s-apiserver-authn-options",
        "kube-apiserver authentication options (--anonymous-auth default, --authentication-config)",
        "https://github.com/kubernetes/kubernetes/blob/fba15ecefa95cd275b3e6d8dd68b983e976e40dd/pkg/kubeapiserver/"
        "options/authentication.go",
        "Apache-2.0",
    ),
    "k8s-apiserver-authz-options": Citation(
        "k8s-apiserver-authz-options",
        "kube-apiserver authorization options (--authorization-mode default, --authorization-config)",
        "https://github.com/kubernetes/kubernetes/blob/fba15ecefa95cd275b3e6d8dd68b983e976e40dd/pkg/kubeapiserver/"
        "options/authorization.go",
        "Apache-2.0",
    ),
    "etcd-embed-config": Citation(
        "etcd-embed-config",
        "etcd server configuration flags and defaults (listen URLs, client-cert-auth)",
        "https://github.com/etcd-io/etcd/blob/d11eca9a9c16b12ae9d93f80f70945dc818c9976/server/embed/config.go",
        "Apache-2.0",
    ),
    "etcd-flags-env": Citation(
        "etcd-flags-env",
        "etcd flags from ETCD_* environment variables, shadowed by the command line",
        "https://github.com/etcd-io/etcd/blob/d11eca9a9c16b12ae9d93f80f70945dc818c9976/pkg/flags/flag.go",
        "Apache-2.0",
    ),
    "openshift-api-apiserver-types": Citation(
        "openshift-api-apiserver-types",
        "openshift/api config/v1 APIServer (spec.encryption.type)",
        "https://github.com/openshift/api/blob/61403fc4e89fad877aba1b000d72a992f388f549/config/v1/types_apiserver.go",
        "Apache-2.0",
    ),
    "openshift-api-oauth-types": Citation(
        "openshift-api-oauth-types",
        "openshift/api config/v1 OAuth identity providers (LDAP insecure)",
        "https://github.com/openshift/api/blob/61403fc4e89fad877aba1b000d72a992f388f549/config/v1/types_oauth.go",
        "Apache-2.0",
    ),
    "hypershift-hostedcluster-types": Citation(
        "hypershift-hostedcluster-types",
        "HyperShift HostedCluster (spec.secretEncryption, spec.configuration.oauth)",
        "https://github.com/openshift/hypershift/blob/f4540b4168b891692eb1c508a336bd4410179803/api/hypershift/"
        "v1beta1/hostedcluster_types.go",
        "Apache-2.0",
    ),
    "k8s-networkpolicy": Citation(
        "k8s-networkpolicy",
        "Network Policies",
        "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
        "CC-BY-4.0",
    ),
    "k8s-pdb": Citation(
        "k8s-pdb",
        "Specifying a Disruption Budget for your Application",
        "https://kubernetes.io/docs/tasks/run-application/configure-pdb/",
        "CC-BY-4.0",
    ),
    "k8s-topology-spread": Citation(
        "k8s-topology-spread",
        "Pod Topology Spread Constraints",
        "https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/",
        "CC-BY-4.0",
    ),
    "k8s-rbac-good-practices": Citation(
        "k8s-rbac-good-practices",
        "Role Based Access Control Good Practices",
        "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
        "CC-BY-4.0",
    ),
    "k8s-secrets-good-practices": Citation(
        "k8s-secrets-good-practices",
        "Good practices for Kubernetes Secrets",
        "https://kubernetes.io/docs/concepts/security/secrets-good-practices/",
        "CC-BY-4.0",
    ),
    "k8s-images": Citation(
        "k8s-images", "Images", "https://kubernetes.io/docs/concepts/containers/images/", "CC-BY-4.0"
    ),
    "k8s-service-lb": Citation(
        "k8s-service-lb",
        "Service - type LoadBalancer",
        "https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer",
        "CC-BY-4.0",
    ),
    "docker-best-practices": Citation(
        "docker-best-practices",
        "Docker - Building best practices (pin base images, apt lists, pipes, USER, multi-stage builds)",
        "https://docs.docker.com/build/building/best-practices/",
        "Apache-2.0",
    ),
    "docker-secrets-arg-env": Citation(
        "docker-secrets-arg-env",
        "Docker build checks - SecretsUsedInArgOrEnv",
        "https://docs.docker.com/reference/build-checks/secrets-used-in-arg-or-env/",
        "Apache-2.0",
    ),
    "docker-build-secrets": Citation(
        "docker-build-secrets",
        "Docker - Build secrets (secret mounts)",
        "https://docs.docker.com/build/building/secrets/",
        "Apache-2.0",
    ),
    "rh-arbitrary-uid": Citation(
        "rh-arbitrary-uid",
        "Red Hat Developer - Adapting Docker and Kubernetes containers to run on OpenShift (arbitrary user ids, "
        "group 0)",
        "https://developers.redhat.com/blog/2020/10/26/adapting-docker-and-kubernetes-containers-to-run-on-red-hat-"
        "openshift-container-platform",
        "link only",
    ),
    "ocp-scc": Citation(
        "ocp-scc",
        "OpenShift - Managing security context constraints",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/authentication_and_authorization/managing-pod-security-policies",
        "CC-BY-SA-3.0",
    ),
    "ocp-routes": Citation(
        "ocp-routes",
        "OpenShift - Route configuration",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/networking/configuring-routes",
        "CC-BY-SA-3.0",
    ),
    "ocp-egressfirewall": Citation(
        "ocp-egressfirewall",
        "OpenShift - Configuring an egress firewall for a project (OVN-Kubernetes)",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/network_security/egress-firewall",
        "CC-BY-SA-3.0",
    ),
    "ocp-deploymentconfig-deprecation": Citation(
        "ocp-deploymentconfig-deprecation",
        "OpenShift 4.14 release notes - DeploymentConfig deprecated",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/4.14/html/release_notes/ocp-4-14-release-notes",
        "CC-BY-SA-3.0",
    ),
    "ocp-storage-access-modes": Citation(
        "ocp-storage-access-modes",
        "OpenShift - Understanding persistent storage (supported access modes)",
        "https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/storage/understanding-persistent-storage",
        "CC-BY-SA-3.0",
    ),
    "rosa-efs": Citation(
        "rosa-efs",
        "ROSA - Setting up the AWS EFS CSI Driver Operator",
        "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/storage/using-container-storage-interface-csi",
        "CC-BY-SA-3.0",
    ),
    "rosa-hcp-architecture": Citation(
        "rosa-hcp-architecture",
        "ROSA with HCP - architecture",
        "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/index",
        "CC-BY-SA-3.0",
    ),
    "aws-ebs-csi": Citation(
        "aws-ebs-csi",
        "AWS EBS CSI driver (ReadWriteOnce block storage, zonal)",
        "https://github.com/kubernetes-sigs/aws-ebs-csi-driver",
        "Apache-2.0",
    ),
    "aws-efs-csi": Citation(
        "aws-efs-csi",
        "AWS EFS CSI driver (ReadWriteMany NFS)",
        "https://github.com/kubernetes-sigs/aws-efs-csi-driver",
        "Apache-2.0",
    ),
    "odf-access-modes": Citation(
        "odf-access-modes",
        "OpenShift Data Foundation - storage classes (RBD block RWO / CephFS RWX)",
        "https://docs.redhat.com/en/documentation/red_hat_openshift_data_foundation/",
        "CC-BY-SA-3.0",
    ),
    "stackrox-policies": Citation(
        "stackrox-policies",
        "StackRox default security policies",
        "https://github.com/stackrox/stackrox/tree/master/pkg/defaults/policies/files",
        "Apache-2.0",
    ),
    "helm-best-practices": Citation(
        "helm-best-practices",
        "Helm Chart Best Practices",
        "https://helm.sh/docs/chart_best_practices/",
        "Apache-2.0",
    ),
    # CVE signatures. The Kubernetes CVE feed (kubernetes.io/docs/reference/issues-security/official-cve-feed/) is
    # generated from the kubernetes/kubernetes issues labelled official-cve-feed; each entry below is one of those
    # issues or a GitHub Security Advisory. They are cited by link and paraphrased: no advisory text is vendored.
    "k8s-cve-2024-10220": Citation(
        "k8s-cve-2024-10220",
        "Kubernetes CVE feed: CVE-2024-10220 arbitrary command execution through gitRepo volumes",
        "https://github.com/kubernetes/kubernetes/issues/128885",
        "link only",
    ),
    "k8s-cve-2025-1767": Citation(
        "k8s-cve-2025-1767",
        "Kubernetes CVE feed: CVE-2025-1767 gitRepo volumes can access local git repositories",
        "https://github.com/kubernetes/kubernetes/issues/130786",
        "link only",
    ),
    "k8s-volumes-gitrepo": Citation(
        "k8s-volumes-gitrepo",
        "Kubernetes Volumes - gitRepo (deprecated since v1.11, last served by v1.35, replaced by an init container)",
        "https://kubernetes.io/docs/concepts/storage/volumes/#gitrepo",
        "CC-BY-4.0",
    ),
    "k8s-cve-2020-8554": Citation(
        "k8s-cve-2020-8554",
        "Kubernetes CVE feed: CVE-2020-8554 man in the middle using LoadBalancer or ExternalIPs (no patch)",
        "https://github.com/kubernetes/kubernetes/issues/97076",
        "link only",
    ),
    "k8s-kep-5707": Citation(
        "k8s-kep-5707",
        "KEP-5707 Deprecate Service.spec.externalIPs (sig-network), verified 2026-11-03",
        "https://www.kubernetes.dev/resources/keps/5707/",
        "link only",
    ),
    "k8s-admission-deny-external-ips": Citation(
        "k8s-admission-deny-external-ips",
        "Kubernetes Admission Controllers Reference - DenyServiceExternalIPs",
        "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#denyserviceexternalips",
        "CC-BY-4.0",
    ),
    "k8s-cve-2023-2431": Citation(
        "k8s-cve-2023-2431",
        "Kubernetes CVE feed: CVE-2023-2431 bypass of seccomp profile enforcement (empty localhostProfile)",
        "https://github.com/kubernetes/kubernetes/issues/118690",
        "link only",
    ),
    "ghsa-cve-2022-0811": Citation(
        "ghsa-cve-2022-0811",
        "GitHub Security Advisory GHSA-6x2m-w449-qwx7: CVE-2022-0811 CRI-O container escape through sysctls "
        "(cr8escape)",
        "https://github.com/advisories/GHSA-6x2m-w449-qwx7",
        "link only",
    ),
    "ghsa-cve-2024-21626": Citation(
        "ghsa-cve-2024-21626",
        "GitHub Security Advisory GHSA-xr7r-f8xq-vfvv: CVE-2024-21626 runc container breakout through a leaked "
        "file descriptor and a working directory under /proc (Leaky Vessels)",
        "https://github.com/advisories/GHSA-xr7r-f8xq-vfvv",
        "link only",
    ),
    "ingress-nginx-annotations-risk": Citation(
        "ingress-nginx-annotations-risk",
        "ingress-nginx - Annotations risk (Critical and High risk annotations, annotations-risk-level)",
        "https://github.com/kubernetes/ingress-nginx/blob/main/docs/user-guide/nginx-configuration/annotations-risk.md",
        "Apache-2.0",
    ),
    "ingress-nginx-configmap": Citation(
        "ingress-nginx-configmap",
        "ingress-nginx - ConfigMap (allow-snippet-annotations, annotations-risk-level, strict-validate-path-type)",
        "https://github.com/kubernetes/ingress-nginx/blob/main/docs/user-guide/nginx-configuration/configmap.md",
        "Apache-2.0",
    ),
    "ingress-nginx-retired": Citation(
        "ingress-nginx-retired",
        "ingress-nginx README - retirement (best-effort maintenance until March 2026, no further releases; the "
        "repository was archived on 2026-03-24; move to a Gateway API implementation)",
        "https://github.com/kubernetes/ingress-nginx",
        "Apache-2.0",
    ),
    "k8s-cve-2021-25742": Citation(
        "k8s-cve-2021-25742",
        "Kubernetes CVE feed: CVE-2021-25742 ingress-nginx custom snippets allow retrieval of every Secret",
        "https://github.com/kubernetes/kubernetes/issues/126811",
        "link only",
    ),
    "k8s-cve-2021-25745": Citation(
        "k8s-cve-2021-25745",
        "Kubernetes CVE feed: CVE-2021-25745 ingress-nginx path field reads the controller's ServiceAccount token",
        "https://github.com/kubernetes/kubernetes/issues/126812",
        "link only",
    ),
    "k8s-cve-2021-25746": Citation(
        "k8s-cve-2021-25746",
        "Kubernetes CVE feed: CVE-2021-25746 ingress-nginx directive injection via annotations",
        "https://github.com/kubernetes/kubernetes/issues/126813",
        "link only",
    ),
    "k8s-cve-2022-4886": Citation(
        "k8s-cve-2022-4886",
        "Kubernetes CVE feed: CVE-2022-4886 ingress-nginx path sanitization bypass (strict-validate-path-type)",
        "https://github.com/kubernetes/kubernetes/issues/126815",
        "link only",
    ),
    "k8s-cve-2023-5043": Citation(
        "k8s-cve-2023-5043",
        "Kubernetes CVE feed: CVE-2023-5043 ingress-nginx configuration-snippet injection",
        "https://github.com/kubernetes/kubernetes/issues/126816",
        "link only",
    ),
    "k8s-cve-2023-5044": Citation(
        "k8s-cve-2023-5044",
        "Kubernetes CVE feed: CVE-2023-5044 ingress-nginx permanent-redirect injection",
        "https://github.com/kubernetes/kubernetes/issues/126817",
        "link only",
    ),
    "k8s-cve-2024-7646": Citation(
        "k8s-cve-2024-7646",
        "Kubernetes CVE feed: CVE-2024-7646 ingress-nginx annotation validation bypass",
        "https://github.com/kubernetes/kubernetes/issues/126744",
        "link only",
    ),
    "k8s-cve-2025-1974": Citation(
        "k8s-cve-2025-1974",
        "Kubernetes CVE feed: CVE-2025-1974 ingress-nginx admission controller remote code execution",
        "https://github.com/kubernetes/kubernetes/issues/131009",
        "link only",
    ),
    "k8s-cve-2025-24514": Citation(
        "k8s-cve-2025-24514",
        "Kubernetes CVE feed: CVE-2025-24514 ingress-nginx auth-url annotation injection",
        "https://github.com/kubernetes/kubernetes/issues/131006",
        "link only",
    ),
    "k8s-cve-2025-1097": Citation(
        "k8s-cve-2025-1097",
        "Kubernetes CVE feed: CVE-2025-1097 ingress-nginx auth-tls-match-cn annotation injection",
        "https://github.com/kubernetes/kubernetes/issues/131007",
        "link only",
    ),
    "k8s-cve-2025-1098": Citation(
        "k8s-cve-2025-1098",
        "Kubernetes CVE feed: CVE-2025-1098 ingress-nginx mirror-target and mirror-host annotation injection",
        "https://github.com/kubernetes/kubernetes/issues/131008",
        "link only",
    ),
    "k8s-cve-2025-24513": Citation(
        "k8s-cve-2025-24513",
        "Kubernetes CVE feed: CVE-2025-24513 ingress-nginx auth secret file path traversal",
        "https://github.com/kubernetes/kubernetes/issues/131005",
        "link only",
    ),
    "k8s-cve-2025-15566": Citation(
        "k8s-cve-2025-15566",
        "Kubernetes CVE feed: CVE-2025-15566 ingress-nginx auth-proxy-set-headers annotation injection",
        "https://github.com/kubernetes/kubernetes/issues/136789",
        "link only",
    ),
    "k8s-cve-2026-1580": Citation(
        "k8s-cve-2026-1580",
        "Kubernetes CVE feed: CVE-2026-1580 ingress-nginx auth-method annotation injection",
        "https://github.com/kubernetes/kubernetes/issues/136677",
        "link only",
    ),
    "k8s-cve-2026-24512": Citation(
        "k8s-cve-2026-24512",
        "Kubernetes CVE feed: CVE-2026-24512 ingress-nginx configuration injection via ImplementationSpecific paths",
        "https://github.com/kubernetes/kubernetes/issues/136678",
        "link only",
    ),
    "k8s-cve-2026-24513": Citation(
        "k8s-cve-2026-24513",
        "Kubernetes CVE feed: CVE-2026-24513 ingress-nginx auth-url validation bypass",
        "https://github.com/kubernetes/kubernetes/issues/136679",
        "link only",
    ),
    "k8s-cve-2026-24514": Citation(
        "k8s-cve-2026-24514",
        "Kubernetes CVE feed: CVE-2026-24514 ingress-nginx validating admission controller denial of service",
        "https://github.com/kubernetes/kubernetes/issues/136680",
        "link only",
    ),
    "k8s-cve-2026-3288": Citation(
        "k8s-cve-2026-3288",
        "Kubernetes CVE feed: CVE-2026-3288 ingress-nginx rewrite-target annotation injection",
        "https://github.com/kubernetes/kubernetes/issues/137560",
        "link only",
    ),
    "k8s-cve-2026-4342": Citation(
        "k8s-cve-2026-4342",
        "Kubernetes CVE feed: CVE-2026-4342 ingress-nginx comment-based configuration injection",
        "https://github.com/kubernetes/kubernetes/issues/137893",
        "link only",
    ),
    # Gap review 2026-10 (docs/evals/gap-review-2026-10.md): feed issues, their fixes and advisories, by link.
    "k8s-cve-2023-3676": Citation(
        "k8s-cve-2023-3676",
        "Kubernetes CVE feed: CVE-2023-3676 insufficient input sanitization on Windows nodes leads to privilege "
        "escalation",
        "https://github.com/kubernetes/kubernetes/issues/119339",
        "link only",
    ),
    "k8s-fix-cve-2023-3676": Citation(
        "k8s-fix-cve-2023-3676",
        "kubernetes/kubernetes PR 120127, the CVE-2023-3676 fix: pass the path and subPath to PowerShell in "
        "environment variables (pkg/volume/util/subpath/subpath_windows.go)",
        "https://github.com/kubernetes/kubernetes/pull/120127",
        "link only",
    ),
    "k8s-cve-2023-5528": Citation(
        "k8s-cve-2023-5528",
        "Kubernetes CVE feed: CVE-2023-5528 insufficient input sanitization in in-tree storage plugin leads to "
        "privilege escalation on Windows nodes",
        "https://github.com/kubernetes/kubernetes/issues/121879",
        "link only",
    ),
    "k8s-cve-2026-3864": Citation(
        "k8s-cve-2026-3864",
        "Kubernetes CVE feed: CVE-2026-3864 CSI Driver for NFS path traversal via subDir",
        "https://github.com/kubernetes/kubernetes/issues/137797",
        "link only",
    ),
    "k8s-cve-2026-3865": Citation(
        "k8s-cve-2026-3865",
        "Kubernetes CVE feed: CVE-2026-3865 CSI Driver for SMB path traversal via subDir",
        "https://github.com/kubernetes/kubernetes/issues/138319",
        "link only",
    ),
    "k8s-cve-2026-2270": Citation(
        "k8s-cve-2026-2270",
        "Kubernetes CVE feed: CVE-2026-2270 StatefulSet and ControllerRevision write permissions allow "
        "cross-namespace pod creation",
        "https://github.com/kubernetes/kubernetes/issues/142097",
        "link only",
    ),
    "k8s-rbac-bootstrap-policy": Citation(
        "k8s-rbac-bootstrap-policy",
        "kubernetes/kubernetes bootstrap RBAC policy (view reads ControllerRevisions; edit writes StatefulSets but not "
        "ControllerRevisions)",
        "https://github.com/kubernetes/kubernetes/blob/master/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go",
        "Apache-2.0",
    ),
    "ghsa-cve-2025-53547": Citation(
        "ghsa-cve-2025-53547",
        "GitHub Security Advisory GHSA-557j-xg8c-q2mm: CVE-2025-53547 Helm chart dependency updating with malicious "
        "Chart.yaml content and a symlinked Chart.lock",
        "https://github.com/advisories/GHSA-557j-xg8c-q2mm",
        "link only",
    ),
    "ghsa-cve-2024-25620": Citation(
        "ghsa-cve-2024-25620",
        "GitHub Security Advisory GHSA-v53g-5gjp-272r: CVE-2024-25620 Helm dependency management path traversal "
        "(a relative path in a chart's name)",
        "https://github.com/advisories/GHSA-v53g-5gjp-272r",
        "link only",
    ),
    "ghsa-cve-2026-35206": Citation(
        "ghsa-cve-2026-35206",
        "GitHub Security Advisory GHSA-hr2v-4r36-88hr: CVE-2026-35206 Helm chart extraction output directory "
        "collapse via a Chart.yaml name dot-segment",
        "https://github.com/advisories/GHSA-hr2v-4r36-88hr",
        "link only",
    ),
    "ghsa-cve-2023-25165": Citation(
        "ghsa-cve-2023-25165",
        "GitHub Security Advisory GHSA-pwcw-6f5g-gxf8: CVE-2023-25165 Helm getHostByName function information "
        "disclosure",
        "https://github.com/advisories/GHSA-pwcw-6f5g-gxf8",
        "link only",
    ),
    "ghsa-cve-2025-32387": Citation(
        "ghsa-cve-2025-32387",
        "GitHub Security Advisory GHSA-5xqw-8hwv-wg92: CVE-2025-32387 Helm stack overflow on a specially crafted "
        "JSON Schema",
        "https://github.com/advisories/GHSA-5xqw-8hwv-wg92",
        "link only",
    ),
    "k8s-configmap": Citation(
        "k8s-configmap",
        "Kubernetes ConfigMaps (a ConfigMap does not provide secrecy or encryption; use a Secret)",
        "https://kubernetes.io/docs/concepts/configuration/configmap/",
        "CC-BY-4.0",
    ),
    "k8s-secret-sa-token": Citation(
        "k8s-secret-sa-token",
        "Kubernetes Secrets - ServiceAccount token Secrets (legacy, long-lived credentials; use the TokenRequest API)",
        "https://kubernetes.io/docs/concepts/configuration/secret/#serviceaccount-token-secrets",
        "CC-BY-4.0",
    ),
    "k8s-rbac-subjects": Citation(
        "k8s-rbac-subjects",
        "Kubernetes RBAC - referring to subjects (system:authenticated, system:unauthenticated and "
        "system:serviceaccounts groups)",
        "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-subjects",
        "CC-BY-4.0",
    ),
    "k8s-hpa-replicas": Citation(
        "k8s-hpa-replicas",
        "Horizontal Pod Autoscaling - Migrating Deployments and StatefulSets to horizontal autoscaling (remove "
        "spec.replicas)",
        "https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/"
        "#migrating-deployments-and-statefulsets-to-horizontal-autoscaling",
        "CC-BY-4.0",
    ),
    "helm-crds": Citation(
        "helm-crds",
        "Helm Chart Best Practices - Custom Resource Definitions (the crds/ directory; Helm does not upgrade or delete "
        "CRDs)",
        "https://helm.sh/docs/chart_best_practices/custom_resource_definitions/",
        "Apache-2.0",
    ),
    "helm-dependencies": Citation(
        "helm-dependencies",
        "Helm Chart Best Practices - Dependencies (https:// repository URLs where possible)",
        "https://helm.sh/docs/chart_best_practices/dependencies/",
        "Apache-2.0",
    ),
    "helm-function-list": Citation(
        "helm-function-list",
        "Helm Template Function List (lookup returns an empty response under helm template; getHostByName needs "
        "--enable-dns)",
        "https://helm.sh/docs/chart_template_guide/function_list/",
        "Apache-2.0",
    ),
}


# --- API groups --------------------------------------------------------------------------------------

# Groups served only by OpenShift (or by operators that ship with OpenShift by default).
OPENSHIFT_ONLY_GROUPS: frozenset[str] = frozenset(
    {
        "route.openshift.io",
        "security.openshift.io",
        "apps.openshift.io",
        "build.openshift.io",
        "image.openshift.io",
        "project.openshift.io",
        "template.openshift.io",
        "quota.openshift.io",
        "user.openshift.io",
        "oauth.openshift.io",
        "authorization.openshift.io",
        "config.openshift.io",
        "operator.openshift.io",
        "machineconfiguration.openshift.io",
        "machine.openshift.io",
        "console.openshift.io",
        "network.openshift.io",
        "cloudcredential.openshift.io",
        "imageregistry.operator.openshift.io",
        "ingress.operator.openshift.io",
        "samples.operator.openshift.io",
        "tuned.openshift.io",
    }
)

# Groups that are present on OpenShift by default but need an add-on on vanilla Kubernetes.
ADDON_GROUPS_ON_VANILLA: dict[str, str] = {
    "k8s.ovn.org": "OVN-Kubernetes CNI (default on OpenShift 4.12+, optional add-on elsewhere)",
    "monitoring.coreos.com": "Prometheus Operator (bundled with OpenShift monitoring)",
    "operators.coreos.com": "Operator Lifecycle Manager (bundled with OpenShift)",
    "platform.stackrox.io": "RHACS / StackRox Operator",
    "gateway.networking.k8s.io": "Gateway API CRDs (install separately on vanilla Kubernetes and OpenShift < 4.19)",
    "snapshot.storage.k8s.io": "CSI external-snapshotter CRDs",
}

# kind -> currently served apiVersions (group/version) on the newest supported platforms.
#: The API groups `KIND_API_VERSIONS` is a complete statement about. A kind name is only unique WITHIN a group, so
#: the table alone cannot say whether an apiVersion is wrong: `Service` is core v1 and also
#: `serving.knative.dev/v1`, `Job` is `batch/v1` and also `batch.volcano.sh/v1alpha1`, and `Build`, `Task`,
#: `Pipeline` and `Workflow` are each several people's CRD. Checking the table without checking the group told a
#: Knative user their correct Service "is not served by serving.knative.dev/v1. Use v1" -- as a CRITICAL, which
#: fails a gate on a valid manifest. A wrong CRITICAL costs more trust than a missed finding, so a kind whose
#: group is not in this set is left to the "no bundled schema" note instead (G233).
KNOWN_API_GROUPS: frozenset[str] = frozenset(
    {
        "",  # core/v1
        "admissionregistration.k8s.io",
        "apiextensions.k8s.io",
        "apps",
        "apps.openshift.io",
        "autoscaling",
        "batch",
        "build.openshift.io",
        "config.openshift.io",
        "discovery.k8s.io",
        "gateway.networking.k8s.io",
        "image.openshift.io",
        "k8s.ovn.org",
        "machine.openshift.io",
        "machineconfiguration.openshift.io",
        "networking.k8s.io",
        "node.k8s.io",
        "operators.coreos.com",
        "platform.stackrox.io",
        "policy",
        "policy.networking.k8s.io",
        "project.openshift.io",
        "quota.openshift.io",
        "rbac.authorization.k8s.io",
        "route.openshift.io",
        "scheduling.k8s.io",
        "security.openshift.io",
        "storage.k8s.io",
        "template.openshift.io",
    }
)


def claims_a_known_group(api_version: str) -> bool:
    """True when this apiVersion names a group kube-noob's kind table is authoritative for."""
    return (api_version.split("/", 1)[0] if "/" in api_version else "") in KNOWN_API_GROUPS


KIND_API_VERSIONS: dict[str, tuple[str, ...]] = {
    "Pod": ("v1",),
    "Service": ("v1",),
    "ConfigMap": ("v1",),
    "Secret": ("v1",),
    "Namespace": ("v1",),
    "ServiceAccount": ("v1",),
    "PersistentVolumeClaim": ("v1",),
    "PersistentVolume": ("v1",),
    "LimitRange": ("v1",),
    "ResourceQuota": ("v1",),
    "Endpoints": ("v1",),
    "Deployment": ("apps/v1",),
    "StatefulSet": ("apps/v1",),
    "DaemonSet": ("apps/v1",),
    "ReplicaSet": ("apps/v1",),
    "Job": ("batch/v1",),
    "CronJob": ("batch/v1",),
    "Ingress": ("networking.k8s.io/v1",),
    "IngressClass": ("networking.k8s.io/v1",),
    "NetworkPolicy": ("networking.k8s.io/v1",),
    "PodDisruptionBudget": ("policy/v1",),
    "HorizontalPodAutoscaler": ("autoscaling/v2", "autoscaling/v1"),
    "StorageClass": ("storage.k8s.io/v1",),
    "CSIDriver": ("storage.k8s.io/v1",),
    "Role": ("rbac.authorization.k8s.io/v1",),
    "RoleBinding": ("rbac.authorization.k8s.io/v1",),
    "ClusterRole": ("rbac.authorization.k8s.io/v1",),
    "ClusterRoleBinding": ("rbac.authorization.k8s.io/v1",),
    "CustomResourceDefinition": ("apiextensions.k8s.io/v1",),
    "PriorityClass": ("scheduling.k8s.io/v1",),
    "RuntimeClass": ("node.k8s.io/v1",),
    "EndpointSlice": ("discovery.k8s.io/v1",),
    "ValidatingWebhookConfiguration": ("admissionregistration.k8s.io/v1",),
    "MutatingWebhookConfiguration": ("admissionregistration.k8s.io/v1",),
    "Gateway": ("gateway.networking.k8s.io/v1",),
    "GatewayClass": ("gateway.networking.k8s.io/v1",),
    "HTTPRoute": ("gateway.networking.k8s.io/v1",),
    "GRPCRoute": ("gateway.networking.k8s.io/v1",),
    # OpenShift
    "Route": ("route.openshift.io/v1",),
    "DeploymentConfig": ("apps.openshift.io/v1",),
    "SecurityContextConstraints": ("security.openshift.io/v1",),
    "BuildConfig": ("build.openshift.io/v1",),
    "Build": ("build.openshift.io/v1",),
    "ImageStream": ("image.openshift.io/v1",),
    "ImageStreamTag": ("image.openshift.io/v1",),
    "Project": ("project.openshift.io/v1",),
    "ProjectRequest": ("project.openshift.io/v1",),
    "Template": ("template.openshift.io/v1",),
    "ClusterResourceQuota": ("quota.openshift.io/v1",),
    "MachineConfig": ("machineconfiguration.openshift.io/v1",),
    "MachineConfigPool": ("machineconfiguration.openshift.io/v1",),
    "KubeletConfig": ("machineconfiguration.openshift.io/v1",),
    "MachineSet": ("machine.openshift.io/v1beta1",),
    "EgressFirewall": ("k8s.ovn.org/v1",),
    "EgressIP": ("k8s.ovn.org/v1",),
    # RHACS / StackRox operator
    "Central": ("platform.stackrox.io/v1alpha1",),
    "SecuredCluster": ("platform.stackrox.io/v1alpha1",),
}

# Kinds whose apiVersion is ambiguous across groups: kind names that also exist in another group.


@dataclass(frozen=True)
class RemovedAPI:
    group_version: str
    kind: str
    deprecated_in: str
    removed_in: str
    replacement: str | None
    notes: str = ""


# The Kubernetes minor this table was read at. The guide lists no removals after v1.32, so for any target up to
# here an empty result is complete. Past here nobody has looked, and an empty result would be a verdict earned by
# absence (G163) -- `beyond_checked` exists so that the answer can say so instead. Raise it only after re-reading
# the guide, because raising it is a claim that somebody did.
CHECKED_THROUGH = "1.37"

# Source: Kubernetes Deprecated API Migration Guide (k8s-deprecation-guide), kubernetes/website
# content/en/docs/reference/using-api/deprecation-guide.md, verified 2026-10-27. The guide lists no removals after
# v1.32; `CHECKED_THROUGH` above records the minor it was read at. Do not add rows without a citation.
REMOVED_APIS: tuple[RemovedAPI, ...] = (
    RemovedAPI("extensions/v1beta1", "Deployment", "1.9", "1.16", "apps/v1", "spec.selector is required"),
    RemovedAPI("apps/v1beta1", "Deployment", "1.9", "1.16", "apps/v1", "spec.selector is required"),
    RemovedAPI("apps/v1beta2", "Deployment", "1.9", "1.16", "apps/v1", "spec.selector is required"),
    RemovedAPI("extensions/v1beta1", "DaemonSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta2", "DaemonSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta1", "StatefulSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta2", "StatefulSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("extensions/v1beta1", "ReplicaSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta1", "ReplicaSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("apps/v1beta2", "ReplicaSet", "1.9", "1.16", "apps/v1"),
    RemovedAPI("extensions/v1beta1", "NetworkPolicy", "1.9", "1.16", "networking.k8s.io/v1"),
    RemovedAPI("extensions/v1beta1", "PodSecurityPolicy", "1.10", "1.16", "policy/v1beta1"),
    RemovedAPI(
        "extensions/v1beta1",
        "Ingress",
        "1.14",
        "1.22",
        "networking.k8s.io/v1",
        "backend.serviceName/servicePort -> backend.service.name/port; pathType is required",
    ),
    RemovedAPI(
        "networking.k8s.io/v1beta1",
        "Ingress",
        "1.19",
        "1.22",
        "networking.k8s.io/v1",
        "backend.serviceName/servicePort -> backend.service.name/port; pathType is required",
    ),
    RemovedAPI("networking.k8s.io/v1beta1", "IngressClass", "1.19", "1.22", "networking.k8s.io/v1"),
    RemovedAPI("rbac.authorization.k8s.io/v1beta1", "ClusterRole", "1.17", "1.22", "rbac.authorization.k8s.io/v1"),
    RemovedAPI(
        "rbac.authorization.k8s.io/v1beta1", "ClusterRoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1"
    ),
    RemovedAPI("rbac.authorization.k8s.io/v1beta1", "Role", "1.17", "1.22", "rbac.authorization.k8s.io/v1"),
    RemovedAPI("rbac.authorization.k8s.io/v1beta1", "RoleBinding", "1.17", "1.22", "rbac.authorization.k8s.io/v1"),
    RemovedAPI("apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", "1.16", "1.22", "apiextensions.k8s.io/v1"),
    RemovedAPI(
        "admissionregistration.k8s.io/v1beta1",
        "ValidatingWebhookConfiguration",
        "1.16",
        "1.22",
        "admissionregistration.k8s.io/v1",
    ),
    RemovedAPI(
        "admissionregistration.k8s.io/v1beta1",
        "MutatingWebhookConfiguration",
        "1.16",
        "1.22",
        "admissionregistration.k8s.io/v1",
    ),
    RemovedAPI("scheduling.k8s.io/v1beta1", "PriorityClass", "1.14", "1.22", "scheduling.k8s.io/v1"),
    RemovedAPI("storage.k8s.io/v1beta1", "StorageClass", "1.19", "1.22", "storage.k8s.io/v1"),
    RemovedAPI("storage.k8s.io/v1beta1", "CSIDriver", "1.19", "1.22", "storage.k8s.io/v1"),
    RemovedAPI("storage.k8s.io/v1beta1", "CSINode", "1.19", "1.22", "storage.k8s.io/v1"),
    RemovedAPI("storage.k8s.io/v1beta1", "VolumeAttachment", "1.19", "1.22", "storage.k8s.io/v1"),
    RemovedAPI("apiregistration.k8s.io/v1beta1", "APIService", "1.19", "1.22", "apiregistration.k8s.io/v1"),
    RemovedAPI("authentication.k8s.io/v1beta1", "TokenReview", "1.19", "1.22", "authentication.k8s.io/v1"),
    RemovedAPI("authorization.k8s.io/v1beta1", "SubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1"),
    RemovedAPI("authorization.k8s.io/v1beta1", "LocalSubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1"),
    RemovedAPI("authorization.k8s.io/v1beta1", "SelfSubjectAccessReview", "1.19", "1.22", "authorization.k8s.io/v1"),
    RemovedAPI("authorization.k8s.io/v1beta1", "SelfSubjectRulesReview", "1.19", "1.22", "authorization.k8s.io/v1"),
    RemovedAPI("certificates.k8s.io/v1beta1", "CertificateSigningRequest", "1.19", "1.22", "certificates.k8s.io/v1"),
    RemovedAPI("coordination.k8s.io/v1beta1", "Lease", "1.19", "1.22", "coordination.k8s.io/v1"),
    RemovedAPI("batch/v1beta1", "CronJob", "1.21", "1.25", "batch/v1"),
    RemovedAPI("discovery.k8s.io/v1beta1", "EndpointSlice", "1.21", "1.25", "discovery.k8s.io/v1"),
    RemovedAPI("events.k8s.io/v1beta1", "Event", "1.19", "1.25", "events.k8s.io/v1"),
    RemovedAPI("autoscaling/v2beta1", "HorizontalPodAutoscaler", "1.23", "1.25", "autoscaling/v2"),
    RemovedAPI(
        "policy/v1beta1",
        "PodDisruptionBudget",
        "1.21",
        "1.25",
        "policy/v1",
        "an empty spec.selector now selects all pods in the namespace",
    ),
    RemovedAPI(
        "policy/v1beta1",
        "PodSecurityPolicy",
        "1.21",
        "1.25",
        None,
        "PodSecurityPolicy was removed; use Pod Security Admission (and SCCs on OpenShift)",
    ),
    RemovedAPI("node.k8s.io/v1beta1", "RuntimeClass", "1.20", "1.25", "node.k8s.io/v1"),
    RemovedAPI(
        "flowcontrol.apiserver.k8s.io/v1beta1",
        "FlowSchema",
        "1.23",
        "1.26",
        "flowcontrol.apiserver.k8s.io/v1",
        "flowcontrol v1 is GA from 1.29; on 1.26-1.28 use v1beta3",
    ),
    RemovedAPI(
        "flowcontrol.apiserver.k8s.io/v1beta1",
        "PriorityLevelConfiguration",
        "1.23",
        "1.26",
        "flowcontrol.apiserver.k8s.io/v1",
        "flowcontrol v1 is GA from 1.29; on 1.26-1.28 use v1beta3",
    ),
    RemovedAPI("autoscaling/v2beta2", "HorizontalPodAutoscaler", "1.23", "1.26", "autoscaling/v2"),
    RemovedAPI("storage.k8s.io/v1beta1", "CSIStorageCapacity", "1.24", "1.27", "storage.k8s.io/v1"),
    RemovedAPI("flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema", "1.26", "1.29", "flowcontrol.apiserver.k8s.io/v1"),
    RemovedAPI(
        "flowcontrol.apiserver.k8s.io/v1beta2",
        "PriorityLevelConfiguration",
        "1.26",
        "1.29",
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    RemovedAPI("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema", "1.29", "1.32", "flowcontrol.apiserver.k8s.io/v1"),
    RemovedAPI(
        "flowcontrol.apiserver.k8s.io/v1beta3",
        "PriorityLevelConfiguration",
        "1.29",
        "1.32",
        "flowcontrol.apiserver.k8s.io/v1",
    ),
)

# OpenShift Container Platform minor -> Kubernetes minor. Source: OCP release notes ("based on Kubernetes 1.x").
OCP_TO_K8S: dict[str, str] = {
    "4.12": "1.25",
    "4.13": "1.26",
    "4.14": "1.27",
    "4.15": "1.28",
    "4.16": "1.29",
    "4.17": "1.30",
    "4.18": "1.31",
    "4.19": "1.32",
    "4.20": "1.33",
    "4.21": "1.34",
    "4.22": "1.35",
    # 4.23 is not GA, and this row is behaviourally a no-op: the +13 extrapolation below already answers 1.36
    # for it. It is written out because openshift/kubernetes has a release-4.23 branch and the rebase bot is
    # opening v1.36.x rebases against it (openshift/kubernetes#2839, "Rebase v1.36.6 in release-4.23", opened
    # 2 November 2026 -- closed, not merged, so this is the direction of travel and not a settled mapping).
    "4.23": "1.36",
}

DEFAULT_K8S_VERSION = "1.35"
DEFAULT_OCP_VERSION = "4.22"


def parse_minor(v: str) -> tuple[int, int]:
    """'1.29' / 'v1.29.3' / '4.16' -> (1, 29)."""
    s = v.strip().lstrip("vV")
    parts = s.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].split("-")[0].isdigit():
        raise ValueError(f"Expected a version like '1.29' or '4.16', got {v!r}")
    return int(parts[0]), int(parts[1].split("-")[0])


def k8s_version_for(platform: str, version: str | None) -> str:
    """Resolve the Kubernetes minor version that a platform/version combination serves."""
    if platform in OPENSHIFT_FAMILY:
        ocp = version or DEFAULT_OCP_VERSION
        major, minor = parse_minor(ocp)
        if major == 1:  # caller passed a Kubernetes version for an OpenShift target
            return f"{major}.{minor}"
        key = f"{major}.{minor}"
        if key in OCP_TO_K8S:
            return OCP_TO_K8S[key]
        # Unknown future OCP minor: OCP 4.x tracks Kubernetes 1.(x+13) for every release since 4.12.
        if major == 4 and minor >= 12:
            return f"1.{minor + 13}"
        raise ValueError(f"Unknown OpenShift version {ocp!r}; supported: {', '.join(OCP_TO_K8S)}")
    if version is None:
        return DEFAULT_K8S_VERSION
    major, minor = parse_minor(version)
    if major != 1:
        # Kubernetes minors are 1.x. `--platform kubernetes --version 4.22` was taken at face value as a
        # Kubernetes 1-like minor "4.22", which does not exist: every version-gated rule then answered about a
        # fictional release, and only the beyond-the-table caveat kept it from being a silent wrong answer.
        # Refuse rather than guess which half the caller meant -- mapping it through the OpenShift table would
        # also silently change which rules apply, since some of them exist only on OpenShift.
        raise ValueError(
            f"{version!r} is not a Kubernetes version: Kubernetes minors are 1.x. For OpenShift {major}.{minor} "
            f"pass --platform openshift (or rosa-classic, rosa-hcp) with --version {major}.{minor}"
        )
    return f"{major}.{minor}"


def beyond_checked(k8s_version: str) -> bool:
    """Is this target past the last Kubernetes minor the removal table was read at?

    True means the removal and deprecation answers for it are "nothing through ``CHECKED_THROUGH``", not
    "nothing". The caller is owed that difference.
    """
    return parse_minor(k8s_version) > parse_minor(CHECKED_THROUGH)


def not_checked_beyond(k8s_version: str) -> dict[str, str] | None:
    """The note a result carries when its target is past the ceiling, or ``None`` when it is covered.

    Returning ``None`` for a covered target keeps every result that was already correct byte-identical.
    """
    if not beyond_checked(k8s_version):
        return None
    return {
        "removalData": CHECKED_THROUGH,
        "target": k8s_version,
        "why": (
            f"The Kubernetes deprecated-API migration guide was read at {CHECKED_THROUGH}, so no removed or "
            f"deprecated API finding here means none through {CHECKED_THROUGH} -- not none in {k8s_version}. "
            f"Check the guide for {k8s_version} before reading this as clean."
        ),
    }


def removed_api(group_version: str, kind: str, k8s_version: str) -> RemovedAPI | None:
    target = parse_minor(k8s_version)
    for r in REMOVED_APIS:
        if r.group_version == group_version and r.kind == kind and target >= parse_minor(r.removed_in):
            return r
    return None


def deprecated_api(group_version: str, kind: str, k8s_version: str) -> RemovedAPI | None:
    """Deprecated in the target version but not yet removed."""
    target = parse_minor(k8s_version)
    for r in REMOVED_APIS:
        if (
            r.group_version == group_version
            and r.kind == kind
            and parse_minor(r.deprecated_in) <= target < parse_minor(r.removed_in)
        ):
            return r
    return None


def api_group(api_version: str) -> str:
    return api_version.split("/", 1)[0] if "/" in api_version else ""


# --- Storage -----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Provisioner:
    name: str
    rwx_filesystem: bool
    rwx_block: bool
    zonal: bool
    description: str
    citation: str


PROVISIONERS: dict[str, Provisioner] = {
    "ebs.csi.aws.com": Provisioner(
        "ebs.csi.aws.com", False, False, True, "AWS EBS block volumes (single node, single AZ)", "aws-ebs-csi"
    ),
    "kubernetes.io/aws-ebs": Provisioner(
        "kubernetes.io/aws-ebs", False, False, True, "legacy in-tree AWS EBS (migrated to CSI)", "aws-ebs-csi"
    ),
    "efs.csi.aws.com": Provisioner(
        "efs.csi.aws.com", True, False, False, "AWS EFS (NFSv4.1, multi-AZ, ReadWriteMany)", "aws-efs-csi"
    ),
    "openshift-storage.rbd.csi.ceph.com": Provisioner(
        "openshift-storage.rbd.csi.ceph.com",
        False,
        True,
        False,
        "ODF Ceph RBD block (RWO filesystem; RWX only with volumeMode: Block)",
        "odf-access-modes",
    ),
    "openshift-storage.cephfs.csi.ceph.com": Provisioner(
        "openshift-storage.cephfs.csi.ceph.com",
        True,
        False,
        False,
        "ODF CephFS shared filesystem (RWX)",
        "odf-access-modes",
    ),
    "rbd.csi.ceph.com": Provisioner(
        "rbd.csi.ceph.com", False, True, False, "Ceph RBD block (RWX only with volumeMode: Block)", "odf-access-modes"
    ),
    "cephfs.csi.ceph.com": Provisioner("cephfs.csi.ceph.com", True, False, False, "CephFS (RWX)", "odf-access-modes"),
    "csi.vsphere.vmware.com": Provisioner(
        "csi.vsphere.vmware.com",
        False,
        False,
        False,
        "vSphere CNS block (RWO); RWX file volumes need vSAN File Services",
        "ocp-storage-access-modes",
    ),
    "pd.csi.storage.gke.io": Provisioner(
        "pd.csi.storage.gke.io",
        False,
        False,
        True,
        "GCP Persistent Disk (zonal block, RWO)",
        "ocp-storage-access-modes",
    ),
    "disk.csi.azure.com": Provisioner(
        "disk.csi.azure.com", False, False, True, "Azure Disk (zonal block, RWO)", "ocp-storage-access-modes"
    ),
    "file.csi.azure.com": Provisioner(
        "file.csi.azure.com", True, False, False, "Azure Files (SMB/NFS, RWX)", "ocp-storage-access-modes"
    ),
    "topolvm.io": Provisioner(
        "topolvm.io", False, False, False, "LVM Storage / TopoLVM node-local volumes (RWO)", "ocp-storage-access-modes"
    ),
    "nfs.csi.k8s.io": Provisioner("nfs.csi.k8s.io", True, False, False, "NFS CSI driver (RWX)", "k8s-pv-access-modes"),
    "rancher.io/local-path": Provisioner(
        "rancher.io/local-path", False, False, False, "local-path provisioner (node-local, RWO)", "k8s-pv-access-modes"
    ),
}

# Well-known StorageClass names that ship by default on the respective platforms.
KNOWN_STORAGE_CLASSES: dict[str, str] = {
    "gp3-csi": "ebs.csi.aws.com",
    "gp2-csi": "ebs.csi.aws.com",
    "gp3": "ebs.csi.aws.com",
    "gp2": "kubernetes.io/aws-ebs",
    "efs-sc": "efs.csi.aws.com",
    "ocs-storagecluster-ceph-rbd": "openshift-storage.rbd.csi.ceph.com",
    "ocs-storagecluster-ceph-rbd-virtualization": "openshift-storage.rbd.csi.ceph.com",
    "ocs-storagecluster-cephfs": "openshift-storage.cephfs.csi.ceph.com",
    "thin-csi": "csi.vsphere.vmware.com",
    "standard-csi": "pd.csi.storage.gke.io",
    "managed-csi": "disk.csi.azure.com",
    "azurefile-csi": "file.csi.azure.com",
    "lvms-vg1": "topolvm.io",
    "local-path": "rancher.io/local-path",
    # "standard" is deliberately absent: it is local-path on kind, GCE PD on GKE and hostPath on minikube.
}

# Recommended StorageClass per platform and access mode for the generator.
DEFAULT_STORAGE_CLASS: dict[str, dict[str, str | None]] = {
    "kubernetes": {"ReadWriteOnce": None, "ReadWriteMany": None},
    "openshift": {"ReadWriteOnce": None, "ReadWriteMany": "ocs-storagecluster-cephfs"},
    "rosa-classic": {"ReadWriteOnce": "gp3-csi", "ReadWriteMany": "efs-sc"},
    "rosa-hcp": {"ReadWriteOnce": "gp3-csi", "ReadWriteMany": "efs-sc"},
}
