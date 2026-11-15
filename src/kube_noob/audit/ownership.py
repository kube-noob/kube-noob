"""Who owns each control-plane component on each platform, as a table (G304).

`--platform rosa-hcp` and `--platform rosa-classic` existed before this and the rules did not know what they
meant. On ROSA with hosted control planes the API server and etcd are not in the cluster at all, so a rule that
read a kube-apiserver manifest there was reading something Red Hat owns and the customer cannot change -- and a
rule that found nothing to read came back CLEAN, which is the worst of the three possible answers: it says the
control plane was examined and is fine when it was never the customer's to configure.

Red Hat's own documentation is the source, fetched 2026-11-15:

* ROSA architecture models,
  https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models
  -- Table 3.1, ROSA with HCP: "Control plane components, such as the API server etcd database, are hosted in a
  Red Hat-owned AWS account." The same table for ROSA Classic: "hosted in a customer-owned AWS account". Section
  3.2: "The worker nodes are deployed in your AWS account and run on your VPC private subnets."
* ROSA policies and service definition (the responsibility assignment matrix),
  https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/introduction_to_rosa/policies-and-service-definition
  -- "Virtual compute management (control plane, infrastructure, and worker nodes)" is Red Hat's in all five
  areas (incident and operations management, change management, access and identity authorization, security and
  regulation compliance, disaster recovery) on BOTH architectures. The customer's rows are the machine pools:
  "Monitor and manage Amazon EC2 worker nodes by creating a machine pool using the OpenShift Cluster Manager or
  ROSA CLI."
* Configuring PID limits,
  https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/cluster_administration/rosa-configuring-pid-limits
  -- the customer DOES configure the worker kubelet, through a `KubeletConfig` object the `rosa` CLI creates and
  a machine pool it is attached to: "Create a new `KubeletConfig` object for your cluster", "Associate the new
  `KubeletConfig` object with a new or existing machine pool."

So the split is not "managed platform, read nothing": the worker kubelet is the customer's on every ROSA
architecture, and the API server, etcd and the control-plane kubelet are not. A table says that once; the
scattered `ctx.is_openshift` conditionals this replaces said it four times and did not distinguish the two ROSA
architectures from each other at all.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The documentation this table was read from, and when, for a message that has to say where it got this.
RESPONSIBILITY_SOURCE = "Red Hat's ROSA architecture models and responsibility assignment matrix, retrieved 2026-11-15"

#: The components whose ownership differs by platform. `kubelet` is a kubelet whose node role the input does not
#: state, which on a managed platform is treated as the control plane's: assuming the worker role there would
#: read Red Hat's own configuration as the customer's (class 4).
COMPONENTS = ("kube-apiserver", "etcd", "kubelet", "kubelet-worker")


@dataclass(frozen=True)
class Ownership:
    """Who may change this component on this platform, and the fixed phrase a decline prints."""

    #: True when the person running kube-noob can change it, so the rule reads the manifest.
    theirs: bool
    #: The reason a rule declines, as a sentence fragment with no text from the input (G281). "" when theirs.
    why: str = ""


_CUSTOMERS = Ownership(theirs=True)

#: ROSA with hosted control planes: the control plane runs in a Red Hat-owned AWS account, so it is neither the
#: customer's to configure nor present in the customer's cluster to be read.
_HCP_CONTROL_PLANE = Ownership(
    theirs=False,
    why=(
        "the control plane is managed by Red Hat on ROSA with hosted control planes and runs in a Red Hat-owned "
        "AWS account rather than in this cluster, so this is not yours to configure"
    ),
)
#: ROSA Classic: the control plane runs in the customer's own AWS account, but Red Hat manages it in all five
#: areas of the responsibility matrix, so its settings are still not the customer's to change.
_CLASSIC_CONTROL_PLANE = Ownership(
    theirs=False,
    why=(
        "the control plane is managed by Red Hat on ROSA Classic -- it runs in your AWS account, but virtual "
        "compute management of the control plane is Red Hat's in every area of the responsibility matrix -- so "
        "this is not yours to configure"
    ),
)
#: Self-managed OpenShift: the cluster's own operators render these, from the platform's configuration rather
#: than from arguments a person wrote, so a manifest here is not what the component runs with.
_OPENSHIFT_CONTROL_PLANE = Ownership(
    theirs=False,
    why=(
        "the control plane is operator-managed on OpenShift and is configured through the platform's own "
        "configuration rather than by these arguments"
    ),
)
#: The ROSA control-plane kubelet: on HCP there is no control-plane node in the customer's account at all.
_HCP_CONTROL_PLANE_KUBELET = Ownership(
    theirs=False,
    why=(
        "no control-plane node runs in this cluster on ROSA with hosted control planes, and the kubelet of a "
        "node Red Hat runs is not yours to configure"
    ),
)

#: platform -> component -> who owns it. Every platform names every component, so a platform added to
#: `catalog.PLATFORMS` without a row here fails `tests/test_rosa_ownership.py` rather than falling through to
#: "the customer's" (class 4).
RESPONSIBILITY: dict[str, dict[str, Ownership]] = {
    "kubernetes": {
        "kube-apiserver": _CUSTOMERS,
        "etcd": _CUSTOMERS,
        "kubelet": _CUSTOMERS,
        "kubelet-worker": _CUSTOMERS,
    },
    "openshift": {
        "kube-apiserver": _OPENSHIFT_CONTROL_PLANE,
        "etcd": _OPENSHIFT_CONTROL_PLANE,
        "kubelet": _CUSTOMERS,  # a KubeletConfig CR or a MachineConfig is how a person configures it here
        "kubelet-worker": _CUSTOMERS,
    },
    "rosa-classic": {
        "kube-apiserver": _CLASSIC_CONTROL_PLANE,
        "etcd": _CLASSIC_CONTROL_PLANE,
        "kubelet": _CLASSIC_CONTROL_PLANE,
        "kubelet-worker": _CUSTOMERS,  # `rosa create kubeletconfig` + a machine pool: documented and supported
    },
    "rosa-hcp": {
        "kube-apiserver": _HCP_CONTROL_PLANE,
        "etcd": _HCP_CONTROL_PLANE,
        "kubelet": _HCP_CONTROL_PLANE_KUBELET,
        "kubelet-worker": _CUSTOMERS,
    },
}


def owner(platform: str, component: str) -> Ownership:
    """Who owns ``component`` on ``platform``.

    An unknown platform is the customer's, because kube-noob's own `--platform` values are closed
    (`catalog.PLATFORMS`) and a value outside them has already been refused by the CLI; treating it as managed
    would silence every control-plane rule on a typo.
    """
    return RESPONSIBILITY.get(platform, {}).get(component, _CUSTOMERS)
