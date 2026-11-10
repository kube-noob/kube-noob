---
name: rosa-hcp
description: >
  Red Hat OpenShift Service on AWS - ROSA Classic against ROSA with Hosted Control Planes (HyperShift): architecture,
  PrivateLink, machine pools, upgrade sequencing, networking CIDRs, EBS against EFS storage and the Terraform rhcs
  modules. Use when the user mentions ROSA, HCP, hosted control planes, HyperShift, machine pools or the rosa CLI.
---

# ROSA (Classic and HCP)

This skill is knowledge, not tools. It explains the two architectures; it generates and audits nothing.

## What HCP changes

- The control plane runs as **pods in a Red Hat-owned AWS account**, not on nodes in yours. You do not see or patch it.
- Workers live in the customer VPC and reach the control plane over **AWS PrivateLink**.
- The control plane is multi-AZ. **Each machine pool is single-AZ**: three AZs means three machine pools, and a
  workload that must survive a zone loss needs topology spread across them.
- **Upgrade the control plane first, then machine pools separately**, and keep them within two minors of each other.

## Node configuration

On HCP you do not write `MachineConfig` objects. Node-level settings come from `rosa create kubeletconfig` and from the
machine pool itself. A manifest that tries to configure nodes with MachineConfig on HCP is wrong, not merely unusual —
this is kube-noob rule KN-V017.

## Storage

- The default `gp3-csi` is EBS: **ReadWriteOnce and zonal**. A pod that gets rescheduled into another AZ cannot attach
  it, which presents as a pod stuck `Pending` with a volume node-affinity conflict.
- **ReadWriteMany requires EFS**: the AWS EFS CSI Driver Operator, an EFS file system with a mount target in *every*
  worker subnet, NFS 2049/tcp allowed between them, and a StorageClass you create yourself with
  `provisioningMode: efs-ap`. None of that is there by default.

## Networking

Plan the CIDRs before the cluster exists; they cannot be changed afterwards. The machine, service and pod CIDRs must
not overlap each other, the VPC, or anything the VPC peers with or reaches over a transit gateway.

## Terraform

The `terraform-redhat/rhcs` provider has separate modules for Classic and HCP. They are not interchangeable, and the
HCP module expects the VPC, subnets and OIDC provider to exist already.

## What this skill cannot do

It cannot generate ROSA-targeted manifests, audit them for the platform, or search a bundled corpus of ROSA and
HyperShift documentation. Those are kube-noob's tools:

```
pip install kube-noob
kube-noob generate --name orders-api --image registry.example.com/orders:1.4 --platform rosa-hcp
kube-noob audit -f manifests.yaml --platform rosa-hcp
kube-noob search "efs access point storageclass"
```
