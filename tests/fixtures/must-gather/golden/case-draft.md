# Support case draft

> Written by kube-noob from a must-gather. Replace every [FILL IN: ...] before you submit. Everything else comes from the must-gather or the bundled indexes; check it.

## Problem statement

[FILL IN: what is not working, as your users see it, in one or two sentences]

What the must-gather shows:

- CRITICAL: the cluster version operator reports Failing
- CRITICAL: cluster operator image-registry is not Available
- HIGH: cluster operator authentication is Degraded
- HIGH: machine config pool worker reports Degraded
- HIGH: machine config pool worker reports NodeDegraded

## Environment

- OpenShift Container Platform 4.20.3 (channel stable-4.20); update to 4.20.4 (Partial)
- Platform: AWS, control plane topology HighlyAvailable
- Nodes: 2 (1 control plane), 1 Ready
- Cluster operators: 3, 2 Available, 1 Degraded
- Operators installed with OLM: rhacs-operator.v4.6.0 (Failed)
- Must-gather `must-gather.tar.gz`, collected 2026-10-28 10:00:05.1 +0000 UTC
- Gather images: openshift/must-gather 4.20.3

## Timeline

- [FILL IN: when it started (date, time and time zone)]
- [FILL IN: what changed before it started: an update, a configuration change, a new workload]
- Update to 4.20.4: Partial, started 2026-10-28T08:00:00Z (ClusterVersion history)
- Update to 4.20.3: Completed (ClusterVersion history)
- Must-gather collected: 2026-10-28 10:00:05.1 +0000 UTC

## Frequency

[FILL IN: constant, intermittent or once; how often and since when]

## Business impact

[FILL IN: who is affected, production or not, any workaround in place]

The most severe finding is critical; [FILL IN: the case severity you choose, and why]

## Evidence

- The must-gather: `must-gather.tar.gz` (attach it to the case)
- 1. critical: the cluster version operator reports Failing: `cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml`
- 2. critical: cluster operator image-registry is not Available: `cluster-scoped-resources/config.openshift.io/clusteroperators/image-registry.yaml`
- 3. high: cluster operator authentication is Degraded: `cluster-scoped-resources/config.openshift.io/clusteroperators/authentication.yaml`
- 4. high: machine config pool worker reports Degraded: `cluster-scoped-resources/machineconfiguration.openshift.io/machineconfigpools/worker.yaml`
- 5. high: machine config pool worker reports NodeDegraded: `cluster-scoped-resources/machineconfiguration.openshift.io/machineconfigpools/worker.yaml`
- 6. high: worker node worker-1 is NotReady: `cluster-scoped-resources/core/nodes/worker-1.yaml`
- 7. high: worker node worker-1 reports MemoryPressure: `cluster-scoped-resources/core/nodes/worker-1.yaml`
- 8. high: operator rhacs-operator.v4.6.0 is Failed: `namespaces/openshift-operator-lifecycle-manager/operators.coreos.com/clusterserviceversions.yaml`
- 9. high: shop/pod api-5c6d: container api: ImagePullBackOff: `namespaces/shop/pods/api-5c6d/api-5c6d.yaml`
- 10. high: shop/ReplicaSet/web-6b8f9: container web: CrashLoopBackOff (2 pods), 14 restarts: `namespaces/shop/pods/web-7d9f/web-7d9f.yaml`, `namespaces/shop/pods/web-7d9f/web/web/logs/previous.log`
- 11. medium: minor version updates are blocked (Upgradeable=False): `cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml`
- 12. medium: openshift-monitoring/pod prometheus-k8s-0: container prometheus was OOMKilled before its last restart, 3 restarts: `namespaces/openshift-monitoring/pods/prometheus-k8s-0/prometheus-k8s-0.yaml`
- 13. medium: Unhealthy: 1 warning event(s) on 1 object(s) in 1 namespace(s): `namespaces/openshift-etcd/core/events.yaml`
- 14. medium: etcd leader changed: 2 election term(s) seen, terms 5 to 6, 1 'lost leader' line(s): `namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs/current.log`
- 15. medium: etcd logged "apply request took too long" 1 time(s) on 1 member(s): `namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs/current.log`
- Evidence is partial: operator inventory: 1 operator from OLM data; Subscriptions were not read, so catalog, channel and approval are not determined for every operator; 1 operator state(s) not determined; operator known issues: the inventory is partial; the cluster is updating to 4.20.4; release notes: the running release 4.20.3 was searched and the update target 4.20.4 was not

## Matched known issues and bugs

- OCPBUGS-1: etcd leader elections under catalog sync I/O (Fixed in 4.20.13; you run 4.20.3, fixed in 4.20.13; matches finding 14, 16)

## Steps already taken

[FILL IN: what you tried and what happened]

Read-only checks kube-noob suggests running first (paste their output into the case):

```bash
oc adm upgrade
oc get clusterversion version -o yaml
oc get clusteroperator image-registry -o yaml
oc describe clusteroperator image-registry
oc get clusteroperator authentication -o yaml
oc describe clusteroperator authentication
oc describe machineconfigpool worker
oc get machineconfigpool
oc describe node worker-1
oc adm node-logs worker-1 -u kubelet
```
