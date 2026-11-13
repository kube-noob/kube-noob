# Must-gather report: OpenShift 4.20.3 on AWS

Written offline by kube-noob TEST from `must-gather.tar.gz`. Known issues from the OpenShift 4.20 release notes, as of 2026-10-27.

## Summary

- OpenShift Container Platform 4.20.3 (channel stable-4.20); update to 4.20.4 (Partial)
- Platform: AWS, control plane topology HighlyAvailable
- Nodes: 2 (1 control plane), 1 Ready
- Cluster operators: 3, 2 Available, 1 Degraded
- Operators installed with OLM: rhacs-operator.v4.6.0 (Failed)
- Must-gather `must-gather.tar.gz`, collected 2026-10-28 10:00:05.1 +0000 UTC
- Gather images: openshift/must-gather 4.20.3
- Findings: 2 critical, 8 high, 10 medium, 2 low, 2 info

Most severe:

1. CRITICAL: the cluster version operator reports Failing
2. CRITICAL: cluster operator image-registry is not Available
3. HIGH: cluster operator authentication is Degraded
4. HIGH: machine config pool worker reports Degraded
5. HIGH: machine config pool worker reports NodeDegraded

## Findings

| # | Severity | Area | Finding | Known issues |
|---|---|---|---|---|
| 1 | critical | clusterversion | the cluster version operator reports Failing |  |
| 2 | critical | clusteroperators | cluster operator image-registry is not Available |  |
| 3 | high | clusteroperators | cluster operator authentication is Degraded |  |
| 4 | high | machineconfigpools | machine config pool worker reports Degraded |  |
| 5 | high | machineconfigpools | machine config pool worker reports NodeDegraded |  |
| 6 | high | nodes | worker node worker-1 is NotReady |  |
| 7 | high | nodes | worker node worker-1 reports MemoryPressure |  |
| 8 | high | olm | operator rhacs-operator.v4.6.0 is Failed |  |
| 9 | high | pods | shop/pod api-5c6d: container api: ImagePullBackOff |  |
| 10 | high | pods | shop/ReplicaSet/web-6b8f9: container web: CrashLoopBackOff (2 pods), 14 restarts |  |
| 11 | medium | clusterversion | minor version updates are blocked (Upgradeable=False) |  |
| 12 | medium | pods | openshift-monitoring/pod prometheus-k8s-0: container prometheus was OOMKilled before its last restart, 3 restarts |  |
| 13 | medium | events | Unhealthy: 1 warning event(s) on 1 object(s) in 1 namespace(s) |  |
| 14 | medium | etcd | etcd leader changed: 2 election term(s) seen, terms 5 to 6, 1 'lost leader' line(s) | OCPBUGS-1 |
| 15 | medium | etcd | etcd logged "apply request took too long" 1 time(s) on 1 member(s) |  |
| 16 | medium | etcd | etcd logged "leader failed to send out heartbeat on time" 1 time(s) on 1 member(s) | OCPBUGS-1 |
| 17 | medium | etcd | etcd logged "slow fdatasync" 1 time(s) on 1 member(s) |  |
| 18 | medium | pods | shop/pod cart-0: cannot be scheduled (PodScheduled=False, Unschedulable) |  |
| 19 | medium | events | BackOff: 37 warning event(s) on 1 object(s) in 1 namespace(s) |  |
| 20 | medium | events | FailedScheduling: 12 warning event(s) on 1 object(s) in 1 namespace(s) |  |
| 21 | low | nodes | worker node worker-1 is cordoned (spec.unschedulable) |  |
| 22 | low | events | QuotaNearlyExhausted: 1 warning event(s) on 1 object(s) in 1 namespace(s) |  |
| 23 | info | clusterversion | an update is in progress |  |
| 24 | info | machineconfigpools | machine config pool worker is updating: 2 of 3 machines updated |  |

### 1. the cluster version operator reports Failing

- Severity: critical (clusterversion, platform)
- Reason: ClusterOperatorDegraded
- Message: Cluster operator authentication is degraded
- Signals: component:cluster-version
- Evidence: `cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml`

```bash
oc adm upgrade
oc get clusterversion version -o yaml
```

### 2. cluster operator image-registry is not Available

- Severity: critical (clusteroperators, platform)
- Reason: NoReplicasAvailable
- Message: The deployment does not have available replicas
- Signals: alert:ClusterOperatorDown, co_condition:image-registry/Available=False:NoReplicasAvailable, component:image-registry
- Evidence: `cluster-scoped-resources/config.openshift.io/clusteroperators/image-registry.yaml`

```bash
oc get clusteroperator image-registry -o yaml
oc describe clusteroperator image-registry
```

### 3. cluster operator authentication is Degraded

- Severity: high (clusteroperators, platform)
- Reason: OAuthServerRouteEndpointAccessibleController_SyncError
- Signals: alert:ClusterOperatorDegraded, co_condition:authentication/Degraded=True:OAuthServerRouteEndpointAccessibleController_SyncError, component:authentication
- Evidence: `cluster-scoped-resources/config.openshift.io/clusteroperators/authentication.yaml`

```bash
oc get clusteroperator authentication -o yaml
oc describe clusteroperator authentication
```

### 4. machine config pool worker reports Degraded

- Severity: high (machineconfigpools, platform)
- Message: Node worker-1 is reporting: "unexpected on-disk state"
- Signals: component:machine-config
- Evidence: `cluster-scoped-resources/machineconfiguration.openshift.io/machineconfigpools/worker.yaml`

```bash
oc describe machineconfigpool worker
oc get machineconfigpool
```

### 5. machine config pool worker reports NodeDegraded

- Severity: high (machineconfigpools, platform)
- Message: 1 nodes are reporting degraded status on sync
- Signals: component:machine-config
- Evidence: `cluster-scoped-resources/machineconfiguration.openshift.io/machineconfigpools/worker.yaml`

```bash
oc describe machineconfigpool worker
oc get machineconfigpool
```

### 6. worker node worker-1 is NotReady

- Severity: high (nodes)
- Reason: KubeletNotReady
- Message: container runtime network not ready
- Signals: alert:KubeNodeNotReady, component:kubelet
- Evidence: `cluster-scoped-resources/core/nodes/worker-1.yaml`

```bash
oc describe node worker-1
oc adm node-logs worker-1 -u kubelet
```

### 7. worker node worker-1 reports MemoryPressure

- Severity: high (nodes)
- Reason: KubeletHasInsufficientMemory
- Signals: alert:KubeNodePressure, component:kubelet
- Evidence: `cluster-scoped-resources/core/nodes/worker-1.yaml`

```bash
oc describe node worker-1
oc adm node-logs worker-1 -u kubelet
```

### 8. operator rhacs-operator.v4.6.0 is Failed

- Severity: high (olm)
- Reason: InstallCheckFailed
- Message: install timeout
- Signals: component:olm
- Evidence: `namespaces/openshift-operator-lifecycle-manager/operators.coreos.com/clusterserviceversions.yaml`

```bash
oc describe csv -n rhacs-operator rhacs-operator.v4.6.0
oc get subscription,installplan -n rhacs-operator
```

### 9. shop/pod api-5c6d: container api: ImagePullBackOff

- Severity: high (pods)
- Reason: ImagePullBackOff
- Message: Back-off pulling image quay.io/shop/api:v9
- Signals: pod_reason:ImagePullBackOff
- Evidence: `namespaces/shop/pods/api-5c6d/api-5c6d.yaml`

```bash
oc describe pod -n shop api-5c6d
oc get events -n shop --field-selector involvedObject.name=api-5c6d
```

### 10. shop/ReplicaSet/web-6b8f9: container web: CrashLoopBackOff (2 pods), 14 restarts

- Severity: high (pods)
- Reason: CrashLoopBackOff
- Message: back-off 5m0s restarting failed container
- Last error in the log: Error: connect ECONNREFUSED 10.0.0.5:5432
- Signals: alert:KubePodCrashLooping, pod_reason:CrashLoopBackOff, error_template:87c80d40e40d
- Team memory: [mem:MEM-7]
- Evidence: `namespaces/shop/pods/web-7d9f/web-7d9f.yaml`, `namespaces/shop/pods/web-7d9f/web/web/logs/previous.log`

```bash
oc describe pod -n shop web-7d9f
oc logs -n shop web-7d9f -c web --previous
```

### 11. minor version updates are blocked (Upgradeable=False)

- Severity: medium (clusterversion, platform)
- Reason: AdminAckRequired
- Message: Kubernetes 1.34 removes several APIs that require an administrator acknowledgment
- Signals: alert:ClusterNotUpgradeable, component:cluster-version
- Evidence: `cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml`

```bash
oc adm upgrade
oc get clusterversion version -o yaml
```

### 12. openshift-monitoring/pod prometheus-k8s-0: container prometheus was OOMKilled before its last restart, 3 restarts

- Severity: medium (pods, platform)
- Reason: OOMKilled
- Signals: pod_reason:OOMKilled, component:monitoring
- Evidence: `namespaces/openshift-monitoring/pods/prometheus-k8s-0/prometheus-k8s-0.yaml`

```bash
oc describe pod -n openshift-monitoring prometheus-k8s-0
oc logs -n openshift-monitoring prometheus-k8s-0 -c prometheus --previous
```

### 13. Unhealthy: 1 warning event(s) on 1 object(s) in 1 namespace(s)

- Severity: medium (events, platform)
- Reason: Unhealthy
- Message: Readiness probe failed
- Signals: event_reason:Unhealthy, error_template:c166d9c33e4c
- Evidence: `namespaces/openshift-etcd/core/events.yaml`

```bash
oc get events -A --field-selector reason=Unhealthy
```

### 14. etcd leader changed: 2 election term(s) seen, terms 5 to 6, 1 'lost leader' line(s)

- Severity: medium (etcd, platform)
- Message: 2026-10-28T09:58:20.0Z {"level":"info","msg":"raft.node: 8e9e05c52164694d lost leader 91bc3c398fb3c146 at term 5"}
- Signals: alert:etcdHighNumberOfLeaderChanges, component:etcd
- Evidence: `namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs/current.log`

```bash
oc get pods -n openshift-etcd -o wide
oc get clusteroperator etcd -o yaml
```

### 15. etcd logged "apply request took too long" 1 time(s) on 1 member(s)

- Severity: medium (etcd, platform)
- Message: 2026-10-28T09:58:01.1Z {"level":"warn","msg":"apply request took too long","took":"312ms"}
- Signals: alert:etcdGRPCRequestsSlow, component:etcd
- Evidence: `namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs/current.log`

```bash
oc get pods -n openshift-etcd -o wide
oc logs -n openshift-etcd etcd-master-0 -c etcd
oc get clusteroperator etcd -o yaml
```

### 16. etcd logged "leader failed to send out heartbeat on time" 1 time(s) on 1 member(s)

- Severity: medium (etcd, platform)
- Message: 2026-10-28T09:58:22.0Z {"level":"warn","msg":"leader failed to send out heartbeat on time; took too long, leader is overloaded likely from slow disk"}
- Signals: component:etcd
- Evidence: `namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs/current.log`

```bash
oc get pods -n openshift-etcd -o wide
oc logs -n openshift-etcd etcd-master-0 -c etcd
oc get clusteroperator etcd -o yaml
```

### 17. etcd logged "slow fdatasync" 1 time(s) on 1 member(s)

- Severity: medium (etcd, platform)
- Message: 2026-10-28T09:58:09.4Z {"level":"warn","msg":"slow fdatasync","took":"1.2s"}
- Signals: alert:etcdHighFsyncDurations, component:etcd
- Evidence: `namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs/current.log`

```bash
oc get pods -n openshift-etcd -o wide
oc logs -n openshift-etcd etcd-master-0 -c etcd
oc get clusteroperator etcd -o yaml
```

### 18. shop/pod cart-0: cannot be scheduled (PodScheduled=False, Unschedulable)

- Severity: medium (pods)
- Reason: Unschedulable
- Message: 0/3 nodes are available: 3 Insufficient memory.
- Evidence: `namespaces/shop/pods/cart-0/cart-0.yaml`

```bash
oc describe pod -n shop cart-0
oc get events -n shop --field-selector involvedObject.name=cart-0
```

### 19. BackOff: 37 warning event(s) on 1 object(s) in 1 namespace(s)

- Severity: medium (events)
- Reason: BackOff
- Message: Back-off restarting failed container web in pod web-7d9f_shop
- Signals: event_reason:BackOff, error_template:9defdc747fae
- Evidence: `namespaces/shop/core/events.yaml`

```bash
oc get events -A --field-selector reason=BackOff
```

### 20. FailedScheduling: 12 warning event(s) on 1 object(s) in 1 namespace(s)

- Severity: medium (events)
- Reason: FailedScheduling
- Message: 0/3 nodes are available: 3 Insufficient memory.
- Signals: event_reason:FailedScheduling
- Evidence: `namespaces/shop/core/events.yaml`

```bash
oc get events -A --field-selector reason=FailedScheduling
```

### 21. worker node worker-1 is cordoned (spec.unschedulable)

- Severity: low (nodes)
- Evidence: `cluster-scoped-resources/core/nodes/worker-1.yaml`

```bash
oc describe node worker-1
oc adm node-logs worker-1 -u kubelet
```

### 22. QuotaNearlyExhausted: 1 warning event(s) on 1 object(s) in 1 namespace(s)

- Severity: low (events)
- Reason: QuotaNearlyExhausted
- Message: quota nearly used
- Signals: event_reason:QuotaNearlyExhausted
- Evidence: `namespaces/shop/core/events.yaml`

```bash
oc get events -A --field-selector reason=QuotaNearlyExhausted
```

### 23. an update is in progress

- Severity: info (clusterversion, platform)
- Message: Working towards 4.20.4: 690 of 873 done (79% complete)
- Signals: component:cluster-version
- Evidence: `cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml`

```bash
oc adm upgrade
oc get clusterversion version -o yaml
```

### 24. machine config pool worker is updating: 2 of 3 machines updated

- Severity: info (machineconfigpools, platform)
- Signals: component:machine-config
- Evidence: `cluster-scoped-resources/machineconfiguration.openshift.io/machineconfigpools/worker.yaml`

```bash
oc describe machineconfigpool worker
oc get machineconfigpool
```

## Known issues that match

| Issue | Status for 4.20.3 | Fixed in | Findings | Summary |
|---|---|---|---|---|
| [OCPBUGS-1](https://example.invalid/OCPBUGS-1) | Fixed in 4.20.13; you run 4.20.3 | 4.20.13 | 14, 16 | etcd leader elections under catalog sync I/O |

## From your team's memory

- [mem:MEM-7] web crashes when the database is not up yet (findings 10)

## Read-only next steps

Run these on the live cluster to confirm, most severe first:

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
oc describe csv -n rhacs-operator rhacs-operator.v4.6.0
oc get subscription,installplan -n rhacs-operator
oc describe pod -n shop api-5c6d
oc get events -n shop --field-selector involvedObject.name=api-5c6d
oc describe pod -n shop web-7d9f
```

## What was read

| Area | Files | Objects | Findings | Note |
|---|---|---|---|---|
| clusterversion | 1 | 1 | 3 |  |
| clusteroperators | 3 | 3 | 2 |  |
| nodes | 2 | 2 | 3 |  |
| machineconfigpools | 1 | 1 | 3 |  |
| olm | 2 | 2 | 1 |  |
| pods | 6 | 6 | 4 |  |
| events | 2 | 5 | 4 |  |
| etcd | 1 | 1 | 4 |  |

- Skipped 2: Secret data (never read)
- Skipped 1: nested archive (not opened)
- Evidence is partial: operator inventory: 1 operator from OLM data; Subscriptions were not read, so catalog, channel and approval are not determined for every operator; 1 operator state(s) not determined; operator known issues: the inventory is partial; the cluster is updating to 4.20.4; release notes: the running release 4.20.3 was searched and the update target 4.20.4 was not

## Signals

alert:ClusterNotUpgradeable, alert:ClusterOperatorDegraded, alert:ClusterOperatorDown, alert:KubeNodeNotReady, alert:KubeNodePressure, alert:KubePodCrashLooping, alert:etcdGRPCRequestsSlow, alert:etcdHighFsyncDurations, alert:etcdHighNumberOfLeaderChanges, co_condition:authentication/Degraded=True:OAuthServerRouteEndpointAccessibleController_SyncError, co_condition:image-registry/Available=False:NoReplicasAvailable, event_reason:BackOff, event_reason:FailedScheduling, event_reason:QuotaNearlyExhausted, event_reason:Unhealthy, pod_reason:CrashLoopBackOff, pod_reason:ImagePullBackOff, pod_reason:OOMKilled, component:authentication, component:cluster-version, component:etcd, component:image-registry, component:kubelet, component:machine-config, component:monitoring, component:olm, error_template:87c80d40e40d, error_template:9defdc747fae, error_template:c166d9c33e4c
