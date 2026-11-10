---
name: kube-debugging
description: >
  Systematic Kubernetes and OpenShift debugging - CrashLoopBackOff, ImagePullBackOff, OOMKilled, Pending pods, PVC
  pending, Multi-Attach, SCC and Pod Security rejections, Route 503, RBAC forbidden, webhook denials, Helm failures,
  evictions, DNS and NetworkPolicy problems. Explains policy denials (Kyverno, Gatekeeper, ValidatingAdmissionPolicy,
  Pod Security, SCC, RHACS, quota, RBAC) and reasons about whether a NetworkPolicy lets one pod reach another. Use when
  the user pastes errors, events, describe output or logs, says something is broken, or asks "why was this denied?"
---

# Debugging

**Diagnose before change.** Never lead with a command that executes inside a container or changes the cluster.
Commands are for the user to run: give them as copy-paste lines with no shell comments, and do not run them yourself.

This skill is knowledge, not tools. It reasons over what the user pastes. It cannot reach their cluster, and it has no
bundled corpus of reported issues, so **never claim a bug is reported**: say that it resembles a known class of
failure and point at where to check.

## 1. Ask for evidence before theorising

```
oc describe pod <name> -n <ns>
oc get events -n <ns> --sort-by=.lastTimestamp
oc logs <pod> -n <ns> --previous
oc get pod <name> -n <ns> -o yaml
```

Read the `Events` block from the bottom up and the last container `State`/`lastState` before anything else. Most pod
failures name their own cause there, and a theory formed before reading it is usually wrong.

## 2. What each symptom actually means

| Symptom | What it means | Read-only check |
| - | - | - |
| `CrashLoopBackOff` | the container started and exited; this is the restart backoff, not the fault | `oc logs <pod> --previous`, then `lastState.terminated.exitCode` |
| exit code 137 with `OOMKilled` | the kernel killed it at the memory limit | compare `limits.memory` to actual use; raise the limit or fix the leak |
| exit code 1 immediately | the process failed on its own; it is an application problem | the previous container's logs |
| `ImagePullBackOff` | registry, tag, or credentials | `describe` names which; check the pull secret is in the same namespace |
| `Pending`, no node | nothing can schedule it | `describe` lists each node's rejection: taint, insufficient CPU/memory, affinity, volume zone |
| PVC `Pending` | no class, no capacity, or an access mode the class cannot serve | `oc describe pvc`, then `oc get storageclass` |
| `Multi-Attach error` | a ReadWriteOnce volume is still attached to another node | wait for the old pod to terminate; this is usually a rolling update on RWO |
| `Route` returns 503 | endpoints, port, termination, or a NetworkPolicy | `oc get endpoints <svc>` first |
| `forbidden: User ... cannot ...` | RBAC | `oc auth can-i <verb> <resource> --as=<user> -n <ns>` |
| `admission webhook ... denied the request` | a policy engine | read which webhook; see below |
| evicted pods | node pressure | `oc describe node` conditions: disk, memory, PID |
| DNS resolution failing | CoreDNS, the search path, or a NetworkPolicy blocking 53 | resolve from a pod that already works before blaming DNS |

## 3. Reading a denial

The webhook name in the message tells you which system denied it, and that decides where the exception lives:

- `policyeval.stackrox.io` — RHACS. Only enforced policies block.
- `validate.kyverno.svc` — Kyverno. The message names the policy and the rule.
- `validation.gatekeeper.sh` — Gatekeeper. The message names the constraint.
- no webhook, `violates PodSecurity "restricted:latest"` — built-in Pod Security admission, enforced by namespace label.
- `unable to validate against any security context constraint` — OpenShift SCC. Usually a fixed `runAsUser`.
- `exceeded quota` — a ResourceQuota, not a policy.

Name the policy, the rule and the failing field, then the fix. **Exceptions, quota increases and new permissions are
the policy owner's decision**: say so rather than telling the user to grant themselves more.

## 4. Can pod A reach pod B?

NetworkPolicy is allow-list and additive, evaluated separately for ingress and egress. Reason about it in that order:

1. Does any policy select the **source** pod for egress? If yes, egress to B must be allowed by one of them.
2. Does any policy select the **destination** pod for ingress? If yes, ingress from A must be allowed by one of them.
3. A pod no policy selects is unrestricted in that direction.
4. A `namespaceSelector` matches namespace **labels**, not names, unless the cluster labels namespaces with their name.
5. Allowing traffic to a Service port means allowing the **pod's** `containerPort`, not the Service's port.

Give the verdict per direction and name the policy and rule that decide it. Propose an allow policy only if the user
wants the traffic.

## 5. Then, and only then

Offer the diagnostic commands that execute (`oc rsh`, `oc exec`, `oc debug`, a `curl` from inside a pod) and the
proposed change, each with its impact stated, and ask for approval. Never apply anything.

## What this skill cannot do

It cannot diagnose pasted text against bundled playbooks, check a NetworkPolicy mechanically, explain a denial from the
policy objects, match an error against reported OpenShift issues and Red Hat Jira tickets, or collect read-only
evidence from a live cluster. Those are kube-noob's tools:

```
pip install kube-noob
kube-noob insight -f pasted.txt
kube-noob diagnose -f error.txt --platform openshift --version 4.20.8
kube-noob policy explain -f denial.txt
kube-noob known-issues "unable to validate against any security context constraint"
kube-noob bundle deployment/<name> -n <ns> --cluster-enabled
```
