#!/usr/bin/env bash
# Say WHY a pod did not become ready, not just that it did not.
#
# The e2e jobs' install handler printed `kubectl get events` and nothing else. When an init container crash-loops,
# the events say "Back-off restarting failed container" and never say what the container printed, so the failure
# cannot be diagnosed from CI output at all -- the e2e-kind (OpenShift 4.22) leg failed this way on several
# branches and on main, and the logs that would have explained it were never captured.
#
# Events describe the kubelet's view. Logs describe the program's. A failure that cannot name its own cause costs
# more than the failure.
#
# Usage: scripts/ci_pod_failure.sh <namespace> [title]
set -uo pipefail

ns="${1:?usage: ci_pod_failure.sh <namespace> [title]}"
title="${2:-pod failure}"

emit() { sed "s|^|::error title=${title}::|"; }

echo "--- events (most recent last)" | emit
kubectl -n "$ns" get events --sort-by=.lastTimestamp 2>&1 | tail -40 | emit

echo "--- pods" | emit
kubectl -n "$ns" get pods -o wide 2>&1 | emit

for pod in $(kubectl -n "$ns" get pods -o name 2>/dev/null); do
  # Every container of every pod, init containers first: the one that failed is usually an init container, and
  # `kubectl logs` without -c picks a container that may never have run.
  names=$(kubectl -n "$ns" get "$pod" \
    -o jsonpath='{range .spec.initContainers[*]}{.name}{"\n"}{end}{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null)
  for c in $names; do
    echo "--- $pod container $c" | emit
    # A crash-looping container's CURRENT attempt is often empty or still starting; --previous holds the attempt
    # that actually failed. Both are printed, because either may be the empty one.
    kubectl -n "$ns" logs "$pod" -c "$c" --tail=60 2>&1 | emit
    kubectl -n "$ns" logs "$pod" -c "$c" --tail=60 --previous 2>/dev/null | emit
  done
  echo "--- $pod state" | emit
  kubectl -n "$ns" get "$pod" \
    -o jsonpath='{range .status.initContainerStatuses[*]}{.name}{": "}{.state}{"\n"}{end}{range .status.containerStatuses[*]}{.name}{": "}{.state}{"\n"}{end}' 2>&1 | emit
done
