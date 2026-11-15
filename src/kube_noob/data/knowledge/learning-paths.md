---
searchWeight: 0.5
id: learning-paths
title: Curated learning paths and practice environments (link-checked 2026-10-27)
tags: [learning, resources]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-27
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [learn, learning, course, courses, tutorial, tutorials, beginner, beginners, certification, cka, ckad, cks, practice, study, roadmap, lab, labs]
sources:
  - {title: "kube-noob link verification (2026-10-27)", url: "https://github.com/kube-noob/kube-noob", license: Apache-2.0}
---
# Learning paths

## Kubernetes fundamentals and architecture
- Kubernetes The Hard Way (Kelsey Hightower, Apache-2.0): https://github.com/kelseyhightower/kubernetes-the-hard-way
- CKAD exercises (MIT): https://github.com/dgkanatsios/CKAD-exercises
- Kubernetes training and free LFS158x course: https://kubernetes.io/training/
- KodeKloud Kubernetes challenges (formerly "Game of Pods"): https://kodekloud.com/courses/kubernetes-challenges
- Illustrated Children's Guide to Kubernetes (CNCF): https://www.cncf.io/phippy/
- Browser labs: https://killercoda.com/

## Local clusters
- kind: https://kind.sigs.k8s.io/
- k3d: https://k3d.io/stable/
- minikube: https://minikube.sigs.k8s.io/docs/
- k0s: https://k0sproject.io/
- OpenShift Local (formerly CodeReady Containers): https://developers.redhat.com/products/openshift-local/overview

## OpenShift and ROSA
- OpenShift documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/
- ROSA documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/ and
  https://docs.aws.amazon.com/rosa/
- Red Hat Cloud Experts (ROSA best practices): https://cloud.redhat.com/experts/rosa/best-practices-recommendations/
- HyperShift (hosted control planes): https://github.com/openshift/hypershift
- rosa CLI: https://github.com/openshift/rosa
- Terraform module for ROSA HCP: https://github.com/terraform-redhat/terraform-rhcs-rosa-hcp
- Developer Sandbox: https://developers.redhat.com/developer-sandbox
- Red Hat interactive labs: https://www.redhat.com/en/interactive-labs

## Helm and StackRox
- Helm docs (Helm 4 default, Helm 3 under /docs/v3/): https://helm.sh/docs/
- StackRox source and policies: https://github.com/stackrox/stackrox

## Curated lists (link only - licenses restrict reuse)
- Awesome Kubernetes (CC BY-NC 4.0, non-commercial): https://github.com/ramitsurana/awesome-kubernetes
- Awesome Kubernetes Security (no license file): https://github.com/magnologan/awesome-k8s-security

## Retired or stale links (do not use)
- kubernetesbyexample.com now redirects to a generic Red Hat developer page.
- github.com/redhat-cop/ansible-openshift-state does not exist.
- redhat-cop/casl-ansible targets OpenShift 3.x (last commit 2020) and openshift/openshift-ansible on 4.x only
  scales/upgrades RHEL compute hosts - neither installs OpenShift 4.
