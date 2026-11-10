# kube-noob skills

The kube-noob rulebook as knowledge, for Claude.

```
/plugin install kube-noob-skills --marketplace kube-noob/kube-noob
```

Seven skills covering Kubernetes, Red Hat OpenShift, ROSA (Classic and with Hosted Control Planes), Helm and Red Hat
Advanced Cluster Security. They carry the facts a general model most often gets wrong about these platforms: the OCP to
Kubernetes version map, what `restricted-v2` actually rejects, why a Route answers 503, the order EgressFirewall rules
match in, which storage classes can be ReadWriteMany, what a Pod Security or SCC denial means and how to read it, and
the seven-step review a manifest should pass before anyone applies it.

## What this plugin is not

It is knowledge only. **There is no MCP server here, no tools and no code.** Nothing in this plugin reads a file, runs a
command, reaches a cluster or makes a network call, because there is nothing in it to run: it is Markdown.

So Claude can tell you that `gp3-csi` is ReadWriteOnce and why your Route returns 503. It cannot audit your manifests,
validate them against bundled schemas, diagnose pasted events, check whether one pod can reach another, or grade an
exercise. Those are kube-noob's tools, and they are a separate install.

## Getting the tools

The tools run on your machine and make no network calls of their own:

```
pip install kube-noob
```

Homebrew and the other routes are in [the install guide](https://github.com/kube-noob/kube-noob/blob/main/docs/install.md).

Then, for example:

```
kube-noob audit -f manifests.yaml --platform openshift --version 4.20
kube-noob diagnose -f error.txt
kube-noob insight -f whatever-you-pasted.txt
```

To give Claude those tools rather than only this knowledge, install the full `kube-noob` plugin from the project's own
marketplace, which ships the MCP server alongside these skills:

```
/plugin marketplace add kube-noob/kube-noob
/plugin install kube-noob@kube-noob
```

## Licence and privacy

Apache-2.0. This plugin collects nothing and sends nothing, because it contains no executable code. The project's
privacy policy covers the tools: https://github.com/kube-noob/kube-noob/blob/main/PRIVACY.md
