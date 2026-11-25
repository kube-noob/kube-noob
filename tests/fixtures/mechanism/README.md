# Mechanism fixtures

Each bundle is a **directory**, not a loose file, and that is the point.

`cli._partial_input` takes a directory to be the whole namespace and one file to be a fragment, which is the
same decision `audit` has always made: `audit -f deployment.yaml` cannot tell "this namespace has no
NetworkPolicy" from "you did not pass it". A walk inherits that, and on a walk the difference is not a softer
count but the opposite verdict — on a fragment the hop `policy-admits-the-packet` is `cannot judge` and the
walk stops at exit 5; on a whole namespace the same hop can hold, fail, and let the walk reach its end.

So `holds` and `broken` are only reachable from a directory. A single-file version of these fixtures would
stop at the policy hop and could never demonstrate either, which is what made them wrong before (G394).

- `complete/` — every observable hop holds; the walk reaches the end. Exit 0.
- `broken/` — the same bundle with the Ingress on `nginx`, which KN-V019 retires. One hop BROKEN, the walk
  still reaches the end. Exit 1.

For exit 5 there are two different causes, and neither needs a fixture of its own: pass `complete/bundle.yaml`
as a single file (a fragment, so the policy hop cannot be judged), or drop an unreadable file into a copy of
`complete/` (a refused read, so nothing is answered about the rest).
