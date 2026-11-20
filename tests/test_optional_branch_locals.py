"""Every name a conditional branch assigns and the code after it reads must have a default before the branch.

`ksi` with no manifests raised ``UnboundLocalError: partly`` on the way to the FedRAMP crosswalk -- the one answer
the dataset exists to give without a bundle -- because nine of the ten names the ``if p.manifests is not None:``
branch assigns were defaulted above it and the tenth was added without one (G281). Nothing caught it: mypy does not
report a possibly-unbound local here, and the branch is taken by every test that passes manifests, so the gap is
invisible unless a test runs the command with nothing to audit.

This is a structural guard rather than one more case: a reason-shaped test for `partly` would have passed the day
an eleventh name arrives. It reads the function's own syntax and asserts the invariant that made the defaults block
correct in the first place, so the failure lands on whoever adds the name rather than on a user.
"""

from __future__ import annotations

import ast
import pathlib

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src" / "kube_noob" / "toolkit.py"


def _assigned_names(node: ast.AST) -> set[str]:
    """Every bare local name assigned anywhere under `node`."""
    out: set[str] = set()
    for sub in ast.walk(node):
        targets: list[ast.expr] = []
        if isinstance(sub, ast.Assign):
            targets = list(sub.targets)
        elif isinstance(sub, (ast.AugAssign, ast.AnnAssign)):
            targets = [sub.target]
        for t in targets:
            for leaf in ast.walk(t):
                if isinstance(leaf, ast.Name):
                    out.add(leaf.id)
        if isinstance(sub, (ast.For, ast.AsyncFor)):
            for leaf in ast.walk(sub.target):
                if isinstance(leaf, ast.Name):
                    out.add(leaf.id)
        if isinstance(sub, ast.withitem) and sub.optional_vars is not None:
            for leaf in ast.walk(sub.optional_vars):
                if isinstance(leaf, ast.Name):
                    out.add(leaf.id)
    return out


_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _comp_targets(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for gen in getattr(node, "generators", []):
        for leaf in ast.walk(gen.target):
            if isinstance(leaf, ast.Name):
                out.add(leaf.id)
    return out


def _read_names(nodes: list[ast.AST]) -> set[str]:
    """Every local name these nodes read, excluding comprehension variables.

    A comprehension has its own scope in Python 3, so ``[r for r in rows]`` standing after a branch that assigned
    `r` reads nothing from the enclosing function. Counting it made this guard fire on two correct call sites, and
    a guard that cries wolf gets deleted rather than obeyed.

    Written as a recursive descent rather than over :func:`ast.walk`, because ``walk`` flattens the tree: skipping
    a comprehension node there does not skip its children, which arrive separately and put the comprehension's own
    variable back into the set. That was this guard's first draft, and it reported the false positives it was
    written to exclude."""
    out: set[str] = set()
    for node in nodes:
        if isinstance(node, _COMPREHENSIONS):
            shadowed = _comp_targets(node)
            # The first generator's iterable is evaluated in the enclosing scope, so it is read from here; the
            # element, the conditions and any later generator see the comprehension's own names.
            first = node.generators[0].iter if node.generators else None
            rest = [n for n in ast.iter_child_nodes(node) if n is not first]
            if first is not None:
                out |= _read_names([first])
            out |= _read_names(rest) - shadowed
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            out.add(node.id)
        out |= _read_names(list(ast.iter_child_nodes(node)))
    return out


def _functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def test_a_name_an_if_branch_assigns_and_later_code_reads_is_defaulted_before_the_branch() -> None:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for fn in _functions(tree):
        # Only the function's own top-level statements: a name bound by an enclosing branch is that branch's
        # problem, and walking into nested functions would report their parameters as unbound.
        body = fn.body
        bound: set[str] = {a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs}
        if fn.args.vararg is not None:
            bound.add(fn.args.vararg.arg)
        if fn.args.kwarg is not None:
            bound.add(fn.args.kwarg.arg)
        for i, stmt in enumerate(body):
            if isinstance(stmt, ast.If) and not stmt.orelse:
                # A bare `if` with no `else`: anything it assigns may never be bound, so every such name that the
                # statements after it read must already have a value.
                conditional = _assigned_names(stmt) - bound
                later = _read_names(list(body[i + 1 :]))
                for name in sorted(conditional & later):
                    offenders.append(f"{SOURCE.name}:{stmt.lineno} {fn.name}(): `{name}`")
            bound |= _assigned_names(stmt)
    assert not offenders, (
        "a name is assigned only inside an `if` with no `else` and read after it, so the path that skips the "
        "branch raises UnboundLocalError; give it a default beside its siblings before the branch:\n  "
        + "\n  ".join(offenders)
    )
