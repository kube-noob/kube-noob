"""`audit/components.py` holds `@rule` definitions, which no split out of `rules.py` had done before (G303).

`rules.py` has to stay under the 256 KiB the Claude plugin directory reads per file, and `KN-S046` pushed it
over. `argv.py`, `cpconfig.py` and `cpflags.py` were split out of it earlier, but they hold helpers: this is the
first module whose import is what puts rules in the catalogue, so the import works in a circle -- `rules.py`
imports it at the end of its own body, and it imports `rule` and `AuditContext` from `rules.py`. A circle is
fine in exactly one direction and broken in the other, so both are tested rather than assumed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENT_RULES = ("KN-S042", "KN-S043", "KN-S044", "KN-S045", "KN-S046")


def _in_a_fresh_interpreter(code: str) -> str:
    """Run ``code`` in a new interpreter: an import order can only be tested before anything is imported."""
    done = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def test_the_component_rules_register_whichever_module_is_imported_first() -> None:
    for first in ("kube_noob.audit.rules", "kube_noob.audit.components"):
        out = _in_a_fresh_interpreter(
            f"import {first}\n"
            "from kube_noob.audit.rules import RULES\n"
            "print(','.join(r for r in RULES if r in " + repr(COMPONENT_RULES) + "))"
        )
        assert sorted(out.split(",")) == sorted(COMPONENT_RULES), first


def test_every_rule_module_stays_under_the_size_the_plugin_directory_reads() -> None:
    """The cap that forced the split, asserted on the source rather than only on the generated plugin copy."""
    cap = 256 * 1024
    for name in ("rules.py", "components.py", "argv.py", "cpconfig.py", "cpflags.py", "kubelet.py", "webhookca.py"):
        path = ROOT / "src" / "kube_noob" / "audit" / name
        assert path.stat().st_size < cap, f"{name} is {path.stat().st_size} bytes, over {cap}"


def test_the_component_rules_are_defined_in_the_component_module_and_not_in_rules() -> None:
    """A rule added to `rules.py` instead would pass every other test and grow the file back over the cap."""
    rules = (ROOT / "src" / "kube_noob" / "audit" / "rules.py").read_text(encoding="utf-8")
    components = (ROOT / "src" / "kube_noob" / "audit" / "components.py").read_text(encoding="utf-8")
    for rule_id in COMPONENT_RULES:
        assert f'"{rule_id}",' in components, rule_id
        assert f'    "{rule_id}",\n    "' not in rules, rule_id


def test_the_kubelet_rules_are_skipped_at_admission_as_the_generated_policies_skip_them() -> None:
    """The webhook and the generated policies must not disagree about a rule (G307).

    Four of the five shapes a kubelet is configured in never reach the API server, so refusing the two that do
    would stop a `KubeletConfig` while leaving every kubelet already running as it is -- the same reason
    `KN-S038` and `KN-S039` are skipped, one component along. The two lists are kept in step here rather than
    by hand, because a rule in one and not the other is a rule the two surfaces answer differently (class 25).
    """
    from kube_noob.admission import CROSS_OBJECT, SKIPPED_RULES
    from kube_noob.generate.policies import NOT_GENERATED

    kubelet = {"KN-S042", "KN-S043", "KN-S044", "KN-S045"}
    assert kubelet <= SKIPPED_RULES
    assert kubelet <= set(NOT_GENERATED)
    assert not kubelet & CROSS_OBJECT
    # KN-S046 is NOT skipped: the webhook evaluates whatever object it is given, and a webhook configuration it
    # is given is one it can read in full. It has no generated policy because a ValidatingAdmissionPolicy
    # cannot validate another one, which is a different reason.
    assert "KN-S046" not in SKIPPED_RULES
    assert "KN-S046" in NOT_GENERATED
