"""Exec-only backend — run samples without any detection backend.

Self-registers as kind="exec". Operators deploy one or more Whiskers
instances running under various user contexts (standard user, admin,
network service, domain-joined low-priv, etc.) and point an exec profile
at each one. The runner executes the sample and reports execution results
only — no alert correlation, no detection scoring.

Results carry ``coverage: "not_configured"`` so the UI clearly shows that
detection was not checked, rather than reporting "no alerts" as if an EDR
had evaluated the run.
"""

from ..backend import EdrBackend, register_backend
from ..profile import EdrProfile


class ExecOnlyBackend(EdrBackend):
    kind = "exec"
    label = "Execution Only"
    required_profile_fields = ()
    optional_profile_fields = ()
    has_correlation = False

    @classmethod
    def health_probe(cls, profile: EdrProfile) -> dict:
        return {"reachable": None, "error": None}


register_backend("exec", ExecOnlyBackend)
