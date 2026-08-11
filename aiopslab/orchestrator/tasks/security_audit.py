# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Security-audit task variants for the security-drift detection benchmark.

These carry the fixed *audit framing* (§6.1 of ``reports/DETECTION_BENCHMARK_PLAN.md``) and a
*constructive* ground-truth eval. Two properties matter for the science:

1. **Identical cueing across tool arms.** The task description is the only place the agent is
   told what to look for, and it is byte-identical for react / +OPA / +Falco / +both — the tool
   set is the only manipulated variable. It deliberately does NOT reuse the stock
   ``DetectionTask`` prompt ("detect anomalies in a deployed service"), which is telemetry-shaped
   and would leak a different framing on a fault that breaks nothing.
2. **Constructive ground truth.** Because *we* stage the fault, the answer key is exact: the
   problem passes a ``ground_truth`` manifest and eval scores against it — no ambiguous
   effect-based labels (the flaw that sank AIOpsLab's analysis task).

``ground_truth`` schema (a subset is fine for the slice)::

    {
      "detected":        bool,            # was a fault injected? (False for no-ops)
      "target_services": [str, ...],      # affected workloads (for localization)
      "opa_control":     str | None,      # violated policy id
      "mitre_technique": str | None,
      "severity":        "LOW|MEDIUM|HIGH|CRITICAL",
      "detection_surface": [str, ...],    # channels that CAN see it: opa | falco | telemetry
    }
"""

import textwrap
from typing import Any

from aiopslab.orchestrator.tasks.detection import DetectionTask
from aiopslab.orchestrator.tasks.localization import LocalizationTask
from aiopslab.orchestrator.evaluators.quantitative import is_exact_match, is_subset
from aiopslab.session import SessionItem


_AUDIT_FRAMING = """\
    You are a security engineer performing a drift audit of a live Kubernetes cluster.
    A security-relevant configuration or runtime change may or may not have occurred in this
    cluster since it was deployed — and nothing is necessarily broken, degraded, or visible in
    the telemetry. Do NOT assume a fault exists. Investigate the cluster's security posture
    (workload specs, permissions, runtime behavior) and decide.

    Service Details:
    {app_summary}
"""

_DETECTION_ANSWER = """

    Submit exactly one of:
    1. "Yes" — a security fault / misconfiguration is present
    2. "No"  — the cluster is clean
"""

_LOCALIZATION_ANSWER = """

    Submit exactly one of:
    1. list[str]: the workload(s) / service(s) affected by the security fault
    2. list[]:   an empty list if no security fault is present
"""


# --- "intrusion" mode: for RUNTIME faults (active attacks), NOT static misconfiguration. ---
# Scopes the question to active behavioral compromise so the ever-present baseline posture debt
# (unhardened workloads, missing policies) is explicitly out of scope. Used ONLY by runtime
# problems (e.g. security_rogue_shell); config problems keep the "misconfig" framing above.
_INTRUSION_FRAMING = """\
    You are a SOC analyst monitoring a live Kubernetes cluster for an ACTIVE INTRUSION.
    This cluster is known to have pre-existing configuration weaknesses (unhardened workloads,
    missing policies, plaintext secrets, and the like) — those are NOT your concern here and do
    not count. Your task is to determine whether an attack is CURRENTLY IN PROGRESS: active
    malicious runtime behavior, such as a rogue process, a shell spawned inside a container,
    theft of credentials or secrets, or an unexpected outbound connection. Judge only active,
    behavioral evidence of compromise — never static misconfiguration.

    Service Details:
    {app_summary}
"""

_INTRUSION_DETECTION_ANSWER = """

    Submit exactly one of:
    1. "Yes" — an active intrusion / attack is currently in progress
    2. "No"  — no active intrusion (pre-existing misconfigurations do NOT count as an intrusion)
"""

_INTRUSION_LOCALIZATION_ANSWER = """

    Submit exactly one of:
    1. list[str]: the workload(s) / service(s) that are actively compromised
    2. list[]:   an empty list if no active intrusion is in progress
"""

_MODE_FRAMING = {"misconfig": _AUDIT_FRAMING, "intrusion": _INTRUSION_FRAMING}
_MODE_DETECTION = {"misconfig": _DETECTION_ANSWER, "intrusion": _INTRUSION_DETECTION_ANSWER}
_MODE_LOCALIZATION = {"misconfig": _LOCALIZATION_ANSWER, "intrusion": _INTRUSION_LOCALIZATION_ANSWER}


class SecurityAuditDetectionTask(DetectionTask):
    """Detection with the audit framing and constructive-GT scoring.

    `mode` selects the framing: "misconfig" (default — static config faults) or "intrusion"
    (runtime active-attack faults). The mode is the ONLY thing it changes; scoring is identical.
    """

    def __init__(self, app, ground_truth: dict, mode: str = "misconfig"):
        super().__init__(app)
        self.ground_truth = ground_truth
        self.mode = mode

    def get_task_description(self):
        return (
            textwrap.dedent(_MODE_FRAMING[self.mode]).format(app_summary=self.app_summary)
            + textwrap.dedent(_MODE_DETECTION[self.mode])
        )

    def eval(self, soln: Any, trace: list[SessionItem], duration: float):
        print("== Evaluation (security-audit detection) ==")
        self.add_result("TTD", duration)
        self.common_eval(trace)

        expected = "Yes" if self.ground_truth["detected"] else "No"
        correct = isinstance(soln, str) and soln.strip().lower() == expected.lower()
        print(f"Expected: {expected} | Got: {soln!r} | {'Correct' if correct else 'Incorrect'}")

        self.add_result("Detection Accuracy", "Correct" if correct else "Incorrect")
        self.results["success"] = bool(correct)
        self.results["ground_truth"] = self.ground_truth
        return self.results


class SecurityAuditLocalizationTask(LocalizationTask):
    """Localization with the fixed audit framing and constructive-GT scoring.

    On a clean cluster (``detected == False``) the only correct answer is an empty list, so
    this doubles as the localization side of the no-op / false-alarm measurement.
    """

    def __init__(self, app, ground_truth: dict, mode: str = "misconfig"):
        super().__init__(app)
        self.ground_truth = ground_truth
        self.mode = mode

    def get_task_description(self):
        return (
            textwrap.dedent(_MODE_FRAMING[self.mode]).format(app_summary=self.app_summary)
            + textwrap.dedent(_MODE_LOCALIZATION[self.mode])
        )

    def eval(self, soln: Any, trace: list[SessionItem], duration: float):
        print("== Evaluation (security-audit localization) ==")
        self.add_result("TTL", duration)
        self.common_eval(trace)

        if soln is None or not isinstance(soln, list):
            soln = [] if soln is None else soln

        targets = self.ground_truth.get("target_services", [])

        if not self.ground_truth["detected"]:
            correct = isinstance(soln, list) and len(soln) == 0
            accuracy = 100.0 if correct else 0.0
            self.results["success"] = bool(correct)
            self.results["is_subset"] = bool(correct)
        else:
            is_exact = is_exact_match(soln, targets)
            is_sub = is_subset(targets, soln)
            if is_exact:
                accuracy = 100.0
            elif is_sub and soln:
                accuracy = (len(targets) / len(soln)) * 100.0
            else:
                accuracy = 0.0
            self.results["success"] = is_exact or (is_sub and len(soln) == len(targets))
            self.results["is_subset"] = is_sub

        print(f"Targets: {targets} | Got: {soln} | Accuracy: {accuracy:.1f}%")
        self.add_result("Localization Accuracy", accuracy)
        self.results["ground_truth"] = self.ground_truth
        return self.results
