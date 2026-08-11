# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""No-op controls — the security-drift benchmark's negative case (RQ1: calibration / false alarms).

Deploy the app, inject NOTHING (`detected=False`). The correct answer is "No" / empty list. These
measure the false-alarm rate: does an agent invent a fault when none was injected, and does adding
a tool make it cry wolf more? Two framings, because the answer means different things:

- **intrusion** (the real RQ1 signal): "is there an ACTIVE INTRUSION?" on a clean cluster → correct
  answer "No". base should say No (no attack); +Falco should say No if calibrated, or "Yes" if it
  over-reacts to benign Falco noise (a genuine false positive). This is the deployability metric.
- **misconfig** (demonstrates the confound): "is a misconfiguration present?" → the app has heavy
  baseline posture debt, so agents will likely say "Yes" here even with no injected fault. That is
  NOT a bug to hide — it is the finding that binary posture-detection saturates on a realistic app.

n=1 distinct no-op per framing is enough: the cluster is identical every time, so 5 runs sample the
agent's false-alarm tendency directly (unlike faults, more no-op *instances* add no diversity).
"""

from aiopslab.orchestrator.tasks.security_audit import (
    SecurityAuditDetectionTask,
    SecurityAuditLocalizationTask,
)
from aiopslab.service.apps.socialnet import SocialNetwork
from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.workload.wrk import Wrk
from aiopslab.paths import TARGET_MICROSERVICES

from aiopslab.orchestrator.problems.k8s_target_port_misconfig.helpers import (
    get_frontend_url,
)


class NoopBaseTask:
    def __init__(self):
        self.app = SocialNetwork()
        self.kubectl = KubeCtl()
        self.namespace = self.app.namespace
        self.faulty_service = None
        self.payload_script = (
            TARGET_MICROSERVICES
            / "socialNetwork/wrk2/scripts/social-network/compose-post.lua"
        )
        self.ground_truth = {
            "detected": False,
            "target_services": [],
            "target": None,
            "opa_control": None,
            "mitre_technique": None,
            "severity": None,
            "detection_surface": [],
            "fault_class": "no-op",
        }

    def start_workload(self):
        print("== Start Workload ==")
        frontend_url = get_frontend_url(self.app)
        wrk = Wrk(rate=10, dist="exp", connections=2, duration=10, threads=2)
        wrk.start_workload(
            payload_script=self.payload_script,
            url=f"{frontend_url}/wrk2-api/post/compose",
        )

    def inject_fault(self):
        print("== Fault Injection (NO-OP: nothing injected) ==")

    def recover_fault(self):
        print("== Fault Recovery (NO-OP: nothing to recover) ==")


# --- misconfig framing (demonstrates the posture-detection confound) ---
class NoopMisconfigDetection(NoopBaseTask, SecurityAuditDetectionTask):
    def __init__(self):
        NoopBaseTask.__init__(self)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="misconfig")


class NoopMisconfigLocalization(NoopBaseTask, SecurityAuditLocalizationTask):
    def __init__(self):
        NoopBaseTask.__init__(self)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="misconfig")


# --- intrusion framing (the real RQ1 false-alarm test) ---
class NoopIntrusionDetection(NoopBaseTask, SecurityAuditDetectionTask):
    def __init__(self):
        NoopBaseTask.__init__(self)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class NoopIntrusionLocalization(NoopBaseTask, SecurityAuditLocalizationTask):
    def __init__(self):
        NoopBaseTask.__init__(self)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
