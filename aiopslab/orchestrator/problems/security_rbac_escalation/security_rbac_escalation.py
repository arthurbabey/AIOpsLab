# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""SM.4 — RBAC privilege-escalation primitive on SocialNetwork (JUDGMENT hard-candidate).

The controlled counterpart to `security_wildcard_rbac`: identical structure (one over-permissive
Role among ~60 benign ones, bound to a workload's ServiceAccount), but the over-permission is a
*subtle* escalation primitive — `impersonate` on identities — instead of a glaring `* * *`. No
wildcard, nothing visually anomalous: it reads like a plausible auth/delegation Role. So spotting
it is not "find the weird object" but a JUDGMENT call — recognizing that `impersonate` is a
complete privilege-escalation path. Inverts `rbac-escalation-primitives.rego`.

Purpose: the decision-gate probe (RQ3). If base aces `security_wildcard_rbac` (glaring) but MISSES
this (subtle), that is a clean crossover isolating judgment from anomaly-spotting; if base aces
both, the config-drift null is robust even against semantic faults.
"""

from aiopslab.orchestrator.tasks.security_audit import (
    SecurityAuditDetectionTask,
    SecurityAuditLocalizationTask,
)
from aiopslab.service.apps.socialnet import SocialNetwork
from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.security_misconfig import SecurityMisconfigInjector
from aiopslab.generators.workload.wrk import Wrk
from aiopslab.paths import TARGET_MICROSERVICES

from aiopslab.orchestrator.problems.k8s_target_port_misconfig.helpers import (
    get_frontend_url,
)


class RbacEscalationBaseTask:
    FAULT_TYPE = "rbac_escalation"
    ESC_ROLE = "auth-delegator"

    def __init__(self, faulty_service: str = "user-service"):
        self.app = SocialNetwork()
        self.kubectl = KubeCtl()
        self.namespace = self.app.namespace
        self.faulty_service = faulty_service
        self.payload_script = (
            TARGET_MICROSERVICES
            / "socialNetwork/wrk2/scripts/social-network/compose-post.lua"
        )
        self.ground_truth = {
            "detected": True,
            "target_services": [faulty_service],
            "target": {
                "namespace": self.namespace,
                "workload": faulty_service,
                "via": f"Role '{self.ESC_ROLE}' (impersonate) bound to its ServiceAccount",
            },
            "opa_control": "rbac-escalation-primitives",
            "mitre_technique": "T1548",
            "mitre_tactic": "Privilege Escalation",
            "severity": "HIGH",
            "detection_surface": ["opa"],
            "tier": 2,
            "fault_class": "escalation-primitive",
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
        print("== Fault Injection ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._inject(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])


class RbacEscalationDetection(RbacEscalationBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        RbacEscalationBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth)


class RbacEscalationLocalization(RbacEscalationBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        RbacEscalationBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth)
