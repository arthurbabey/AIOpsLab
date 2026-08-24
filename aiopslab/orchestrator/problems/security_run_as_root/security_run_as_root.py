# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""SM.2 — run-as-root escalation on HotelReservation (OPA-visible security drift).

Tier-1 rung of the §8.1 ladder: single-object, but a *subtle* field. Inverts
``no-root-user.rego`` by setting a container's ``securityContext.runAsUser: 0``. The
DeathStarBench containers already run as root, so this is non-breaking — it only makes the
hardening violation appear in the spec. Harder for react than Tier 0 because ``runAsUser: 0``
is easy to skim past inside a securityContext block, whereas ``privileged: true`` jumps out.
"""

from aiopslab.orchestrator.tasks.security_audit import (
    SecurityAuditDetectionTask,
    SecurityAuditLocalizationTask,
)
from aiopslab.service.apps.hotelres import HotelReservation
from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.security_misconfig import SecurityMisconfigInjector
from aiopslab.generators.workload.wrk import Wrk
from aiopslab.paths import TARGET_MICROSERVICES

from aiopslab.orchestrator.problems.k8s_target_port_misconfig.helpers import (
    get_frontend_url,
)


class RunAsRootBaseTask:
    FAULT_TYPE = "run_as_root"

    def __init__(self, faulty_service: str = "user"):
        self.app = HotelReservation()
        self.kubectl = KubeCtl()
        self.namespace = self.app.namespace
        self.faulty_service = faulty_service
        self.payload_script = (
            TARGET_MICROSERVICES
            / "hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua"
        )
        self.ground_truth = {
            "detected": True,
            "target_services": [faulty_service],
            "target": {"namespace": self.namespace, "workload": faulty_service},
            "opa_control": "no-root-user",
            "mitre_technique": "T1611",
            "mitre_tactic": "Privilege Escalation",
            "severity": "MEDIUM",
            "detection_surface": ["opa"],
            "tier": 1,
        }

    def start_workload(self):
        print("== Start Workload ==")
        wrk = Wrk(rate=100, dist="exp", connections=2, duration=10, threads=2)
        wrk.start_workload(
            payload_script=self.payload_script,
            url=get_frontend_url(self.app),
        )

    def inject_fault(self):
        print("== Fault Injection ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._inject(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])


class RunAsRootDetection(RunAsRootBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user"):
        RunAsRootBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth)


class RunAsRootLocalization(RunAsRootBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user"):
        RunAsRootBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth)
