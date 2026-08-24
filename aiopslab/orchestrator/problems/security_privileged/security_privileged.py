# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""SM.1 — privileged-container escalation on HotelReservation (OPA-visible security drift).

Tier-0 rung of the §8.1 difficulty ladder (``reports/DETECTION_BENCHMARK_PLAN.md``): a single,
obvious, single-object misconfig. Inverts ``no-privileged-containers.rego`` by patching a
workload to ``securityContext.privileged: true``. The change is spec-visible (OPA fires) but
service-non-breaking (telemetry stays clean), so this is the anchor that should *reproduce the
null*: a react agent with a shell can eyeball one privileged pod, so +OPA is expected to add
little here — the lift only appears at higher tiers.
"""

from typing import Any

from aiopslab.orchestrator.tasks.security_audit import (
    SecurityAuditDetectionTask,
    SecurityAuditLocalizationTask,
)
from aiopslab.service.apps.hotelres import HotelReservation
from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.security_misconfig import SecurityMisconfigInjector
from aiopslab.generators.workload.wrk import Wrk
from aiopslab.paths import TARGET_MICROSERVICES
from aiopslab.session import SessionItem

from aiopslab.orchestrator.problems.k8s_target_port_misconfig.helpers import (
    get_frontend_url,
)


class PrivilegedContainerBaseTask:
    FAULT_TYPE = "privileged_container"

    def __init__(self, faulty_service: str = "user"):
        self.app = HotelReservation()
        self.kubectl = KubeCtl()
        self.namespace = self.app.namespace
        self.faulty_service = faulty_service
        self.payload_script = (
            TARGET_MICROSERVICES
            / "hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua"
        )
        # Constructive ground truth — staged, so the answer key is exact (§5 of the plan).
        self.ground_truth = {
            "detected": True,
            "target_services": [faulty_service],
            "target": {"namespace": self.namespace, "workload": faulty_service},
            "opa_control": "no-privileged-containers",
            "mitre_technique": "T1611",
            "mitre_tactic": "Privilege Escalation",
            "severity": "HIGH",
            "detection_surface": ["opa"],
            "tier": 0,
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
        injector._inject(
            fault_type=self.FAULT_TYPE, microservices=[self.faulty_service]
        )
        print(f"Service: {self.faulty_service} | Namespace: {self.namespace}\n")

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._recover(
            fault_type=self.FAULT_TYPE, microservices=[self.faulty_service]
        )
        print(f"Service: {self.faulty_service} | Namespace: {self.namespace}\n")


################## Detection Problem ##################
class PrivilegedContainerDetection(
    PrivilegedContainerBaseTask, SecurityAuditDetectionTask
):
    def __init__(self, faulty_service: str = "user"):
        PrivilegedContainerBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth)


################## Localization Problem ##################
class PrivilegedContainerLocalization(
    PrivilegedContainerBaseTask, SecurityAuditLocalizationTask
):
    def __init__(self, faulty_service: str = "user"):
        PrivilegedContainerBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth)
