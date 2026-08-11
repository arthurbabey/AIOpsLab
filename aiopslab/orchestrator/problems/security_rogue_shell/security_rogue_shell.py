# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""SR.1 — rogue process reading credentials on SocialNetwork (Falco-visible runtime drift).

The first fault where a tool is load-bearing for ACCURACY, not just cost. A rogue process inside
`user-service` repeatedly reads /etc/shadow — a syscall-level intrusion that changes no spec and
produces no telemetry symptom, so `base` (shell/logs/metrics/specs) and `+OPA` (declarative state)
are both BLIND. Only `+Falco` (runtime monitoring) sees it, via the default "Read sensitive file
untrusted" rule (MITRE T1555, Credential Access).

`detection_surface=["falco"]` marks this as Falco-only: the expected outcome is base ≈ "No" (blind)
/ +Falco = "Yes" (detects), the headline "coverage, not capability" result.
"""

from aiopslab.orchestrator.tasks.security_audit import (
    SecurityAuditDetectionTask,
    SecurityAuditLocalizationTask,
)
from aiopslab.service.apps.socialnet import SocialNetwork
from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.security_runtime import SecurityRuntimeInjector
from aiopslab.generators.workload.wrk import Wrk
from aiopslab.paths import TARGET_MICROSERVICES

from aiopslab.orchestrator.problems.k8s_target_port_misconfig.helpers import (
    get_frontend_url,
)


class RogueShellBaseTask:
    FAULT_TYPE = "rogue_shell"

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
            "target": {"namespace": self.namespace, "workload": faulty_service},
            "opa_control": None,
            "mitre_technique": "T1555",
            "mitre_tactic": "Credential Access",
            "expected_falco_rules": ["Read sensitive file untrusted"],
            "severity": "HIGH",
            "detection_surface": ["falco"],
            "tier": None,
            "fault_class": "runtime-intrusion",
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
        injector = SecurityRuntimeInjector(namespace=self.namespace)
        injector._inject(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityRuntimeInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])


class RogueShellDetection(RogueShellBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        RogueShellBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class RogueShellLocalization(RogueShellBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        RogueShellBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
