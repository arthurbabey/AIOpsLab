# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Benign twins — the RQ2 / specificity controls (precision under attack-shaped-but-legitimate activity).

These are `detected=False` even though **Falco fires**: a *legitimate* action that trips an
intrusion-shaped rule. They go one step past the no-op — the no-op's benign alerts are a different
rule-type than the attack (easy to dismiss by category), whereas a twin fires the *same kind* of
alert an attacker would, so the agent must judge by **context**, not rule-type.

- `benign_admin_shell`: an operator debug session (runs id/uname/ls/df) — fires "Terminal shell in
  container" / exec activity, exactly like an attacker shell, but only does harmless diagnostics.
- `benign_secret_read`: the workload reading its OWN mounted ServiceAccount token — looks like
  credential access (T1552-shaped) but is normal self-authentication.

Correct answer: "No" / `[]`. A "Yes" is a **false positive** — the deployability metric a SOC
lives on. The question: does the +Falco agent reason about context (admin vs attacker, own-token
vs /etc/shadow), or does it cry wolf on any attack-shaped alert? Uses the intrusion framing.
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


class _BenignTwinBase:
    FAULT_TYPE = None          # set by subclass -> injector inject_<FAULT_TYPE>
    BENIGN_ACTIVITY = None

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
            "detected": False,            # benign — the correct answer is "No" / []
            "target_services": [],
            "target": None,
            "opa_control": None,
            "mitre_technique": None,
            "severity": None,
            "detection_surface": [],
            "fault_class": "benign-twin",
            "benign_activity": self.BENIGN_ACTIVITY,
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
        print(f"== Fault Injection (BENIGN TWIN: {self.BENIGN_ACTIVITY}) ==")
        injector = SecurityRuntimeInjector(namespace=self.namespace)
        injector._inject(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityRuntimeInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])


# ---- twin A: admin debug shell ----
class _BenignAdminShell(_BenignTwinBase):
    FAULT_TYPE = "benign_admin_shell"
    BENIGN_ACTIVITY = "admin debug shell running harmless diagnostics"


class BenignAdminShellDetection(_BenignAdminShell, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignAdminShell.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class BenignAdminShellLocalization(_BenignAdminShell, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignAdminShell.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


# ---- twin B: workload reads its own SA token ----
class _BenignSecretRead(_BenignTwinBase):
    FAULT_TYPE = "benign_secret_read"
    BENIGN_ACTIVITY = "workload reading its own mounted ServiceAccount token"


class BenignSecretReadDetection(_BenignSecretRead, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignSecretRead.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class BenignSecretReadLocalization(_BenignSecretRead, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignSecretRead.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
