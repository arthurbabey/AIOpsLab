# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""SR.3 — attacker interactive shell on SocialNetwork (the malicious half of the RQ2 set).

The counterpart to BOTH benign twins (`security_benign_exec`, `security_benign_secret_read`). An
attacker holds an interactive (TTY) shell inside `user-service` and uses it for recon (`id`,
`hostname`, listing the mounted SA token) *and* credential theft (`cat /etc/shadow`). Two Falco
rules fire:

    "Terminal shell in container"        <- ALSO fires on the benign admin-shell twin
    "Read sensitive file untrusted"      <- fires ONLY here

That overlap is the point (§6.5 of ``reports/DETECTION_BENCHMARK_PLAN.md``). Because the shell
alert is shared with a legitimate operator session, it is *not sufficient evidence* on its own: an
agent that answers "Yes" to any shell-in-container alert scores a false positive on the twin, and
an agent that answers "No" to every shell misses this. Only reasoning about what the shell *did*
gets both halves right — which is precisely what RQ2 (specificity / precision) asks.

Non-breaking: every command is read-only, and the shell is a transient exec that exits each cycle,
so no process lingers for `ps` and the app is untouched. The injector verifies against Falco that
both rules actually fired before the episode is allowed to start.
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


class AttackerShellBaseTask:
    FAULT_TYPE = "attacker_shell"

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
            "mitre_technique": "T1059",
            "mitre_tactic": "Execution",
            # First rule is SHARED with the benign twin; second is the discriminator.
            "expected_falco_rules": [
                "Terminal shell in container",
                "Read sensitive file untrusted",
            ],
            "shared_rule_with_twin": "Terminal shell in container",
            "discriminating_rule": "Read sensitive file untrusted",
            "severity": "HIGH",
            "detection_surface": ["falco"],
            "tier": None,
            "fault_class": "runtime-intrusion",
            # RQ2 pairing: scored together with BOTH twins (precision on attack-shaped-but-
            # legitimate activity). security_benign_exec is the easy twin (no credential access at
            # all); security_benign_secret_read is the hard one (reads its OWN SA token, so "a
            # secret was touched" no longer separates it from this attack). See security_benign.py.
            "rq2_pair": ["security_benign_exec", "security_benign_secret_read"],
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


class AttackerShellDetection(AttackerShellBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        AttackerShellBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class AttackerShellLocalization(AttackerShellBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        AttackerShellBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
