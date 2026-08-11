# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""SR.2 — TRANSIENT credential reads on SocialNetwork (Falco-only, the clean coverage fault).

The controlled counterpart to `security_rogue_shell`: same intrusion (a process reading
/etc/shadow in `user-service`), but delivered as **transient one-shot reads** with NO lingering
process in the pod (a host-side loop execs a `cat` that exits immediately each time). So:

- `ps` inside the pod finds **nothing** — the process is already gone → a shell agent (`base`) is
  genuinely **BLIND**, not merely slow. There is no persistent artifact to discover.
- Falco **recorded** every read in its log → `+Falco` detects it via `get_alerts`.

This is the fault that tests **coverage, not efficiency**: unlike the persistent `rogue_shell`
(which base can find by `ps`-ing pods, so the tool only saved cost), here there is nothing to
`ps` — the runtime tool is load-bearing for **accuracy**. Expected: base ≈ "No" (blind), +Falco =
"Yes" (detects). Uses the "intrusion" task framing (active attack vs static misconfig).
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


class TransientReadBaseTask:
    FAULT_TYPE = "transient_read"

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
            "fault_class": "runtime-intrusion-transient",
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


class TransientReadDetection(TransientReadBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        TransientReadBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class TransientReadLocalization(TransientReadBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        TransientReadBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
