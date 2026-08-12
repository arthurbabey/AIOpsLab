# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Benign twins — the RQ2 / specificity controls (precision under attack-shaped-but-legitimate activity).

A twin is `detected=False` even though **Falco fires**: a *legitimate* action that trips an
intrusion-shaped rule. It goes one step past the no-op — a no-op produces silence, so "No" is free,
whereas a twin fires the *same rule* an attacker would, so the agent must judge by **context**
rather than by the presence or type of an alert.

- `benign_admin_shell` — ✅ **a working twin.** An operator debug session: an interactive (TTY)
  shell running harmless diagnostics (`id`, `uname -a`, `ls /tmp`, `df -h`). It fires
  **"Terminal shell in container"** — the *same rule, same priority, same pod* as the attack half,
  `security_attacker_shell`. The attack additionally reads /etc/shadow and so also fires
  "Read sensitive file untrusted"; the twin touches no sensitive file. The shell alert alone is
  therefore not sufficient evidence, and an agent that treats every shell-in-container alert as an
  intrusion produces a visible false positive here. Score this problem **paired** with
  `security_attacker_shell` — that pair is what RQ2 rests on.

- `benign_secret_read` — ⚠️ **not a working twin; see `reports/PROBLEM_REVIEW.md` §3.4.** The
  intent was "the workload reads its OWN ServiceAccount token" (legitimate self-access shaped like
  credential theft). But Falco's `sensitive_files` macro covers /etc/shadow, /etc/sudoers and
  /etc/pam.* — *not* `/var/run/secrets/...` — so nothing fires and this is behaviourally a second
  no-op. It is kept only as an extra negative control and must NOT be counted as an RQ2 twin.
  Retire it or rebuild it around a rule an attack actually fires.

Correct answer for both: "No" / `[]`. A "Yes" is a **false positive** — the deployability metric a
SOC lives on. Uses the intrusion framing.
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
    # Falco rules this benign activity is EXPECTED to fire. Non-empty == a real twin (the agent
    # sees an attack-shaped alert and must still answer "No"); empty == behaves like a no-op.
    EXPECTED_FALCO_RULES: list[str] = []
    # Problem id of the attack this twin is matched against, for RQ2 precision. None == unpaired.
    RQ2_PAIR: str | None = None

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
            # A working twin IS visible to Falco — that is the whole point — even though the
            # correct answer stays "No". An empty list marks a twin that fires nothing and so
            # behaves as a no-op (see the module docstring on benign_secret_read).
            "detection_surface": ["falco"] if self.EXPECTED_FALCO_RULES else [],
            "fault_class": "benign-twin" if self.EXPECTED_FALCO_RULES else "benign-twin-silent",
            "benign_activity": self.BENIGN_ACTIVITY,
            "expected_falco_rules": self.EXPECTED_FALCO_RULES,
            "rq2_pair": self.RQ2_PAIR,
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


# ---- twin A: admin debug shell — the working RQ2 twin ----
class _BenignAdminShell(_BenignTwinBase):
    FAULT_TYPE = "benign_admin_shell"
    BENIGN_ACTIVITY = "admin debug shell running harmless diagnostics"
    # Same rule the attack half (security_attacker_shell) fires. The attack ALSO fires
    # "Read sensitive file untrusted"; this one does not — that absence is the discriminator.
    EXPECTED_FALCO_RULES = ["Terminal shell in container"]
    RQ2_PAIR = "security_attacker_shell"


class BenignAdminShellDetection(_BenignAdminShell, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignAdminShell.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class BenignAdminShellLocalization(_BenignAdminShell, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignAdminShell.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


# ---- twin B: workload reads its own SA token — fires NOTHING, so not an RQ2 twin ----
class _BenignSecretRead(_BenignTwinBase):
    FAULT_TYPE = "benign_secret_read"
    BENIGN_ACTIVITY = "workload reading its own mounted ServiceAccount token"
    # Empty on purpose: the SA token is not in Falco's `sensitive_files` set, so no rule fires.
    # Leaving this empty keeps the ground truth honest and marks the problem as an extra negative
    # control rather than a specificity test. See the module docstring and PROBLEM_REVIEW §3.4.
    EXPECTED_FALCO_RULES = []
    RQ2_PAIR = None


class BenignSecretReadDetection(_BenignSecretRead, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignSecretRead.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class BenignSecretReadLocalization(_BenignSecretRead, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignSecretRead.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
