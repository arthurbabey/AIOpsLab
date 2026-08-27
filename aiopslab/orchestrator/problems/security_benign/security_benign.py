# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Benign twins — the RQ2 / specificity controls (precision under attack-shaped-but-legitimate activity).

A twin is `detected=False` even though **Falco fires**: a *legitimate* action that trips an
intrusion-shaped rule. It goes one step past the no-op — a no-op produces silence, so "No" is free,
whereas a twin fires the *same rule* an attacker would, so the agent must judge by **context**
rather than by the presence or type of an alert.

Both twins here are matched against the same attack half, `security_attacker_shell`, and both fire
**"Terminal shell in container"** — the *same rule, same priority, same pod* as the attack. The
attack additionally reads /etc/shadow and so also fires "Read sensitive file untrusted"; neither
twin does. The shell alert alone is therefore never sufficient evidence.

- `benign_admin_shell` — the *easy* twin. An operator debug session running harmless diagnostics
  (`id`, `uname -a`, `ls /tmp`, `df -h`). It touches no credential at all, so "did this session
  access a secret?" already separates it from the attack.

- `benign_secret_read` — the *hard* twin. An operator session that reads the pod's OWN mounted
  ServiceAccount token. It touches a credential, legitimately — so an agent cannot separate it
  from the attack by asking "was a secret accessed?"; it must ask *whose* secret. (Historical note:
  this problem previously ran the token read WITHOUT a shell. The SA token is not in Falco's
  `sensitive_files` macro — which covers /etc/shadow, /etc/sudoers, /etc/pam.* — so it fired no
  rule at all and behaved as a second no-op. Delivering it through a TTY shell is what makes it a
  real twin.)

Score both **paired** with `security_attacker_shell`; that trio is what RQ2 rests on.

Correct answer for both: "No" / `[]`. A "Yes" is a **false positive** — the deployability metric a
SOC lives on. Uses the intrusion framing.

The exception: a twin whose shared surface is TELEMETRY, not Falco
-----------------------------------------------------------------
`benign_cpu_job` (twin E, the S7 pair) breaks the "a twin must fire the same Falco rule" rule
stated above, and does so on purpose. That rule is not really about Falco — it is about the twin
sharing the attack's *evidence*, so that the agent cannot separate the halves by the shape of an
alert and has to reason about context instead. For every other pair here Falco is the only
surface there is, so "share the evidence" and "share a Falco rule" are the same requirement.

S7 is the one fault in the suite that is visible on two surfaces (see
`security_crypto_miner.py`): Falco sees a miner, telemetry sees a pegged core. Its twin shares
the *telemetry* signature exactly — same sustained one-core load, same pod, same duration — and
is silent on Falco. So the doctrine holds where it matters: an agent reasoning from "sustained
CPU spike -> compromised workload" cannot tell this from the miner and false-positives here,
which is precisely the reasoning S7 exists to catch. What separates them is the miner signature
on the *other* surface. A twin that fired a miner rule would be a mislabelled attack, so
`_verify_falco_silent` measures the silence rather than assuming it.
"""

from aiopslab.orchestrator.tasks.security_audit import (
    SecurityAuditDetectionTask,
    SecurityAuditLocalizationTask,
)
from aiopslab.service.apps.hotelres import HotelReservation
from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.security_runtime import SecurityRuntimeInjector
from aiopslab.generators.fault.security_misconfig import SecurityMisconfigInjector
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
            "detected": False,            # benign — the correct answer is "No" / []
            "target_services": [],
            "target": None,
            "opa_control": None,
            "mitre_technique": None,
            "severity": None,
            # A working twin IS visible to Falco — that is the whole point — even though the
            # correct answer stays "No". An empty list would mark a twin that fires nothing and so
            # behaves as a no-op; both twins here fire, so both are real specificity tests.
            "detection_surface": ["falco"] if self.EXPECTED_FALCO_RULES else [],
            "fault_class": "benign-twin" if self.EXPECTED_FALCO_RULES else "benign-twin-silent",
            "benign_activity": self.BENIGN_ACTIVITY,
            "expected_falco_rules": self.EXPECTED_FALCO_RULES,
            "rq2_pair": self.RQ2_PAIR,
        }

    def start_workload(self):
        print("== Start Workload ==")
        wrk = Wrk(rate=100, dist="exp", connections=2, duration=10, threads=2)
        wrk.start_workload(
            payload_script=self.payload_script,
            url=get_frontend_url(self.app),
        )

    def inject_fault(self):
        print(f"== Fault Injection (BENIGN TWIN: {self.BENIGN_ACTIVITY}) ==")
        injector = SecurityRuntimeInjector(namespace=self.namespace)
        injector._inject(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityRuntimeInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])


class _BenignOpaTwinBase(_BenignTwinBase):
    """A twin whose sensor is OPA rather than Falco.

    The two sensors need different twins for a structural reason. Falco cannot see intent, so a
    runtime twin is built by doing the same ACTION for a legitimate reason. OPA reads the spec,
    and the spec IS the fact — `privileged: true` is `privileged: true` — so intent has nowhere
    to hide. An OPA twin has to move the field onto a WORKLOAD that has a reason for it.

    That makes the pairing rule sharper, not looser: the twin must fire the same policy as its
    attack and no other DRIFT policy. Posture findings do not count, because every workload of
    an un-hardened chart carries them and they discriminate nothing.
    """

    # OPA policy ids this benign workload is EXPECTED to fire. Must match the attack's set
    # exactly, or the agent can separate the two without judging anything.
    EXPECTED_OPA_POLICIES: list[str] = []

    def __init__(self, faulty_service: str = "user-service"):
        super().__init__(faulty_service=faulty_service)
        # HotelReservation: no baseline drift finding, so a fault-free problem really is one.
        self.app = HotelReservation()
        self.namespace = self.app.namespace
        self.payload_script = (
            TARGET_MICROSERVICES
            / "hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua"
        )
        self.ground_truth |= {
            "detected": False,
            "detection_surface": ["opa"] if self.EXPECTED_OPA_POLICIES else [],
            "fault_class": "benign-twin" if self.EXPECTED_OPA_POLICIES else "benign-twin-silent",
            "opa_control": self.EXPECTED_OPA_POLICIES[0] if self.EXPECTED_OPA_POLICIES else None,
            "expected_opa_policies": self.EXPECTED_OPA_POLICIES,
            "expected_falco_rules": [],
        }

    def start_workload(self):
        print("== Start Workload ==")
        wrk = Wrk(rate=100, dist="exp", connections=2, duration=10, threads=2)
        wrk.start_workload(payload_script=self.payload_script,
                           url=get_frontend_url(self.app))

    def inject_fault(self):
        print(f"== Fault Injection (BENIGN TWIN: {self.BENIGN_ACTIVITY}) ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._inject(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])


# ---- twin C: legitimately-privileged CNI installer — the OPA-side twin of SM.1 ----
class _BenignPrivileged(_BenignOpaTwinBase):
    FAULT_TYPE = "benign_privileged"
    BENIGN_ACTIVITY = (
        "CNI plugin installer DaemonSet running privileged to write the plugin binary and "
        "config onto the node filesystem"
    )
    # Exactly the policy security_privileged fires, and only that one. hostNetwork is omitted
    # from the manifest for this reason even though the real istio-cni-node sets it.
    EXPECTED_OPA_POLICIES = ["arrive-no-privileged-containers"]
    RQ2_PAIR = "security_privileged-detection-1"


class BenignPrivilegedDetection(_BenignPrivileged, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignPrivileged.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="misconfig")


class BenignPrivilegedLocalization(_BenignPrivileged, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignPrivileged.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="misconfig")


# ---- twin D: legitimately root node exporter — the OPA-side twin of SM.2 ----
class _BenignRunAsRoot(_BenignOpaTwinBase):
    FAULT_TYPE = "benign_run_as_root"
    BENIGN_ACTIVITY = (
        "node metrics exporter DaemonSet running as root to read the host's /proc and /sys"
    )
    # Exactly the policy security_run_as_root fires, and only that one — and via the same deny
    # rule, container-level runAsUser: 0, so the two halves are indistinguishable by message
    # shape as well as by policy.
    EXPECTED_OPA_POLICIES = ["arrive-no-root-user"]
    RQ2_PAIR = "security_run_as_root-detection-1"


class BenignRunAsRootDetection(_BenignRunAsRoot, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignRunAsRoot.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="misconfig")


class BenignRunAsRootLocalization(_BenignRunAsRoot, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        _BenignRunAsRoot.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="misconfig")


# ---- twin A: admin debug shell — the working RQ2 twin ----
class _BenignAdminShell(_BenignTwinBase):
    FAULT_TYPE = "benign_admin_shell"
    BENIGN_ACTIVITY = "admin debug shell running harmless diagnostics"
    # Same rule the attack half (security_attacker_shell) fires. The attack ALSO fires
    # "Read sensitive file untrusted"; this one does not — that absence is the discriminator.
    EXPECTED_FALCO_RULES = ["Terminal shell in container"]
    RQ2_PAIR = "security_attacker_shell"


class BenignAdminShellDetection(_BenignAdminShell, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user"):
        _BenignAdminShell.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class BenignAdminShellLocalization(_BenignAdminShell, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user"):
        _BenignAdminShell.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


# ---- twin B: interactive session reading its OWN SA token — the harder RQ2 twin ----
class _BenignSecretRead(_BenignTwinBase):
    FAULT_TYPE = "benign_secret_read"
    BENIGN_ACTIVITY = "operator session reading the pod's own mounted ServiceAccount token"
    # Fires the shared rule via the TTY shell, NOT via the token read: the SA token is not in
    # Falco's `sensitive_files` set, so reading it alone fires nothing (that is why this problem
    # used to behave as a second no-op). Delivered through an interactive shell it fires exactly
    # the attack's shared rule — see security_runtime.py::inject_benign_secret_read.
    EXPECTED_FALCO_RULES = ["Terminal shell in container"]
    RQ2_PAIR = "security_attacker_shell"


class BenignSecretReadDetection(_BenignSecretRead, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user"):
        _BenignSecretRead.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class BenignSecretReadLocalization(_BenignSecretRead, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user"):
        _BenignSecretRead.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


# ---- twin E: legitimate CPU-heavy batch job — the TELEMETRY-side twin of S7 ----
class _BenignCpuJob(_BenignTwinBase):
    FAULT_TYPE = "benign_cpu_job"
    BENIGN_ACTIVITY = (
        "nightly analytics rollup — a legitimate CPU-heavy batch job saturating one core "
        "inside an application pod"
    )
    # Deliberately EMPTY, and deliberately not the same thing as a silent twin. This pair's
    # shared evidence is the telemetry signature, not a Falco rule; the Falco silence IS the
    # discriminator, so it is asserted here and measured by the injector's
    # `_verify_falco_silent` against the miner's rule set. See the module docstring.
    EXPECTED_FALCO_RULES: list[str] = []
    RQ2_PAIR = "security_crypto_miner-detection-1"
    # The miner rules this benign job must NOT fire, mirrored from the attack half's ground
    # truth. Kept on the problem so the label registry and any analysis can read the twin's
    # negative claim without importing the injector.
    # The second is shadowed on the attack half (Falco's `rule_matching: first`), so it never
    # reports there either. It stays in the twin's forbidden set anyway: this list is what the
    # twin must NOT do, and it costs nothing to assert silence on a rule that could start
    # reporting the day someone sets `rule_matching: all`.
    FORBIDDEN_FALCO_RULES = [
        "Detect crypto miners using the Stratum protocol",
        "Known Cryptominer Process Executed",
    ]

    def __init__(self, faulty_service: str = "user"):
        super().__init__(faulty_service=faulty_service)
        # The base class derives `detection_surface` and `fault_class` from EXPECTED_FALCO_RULES,
        # which is the right default for every Falco-side twin and the wrong one here: an empty
        # Falco list would mark this "benign-twin-silent" (behaves as a second no-op) when in
        # fact it is loudly visible — on telemetry. Overridden rather than generalised, because
        # this is the only two-surface fault in the suite and a general mechanism would invite
        # future twins to declare a surface they have not verified.
        self.ground_truth |= {
            "detection_surface": ["telemetry"],
            "fault_class": "benign-twin",
            "shared_surface_with_twin": "telemetry",
            "forbidden_falco_rules": self.FORBIDDEN_FALCO_RULES,
        }


class BenignCpuJobDetection(_BenignCpuJob, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user"):
        _BenignCpuJob.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class BenignCpuJobLocalization(_BenignCpuJob, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user"):
        _BenignCpuJob.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


# ---- twin F: legitimate telemetry egress — the Falco-side twin of S4 (exfil) ----
class _BenignTelemetryEgress(_BenignTwinBase):
    FAULT_TYPE = "benign_telemetry_egress"
    BENIGN_ACTIVITY = (
        "operational telemetry POST — a periodic outbound connection shipping pod uptime "
        "counters to the documented telemetry-collector"
    )
    # The SAME single rule the attack half (security_exfil_egress) fires — a socket-dup detection
    # that does NOT look at the destination, so the alert is byte-identical for the two halves.
    # Unlike the shell twins, there is no second attack-only rule: the attack's extra evidence is
    # WHAT it read (the SA token) and WHERE it sent it (the unlisted data-collector), both visible
    # only in the shared alert's proc.cmdline / connection fields, not as a distinct rule. That is
    # the discriminator, and it is why an agent that flags any outbound redirect false-positives
    # here. See security_runtime.py::inject_benign_telemetry_egress.
    EXPECTED_FALCO_RULES = ["Redirect STDOUT/STDIN to Network Connection in Container"]
    RQ2_PAIR = "security_exfil_egress"


class BenignTelemetryEgressDetection(_BenignTelemetryEgress, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user"):
        _BenignTelemetryEgress.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class BenignTelemetryEgressLocalization(_BenignTelemetryEgress, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user"):
        _BenignTelemetryEgress.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
