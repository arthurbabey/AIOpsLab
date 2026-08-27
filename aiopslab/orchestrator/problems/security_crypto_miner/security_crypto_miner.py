# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""S7 — crypto-miner behaviour on HotelReservation, and its benign CPU-heavy twin.

This is the **two-surface** fault (`reports/BENCHMARK_IDEAS.md` §2, row S7), and it is the only
one in the security suite that is not single-surface. Every other runtime problem here is
Falco-only by construction — that is what those problems exist to prove. **Do not read this one
the same way.** S7 is visible to Falco AND to telemetry, at the same time, for two different
reasons that support two different conclusions:

    Falco     -> a process named `xmrig` with a `stratum+tcp://` pool URI in its argv
                 => resource hijacking, MITRE T1496, tactic Impact, severity HIGH
    telemetry -> one core pegged at 100% inside an application pod
                 => "hot workload" — a *reliability* symptom, and a *reliability* severity

The failure mode this problem is built to catch is an agent that stops at the second reading.
"CPU is high" is a true observation that leads to the wrong incident class and the wrong severity,
and it is available to every arm, including the ones with no security sensor at all. So a correct
"something is wrong here" is cheap; a correct *attribution* is not. That is the measurement.

The attack is a simulator, not mining software: the "miner" is the base image's own /bin/sh
burning a bounded loop under a symlinked name, and the pool URI is an unresolvable `.invalid`
host that nothing ever connects to. It reproduces the two observables a defender's tooling reads
and confers no capability beyond that. See `security_runtime.py` for the mechanism, for the
verification of each Falco rule name against the pinned upstream ruleset, and for why the third
upstream miner rule ("Detect outbound connections to common miner pool ports") is deliberately
not used — it cannot be fired without contacting a real mining pool.

Non-breaking, and bounded for a reason: one shell loop is exactly one core in one container, and
it runs at `nice -n 19` so the app's own threads win every scheduling contest. A readiness probe
that started failing would put a SECOND telemetry symptom on the board, and S7's design depends
on there being exactly one.

RULESET PREREQUISITE: the miner rules ship in Falco's **sandbox** ruleset, which the chart does
not install by default. The injector fails fast with the required helm flags if they are absent.

The RQ2 twin (`security_benign_cpu_job`) is the pair named explicitly in
`DETECTION_BENCHMARK_PLAN.md` §6.5 — "a real CPU-heavy job vs a crypto-miner". Note that its
shared surface is TELEMETRY, not Falco: unlike the shell twins, it fires no Falco rule at all.
That is not a degenerate twin, it is the same specificity test aimed at the other surface — see
`security_benign.py::_BenignCpuJob` for the argument.
"""

from aiopslab.orchestrator.tasks.security_audit import (
    SecurityAuditDetectionTask,
    SecurityAuditLocalizationTask,
)
from aiopslab.service.apps.hotelres import HotelReservation
from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.security_runtime import SecurityRuntimeInjector
from aiopslab.generators.workload.wrk import Wrk
from aiopslab.paths import TARGET_MICROSERVICES

from aiopslab.orchestrator.problems.k8s_target_port_misconfig.helpers import (
    get_frontend_url,
)


class CryptoMinerBaseTask:
    FAULT_TYPE = "crypto_miner"

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
            "opa_control": None,          # nothing changes in the spec — OPA is blind here
            # T1496 "Resource Hijacking", tactic Impact (TA0040), present in the ATT&CK
            # Containers matrix — verified at attack.mitre.org, not recalled. ATT&CK has since
            # split it into sub-techniques and T1496.001 "Compute Hijacking" is the exact one;
            # the parent ID is recorded here because that is what the Falco rules tag, so the
            # ground truth and the detector's own labels agree.
            "mitre_technique": "T1496",
            "mitre_tactic": "Impact",
            # Verified against falcosecurity/rules at falco-sandbox-rules-6.1.0 AND observed
            # firing on a live kind+Falco 0.44.1 cluster (see security_runtime.py). Fires on the
            # literal "stratum+tcp" substring in the process cmdline — guaranteed by construction.
            "expected_falco_rules": [
                "Detect crypto miners using the Stratum protocol",
            ],
            # SHADOWED — matches the miner but can never report it. Falco's default
            # `rule_matching: first` reports only the first rule that matches an event, and the
            # stratum rule sits earlier in the same ruleset file. Measured on a live cluster with
            # both rules loaded: only the stratum rule appeared, on an execve Falco itself
            # recorded as `proc.name=xmrig`. Recorded here so its absence reads as designed
            # rather than as a missing detection; nothing is lost, both rules are CRITICAL/T1496.
            "shadowed_falco_rules": [
                "Known Cryptominer Process Executed",
            ],
            # HIGH per DETECTION_BENCHMARK_PLAN.md §5.1: resource hijacking is an Impact-stage
            # objective (the adversary is already monetising access), but it is not data
            # exfiltration / C2 / data loss, which is what the rubric reserves CRITICAL for.
            # Falco's own priority on these rules is CRITICAL; the rubric's kill-chain anchor is
            # what breaks the tie, and it is the rubric that scores.
            "severity": "HIGH",
            # THE TWO-SURFACE FAULT. Every other runtime problem in this suite carries
            # ["falco"] alone; this one does not, and that is the whole reason it exists. A
            # reader generalising "runtime == Falco-only" from the neighbouring files will
            # mis-read every result on this problem.
            "detection_surface": ["falco", "telemetry"],
            "tier": None,
            "fault_class": "runtime-intrusion",
            # RQ2 pairing. Unlike the shell pairs, the shared signal is the TELEMETRY signature
            # (identical sustained CPU), not a shared Falco rule — so the discriminator is the
            # miner signature and an agent reasoning from CPU alone cannot separate the halves.
            "rq2_pair": ["security_benign_cpu_job"],
            "shared_surface_with_twin": "telemetry",
            "discriminating_rule": "Detect crypto miners using the Stratum protocol",
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
        injector = SecurityRuntimeInjector(namespace=self.namespace)
        injector._inject(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityRuntimeInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])


class CryptoMinerDetection(CryptoMinerBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user"):
        CryptoMinerBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class CryptoMinerLocalization(CryptoMinerBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user"):
        CryptoMinerBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
