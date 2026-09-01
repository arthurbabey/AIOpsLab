# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""S2 -- hostPath / host-mount escape on HotelReservation (``reports/BENCHMARK_IDEAS.md`` SS2).

A workload gains a hostPath volume mounting `/var/lib/kubelet` -- the kubelet's own working
directory, which holds the kubelet's client certificate/key and every pod's per-pod mount state.
Reading the credential material off that mount hands an attacker the kubelet's own identity: full
node compromise and, depending on RBAC, cluster-API access (NSA/CISA Kubernetes Hardening
Guidance v1.2; NIST SP 800-190 SS4). MITRE **T1611** (Escape to Host), tactic Privilege Escalation,
severity **HIGH** (contained code-execution-class access, per ``reports/DETECTION_BENCHMARK_PLAN.md``
SS5.1 -- not CRITICAL, because nothing has yet left the cluster boundary; see S4 for that).

Two channels, verified independently, both fire on the SAME mount and require nothing beyond the
patch landing (no exec, no access step):

1. **OPA** sees the spec the instant it's applied: ``no-sensitive-hostpath-mounts.rego`` denies
   any workload with a hostPath volume at one of a short list of host paths that grant effective
   node/cluster compromise (container-runtime socket, the kubelet directory, host root/`/etc`) --
   the SAME path set Falco's own `sensitive_mount` macro keys on, chosen before looking at this
   fault (``policies/README.md`` "is this cheating?" test).
2. **Falco** fires **"Launch Sensitive Mount Container"** (``falco-sandbox_rules.yaml``,
   `container_started and sensitive_mount`) the moment the patched pod's container starts --
   verified live against the deployed ruleset, not assumed from the rule's docstring. Unlike S4's
   shared rule, this one is keyed on the CONTAINER-SIDE mount path
   (`container.mount.dest`), which is why the injector mounts at the identical path
   (`/var/lib/kubelet`) rather than a renamed subdirectory -- see
   ``security_misconfig.py::_verify_hostpath_falco``.

This makes S2 the suite's first fault with a LIVE-VERIFIED dual-corroboration story: SM.1
(privileged) and SM.2 (run-as-root) also carry an `opa_control` field, but neither injector checks
whether Falco actually corroborates, because the ARRIVE OPA-ladder result is that static-spec
drift already saturates a react agent with `kubectl` -- adding a sensor there was never expected
to move accuracy. S2 is different: the runtime confirmation is unconditional (no access step
needed), so it is cheap to demand and verify, and it is the first fault where "OPA caught the
spec, Falco confirmed the behaviour" is a claim this repo has actually measured live rather than
only designed for.

The RQ2 twin is ``security_benign_hostpath_mount`` (in ``security_benign.py``): a CSI node-driver
-style DaemonSet that mounts the IDENTICAL host path for a real, common reason (managing per-pod
volume state) and so fires the SAME OPA policy and the SAME Falco rule. Unlike S4's twin, there is
no second field to omit that would separate the pair's evidence -- both surfaces are already
identical by construction. The discriminator is WHOSE workload this is: a CSI-node-plugin
DaemonSet has a documented reason to touch the kubelet directory; an application microservice
(HotelReservation's `user` service) does not. Score the two paired.

Non-breaking: the mount is read-only and never exercised (no cat/read of the kubelet's
credentials) -- the drift is the mount's PRESENCE, matching SM.1-SM.4's design; the app's own
process keeps running unmodified. The injector verifies both channels fired before the episode
starts.
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


class HostpathEscapeBaseTask:
    FAULT_TYPE = "hostpath_escape"

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
            "opa_control": "no-sensitive-hostpath-mounts",
            "mitre_technique": "T1611",
            "mitre_tactic": "Privilege Escalation",
            # Verified against falco-sandbox_rules.yaml (deployed) AND observed firing on a live
            # kind+Falco cluster: the mount alone fires this rule at container start, no access
            # step required -- see the module docstring.
            "expected_falco_rules": ["Launch Sensitive Mount Container"],
            "shared_rule_with_twin": "Launch Sensitive Mount Container",
            "shared_opa_policy_with_twin": "arrive-no-sensitive-hostpath-mounts",
            "severity": "HIGH",
            "detection_surface": ["opa", "falco"],
            "tier": None,
            "fault_class": "config-drift-verified-runtime",
            # RQ2 pairing: scored together with the benign twin (precision on a legitimate
            # CSI-style workload that mounts the identical host path).
            "rq2_pair": ["security_benign_hostpath_mount"],
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
        print(f"Service: {self.faulty_service} | Namespace: {self.namespace}\n")

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])
        print(f"Service: {self.faulty_service} | Namespace: {self.namespace}\n")


class HostpathEscapeDetection(HostpathEscapeBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user"):
        HostpathEscapeBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth, mode="misconfig")


class HostpathEscapeLocalization(HostpathEscapeBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user"):
        HostpathEscapeBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth, mode="misconfig")
