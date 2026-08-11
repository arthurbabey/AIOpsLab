# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""SM.3 — over-permissive RBAC on SocialNetwork (OPA-visible security drift).

Tier-2 rung of the §8.1 ladder: *needle-in-a-haystack*. Inverts ``rbac-least-privilege.rego``
by creating one namespaced Role granting ``verbs:["*"] / resources:["*"]`` alongside ~40
benign, realistic-looking Roles. Nothing breaks (the grant just exists). The difficulty is
context/attention: react must pull the whole pile of Roles and spot the single dangerous rule,
where at Tier 0/1 there was only one object to look at. OPA flags the wildcard rule instantly —
so this is where the tool is predicted to start pulling ahead of manual inspection.

Note on the answer key: the affected resource here is a *Role*, not a workload, so
``target_services`` holds the wildcard Role's name — the thing the agent must name.
"""

from aiopslab.orchestrator.tasks.security_audit import (
    SecurityAuditDetectionTask,
    SecurityAuditLocalizationTask,
)
from aiopslab.service.apps.socialnet import SocialNetwork
from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.security_misconfig import SecurityMisconfigInjector
from aiopslab.generators.workload.wrk import Wrk
from aiopslab.paths import TARGET_MICROSERVICES

from aiopslab.orchestrator.problems.k8s_target_port_misconfig.helpers import (
    get_frontend_url,
)


class WildcardRbacBaseTask:
    FAULT_TYPE = "wildcard_rbac"
    WILDCARD_ROLE = "audit-log-collector"

    def __init__(self, faulty_service: str = "user-service"):
        self.app = SocialNetwork()
        self.kubectl = KubeCtl()
        self.namespace = self.app.namespace
        # The wildcard Role is bound to this workload's ServiceAccount, so the affected
        # resource is a real SERVICE (localizing it = trace Deployment → SA → RoleBinding → Role).
        self.faulty_service = faulty_service
        self.payload_script = (
            TARGET_MICROSERVICES
            / "socialNetwork/wrk2/scripts/social-network/compose-post.lua"
        )
        self.ground_truth = {
            "detected": True,
            "target_services": [faulty_service],
            "target": {
                "namespace": self.namespace,
                "workload": faulty_service,
                "via": f"wildcard Role '{self.WILDCARD_ROLE}' bound to its ServiceAccount",
            },
            "opa_control": "rbac-least-privilege",
            "mitre_technique": "T1078",
            "mitre_tactic": "Privilege Escalation",
            "severity": "MEDIUM",
            "detection_surface": ["opa"],
            "tier": 2,
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
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._inject(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])

    def recover_fault(self):
        print("== Fault Recovery ==")
        injector = SecurityMisconfigInjector(namespace=self.namespace)
        injector._recover(fault_type=self.FAULT_TYPE, microservices=[self.faulty_service])


class WildcardRbacDetection(WildcardRbacBaseTask, SecurityAuditDetectionTask):
    def __init__(self, faulty_service: str = "user-service"):
        WildcardRbacBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditDetectionTask.__init__(self, self.app, self.ground_truth)


class WildcardRbacLocalization(WildcardRbacBaseTask, SecurityAuditLocalizationTask):
    def __init__(self, faulty_service: str = "user-service"):
        WildcardRbacBaseTask.__init__(self, faulty_service=faulty_service)
        SecurityAuditLocalizationTask.__init__(self, self.app, self.ground_truth)
