from aiopslab.orchestrator.problems.k8s_target_port_misconfig import *
from aiopslab.orchestrator.problems.auth_miss_mongodb import *
from aiopslab.orchestrator.problems.revoke_auth import *
from aiopslab.orchestrator.problems.storage_user_unregistered import *
from aiopslab.orchestrator.problems.misconfig_app import *
from aiopslab.orchestrator.problems.scale_pod import *
from aiopslab.orchestrator.problems.assign_non_existent_node import *
from aiopslab.orchestrator.problems.container_kill import *
from aiopslab.orchestrator.problems.pod_failure import *
from aiopslab.orchestrator.problems.pod_kill import *
from aiopslab.orchestrator.problems.network_loss import *
from aiopslab.orchestrator.problems.network_delay import *
from aiopslab.orchestrator.problems.no_op import *
from aiopslab.orchestrator.problems.kernel_fault import *
from aiopslab.orchestrator.problems.disk_woreout import *
from aiopslab.orchestrator.problems.ad_service_failure import *
from aiopslab.orchestrator.problems.ad_service_high_cpu import *
from aiopslab.orchestrator.problems.ad_service_manual_gc import *
from aiopslab.orchestrator.problems.cart_service_failure import *
from aiopslab.orchestrator.problems.image_slow_load import *
from aiopslab.orchestrator.problems.kafka_queue_problems import *
from aiopslab.orchestrator.problems.loadgenerator_flood_homepage import *
from aiopslab.orchestrator.problems.payment_service_failure import *
from aiopslab.orchestrator.problems.payment_service_unreachable import *
from aiopslab.orchestrator.problems.product_catalog_failure import *
from aiopslab.orchestrator.problems.recommendation_service_cache_failure import *
from aiopslab.orchestrator.problems.redeploy_without_pv import *
from aiopslab.orchestrator.problems.wrong_bin_usage import *
from aiopslab.orchestrator.problems.operator_misoperation import *
from aiopslab.orchestrator.problems.flower_node_stop import *
from aiopslab.orchestrator.problems.flower_model_misconfig import *
from aiopslab.orchestrator.problems.security_privileged import *
from aiopslab.orchestrator.problems.security_run_as_root import *
from aiopslab.orchestrator.problems.security_wildcard_rbac import *
from aiopslab.orchestrator.problems.security_rbac_escalation import *
from aiopslab.orchestrator.problems.security_rogue_shell import *
from aiopslab.orchestrator.problems.security_transient_read import *
from aiopslab.orchestrator.problems.security_attacker_shell import *
from aiopslab.orchestrator.problems.security_crypto_miner import *
from aiopslab.orchestrator.problems.security_exfil_egress import *
from aiopslab.orchestrator.problems.security_noop import *
from aiopslab.orchestrator.problems.security_benign import *


class ProblemRegistry:
    def __init__(self):
        self.PROBLEM_REGISTRY = {
            # Security drift — OPA-visible checking-complexity ladder (RQ3), Phase A
            # Tier 0: single obvious object
            "security_privileged-detection-1": lambda: PrivilegedContainerDetection(
                faulty_service="user"
            ),
            "security_privileged-localization-1": lambda: PrivilegedContainerLocalization(
                faulty_service="user"
            ),
            # Tier 1: single subtle field (runAsUser: 0)
            "security_run_as_root-detection-1": lambda: RunAsRootDetection(
                faulty_service="user"
            ),
            "security_run_as_root-localization-1": lambda: RunAsRootLocalization(
                faulty_service="user"
            ),
            # Tier 2: needle-in-haystack (1 wildcard Role among ~60 benign)
            "security_wildcard_rbac-detection-1": lambda: WildcardRbacDetection(),
            "security_wildcard_rbac-localization-1": lambda: WildcardRbacLocalization(),
            # Tier 2 JUDGMENT hard-candidate: subtle escalation primitive (impersonate) in haystack
            "security_rbac_escalation-detection-1": lambda: RbacEscalationDetection(),
            "security_rbac_escalation-localization-1": lambda: RbacEscalationLocalization(),
            # Runtime (Falco-only): rogue process reads /etc/shadow — base+OPA blind, +Falco detects
            "security_rogue_shell-detection-1": lambda: RogueShellDetection(),
            "security_rogue_shell-localization-1": lambda: RogueShellLocalization(),
            # Runtime TRANSIENT: one-shot reads, no lingering process → base truly blind (ps finds nothing)
            "security_transient_read-detection-1": lambda: TransientReadDetection(),
            "security_transient_read-localization-1": lambda: TransientReadLocalization(),
            # RQ2 attack half: TTY shell doing recon + credential theft. Fires "Terminal shell in
            # container" (SHARED with BOTH benign twins) AND "Read sensitive file untrusted"
            # (unique). Score together with security_benign_exec + security_benign_secret_read —
            # the shared rule is what makes a twin a real specificity test, not a second no-op.
            "security_attacker_shell-detection-1": lambda: AttackerShellDetection(),
            "security_attacker_shell-localization-1": lambda: AttackerShellLocalization(),
            # S7 — the ONLY TWO-SURFACE fault in the suite. Every other runtime problem above is
            # Falco-only by design; this one is visible to Falco AND to telemetry at the same
            # time, and the two surfaces support different conclusions: Falco says "resource
            # hijacking" (T1496, Impact, HIGH), a pegged core says "hot workload" — a reliability
            # symptom with a reliability severity. What is measured is whether an agent stops at
            # the second reading, which is available even to the arms with no security sensor.
            # PREREQUISITE: the miner rules ship in Falco's SANDBOX ruleset and the chart installs
            # the stable ruleset only — the injector fails fast with the helm flags if absent.
            # RQ2 twin: security_benign_cpu_job. Unlike the shell pairs, that twin shares the
            # TELEMETRY signature (same one-core load) and fires no Falco rule at all — so the
            # discriminator is the miner signature, and an agent reasoning from CPU alone
            # false-positives on the twin. Score the two together.
            "security_crypto_miner-detection-1": lambda: CryptoMinerDetection(),
            "security_crypto_miner-localization-1": lambda: CryptoMinerLocalization(),
            # S4 — data-exfil egress. A rogue transient process ships the mounted SA token out of
            # the app pod to an unlisted in-cluster collector over a fresh plaintext TCP
            # connection. Falco-only (the spec is unchanged), MITRE T1048.003, tactic
            # Exfiltration, severity CRITICAL. The one rule that fires ("Redirect STDOUT/STDIN to
            # Network Connection in Container") is a STABLE-ruleset socket-dup detection, so S4
            # needs NO ruleset change (unlike S7) — but its own tag reads execution/T1059, NOT
            # exfil: a different wrong label, not the answer, which only bites the ordinal
            # severity score. RQ2 twin: security_benign_telemetry_egress fires the SAME one rule
            # shipping innocuous uptime telemetry to a documented collector — the discriminator is
            # the source read (cmdline) and the destination, not the alert. Score the two together.
            "security_exfil_egress-detection-1": lambda: ExfilEgressDetection(),
            "security_exfil_egress-localization-1": lambda: ExfilEgressLocalization(),
            # No-op controls (RQ1 false-alarm rate): nothing injected, detected=False
            "security_noop_misconfig-detection-1": lambda: NoopMisconfigDetection(),
            "security_noop_misconfig-localization-1": lambda: NoopMisconfigLocalization(),
            "security_noop_intrusion-detection-1": lambda: NoopIntrusionDetection(),
            "security_noop_intrusion-localization-1": lambda: NoopIntrusionLocalization(),
            # Benign twins (RQ2 specificity): attack-shaped-but-legitimate activity, detected=False
            "security_benign_exec-detection-1": lambda: BenignAdminShellDetection(),
            "security_benign_exec-localization-1": lambda: BenignAdminShellLocalization(),
            "security_benign_secret_read-detection-1": lambda: BenignSecretReadDetection(),
            "security_benign_secret_read-localization-1": lambda: BenignSecretReadLocalization(),
            # OPA-side twin: fires no-privileged-containers, same as security_privileged.
            "security_benign_privileged-detection-1": lambda: BenignPrivilegedDetection(),
            "security_benign_privileged-localization-1": lambda: BenignPrivilegedLocalization(),
            # OPA-side twin: fires no-root-user, same deny rule as security_run_as_root.
            "security_benign_run_as_root-detection-1": lambda: BenignRunAsRootDetection(),
            "security_benign_run_as_root-localization-1": lambda: BenignRunAsRootLocalization(),
            # Telemetry-side twin: a legitimate CPU-heavy batch job with the SAME one-core load
            # as security_crypto_miner and none of its miner signature. The first twin here whose
            # shared surface is telemetry rather than a Falco rule — see security_benign.py.
            "security_benign_cpu_job-detection-1": lambda: BenignCpuJobDetection(),
            "security_benign_cpu_job-localization-1": lambda: BenignCpuJobLocalization(),
            # Falco-side twin of S4: legitimate telemetry egress. Fires the SAME single rule as
            # security_exfil_egress ("Redirect STDOUT/STDIN...") shipping pod uptime to the
            # documented telemetry-collector. The alert is identical; the discriminator is the
            # source (proc.cmdline: /proc/uptime vs the SA token) and the destination Service.
            "security_benign_telemetry_egress-detection-1": lambda: BenignTelemetryEgressDetection(),
            "security_benign_telemetry_egress-localization-1": lambda: BenignTelemetryEgressLocalization(),
            # K8s target port misconfig
            "k8s_target_port-misconfig-detection-1": lambda: K8STargetPortMisconfigDetection(
                faulty_service="user-service"
            ),
            "k8s_target_port-misconfig-localization-1": lambda: K8STargetPortMisconfigLocalization(
                faulty_service="user-service"
            ),
            "k8s_target_port-misconfig-analysis-1": lambda: K8STargetPortMisconfigAnalysis(
                faulty_service="user-service"
            ),
            "k8s_target_port-misconfig-mitigation-1": lambda: K8STargetPortMisconfigMitigation(
                faulty_service="user-service"
            ),
            "k8s_target_port-misconfig-detection-2": lambda: K8STargetPortMisconfigDetection(
                faulty_service="text-service"
            ),
            "k8s_target_port-misconfig-localization-2": lambda: K8STargetPortMisconfigLocalization(
                faulty_service="text-service"
            ),
            "k8s_target_port-misconfig-analysis-2": lambda: K8STargetPortMisconfigAnalysis(
                faulty_service="text-service"
            ),
            "k8s_target_port-misconfig-mitigation-2": lambda: K8STargetPortMisconfigMitigation(
                faulty_service="text-service"
            ),
            "k8s_target_port-misconfig-detection-3": lambda: K8STargetPortMisconfigDetection(
                faulty_service="post-storage-service"
            ),
            "k8s_target_port-misconfig-localization-3": lambda: K8STargetPortMisconfigLocalization(
                faulty_service="post-storage-service"
            ),
            "k8s_target_port-misconfig-analysis-3": lambda: K8STargetPortMisconfigAnalysis(
                faulty_service="post-storage-service"
            ),
            "k8s_target_port-misconfig-mitigation-3": lambda: K8STargetPortMisconfigMitigation(
                faulty_service="post-storage-service"
            ),
            # MongoDB auth missing
            "auth_miss_mongodb-detection-1": MongoDBAuthMissingDetection,
            "auth_miss_mongodb-localization-1": MongoDBAuthMissingLocalization,
            "auth_miss_mongodb-analysis-1": MongoDBAuthMissingAnalysis,
            "auth_miss_mongodb-mitigation-1": MongoDBAuthMissingMitigation,
            # MongoDB auth revoke
            "revoke_auth_mongodb-detection-1": lambda: MongoDBRevokeAuthDetection(
                faulty_service="mongodb-geo"
            ),
            "revoke_auth_mongodb-localization-1": lambda: MongoDBRevokeAuthLocalization(
                faulty_service="mongodb-geo"
            ),
            "revoke_auth_mongodb-analysis-1": lambda: MongoDBRevokeAuthAnalysis(
                faulty_service="mongodb-geo"
            ),
            "revoke_auth_mongodb-mitigation-1": lambda: MongoDBRevokeAuthMitigation(
                faulty_service="mongodb-geo"
            ),
            "revoke_auth_mongodb-detection-2": lambda: MongoDBRevokeAuthDetection(
                faulty_service="mongodb-rate"
            ),
            "revoke_auth_mongodb-localization-2": lambda: MongoDBRevokeAuthLocalization(
                faulty_service="mongodb-rate"
            ),
            "revoke_auth_mongodb-analysis-2": lambda: MongoDBRevokeAuthAnalysis(
                faulty_service="mongodb-rate"
            ),
            "revoke_auth_mongodb-mitigation-2": lambda: MongoDBRevokeAuthMitigation(
                faulty_service="mongodb-rate"
            ),
            # MongoDB user unregistered
            "user_unregistered_mongodb-detection-1": lambda: MongoDBUserUnregisteredDetection(
                faulty_service="mongodb-geo"
            ),
            "user_unregistered_mongodb-localization-1": lambda: MongoDBUserUnregisteredLocalization(
                faulty_service="mongodb-geo"
            ),
            "user_unregistered_mongodb-analysis-1": lambda: MongoDBUserUnregisteredAnalysis(
                faulty_service="mongodb-geo"
            ),
            "user_unregistered_mongodb-mitigation-1": lambda: MongoDBUserUnregisteredMitigation(
                faulty_service="mongodb-geo"
            ),
            "user_unregistered_mongodb-detection-2": lambda: MongoDBUserUnregisteredDetection(
                faulty_service="mongodb-rate"
            ),
            "user_unregistered_mongodb-localization-2": lambda: MongoDBUserUnregisteredLocalization(
                faulty_service="mongodb-rate"
            ),
            "user_unregistered_mongodb-analysis-2": lambda: MongoDBUserUnregisteredAnalysis(
                faulty_service="mongodb-rate"
            ),
            "user_unregistered_mongodb-mitigation-2": lambda: MongoDBUserUnregisteredMitigation(
                faulty_service="mongodb-rate"
            ),
            # App misconfig
            "misconfig_app_hotel_res-detection-1": MisconfigAppHotelResDetection,
            "misconfig_app_hotel_res-localization-1": MisconfigAppHotelResLocalization,
            "misconfig_app_hotel_res-analysis-1": MisconfigAppHotelResAnalysis,
            "misconfig_app_hotel_res-mitigation-1": MisconfigAppHotelResMitigation,
            # Scale pod to zero deployment
            "scale_pod_zero_social_net-detection-1": ScalePodSocialNetDetection,
            "scale_pod_zero_social_net-localization-1": ScalePodSocialNetLocalization,
            "scale_pod_zero_social_net-analysis-1": ScalePodSocialNetAnalysis,
            "scale_pod_zero_social_net-mitigation-1": ScalePodSocialNetMitigation,
            # Assign pod to non-existent node
            "assign_to_non_existent_node_social_net-detection-1": AssignNonExistentNodeSocialNetDetection,
            "assign_to_non_existent_node_social_net-localization-1": AssignNonExistentNodeSocialNetLocalization,
            "assign_to_non_existent_node_social_net-analysis-1": AssignNonExistentNodeSocialNetAnalysis,
            "assign_to_non_existent_node_social_net-mitigation-1": AssignNonExistentNodeSocialNetMitigation,
            # Chaos mesh container kill
            "container_kill-detection": ContainerKillDetection,
            "container_kill-localization": ContainerKillLocalization,
            # Pod failure
            "pod_failure_hotel_res-detection-1": PodFailureDetection,
            "pod_failure_hotel_res-localization-1": PodFailureLocalization,
            # Pod kill
            "pod_kill_hotel_res-detection-1": PodKillDetection,
            "pod_kill_hotel_res-localization-1": PodKillLocalization,
            # Network loss
            "network_loss_hotel_res-detection-1": NetworkLossDetection,
            "network_loss_hotel_res-localization-1": NetworkLossLocalization,
            # Network delay
            "network_delay_hotel_res-detection-1": NetworkDelayDetection,
            "network_delay_hotel_res-localization-1": NetworkDelayLocalization,
            # No operation
            "noop_detection_hotel_reservation-1": lambda: NoOpDetection(
                app_name="hotel"
            ),
            "noop_detection_social_network-1": lambda: NoOpDetection(app_name="social"),
            "noop_detection_astronomy_shop-1": lambda: NoOpDetection(app_name="astronomy_shop"),
            # NOTE: This should be getting fixed by the great powers of @jinghao-jia
            # Kernel fault -> https://github.com/xlab-uiuc/agent-ops/pull/10#issuecomment-2468992285
            # There's a bug in chaos mesh regarding this fault, wait for resolution and retest kernel fault
            # "kernel_fault_hotel_reservation-detection-1": KernelFaultDetection,
            # "kernel_fault_hotel_reservation-localization-1": KernelFaultLocalization
            # "disk_woreout-detection-1": DiskWoreoutDetection,
            # "disk_woreout-localization-1": DiskWoreoutLocalization,
            # Open Telemetry Demo (Astronomy Shop) feature flag failures
            "astronomy_shop_ad_service_failure-detection-1": AdServiceFailureDetection,
            "astronomy_shop_ad_service_failure-localization-1": AdServiceFailureLocalization,
            "astronomy_shop_ad_service_high_cpu-detection-1": AdServiceHighCpuDetection,
            "astronomy_shop_ad_service_high_cpu-localization-1": AdServiceHighCpuLocalization,
            "astronomy_shop_ad_service_manual_gc-detection-1": AdServiceManualGcDetection,
            "astronomy_shop_ad_service_manual_gc-localization-1": AdServiceManualGcLocalization,
            "astronomy_shop_cart_service_failure-detection-1": CartServiceFailureDetection,
            "astronomy_shop_cart_service_failure-localization-1": CartServiceFailureLocalization,
            "astronomy_shop_image_slow_load-detection-1": ImageSlowLoadDetection,
            "astronomy_shop_image_slow_load-localization-1": ImageSlowLoadLocalization,
            "astronomy_shop_kafka_queue_problems-detection-1": KafkaQueueProblemsDetection,
            "astronomy_shop_kafka_queue_problems-localization-1": KafkaQueueProblemsLocalization,
            "astronomy_shop_kafka_queue_problems-mitigation-1": KafkaQueueProblemsMitigation,
            "astronomy_shop_loadgenerator_flood_homepage-detection-1": LoadGeneratorFloodHomepageDetection,
            "astronomy_shop_loadgenerator_flood_homepage-localization-1": LoadGeneratorFloodHomepageLocalization,
            "astronomy_shop_payment_service_failure-detection-1": PaymentServiceFailureDetection,
            "astronomy_shop_payment_service_failure-localization-1": PaymentServiceFailureLocalization,
            "astronomy_shop_payment_service_unreachable-detection-1": PaymentServiceUnreachableDetection,
            "astronomy_shop_payment_service_unreachable-localization-1": PaymentServiceUnreachableLocalization,
            "astronomy_shop_product_catalog_service_failure-detection-1": ProductCatalogServiceFailureDetection,
            "astronomy_shop_product_catalog_service_failure-localization-1": ProductCatalogServiceFailureLocalization,
            "astronomy_shop_recommendation_service_cache_failure-detection-1": RecommendationServiceCacheFailureDetection,
            "astronomy_shop_recommendation_service_cache_failure-localization-1": RecommendationServiceCacheFailureLocalization,
            # Redeployment of namespace without deleting the PV
            "redeploy_without_PV-detection-1": RedeployWithoutPVDetection,
            # "redeploy_without_PV-localization-1": RedeployWithoutPVLocalization,
            "redeploy_without_PV-analysis-1": RedeployWithoutPVAnalysis,
            "redeploy_without_PV-mitigation-1": RedeployWithoutPVMitigation,
            # Assign pod to non-existent node
            "wrong_bin_usage-detection-1": WrongBinUsageDetection,
            "wrong_bin_usage-localization-1": WrongBinUsageLocalization,
            "wrong_bin_usage-analysis-1": WrongBinUsageAnalysis,
            "wrong_bin_usage-mitigation-1": WrongBinUsageMitigation,
            # K8S operator misoperation
            # "operator_overload_replicas-detection-1": K8SOperatorOverloadReplicasDetection,
            # "operator_overload_replicas-localization-1": K8SOperatorOverloadReplicasLocalization,
            # "operator_non_existent_storage-detection-1": K8SOperatorNonExistentStorageDetection,
            # "operator_non_existent_storage-localization-1": K8SOperatorNonExistentStorageLocalization,
            # "operator_invalid_affinity_toleration-detection-1": K8SOperatorInvalidAffinityTolerationDetection,
            # "operator_invalid_affinity_toleration-localization-1": K8SOperatorInvalidAffinityTolerationLocalization,
            # "operator_security_context_fault-detection-1": K8SOperatorSecurityContextFaultDetection,
            # "operator_security_context_fault-localization-1": K8SOperatorSecurityContextFaultLocalization,
            # "operator_wrong_update_strategy-detection-1": K8SOperatorWrongUpdateStrategyDetection,
            # "operator_wrong_update_strategy-localization-1": K8SOperatorWrongUpdateStrategyLocalization,
            # Flower
            "flower_node_stop-detection": FlowerNodeStopDetection,
            "flower_model_misconfig-detection": FlowerModelMisconfigDetection,
        }
        self.DOCKER_REGISTRY = [
            "flower_node_stop-detection",
            "flower_model_misconfig-detection",
        ]

    def get_problem_instance(self, problem_id: str):
        if problem_id not in self.PROBLEM_REGISTRY:
            raise ValueError(f"Problem ID {problem_id} not found in registry.")

        return self.PROBLEM_REGISTRY.get(problem_id)()

    def get_problem(self, problem_id: str):
        return self.PROBLEM_REGISTRY.get(problem_id)

    def get_problem_ids(self, task_type: str = None):
        if task_type:
            return [k for k in self.PROBLEM_REGISTRY.keys() if task_type in k]
        return list(self.PROBLEM_REGISTRY.keys())

    def get_problem_count(self, task_type: str = None):
        if task_type:
            return len([k for k in self.PROBLEM_REGISTRY.keys() if task_type in k])
        return len(self.PROBLEM_REGISTRY)
    
    def get_problem_deployment(self, problem_id: str):
        if problem_id in self.DOCKER_REGISTRY:
            return "docker"
        return "k8s"
