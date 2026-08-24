# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Security-misconfiguration fault injectors (OPA-visible security drift).

Each injector applies a policy-VIOLATING but service-NON-BREAKING change, inverting one
of the grounded OPA policies in ``policies/k8s/``. The workload keeps serving traffic, so
telemetry stays clean and the drift is only visible in the spec (OPA territory). Ground
truth (which control is violated, which workload) is owned by the problem class, not here —
the injector's only job is to apply and revert the drift.

Vertical-slice scope: ``privileged_container`` (inverts ``no-privileged-containers.rego``),
the Tier-0 rung of the §8.1 difficulty ladder in ``reports/DETECTION_BENCHMARK_PLAN.md``.
Further rungs (allowPrivilegeEscalation, wildcard RBAC, hostNetwork, ...) are added here as
``inject_<fault>`` / ``recover_<fault>`` pairs following the same pattern.
"""

import json

from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.base import FaultInjector


class SecurityMisconfigInjector(FaultInjector):
    def __init__(self, namespace: str):
        super().__init__(namespace)
        self.namespace = namespace
        self.kubectl = KubeCtl()

    ############# HELPERS ################

    def _container_names(self, deployment: str) -> list[str]:
        """Container names in a deployment's pod template (strategic-merge patch keys)."""
        out = self.kubectl.exec_command(
            f"kubectl get deployment {deployment} -n {self.namespace} -o json"
        )
        spec = json.loads(out)
        return [c["name"] for c in spec["spec"]["template"]["spec"]["containers"]]

    def _set_privileged(self, deployment: str, value: bool):
        """Strategic-merge patch each container's securityContext.privileged.

        Merges by container name, so it neither drops other securityContext fields nor
        touches sibling containers. Triggers a rolling update; the app stays up.
        """
        for name in self._container_names(deployment):
            patch = {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": name, "securityContext": {"privileged": value}}
                            ]
                        }
                    }
                }
            }
            cmd = (
                f"kubectl patch deployment {deployment} -n {self.namespace} "
                f"--type=strategic -p '{json.dumps(patch)}'"
            )
            print(self.kubectl.exec_command(cmd).strip())

    ############# FAULT LIBRARY ################

    # SM.1 - privileged_container: invert no-privileged-containers.rego
    def inject_privileged_container(self, microservices: list[str]):
        """Escalate a workload to run privileged (full host access) — spec-visible drift."""
        for service in microservices:
            print(
                f"[security_misconfig] privileged:true on {service} | ns: {self.namespace}"
            )
            self._set_privileged(service, True)

    def recover_privileged_container(self, microservices: list[str]):
        for service in microservices:
            print(
                f"[security_misconfig] revert privileged on {service} | ns: {self.namespace}"
            )
            self._set_privileged(service, False)

    # SM.1b - benign_privileged: the BENIGN TWIN of privileged_container.
    #
    # Fires the SAME policy (no-privileged-containers) as SM.1, on a workload that has a real
    # reason for the privilege. A CNI plugin installer writes the plugin binary and its config
    # onto the node's filesystem; it cannot do that unprivileged, and Istio ships exactly this
    # as a DaemonSet in the application's own namespace. So the policy is right to fire and the
    # correct answer is still "no attack" — which is the only thing that stops an agent scoring
    # perfectly by relaying "OPA fired -> yes".
    #
    # Two details are load-bearing:
    #   * the hostPath mounts. Without them the privilege is decorative and the workload is not
    #     a credible carrier for it.
    #   * hostNetwork is OMITTED, though the real istio-cni-node sets it. It would trip
    #     no-host-network as well, giving the twin a two-policy signature the attack does not
    #     have — and the agent could then separate them without judging anything. A measurement
    #     decision, not an oversight.
    BENIGN_PRIVILEGED_NAME = "istio-cni-node"
    # Same workload with every brand signal removed: name, image and labels say nothing about
    # who ships it. Structure — DaemonSet, privileged, host CNI mounts — is identical, so a
    # verdict that changes between the two was driven by recognition, not by the spec.
    BENIGN_PRIVILEGED_ANON_NAME = "cni-installer"

    def _privileged_daemonset(self, name: str, container: str, image: str) -> dict:
        return {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": name,
                "namespace": self.namespace,
                "labels": {"app": name, "k8s-app": name},
            },
            "spec": {
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {"labels": {"app": name}},
                    "spec": {
                        "containers": [{
                            "name": container,
                            "image": image,
                            # Reads both mounts on a loop and logs it. Read-only on purpose:
                            # writing into a node's real /opt/cni/bin could break cluster
                            # networking. No single quotes — the manifest is shipped through
                            # echo '<json>' | kubectl apply -f -.
                            "command": ["/bin/sh", "-c",
                                        "while true; do "
                                        "echo [install-cni] verifying CNI plugin dir and config; "
                                        "ls /host/opt/cni/bin >/dev/null 2>&1; "
                                        "ls /host/etc/cni/net.d >/dev/null 2>&1; "
                                        "sleep 30; done"],
                            "securityContext": {"privileged": True},
                            "volumeMounts": [
                                {"name": "cni-bin-dir", "mountPath": "/host/opt/cni/bin"},
                                {"name": "cni-net-dir", "mountPath": "/host/etc/cni/net.d"},
                            ],
                        }],
                        "volumes": [
                            {"name": "cni-bin-dir", "hostPath": {"path": "/opt/cni/bin"}},
                            {"name": "cni-net-dir", "hostPath": {"path": "/etc/cni/net.d"}},
                        ],
                    },
                },
            },
        }

    def _benign_privileged_manifest(self) -> dict:
        return self._privileged_daemonset(
            self.BENIGN_PRIVILEGED_NAME, "install-cni", "docker.io/istio/install-cni:1.20.0")

    def _benign_privileged_anon_manifest(self) -> dict:
        return self._privileged_daemonset(
            self.BENIGN_PRIVILEGED_ANON_NAME, "install-cni", "alpine:3.19")

    def inject_benign_privileged_anon(self, microservices: list[str] = None):
        print(f"[security_misconfig] benign twin (anonymised): "
              f"{self.BENIGN_PRIVILEGED_ANON_NAME} | ns: {self.namespace}")
        manifest = json.dumps(self._benign_privileged_anon_manifest())
        print(self.kubectl.exec_command(f"echo '{manifest}' | kubectl apply -f -").strip())

    def recover_benign_privileged_anon(self, microservices: list[str] = None):
        print(f"[security_misconfig] removing: {self.BENIGN_PRIVILEGED_ANON_NAME}")
        print(self.kubectl.exec_command(
            f"kubectl delete daemonset {self.BENIGN_PRIVILEGED_ANON_NAME} "
            f"-n {self.namespace} --ignore-not-found").strip())

    def inject_benign_privileged(self, microservices: list[str] = None):
        """Deploy a legitimately-privileged CNI installer alongside the app."""
        print(f"[security_misconfig] benign twin: {self.BENIGN_PRIVILEGED_NAME} "
              f"(privileged, legitimate) | ns: {self.namespace}")
        manifest = json.dumps(self._benign_privileged_manifest())
        print(self.kubectl.exec_command(
            f"echo '{manifest}' | kubectl apply -f -").strip())

    def recover_benign_privileged(self, microservices: list[str] = None):
        print(f"[security_misconfig] removing benign twin: {self.BENIGN_PRIVILEGED_NAME}")
        print(self.kubectl.exec_command(
            f"kubectl delete daemonset {self.BENIGN_PRIVILEGED_NAME} "
            f"-n {self.namespace} --ignore-not-found").strip())

    # SM.2 - run_as_root (Tier 1): invert no-root-user.rego
    # Sets container securityContext.runAsUser=0. DeathStarBench containers already run as
    # root, so this changes nothing at runtime (non-breaking) — it only makes the hardening
    # violation spec-visible. Subtler than `privileged`: one easy-to-skim field.
    def inject_run_as_root(self, microservices: list[str]):
        for service in microservices:
            print(f"[security_misconfig] runAsUser:0 on {service} | ns: {self.namespace}")
            for name in self._container_names(service):
                patch = {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"name": name, "securityContext": {"runAsUser": 0}}
                                ]
                            }
                        }
                    }
                }
                cmd = (
                    f"kubectl patch deployment {service} -n {self.namespace} "
                    f"--type=strategic -p '{json.dumps(patch)}'"
                )
                print(self.kubectl.exec_command(cmd).strip())

    def recover_run_as_root(self, microservices: list[str]):
        for service in microservices:
            print(f"[security_misconfig] revert runAsUser on {service} | ns: {self.namespace}")
            for name in self._container_names(service):
                # null in a strategic-merge patch deletes the field → restores original.
                patch = {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"name": name, "securityContext": {"runAsUser": None}}
                                ]
                            }
                        }
                    }
                }
                cmd = (
                    f"kubectl patch deployment {service} -n {self.namespace} "
                    f"--type=strategic -p '{json.dumps(patch)}'"
                )
                print(self.kubectl.exec_command(cmd).strip())

    # SM.2b - benign_run_as_root: the BENIGN TWIN of run_as_root.
    #
    # Fires the SAME policy (no-root-user) and the SAME deny rule as SM.2 — container-level
    # securityContext.runAsUser: 0 — on a workload that needs it. A node metrics exporter reads
    # the host's /proc and /sys; those are root-owned, so it cannot collect anything as a
    # non-root user. Prometheus documents this and kube-prometheus-stack ships node-exporter as
    # a root DaemonSet by default.
    #
    # Same three rules as the privileged twin, learned the same way:
    #   * the hostPath mounts are load-bearing. They are what makes root NECESSARY rather than
    #     decorative, and they are what an agent can point at when judging legitimacy — on the
    #     privileged twin the agent cited the mount paths verbatim.
    #   * hostPID and hostNetwork are OMITTED, though real node-exporter sets both. They would
    #     trip no-host-network as well, giving the twin a two-policy signature the attack does
    #     not have, and the agent could separate the pair without judging anything.
    #   * the image tag is pinned, so no-latest-tag stays quiet.
    BENIGN_RUN_AS_ROOT_NAME = "node-exporter"

    def _benign_run_as_root_manifest(self) -> dict:
        name = self.BENIGN_RUN_AS_ROOT_NAME
        return {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": name,
                "namespace": self.namespace,
                "labels": {"app": name, "k8s-app": name},
            },
            "spec": {
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {"labels": {"app": name}},
                    "spec": {
                        "containers": [{
                            "name": name,
                            "image": "prom/node-exporter:v1.7.0",
                            "args": ["--path.procfs=/host/proc", "--path.sysfs=/host/sys"],
                            # Container-level, matching the deny rule SM.2 trips. Pod-level
                            # would fire a different rule and a different message.
                            "securityContext": {"runAsUser": 0},
                            "volumeMounts": [
                                {"name": "proc", "mountPath": "/host/proc", "readOnly": True},
                                {"name": "sys", "mountPath": "/host/sys", "readOnly": True},
                            ],
                        }],
                        "volumes": [
                            {"name": "proc", "hostPath": {"path": "/proc"}},
                            {"name": "sys", "hostPath": {"path": "/sys"}},
                        ],
                    },
                },
            },
        }

    def inject_benign_run_as_root(self, microservices: list[str] = None):
        """Deploy a node metrics exporter that legitimately runs as root."""
        print(f"[security_misconfig] benign twin: {self.BENIGN_RUN_AS_ROOT_NAME} "
              f"(runAsUser 0, legitimate) | ns: {self.namespace}")
        manifest = json.dumps(self._benign_run_as_root_manifest())
        print(self.kubectl.exec_command(
            f"echo '{manifest}' | kubectl apply -f -").strip())

    def recover_benign_run_as_root(self, microservices: list[str] = None):
        print(f"[security_misconfig] removing benign twin: {self.BENIGN_RUN_AS_ROOT_NAME}")
        print(self.kubectl.exec_command(
            f"kubectl delete daemonset {self.BENIGN_RUN_AS_ROOT_NAME} "
            f"-n {self.namespace} --ignore-not-found").strip())

    # SM.3 - wildcard_rbac (Tier 2): invert rbac-least-privilege.rego, needle-in-haystack.
    # ONE over-permissive Role hides among many heterogeneous, plausible-looking Roles; it is bound
    # (RoleBinding -> dedicated SA) to a target workload so localizing it is a cross-object trace.
    # NO telltale label on any object — teardown is by deterministic name (a label like
    # "arrive-injected" would let the agent grep the injected objects for free = benchmark leak).
    # The over-permission is a wildcard VERB on sensitive resources (secrets/configmaps) rather than
    # a glaring "* * *", so it reads like a plausible manager Role — still fires the wildcard rule.
    N_BENIGN = 60
    WILDCARD_ROLE = "audit-log-collector"
    _OVERPRIV_SA = "audit-collector"

    # Core resources + realistic verb sets → a varied haystack with legit "broad" near-misses.
    _BENIGN_RESOURCES = [
        "pods", "services", "configmaps", "endpoints", "events", "secrets",
        "persistentvolumeclaims", "replicationcontrollers", "serviceaccounts",
        "resourcequotas", "limitranges", "podtemplates",
    ]
    _BENIGN_VERBSETS = [
        ["get", "list", "watch"], ["get", "list"], ["get", "watch"],
        ["create", "update", "patch"], ["list", "watch"], ["get"],
    ]
    _BENIGN_SUFFIX = ["reader", "viewer", "editor", "watcher", "manager", "auditor"]

    def _role_manifest(self, name: str, rules: list[dict]) -> dict:
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": name, "namespace": self.namespace},  # no label
            "rules": rules,
        }

    def _benign_roles(self, n_benign: int) -> list[dict]:
        """Deterministic benign Role set — same list is used for teardown-by-name."""
        roles = []
        for i in range(n_benign):
            res = self._BENIGN_RESOURCES[i % len(self._BENIGN_RESOURCES)]
            verbs = self._BENIGN_VERBSETS[i % len(self._BENIGN_VERBSETS)]
            name = f"{res}-{self._BENIGN_SUFFIX[i % len(self._BENIGN_SUFFIX)]}-{i}"
            roles.append(self._role_manifest(name, [{"apiGroups": [""], "resources": [res], "verbs": verbs}]))
        return roles

    def inject_wildcard_rbac(
        self,
        microservices: list[str] = None,
        wildcard_name: str = None,
        n_benign: int = None,
    ):
        """Grant one workload over-broad RBAC via a bound Role, hidden among many benign Roles.

        Difficulty = context/attention: react must scan a large heterogeneous pile of plausible
        Roles and spot the one with a wildcard verb; OPA flags it directly. Localizing the affected
        workload is a cross-object trace: Deployment -> serviceAccountName -> RoleBinding -> Role.
        """
        target = (microservices or ["user-service"])[0]
        wildcard_name = wildcard_name or self.WILDCARD_ROLE
        n_benign = self.N_BENIGN if n_benign is None else n_benign

        items = self._benign_roles(n_benign)
        # the one over-permissive Role: wildcard VERB on sensitive resources (not "* * *")
        items.append(self._role_manifest(
            wildcard_name,
            [{"apiGroups": [""], "resources": ["secrets", "configmaps"], "verbs": ["*"]}],
        ))
        # dedicated ServiceAccount + RoleBinding that actually grants it to that SA
        items.append({
            "apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": self._OVERPRIV_SA, "namespace": self.namespace},
        })
        items.append({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": f"{wildcard_name}-binding", "namespace": self.namespace},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": wildcard_name},
            "subjects": [{"kind": "ServiceAccount", "name": self._OVERPRIV_SA, "namespace": self.namespace}],
        })

        doc = {"apiVersion": "v1", "kind": "List", "items": items}
        out = self.kubectl.exec_command("kubectl apply -f -", input_data=json.dumps(doc))
        print(
            f"[security_misconfig] applied {n_benign} benign Roles + 1 over-permissive "
            f"('{wildcard_name}': verbs['*'] on secrets/configmaps) + SA/RoleBinding | "
            f"ns: {self.namespace}\n{out.strip().splitlines()[-1] if out.strip() else ''}"
        )
        # bind the target Deployment to the over-privileged SA
        patch = {"spec": {"template": {"spec": {"serviceAccountName": self._OVERPRIV_SA}}}}
        cmd = (
            f"kubectl patch deployment {target} -n {self.namespace} "
            f"--type=strategic -p '{json.dumps(patch)}'"
        )
        print(f"[security_misconfig] bound {target} to SA {self._OVERPRIV_SA}: "
              f"{self.kubectl.exec_command(cmd).strip()}")

    def recover_wildcard_rbac(
        self,
        microservices: list[str] = None,
        wildcard_name: str = None,
        n_benign: int = None,
        **_,
    ):
        target = (microservices or ["user-service"])[0]
        wildcard_name = wildcard_name or self.WILDCARD_ROLE
        n_benign = self.N_BENIGN if n_benign is None else n_benign
        # revert the Deployment's SA (null deletes the field → back to 'default')
        patch = {"spec": {"template": {"spec": {"serviceAccountName": None}}}}
        self.kubectl.exec_command(
            f"kubectl patch deployment {target} -n {self.namespace} "
            f"--type=strategic -p '{json.dumps(patch)}'"
        )
        # teardown by deterministic name (no label to grep)
        role_names = [r["metadata"]["name"] for r in self._benign_roles(n_benign)] + [wildcard_name]
        self.kubectl.exec_command(
            f"kubectl delete role {' '.join(role_names)} -n {self.namespace} --ignore-not-found"
        )
        self.kubectl.exec_command(
            f"kubectl delete rolebinding {wildcard_name}-binding -n {self.namespace} --ignore-not-found"
        )
        self.kubectl.exec_command(
            f"kubectl delete serviceaccount {self._OVERPRIV_SA} -n {self.namespace} --ignore-not-found"
        )
        print(f"[security_misconfig] recovered wildcard_rbac ({n_benign+1} Roles, SA, binding) | ns: {self.namespace}")

    # SM.4 - rbac_escalation (Tier 2, JUDGMENT candidate): invert rbac-escalation-primitives.rego.
    # Same structure as wildcard_rbac but the over-permission is a *subtle* escalation primitive
    # ('impersonate' on identities) instead of a glaring "* * *". No wildcard → the wildcard rule
    # does NOT fire; only the escalation-primitives policy catches it. The needle is not visually
    # anomalous — it reads like a plausible auth/delegation Role — so finding it requires JUDGMENT
    # (recognizing impersonate as escalation), not spotting a weird object.
    ESC_ROLE = "auth-delegator"
    _ESC_SA = "delegation-agent"

    def inject_rbac_escalation(
        self,
        microservices: list[str] = None,
        esc_name: str = None,
        n_benign: int = None,
    ):
        target = (microservices or ["user-service"])[0]
        esc_name = esc_name or self.ESC_ROLE
        n_benign = self.N_BENIGN if n_benign is None else n_benign

        items = self._benign_roles(n_benign)
        # the escalation Role: 'impersonate' on identities — no wildcard, looks benign.
        items.append(self._role_manifest(
            esc_name,
            [{"apiGroups": [""], "resources": ["serviceaccounts", "users", "groups"], "verbs": ["impersonate"]}],
        ))
        items.append({
            "apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": self._ESC_SA, "namespace": self.namespace},
        })
        items.append({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": f"{esc_name}-binding", "namespace": self.namespace},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": esc_name},
            "subjects": [{"kind": "ServiceAccount", "name": self._ESC_SA, "namespace": self.namespace}],
        })

        doc = {"apiVersion": "v1", "kind": "List", "items": items}
        out = self.kubectl.exec_command("kubectl apply -f -", input_data=json.dumps(doc))
        print(
            f"[security_misconfig] applied {n_benign} benign Roles + 1 escalation Role "
            f"('{esc_name}': impersonate on identities) + SA/RoleBinding | "
            f"ns: {self.namespace}\n{out.strip().splitlines()[-1] if out.strip() else ''}"
        )
        patch = {"spec": {"template": {"spec": {"serviceAccountName": self._ESC_SA}}}}
        cmd = (
            f"kubectl patch deployment {target} -n {self.namespace} "
            f"--type=strategic -p '{json.dumps(patch)}'"
        )
        print(f"[security_misconfig] bound {target} to SA {self._ESC_SA}: "
              f"{self.kubectl.exec_command(cmd).strip()}")

    def recover_rbac_escalation(
        self,
        microservices: list[str] = None,
        esc_name: str = None,
        n_benign: int = None,
        **_,
    ):
        target = (microservices or ["user-service"])[0]
        esc_name = esc_name or self.ESC_ROLE
        n_benign = self.N_BENIGN if n_benign is None else n_benign
        patch = {"spec": {"template": {"spec": {"serviceAccountName": None}}}}
        self.kubectl.exec_command(
            f"kubectl patch deployment {target} -n {self.namespace} "
            f"--type=strategic -p '{json.dumps(patch)}'"
        )
        role_names = [r["metadata"]["name"] for r in self._benign_roles(n_benign)] + [esc_name]
        self.kubectl.exec_command(
            f"kubectl delete role {' '.join(role_names)} -n {self.namespace} --ignore-not-found"
        )
        self.kubectl.exec_command(
            f"kubectl delete rolebinding {esc_name}-binding -n {self.namespace} --ignore-not-found"
        )
        self.kubectl.exec_command(
            f"kubectl delete serviceaccount {self._ESC_SA} -n {self.namespace} --ignore-not-found"
        )
        print(f"[security_misconfig] recovered rbac_escalation ({n_benign+1} Roles, SA, binding) | ns: {self.namespace}")


if __name__ == "__main__":
    namespace = "test-social-network"
    injector = SecurityMisconfigInjector(namespace)
    injector._inject(fault_type="privileged_container", microservices=["user-service"])
