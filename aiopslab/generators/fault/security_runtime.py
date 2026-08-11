# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Security-RUNTIME fault injectors (Falco-visible behavioral drift).

Where SecurityMisconfigInjector changes declarative *state* (OPA territory), this injector
produces malicious runtime *behavior* — a syscall-level event that leaves NO spec change and NO
telemetry symptom. The only witness is a runtime monitor (Falco). This is the regime where the
tool is load-bearing for accuracy: a shell agent inspecting specs/logs/metrics is blind, because
there is nothing there to see.

Slice scope: `rogue_shell` — a rogue process inside a running app pod repeatedly reading a
sensitive credential file (/etc/shadow). Fires Falco's default "Read sensitive file untrusted"
rule (MITRE T1555, Credential Access). Non-breaking: the app keeps serving.

Design note (persistent vs one-shot): the rogue process runs in a background loop so alerts stay
fresh for the whole episode (a Falco-equipped agent can query any reasonable window and still see
it). It's a background process inside ONE pod, so base's normal investigation (logs/metrics/specs)
won't surface it — base would have to `exec ps` the exact compromised pod among many.
"""

import subprocess

from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.base import FaultInjector

# marker embedded in the rogue command so recovery can find & kill it
_ROGUE_MARKER = "cat /etc/shadow"
# marker on every host-side loop's cmdline (transient attack + benign twins) so recovery/cleanup
# can pkill them all with one pattern. Kept as a stable string for the run-command sweep's pkill.
_HOST_LOOP_MARKER = "ARRIVE_HOST_LOOP"


class SecurityRuntimeInjector(FaultInjector):
    def __init__(self, namespace: str):
        super().__init__(namespace)
        self.namespace = namespace
        self.kubectl = KubeCtl()

    def _first_pod(self, service: str) -> str | None:
        """Name of a running pod for `service` (DeathStarBench pods are '<service>-<hash>')."""
        out = self.kubectl.exec_command(
            f"kubectl get pods -n {self.namespace} -o name --field-selector=status.phase=Running"
        )
        for line in out.splitlines():
            name = line.strip().removeprefix("pod/")
            if name.startswith(service):
                return name
        return None

    # SR.1 - rogue_shell: rogue process reads /etc/shadow in a loop (Falco: Read sensitive file)
    def inject_rogue_shell(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            # Background subshell loop (no setsid/nohup dependency); survives exec-session exit,
            # keeps firing Falco every ~12s for the episode. stdin/out detached so exec returns.
            inner = f"(while true; do {_ROGUE_MARKER} >/dev/null 2>&1; sleep 12; done) </dev/null >/dev/null 2>&1 &"
            cmd = f"kubectl exec {pod} -n {self.namespace} -- sh -c '{inner}'"
            out = self.kubectl.exec_command(cmd)
            print(f"[security_runtime] rogue process reading /etc/shadow in pod {pod} "
                  f"({service}) | ns: {self.namespace} {out.strip()}")

    def recover_rogue_shell(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                continue
            # best-effort kill; namespace teardown also removes it
            cmd = f"kubectl exec {pod} -n {self.namespace} -- sh -c 'pkill -f \"{_ROGUE_MARKER}\" 2>/dev/null; true'"
            self.kubectl.exec_command(cmd)
            print(f"[security_runtime] killed rogue process in pod {pod} ({service}) | ns: {self.namespace}")

    # ---- shared host-side loop (used by the transient attack AND the benign twins) ----
    # A background loop ON THE HOST periodically `kubectl exec`s a ONE-SHOT command that exits at
    # once, so nothing lingers in the pod for `ps` to find — only Falco's log records the activity.
    # The action is what differs: a malicious read (/etc/shadow) vs a benign one (admin diagnostics,
    # app reading its own token). Self-terminating on pod/cluster disappearance; bounded kubectl.
    def _start_host_loop(self, pod: str, action: str):
        check = f"kubectl get pod {pod} -n {self.namespace} --request-timeout=5s >/dev/null 2>&1"
        act = f"kubectl exec {pod} -n {self.namespace} --request-timeout=20s -- {action} >/dev/null 2>&1"
        script = f": {_HOST_LOOP_MARKER} {pod}; while {check}; do {act}; sleep 8; done"
        subprocess.Popen(
            ["sh", "-c", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def _stop_host_loops(self):
        subprocess.run(
            f"pkill -f '{_HOST_LOOP_MARKER}'", shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    # SR.2 - transient_read: TRANSIENT credential theft — the clean "coverage" fault (base blind).
    def inject_transient_read(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            self._start_host_loop(pod, "cat /etc/shadow")
            print(f"[security_runtime] MALICIOUS transient /etc/shadow reads against pod {pod} "
                  f"({service}) via host loop | ns: {self.namespace}")

    def recover_transient_read(self, microservices: list[str] = None):
        self._stop_host_loops()
        print(f"[security_runtime] stopped host loop [{_HOST_LOOP_MARKER}] | ns: {self.namespace}")

    # SR.3 - benign_admin_shell (BENIGN TWIN, detected=False): an operator debug session that fires
    # the same intrusion-shaped Falco rules ("Terminal shell in container", exec activity) as an
    # attacker shell — but only runs harmless diagnostics. RQ2 specificity test: does the agent tell
    # an admin shell from an attacker shell, or cry wolf on every shell-in-container alert?
    def inject_benign_admin_shell(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            self._start_host_loop(pod, "sh -c 'id; uname -a; ls -la /tmp; cat /etc/os-release; df -h'")
            print(f"[security_runtime] BENIGN admin debug shell (diagnostics) on pod {pod} "
                  f"({service}) via host loop | ns: {self.namespace}")

    def recover_benign_admin_shell(self, microservices: list[str] = None):
        self._stop_host_loops()

    # SR.4 - benign_secret_read (BENIGN TWIN, detected=False): the workload reading its OWN mounted
    # ServiceAccount token — exactly what apps do to authenticate to the API. Looks like credential
    # access (T1552-shaped) but is legitimate self-access. RQ2: does the agent distinguish reading
    # one's own token (benign) from stealing /etc/shadow (attack)?
    def inject_benign_secret_read(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            self._start_host_loop(pod, "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
            print(f"[security_runtime] BENIGN own-SA-token read on pod {pod} "
                  f"({service}) via host loop | ns: {self.namespace}")

    def recover_benign_secret_read(self, microservices: list[str] = None):
        self._stop_host_loops()


if __name__ == "__main__":
    injector = SecurityRuntimeInjector("test-social-network")
    injector._inject(fault_type="rogue_shell", microservices=["user-service"])
