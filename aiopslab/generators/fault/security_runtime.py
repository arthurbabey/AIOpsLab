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

RQ2 matched twins (one attack, two benign look-alikes) — the specificity test
-----------------------------------------------------------------------------
A benign twin only tests specificity if it fires the SAME Falco rule as an attack; otherwise the
agent dismisses it by rule-type and never has to reason about context. All three fire
"Terminal shell in container", same priority, same pod:

    attacker_shell      TTY shell -> recon + `cat /etc/shadow`          (detected=True)
                        fires "Terminal shell in container" AND "Read sensitive file untrusted"
    benign_admin_shell  TTY shell -> harmless diagnostics only          (detected=False)
                        fires "Terminal shell in container" ONLY
    benign_secret_read  TTY shell -> reads its OWN mounted SA token     (detected=False)
                        fires "Terminal shell in container" ONLY

The discriminator is what the shell *did* — exactly the SOC judgement: a shell alone is not a
compromise, a shell plus *someone else's* credentials is. An agent that flags every
"Terminal shell in container" alert now produces a visible false positive on both twins.

The two twins sit at different difficulties, deliberately: `benign_admin_shell` is anodyne
(`uname`, `df`), so "no credential access" is easy to see; `benign_secret_read` DOES touch a
credential, just its own, so the agent must distinguish self-access from theft rather than just
checking whether a secret was touched at all.

TTY mechanics (why the twin used to fire nothing): Falco's "Terminal shell in container" requires
`proc.tty != 0`, and `kubectl exec -t` SILENTLY disables the TTY when its stdin is not a terminal
(kubectl's SetupTTY drops `-t` if `-i` is absent, or if stdin is not a tty). So the loop must pass
`-i -t` AND own a real PTY — see `_start_host_loop(tty=True)`. Because that is easy to get wrong
and fails *silently*, every runtime injector now verifies against Falco that its expected rules
actually fired, and raises if not (a mislabelled episode is worse than a failed one).
"""

import json
import os
import pty
import subprocess
import time

from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.base import FaultInjector

# marker embedded in the rogue command so recovery can find & kill it
_ROGUE_MARKER = "cat /etc/shadow"
# marker on every host-side loop's cmdline (transient attack + benign twins) so recovery/cleanup
# can pkill them all with one pattern. Kept as a stable string for the run-command sweep's pkill.
_HOST_LOOP_MARKER = "ARRIVE_HOST_LOOP"

# Where Falco lives, for post-injection verification (mirrors mcp_servers/falco.py).
FALCO_NAMESPACE = os.getenv("FALCO_NAMESPACE", "falco")
FALCO_SELECTOR = os.getenv("FALCO_SELECTOR", "app.kubernetes.io/name=falco")
# Set ARRIVE_VERIFY_INJECTION=0 to downgrade verification failures to a warning (debugging only —
# runs with it disabled must not be used as results).
_VERIFY = os.getenv("ARRIVE_VERIFY_INJECTION", "1") != "0"

# PTY master fds kept open for the lifetime of the process: closing the master makes the slave
# return EIO, which would kill the loop's kubectl streams. One fd per TTY injection; released by
# _stop_host_loops().
_PTY_MASTERS: list[int] = []


class FaultVerificationError(RuntimeError):
    """An injector ran but Falco did not observe the behaviour it is defined by.

    Raised (not warned) on purpose: the ground truth asserts these rules fired, so continuing
    would produce a mislabelled episode — a silent data-quality failure that reads as a model
    failure downstream.
    """


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
            self._verify_falco(["Read sensitive file untrusted"], pod)

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
    def _start_host_loop(self, pod: str, action: str, tty: bool = False):
        """Loop a one-shot `kubectl exec` against `pod` every 8s.

        tty=True allocates a real PTY for the loop's stdin and execs with `-i -t`, so the process
        inside the container gets a controlling terminal (`proc.tty != 0`) and Falco's
        "Terminal shell in container" rule can fire. Without a PTY, kubectl quietly drops `-t` and
        the rule never fires — the defect this pair exists to avoid.

        Each exec is wrapped in `timeout 20` because `kubectl exec -i` can block waiting for stdin
        EOF; `--request-timeout` does not bound an upgraded stream.
        """
        check = f"kubectl get pod {pod} -n {self.namespace} --request-timeout=5s >/dev/null 2>&1"
        flags = "-i -t " if tty else ""
        act = (
            f"timeout 20 kubectl exec {flags}{pod} -n {self.namespace} "
            f"-- {action} >/dev/null 2>&1"
        )
        script = f": {_HOST_LOOP_MARKER} {pod}; while {check}; do {act}; sleep 8; done"

        stdin = subprocess.DEVNULL
        slave = None
        if tty:
            master, slave = pty.openpty()
            _PTY_MASTERS.append(master)  # held open on purpose; see module docstring
            stdin = slave

        subprocess.Popen(
            ["sh", "-c", script],
            stdin=stdin,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        if slave is not None:
            os.close(slave)  # the child holds its own copy

    def _stop_host_loops(self):
        subprocess.run(
            f"pkill -f '{_HOST_LOOP_MARKER}'", shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        while _PTY_MASTERS:
            try:
                os.close(_PTY_MASTERS.pop())
            except OSError:
                pass

    # ---- post-injection verification against Falco ----

    def _falco_rules_fired(self, since_seconds: int, pod: str | None = None) -> set[str]:
        """Distinct Falco rule names observed in the last `since_seconds`, optionally for one pod."""
        try:
            out = subprocess.run(
                ["kubectl", "logs", "-n", FALCO_NAMESPACE, "-l", FALCO_SELECTOR,
                 f"--since={since_seconds}s", "--tail=-1", "--prefix=false"],
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            return set()
        rules: set[str] = set()
        for line in out.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule = alert.get("rule")
            if not rule:
                continue
            if pod:
                observed = (alert.get("output_fields") or {}).get("k8s.pod.name")
                if observed and pod not in observed:
                    continue
            rules.add(rule)
        return rules

    def _verify_falco(self, expected: list[str], pod: str, attempts: int = 4, delay: int = 8):
        """Block until Falco has reported every rule in `expected` for `pod`, else raise.

        The loops fire every 8s, so a few short waits are enough. Failure means the injected
        behaviour is not observable — the episode's ground truth would be a lie.
        """
        waited = 0
        for _ in range(attempts):
            time.sleep(delay)
            waited += delay
            fired = self._falco_rules_fired(since_seconds=waited + 30, pod=pod)
            missing = [r for r in expected if r not in fired]
            if not missing:
                print(f"[security_runtime] verified Falco rules {expected} on pod {pod}")
                return
        msg = (
            f"[security_runtime] VERIFICATION FAILED for pod {pod}: expected Falco rule(s) "
            f"{missing} did not fire within {waited}s. Observed: {sorted(fired) or 'none'}. "
            "Common causes: Falco not installed/ready; the container lacks /etc/shadow or a shell; "
            "no PTY was allocated (the 'Terminal shell in container' rule needs proc.tty != 0)."
        )
        if _VERIFY:
            raise FaultVerificationError(msg)
        print(f"[warn] {msg} (ARRIVE_VERIFY_INJECTION=0 — continuing with an UNVERIFIED episode)")

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
            self._verify_falco(["Read sensitive file untrusted"], pod)

    def recover_transient_read(self, microservices: list[str] = None):
        self._stop_host_loops()
        print(f"[security_runtime] stopped host loop [{_HOST_LOOP_MARKER}] | ns: {self.namespace}")

    # SR.3 - attacker_shell (ATTACK, detected=True): the malicious half of the RQ2 matched pair.
    # An interactive (TTY) shell in the app container that does recon AND steals credentials.
    # Fires BOTH "Terminal shell in container" (shared with the benign twin) and "Read sensitive
    # file untrusted" (unique to the attack) — so the shell alert alone is NOT sufficient evidence,
    # and the agent has to look at what the shell did. Non-breaking: every command is read-only.
    _ATTACKER_SHELL_RULES = ["Terminal shell in container", "Read sensitive file untrusted"]
    _BENIGN_SHELL_RULES = ["Terminal shell in container"]

    def inject_attacker_shell(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            # recon + credential theft; `sh -c` keeps the spawned process a shell_binary with
            # runc as its parent, which is what "Terminal shell in container" matches on.
            self._start_host_loop(
                pod,
                "sh -c 'id; hostname; cat /etc/shadow; ls -la /var/run/secrets/kubernetes.io/serviceaccount'",
                tty=True,
            )
            print(f"[security_runtime] ATTACKER interactive shell (recon + /etc/shadow) on pod {pod} "
                  f"({service}) via host loop | ns: {self.namespace}")
            self._verify_falco(self._ATTACKER_SHELL_RULES, pod)

    def recover_attacker_shell(self, microservices: list[str] = None):
        self._stop_host_loops()
        print(f"[security_runtime] stopped host loop [{_HOST_LOOP_MARKER}] | ns: {self.namespace}")

    # SR.4 - benign_admin_shell (BENIGN TWIN of attacker_shell, detected=False): an operator debug
    # session — an interactive (TTY) shell running harmless diagnostics. Fires exactly ONE of the
    # attack's two rules: "Terminal shell in container", identical rule and priority, same pod.
    # It does NOT touch a sensitive file, so "Read sensitive file untrusted" stays silent.
    # RQ2 specificity: an agent that treats any shell-in-container alert as an intrusion produces a
    # false positive here; one that checks what the shell actually did gets both halves right.
    def inject_benign_admin_shell(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            self._start_host_loop(
                pod,
                "sh -c 'id; uname -a; ls -la /tmp; cat /etc/os-release; df -h'",
                tty=True,
            )
            print(f"[security_runtime] BENIGN admin debug shell (diagnostics) on pod {pod} "
                  f"({service}) via host loop | ns: {self.namespace}")
            # The twin is only a twin if it really fires the shared rule — verify, don't assume.
            self._verify_falco(self._BENIGN_SHELL_RULES, pod)

    def recover_benign_admin_shell(self, microservices: list[str] = None):
        self._stop_host_loops()

    # SR.5 - benign_secret_read (BENIGN TWIN of attacker_shell, detected=False): an operator/workload
    # session that legitimately touches its OWN credentials — the SA token mounted into the pod.
    #
    # Why it is delivered through a TTY shell: Falco's `sensitive_files` macro covers /etc/shadow,
    # /etc/sudoers and /etc/pam.* — NOT /var/run/secrets/... — so reading the token fires no rule
    # of its own. Read alone (the original form of this injector) it therefore fired NOTHING and
    # was behaviourally a second no-op rather than a specificity test. Running it inside an
    # interactive shell makes it fire "Terminal shell in container", the SAME rule (same priority,
    # same pod) as the attack half `attacker_shell` — so it becomes a real twin.
    #
    # This makes it a HARDER twin than benign_admin_shell: both halves of this pair now show
    # "shell + credential access", and the discriminator is WHOSE credentials — the attack reads
    # /etc/shadow (fires "Read sensitive file untrusted" on top), this reads only the pod's own
    # mounted token. An agent that flags "shell touched a credential" produces a false positive here.
    #
    # Note the rule no longer depends on the token being readable: the shell itself is what fires.
    def inject_benign_secret_read(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            self._start_host_loop(
                pod,
                "sh -c 'id; cat /var/run/secrets/kubernetes.io/serviceaccount/token; "
                "ls -la /var/run/secrets/kubernetes.io/serviceaccount'",
                tty=True,
            )
            print(f"[security_runtime] BENIGN own-SA-token read (interactive session) on pod {pod} "
                  f"({service}) via host loop | ns: {self.namespace}")
            # Same verification contract as every other runtime injector: a twin that does not fire
            # the shared rule is not a twin, and a silently-silent twin is a mislabelled episode.
            self._verify_falco(self._BENIGN_SHELL_RULES, pod)

    def recover_benign_secret_read(self, microservices: list[str] = None):
        self._stop_host_loops()


if __name__ == "__main__":
    injector = SecurityRuntimeInjector("test-social-network")
    injector._inject(fault_type="rogue_shell", microservices=["user-service"])
