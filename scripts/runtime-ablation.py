#!/usr/bin/env python3
"""Ablate reload ownership and handoff mechanisms in isolated copies.

Run after generating production and kernel-test BPF objects. Requires Go,
clang and passwordless sudo. --baseline is a source snapshot containing control/
from before simplification. Results and generated mutations stay in /tmp/opencode;
no experiment switches enter production code.
"""

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import tempfile
from pathlib import Path


def replace(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"stale mutation ({text.count(old)} matches): {old}")
    return text.replace(old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if args.rounds < 0:
        parser.error("--rounds must be nonnegative")
    root = Path(__file__).resolve().parent.parent
    output = Path(tempfile.mkdtemp(prefix="runtime-ablation-", dir="/tmp/opencode"))
    print(f"Results: {output}", flush=True)

    def run(command, name, failure=None):
        result = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / f"{name}.log").write_text(result.stdout)
        if failure is None:
            if result.returncode:
                raise RuntimeError(f"{name}: {result.stdout}")
        elif result.returncode == 0 or failure not in result.stdout:
            raise RuntimeError(f"mutation did not fail the expected assertion: {name}: {result.stdout}")
        return result.stdout

    def build(name, sources, package="./control", tags="trace,dae_splice"):
        directory = output / name
        directory.mkdir()
        overlay = {}
        for path, text in sources.items():
            dest = directory / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text)
            overlay[str(root / path)] = str(dest)
        manifest = directory / "overlay.json"
        manifest.write_text(json.dumps({"Replace": overlay}))
        binary = directory / "tests"
        run(["go", "test", "-c", "-tags", tags, "-overlay", str(manifest), "-o", str(binary), package], name + "-build")
        return binary

    cpu = min(os.sched_getaffinity(0))
    prefix = ([] if os.geteuid() == 0 else ["sudo", "-n"]) + ["unshare", "--net", "bash", "-c",
        'ip link set lo up && exec "$@"', "runtime-ablation", "taskset", "-c", str(cpu), "env", "GOMAXPROCS=1"]
    current = lambda path: (root / path).read_text()
    variants = {"simplified": {}}
    if args.baseline:
        baseline = {str(p.relative_to(args.baseline)): p.read_text() for directory in ("control", "component/outbound")
                    for p in (args.baseline / directory).glob("*.go") if not p.name.startswith("bpf_bpf")}
        # The same benchmark and late-membership assertion run in every variant.
        baseline["control/runtime_benchmark_test.go"] = current("control/runtime_benchmark_test.go").replace("c.restoreRuntimeSettings(true)", "c.refreshKernelSettings()")
        variants["baseline"] = baseline
        direct = dict(baseline)
        for path in ("control/control_plane_ingress.go", "control/ingress_test.go", "control/shutdown_test.go"):
            direct[path] = current(path)
        direct["control/control_plane_ingress.go"] = direct["control/control_plane_ingress.go"].replace("src, dst, unix.IPPROTO_TCP)", "src, dst, unix.IPPROTO_TCP, true)").replace("src, dst, unix.IPPROTO_UDP)", "src, dst, unix.IPPROTO_UDP, false)")
        text = baseline["control/runtime.go"]
        text = replace(text, "ingress        *controlPlaneIngress", "ingress        sync.WaitGroup")
        text = replace(text, "listener, ingress := r.listener, r.ingress", "listener := r.listener")
        text = replace(text, """if ingress != nil {
			r.closeErr = errors.Join(r.closeErr, ingress.close())
			ingress.loops.Wait()
		}""", "r.ingress.Wait()")
        direct["control/runtime.go"] = text
        variants["direct-listener"] = direct
        targeted = dict(baseline)
        targeted["control/runtime.go"] = replace(baseline["control/runtime.go"],
            "return c.routingMatcherBuilder.BuildKernspace()", "return nil")
        text = baseline["control/control_plane_lifecycle.go"]
        text = replace(text, "\tc.kernelActive = true\n", "")
        text = replace(text, "return c.core.publishOutboundConnectivity()", "c.kernelActive = true\n\treturn c.core.publishOutboundConnectivity()")
        targeted["control/control_plane_lifecycle.go"] = text
        targeted["control/runtime_settings.go"] = replace(baseline["control/runtime_settings.go"],
            "SetClientMembers(c.routingMatcher, name, members, false)", "SetClientMembers(c.routingMatcher, name, members, c.kernelActive)")
        variants["targeted-refresh"] = targeted

    binaries = {}
    functional = "Test(PreparedGenerationRefreshesLatestKernelMembership|ServeReportsIngressFailure|RuntimeTCPHandoffAdmission|RuntimeCloseJoinsIngress|RuntimeListenerUsesSockmapCompatibleTCP|ShutdownResetsQueuedTCPBeforeDetachingKernel)$"
    for name, sources in variants.items():
        binary = build(name, sources)
        binaries[name] = binary
        run(prefix + [str(binary), f"-test.run=^({functional})", "-test.timeout=90s"], name + "-functional")
        print(f"{name}: functional PASS", flush=True)

    # Require a semantic assertion failure, not a build/verifier/permission error.
    removals = {
        "no-late-settings": ("control/runtime_settings.go", "members, c.kernelReady)", "members, false)", "./control", "^TestPreparedGenerationRefreshesLatestKernelMembership$", "kernel verdict=4294967295"),
        "wrong-generation": ("control/control_plane_ingress.go", "if c := r.planes[result.Generation];", "if c := r.current;", "./control", "^TestRuntimeTCPHandoffAdmission/queued", "wrong generation or route"),
        "no-expiry": ("control/routing_input.go", "if int32(handoff.Expires-", "if false && int32(handoff.Expires-", "./control", "^TestRuntimeTCPHandoffAdmission/expired", "admitted an invalid generation"),
        "no-consume": ("control/routing_input.go", "m.LookupAndDelete(&tuples, &handoff)", "m.Lookup(&tuples, &handoff)", "./control", "^TestRuntimeTCPHandoffAdmission/queued", "handoff was not consumed"),
        "no-lease-forwarding": ("component/outbound/connection_policy.go", "return p.successor.inheritedConnectionLease(network, fallback, p.networks[network.Index()].selected)", "return nil", "./component/outbound", "^TestReloadOwnsLateSetupPolicyLeases$", "late setup escaped current policy ownership"),
        "no-close-barrier": ("control/tcp_lifecycle.go", "\t\t<-done", "\t\t_ = done", "./control", "^TestShutdownInterruptsTrafficBeforeJoiningStateUsers$", "kernel state released before accepted TCP socket closed"),
    }
    for name, (path, old, new, package, test, failure) in removals.items():
        binary = build(name, {path: replace(current(path), old, new)}, package)
        run(prefix + [str(binary), "-test.run=" + test, "-test.timeout=30s"], name + "-functional", failure)
        print(f"{name}: required (mutation detected)", flush=True)

    kernel_binary = build("kernel-tests", {}, "./control/kern/tests", "dae_bpf_tests")
    kernel_variants = {
        "kernel-full": (None, None, "TestReload(PendingSYNAndConsumedHandoff|InvalidatesUnboundUDPCache)$", None),
        "no-syn-handoff": ("if (pending && pending->syn_seq", "if (false && pending && pending->syn_seq", "TestReloadPendingSYNAndConsumedHandoff$", "TCP verdict=2"),
        "no-flow-state": ("return bpf_map_update_elem(&tcp_flow_map, key, &flow, BPF_ANY);", "return 0;", "TestReloadPendingSYNAndConsumedHandoff$", "TCP verdict=4294967295"),
        "no-udp-generation": ("(check_generation && value->result.generation != routing_generation)", "false", "TestReloadInvalidatesUnboundUDPCache$", "UDP verdict=4294967295"),
    }
    for name, (old, new, test, failure) in kernel_variants.items():
        directory = output / name
        shutil.copytree(root / "control/kern", directory)
        if old is not None:
            (directory / "tproxy.c").write_text(replace((directory / "tproxy.c").read_text(), old, new))
        obj = directory / "variant.o"
        run(["clang", "-O2", "-g", "-target", "bpfel", "-mcpu=v1", "-Wall", "-Werror", "-c", str(directory / "tests/bpf_test.c"), "-o", str(obj)], name + "-compile")
        run(prefix + [f"DAE_BPF_TEST_OBJECT={obj}", str(kernel_binary), "-test.run=^" + test, "-test.timeout=60s"], name + "-functional", failure)
        print(f"{name}: {'required (mutation detected)' if failure else 'PASS'}", flush=True)

    samples = {}
    for i in range(args.rounds):
        for name in list(binaries)[::1 if i % 2 == 0 else -1]:
            text = run(prefix + [str(binaries[name]), "-test.run=^$", "-test.bench=^BenchmarkRuntime(KernelRefresh|Ingress)$", "-test.benchtime=100x"], f"{name}-bench-{i}")
            for line in text.splitlines():
                if not line.startswith("BenchmarkRuntime"):
                    continue
                case = re.sub(r"-\d+$", "", line.split()[0])
                metrics = {unit: float(value) for value, unit in re.findall(r"([0-9.]+)\s+(ns/op|B/op|allocs/op|extra-fds)", line)}
                samples.setdefault(name, {}).setdefault(case, []).append(metrics)
    summary = {"kernel": os.uname().release, "cpu": cpu, "rounds": args.rounds, "samples": samples,
        "medians": {name: {case: {unit: statistics.median(x[unit] for x in values) for unit in values[0]}
            for case, values in cases.items()} for name, cases in samples.items()}}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary["medians"], indent=2), flush=True)


if __name__ == "__main__":
    main()
