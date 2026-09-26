#!/usr/bin/env python3
"""Build isolated physinif mutations and measure the real bridge classifier.

Run after `make ebpf` and generation of control/kern/tests/bpf_test.go.
Requires root or passwordless sudo, br_netfilter, clang, Go and taskset.
All source mutations and network/sysctl changes are confined to temporary
copies and test namespaces. No experimental flags enter production code.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-source", type=Path, help="earlier control/kern snapshot")
    parser.add_argument("--rounds", type=int, default=5, help="timing rounds; 0 runs only functional ablations")
    parser.add_argument("--benchtime", default="200ms")
    args = parser.parse_args()
    if args.rounds < 0:
        parser.error("--rounds must be nonnegative")
    root = Path(__file__).resolve().parent.parent
    temp_root = "/tmp/opencode" if Path("/tmp/opencode").is_dir() else None
    output = Path(tempfile.mkdtemp(prefix="physinif-ablation-", dir=temp_root))
    print(f"Results: {output}", flush=True)

    def run(command, log, expected_error=None):
        result = subprocess.run(command, cwd=root, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / log).write_text(result.stdout)
        if expected_error is None:
            if result.returncode:
                raise RuntimeError(f"{log}: {result.stdout}")
        elif result.returncode == 0 or expected_error not in result.stdout:
            raise RuntimeError(f"mutation was not detected as expected: {log}: {result.stdout}")
        return result.stdout

    # Each mutation removes one link in the provenance chain. Require a specific
    # assertion failure, so a verifier/build/privilege error cannot count as success.
    mutations = {
        "full": [],
        "no-read": [("tproxy.c", "is_wan ? 0 : skb_bridge_physinif(skb)", "0", 2)],
        "no-match": [("routing.h", "ctx->params->physinif == match_set->ifindex", "false", 1)],
        "no-zero-guard": [("routing.h", "if (match_set->ifindex &&", "if (", 1)],
        "no-cache-store": [("tproxy.c", "decision->physinif = result->physinif;", "decision->physinif = 0;", 1)],
        "no-cache-restore": [("tproxy.c", "result->physinif = decision->physinif;", "result->physinif = 0;", 1)],
        "no-handoff": [("tproxy.c", "routing_result->physinif = params.physinif;", "routing_result->physinif = 0;", 1)],
        # Reconstruct the original four-helper reader for repeatable comparisons
        # after the optimization, without relying on a historical checkout.
        "probe-read": [
            ("bridge.h", "struct skb_ext___dae_bridge *ext;", "struct skb_ext___dae_bridge *ext = NULL;", 1),
            ("bridge.h", "__u8 offset;", "__u8 active = 0, offset = 0;", 1),
            ("bridge.h", "if (!(skb->active_extensions & (1U << id)))", "if (bpf_core_read(&active, sizeof(active), &skb->active_extensions) || !(active & (1U << id)))", 1),
            ("bridge.h", "ext = skb->extensions;\n\tif (!ext)", "if (bpf_core_read(&ext, sizeof(ext), &skb->extensions) || !ext)", 1),
            ("bridge.h", "offset = ext->offset[id];\n\tif (!offset)", "if (bpf_core_read(&offset, sizeof(offset), &ext->offset[id]) || !offset)", 1),
        ],
    }
    expected = {"no-read": "want bridge=", "no-match": "want bridge=",
                "no-zero-guard": "want bridge=",
                "no-cache-store": "lost cached identity", "no-cache-restore": "lost handoff identity",
                "no-handoff": "lost handoff identity"}
    if args.baseline_source:
        mutations["baseline"] = []
    objects = {}
    for name, changes in mutations.items():
        source = args.baseline_source if name == "baseline" else root / "control/kern"
        directory = output / name
        shutil.copytree(source, directory)
        for file, old, new, count in changes:
            path = directory / file
            text = path.read_text()
            if text.count(old) != count:
                raise RuntimeError(f"stale mutation: {name}/{file}: {old}")
            path.write_text(text.replace(old, new))
        obj = directory / "ablation.o"
        run([os.environ.get("CLANG", "clang"), "-O2", "-g", "-target", "bpfel", "-mcpu=v1",
             "-Wall", "-Werror", "-c", str(directory / "tests/bpf_test.c"), "-o", str(obj)], f"{name}-compile.log")
        objects[name] = obj

    binary = output / "kern.test"
    run(["go", "test", "-c", "-tags", "dae_bpf_tests", "-o", str(binary), "./control/kern/tests"], "build.log")
    cpu = min(os.sched_getaffinity(0))
    prefix = ["taskset", "-c", str(cpu)] + ([] if os.geteuid() == 0 else ["sudo", "-n"])

    def test_command(name, *flags):
        return prefix + ["env", "GOMAXPROCS=1", f"DAE_BPF_TEST_OBJECT={objects[name]}", str(binary), *flags]

    for name in objects:
        run(test_command(name, "-test.run=^TestBridgePhysinif$", "-test.v"),
            f"{name}-functional.log", expected.get(name))
        print(f"{name}: {'detected' if name in expected else 'passed'}", flush=True)

    # Go overlay removes userspace identity propagation without editing the tree.
    source = root / "control/routing_input.go"
    text = source.read_text()
    old = "physinif: r.Physinif,"
    if text.count(old) != 1:
        raise RuntimeError("stale userspace propagation mutation")
    replacement = output / "routing_input.go"
    replacement.write_text(text.replace(old, "physinif: 0,"))
    overlay = output / "overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(replacement)}}))
    run(["go", "test", "-overlay", str(overlay), "./control", "-run", "^TestDestinationRoutingPreservesIdentityAndUsesNewContext$"],
        "no-userspace-functional.log", "FAIL: TestDestinationRoutingPreservesIdentityAndUsesNewContext")
    print("no-userspace: detected", flush=True)

    samples = {}
    variants = [name for name in ("baseline" if args.baseline_source else "probe-read", "no-read", "full") if name in objects]
    for round_index in range(args.rounds):
        for name in variants[::1 if round_index % 2 == 0 else -1]:
            text = run(test_command(name, "-test.run=^$", "-test.bench=^BenchmarkBridgePhysinif$",
                                    f"-test.benchtime={args.benchtime}"), f"{name}-bench-{round_index}.log")
            found = 0
            for line in text.splitlines():
                metric = re.search(r"([0-9.]+)\s+bpf-ns/pkt", line)
                if metric:
                    scenario = re.sub(r"-\d+$", "", line.split()[0].removeprefix("BenchmarkBridgePhysinif/"))
                    samples.setdefault(name, {}).setdefault(scenario, []).append(float(metric[1]))
                    found += 1
            if found != 4:
                raise RuntimeError(f"missing benchmark samples: {name}: {text}")
    summary = {"kernel": os.uname().release, "cpu": cpu, "rounds": args.rounds,
               "samples_bpf_ns_per_packet": samples,
               "medians": {name: {case: statistics.median(values) for case, values in cases.items()}
                           for name, cases in samples.items()}}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
