#!/usr/bin/env python3
"""Ablate entry DNS/egress checks and benchmark discovery using Go overlays.

Requires Go and root or passwordless sudo for isolated socket/netns tests.
Only temporary copies are mutated; no experiment flags enter production code.
The controlled-delay benchmark is a scheduling model, not Internet DNS latency.
"""

import argparse
import hashlib
import json
import os
import re
import statistics
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("egress", "loopback-dns"), default="egress")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--benchtime", default="100ms")
    parser.add_argument("--baseline-source", type=Path, help="earlier component/outbound snapshot; egress suite timing only")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.rounds < 0:
        parser.error("--rounds must be nonnegative")
    if args.baseline_source and args.suite != "egress":
        parser.error("--baseline-source is for the egress suite; loopback-dns includes before-cleanup")
    root = Path(__file__).resolve().parent.parent
    output = args.output or Path(tempfile.mkdtemp(prefix="entry-egress-ablation-", dir="/tmp/opencode"))
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve()
    env = dict(os.environ, GOMAXPROCS="4")
    privilege = [] if os.geteuid() == 0 else ["sudo", "-n"]
    print(f"Results: {output}", flush=True)

    def run(command, log, expected=None):
        result = subprocess.run(command, cwd=root, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        (output / log).write_text(result.stdout)
        if expected is None:
            if result.returncode:
                raise RuntimeError(f"{log}: {result.stdout}")
        elif result.returncode == 0 or expected not in result.stdout:
            raise RuntimeError(f"mutation not detected by the expected assertion: {log}: {result.stdout}")
        return result.stdout

    discovery = "component/outbound/entry_discovery.go"
    families = "component/outbound/entry_families.go"
    label = "component/outbound/entry_dialer.go"
    socket = "third_party/outbound/protocol/direct/dialer.go"
    source_files = [discovery, families, label, socket]
    tests = "^(TestEntryVariantsRequireDNSAndLocalFamily|TestEntryDiscoveryOnRealLocalRoute|TestEntryFamilyRouteAndInterface|TestEntryDiscoveryCacheIsolation|TestEntryDiscoveryCanceledBeforeStart|TestEntryVariantLabelsAndIdentity|TestEntrySockets|TestEntryDNSBindingAndFamilyRecovery|TestQUICProtocolsUseEntryResolverOnReconnect)$"
    benchmark = "BenchmarkEntryDiscovery"
    benchmark_cases = 6
    timing_variants = ["before", "full", "serial", "unbounded", "no-dedup", "no-literal-mask-cache"]
    # Each correctness variant removes just one guard. A build/privilege failure
    # must never count as detecting a mutation: require its assertion text.
    mutations = {
        "full": [],
        "assume-dual-dns": [(families, "\tvar families uint8\n", '\taddresses = append(addresses, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"))\n\tvar families uint8\n')],
        "no-local-gate": [(families, "families&family == 0 && usable(address, p.effectiveMark(option), p.Entry.Interface)", "families&family == 0")],
        "no-route-interface": [(families, "Mark: mark, Oif: iface", 'Mark: mark, Oif: ""')],
        "no-route-mark": [(families, "Mark: mark, Oif: iface", "Mark: 0, Oif: iface")],
        "no-source-ownership": [(families, "addr.IP.Equal(route.Src) && addr.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) == 0", "addr.IP != nil")],
        "no-cache-interface": [(discovery, "host: entryHostname(path.Nodes[0].Property.Address), iface: path.Entry.Interface", "host: entryHostname(path.Nodes[0].Property.Address)")],
        "no-cache-mark": [(discovery, "key.mark, key.markSet = *path.Entry.Mark, true", "key.mark, key.markSet = 0, false")],
        "label-single-stack": [(label, "if p.showIPVersion {", "if p.IPVersion != 0 {")],
        "no-socket-mark": [(socket, "\t\t\tif option.Mark != 0 {", "\t\t\tif false {")],
        "no-socket-interface": [(socket, '\t\t\tif option.Interface != "" {', "\t\t\tif false {")],
        "serial": [(discovery, "maxConcurrentEntryLookups = 8", "maxConcurrentEntryLookups = 1")],
        "unbounded": [(discovery, "min(maxConcurrentEntryLookups, len(entries))", "len(entries)")],
        "no-dedup": [(discovery, "entry := cache[key]", "var entry *entryDiscovery")],
        "no-literal-mask-cache": [
            (discovery, "entry.families &= entryHostFamilies(entry.key.host)", "entry.families &= allFamilies"),
            (discovery, "mask := results[i].families", "mask := results[i].families & entryAddressFamilies(path.Nodes[0].Property.Address)"),
        ],
    }
    expected = {
        "assume-dual-dns": "created families = [4 6], want [4]",
        "no-local-gate": "created families = [4 6], want [4]",
        "no-route-interface": '2001:db8:6::2 on "wan4" usable = true, want false',
        "no-route-mark": "family discovery ignored the mark's policy-routing rule",
        "no-source-ownership": '2001:db8:4::2 on "wan4" usable = true, want false',
        "no-cache-interface": "entry cache crossed mark/interface boundaries",
        "no-cache-mark": "entry cache crossed mark/interface boundaries",
        "label-single-stack": "single/dual-stack display mismatch",
        "no-socket-mark": "SO_MARK =",
        "no-socket-interface": "SO_BINDTODEVICE =",
    }
    if args.suite == "loopback-dns":
        bootstrap = "common/netutils/resolver.go"
        parse_guard = (label, "server, _ := netip.ParseAddrPort(address)\n\t\tif server.Addr().IsLoopback() {",
                       "server, err := netip.ParseAddrPort(address)\n\t\tif err == nil && server.Addr().IsLoopback() {")
        unmap = (label, "server.Addr().IsLoopback()", "server.Addr().Unmap().IsLoopback()")
        mutable_bootstrap = (bootstrap, '''\tresolver := &net.Resolver{PreferGo: true, Dial: dial}
\tif address.IsValid() {
\t\tserver = address.String()
\t\tresolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
\t\t\treturn dial(ctx, network, server)
\t\t}
\t}
\treturn resolver, nil''', "\treturn newInternalResolver(address, dial).Bootstrap, nil")
        mutations = {
            "full": [],
            "no-loopback-exception": [(label, "if server.Addr().IsLoopback() {", "if false && server.Addr().IsLoopback() {")],
            "no-local-dns-mark": [(label, "direct.Option{Mark: socket.Mark}", "direct.Option{}")],
            "no-external-dns-bind": [(label, "dns := direct.NewDirectDialer(socket)", 'socket.Interface = ""\n\tdns := direct.NewDirectDialer(socket)')],
            "udp-only-loopback": [(label, "if server.Addr().IsLoopback() {", 'if network == "udp" && server.Addr().IsLoopback() {')],
            "private-dns-unbound": [(label, "if server.Addr().IsLoopback() {", "if server.Addr().IsLoopback() || server.Addr().IsPrivate() {")],
            "ipv4-only-loopback": [(label, "if server.Addr().IsLoopback() {", "if server.Addr().Is4() && server.Addr().IsLoopback() {")],
            "classify-configured-server": [(label, "netip.ParseAddrPort(address)", "netip.ParseAddrPort(option.DNSResolver)")],
            "redundant-parse-guard": [parse_guard],
            "redundant-unmap": [unmap],
            "mutable-bootstrap": [mutable_bootstrap],
            "before-cleanup": [parse_guard, unmap, mutable_bootstrap],
        }
        expected = {
            "no-loopback-exception": "default v4/v6 plus cu v4:",
            "no-local-dns-mark": "SO_MARK = 0x0, <nil>; want 0x100",
            "no-external-dns-bind": 'SO_BINDTODEVICE = "", <nil>; want "cu"',
            "udp-only-loopback": "default v4/v6 plus cu v4:",
            "private-dns-unbound": 'SO_BINDTODEVICE = "", <nil>; want "cu"',
            "ipv4-only-loopback": 'SO_BINDTODEVICE = "cu", <nil>; want ""',
            "classify-configured-server": 'SO_BINDTODEVICE = "cu", <nil>; want ""',
        }
        tests = "^(TestEntryLoopbackDNSWithBoundInterface|TestEntrySockets|TestEntryDNSBindingAndFamilyRecovery|TestQUICProtocolsUseEntryResolverOnReconnect)$"
        benchmark, benchmark_cases = "BenchmarkEntryResolver", 3
        timing_variants = ["before-cleanup", "full", "redundant-parse-guard", "redundant-unmap", "mutable-bootstrap"]
        source_files = [label, bootstrap, socket, "component/outbound/entry_dns_linux_test.go", "component/outbound/entry_resolver_benchmark_test.go"]
    if args.baseline_source:
        mutations["before"] = []

    binaries = {}
    hashes = {}
    for name, changes in mutations.items():
        directory = output / name
        directory.mkdir(exist_ok=True)
        replacements, texts = {}, {}
        if name == "before":
            for source in (root / "component/outbound").glob("*.go"):
                previous = args.baseline_source / source.name
                texts[str(source.relative_to(root))] = previous.read_text() if previous.exists() else "package outbound\n"
        for file, old, new in changes:
            text = texts.get(file, (root / file).read_text())
            if text.count(old) != 1:
                raise RuntimeError(f"stale mutation: {name}/{file}: {old}")
            texts[file] = text.replace(old, new)
        for file, text in texts.items():
            replacement = directory / file
            replacement.parent.mkdir(parents=True, exist_ok=True)
            replacement.write_text(text)
            replacements[str(root / file)] = str(replacement)
        overlay = directory / "overlay.json"
        overlay.write_text(json.dumps({"Replace": replacements}, indent=2))
        binary = directory / "outbound.test"
        run(["go", "test", "-c", "-overlay", str(overlay), "-o", str(binary), "./component/outbound"], f"{name}-build.log")
        binaries[name] = binary
        if name in expected or name == "full" or args.suite == "loopback-dns":
            text = run(privilege + [str(binary), "-test.run=" + tests, "-test.v"], f"{name}-functional.log", expected.get(name))
            if "--- SKIP:" in text:
                raise RuntimeError(f"{name} skipped a required socket/netns check")
            print(f"{name}: {'detected' if name in expected else 'passed'}", flush=True)

    samples = {}
    variants = [name for name in timing_variants if name in binaries]
    for round_index in range(args.rounds):
        for name in variants[::1 if round_index % 2 == 0 else -1]:
            text = run([str(binaries[name]), "-test.run=^$", f"-test.bench=^{benchmark}$",
                        f"-test.benchtime={args.benchtime}"], f"{name}-bench-{round_index}.log")
            found = 0
            for line in text.splitlines():
                if not line.startswith(benchmark + "/"):
                    continue
                fields = line.split()
                case = re.sub(r"-\d+$", "", fields[0].removeprefix(benchmark + "/"))
                metrics = samples.setdefault(name, {}).setdefault(case, {})
                for i in range(2, len(fields), 2):
                    metrics.setdefault(fields[i + 1], []).append(float(fields[i]))
                found += 1
            if found != benchmark_cases:
                raise RuntimeError(f"missing benchmark samples: {name}: {text}")
        print(f"timing round {round_index + 1}/{args.rounds}", flush=True)

    for file in source_files:
        hashes[file] = hashlib.sha256((root / file).read_bytes()).hexdigest()
    summary = {
        "kernel": os.uname().release,
        "suite": args.suite,
        "go": run(["go", "version"], "go-version.log").strip(),
        "gomaxprocs": 4, "rounds": args.rounds, "source_sha256": hashes,
        "detected_mutations": list(expected), "samples": samples,
        "medians": {name: {case: {unit: statistics.median(values) for unit, values in metrics.items()}
                           for case, metrics in cases.items()} for name, cases in samples.items()},
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Summary: {output / 'summary.json'}", flush=True)


if __name__ == "__main__":
    main()
