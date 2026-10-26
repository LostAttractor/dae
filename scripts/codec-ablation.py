#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import platform
import re
import tempfile
from pathlib import Path

from ablation import make_runner, medians, replace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--benchtime", default="500ms")
    parser.add_argument("--bench", default="BenchmarkCodec")
    parser.add_argument("--variants", metavar="VARIANT[,VARIANT...]")
    args = parser.parse_args()
    if args.rounds < 0:
        parser.error("rounds must be nonnegative")
    root = Path(__file__).resolve().parent.parent
    output = args.output or Path(tempfile.mkdtemp(prefix="codec-ablation-"))
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    env = dict(os.environ, GOMAXPROCS="2", GOPROXY="off", GOSUMDB="off")
    run = make_runner(root, output, env=env, timeout=180)
    print(f"Results directory: {output}", flush=True)

    files = set()
    for directory in ("component/plugin", "pkg/membuffer", "common/fileio"):
        files.update((root / directory).rglob("*.go"))
    files.update(p for p in (root / "go.mod", root / "go.sum", root / "go.work", root / "go.work.sum") if p.exists())
    texts = {str(p.relative_to(root)): p.read_text() for p in sorted(files)}
    hashes = {file: hashlib.sha256(text.encode()).hexdigest() for file, text in texts.items()}
    (output / "hashes.json").write_text(json.dumps(hashes, indent=2))
    cpu = next((line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), platform.processor())
    metadata = {"platform": platform.platform(), "cpu": cpu, "GOMAXPROCS": env["GOMAXPROCS"],
                "go": run(["go", "version"], "go-version.log").strip(), "rounds": args.rounds, "benchtime": args.benchtime}
    (output / "environment.json").write_text(json.dumps(metadata, indent=2))

    def unchanged():
        for file, digest in hashes.items():
            if hashlib.sha256((root / file).read_bytes()).hexdigest() != digest:
                raise RuntimeError(f"Source changed; cannot mix samples: {file}")

    http, grpc, transform = ("component/plugin/codec/" + name + ".go" for name in ("http", "grpc", "grpc_transform"))
    pregrow = '''\tif err := b.Grow(int(size + 5)); err != nil {
\t\treturn nil, err
\t}
'''
    frame_body = '''\tb := membuffer.Buffer{Budget: c.budget, Limit: size + 5}
\tdefer b.Close()
''' + pregrow + '''\tvar header [5]byte
\tbinary.BigEndian.PutUint32(header[1:], uint32(size))
\tif _, err := b.Write(header[:]); err != nil {
\t\treturn nil, err
\t}
\tfor _, part := range parts {
\t\tif _, err := b.Write(part); err != nil {
\t\t\treturn nil, err
\t\t}
\t}
\tif err := c.ctx.Err(); err != nil {
\t\treturn nil, err
\t}
\treturn b.View(), nil'''
    exact_frame = '''\tvar header [5]byte
\tbinary.BigEndian.PutUint32(header[1:], uint32(size))
\treaders := make([]io.Reader, 0, len(parts)+1)
\treaders = append(readers, bytes.NewReader(header[:]))
\tfor _, part := range parts {
\t\treaders = append(readers, bytes.NewReader(part))
\t}
\tframe, err := membuffer.ReadExact(io.MultiReader(readers...), size+5, c.budget)
\tif err == nil {
\t\terr = c.ctx.Err()
\t}
\tif err != nil {
\t\tframe.Close()
\t\treturn nil, err
\t}
\treturn frame, nil'''
    mutations = {
        "full": [],
        "no-real-eof": [(http, '''\tfor {
\t\t_, err := r.input.Read(p)
\t\tif err != nil {
\t\t\treturn 0, err
\t\t}
\t}''', '\treturn 0, io.EOF')],
        "no-sticky-source-error": [(grpc, '\tn, err := r.source.Read(p)\n\tr.err = err', '\tn, err := r.source.Read(p)\n\tr.err = nil')],
        "conflate-content-truncation": [(grpc, '\tif d.truncated {', '\tif d.truncated || errors.Is(d.failed, io.ErrUnexpectedEOF) {')],
        "wait-for-tail": [(transform, '\t\t\tif n != 0 || err != nil {', '\t\t\tif n > 0 { _, _ = r.decoder.Next() }\n\t\t\tif n != 0 || err != nil {')],
        "no-wire-bound": [(http, 'r.bounded(r.source, r.wireLimit)', 'r.bounded(r.source, r.decodedLimit)')],
        "no-layer-bound": [(http, 'r.bounded(&httpDecodedReader{decoder: decoder, input: input}, r.decodedLimit)', 'r.bounded(&httpDecodedReader{decoder: decoder, input: input}, r.wireLimit)')],
        "no-workspace": [(http, 'r.codec.budget.Reserve(size)', 'r.codec.budget.Reserve(0)')],
        "close-after-lock-http": [(http, '\terr := r.closeSource()\n\tr.mu.Lock()', '\tr.mu.Lock()\n\terr := r.closeSource()')],
        "close-after-lock-grpc": [(grpc, '\terr := d.closeSource()\n\td.mu.Lock()', '\td.mu.Lock()\n\terr := d.closeSource()')],
        "drain-scratch-buffer": [(http, '\tfor {\n\t\t_, err := r.input.Read(p)', '\tvar scratch [4096]byte\n\tfor {\n\t\t_, err := r.input.Read(scratch[:])')],
        "frame-exact-reader": [(grpc, frame_body, exact_frame)],
        "frame-growing": [(grpc, pregrow, '')],
        "growing-input": [(grpc, '\td.partial, err = membuffer.ReadExact(framed, size, d.codec.budget)', '''\td.partial, err = membuffer.Read(io.LimitReader(framed, size), size, d.codec.budget)
\tif err == nil && int64(len(d.partial.Bytes())) != size { err = io.ErrUnexpectedEOF }''')],
    }
    checks = {
        "no-real-eof": ("^TestHTTPReaderTrueEOF$/deflate$", "decoder EOF escaped before source EOF"),
        "no-sticky-source-error": ("^TestCodecSourceErrorAtFrameBoundary$", "source error at complete frame was lost"),
        "conflate-content-truncation": ("^TestGRPCTransformReplay$/gzip-invalid$", "unexpected EOF"),
        "wait-for-tail": ("^TestCodecFirstMessageBeforeTail$", "first message waited for the tail"),
        "no-wire-bound": ("^TestHTTPBounds$/gzip/wire$", "reader length="),
        "no-layer-bound": ("^TestHTTPBounds$/intermediate_br$", "intermediate reader limit:"),
        "no-workspace": ("^TestHTTPWorkspace$/gzip$", "scratch bypassed budget"),
        "close-after-lock-http": ("^TestCodecCloseUnblocksSource$/http$", "Close waited for Read"),
        "close-after-lock-grpc": ("^TestCodecCloseUnblocksSource$/grpc$", "Close waited for Read"),
    }
    if args.variants:
        selected = args.variants.split(",")
        if any(name not in mutations for name in selected):
            parser.error("unknown variant")
        mutations = {name: mutations[name] for name in selected}
        checks = {name: check for name, check in checks.items() if name in mutations}
    regressions = {
        "frame-growing": [
            ("TestCodecFrameExactBudget", "known-size frame requires extra allocation"),
            ("TestCodecRewriteCoexistingBudget", "coexisting representations:"),
        ],
        "growing-input": [("TestCodecRewriteCoexistingBudget", "coexisting representations:")],
    }
    binaries = {}
    commands = []

    def execute(command, log, expected=None):
        commands.append({"command": command, "log": log, "expected": expected})
        (output / "commands.json").write_text(json.dumps(commands, indent=2))
        text = run(command, log, expected)
        if expected is not None and ("panic:" in text or "fatal error:" in text or "--- FAIL:" not in text):
            raise RuntimeError(f"Variant did not fail through a normal test assertion: {log}")
        return text

    empty = output / "empty-overlay.json"
    empty.write_text('{"Replace": {}}')
    execute(["go", "test", "-overlay", str(empty), "./component/plugin/codec", "-count=1", "-timeout=30s"], "empty-overlay.log")
    for name, changes in mutations.items():
        unchanged()
        current = dict(texts)
        for file, old, new in changes:
            current[file] = replace(current[file], old, new, context=f"{name}/{file}")
        directory = output / name
        replacements = {}
        for file, text in current.items():
            path = directory / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            if file.endswith(".go"):
                replacements[str(root / file)] = str(path)
        overlay = directory / "overlay.json"
        overlay.write_text(json.dumps({"Replace": replacements}, indent=2))
        binary = directory / "codec.test"
        execute(["go", "test", "-c", "-overlay", str(overlay), "-o", str(binary), "./component/plugin/codec"], name + "-build.log")
        if name in checks:
            test, assertion = checks[name]
            execute([str(binary), "-test.run=" + test, "-test.count=1", "-test.timeout=15s"], name + "-check.log", assertion)
        else:
            failures = regressions.get(name, [])
            for test, assertion in failures:
                execute([str(binary), "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=15s"],
                        name + "-" + test + ".log", assertion)
            skip = ["-test.skip=^(" + "|".join(test for test, _ in failures) + ")$"] if failures else []
            execute([str(binary), "-test.run=Test", "-test.count=1", "-test.timeout=30s", *skip], name + "-check.log")
            binaries[name] = binary
        print(f"Validated: {name}", flush=True)
        unchanged()

    samples = {}
    pattern = re.compile(r"^(Benchmark\S+)-\d+\s+\d+\s+(.+)$")
    for turn in range(args.rounds):
        order = list(binaries)
        if turn % 2:
            order.reverse()
        for name in order:
            unchanged()
            text = execute([str(binaries[name]), "-test.run=^$", "-test.bench=" + args.bench, "-test.benchmem",
                            "-test.benchtime=" + args.benchtime, "-test.count=1"], f"{name}-bench-{turn}.log")
            for line in text.splitlines():
                match = pattern.match(line)
                if not match:
                    continue
                values = match[2].split()
                metrics = {values[i + 1]: float(values[i]) for i in range(0, len(values), 2)}
                samples.setdefault(name, {}).setdefault(match[1], []).append(metrics)
        print(f"Measured: {turn + 1}/{args.rounds}", flush=True)
    unchanged()
    (output / "samples.json").write_text(json.dumps(samples, indent=2))
    if args.rounds and binaries and (set(samples) != set(binaries) or any(
        len(values) != args.rounds for benchmarks in samples.values() for values in benchmarks.values()
    )):
        raise RuntimeError("Benchmark samples are missing; cannot summarize")
    summary = {"checks": {name: "detected" for name in checks}, "medians": medians(samples)}
    summary["expected_regressions"] = {
        name: [test for test, _ in failures] for name, failures in regressions.items() if name in mutations
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
