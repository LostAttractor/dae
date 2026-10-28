"""Generate test-only fq overlays without changing the working tree.

Usage: python3 scripts/tests/queueing/ablate.py NEW_OUTPUT_DIRECTORY
Run TestDatagramQueueScenarios with each overlay to compare policy effects.
These mechanism knockouts retain the state and tests of the full scheduler;
they are diagnostic variants, not production deletion patches.
"""

import difflib
import json
import pathlib
import sys


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("scheduler changed: ablation no longer matches uniquely")
    return source.replace(old, new, 1)


def variants(source):
    no_codel = replace_once(source, "drop := s.overTarget(f, now)", "drop := false")
    no_guard = replace_once(source, """\tvar frameTime time.Duration
\tif s.rate > 0 {
\t\tframeTime = time.Duration(Quantum / s.rate * float64(time.Second))
\t}
""", "")
    no_guard = replace_once(no_guard, "sojourn <= Target || sojourn <= 2*frameTime*time.Duration(s.old.Len()) || sojourn <= 4*frameTime || f.datagrams <= Quantum", "sojourn <= Target || f.datagrams <= Quantum")
    return {"base": source, "no-codel": no_codel, "no-rate-guard": no_guard}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = pathlib.Path(__file__).resolve().parents[3]
    path = root / "pkg/outbound/netproxy/fq/fq.go"
    source = path.read_text()
    generated = variants(source)
    out = pathlib.Path(sys.argv[1]).resolve()
    out.mkdir()
    for name, code in generated.items():
        target = out / (name + ".go")
        target.write_text(code)
        (out / (name + ".json")).write_text(json.dumps({"Replace": {str(path): str(target)}}, indent=2))
        (out / (name + ".patch")).write_text("".join(difflib.unified_diff(source.splitlines(True), code.splitlines(True), fromfile="a/pkg/outbound/netproxy/fq/fq.go", tofile="b/pkg/outbound/netproxy/fq/fq.go")))
    print(out)


if __name__ == "__main__":
    main()
