"""Prints each metric over the runs of every scenario and binary: the median
with the range, and for the losses no drop counter accounts for and the
samples cut short by the end of the load, the run furthest from zero. Given
two binary tags, it then prints the change from the first binary's runs to
the second's, paired by repetition: the median and range of the relative
differences. Invalid runs are excluded from performance aggregates; pairs
with missing or different conditions are not compared. This is not an automatic
performance pass/fail decision.

usage: summarize.py OUT_DIR [BEFORE AFTER]

Runs are OUT_DIR/SCENARIO@TAG.N.json, as matrix.sh names them.
"""

import json
import math
import pathlib
import statistics
import sys

COLUMNS = [
    ("game_up_ms", "N"), ("game_up_ms", "P50"), ("game_up_ms", "P90"),
    ("game_up_ms", "P99"), ("game_up_ms", "Max"), ("game_down_ms", "P50"),
    ("game_down_ms", "P99"), ("game_up_ms_q1", "P50"), ("game_up_ms_q4", "P50"),
    ("game_down_ms_q1", "P50"), ("game_down_ms_q4", "P50"), ("game_lost", None),
    ("itcp_up_ms", "P50"), ("ttfb_ms", "P50"), ("bulk_mbit", None),
    ("bulk_jain", None), ("quic_share", None), ("notsent_bytes", "P99"),
    ("cpu_ms", None), ("uploaded_bytes", None), ("cpu_us_per_game_packet", None),
    ("cpu_ms_per_gb", None), ("datagram_memory_peak", None), ("maxrss_kb", None),
    ("flood_up_ms", "P50"), ("flood_up_ms", "P99"), ("flood_mbit", None), ("drops_upload", None),
    ("drops_download", None), ("qdisc_drops", None), ("flood_lost", None),
    ("game_echoed", None), ("game_sent", None), ("game_window_sent", None), ("game_window_unechoed", None),
    ("settle_s", None), ("settle_timeout", None),
    ("late", "game_up_ms"), ("late", "game_down_ms"), ("late", "itcp_up_ms"),
    ("late", "flood_up_ms"), ("late", "flood_down_ms"),
    ("late", "ttfb_ms"), ("upload_unaccounted", None),
    ("download_unaccounted", None),
]
# Checks that should be 0: the worst run is shown, not the median.
WORST = {"upload_unaccounted", "download_unaccounted", "late", "settle_timeout"}


CONDITIONS = {
    "rate_bps", "return_delay", "server_frame_writes", "cc", "ecn", "workload", "max_connections",
    "writer_delay", "socket_samples", "udp", "mptcp", "download", "lan_rate",
    "warmup_s", "duration_s", "go_version", "goos", "goarch",
}


def invalid_reasons(run):
    reasons = []
    conditions = run.get("conditions")
    if not isinstance(conditions, dict) or not CONDITIONS <= conditions.keys():
        reasons.append("missing conditions")
    if run.get("settle_timeout") is not False:
        reasons.append("incomplete window")
    late = run.get("late")
    if not isinstance(late, dict) or any(late.values()):
        reasons.append("late or missing samples")
    for key in ("upload_unaccounted", "download_unaccounted"):
        if key in run and run[key] != 0:
            reasons.append(key)
    if isinstance(conditions, dict) and isinstance(conditions.get("workload"), dict):
        work = conditions["workload"]
        if not work.get("quic", 0):
            required = ["download_unaccounted"]
            if conditions.get("udp") == "mux" or not (any(work.get(k, 0) for k in ("bulk", "itcp", "ttfb")) or conditions.get("download")):
                required.append("upload_unaccounted")
            reasons.extend("missing " + key for key in required if key not in run)
    return reasons


def value(run, key, field):
    v = run.get(key)
    if isinstance(v, dict):
        v = v.get(field)
    return v if isinstance(v, (int, float)) and math.isfinite(v) else None


def spread(values, fmt):
    """The median and, when the runs differ, their range."""
    text = fmt(statistics.median(values))
    if min(values) != max(values):
        text += f" [{fmt(min(values))},{fmt(max(values))}]"
    return text


def main(out, tags):
    runs = {}  # (scenario, tag) -> {repetition: report}
    for path in sorted(pathlib.Path(out).glob("*.json")):
        label, _, repetition = path.stem.rpartition(".")
        scenario, _, tag = label.partition("@")
        runs.setdefault((scenario, tag), {})[repetition] = json.loads(path.read_text())
    failed = not runs or any(invalid_reasons(r) for group in runs.values() for r in group.values())
    header = [k + ("." + f.lower() if f else "") for k, f in COLUMNS]
    print("\t".join(["scenario", "binary", "n", "invalid"] + header))
    for (scenario, tag), group in sorted(runs.items()):
        good = [r for r in group.values() if not invalid_reasons(r)]
        row = [scenario, tag, str(len(group)), str(len(group) - len(good))]
        for key, field in COLUMNS:
            population = group.values() if key in WORST else good
            values = [v for v in (value(r, key, field) for r in population) if v is not None]
            if not values:
                row.append("-")
            elif key in WORST:
                row.append(str(max(values, key=abs)))
            else:
                row.append(spread(values, lambda v: f"{v:.4g}"))
        print("\t".join(row))
    if len(tags) != 2:
        return int(failed)
    before, after = tags
    print(f"\nchange from {before} to {after}, paired by repetition")
    print("\t".join(["scenario", "pairs", "excluded"] + header))
    for scenario in sorted({s for s, _ in runs}):
        a, b = runs.get((scenario, before), {}), runs.get((scenario, after), {})
        missing = a.keys() ^ b.keys()
        if missing:
            print(f"{scenario}: missing counterpart for repetitions {sorted(missing)}", file=sys.stderr)
        common = sorted(a.keys() & b.keys())
        pairs = []
        for repetition in common:
            invalid = invalid_reasons(a[repetition]) + invalid_reasons(b[repetition])
            if invalid:
                print(f"{scenario}.{repetition}: excluded invalid pair ({', '.join(sorted(set(invalid)))})", file=sys.stderr)
            elif a[repetition]["conditions"] != b[repetition]["conditions"]:
                print(f"{scenario}.{repetition}: excluded different conditions", file=sys.stderr)
            else:
                pairs.append(repetition)
        excluded = len(common) - len(pairs) + len(missing)
        failed = failed or bool(excluded) or not pairs
        row = [scenario, str(len(pairs)), str(excluded)]
        for key, field in COLUMNS:
            changes = []
            for repetition in pairs:
                x, y = value(a[repetition], key, field), value(b[repetition], key, field)
                if key not in WORST and x and y is not None:
                    changes.append(y / x - 1)
            row.append(spread(changes, lambda v: f"{v:+.1%}") if changes else "-")
        print("\t".join(row))

    return int(failed)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2:]))
