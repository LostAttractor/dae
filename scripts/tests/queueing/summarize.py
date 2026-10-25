"""Prints each metric over the runs of every scenario and binary: the median
with the range, and for the losses no drop counter accounts for and the
samples cut short by the end of the load, the run furthest from zero. Given
two binary tags, it then prints the change from the first binary's runs to
the second's, paired by repetition: the median and range of the relative
differences.

usage: summarize.py OUT_DIR [BEFORE AFTER]

Runs are OUT_DIR/SCENARIO@TAG.N.json, as matrix.sh names them.
"""

import json
import pathlib
import statistics
import sys

COLUMNS = [
    ("game_up_ms", "P50"), ("game_up_ms", "P99"), ("game_down_ms", "P50"),
    ("game_down_ms", "P99"), ("game_up_ms_q1", "P50"), ("game_up_ms_q4", "P50"),
    ("game_down_ms_q1", "P50"), ("game_down_ms_q4", "P50"), ("game_lost", None),
    ("itcp_up_ms", "P50"), ("ttfb_ms", "P50"), ("bulk_mbit", None),
    ("bulk_jain", None), ("quic_share", None), ("notsent_bytes", "P99"),
    ("cpu_ms_per_gb", None), ("datagram_memory_peak", None), ("maxrss_kb", None),
    ("flood_up_ms", "P50"), ("flood_up_ms", "P99"), ("flood_mbit", None), ("drops_upload", None),
    ("drops_download", None), ("qdisc_drops", None), ("flood_lost", None),
    ("game_echoed", None), ("game_sent", None), ("game_window_unechoed", None),
    ("settle_s", None), ("settle_timeout", None),
    ("late", "game_up_ms"), ("late", "game_down_ms"), ("late", "itcp_up_ms"),
    ("late", "flood_up_ms"), ("late", "flood_down_ms"),
    ("late", "ttfb_ms"), ("upload_unaccounted", None),
    ("download_unaccounted", None),
]
# Checks that should be 0: the worst run is shown, not the median.
WORST = {"upload_unaccounted", "download_unaccounted", "late", "settle_timeout"}


def value(run, key, field):
    v = run.get(key)
    if isinstance(v, dict):
        v = v.get(field)
    return v if isinstance(v, (int, float)) else None


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
    header = [k + ("." + f.lower() if f else "") for k, f in COLUMNS]
    print("\t".join(["scenario", "binary", "n"] + header))
    for (scenario, tag), group in sorted(runs.items()):
        row = [scenario, tag, str(len(group))]
        for key, field in COLUMNS:
            values = [v for v in (value(r, key, field) for r in group.values()) if v is not None]
            if not values:
                row.append("-")
            elif key in WORST:
                row.append(str(max(values, key=abs)))
            else:
                row.append(spread(values, lambda v: f"{v:.4g}"))
        print("\t".join(row))
    if len(tags) != 2:
        return
    before, after = tags
    print(f"\nchange from {before} to {after}, paired by repetition")
    print("\t".join(["scenario", "pairs"] + header))
    for scenario in sorted({s for s, _ in runs}):
        a, b = runs.get((scenario, before), {}), runs.get((scenario, after), {})
        pairs = sorted(a.keys() & b.keys())
        row = [scenario, str(len(pairs))]
        for key, field in COLUMNS:
            changes = []
            for repetition in pairs:
                x, y = value(a[repetition], key, field), value(b[repetition], key, field)
                if key not in WORST and x and y is not None:
                    changes.append(y / x - 1)
            row.append(spread(changes, lambda v: f"{v:+.1%}") if changes else "-")
        print("\t".join(row))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2:])
