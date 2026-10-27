#!/usr/bin/env bash
# Runs selected scenarios (default: normal and saturated, two repetitions)
# through run.sh, then
# summarizes them with summarize.py.
#
#   matrix.sh TEST_BINARY[,TEST_BINARY] [REPS] [SCENARIO...]
#
# Two binaries, before and after a change, alternate in every repetition,
# so that summarize.py can pair their runs; their file names without
# .test tag the runs and must differ. Each run is privileged; SUDO
# (default "sudo -n") prefixes run.sh, for example with a lock shared by
# root tests. OUT, passed to run.sh, must be empty or missing, so that no
# earlier run is summarized with these. Diagnostic scenarios must be named
# explicitly. Build settings and one fingerprint per binary go in artifacts/.
set -euo pipefail

here=$(dirname "$(realpath "$0")")
IFS=, read -ra bins <<<"$1"
REPS=${2:-2}
shift $(($# < 2 ? $# : 2))
[[ "$REPS" =~ ^[1-9][0-9]*$ ]] || { echo "REPS must be a positive integer" >&2; exit 1; }
OUT=${OUT:-/tmp/dae-queueing}
read -ra sudo <<<"${SUDO:-sudo -n}"
[ -z "$(ls -A "$OUT" 2>/dev/null)" ] || { echo "OUT=$OUT is not empty" >&2; exit 1; }
tags=()
for i in "${!bins[@]}"; do
	bins[i]=$(realpath "${bins[i]}")
	tags+=("$(basename "${bins[i]}" .test)")
done
[ ${#bins[@]} -le 2 ] && [ "$(printf '%s\n' "${tags[@]}" | sort -u | wc -l)" -eq ${#bins[@]} ] ||
	{ echo "give one or two test binaries with different names" >&2; exit 1; }

# name: run.sh assignments. W*/S* name the workloads of the queueing design.
declare -A scenarios=(
	[normal]="QEXP_WORKLOAD=game QEXP_SOCKET_SAMPLES=false"
	[saturated]="QEXP_WORKLOAD=game,bulk:4 QEXP_SOCKET_SAMPLES=false"
	[w1]="QEXP_WORKLOAD=game,bulk:4"
	[w1_mc1]="QEXP_WORKLOAD=game,bulk:4 QEXP_MAX_CONNECTIONS=1"
	[w1_mc1_ecn]="QEXP_WORKLOAD=game,bulk:4 QEXP_MAX_CONNECTIONS=1 ECN=1"
	[w1_cubic]="QEXP_WORKLOAD=game,bulk:4 CC=cubic"
	[w1_mptcp]="QEXP_WORKLOAD=game,bulk:4 QEXP_MPTCP=1"
	[w2]="QEXP_WORKLOAD=game,bulk:4,quic"
	[w2_mc1]="QEXP_WORKLOAD=game,bulk:4,quic QEXP_MAX_CONNECTIONS=1"
	[w3]="QEXP_WORKLOAD=itcp,bulk:4"
	[w4]="QEXP_WORKLOAD=ttfb,game,bulk:4"
	[w4_idle]="QEXP_WORKLOAD=ttfb"
	[w6_stall]="QEXP_WORKLOAD=game QEXP_DOWNLOAD=stall"
	[w6_slow]="QEXP_WORKLOAD=game QEXP_DOWNLOAD=slow"
	[w6_lan]="QEXP_WORKLOAD=game LAN_RATE=8kbit"
	[w6_lan_direct]="QEXP_WORKLOAD=game QEXP_UDP=direct LAN_RATE=8kbit"
	[w7]="QEXP_WORKLOAD=bulk:4"
	[w7_cubic]="QEXP_WORKLOAD=bulk:4 CC=cubic"
	[w7_d2]="QEXP_WORKLOAD=bulk:4 QEXP_WRITER_DELAY=2ms"
	[w7_d4]="QEXP_WORKLOAD=bulk:4 QEXP_WRITER_DELAY=4ms"
	[w7_200]="QEXP_WORKLOAD=bulk:4 RATE=200mbit RETURN_DELAY=20ms"
	[w7_200_d2]="QEXP_WORKLOAD=bulk:4 RATE=200mbit RETURN_DELAY=20ms QEXP_WRITER_DELAY=2ms"
	[w7_200_d4]="QEXP_WORKLOAD=bulk:4 RATE=200mbit RETURN_DELAY=20ms QEXP_WRITER_DELAY=4ms"
	[w7_1g]="QEXP_WORKLOAD=bulk:4 RATE=1gbit RETURN_DELAY=2ms"
	[s4]="QEXP_WORKLOAD=game,flood:60 QEXP_MAX_CONNECTIONS=1"
	[s4_direct]="QEXP_WORKLOAD=game,flood:60 QEXP_UDP=direct"
	[s4_direct_30]="QEXP_WORKLOAD=game,flood:30 QEXP_UDP=direct"
)
names=("$@")
[ ${#names[@]} -gt 0 ] || names=(normal saturated)
for name in "${names[@]}"; do
	[ -n "${scenarios[$name]+set}" ] || { echo "unknown scenario $name" >&2; exit 1; }
done

mkdir -p "$OUT/artifacts"
identities=()
for b in "${!bins[@]}"; do
	identities+=("$(sha256sum "${bins[b]}" | cut -d' ' -f1)")
	printf '%s  %s\n' "${identities[b]}" "${bins[b]}" > "$OUT/artifacts/${tags[b]}.identity.txt"
	go version -m "${bins[b]}" > "$OUT/artifacts/${tags[b]}.build.txt"
done

if [ ${#bins[@]} -eq 2 ]; then
	python3 -I - "$OUT/artifacts/${tags[0]}.build.txt" "$OUT/artifacts/${tags[1]}.build.txt" <<'PYBUILD'
import pathlib, sys

def settings(path):
    lines = pathlib.Path(path).read_text().splitlines()
    return lines[0].split(": ", 1)[-1], sorted(line for line in lines if line.startswith("\tbuild\t") and not line.startswith("\tbuild\tvcs."))

if settings(sys.argv[1]) != settings(sys.argv[2]):
    sys.exit("binary Go versions or build settings differ; rebuild both with the same flags")
PYBUILD
fi

for name in "${names[@]}"; do
	for i in $(seq "$REPS"); do
		# Odd repetitions run the first binary first, even ones the second.
		for b in $(if ((i % 2)); then echo "${!bins[@]}"; else echo "${!bins[@]}" | rev; fi); do
			label="$name@${tags[b]}.$i"
			# shellcheck disable=SC2086 # assignments are words
			"${sudo[@]}" "$here/run.sh" "${bins[b]}" "$label" OUT="$OUT" QEXP_BINARY="${identities[b]}" ${scenarios[$name]} >/dev/null
			echo "$label done" >&2
		done
	done
done
python3 -I "$here/summarize.py" "$OUT" "${tags[@]}"
