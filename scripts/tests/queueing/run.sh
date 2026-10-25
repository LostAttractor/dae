#!/usr/bin/env bash
# Runs one queueing experiment as root: the client namespace plays the LAN,
# dae and the router's WAN qdisc; the server namespace relays and reflects.
#
#   run.sh TEST_BINARY LABEL [NAME=VALUE...]
#
# TEST_BINARY is the control package's test binary (go test -c ./control).
# Topology (defaults mirror the router's uplink):
#   RATE=40mbit         cake on the client's egress, as on the router's cu:
#                       diffserv3 triple-isolate nonat nowash split-gso raw,
#                       rtt 50ms with the default 5 ms target
#   RETURN_DELAY=90ms   netem on the server's egress only, so the upload's
#                       one-way delay is its queueing delay
#   CC=bbr              congestion control in both namespaces
#   ECN=0               tcp_ecn of the client namespace
#   LAN_RATE=           replies reach the LAN host through transparent sockets,
#                       on the client's loopback shaped to this rate (tc units)
#                       until the load stops; unset, the test takes them
#   OUT=/tmp/dae-queueing  where LABEL.json, LABEL.tc and LABEL.nstat are
#                       written; a run whose server namespace dropped UDP
#                       fails and leaves no LABEL.json
# The client and the server run on disjoint halves of the physical cores.
# The client namespace's UDP socket errors go to LABEL.client.nstat.
# Workload, passed to the client test (see control/queueing_experiment_test.go):
#   QEXP_WORKLOAD=game,bulk:4  game, bulk:N, quic, itcp, ttfb, flood:MBIT
#   QEXP_DOWNLOAD=stall|slow   a TCP download that stalls or reads 1 MiB/s
#   QEXP_MAX_CONNECTIONS=0     smux sessions (0: the default)
#   QEXP_UDP=mux               UDP flows through smux, or direct: a socket each
#   QEXP_WRITER_DELAY=0s       CPU spin before each carrier write
#   QEXP_MPTCP=0               dial carriers with MPTCP, remembered per server
#   QEXP_WARMUP=3s QEXP_DURATION=20s
set -euo pipefail

BIN=$(realpath "$1")
LABEL=$2
shift 2
for assignment in "$@"; do
	export "${assignment?}"
done
RATE=${RATE:-40mbit}
RETURN_DELAY=${RETURN_DELAY:-90ms}
CC=${CC:-bbr}
ECN=${ECN:-0}
OUT=${OUT:-/tmp/dae-queueing}
mkdir -p "$OUT"

# Without SMT siblings in common, so that neither side slows the other.
read -r client_cpus server_cpus < <(lscpu -p=CPU,CORE | awk -F, '
	!/^#/ { cpu[NR] = $1; core[NR] = $2; if ($2 > last) last = $2 }
	END { for (i in cpu) if (core[i] <= last / 2) c = c "," cpu[i]; else s = s "," cpu[i]; print substr(c, 2), substr(s, 2) }')
[ -n "$server_cpus" ] || { echo "the experiment needs two physical cores" >&2; exit 1; }
# The client's own -test.timeout; the server outlives it.
minutes=10

client=qexpc$$
server=qexps$$
report="$OUT/$LABEL.json"
pids=()
cleanup() {
	set +e # the namespaces go whatever the processes exited with
	for pid in "${pids[@]}"; do
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	done
	rm -f "$report.tmp"
	ip netns del "$client" 2>/dev/null
	ip netns del "$server" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

ip netns add "$client"
ip netns add "$server"
ip link add qexpa netns "$client" type veth peer name qexpb netns "$server"
ip -n "$client" addr add 10.77.0.1/24 dev qexpa
ip -n "$server" addr add 10.77.0.2/24 dev qexpb
# BIG TCP as on the router: one segment can carry 512 KiB.
ip -n "$client" link set qexpa gso_max_size 524280 gso_ipv4_max_size 524280
ip -n "$server" link set qexpb gro_max_size 524280 gro_ipv4_max_size 524280
for ns in "$client" "$server"; do
	ip -n "$ns" link set lo up
	ip netns exec "$ns" sysctl -qw net.ipv4.tcp_congestion_control="$CC"
done
ip -n "$client" link set qexpa up
ip -n "$server" link set qexpb up
ip netns exec "$client" sysctl -qw net.ipv4.tcp_wmem="4096 16384 655360" net.ipv4.tcp_ecn="$ECN"
ip netns exec "$server" sysctl -qw net.ipv4.tcp_rmem="4096 131072 26214400"
# tc's rtt keyword would set the target to rtt/20; netlink sets both.
env DAE_QUEUE_EXP=1 QEXP_CAKE_DEV=qexpa QEXP_CAKE_RATE="$RATE" ip netns exec "$client" \
	"$BIN" -test.run '^TestQueueingExperimentCake$' >/dev/null
tins=$(ip netns exec "$client" tc -s qdisc show dev qexpa)
best_effort() { awk -v row="$1" '$1 == row { print $3 }' <<<"$tins"; }
[ "$(best_effort target)" = 5ms ] && [ "$(best_effort interval)" = 50ms ] ||
	{ echo "cake's Best Effort tin is not target 5ms interval 50ms:" >&2; echo "$tins" >&2; exit 1; }
ip netns exec "$server" tc qdisc replace dev qexpb root netem delay "$RETURN_DELAY" limit 100000

env DAE_QUEUE_EXP=1 QEXP_SERVER=10.77.0.2 ip netns exec "$server" taskset -c "$server_cpus" \
	"$BIN" -test.run '^TestQueueingExperimentServer$' -test.timeout=$((minutes + 1))m >"$OUT/$LABEL.server.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do
	ip netns exec "$server" ss -Hltn 'sport = :8388' | grep -q . && break
	sleep 0.1
done

env DAE_QUEUE_EXP=1 QEXP_SERVER=10.77.0.2 QEXP_CAKE_DEV=qexpa QEXP_LAN_RATE="${LAN_RATE:-}" QEXP_OUT="$report.tmp" QEXP_RETURN_DELAY="$RETURN_DELAY" QEXP_LABEL="$LABEL" \
	QEXP_BINARY="$(sha256sum "$BIN" | cut -d' ' -f1)" ip netns exec "$client" taskset -c "$client_cpus" \
	"$BIN" -test.run '^TestQueueingExperimentClient$' -test.timeout=${minutes}m >"$OUT/$LABEL.client.log" 2>&1 &
pids+=($!)
wait "${pids[-1]}" || { tail -20 "$OUT/$LABEL.client.log" >&2; exit 1; }
ip netns exec "$client" tc -s qdisc show dev qexpa >"$OUT/$LABEL.tc"
ip netns exec "$client" nstat -saz UdpRcvbufErrors UdpSndbufErrors Udp6RcvbufErrors Udp6SndbufErrors >"$OUT/$LABEL.client.nstat"
# Lost probes must be the client's: the server must not drop UDP.
ip netns exec "$server" nstat -saz UdpRcvbufErrors UdpInErrors Udp6RcvbufErrors Udp6InErrors >"$OUT/$LABEL.nstat"
if awk '$1 ~ /^Udp/ && $2 != 0 { bad = 1 } END { exit !bad }' "$OUT/$LABEL.nstat"; then
	echo "the server namespace dropped UDP; the run is invalid:" >&2
	cat "$OUT/$LABEL.nstat" >&2
	exit 1
fi
mv "$report.tmp" "$report"
cat "$report"
