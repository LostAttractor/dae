#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --isolated ]]; then
    if [[ $$ != 1 ]]; then
        echo "--isolated must run as PID 1 inside the test namespaces" >&2
        exit 1
    fi
    shift
    mount --bind "$test_cgroup" /sys/fs/cgroup
    mount -t tmpfs tmpfs /run
    mkdir -p /run/netns
    mount -t bpf bpf /sys/fs/bpf
    ip link set lo up
    echo 1 > /proc/sys/net/mptcp/enabled
    export DAE_TEST_ISOLATED=1 DAE_TEST_NETFILTER=1 DAE_TEST_API_NETNS=1 DAE_NETKIT_TEST=1
    # Keep the shell as PID 1 so tests and their children have ordinary PID semantics.
    "$@" -test.v -test.count=1 -test.timeout=3m
    exit
fi

test "$(id -u)" = 0
export test_cgroup
test_cgroup=$(mktemp -d /sys/fs/cgroup/dae-kernel-control.XXXXXX)
log=$(mktemp)
trap 'rm -f "$log"; rmdir "$test_cgroup"' EXIT

run_suite() {
    local binary=$1 pattern=$2 name
    local names
    binary=$(command -v "$binary") || return 1
    names=$("$binary" -test.list "$pattern") || return 1
    test -n "$names" || return 1
    local failed=0
    while read -r name; do
        case "$name" in
            TestConfiguredBPFMapCapacities|TestPersistentKernelProcess) continue ;;
        esac
        # Each test gets fresh pins and namespaces, including subprocess tests.
        if ! (
            echo "$BASHPID" > "$test_cgroup/cgroup.procs" || exit 1
            exec unshare --mount --propagation private --net --pid --fork --kill-child --mount-proc \
                bash "$0" --isolated "$binary" "-test.run=^$name$"
        ) | tee "$log"; then
            echo "Failed on $(uname -r): $name" >&2
            failed=1
            continue
        fi
        # An optional CO-RE mutation cannot be synthesized if the field is
        # already absent from the running kernel's BTF.
        if grep -E '^[[:space:]]*--- SKIP:' "$log" |
            grep -vE '^[[:space:]]+--- SKIP: TestBridgeMetadataOptionalKernel/' >&2; then
            echo "Unexpected skip in $binary: $name" >&2
            failed=1
        fi
        if ! grep -qE "^--- PASS: $name \\(" "$log"; then
            echo "No top-level PASS on $(uname -r): $name" >&2
            failed=1
        fi
    done <<< "$names"
    return "$failed"
}

control_extra='HostIdentityPrecedesBusinessMaps|UDPRelayDoesNotCreateInboundConntrack'
control_extra+='|TCPProxyTupleKeepsAcceptedSocket|TCPSocketIndexLifecycle|UDPConnStateReleasesRetiredGeneration'
control_extra+='|RemoveIncompatiblePinnedMaps|SocketOwnerStorageIsReusedAcrossLoads|RedirectTrackDistributedLRUCrossCPU'
control_extra+='|ExplicitAPIAddressLifecycle|ClientExport.*|SendUDPv[46]RawDirect'
control_extra+='|AnyfromBackpressureDeadlineAndClose|DNSUpstreamSocketDropsAreNotUploaded|TCPFlowSurvivesRealIngressRelayClose'
failed=0
run_suite control.test "^Test(.*(BPF|Kernel|Integration|TCX|TCFilters).*|NativeTCP.*|TCPMonitor.*|TCPWriteCounter.*|TCPIdleTimeout.*|$control_extra)$" || failed=1
run_suite daemon.test '^Test.*Kernel$' || failed=1
run_suite clientset.test '^TestKernel' || failed=1
run_suite apiserver.test '^TestLANListenerBridgePortPreparationKeepsOldListener$' || failed=1
exit "$failed"
