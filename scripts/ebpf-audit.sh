#!/usr/bin/env bash
# shellcheck disable=SC2329 # Cleanup functions are invoked by signal traps.
set -euo pipefail

OUT_DIR="${1:-build/ebpf-audit}"
CLANG_BIN="${CLANG:-clang}"
OBJDUMP_BIN="${LLVM_OBJDUMP:-llvm-objdump}"
BPFTOOL_BIN="${BPFTOOL_BIN:-bpftool}"
BPF_ENDIAN_TARGET="${BPF_ENDIAN_TARGET:-bpfel}"
MAX_MATCH_SET_LEN="${MAX_MATCH_SET_LEN:-1024}"

for command_name in findmnt git realpath; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command_name}" >&2
    exit 1
  fi
done

REPO_ROOT=$(realpath -e -- "$(git rev-parse --show-toplevel)")
if [[ -L "${REPO_ROOT}/build" ]]; then
  echo "refusing symlinked build directory: ${REPO_ROOT}/build" >&2
  exit 1
fi
BUILD_ROOT=$(realpath -m -- "${REPO_ROOT}/build")
OUT_DIR=$(realpath -m -- "${OUT_DIR}")
EXPECTED_OUT_DIR="${BUILD_ROOT}/ebpf-audit"
if [[ "${OUT_DIR}" != "${EXPECTED_OUT_DIR}" ]]; then
  echo "output directory must be ${EXPECTED_OUT_DIR}: ${OUT_DIR}" >&2
  exit 1
fi
OBJECT_PATH="${OUT_DIR}/static/tproxy_${BPF_ENDIAN_TARGET}.o"
AUDIT_BIN="${OUT_DIR}/dae-ebpf-audit"
OUTPUT_MARKER="${OUT_DIR}/.dae-ebpf-audit-output"

refuse_nested_mounts() {
  local encoded_target
  local encoded_targets
  local mount_target
  if ! encoded_targets=$(findmnt -rnro TARGET); then
    echo "failed to inspect mounted paths" >&2
    return 1
  fi
  while IFS= read -r encoded_target; do
    printf -v mount_target '%b' "${encoded_target}"
    case "${mount_target}" in
      "${OUT_DIR}"|"${OUT_DIR}/"*)
        echo "refusing mounted path inside output directory: ${mount_target}" >&2
        return 1
        ;;
    esac
  done <<< "${encoded_targets}"
}

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=()
elif command -v sudo >/dev/null 2>&1; then
  SUDO=(sudo)
else
  echo "sudo is required to load and inspect eBPF programs" >&2
  exit 1
fi

for command_name in "${CLANG_BIN}" "${OBJDUMP_BIN}" go; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command is unavailable: ${command_name}" >&2
    exit 1
  fi
done

if resolved_bpftool=$(command -v "${BPFTOOL_BIN}" 2>/dev/null) && "${resolved_bpftool}" version >/dev/null 2>&1; then
  BPFTOOL_BIN="${resolved_bpftool}"
else
  for candidate in /usr/lib/linux-tools/*/bpftool; do
    if [[ -x "${candidate}" ]] && "${candidate}" version >/dev/null 2>&1; then
      BPFTOOL_BIN="${candidate}"
      break
    fi
  done
fi
if ! "${BPFTOOL_BIN}" version >/dev/null 2>&1; then
  echo "a working bpftool is required" >&2
  exit 1
fi
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  echo "kernel BTF is required at /sys/kernel/btf/vmlinux" >&2
  exit 1
fi

if [[ -e "${OUT_DIR}" || -L "${OUT_DIR}" ]]; then
  if [[ ! -d "${OUT_DIR}" || -L "${OUT_DIR}" ]]; then
    echo "refusing non-directory or symlinked output path: ${OUT_DIR}" >&2
    exit 1
  fi
  refuse_nested_mounts
  if [[ ! -f "${OUTPUT_MARKER}" || -L "${OUTPUT_MARKER}" ]] ||
    [[ "$(<"${OUTPUT_MARKER}")" != "dae-ebpf-audit-output-v1" ]]; then
    echo "refusing unmarked output directory: ${OUT_DIR}" >&2
    exit 1
  fi
  rm -rf --one-file-system --preserve-root=all -- "${OUT_DIR}"
fi
mkdir -p "${OUT_DIR}/static" "${OUT_DIR}/bpftool/programs" "${OUT_DIR}/bpftool/maps"
printf '%s\n' 'dae-ebpf-audit-output-v1' > "${OUTPUT_MARKER}"

audit_pid=""
audit_process_pid=""
restore_ownership() {
  if [[ "${EUID}" -ne 0 ]]; then
    refuse_nested_mounts || return
    "${SUDO[@]}" chown -R --no-dereference "$(id -u):$(id -g)" "${OUT_DIR}" 2>/dev/null || true
  fi
}
read_audit_process_pid() {
  local executable
  local pid
  [[ -s "${OUT_DIR}/audit.pid" ]] || return 1
  pid=$(<"${OUT_DIR}/audit.pid")
  case "${pid}" in
    ""|*[!0-9]*) return 1 ;;
  esac
  while [[ "${pid}" == 0* && "${#pid}" -gt 1 ]]; do
    pid="${pid#0}"
  done
  if [[ "${pid}" == 0 || "${pid}" == 1 ]]; then
    return 1
  fi
  executable=$("${SUDO[@]}" realpath -e -- "/proc/${pid}/exe" 2>/dev/null) || return 1
  if [[ "${executable}" != "${AUDIT_BIN}" ]]; then
    return 1
  fi
  audit_process_pid="${pid}"
}
stop_audit() {
  if [[ -z "${audit_process_pid}" ]]; then
    read_audit_process_pid || true
  fi
  local pid="${audit_process_pid:-${audit_pid}}"
  if [[ -n "${pid}" ]] && "${SUDO[@]}" kill -0 "${pid}" 2>/dev/null; then
    "${SUDO[@]}" kill -TERM "${pid}" 2>/dev/null || true
  fi
}
cleanup() {
  if [[ -n "${audit_pid}" ]]; then
    stop_audit
    wait "${audit_pid}" 2>/dev/null || true
  fi
  restore_ownership
}
handle_signal() {
  local status="$1"
  trap - EXIT INT TERM
  cleanup
  exit "${status}"
}
trap cleanup EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -a)"
  echo "bpftool=$(${BPFTOOL_BIN} version 2>&1 | tr '\n' ' ')"
  echo "clang=$(${CLANG_BIN} --version | head -n1)"
  echo "llvm-objdump=$(${OBJDUMP_BIN} --version | head -n1)"
  echo "go=$(go version)"
  echo "kernel_btf=/sys/kernel/btf/vmlinux"
} > "${OUT_DIR}/environment.txt"

git submodule update --init --recursive

if ! "${CLANG_BIN}" -O2 -g -target "${BPF_ENDIAN_TARGET}" -mcpu=v1 -Wall -Werror \
  -Wno-unused-command-line-argument \
  -DMAX_MATCH_SET_LEN="${MAX_MATCH_SET_LEN}" \
  -c control/kern/tproxy.c -o "${OBJECT_PATH}" \
  > "${OUT_DIR}/static/compile.stdout.txt" 2> "${OUT_DIR}/static/compile.stderr.txt"; then
  exit 1
fi

"${OBJDUMP_BIN}" -h "${OBJECT_PATH}" > "${OUT_DIR}/static/object-sections.txt"
"${OBJDUMP_BIN}" -t "${OBJECT_PATH}" > "${OUT_DIR}/static/object-symbols.txt"
"${OBJDUMP_BIN}" -d --no-show-raw-insn "${OBJECT_PATH}" > "${OUT_DIR}/static/object-disasm.txt"
go build -o "${AUDIT_BIN}" ./cmd/dae-ebpf-audit

"${SUDO[@]}" "${BPFTOOL_BIN}" feature probe kernel > "${OUT_DIR}/bpftool/feature-probe.txt" 2>&1

"${SUDO[@]}" "${AUDIT_BIN}" \
  -object "${OBJECT_PATH}" \
  -output-dir "${OUT_DIR}" \
  -hold \
  > "${OUT_DIR}/audit.stdout.txt" 2> "${OUT_DIR}/audit.stderr.txt" &
audit_pid=$!

ready=0
for _ in $(seq 1 60); do
  if [[ -s "${OUT_DIR}/audit.ready" ]] && read_audit_process_pid; then
    ready=1
    break
  fi
  if [[ -f "${OUT_DIR}/load-error.txt" ]]; then
    break
  fi
  if ! "${SUDO[@]}" kill -0 "${audit_pid}" 2>/dev/null; then
    break
  fi
  sleep 1
done

audit_status=0
if [[ "${ready}" -eq 1 && -s "${OUT_DIR}/manifest.tsv" ]]; then
  while IFS=$'\t' read -r kind name id; do
    [[ -n "${kind}" ]] || continue
    case "${kind}" in
      program)
        "${SUDO[@]}" "${BPFTOOL_BIN}" prog show id "${id}" > "${OUT_DIR}/bpftool/programs/${name}.show.txt" 2>&1 || audit_status=1
        "${SUDO[@]}" "${BPFTOOL_BIN}" prog dump xlated id "${id}" > "${OUT_DIR}/bpftool/programs/${name}.xlated.txt" 2>&1 || audit_status=1
        "${SUDO[@]}" "${BPFTOOL_BIN}" prog dump jited id "${id}" > "${OUT_DIR}/bpftool/programs/${name}.jited.txt" 2>&1 || true
        ;;
      map)
        "${SUDO[@]}" "${BPFTOOL_BIN}" map show id "${id}" > "${OUT_DIR}/bpftool/maps/${name}.show.txt" 2>&1 || audit_status=1
        ;;
    esac
  done < "${OUT_DIR}/manifest.tsv"
else
  echo "audit process did not become ready" > "${OUT_DIR}/bpftool/dump-error.txt"
  audit_status=1
fi

stop_audit
loader_status=0
wait "${audit_pid}" || loader_status=$?
audit_pid=""
audit_process_pid=""
if [[ "${ready}" -eq 1 && "${loader_status}" -eq 143 ]]; then
  loader_status=0
fi
if [[ "${loader_status}" -ne 0 ]]; then
  audit_status="${loader_status}"
fi

restore_ownership
trap - EXIT INT TERM
exit "${audit_status}"
