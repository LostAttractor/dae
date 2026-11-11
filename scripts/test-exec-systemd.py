#!/usr/bin/env python3
"""Verify same-PID self-exec with transient units, without BPF or network access.

First run go test -c -o /tmp/dae-handoff.test ./internal/handoff, then:
sudo python3 -I scripts/test-exec-systemd.py /tmp/dae-handoff.test
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def wait_for(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("timed out waiting for the test unit")


def properties(unit):
    output = run("systemctl", "show", unit, "-p", "MainPID", "-p", "ActiveState",
                 "-p", "Result", "-p", "StatusText", "-p", "NotifyAccess")
    return dict(line.split("=", 1) for line in output.splitlines())


def process_stat(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    return fields[19], int(fields[11]) + int(fields[12])


def test(binary, kind, stopping):
    unit = f"dae-exec-test-{uuid.uuid4().hex}.service"
    with tempfile.TemporaryDirectory(prefix="dae-exec-systemd-") as directory:
        directory = Path(directory)
        for generation in (1, 2):
            target = directory / f"image-{generation}"
            shutil.copyfile(binary, target)
            with target.open("ab") as file:
                file.write(f"\ndae-exec-generation-{generation}\n".encode())
            target.chmod(0o700)
        try:
            args = [str(binary), "-test.run=^TestExecFixture$", "--", "fixture argument", "with=equals"]
            run("systemd-run", "--no-block", f"--unit={unit}", f"--property=Type={kind}",
                "--property=NotifyAccess=main", "--property=Restart=no",
                "--property=KillMode=control-group", "--property=TimeoutStopSec=10",
                "--property=RuntimeMaxSec=90", f"--setenv=DAE_EXEC_TEST_DIR={directory}",
                "--setenv=DAE_EXEC_TEST_VALUE=kept=value with spaces", *args)
            identity = None
            previous = None
            counts = []
            for generation in range(4):
                state_file = directory / f"state-{generation}"
                wait_for(state_file.exists)
                state = json.loads(state_file.read_text())
                wait_for(lambda: properties(unit)["StatusText"] == f"generation {generation}")
                status = properties(unit)
                assert status["ActiveState"] == "active", status
                assert status["NotifyAccess"] == "main", status
                assert int(status["MainPID"]) == state["PID"], status
                current = state["PID"], process_stat(state["PID"])[0]
                if identity is None:
                    identity = current
                assert current == identity
                assert state["Starttime"] == current[1] and state["HeapReset"], state
                assert state["Args"] == args, state
                assert "DAE_EXEC_TEST_VALUE=kept=value with spaces" in state["Env"], state
                image = binary if generation == 0 else directory / f"image-{min(generation, 2)}"
                assert os.path.samefile(f"/proc/{state['PID']}/exe", image)
                assert state["Digest"] == hashlib.sha256(image.read_bytes()).hexdigest(), state
                if previous is not None:
                    assert state["Protocol"] == previous["Protocol"], state
                    assert state["Boot"] != previous["Boot"], state
                    assert state["Env"] == previous["Env"], state
                    assert not Path(f"/proc/{state['OwnedChild']}").exists(), state
                    if generation == 2:
                        assert state["Digest"] != previous["Digest"], state
                    elif generation == 3:
                        assert state["Digest"] == previous["Digest"], state
                previous = state
                counts.append(len(list(Path(f"/proc/{state['PID']}/fd").iterdir())))
                if generation < 3:
                    (directory / f"next-{generation}").touch()
                    wait_for((directory / f"reloading-{generation}").exists)
                    wait_for(lambda: properties(unit)["ActiveState"] == "reloading")
                    assert int(properties(unit)["MainPID"]) == state["PID"]
                    (directory / f"exec-{generation}").touch()
            assert counts[3] <= counts[2] <= counts[1], counts
            before = process_stat(state["PID"])[1]
            time.sleep(1)
            ticks = process_stat(state["PID"])[1] - before
            memory = next(line for line in Path(f"/proc/{state['PID']}/status").read_text().splitlines()
                          if line.startswith("VmRSS:"))
            if stopping:
                run("systemctl", "stop", unit)
                status = properties(unit)
                assert status["ActiveState"] == "inactive" and status["Result"] == "success", status
            else:
                os.kill(state["PID"], 9)
                wait_for(lambda: properties(unit)["ActiveState"] == "failed")
                status = properties(unit)
                assert status["Result"] == "signal", status
            assert status["MainPID"] == "0", status
            assert not Path(f"/proc/{state['PID']}").exists()
            print(
                f"PASS {kind} {'stop' if stopping else 'crash'}: stable PID/starttime, "
                f"two ELF images + forced same-ELF exec, READY/RELOADING, exit result; "
                f"FD={counts}, {memory}, idle CPU={ticks} ticks/s"
            )
        except BaseException:
            print(run("journalctl", "-u", unit, "--no-pager", "-n", "80"), file=sys.stderr)
            raise
        finally:
            subprocess.run(["systemctl", "stop", unit], check=False, capture_output=True)
            subprocess.run(["systemctl", "reset-failed", unit], check=False, capture_output=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or os.geteuid() != 0:
        sys.exit(__doc__)
    binary = Path(sys.argv[1]).resolve(strict=True)
    for kind in ("simple", "notify"):
        for stopping in (False, True):
            test(binary, kind, stopping)
