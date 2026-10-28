"""Check matrix scheduling without namespaces or privileged commands."""

import os
import json
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import unittest


class MatrixTest(unittest.TestCase):
    def test_default_scope_order_and_one_fingerprint_per_binary(self):
        source = pathlib.Path(__file__).parent
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in ("matrix.sh", "summarize.py"):
                (root / name).write_text((source / name).read_text())
            tools = root / "tools"
            tools.mkdir()
            sha = shutil.which("sha256sum")
            self.assertIsNotNone(sha)
            scripts = {
                tools / "sha256sum": f'#!/usr/bin/env bash\nprintf "%s\\n" "$1" >> "$HASH_CALLS"\nexec {shlex.quote(sha)} "$@"\n',
                tools / "go": '#!/usr/bin/env bash\ntags=netgo\nif [[ "$3" == *after.test && "${DIFFERENT_BUILD:-0}" = 1 ]]; then tags=other; fi\nprintf "%s: test-go\\n\\tbuild\\t-tags=%s\\n" "$3" "$tags"\n',
                root / "run.sh": '''#!/usr/bin/env bash
set -eu
label=$2
shift 2
for assignment in "$@"; do export "$assignment"; done
[ "$QEXP_SOCKET_SAMPLES" = false ]
[ "${#QEXP_BINARY}" -eq 64 ]
printf '%s %s\n' "$label" "$QEXP_BINARY" >> "$RUN_LOG"
cp "$VALID_REPORT" "$OUT/$label.json"
''',
            }
            for path, text in scripts.items():
                path.write_text(text)
                path.chmod(0o755)
            report = {
                "conditions": {
                    "rate_bps": 40_000_000, "return_delay": "90ms", "server_frame_writes": "joined-frame", "cc": "bbr", "ecn": "0",
                    "workload": {"game": 1}, "max_connections": 0, "writer_delay": "0s",
                    "socket_samples": False, "udp": "mux", "mptcp": False, "download": "", "lan_rate": "",
                    "warmup_s": 3, "duration_s": 20, "go_version": "test-go", "goos": "linux", "goarch": "amd64",
                },
                "settle_timeout": False, "late": {}, "upload_unaccounted": 0, "download_unaccounted": 0,
            }
            (root / "report").write_text(json.dumps(report))
            before, after = root / "before.test", root / "after.test"
            before.write_text("before")
            after.write_text("after")
            env = dict(os.environ, VALID_REPORT=str(root / "report"), PATH=str(tools) + os.pathsep + os.environ["PATH"], SUDO="env",
                       OUT=str(root / "results"), RUN_LOG=str(root / "runs"), HASH_CALLS=str(root / "hashes"))
            subprocess.run(["bash", str(root / "matrix.sh"), f"{before},{after}"], env=env, check=True, capture_output=True, text=True)
            runs = (root / "runs").read_text().splitlines()
            self.assertEqual([line.split()[0] for line in runs], [
                "normal@before.1", "normal@after.1", "normal@after.2", "normal@before.2",
                "saturated@before.1", "saturated@after.1", "saturated@after.2", "saturated@before.2",
            ])
            self.assertEqual(len({line.split()[1] for line in runs}), 2)
            self.assertEqual((root / "hashes").read_text().splitlines(), [str(before), str(after)])
            self.assertEqual(len(list((root / "results/artifacts").glob("*.build.txt"))), 2)
            env.update(OUT=str(root / "mismatch"), DIFFERENT_BUILD="1")
            result = subprocess.run(["bash", str(root / "matrix.sh"), f"{before},{after}"], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("build settings differ", result.stderr)
            self.assertEqual((root / "runs").read_text().splitlines(), runs, "mismatched builds started experiments")


if __name__ == "__main__":
    unittest.main()
