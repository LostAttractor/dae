"""Checks for isolated, source-checked queueing ablations."""

import json
import pathlib
import runpy
import subprocess
import sys
import tempfile
import unittest


class AblationTest(unittest.TestCase):
    def test_generation_preserves_source_and_refuses_existing_output(self):
        script = pathlib.Path(__file__).with_name("ablate.py")
        source = script.resolve().parents[3] / "pkg/outbound/netproxy/fq/fq.go"
        before = source.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory) / "variants"
            subprocess.run([sys.executable, str(script), str(out)], check=True, capture_output=True)
            for name in ("base", "no-codel", "no-rate-guard"):
                overlay = json.loads((out / (name + ".json")).read_text())
                self.assertEqual(overlay["Replace"], {str(source): str(out / (name + ".go"))})
            self.assertEqual((out / "base.go").read_bytes(), before)
            self.assertIn("drop := false", (out / "no-codel.go").read_text())
            self.assertNotIn("var frameTime", (out / "no-rate-guard.go").read_text())
            rerun = subprocess.run([sys.executable, str(script), str(out)], capture_output=True)
            self.assertNotEqual(rerun.returncode, 0)
            self.assertEqual((out / "base.go").read_bytes(), before)
        self.assertEqual(source.read_bytes(), before)

    def test_changed_source_is_not_silently_modified(self):
        ablate = runpy.run_path(str(pathlib.Path(__file__).with_name("ablate.py")))
        for source in ("missing", "duplicate duplicate"):
            with self.assertRaises(ValueError):
                ablate["replace_once"](source, "duplicate", "replacement")


if __name__ == "__main__":
    unittest.main()
