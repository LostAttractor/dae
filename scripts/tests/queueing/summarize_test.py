"""Self-contained checks for queueing report validity columns."""

import contextlib
import io
import json
import pathlib
import runpy
import tempfile
import unittest


class SummaryTest(unittest.TestCase):
    def test_flood_late_and_timeout_are_not_hidden_by_medians(self):
        summarize = runpy.run_path(str(pathlib.Path(__file__).with_name("summarize.py")))
        with tempfile.TemporaryDirectory() as out:
            for i in range(3):
                report = {
                    "settle_timeout": i == 2,
                    "late": {
                        "flood_up_ms": 7 if i == 2 else 0,
                        "flood_down_ms": 9 if i == 2 else 0,
                    },
                }
                pathlib.Path(out, f"flood@after.{i}.json").write_text(json.dumps(report))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                summarize["main"](out, [])
        header, row = [line.split("\t") for line in output.getvalue().splitlines()]
        values = dict(zip(header, row))
        self.assertEqual(values["late.flood_up_ms"], "7")
        self.assertEqual(values["late.flood_down_ms"], "9")
        self.assertEqual(values["settle_timeout"], "True")


if __name__ == "__main__":
    unittest.main()
