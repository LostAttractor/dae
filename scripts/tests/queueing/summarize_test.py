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


    def report(self, cpu=10):
        return {
            "conditions": {
                "rate_bps": 40_000_000, "return_delay": "90ms", "server_frame_writes": "joined-frame", "cc": "bbr", "ecn": "0",
                "workload": {"game": 1, "bulk": 4}, "max_connections": 0,
                "writer_delay": "0s", "socket_samples": False, "udp": "mux", "mptcp": False,
                "download": "", "lan_rate": "", "warmup_s": 3, "duration_s": 20,
                "go_version": "test-go", "goos": "linux", "goarch": "amd64",
            },
            "settle_timeout": False, "late": {}, "upload_unaccounted": 0,
            "download_unaccounted": 0, "cpu_ms_per_gb": cpu,
        }

    def summarize(self, reports):
        summarize = runpy.run_path(str(pathlib.Path(__file__).with_name("summarize.py")))
        output, errors = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as out:
            for name, report in reports.items():
                pathlib.Path(out, name + ".json").write_text(json.dumps(report))
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = summarize["main"](out, ["before", "after"])
        lines = output.getvalue().splitlines()
        header = lines[0].split("\t")
        raw = [dict(zip(header, line.split("\t"))) for line in lines[1:lines.index("")]]
        pair_header, pair = lines[-2].split("\t"), lines[-1].split("\t")
        self.assertEqual(status, int(any(row["invalid"] != "0" for row in raw) or pair[pair_header.index("excluded")] != "0" or pair[pair_header.index("pairs")] == "0"))
        return raw, dict(zip(pair_header, pair)), errors.getvalue()

    def test_invalid_run_cannot_improve_cpu(self):
        invalid = self.report(1)
        invalid["settle_timeout"] = True
        raw, pair, errors = self.summarize({
            "case@before.1": self.report(10), "case@after.1": self.report(11),
            "case@before.2": self.report(10), "case@after.2": invalid,
        })
        after = next(row for row in raw if row["binary"] == "after")
        self.assertEqual(after["invalid"], "1")
        self.assertEqual(after["cpu_ms_per_gb"], "11")
        self.assertEqual(pair["pairs"], "1")
        self.assertEqual(pair["excluded"], "1")
        self.assertEqual(pair["cpu_ms_per_gb"], "+10.0%")
        self.assertIn("excluded invalid pair", errors)

    def test_different_conditions_are_not_paired(self):
        for key, changed in [("rate_bps", 200_000_000), ("socket_samples", True), ("writer_delay", "4ms"), ("go_version", "other-go"), ("server_frame_writes", "split-header")]:
            with self.subTest(key=key):
                before, after = self.report(), self.report(1)
                after["conditions"][key] = changed
                _, pair, errors = self.summarize({"case@before.1": before, "case@after.1": after})
                self.assertEqual(pair["pairs"], "0")
                self.assertEqual(pair["excluded"], "1")
                self.assertEqual(pair["cpu_ms_per_gb"], "-")
                self.assertIn("different conditions", errors)

    def test_missing_counterpart_is_reported(self):
        _, pair, errors = self.summarize({
            "case@before.1": self.report(), "case@after.1": self.report(),
            "case@before.2": self.report(),
        })
        self.assertEqual(pair["pairs"], "1")
        self.assertEqual(pair["excluded"], "1")
        self.assertIn("missing counterpart", errors)

    def test_missing_conditions_or_loss_accounting_are_invalid(self):
        summarize = runpy.run_path(str(pathlib.Path(__file__).with_name("summarize.py")))
        for key in ["conditions", "late", "settle_timeout", "upload_unaccounted", "download_unaccounted"]:
            with self.subTest(key=key):
                report = self.report()
                del report[key]
                self.assertTrue(summarize["invalid_reasons"](report))
        report = self.report()
        report["upload_unaccounted"] = -1
        self.assertIn("upload_unaccounted", summarize["invalid_reasons"](report))


if __name__ == "__main__":
    unittest.main()
