#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check memory sampling across transient exec gaps without running a daemon."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
with mock.patch('shutil.which', side_effect=lambda name, path: '/fixtures/' + name):
    MemorySampler = runpy.run_path(str(ROOT / 'scripts/test-process-replacement.py'))['MemorySampler']


class MemorySamplerTest(unittest.TestCase):
    def finish(self, samples):
        sampler = MemorySampler.__new__(MemorySampler)
        sampler.samples, sampler.errors = samples, []
        sampler.stop, sampler.thread = threading.Event(), mock.Mock()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            sampler.finish({})
        return json.loads(output.getvalue().split(': ', 1)[1])

    def test_exec_gap_does_not_discard_valid_measurements(self):
        empty = {'pss_kb': 0, 'private_kb': 0, 'processes': []}
        measured = {'pss_kb': 20, 'private_kb': 10, 'processes': [{'pid': 7}]}
        report = self.finish([empty, measured, empty])
        self.assertEqual(report['replacement_suite_peak'],
                         {'pss_kb': 20, 'private_kb': 10, 'process_count': 1})
        self.assertEqual(report['samples'], 1)

    def test_missing_measurements_still_fail(self):
        for samples in ([], [{'pss_kb': 0, 'private_kb': 0, 'processes': []}]):
            with self.subTest(samples=samples), self.assertRaises(AssertionError):
                self.finish(samples)


if __name__ == '__main__':
    unittest.main()
