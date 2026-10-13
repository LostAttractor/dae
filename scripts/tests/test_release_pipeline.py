#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify bare release binaries and their checksums using tiny local fixtures."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TARGETS = json.loads((ROOT / 'install/release-targets.json').read_text())


class ReleasePipelineTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='dae release test ')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def create_checksums(self, binary):
        result = subprocess.run([str(ROOT / 'scripts/release-checksums.sh'), str(binary)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def expected_checksums(self, binary):
        data = binary.read_bytes()
        return ''.join(f'{hashlib.new(algorithm, data).hexdigest()}  {binary.name}  {algorithm}\n'
                       for algorithm in ['md5', 'sha1', 'sha256', 'sha512'])

    def test_release_contains_only_binaries_and_checksums_for_every_target(self):
        self.assertEqual(len(TARGETS), 16)
        self.assertEqual(len({t['name'] for t in TARGETS}), len(TARGETS))
        expected_files = set()
        for target in TARGETS:
            with self.subTest(target=target['name']):
                binary = self.directory / f'dae-{target["name"]}'
                data = f'fixture binary for {target["name"]}\n'.encode()
                binary.write_bytes(data)
                binary.chmod(0o755)
                self.create_checksums(binary)
                checksum = binary.with_name(binary.name + '.dgst')
                self.assertEqual(checksum.read_text(), self.expected_checksums(binary))
                self.assertEqual(binary.read_bytes(), data)
                self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
                expected_files.update([binary.name, checksum.name])
        self.assertEqual({p.name for p in self.directory.iterdir()}, expected_files)

    def test_regeneration_replaces_stale_checksums(self):
        binary = self.directory / 'dae-linux-test'
        binary.write_bytes(b'first binary\n')
        self.create_checksums(binary)
        binary.write_bytes(b'updated binary\n')
        self.create_checksums(binary)
        self.assertEqual(binary.with_name(binary.name + '.dgst').read_text(),
                         self.expected_checksums(binary))
        self.assertEqual({p.name for p in self.directory.iterdir()},
                         {binary.name, binary.name + '.dgst'})


if __name__ == '__main__':
    unittest.main()
