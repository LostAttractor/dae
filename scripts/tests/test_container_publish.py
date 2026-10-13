#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise digest handoffs and publication gates without a remote registry."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ContainerPublishTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='dae container test ')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.digests = self.directory / 'digests'
        self.digests.mkdir()
        self.targets = [{'platform': platform, 'id': platform.replace('/', '-')}
                        for platform in ['linux/amd64', 'linux/arm64', 'linux/arm/v7', 'linux/386']]
        self.references = []
        manifests = []
        for target in self.targets:
            digest = 'sha256:' + hashlib.sha256(target['platform'].encode()).hexdigest()
            (self.digests / f'{target["id"]}.digest').write_text(digest + '\n')
            self.references.append('registry.example/dae@' + digest)
            parts = target['platform'].split('/')
            platform = {'os': parts[0], 'architecture': parts[1]}
            if len(parts) == 3:
                platform['variant'] = parts[2]
            if platform['architecture'] == 'arm64':
                platform['variant'] = 'v8'
            manifests.append({'digest': digest, 'platform': platform})
        manifests.append({'platform': {'os': 'unknown', 'architecture': 'unknown'},
                          'annotations': {'vnd.docker.reference.type': 'attestation-manifest'}})
        self.index = {'schemaVersion': 2, 'manifests': manifests}
        self.index_path = self.directory / 'index.json'
        self.index_path.write_text(json.dumps(self.index))
        self.log = self.directory / 'docker-calls.jsonl'
        tools = self.directory / 'bin'
        tools.mkdir()
        docker = tools / 'docker'
        docker.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
assert args[:3] == ['buildx', 'imagetools', 'create'], args
with open(os.environ['FIXTURE_CALL_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
if '--dry-run' in args:
    if os.environ.get('FIXTURE_FAIL_DRY_RUN'):
        sys.exit(42)
    print(pathlib.Path(os.environ['FIXTURE_INDEX']).read_text())
''')
        docker.chmod(0o755)
        self.environment = dict(os.environ, PATH=f'{tools}:{os.environ["PATH"]}',
                                IMAGE='registry.example/dae', MATRIX_JSON=json.dumps({'include': self.targets}),
                                DIGEST_DIRECTORY=str(self.digests),
                                TAGS='registry.example/dae:sha-fixture\nregistry.example/dae:next',
                                FIXTURE_CALL_LOG=str(self.log), FIXTURE_INDEX=str(self.index_path))

    def publish(self, **environment):
        return subprocess.run(['python3', str(ROOT / 'scripts/publish-container-index.py')],
                              env=dict(self.environment, **environment), text=True, capture_output=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_complete_index_publishes_all_tags_from_immutable_digests(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [
            ['buildx', 'imagetools', 'create', '--dry-run', *self.references],
            ['buildx', 'imagetools', 'create', '--tag', 'registry.example/dae:sha-fixture',
             '--tag', 'registry.example/dae:next', *self.references],
        ])

    def test_missing_or_extra_digest_artifacts_cannot_publish(self):
        digest = self.digests / 'linux-amd64.digest'
        data = digest.read_text()
        digest.unlink()
        self.assertNotEqual(self.publish().returncode, 0)
        digest.write_text(data)
        (self.digests / 'unexpected.digest').write_text(data)
        self.assertNotEqual(self.publish().returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_invalid_digest_or_foreign_tag_cannot_publish(self):
        self.assertNotEqual(self.publish(TAGS='another.example/dae:next').returncode, 0)
        self.assertNotEqual(self.publish(TAGS='').returncode, 0)
        (self.digests / 'linux-amd64.digest').write_text('sha256:invalid\n')
        self.assertNotEqual(self.publish().returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_incomplete_duplicate_or_wrong_platform_cannot_update_tags(self):
        original = self.index['manifests']
        cases = [original[1:], original + [original[0]],
                 original[:-1] + [{'platform': {'os': 'linux', 'architecture': 'riscv64'}}],
                 original[:-1] + [{'platform': {'os': 'unknown', 'architecture': 'unknown'}}]]
        for manifests in cases:
            with self.subTest(manifests=manifests):
                self.log.unlink(missing_ok=True)
                self.index_path.write_text(json.dumps({'manifests': manifests}))
                result = self.publish()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('do not match', result.stderr)
                self.assertEqual(self.calls(), [['buildx', 'imagetools', 'create', '--dry-run', *self.references]])

    def test_registry_failure_cannot_update_tags(self):
        self.assertNotEqual(self.publish(FIXTURE_FAIL_DRY_RUN='1').returncode, 0)
        self.assertEqual(self.calls(), [['buildx', 'imagetools', 'create', '--dry-run', *self.references]])


if __name__ == '__main__':
    unittest.main()
