#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Publish image tags only after every requested platform is present."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


def platform_name(platform):
    system = platform['os']
    architecture = platform['architecture']
    variant = platform.get('variant', '')
    if (architecture, variant) in [('arm64', 'v8'), ('amd64', 'v1')]:
        variant = ''
    return '/'.join(part for part in [system, architecture, variant] if part)


def main():
    image = os.environ['IMAGE']
    targets = json.loads(os.environ['MATRIX_JSON'])['include']
    directory = Path(os.environ['DIGEST_DIRECTORY'])
    expected = [target['platform'] for target in targets]
    if not expected or len(set(expected)) != len(expected):
        raise ValueError('Expected platforms must be nonempty and unique')
    for target in targets:
        if target['id'] != target['platform'].replace('/', '-'):
            raise ValueError(f'Invalid platform ID: {target["id"]}')
    filenames = {f'{target["id"]}.digest' for target in targets}
    if {path.name for path in directory.iterdir()} != filenames:
        raise ValueError('Digest artifacts do not match the requested platforms')
    references = []
    for target in targets:
        digest = (directory / f'{target["id"]}.digest').read_text().strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError(f'Invalid image digest for {target["platform"]}')
        references.append(f'{image}@{digest}')

    tags = os.environ['TAGS'].splitlines()
    pattern = re.escape(image) + r':[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}'
    if not tags or any(not re.fullmatch(pattern, tag) for tag in tags):
        raise ValueError('Tags must belong to the prepared image repository')

    command = ['docker', 'buildx', 'imagetools', 'create']
    index = json.loads(subprocess.check_output(command + ['--dry-run', *references],
                                               text=True))
    platforms = []
    for manifest in index['manifests']:
        if manifest.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest':
            continue
        platforms.append(platform_name(manifest['platform']))
    if sorted(platforms) != sorted(expected):
        raise ValueError(f'Image platforms {platforms} do not match {expected}')

    tag_arguments = [argument for tag in tags for argument in ['--tag', tag]]
    subprocess.run(command + tag_arguments + references, check=True)


if __name__ == '__main__':
    try:
        main()
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f'Container publication failed: {error}')
