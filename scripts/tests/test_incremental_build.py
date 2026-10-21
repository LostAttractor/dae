#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check Make's invalidation rules with local compiler and frontend fixtures."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = r'''
import json, os, pathlib, shutil, sys
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
def record():
    with (root / 'calls.jsonl').open('a') as f:
        f.write(json.dumps([name, *args]) + '\n')
if name in ('clang', 'llvm-strip', 'node'):
    print((root / 'tool-version').read_text())
elif name == 'go':
    if args[0] == 'env':
        print({'GOARCH': 'amd64', 'GOVERSION': 'go1.27.3'}[args[1]])
    elif args[0] == 'generate':
        record()
        if os.environ.get('FAIL_GENERATE'):
            sys.exit(1)
        prefixes = ['control/bpf_bpfel', 'control/bpf_bpfeb'] if 'control/' in args[1] else ['trace/bpf_x86_bpfel']
        for prefix in prefixes:
            for suffix in ('.go', '.o', '.o.gz'):
                write(root / (prefix + suffix), os.environ['BPF_CFLAGS'])
        write(root / 'internal/routingabi/abi_generated.go', 'fixture')
    else:
        raise RuntimeError(args)
elif name == 'pnpm':
    if args[0] == 'install':
        path = root / 'node_modules/.modules.yaml'
        if not path.exists():
            write(path, 'fixture')
    elif args[:2] == ['run', 'build']:
        record()
        if os.environ.get('FAIL_WEB'):
            sys.exit(1)
        output = pathlib.Path(args[2])
        shutil.rmtree(output, ignore_errors=True)
        write(output / 'index.html', 'fixture')
        write(output / 'assets/app.js', 'fixture')
    else:
        raise RuntimeError(args)
'''


class IncrementalBuildTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='dae-build-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for path in ('Makefile', 'web/Makefile'):
            self.write(path, (ROOT / path).read_text())
        for path in ('go.mod', 'go.sum', '.gitmodules', 'control/control.go',
                     'trace/trace.go', 'control/kern/main.c', 'trace/kern/main.c',
                     'kern/headers/nested/header.h', 'cmd/dae-bpf-pack/main.go',
                     'web/src/app.ts', 'web/tooling/tool.ts', 'web/tests/test.ts',
                     'web/package.json', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml'):
            self.write(path, '')
        self.write('tool-version', 'fixture-1')
        for name in ('go', 'clang', 'llvm-strip', 'node', 'pnpm'):
            self.write('bin/' + name, '#!' + sys.executable + '\n' + TOOL)
            (self.root / 'bin' / name).chmod(0o755)
        self.environment = dict(os.environ, FIXTURE_ROOT=str(self.root),
                                PATH=f'{self.root / "bin"}:{os.environ["PATH"]}')
        for name in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'CLANG', 'STRIP'):
            self.environment.pop(name, None)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def make(self, *targets, success=True, **environment):
        result = subprocess.run(['make', '-j4', '--no-print-directory', *targets], cwd=self.root,
                                env=dict(self.environment, **environment), text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)

    def calls(self, tool):
        return [c for line in (self.root / 'calls.jsonl').read_text().splitlines()
                if (c := json.loads(line))[0] == tool]

    def test_ebpf_sources_options_tools_outputs_and_retry(self):
        self.make('ebpf')
        count = len(self.calls('go'))
        self.make('ebpf')
        self.assertEqual(len(self.calls('go')), count)
        for name in ('kern/headers/nested/header.h', 'control/kern/added.h', 'tool-version'):
            self.write(name, 'changed')
            self.make('ebpf')
            count += 2
            self.assertEqual(len(self.calls('go')), count)
        (self.root / 'control/kern/added.h').unlink()
        self.make('ebpf')
        self.assertEqual(len(self.calls('go')), count + 2)
        self.make('ebpf', 'MAX_DOMAIN_ROUTING_NUM=1234')
        self.assertIn('-DMAX_DOMAIN_ROUTING_NUM=1234', (self.root / 'control/bpf_bpfel.o').read_text())
        (self.root / 'control/bpf_bpfel.o.gz').unlink()
        self.make('ebpf', 'MAX_DOMAIN_ROUTING_NUM=1234')
        self.assertTrue((self.root / 'control/bpf_bpfel.o.gz').exists())
        self.make('ebpf', 'GOARCH=386')
        self.assertEqual((self.root / '.build_tags').read_text(), '\n')
        self.assertFalse((self.root / 'trace/bpf_x86_bpfel.go').exists())
        self.make('ebpf', success=False, FAIL_GENERATE='1')
        self.make('ebpf')
        self.assertEqual((self.root / '.build_tags').read_text(), 'trace\n')

    def test_web_sources_destination_outputs_copy_and_retry(self):
        self.make('web-assets')
        index = self.root / 'internal/webui/assets/index.html'
        modified = index.stat().st_mtime_ns
        self.make('web-assets')
        self.assertEqual(len(self.calls('pnpm')), 1)
        self.assertEqual(index.stat().st_mtime_ns, modified)
        for name in ('web/src/app.ts', 'web/src/added.ts'):
            self.write(name, 'changed')
            self.make('web-assets')
        (self.root / 'web/src/added.ts').unlink()
        self.make('web-assets')
        self.assertEqual(len(self.calls('pnpm')), 4)
        index.unlink()
        self.make('web-assets')
        self.assertTrue(index.exists())
        self.assertEqual(len(self.calls('pnpm')), 4)
        (self.root / 'build/web/assets/app.js').unlink()
        self.make('web-assets')
        self.assertEqual(len(self.calls('pnpm')), 5)
        self.make('web-assets', 'WEB_OUTPUT=build/other')
        self.assertTrue((self.root / 'build/other/index.html').exists())
        self.make('web-assets', success=False, FAIL_WEB='1')
        self.make('web-assets')
        shutil.rmtree(self.root / 'node_modules')
        self.make('web-assets')
        self.assertTrue((self.root / 'node_modules/.modules.yaml').exists())


if __name__ == '__main__':
    unittest.main()
