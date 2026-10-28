#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check guarded kernel mutations without building or loading BPF programs."""

import ast
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RuntimeAblationTest(unittest.TestCase):
    def test_kernel_mutations_match_current_source(self):
        tree = ast.parse((ROOT / 'scripts/runtime-ablation.py').read_text())
        variants = next(ast.literal_eval(node.value) for node in ast.walk(tree)
                        if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == 'kernel_variants'
                                for target in node.targets))
        replace = runpy.run_path(str(ROOT / 'scripts/ablation.py'))['replace']
        source = (ROOT / 'control/kern/tproxy.c').read_text()
        for name, (old, new, _, _) in variants.items():
            if old is None:
                continue
            with self.subTest(variant=name):
                mutated = replace(source, old, new, context=name)
                self.assertNotEqual(mutated, source)
                self.assertNotIn(old, mutated)


if __name__ == '__main__':
    unittest.main()
