import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { remark } from 'remark';
import headingIds from './heading-ids.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));

function run(cwd, command, args) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', timeout: 30_000 });
  assert.ifError(result.error);
  return { status: result.status, output: result.stdout + result.stderr };
}

function fixture(t) {
  const cwd = mkdtempSync(join(tmpdir(), 'dae-doc-tools-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  for (const path of ['package.json', '.markdownlint.jsonc', 'hack/docs']) {
    cpSync(join(root, path), join(cwd, path), { recursive: true });
  }
  symlinkSync(join(root, 'node_modules'), join(cwd, 'node_modules'), 'dir');
  mkdirSync(join(cwd, 'docs', 'nested'), { recursive: true });
  writeFileSync(join(cwd, 'README.md'), '# Documentation\n');
  writeFileSync(join(cwd, 'README.zh.md'), '# Documentation\n');
  for (const directory of ['plugins/fixture', 'pkg/outbound', 'component/plugin']) {
    mkdirSync(join(cwd, directory), { recursive: true });
    writeFileSync(join(cwd, directory, 'README.md'), '# Component\n');
  }
  assert.equal(run(cwd, 'git', ['init', '--quiet']).status, 0);
  assert.equal(run(cwd, 'git', ['remote', 'add', 'origin', 'https://github.com/daeuniverse/dae']).status, 0);
  return cwd;
}

function npm(cwd, script) {
  return run(cwd, 'npm', ['run', '--silent', script]);
}

test('link checks preserve explicit IDs, generated IDs and cross-file validation', (t) => {
  const cwd = fixture(t);
  writeFileSync(join(cwd, 'docs', 'nested', 'target.md'), [
    '# Target', '',
    '## Explicit **heading** {#chosen-id}', '',
    '## Ordinary heading', '',
    '## Ordinary heading', '',
    '## *Emphasis*', '',
  ].join('\n'));
  const valid = '# Links\n\n' + [
    '[Explicit](docs/nested/target.md#chosen-id)',
    '[Ordinary](docs/nested/target.md#ordinary-heading)',
    '[Duplicate](docs/nested/target.md#ordinary-heading-1)',
    '[Emphasis](docs/nested/target.md#emphasis)',
  ].join('\n') + '\n';
  writeFileSync(join(cwd, 'README.zh.md'), valid);
  let result = npm(cwd, 'check-broken-link');
  assert.equal(result.status, 0, result.output);
  assert.equal(readFileSync(join(cwd, 'README.zh.md'), 'utf8'), valid);

  for (const target of ['target.md#missing', 'missing.md']) {
    writeFileSync(join(cwd, 'README.zh.md'), `# Broken\n\n[Link](docs/nested/${target})\n`);
    result = npm(cwd, 'check-broken-link');
    assert.equal(result.status, 1, result.output);
    assert.match(result.output, /missing/i);
  }
});

test('explicit heading IDs preserve spaces and tolerate headings without text', () => {
  const processor = remark().use(headingIds);
  const tree = processor.runSync(processor.parse([
    '# Space {#space id}', '', '# *Emphasis*', '', '#', '', '# Empty {#}', '',
    '# Invalid {#bad}suffix}', '', '# Last {#first} {#last}', '',
  ].join('\n')));
  assert.deepEqual(tree.children.map((node) => node.data?.id), [
    'space id', undefined, undefined, undefined, undefined, 'last',
  ]);
});

test('lint commands keep custom rules, recursive discovery and automatic fixes', (t) => {
  const cwd = fixture(t);
  const path = join(cwd, 'docs', 'nested', 'guide.md');
  writeFileSync(path, '# Guide\n\ngithub and [link](https://example.com/).\n');
  let result = npm(cwd, 'markdown-lint');
  assert.equal(result.status, 1, result.output);
  assert.match(result.output, /enhanced-proper-names/);
  assert.match(result.output, /no-trailing-slash-in-links/);

  writeFileSync(path, '# Guide\n\nGitHub is available.   \n');
  result = npm(cwd, 'markdown-lint-fix');
  assert.equal(result.status, 0, result.output);
  assert.equal(readFileSync(path, 'utf8'), '# Guide\n\nGitHub is available.\n');

  writeFileSync(join(cwd, 'README.zh.md'), '# Guide\n\ngithub\n');
  result = npm(cwd, 'markdown-lint');
  assert.equal(result.status, 1, result.output);
  assert.match(result.output, /README.zh.md/);
});

test('format and brace patterns in Markdown remain ordinary text', (t) => {
  const cwd = fixture(t);
  const text = '# Literal patterns\n\n```text\n' +
    '{'.repeat(10_000) + 'x' + '}'.repeat(10_000) + '\n%.1000000f\n```\n';
  writeFileSync(join(cwd, 'docs', 'patterns.md'), text);
  for (const script of ['check-broken-link', 'markdown-lint']) {
    const result = npm(cwd, script);
    assert.equal(result.status, 0, result.output);
  }
  assert.equal(readFileSync(join(cwd, 'docs', 'patterns.md'), 'utf8'), text);
});
