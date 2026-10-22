import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

function run(phase = 'all', extra = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'xml-sec-doc-contract-'));
  try {
    const bin = join(directory, 'bin');
    mkdirSync(bin);
    const calls = join(directory, 'calls');
    writeFileSync(calls, '');
    writeFileSync(join(bin, 'cargo'), `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$CALLS"
if [[ \${FAIL_PHASE:-} == "$1" ]]; then exit 37; fi
if [[ "$1" == doc && "\${RUSTDOCFLAGS:-}" != *'-D warnings -D missing-docs'* ]]; then exit 38; fi
if [[ "$*" == *'--example sign'* ]]; then printf '<Invoice>42.00</Invoice>'; fi
if [[ "$*" == *'--example verify'* && "$*" == *'/tampered.xml'* ]]; then
  if [[ \${ACCEPT_TAMPER:-} == 1 ]]; then exit 0; fi
  echo "\${TAMPER_ERROR:-expected target was not authenticated}" >&2
  exit 1
fi
`, { mode: 0o755 });
    const result = spawnSync('/bin/bash', [resolve(import.meta.dirname, 'check-documentation.sh'), phase], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: calls,
        TMPDIR: directory, FAIL_PHASE: '', ACCEPT_TAMPER: '', TAMPER_ERROR: '', ...extra },
    });
    const text = readFileSync(calls, 'utf8').trim();
    const commands = text ? text.split('\n') : [];
    return { ...result, commands };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('docs-only checks the core and config APIs, not private workspace kernels', () => {
  // A private vendor crate's undocumented internals are not the public core contract.
  const result = run('docs');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.commands, ['doc -p xml-sec -p xml-sec-config --all-features --no-deps']);
});

test('full qualification executes the examples and rejects accepted tampering', () => {
  // Merely compiling examples must not count as runtime qualification.
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  for (const example of ['sign', 'verify', 'encrypt', 'policy_roundtrip']) {
    assert.ok(result.commands.some(command => command.includes(`--example ${example}`)));
  }
  assert.ok(result.commands.some(command => command.includes('--test documentation')));
  assert.notEqual(run('all', { ACCEPT_TAMPER: '1' }).status, 0);
  assert.notEqual(run('all', { TAMPER_ERROR: 'compiler or setup failure' }).status, 0);
});

test('failed prerequisites stop before later phases', () => {
  // A later success or expected negative example cannot hide a real failure.
  for (const phase of ['doc', 'test', 'nextest']) {
    const result = run('all', { FAIL_PHASE: phase });
    assert.equal(result.status, 37);
    assert.ok(!result.commands.some(command => command.includes('--example sign')));
  }
});

test('an unknown phase never runs Cargo', () => {
  // A typo must not silently become a passing docs-only invocation.
  const result = run('unknown');
  assert.equal(result.status, 2);
  assert.deepEqual(result.commands, []);
});

test('the documentation entry pages link to existing local files', () => {
  // These owned guides use ordinary inline links, not arbitrary Markdown input.
  // Check destinations without reading imported fixture payloads.
  const root = resolve(import.meta.dirname, '..');
  for (const file of ['docs/README.md', 'docs/examples.md', 'docs/deployment.md',
    'docs/migration-libxmlsec1.md', 'docs/policy-schema-v1.md']) {
    const absolute = join(root, file);
    for (const [, target] of readFileSync(absolute, 'utf8').matchAll(/\]\(([^)]+)\)/g)) {
      if (/^(https?:|mailto:|#)/.test(target)) continue;
      assert.ok(statSync(resolve(dirname(absolute), target.split('#')[0])).isFile(), `${file}: ${target}`);
    }
  }
});

test('the schema reference lists every resource field admitted by the loader', () => {
  // The loader's one macro list drives both admission and effective output.
  // This is a drift check of that list, not a second TOML/policy implementation.
  const root = resolve(import.meta.dirname, '..');
  const source = readFileSync(join(root, 'crates/xml-sec-config/src/settings.rs'), 'utf8');
  const start = source.indexOf('macro_rules! resource_fields');
  const end = source.indexOf('macro_rules! update_numbers', start);
  assert.ok(start >= 0 && end > start);
  const fields = new Set(source.slice(start, end).match(/\bmax_[a-z0-9_]+\b/g));
  assert.ok(fields.size > 0);
  const guide = readFileSync(join(root, 'docs/policy-schema-v1.md'), 'utf8');
  for (const field of fields) assert.ok(guide.includes(`\`${field}\``), `undocumented resource: ${field}`);
});
