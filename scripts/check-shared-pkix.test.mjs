import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const names = ['structured-asn1', 'structured-pkix', 'structured-cms', 'structured-ltv', 'structured-xades'];
const packages = () => names.map(name => ({ name, version: '0.13.0', source: 'registry+https://github.com/rust-lang/crates.io-index',
  manifest_path: `/store/registry/src/index/${name}-0.13.0/Cargo.toml` }));

function run(shared, failure = false, metadataFailure = false) {
  const directory = mkdtempSync(join(tmpdir(), 'xml-sec-shared-graph-'));
  try {
    const calls = join(directory, 'calls');
    const metadata = join(directory, 'metadata');
    writeFileSync(calls, '');
    writeFileSync(metadata, JSON.stringify({ packages: shared }));
    writeFileSync(join(directory, 'cargo'), `#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';
const args = process.argv.slice(2);
appendFileSync(process.env.CALLS, JSON.stringify(args) + '\\n');
if (args[0] === 'metadata') {
  process.stdout.write(readFileSync(process.env.METADATA));
  if (process.env.FAIL_METADATA === '1') process.exitCode = 37;
}
else if (process.env.FAIL_CHECK === '1') process.exitCode = 37;
`, { mode: 0o755 });
    const result = spawnSync('/bin/bash', [resolve(import.meta.dirname, 'check-shared-pkix.sh')], {
      cwd: resolve(import.meta.dirname, '..'), encoding: 'utf8',
      env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, CALLS: calls, METADATA: metadata,
        FAIL_CHECK: failure ? '1' : '0', FAIL_METADATA: metadataFailure ? '1' : '0' },
    });
    return { ...result, calls: readFileSync(calls, 'utf8').trim().split('\n').map(JSON.parse) };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('the published PKIX and XAdES alloc graphs qualify on both non-std targets', () => {
  // The high XAdES entrypoint must qualify CMS/LTV too, not just a host std union.
  const result = run(packages());
  assert.equal(result.status, 0, result.stderr);
  const checks = result.calls.filter(args => args[0] === 'check');
  assert.equal(checks.length, 4);
  for (const name of ['structured-pkix', 'structured-xades']) {
    for (const target of ['thumbv7em-none-eabihf', 'wasm32-unknown-unknown']) {
      const args = checks.find(args => args.includes(target) && args.some(arg => arg.includes(`/${name}-`)));
      assert.ok(args, `${name} ${target}`);
      assert.ok(args.includes('--locked'));
      assert.ok(args.includes('--no-default-features'));
      assert.equal(args[args.indexOf('--features') + 1], 'alloc');
    }
  }
});

test('mixed generations, duplicate packages and non-registry substitutes fail before checking', () => {
  // A successful PKIX-only probe cannot hide another ASN.1 generation or a local patch.
  const mixed = packages(); mixed[0].version = '0.11.0';
  const local = packages(); local[2].source = null;
  for (const shared of [mixed, local, packages().slice(1), [...packages(), packages()[0]]]) {
    const result = run(shared);
    assert.notEqual(result.status, 0);
    assert.equal(result.calls.filter(args => args[0] === 'check').length, 0);
  }
});

test('a target failure terminates qualification with its original status', () => {
  // Later successful targets must not conceal an alloc-only compile failure.
  const result = run(packages(), true);
  assert.equal(result.status, 37);
  assert.equal(result.calls.filter(args => args[0] === 'check').length, 1);
});

test('a metadata process failure cannot be hidden by valid partial output', () => {
  // A declaration builtin must not mask the metadata pipeline's nonzero exit.
  const result = run(packages(), false, true);
  assert.equal(result.status, 37);
  assert.equal(result.calls.filter(args => args[0] === 'check').length, 0);
});
