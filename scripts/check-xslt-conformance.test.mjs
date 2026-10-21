import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
import { spawnSync } from 'node:child_process';

function runGate(t, overrides = {}) {
  const root = mkdtempSync(join(tmpdir(), 'xml-sec-xslt-gate-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'scripts'));
  mkdirSync(join(root, 'bin'));
  const oracleRoot = overrides.ORACLE_UNDER_TARGET === '1' ? join(root, 'target/oracle') : root;
  mkdirSync(join(oracleRoot, 'bin'), { recursive: true });
  mkdirSync(join(root, 'compatibility'));
  const pinned = '5fdd47dc3575000000000000000000000000000000';
  writeFileSync(join(root, 'compatibility/libxmlsec1-1.3.13-donor-commit.txt'), pinned + '\n');
  writeFileSync(join(oracleRoot, '.xmlsec-source-commit'), (overrides.SOURCE_COMMIT ?? pinned) + '\n');
  copyFileSync(new URL('./check-xslt-conformance.sh', import.meta.url), join(root, 'scripts/check-xslt-conformance.sh'));
  writeFileSync(join(root, 'scripts/import-libxslt-oracle-fixtures.sh'), '#!/bin/bash\nexit 0\n');
  writeFileSync(join(oracleRoot, 'bin/xmlsec1'), `#!/usr/bin/env node
console.log(process.argv[2] === '--version' ? process.env.ORACLE_VERSION : process.env.ORACLE_TRANSFORMS);
`, { mode: 0o755 });
  writeFileSync(join(root, 'bin/cargo'), `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.CALLS, JSON.stringify({args, range:process.env.XML_SEC_LIBXSLT_CASE_RANGE, worker:process.env.XML_SEC_LIBXSLT_CASE})+'\\n');
if (args[0] === 'nextest' && (process.env.FAIL_TESTS === '1' || args.includes(process.env.FAIL_PACKAGE))) process.exit(57);
if (args[0] === 'clean') fs.rmSync('target', { recursive: true, force: true });
if (args[0] === 'nextest' && args.includes('xml-sec') && !fs.existsSync(process.env.XMLSEC1_BIN)) {
  console.log('reciprocal oracle skipped: executable was removed');
}
`, { mode: 0o755 });
  const log = join(root, 'calls');
  const result = spawnSync('/bin/bash', ['scripts/check-xslt-conformance.sh'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 10_000,
    env: {
      ...process.env,
      PATH: `${join(root, 'bin')}${delimiter}${process.env.PATH}`,
      CALLS: log,
      LIBXSLT_SOURCE_DIR: root,
      XMLSEC1_BIN: join(oracleRoot, 'bin/xmlsec1'),
      ORACLE_VERSION: 'xmlsec1 1.3.13 (openssl)',
      ORACLE_TRANSFORMS: '"xslt","sha256"',
      XML_SEC_LIBXSLT_CASE_RANGE: '0..1',
      XML_SEC_LIBXSLT_CASE: '0',
      ...overrides,
    },
  });
  const calls = existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse) : [];
  return { ...result, calls };
}

test('conformance cannot inherit a sliced corpus and cleans the successful gate', t => {
  // A developer's single-case diagnosis must never masquerade as the full gate.
  const result = runGate(t);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.map(call => call.args[0]), ['nextest', 'nextest', 'clean']);
  for (const call of result.calls) {
    assert.equal(call.range, undefined);
    assert.equal(call.worker, undefined);
  }
  assert.match(result.stdout, /XSLT conformance: .*passed/);
});

test('oracle installed under target survives until reciprocal checks finish', t => {
  // Cargo cleanup must not turn admitted reciprocal checks into silent skips.
  const result = runGate(t, { ORACLE_UNDER_TARGET: '1' });
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /oracle skipped/);
  assert.deepEqual(result.calls.map(call => call.args[0]), ['nextest', 'nextest', 'clean']);
});

test('failed suites remain failed and retain build evidence', t => {
  // No cleanup or later successful command can overwrite a failing test status.
  const result = runGate(t, { FAIL_TESTS: '1' });
  assert.equal(result.status, 57, result.stderr);
  assert.equal(result.calls.length, 1);
  assert.doesNotMatch(result.stdout, /passed/);
});

test('failed reciprocal suite retains evidence and never cleans or reports success', t => {
  // The second half's failure must survive the successful engine half.
  const result = runGate(t, { FAIL_PACKAGE: 'xml-sec', ORACLE_UNDER_TARGET: '1' });
  assert.equal(result.status, 57, result.stderr);
  assert.deepEqual(result.calls.map(call => call.args[0]), ['nextest', 'nextest']);
  assert.doesNotMatch(result.stdout, /passed/);
});

for (const overrides of [
  { ORACLE_VERSION: 'xmlsec1 1.3.12 (openssl)' },
  { ORACLE_TRANSFORMS: '"sha256"' },
  { XMLSEC1_BIN: '' },
  { SOURCE_COMMIT: 'different-source-revision' },
]) {
  test(`unqualified oracle fails before tests: ${JSON.stringify(overrides)}`, t => {
    // Missing executables, a different version or a missing XSLT capability
    // cannot fall through to interoperability tests that would silently skip.
    const result = runGate(t, overrides);
    assert.notEqual(result.status, 0);
    assert.deepEqual(result.calls, []);
    assert.doesNotMatch(result.stdout, /passed/);
  });
}
