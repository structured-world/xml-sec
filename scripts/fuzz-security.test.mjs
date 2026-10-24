import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
import { spawnSync } from 'node:child_process';

function fixture(t, corpusSize, failure = false) {
  const root = mkdtempSync(join(tmpdir(), 'xml-sec-fuzz-runner-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const directory of ['scripts', 'bin', 'fuzz/seeds', 'fuzz/corpus/test_target']) {
    mkdirSync(join(root, directory), { recursive: true });
  }
  copyFileSync(new URL('./fuzz-security.sh', import.meta.url), join(root, 'scripts/fuzz-security.sh'));
  writeFileSync(join(root, 'fuzz/seeds/input'), 'seed');
  writeFileSync(join(root, 'fuzz/seeds.tsv'), 'test_target\tfuzz/seeds/input\n');
  for (let index = 0; index < corpusSize; index += 1) {
    writeFileSync(join(root, 'fuzz/corpus/test_target', `input-${index}`), `input ${index}`);
  }
  writeFileSync(join(root, 'bin/cargo'), `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.CALLS, JSON.stringify(args) + '\\n');
if (args[1] === 'fuzz' && args[2] === 'list') {
  console.log('test_target\\nxmldsig_verify\\nxml_semantics\\nsecurity_roundtrip\\ntransform_parameters\\nxslt_execution\\nkey_formats\\npolicy_compilation\\nprovider_operations');
} else if (args[1] === 'fuzz' && args[2] === 'run') {
  fs.writeFileSync('fuzz/Cargo.lock', 'test lock');
  console.log('mutation execution');
  if (process.env.FAKE_FAILURE === '1') {
    fs.writeFileSync('fuzz/artifacts/' + args[3] + '/crash-input', 'reproducer');
    process.exit(77);
  }
}
`, { mode: 0o755 });
  for (const tool of ['git', 'rustc']) {
    writeFileSync(join(root, 'bin', tool), '#!/usr/bin/env node\nconsole.log("test metadata");\n', { mode: 0o755 });
  }
  const log = join(root, 'calls.jsonl');
  const invoke = (mode, shell = 'bash', fips = false, target = 'test_target', managed = false) => {
    const result = spawnSync(shell, ['scripts/fuzz-security.sh', target, mode, ...(managed ? ['--cache-managed'] : [])], {
      cwd: root,
      encoding: 'utf8',
      timeout: 10_000,
      env: {
        ...process.env,
        PATH: `${join(root, 'bin')}${delimiter}${process.env.PATH}`,
        CALLS: log,
        FAKE_FAILURE: failure ? '1' : '0',
        FUZZ_AWS_LC_FIPS: fips ? '1' : '0',
        FUZZ_OUTPUT: join(root, 'evidence'),
      },
    });
    const calls = readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    return { ...result, calls, run: calls.find(args => args[1] === 'fuzz' && args[2] === 'run') };
  };
  return { root, invoke };
}

test('ASan block executes every target and cleans only after the complete block', t => {
  // Shared compilation must not remove any target or collapse target-specific evidence.
  const { root, invoke } = fixture(t, 0);
  const result = invoke('smoke', '/bin/bash', false, 'asan');
  assert.equal(result.status, 0, result.stderr);
  const targets = ['xmldsig_verify', 'xml_semantics', 'security_roundtrip', 'transform_parameters',
    'xslt_execution', 'key_formats', 'policy_compilation', 'provider_operations'];
  assert.deepEqual(result.calls.filter(args => args[2] === 'run').map(args => args[3]), targets);
  assert.equal(result.calls.filter(args => args[1] === 'clean').length, 1);
  assert.equal(result.calls.at(-1)[1], 'clean');
  for (const target of targets) assert.ok(existsSync(join(root, 'evidence', target, 'run.log')));
});

test('a failed block stops immediately and preserves the build', t => {
  // A later target must never hide a crash from an earlier one.
  const { invoke } = fixture(t, 0, true);
  const result = invoke('smoke', '/bin/bash', false, 'asan');
  assert.equal(result.status, 77, result.stderr);
  assert.equal(result.calls.filter(args => args[2] === 'run').length, 1);
  assert.ok(!result.calls.some(args => args[1] === 'clean'));
});

test('cache-managed execution leaves cleanup to the registered post action', t => {
  // Saving compiled dependencies must precede successful CI cleanup.
  const { invoke } = fixture(t, 0);
  const result = invoke('smoke', '/bin/bash', false, 'test_target', true);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!result.calls.some(args => args[1] === 'clean'));
});

test('smoke admits new mutations after replaying a growing corpus', t => {
  // libFuzzer counts seed execution against -runs; 300 restored entries must
  // not turn the mutation smoke gate into a replay-only pass.
  const { root, invoke } = fixture(t, 300);
  const result = invoke('smoke');
  assert.equal(result.status, 0, result.stderr);
  const corpusSize = readdirSync(join(root, 'fuzz/corpus/test_target')).length;
  assert.ok(Number(result.run.find(arg => arg.startsWith('-runs=')).slice(6)) >= corpusSize + 257);
  assert.ok(result.calls.some(args => args[1] === 'clean'));
  assert.ok(existsSync(join(root, 'evidence/run.log')));
  assert.deepEqual(readdirSync(join(root, 'fuzz/artifacts/test_target')), []);
});

test('crashes survive tee and retain evidence without cleaning the failed build', t => {
  // A failing process must stay red, retain its lock/input/log, and never
  // turn diagnostics into the crash files cargo-fuzz attempts to reproduce.
  const { root, invoke } = fixture(t, 0, true);
  const result = invoke('smoke');
  assert.equal(result.status, 77, result.stderr);
  assert.ok(!result.calls.some(args => args[1] === 'clean'));
  assert.deepEqual(readdirSync(join(root, 'fuzz/artifacts/test_target')), ['crash-input']);
  assert.equal(readFileSync(join(root, 'evidence/Cargo.lock'), 'utf8'), 'test lock');
  assert.match(readFileSync(join(root, 'evidence/run.log'), 'utf8'), /mutation execution/);
});

test('replay is finite and retains the full corpus', t => {
  // Replay-only execution never invents an unbounded fuzz campaign or removes
  // retained inputs; the native target is still responsible for every oracle.
  const { root, invoke } = fixture(t, 3);
  const result = invoke('replay');
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.run.includes('-runs=0'));
  assert.equal(readdirSync(join(root, 'fuzz/corpus/test_target')).length, 4);
});

for (const fips of [false, true]) {
  test(`system Bash preserves optional feature arguments (FIPS=${fips})`, t => {
    // macOS /bin/bash is 3.2: nounset must accept an empty features array,
    // while a populated array must retain both arguments without word loss.
    const { root, invoke } = fixture(t, 0);
    const result = invoke('smoke', '/bin/bash', fips);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.run.includes('--features'), fips);
    assert.equal(result.run.includes('aws-lc-fips'), fips);
    assert.equal(readFileSync(join(root, 'evidence/command.txt'), 'utf8').includes('--features aws-lc-fips'), fips);
    const sanitizer = result.run.indexOf('--sanitizer');
    assert.ok(sanitizer >= 0, 'record an explicit sanitizer mode');
    assert.equal(result.run[sanitizer + 1], fips ? 'none' : 'address');
    assert.match(readFileSync(join(root, 'evidence/command.txt'), 'utf8'),
      fips ? /--sanitizer none/ : /--sanitizer address/);
  });
}
