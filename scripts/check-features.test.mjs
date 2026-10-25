import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const script = resolve(import.meta.dirname, 'check-features.sh');

function run(profile, phase = 'all', extra = {}, shell = 'bash') {
  const directory = mkdtempSync(join(tmpdir(), 'xml-sec-feature-runner-'));
  try {
    const bin = join(directory, 'bin');
    mkdirSync(bin);
    const calls = join(directory, 'calls');
    // Only Cargo is replaced: execute the real runner with adversarial outcomes.
    writeFileSync(join(bin, 'cargo'), `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$CALLS"
if [[ \${FAIL_PHASE:-} == "$1" ]]; then exit 37; fi
if [[ $* == *'--no-default-features'* && $* != *'--features'* ]]; then
  if [[ \${NO_BACKEND_COMPILES:-} == 1 ]]; then exit 0; fi
  printf '%s\\n' "\${BACKEND_ERROR:-compile at least one XML backend}" >&2
  exit 101
fi
`, { mode: 0o755 });
    writeFileSync(join(bin, 'rustc'), `#!/usr/bin/env bash
printf 'rustc %s (fixture)\\n' "\${RUSTC_VERSION:-1.95.0}"
`, { mode: 0o755 });
    const result = spawnSync(shell, [script, profile, phase], {
      encoding: 'utf8',
      env: {
        ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: calls,
        FAIL_PHASE: '', BACKEND_ERROR: '', NO_BACKEND_COMPILES: '', ...extra,
      },
    });
    let commands = [];
    try { commands = readFileSync(calls, 'utf8').trim().split('\n'); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    return { ...result, commands };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('minimal signature checks isolate the package and do not enable encryption', () => {
  // Workspace defaults must not make an invalid minimal core appear healthy.
  const result = run('dsig-roxmltree');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.commands, [
    'clippy -p xml-sec --no-default-features --features xmldsig,xml-backend-roxmltree --all-targets -- -D warnings',
    'nextest run -p xml-sec --no-default-features --features xmldsig,xml-backend-roxmltree --lib --test rust_api',
    'test --doc -p xml-sec --no-default-features --features xmldsig,xml-backend-roxmltree',
  ]);
});

test('default qualification uses actual defaults rather than a hand-built equivalent', () => {
  // A newly added default feature must automatically enter this gate.
  const result = run('default', 'test');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.commands, ['nextest run -p xml-sec --lib --test rust_api']);
});

test('default profile works under the operating system Bash', () => {
  // macOS supplies Bash 3.2: empty arrays under nounset must not break defaults.
  const result = run('default', 'all', {}, '/bin/bash');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.commands.length, 3);
});

test('each failed phase terminates qualification without running later phases', () => {
  // A successful subsequent Cargo invocation must not mask an earlier failure.
  for (const [phase, calls] of [['clippy', 1], ['nextest', 2], ['test', 3]]) {
    const result = run('xmlenc-xmloxide', 'all', { FAIL_PHASE: phase });
    assert.equal(result.status, 37);
    assert.equal(result.commands.length, calls);
  }
});

test('missing backend is accepted only for the intended compile diagnostic', () => {
  // A broken dependency or missing tool is not proof of the backend contract.
  const result = run('no-backend');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.commands, ['check -p xml-sec --lib --no-default-features']);
  assert.notEqual(run('no-backend', 'all', { BACKEND_ERROR: 'registry unavailable' }).status, 0);
  assert.notEqual(run('no-backend', 'all', { NO_BACKEND_COMPILES: '1' }).status, 0);
});

test('each minimal profile selects only its declared feature graph', () => {
  // In particular XMLEnc, PQ and FIPS must not gain C14N or other providers
  // merely because the enclosing workspace has richer defaults.
  const profiles = {
    'dom-xmloxide': 'xml-backend-xmloxide',
    'dom-roxmltree': 'xml-backend-roxmltree',
    'c14n-xmloxide': 'c14n,xml-backend-xmloxide',
    'c14n-roxmltree': 'c14n,xml-backend-roxmltree',
    'dsig-xmloxide': 'xmldsig,xml-backend-xmloxide',
    'dsig-roxmltree': 'xmldsig,xml-backend-roxmltree',
    'xmlenc-xmloxide': 'xmlenc,xml-backend-xmloxide',
    'xmlenc-roxmltree': 'xmlenc,xml-backend-roxmltree',
    xslt: 'xslt,xml-backend-xmloxide',
    legacy: 'xmldsig,legacy-algorithms,xml-backend-xmloxide',
    experimental: 'experimental-pq,xml-backend-xmloxide',
    'fips-dsig': 'aws-lc-fips,xml-backend-xmloxide',
    pkcs11: 'pkcs11,xml-backend-xmloxide',
  };
  for (const [profile, features] of Object.entries(profiles)) {
    const result = run(profile, 'lint');
    assert.equal(result.status, 0, `${profile}: ${result.stderr}`);
    assert.deepEqual(result.commands, [
      `clippy -p xml-sec --no-default-features --features ${features} --all-targets -- -D warnings`,
    ]);
  }
});

test('only clippy releases with the harness false positive relax it', () => {
  // Older clippy flags the generated libtest array; current clippy must keep
  // large_stack_arrays for real arrays, so the relaxation is version-bound.
  for (const [version, extra] of [['1.92.0', ' -A clippy::large_stack_arrays'], ['1.94.1', '']]) {
    const result = run('dsig-xmloxide', 'lint', { RUSTC_VERSION: version });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.commands, [
      `clippy -p xml-sec --no-default-features --features xmldsig,xml-backend-xmloxide --all-targets -- -D warnings${extra}`,
    ]);
  }
});

test('token tests execute the real disposable-store harness', () => {
  // The runner must not turn a missing native module into an ignored test;
  // with explicit setup its Cargo arguments retain the isolated core graph.
  const result = run('pkcs11', 'test', { PKCS11_MODULE: '/explicit/test/module.so' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.commands, [
    'nextest run --features pkcs11 --test pkcs11 -p xml-sec --no-default-features --features pkcs11,xml-backend-xmloxide --lib --test rust_api --no-capture',
  ]);
});

test('unknown profiles, phases and missing token setup fail before Cargo', () => {
  // Typos and absent native setup must never silently fall back to defaults.
  for (const [profile, phase] of [['unknown', 'all'], ['default', 'typo'], ['pkcs11', 'test']]) {
    const result = run(profile, phase, { PKCS11_MODULE: '' });
    assert.notEqual(result.status, 0);
    assert.deepEqual(result.commands, []);
  }
});
