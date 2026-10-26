import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildIdentity, cargoConfigs } from './build-identity.mjs';
import { incomparability } from './compare-regression.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const runWith = build => {
  const level = { environment: { platform: 'linux', architecture: 'x64', cpu: 'Xeon', samples: 30, repetitions: 3 } };
  return { cli: { ...level, corpus: [] }, library: level, build };
};

test('a release-profile or flag override changes the build identity', () => {
  // Two runs that differ only in Cargo overrides must not be compared.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-build-identity-'));
  try {
    const plain = buildIdentity({ cli: 'x' }, { CARGO_HOME: directory }, directory);
    for (const override of [{ CARGO_PROFILE_RELEASE_LTO: 'thin' }, { CARGO_ENCODED_RUSTFLAGS: '-Ctarget-cpu=native' }, { CC: 'clang-18' },
      { RUSTC_WRAPPER: 'sccache' }]) {
      const changed = buildIdentity({ cli: 'x' }, { CARGO_HOME: directory, ...override }, directory);
      assert.deepEqual(changed.environment, override);
      assert.deepEqual(incomparability(runWith(plain), runWith(changed)), ['build environment differs']);
    }
    assert.deepEqual(buildIdentity({ cli: 'x' }, { CARGO_HOME: directory, CARGO_TERM_COLOR: 'always', HOME: '/x' }, directory).environment, {});
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test('Cargo configuration files that apply are part of the identity', () => {
  // A profile set in a config file changes the build as much as one in the environment.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-build-identity-'));
  try {
    const home = path.join(directory, 'home');
    const project = path.join(directory, 'project', 'nested');
    fs.mkdirSync(home);
    fs.mkdirSync(project, { recursive: true });
    const before = cargoConfigs(project, { CARGO_HOME: home });
    fs.mkdirSync(path.join(directory, 'project', '.cargo'));
    fs.writeFileSync(path.join(directory, 'project', '.cargo', 'config.toml'), '[profile.release]\nlto = "thin"\n');
    fs.writeFileSync(path.join(home, 'config.toml'), '[build]\njobs = 2\n');
    const after = cargoConfigs(project, { CARGO_HOME: home });
    assert.equal(after.length, before.length + 2);
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test('swapping configuration between the project and CARGO_HOME changes the identity', () => {
  // The deeper directory wins in Cargo, so the same two files in swapped places build differently.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-build-identity-'));
  try {
    const home = path.join(directory, 'home');
    const project = path.join(directory, 'project');
    fs.mkdirSync(home);
    fs.mkdirSync(path.join(project, '.cargo'), { recursive: true });
    const write = (projectLevel, homeLevel) => {
      fs.writeFileSync(path.join(project, '.cargo', 'config.toml'), `[profile.release]\nopt-level = ${projectLevel}\n`);
      fs.writeFileSync(path.join(home, 'config.toml'), `[profile.release]\nopt-level = ${homeLevel}\n`);
      return cargoConfigs(project, { CARGO_HOME: home });
    };
    const projectOptimized = write(3, 0);
    const homeOptimized = write(0, 3);
    assert.notDeepEqual(projectOptimized, homeOptimized);
    assert.deepEqual(projectOptimized.map(({ sha256, ...role }) => role).slice(-1), [{ location: 'cargo_home', file: 'config.toml' }]);
    assert.deepEqual(projectOptimized[0], { ...projectOptimized[0], location: 'directory', levels: 0, file: 'config.toml' });
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test('an identity that cannot be recorded fails instead of writing a partial one', () => {
  // Without a working compiler the run could not prove which build it measured.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-build-identity-'));
  try {
    fs.writeFileSync(path.join(directory, 'rustc'), '#!/bin/sh\nexit 3\n', { mode: 0o755 });
    const result = spawnSync(process.execPath, ['scripts/build-identity.mjs', 'cli=x'],
      { cwd: root, encoding: 'utf8', env: { ...process.env, PATH: `${directory}:${process.env.PATH}` } });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /cannot record the build identity: rustc -V failed/);
    assert.equal(result.stdout, '');
    const usage = spawnSync(process.execPath, ['scripts/build-identity.mjs', 'no-separator'], { cwd: root, encoding: 'utf8' });
    assert.notEqual(usage.status, 0);
    const written = spawnSync(process.execPath, ['scripts/build-identity.mjs', 'cli=benchmark-internals,xslt', 'heap=true'], { cwd: root, encoding: 'utf8' });
    assert.equal(written.status, 0, written.stderr);
    assert.deepEqual(JSON.parse(written.stdout).selections, { cli: 'benchmark-internals,xslt', heap: 'true' });
  } finally { fs.rmSync(directory, { recursive: true }); }
});
