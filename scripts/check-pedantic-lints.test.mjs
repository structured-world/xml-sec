import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { EXEMPT, forbiddenLints, listProblems, parseLintHelp, suppressions } from './check-pedantic-lints.mjs';

const manifest = readFileSync(new URL('../Cargo.toml', import.meta.url), 'utf8');
const help = (pedantic, others = []) => [
  ...[...pedantic, ...others].map(name => `   clippy::${name.replaceAll('_', '-')}  allow    some meaning`),
  `clippy::pedantic  ${pedantic.map(name => `clippy::${name.replaceAll('_', '-')}`).join(', ')}`,
].join('\n');
const toolchain = (name, pedantic, others) => ({ name, ...parseLintHelp(help(pedantic, others)) });

test('clippy lint help yields the pedantic group and every known lint', () => {
  const parsed = parseLintHelp(help(['similar_names', 'cast_lossless'], ['unwrap_used']));
  assert.deepEqual([...parsed.pedantic].sort(), ['cast_lossless', 'similar_names']);
  assert.deepEqual([...parsed.known].sort(), ['cast_lossless', 'similar_names', 'unwrap_used']);
  assert.throws(() => parseLintHelp('no groups here'), /no pedantic group/);
});

test('the manifest table yields only forbidden clippy lints', () => {
  const forbidden = forbiddenLints('[workspace.lints.clippy]\npedantic = { level = "warn", priority = -1 }\na_lint = "forbid"\nb_lint = "deny"\n[profile.dev]\nc_lint = "forbid"\n');
  assert.deepEqual([...forbidden], ['a_lint']);
  assert.ok(forbiddenLints(manifest).has('similar_names'));
});

test('a pedantic lint missing from the forbid list is reported', () => {
  // A new pedantic lint known to every toolchain must be forbidden or exempt.
  const toolchains = [toolchain('old', ['a', 'b']), toolchain('new', ['a', 'b'])];
  assert.deepEqual(listProblems(new Set(['a']), toolchains), ['pedantic b of clippy old is neither forbidden nor exempt',
    'pedantic b of clippy new is neither forbidden nor exempt']);
});

test('a lint one toolchain does not know is neither required nor allowed', () => {
  // Listing it would fail that toolchain's lint run as an unknown lint.
  const toolchains = [toolchain('old', ['a', 'renamed']), toolchain('new', ['a', 'added'])];
  assert.deepEqual(listProblems(new Set(['a']), toolchains), []);
  assert.deepEqual(listProblems(new Set(['a', 'added']), toolchains), ['added is forbidden but unknown to clippy old']);
});

test('exempt lints are neither required nor forbidden, and non-pedantic names are refused', () => {
  const exempt = [...EXEMPT.keys()];
  const toolchains = [toolchain('only', ['a', ...exempt], ['unwrap_used'])];
  assert.deepEqual(listProblems(new Set(['a']), toolchains), []);
  assert.deepEqual(listProblems(new Set(['a', exempt[0]]), toolchains), [`${exempt[0]} is exempt and must not be forbidden`]);
  assert.deepEqual(listProblems(new Set(['a', 'unwrap_used']), toolchains), ['unwrap_used is forbidden but pedantic in no toolchain']);
});

test('sources may not suppress an exempt lint or the whole pedantic group', () => {
  const text = [
    '#[allow(clippy::used_underscore_binding)]', 'fn a() {}',
    '#[cfg_attr(test, expect(clippy::used_underscore_binding, reason = "x"))]', 'fn b() {}',
    '#![allow(clippy::pedantic)]',
    '#[allow(clippy::unwrap_used)]', 'fn c() { value.expect("clippy::pedantic is fine in a message"); }',
  ].join('\n');
  assert.deepEqual(suppressions('lib.rs', text), [
    'lib.rs:1: allow(clippy::used_underscore_binding)',
    'lib.rs:3: expect(clippy::used_underscore_binding, reason = "x")',
    'lib.rs:5: allow(clippy::pedantic)',
  ]);
});

test('a reason string with parentheses or quotes does not hide a suppression', () => {
  // Clippy accepts these attributes, so the scanner must see past quoted text.
  const text = [
    '#[allow(clippy::used_underscore_binding, reason = "compatibility (upstream)")]',
    '#[expect(clippy::pedantic, reason = "see \\"foo()\\" here")]',
    '#[allow(clippy::unwrap_used, reason = "not clippy::pedantic, nor clippy::used_underscore_binding")]',
  ].join('\n');
  assert.deepEqual(suppressions('lib.rs', text).map(found => found.split(':').slice(0, 2).join(':')), ['lib.rs:1', 'lib.rs:2']);
});

test('whitespace around the path separator does not hide a suppression', () => {
  // Rust tokenizes `clippy :: pedantic` as the same lint path as `clippy::pedantic`.
  const text = ['#[allow(clippy :: used_underscore_binding)]', '#![expect(clippy::\n  pedantic)]', '#[allow(clippy :: unwrap_used)]'].join('\n');
  assert.deepEqual(suppressions('lib.rs', text).map(found => found.split(':').slice(0, 2).join(':')), ['lib.rs:1', 'lib.rs:2']);
});

test('a local allow of any forbidden pedantic lint fails the lint gate', () => {
  // The workspace lint table, applied to a crate that allows every listed lint
  // locally, must make clippy fail with E0453 for each of them; without the
  // allows the same crate passes, so the failure is the forbid and nothing else.
  const forbidden = [...forbiddenLints(manifest)];
  assert.ok(forbidden.includes('cast_possible_truncation'), 'the manifest forbids pedantic lints by name');
  const table = manifest.slice(manifest.indexOf('[workspace.lints.clippy]')).split('\n').slice(1);
  const end = table.findIndex(line => line.startsWith('['));
  const lints = `[lints.clippy]\n${(end < 0 ? table : table.slice(0, end)).join('\n')}\n`;
  const directory = mkdtempSync(join(tmpdir(), 'xml-sec-pedantic-'));
  try {
    mkdirSync(join(directory, 'src'));
    const clippy = (source, table = lints) => {
      writeFileSync(join(directory, 'Cargo.toml'),
        `[package]\nname = "pedantic-probe"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n[workspace]\n\n${table}`);
      writeFileSync(join(directory, 'src/lib.rs'), source);
      return spawnSync('cargo', ['clippy', '--quiet', '--', '-D', 'warnings'], { cwd: directory, encoding: 'utf8' });
    };
    // Forbidding only the group is not enough: rustc lets a member allow
    // override it with a forbidden_lint_groups warning, and the lint is silenced.
    const truncating = '//! Probe.\n#[allow(clippy::cast_possible_truncation)]\n#[must_use]\npub fn narrow(value: u64) -> u8 { value as u8 }\n';
    const groupOnly = clippy(truncating, '[lints.clippy]\npedantic = { level = "forbid", priority = -1 }\n');
    assert.equal(groupOnly.status, 0, groupOnly.stderr);
    assert.notEqual(clippy(truncating).status, 0);
    const clean = clippy('//! Probe.\n');
    assert.equal(clean.status, 0, clean.stderr);
    const allowed = clippy(`//! Probe.\n#[allow(${forbidden.map(name => `clippy::${name}`).join(', ')})]\npub fn probe() {}\n`);
    assert.notEqual(allowed.status, 0);
    for (const name of forbidden)
      assert.match(allowed.stderr, new RegExp(`E0453.*allow\\(clippy::${name}\\) incompatible with previous forbid`), name);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
