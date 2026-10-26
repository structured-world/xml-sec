// Keeps the per-lint `forbid` list in the workspace manifest equal to clippy's
// pedantic group, and rejects sources that allow the pedantic lints the list
// cannot forbid. Usage: check-pedantic-lints.mjs TOOLCHAIN...
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Pedantic lints that stay out of the forbid list, each with its reason.
export const EXEMPT = new Map([
  ['used_underscore_binding', "thiserror's derive allows it in its own expansion"],
  ['large_stack_arrays', 'clippy 1.92 reports the libtest harness (rust-lang/rust-clippy#13774); CI allows it on that toolchain'],
]);

const normalize = name => name.trim().replace(/^clippy::/, '').replaceAll('-', '_');

/** Pedantic members and every known clippy lint, from `clippy-driver -W help`. */
export function parseLintHelp(text) {
  const lines = text.split('\n').map(line => line.trim());
  const group = lines.find(line => line.startsWith('clippy::pedantic '));
  if (!group) throw Error('clippy lint help lists no pedantic group');
  const pedantic = new Set(group.slice('clippy::pedantic'.length).split(',').map(normalize).filter(Boolean));
  const known = new Set(lines.filter(line => /^clippy::[a-z0-9-]+\s+(allow|warn|deny|forbid)\s/.test(line))
    .map(line => normalize(line.split(/\s+/)[0])));
  return { pedantic, known };
}

/** Lints the workspace manifest forbids by name in `[workspace.lints.clippy]`. */
export function forbiddenLints(manifest) {
  const start = manifest.indexOf('[workspace.lints.clippy]');
  if (start < 0) throw Error('the manifest has no [workspace.lints.clippy] table');
  const body = manifest.slice(start).split('\n').slice(1);
  const end = body.findIndex(line => line.startsWith('['));
  const forbidden = new Set();
  for (const line of end < 0 ? body : body.slice(0, end)) {
    const entry = /^([a-z0-9_]+)\s*=\s*"forbid"\s*$/.exec(line.trim());
    if (entry) forbidden.add(entry[1]);
  }
  return forbidden;
}

/** Every inconsistency between the forbid list and the given toolchains' clippy. */
export function listProblems(forbidden, toolchains) {
  const problems = [];
  for (const { name, pedantic, known } of toolchains) {
    for (const lint of forbidden)
      if (!known.has(lint)) problems.push(`${lint} is forbidden but unknown to clippy ${name}`);
    for (const lint of pedantic) {
      if (forbidden.has(lint) || EXEMPT.has(lint)) continue;
      // A lint another toolchain does not know cannot be listed; that toolchain
      // already fails a local allow of it as an unknown or renamed lint.
      const unknownElsewhere = toolchains.some(other => !other.known.has(lint));
      if (!unknownElsewhere) problems.push(`pedantic ${lint} of clippy ${name} is neither forbidden nor exempt`);
    }
  }
  for (const lint of forbidden)
    if (!toolchains.some(({ pedantic }) => pedantic.has(lint))) problems.push(`${lint} is forbidden but pedantic in no toolchain`);
  for (const lint of EXEMPT.keys())
    if (forbidden.has(lint)) problems.push(`${lint} is exempt and must not be forbidden`);
  return problems;
}

/** Allow/expect attributes naming the pedantic group or an exempt lint. */
export function suppressions(path, text) {
  const found = [];
  const names = new Set(['pedantic', ...EXEMPT.keys()]);
  // Arguments may hold quoted reasons with parentheses or escaped quotes.
  for (const match of text.matchAll(/\b(?:allow|expect)\s*\(((?:[^()"]|"(?:[^"\\]|\\.)*")*)\)/g)) {
    // A reason's own text is not a lint name, however it is worded.
    for (const item of match[1].replace(/"(?:[^"\\]|\\.)*"/g, '""').split(',')) {
      const lint = item.trim();
      if (lint.startsWith('clippy::') && names.has(normalize(lint))) {
        const line = text.slice(0, match.index).split('\n').length;
        found.push(`${path}:${line}: ${match[0]}`);
      }
    }
  }
  return found;
}

function main() {
  const toolchainNames = process.argv.slice(2);
  if (toolchainNames.length === 0) throw Error('usage: check-pedantic-lints.mjs TOOLCHAIN...');
  const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const toolchains = toolchainNames.map(name => {
    const help = spawnSync('rustup', ['run', name, 'clippy-driver', '-W', 'help'], { encoding: 'utf8', maxBuffer: 16 << 20 });
    if (help.error || help.status !== 0) throw Error(`clippy ${name} lint help failed: ${help.error ?? help.stderr}`);
    return { name, ...parseLintHelp(help.stdout) };
  });
  const problems = listProblems(forbiddenLints(readFileSync(join(root, 'Cargo.toml'), 'utf8')), toolchains);
  const files = spawnSync('git', ['ls-files', '-z', '--', '*.rs'], { cwd: root, encoding: 'utf8' });
  if (files.error || files.status !== 0) throw Error(`listing sources failed: ${files.error ?? files.stderr}`);
  for (const path of files.stdout.split('\0').filter(Boolean))
    problems.push(...suppressions(path, readFileSync(join(root, path), 'utf8')).map(found => `suppressed: ${found}`));
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    process.exitCode = 1;
    return;
  }
  console.log(`Pedantic lint list matches clippy ${toolchainNames.join(', ')}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
