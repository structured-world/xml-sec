// Prints the build identity a regression report requires to match between two
// comparison runs. Usage: build-identity.mjs NAME=VALUE... (the runner's recorded
// selections: features, native flags, heap mode, competitor revisions).
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// Environment that changes what Cargo or the C compiler build, beyond the manifest.
const OVERRIDE = /^(RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_INCREMENTAL|CARGO_BUILD_[A-Z0-9_]+|CARGO_PROFILE_[A-Z0-9_]+|CARGO_TARGET_[A-Z0-9_]+|CC|CFLAGS|RUSTC)$/;

const version = (command, args) => {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.error || result.status !== 0) throw Error(`cannot record the build identity: ${command} ${args.join(' ')} failed`);
  return result.stdout.split('\n')[0].trim();
};

/** Digests of every Cargo configuration file Cargo would read from this directory. */
export function cargoConfigs(directory, environment) {
  const candidates = [];
  for (let current = path.resolve(directory); ; current = path.dirname(current)) {
    candidates.push(path.join(current, '.cargo', 'config.toml'), path.join(current, '.cargo', 'config'));
    if (path.dirname(current) === current) break;
  }
  const home = environment.CARGO_HOME ?? path.join(os.homedir(), '.cargo');
  candidates.push(path.join(home, 'config.toml'), path.join(home, 'config'));
  return [...new Set(candidates)].filter(file => fs.existsSync(file))
    .map(file => createHash('sha256').update(fs.readFileSync(file)).digest('hex')).sort();
}

/** The identity object; throws when a required part cannot be recorded. */
export function buildIdentity(selections, environment, directory) {
  const overrides = Object.fromEntries(Object.keys(environment).filter(name => OVERRIDE.test(name)).sort()
    .map(name => [name, environment[name]]));
  return { schema: 1, profile: 'release', rustc: version('rustc', ['-V']), cc: version('cc', ['--version']),
    environment: overrides, cargo_configs: cargoConfigs(directory, environment), selections };
}

function main() {
  const selections = {};
  for (const argument of process.argv.slice(2)) {
    const separator = argument.indexOf('=');
    if (separator <= 0) throw Error(`Usage: build-identity.mjs NAME=VALUE..., got ${argument}`);
    selections[argument.slice(0, separator)] = argument.slice(separator + 1);
  }
  process.stdout.write(`${JSON.stringify(buildIdentity(selections, process.env, process.cwd()))}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
