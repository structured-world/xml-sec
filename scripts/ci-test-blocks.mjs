import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const core = backend => `xmldsig,xmlenc,c14n,${backend === 'fat-runtime' ? 'xml-backends-all' : `xml-backend-${backend}`}`;
const profile = (name, features, extra = {}) => ({ name, features, ...extra });
const ordinary = backend => profile(backend, core(backend), { build: true, lint: true });
// Library-only lint graphs whose cfg combinations no tested profile resolves.
const minimal = feature => profile(`${feature}-minimal`, `${feature},xml-backend-differential`,
  { lint: true, lintOnly: true });

// Each profile remains a distinct Cargo invocation: a block shares runner/setup,
// not enabled features. Keep expensive FIPS compilation in its own block.
export const blocks = {
  core: [
    profile('default-features', undefined, { lint: true }),
    ...['xmloxide', 'roxmltree', 'differential', 'fat-runtime'].map(ordinary),
    ...['xmldsig', 'xmldsig-sign', 'xmlenc', 'xslt'].map(minimal),
  ],
  extended: [
    profile('all-features', undefined, { all: true, build: true, lint: true }),
    profile('legacy-fat-runtime', `${core('fat-runtime')},legacy-algorithms`),
    profile('xslt-fat-runtime', `${core('fat-runtime')},xslt`, { lint: true }),
  ],
  experimental: [
    ...['xmloxide', 'roxmltree', 'differential'].map(backend => profile(`experimental-pq-${backend}`,
      `${core(backend)},legacy-algorithms,experimental-pq`, { pq: true, lint: true })),
    profile('xslt-xmloxide', `${core('xmloxide')},xslt`, { lint: true }),
  ],
  fips: [
    profile('legacy-aws-fips', 'aws-lc-fips,xmlenc,c14n,xml-backend-xmloxide,legacy-algorithms', { fips: true, lint: true }),
    ...['xmloxide', 'roxmltree', 'differential', 'fat-runtime'].map(backend => profile(`aws-fips-${backend}`,
      `aws-lc-fips,xmlenc,c14n,${backend === 'fat-runtime' ? 'xml-backends-all' : `xml-backend-${backend}`}`,
      { fips: true, lint: true })),
  ],
};

export function plan(name, module) {
  if (!Object.hasOwn(blocks, name)) throw new Error(`Unknown CI test block: ${name}`);
  const commands = [];
  const add = (label, file, args) => commands.push({ label, file, args });
  if (name === 'fips') add('FIPS without encryption', 'cargo', ['check', '--no-default-features', '--features', 'aws-lc-fips,xml-backend-xmloxide']);
  if (name === 'core') add('xmlenc-inventory: build', 'cargo', ['build', '-p', 'xml-sec', '--no-default-features', '--features', 'xmlenc,xml-backend-xmloxide']);
  for (const profile of blocks[name]) {
    const args = profile.all ? ['--all-features'] : profile.features ? ['--no-default-features', '--features', profile.features] : [];
    if (profile.build) add(`${profile.name}: build`, 'cargo', ['build', '--workspace', ...args]);
    const scope = profile.lintOnly ? ['-p', 'xml-sec', '--lib']
      : [...(profile.pq || profile.fips ? [] : ['--workspace']), '--all-targets'];
    if (profile.lint) add(`${profile.name}: lint`, 'cargo', ['clippy', ...scope, ...args, '--', '-D', 'warnings']);
    if (profile.lintOnly) continue;
    const tests = ['--workspace', ...args, '-E', 'not binary(libxslt_oracle)'];
    if (profile.all) {
      if (!module) throw new Error('PKCS11_MODULE is required for all-feature test blocks');
      add(`${profile.name}: tests`, 'bash', ['scripts/test-pkcs11.sh', module, ...tests]);
    } else add(`${profile.name}: tests`, 'cargo', ['nextest', 'run', ...tests]);
    add(`${profile.name}: docs`, 'cargo', ['test', '--doc', '--workspace', ...args]);
  }
  return commands;
}

export function execute(commands, run) {
  for (const command of commands) {
    console.log(`::group::${command.label}`);
    const result = run(command);
    if (result.error) throw result.error;
    if (result.status !== 0 || result.signal) {
      throw new Error(`${command.label}: status=${result.status}, signal=${result.signal}`);
    }
    console.log('::endgroup::');
  }
}

function main() {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/ci-test-blocks.mjs BLOCK');
  const name = process.argv[2];
  const commands = plan(name, process.env.PKCS11_MODULE);
  const root = resolve(import.meta.dirname, '..');
  execute(commands, command => spawnSync(command.file, command.args, { cwd: root, stdio: 'inherit' }));
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  try { main(); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
