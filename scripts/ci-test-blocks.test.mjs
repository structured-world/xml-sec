import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { blocks, execute, plan } from './ci-test-blocks.mjs';

test('grouping retains every isolated test graph and toolchain', () => {
  // Batching must not turn separate Cargo feature resolutions into a union.
  const profiles = Object.values(blocks).flatMap(block => block.profiles);
  assert.equal(profiles.length, 20);
  assert.equal(new Set(profiles.map(profile => `${profile.rust}:${profile.name}`)).size, 20);
  assert.deepEqual(profiles.map(profile => `${profile.rust}:${profile.name}`).sort(), [
    '1.92.0:all-features', '1.92.0:aws-fips-differential', '1.92.0:aws-fips-fat-runtime',
    '1.92.0:aws-fips-roxmltree', '1.92.0:aws-fips-xmloxide',
    '1.92.0:experimental-pq-differential', '1.92.0:experimental-pq-roxmltree',
    '1.92.0:experimental-pq-xmloxide', '1.92.0:legacy-aws-fips',
    '1.92.0:roxmltree', '1.92.0:xmloxide', '1.92.0:xslt-xmloxide',
    'stable:all-features', 'stable:default-features', 'stable:differential',
    'stable:fat-runtime', 'stable:legacy-fat-runtime', 'stable:roxmltree',
    'stable:xmloxide', 'stable:xslt-fat-runtime',
  ]);
  assert.deepEqual(profiles.filter(profile => profile.all).map(profile => profile.rust).sort(), ['1.92.0', 'stable']);
  assert.equal(profiles.filter(profile => profile.fips).length, 5);
  assert.equal(profiles.filter(profile => profile.pq).length, 3);
  for (const [name, block] of Object.entries(blocks)) {
    assert.ok(block.profiles.every(profile => profile.rust === block.rust), name);
    const commands = plan(name, '/test/token.so');
    assert.equal(commands.filter(command => command.label.endsWith(': tests')).length, block.profiles.length);
    assert.equal(commands.filter(command => command.label.endsWith(': docs')).length, block.profiles.length);
    for (const profile of block.profiles) {
      const command = commands.find(command => command.label === `${profile.name}: tests`);
      assert.ok(command.args.includes('--workspace'));
      assert.deepEqual(command.args.slice(-2), ['-E', 'not binary(libxslt_oracle)']);
      assert.equal(command.file === 'bash', Boolean(profile.all));
      if (profile.all) assert.ok(command.args.includes('/test/token.so'));
    }
  }
});

test('build and lint contracts remain separately resolved', () => {
  // No workspace feature unification may enrich the XMLenc inventory build.
  const commands = Object.keys(blocks).flatMap(name => plan(name, '/test/token.so'));
  assert.equal(commands.filter(command => command.label.endsWith(': build')).length, 9);
  const inventory = commands.find(command => command.label === 'xmlenc-inventory: build');
  assert.deepEqual(inventory.args, ['build', '-p', 'xml-sec', '--no-default-features', '--features', 'xmlenc,xml-backend-xmloxide']);
  assert.equal(commands.filter(command => command.label.endsWith(': lint')).length, 15);
  assert.equal(commands.filter(command => command.label === 'FIPS without encryption').length, 1);
  assert.throws(() => plan('unknown', '/test/token.so'), /Unknown/);
  assert.throws(() => plan('msrv-extended'), /PKCS11_MODULE/);
});

test('the workflow wires every block to its toolchain and retains required aggregates', () => {
  // A correct standalone plan is insufficient if CI omits a block or required check.
  const workflow = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  const wired = [...workflow.matchAll(/- block: ([\w-]+)\n\s+rust: "?([\w.]+)"?/g)]
    .map(([, name, rust]) => [name, rust]);
  assert.deepEqual(wired, Object.entries(blocks).map(([name, block]) => [name, block.rust]));
  for (const name of ['build', 'clippy']) {
    const job = workflow.split(`\n  ${name}:\n`)[1]?.split(/\n  [\w-]+:\n/)[0];
    assert.ok(job, name);
    assert.match(job, /needs: test-matrix/);
    assert.ok(job.includes('always()'));
    assert.ok(job.includes('needs.test-matrix.result'));
    assert.ok(job.includes('= "success"'));
  }
  const oracle = workflow.split('\n  xslt-oracle:\n')[1]?.split(/\n  [\w-]+:\n/)[0];
  assert.ok(oracle.includes('python3 scripts/check-xades-interop.py --output'));
  assert.ok(oracle.includes('bash scripts/check-xslt-conformance.sh'));
  assert.ok(oracle.includes('name: xades-interop-results'));
  assert.ok(oracle.includes('name: xslt-performance'));
});

test('each failed process stops its block without a successful later command', () => {
  // The aggregate must see the original refusal, not a final successful doc test.
  const commands = plan('msrv-core', '/test/token.so');
  for (const failed of [0, 2, commands.length - 1]) {
    const observed = [];
    assert.throws(() => execute(commands, command => {
      observed.push(command);
      return { status: observed.length - 1 === failed ? 37 : 0, signal: null };
    }), /status=37/);
    assert.equal(observed.length, failed + 1);
  }
  for (const failure of [{ status: null, signal: 'SIGTERM' }, { error: new Error('spawn failed') }]) {
    assert.throws(() => execute(commands, () => failure));
  }
  let completed = 0;
  execute(commands, () => { completed++; return { status: 0, signal: null }; });
  assert.equal(completed, commands.length);
});
