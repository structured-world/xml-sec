import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  percentile, resources, heapStats, createEvidenceDirectory,
  SCENARIOS, unsupported, documentBody, tamper, wrap, engineArguments, caseFiles, policyRefusal,
} from './compare-security.mjs';

test('only a default resource-limit refusal is recorded instead of failing', () => {
  // An engine over its own default limit is reported with its reason; any other failure,
  // including an invalid signature, must still stop the comparison.
  assert.equal(
    policyRefusal('Error: XML signature operation failed: signing policy violation: XSLT workspace bytes exceeds policy maximum 67108864: got 67280426\n'),
    'XSLT workspace bytes exceeds policy maximum 67108864: got 67280426',
  );
  assert.equal(policyRefusal('Error: signature verification failed: digest mismatch\n'), undefined);
  assert.equal(policyRefusal('verification policy violation: signing policy rejects algorithm sha1\n'), undefined);
});

test('wrapping places an unsigned forgery with the signed ID before the signed assertion', () => {
  // Engines are checked to reject this; a no-op wrap would check an intact document.
  const signed = '<samlp:Response><saml:Assertion ID="assertion"><ds:Signature xmlns:ds="d"><ds:SignedInfo/></ds:Signature>'
    + '<saml:Subject><saml:NameID>user@example.invalid</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>';
  const wrapped = wrap(signed);
  const forged = wrapped.indexOf('attacker@example.invalid');
  const original = wrapped.indexOf('user@example.invalid');
  assert.ok(forged > 0 && original > forged);
  assert.equal(wrapped.split('ID="assertion"').length, 3);
  assert.equal(wrapped.split('<ds:Signature').length, 2);
  assert.throws(() => wrap('<samlp:Response/>'), /Signed assertion missing/);
});

test('unsupported work is recorded per operation, not per workload', () => {
  // Bergshamra verifies assertions and decrypts in-place documents it cannot produce.
  assert.ok(unsupported('bergshamra', 'assertion', 'sign'));
  assert.equal(unsupported('bergshamra', 'assertion', 'verify'), undefined);
  assert.ok(unsupported('bergshamra', 'element_in_place', 'encrypt'));
  assert.equal(unsupported('bergshamra', 'element_in_place', 'decrypt'), undefined);
  assert.equal(unsupported('xml-sec', 'xslt', 'sign'), undefined);
});

test('tampering changes a signed value in every signing workload', () => {
  // A replacement that matches nothing would make the rejection check verify an intact document.
  const signed = {
    payload: '<Doc><Payload Id="payload">x</Payload></Doc>',
    assertion: '<saml:Attribute><saml:AttributeValue>value</saml:AttributeValue></saml:Attribute>',
    xslt: '<List Id="list"><Item n="0">value</Item></List>',
  };
  for (const [scenario, operations] of Object.entries(SCENARIOS)) {
    if (!operations.includes('verify')) continue;
    const changed = tamper(signed[scenario], scenario);
    assert.notEqual(changed, signed[scenario], scenario);
  }
  assert.throws(() => tamper('<Doc/>', 'assertion'), /Tamper target missing/);
});

test('XML round trips ignore only the declaration and outer whitespace', () => {
  const plain = Buffer.from('<?xml version="1.0"?><Order><Payment/></Order>');
  assert.equal(documentBody(Buffer.from('<Order><Payment/></Order>\n')), documentBody(plain));
  assert.notEqual(documentBody(Buffer.from('<Order><Payment> </Payment></Order>')), documentBody(plain));
});

test('every measured engine has arguments for each workload operation', () => {
  // A missing combination would throw mid-run after minutes of earlier measurements.
  const files = { template: 't', signed: 's', plain: 'p', encrypted: 'e', destination: 'd', corpus: 'c' };
  for (const [scenario, operations] of Object.entries(SCENARIOS)) {
    for (const engine of [['xmlsec', 'xml-sec'], ['xmlsec', 'libxmlsec1'], ['berg', 'bergshamra']]) {
      for (const operation of operations) {
        if (unsupported(engine[1], scenario, operation)) continue;
        const args = engineArguments(engine[0], scenario, operation, files);
        assert.ok(Array.isArray(args) && args[0] === operation, `${engine[1]} ${scenario} ${operation}`);
      }
    }
  }
});

test('in-place encryption reads the whole document, standalone reads the element', () => {
  assert.equal(caseFiles({ name: 'element_in_place-16', scenario: 'element_in_place', units: 16 }).plain, 'order-16.plain.xml');
  assert.equal(caseFiles({ name: 'element-16', scenario: 'element', units: 16 }).plain, 'element-16.plain.xml');
  assert.equal(caseFiles({ name: 'saml-16', scenario: 'payload', units: 16 }).plain, 'saml-16.plain.xml');
});

test('fresh nested evidence directories work without overwriting prior results', () => {
  // Clean CI has no performance directory; only parents may be reused.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-evidence-test-'));
  const output = path.join(directory, 'target', 'performance', 'comparison');
  try {
    createEvidenceDirectory(output);
    assert.equal(fs.statSync(output).isDirectory(), true);
    fs.writeFileSync(path.join(output, 'evidence'), 'preserved');
    assert.throws(() => createEvidenceDirectory(output), { code: 'EEXIST' });
    assert.equal(fs.readFileSync(path.join(output, 'evidence'), 'utf8'), 'preserved');
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test('nearest rank sorts independently and rejects missing samples', () => {
  const input = [30, 10, 20];
  assert.equal(percentile(input, 50), 20);
  assert.equal(percentile(input, 99), 30);
  assert.deepEqual(input, [30, 10, 20]);
  assert.throws(() => percentile([], 99));
});
test('latency runner supports empty and nonempty loader arrays under system Bash', () => {
  // Exercise both actual invocation lines, including macOS Bash 3.2 nounset.
  const script = fs.readFileSync(new URL('./benchmark-security.sh', import.meta.url), 'utf8');
  const invocations = script.split('\n').filter(line =>
    line.includes('"$binary" --list') || line.includes('/usr/bin/time "${time_args[@]}"'));
  assert.equal(invocations.length, 2);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-loader-test-'));
  try {
    for (const loader of ['()', '(/usr/bin/env BENCH_LOADER_TEST=present)']) {
      for (const invocation of invocations) {
        const result = spawnSync('/bin/bash', ['-uc', `
          loader_env=${loader}
          time_args=(${process.platform === 'darwin' ? '-l' : '-v'})
          binary=/usr/bin/true
          output=$1
          name=case operation=parse shape=text units=16 backend=xmloxide provider=rustcrypto samples=1
          ${invocation}
        `, 'loader-test', directory], { encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr);
      }
    }
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
test('published package includes every shared benchmark entry point', () => {
  // Published tooling must retain support modules and build a standalone dashboard.
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const result = spawnSync('cargo', ['package', '--list', '--allow-dirty'],
    { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const files = new Set(result.stdout.trim().split('\n'));
  for (const file of [
    'benches/security.rs', 'benches/support/mod.rs', 'examples/benchmark_latency.rs',
    'benchmarks/dashboard/index.html', 'benchmarks/dashboard/app.js',
    'benchmarks/dashboard/style.css', 'benchmarks/Dockerfile',
    'scripts/build-benchmark-dashboard.mjs',
  ]) {
    assert.equal(files.has(file), true, `Missing packaged ${file}`);
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-package-test-'));
  try {
    const builder = 'scripts/build-benchmark-dashboard.mjs';
    const assets = ['index.html', 'app.js', 'style.css'];
    for (const file of [builder, ...assets.map(file => `benchmarks/dashboard/${file}`)]) {
      const destination = path.join(directory, file);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(path.join(root, file), destination);
    }
    const report = { schema: 2, results: Array.from({ length: 336 }, (_, index) => index < 8
      ? { unsupported: 'not available' } : { commands: ['private path'], repetitions: [{}] }) };
    fs.writeFileSync(path.join(directory, 'comparison.json'), JSON.stringify(report));
    const library = { schema: 1, results: Array.from({ length: 144 }, (_, index) => index < 4
      ? { unsupported: 'not available' } : { repetitions: [{}] }) };
    fs.writeFileSync(path.join(directory, 'library.json'), JSON.stringify(library));
    const output = path.join(directory, 'site');
    const built = spawnSync(process.execPath, [builder, directory, output],
      { cwd: directory, encoding: 'utf8' });
    assert.equal(built.status, 0, built.stderr);
    for (const file of assets) {
      assert.deepEqual(fs.readFileSync(path.join(output, file)),
        fs.readFileSync(path.join(root, 'benchmarks/dashboard', file)));
    }
    const published = JSON.parse(fs.readFileSync(path.join(output, 'comparison.json'), 'utf8'));
    assert.equal(published.results.length, 336);
    assert.ok(published.results.every(entry => !Object.hasOwn(entry, 'commands')));
    assert.equal(JSON.parse(fs.readFileSync(path.join(output, 'library.json'), 'utf8')).results.length, 144);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
test('CI benchmark evidence stays outside the restored build cache', () => {
  // A cache hit must never supply old evidence to a runner that forbids overwrite.
  const workflow = fs.readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  assert.ok(workflow.includes('bash scripts/benchmark-security.sh "$RUNNER_TEMP/benchmark-smoke-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"'));
  assert.ok(workflow.includes('path: ${{ runner.temp }}/benchmark-smoke-${{ github.run_id }}-${{ github.run_attempt }}'));
  assert.equal(workflow.includes('target/performance/smoke'), false);
  const comparison = fs.readFileSync(new URL('../.github/workflows/benchmark-comparison.yml', import.meta.url), 'utf8');
  assert.ok(comparison.includes('"$RUNNER_TEMP/benchmark-comparison-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"'));
  assert.ok(comparison.includes('"$RUNNER_TEMP/benchmark-site-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"'));
  assert.ok(comparison.includes('benchmark-compare.sh "$COMPARISON_OUTPUT"'));
  assert.ok(comparison.includes('build-benchmark-dashboard.mjs "$COMPARISON_OUTPUT" "$SITE_OUTPUT"'));
  assert.ok(comparison.includes('path: ${{ env.COMPARISON_OUTPUT }}'));
  assert.ok(comparison.includes('path: ${{ env.SITE_OUTPUT }}'));
  assert.equal(comparison.includes('target/performance/'), false);
});
test('RSS units differ between GNU time and macOS', () => {
  assert.deepEqual(resources('diagnostic\n__METRICS 1.2 0.3 1024\n', 'linux'), { cpu_seconds: 1.5, rss_bytes: 1048576 });
  assert.deepEqual(resources(' 1.5 real 1.2 user 0.3 sys\n 1024 maximum resident set size', 'darwin'), { cpu_seconds: 1.5, rss_bytes: 1024 });
  assert.throws(() => resources('aborted', 'linux'));
});
test('heap high-water mark is simultaneous requested plus allocator bytes', () => {
  assert.deepEqual(heapStats('total heap usage: 1,234 allocs, 10 frees, 12,345 bytes allocated', 'mem_heap_B=100\nmem_heap_extra_B=30\nmem_heap_B=80\nmem_heap_extra_B=60\n'), { allocation_calls: 1234, allocated_bytes: 12345, peak_heap_bytes: 140 });
  assert.throws(() => heapStats('', ''));
});

test('invalid runner arguments never build or overwrite evidence', () => {
  // Reject arguments before donor/network/build work; preserve prior results.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-comparison-test-'));
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const output = path.join(directory, 'new');
  try {
    for (const samples of ['0', '-1', '1001', '99999999999999999999', 'invalid']) {
      const result = spawnSync('bash', ['scripts/benchmark-compare.sh', output, samples], { cwd: root });
      assert.equal(result.status, 2);
      assert.equal(fs.existsSync(output), false);
    }
    assert.equal(spawnSync('bash', ['scripts/benchmark-compare.sh', output, '1', '--unknown'], { cwd: root }).status, 2);
    fs.mkdirSync(output);
    fs.writeFileSync(path.join(output, 'evidence'), 'preserved');
    assert.equal(spawnSync('bash', ['scripts/benchmark-compare.sh', output, '1'], { cwd: root }).status, 2);
    assert.equal(fs.readFileSync(path.join(output, 'evidence'), 'utf8'), 'preserved');
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test('incomplete reports cannot publish a dashboard', () => {
  // A partial run must fail publication rather than present missing engines as zeros.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-dashboard-test-'));
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  try {
    const output = path.join(directory, 'site');
    const complete = Array.from({ length: 336 }, () => ({ repetitions: [{}] }));
    const library = Array.from({ length: 144 }, () => ({ repetitions: [{}] }));
    const unmeasured = list => [...list.slice(1), { engine: 'unmeasured' }];
    // Missing entries, and a supported entry without measurements, are both incomplete
    // at either level; a complete pair is the control that the builder accepts.
    for (const [cli, inProcess, accepted] of [[[], library, false], [unmeasured(complete), library, false],
      [complete, [], false], [complete, unmeasured(library), false], [complete, library, true]]) {
      fs.writeFileSync(path.join(directory, 'comparison.json'), JSON.stringify({ schema: 2, results: cli }));
      fs.writeFileSync(path.join(directory, 'library.json'), JSON.stringify({ schema: 1, results: inProcess }));
      const result = spawnSync(process.execPath, ['scripts/build-benchmark-dashboard.mjs', directory, output], { cwd: root });
      assert.equal(result.status === 0, accepted);
      assert.equal(fs.existsSync(output), accepted);
      fs.rmSync(output, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
