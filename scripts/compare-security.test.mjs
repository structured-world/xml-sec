import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { percentile, resources, heapStats, createEvidenceDirectory } from './compare-security.mjs';

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
    const report = { schema: 1, results: Array.from({ length: 160 }, () => ({ commands: ['private path'] })) };
    fs.writeFileSync(path.join(directory, 'comparison.json'), JSON.stringify(report));
    const output = path.join(directory, 'site');
    const built = spawnSync(process.execPath, [builder, directory, output],
      { cwd: directory, encoding: 'utf8' });
    assert.equal(built.status, 0, built.stderr);
    for (const file of assets) {
      assert.deepEqual(fs.readFileSync(path.join(output, file)),
        fs.readFileSync(path.join(root, 'benchmarks/dashboard', file)));
    }
    const published = JSON.parse(fs.readFileSync(path.join(output, 'comparison.json'), 'utf8'));
    assert.equal(published.results.length, 160);
    assert.ok(published.results.every(entry => !Object.hasOwn(entry, 'commands')));
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
    fs.writeFileSync(path.join(directory, 'comparison.json'), JSON.stringify({ schema: 1, results: [] }));
    const output = path.join(directory, 'site');
    const result = spawnSync(process.execPath, ['scripts/build-benchmark-dashboard.mjs', directory, output], { cwd: root });
    assert.notEqual(result.status, 0);
    assert.equal(fs.existsSync(output), false);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
