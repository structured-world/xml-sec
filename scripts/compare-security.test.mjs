import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { percentile, resources, heapStats } from './compare-security.mjs';

test('nearest rank sorts independently and rejects missing samples', () => {
  const input = [30, 10, 20];
  assert.equal(percentile(input, 50), 20);
  assert.equal(percentile(input, 99), 30);
  assert.deepEqual(input, [30, 10, 20]);
  assert.throws(() => percentile([], 99));
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
