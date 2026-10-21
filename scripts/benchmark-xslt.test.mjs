import assert from 'node:assert/strict';
import { test } from 'node:test';
import { summary, validate, resources, checkOutputLocation } from './benchmark-xslt.mjs';
import { mkdtempSync, mkdirSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

test('native oracle configures with pkg-config libxml2 without a vendor CMake config', t => {
  // Ubuntu libxml2-dev supplies pkg-config metadata, not LibXml2Config.cmake.
  const source = process.env.LIBXSLT_SOURCE_DIR;
  if (!source) return t.skip('requires the pinned LIBXSLT_SOURCE_DIR');
  const build = mkdtempSync(join(tmpdir(), 'xml-sec-xslt-cmake-'));
  t.after(() => rmSync(build, { recursive: true, force: true }));
  const result = spawnSync('cmake', ['-S', source, '-B', build,
    '-DLibXml2_DIR=' + join(process.cwd(), 'benchmarks/cmake/libxml2'),
    '-DLIBXSLT_WITH_PYTHON=OFF', '-DLIBXSLT_WITH_TESTS=OFF', '-DLIBXSLT_WITH_PROGRAMS=OFF'],
  { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('an output symlink alias cannot put evidence inside the cleaned target', t => {
  // A lexical path check loses evidence when an existing parent aliases target.
  const root = mkdtempSync(join(tmpdir(), 'xml-sec-xslt-path-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const target = join(root, 'target');
  mkdirSync(target);
  symlinkSync(target, join(root, 'alias'));
  assert.throws(() => checkOutputLocation(join(root, 'alias/results'), target));
  assert.doesNotThrow(() => checkOutputLocation(join(root, 'results'), target));
});

test('nearest-rank percentiles retain outliers without mutating raw samples', () => {
  // Tail samples must not vanish into an average or interpolation.
  const raw = [100, 1, 2, 3];
  assert.deepEqual(summary(raw), { p50_ns: 2, p95_ns: 100, p99_ns: 100 });
  assert.deepEqual(raw, [100, 1, 2, 3]);
});
test('RSS units remain platform-specific and missing RSS is a failure', () => {
  // macOS reports bytes; Linux reports KiB. Never subtract setup high-water marks.
  assert.equal(resources('123 maximum resident set size', 'darwin').peak_rss_bytes, 123);
  assert.equal(resources('Maximum resident set size (kbytes): 123', 'linux').peak_rss_bytes, 125952);
  assert.throws(() => resources('', 'linux'));
});
test('reject absent, invalid and mismatched measurements instead of timing unsupported work', () => {
  // Missing observations are failures, never zero-cost or successful results.
  for (const samples of [[], [0], [-1], [NaN], [1.5]]) assert.throws(() => summary(samples));
  const result = { engine: 'xml-sec', phase: 'tree', samples_ns: [1], source_bytes: 10, stylesheet_bytes: 20, output_bytes: 100 };
  assert.equal(validate(result, 1, 10, 20, 100, 'xml-sec', 'tree').output_amplification, 10);
  assert.throws(() => validate(result, 2, 10, 20, 100, 'xml-sec', 'tree'));
  assert.throws(() => validate(result, 1, 10, 20, 101, 'xml-sec', 'tree'));
  assert.throws(() => validate(result, 1, 10, 20, 100, 'libxslt', 'tree'));
  assert.throws(() => validate(result, 1, 10, 20, 100, 'xml-sec', 'retained'));
});
