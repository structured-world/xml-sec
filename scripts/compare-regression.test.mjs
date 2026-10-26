import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadRun, ordering, regressionReport, summary } from './compare-regression.mjs';

const environment = (samples = 30, repetitions = 3) => ({ platform: 'linux', architecture: 'x64', cpu: 'Xeon', samples, repetitions });
const build = () => ({ schema: 1, profile: 'release', rustc: 'rustc 1.92.0', features: { cli: 'benchmark-internals,xslt' } });
const repetition = p50 => ({ p50_ns: p50, p95_ns: p50 * 2, p99_ns: p50 * 3, raw: [{ wall_ns: p50, rss_bytes: 1000 }] });
const entry = (name, p50s, extra = {}) => ({ level: 'cli', engine: 'xml-sec', scenario: 'assertion', name, operation: 'verify',
  boundary: 'process', memory: { allocation_calls: 10, allocated_bytes: 100, peak_heap_bytes: 50 }, repetitions: p50s.map(repetition), ...extra });
const run = (results, overrides = {}) => ({
  cli: { schema: 2, source_revision: 'abc', environment: environment(), corpus: [{ name: 'a', sha256: '1' }], results },
  library: { schema: 1, environment: environment(), results: [] },
  build: build(), ...overrides,
});

test('identical runs compare every case and find every distribution overlapping', () => {
  const results = [entry('saml-16', [100, 110, 105])];
  const report = regressionReport(run(results), run(results));
  assert.equal(report.comparable, true);
  assert.deepEqual(report.counts, { 'compared, p50 overlapping': 1 });
  assert.equal(report.entries[0].latency.p50_ns.median_ratio, 1);
  assert.equal(report.entries[0].allocations.allocation_calls.change, 0);
});

test('a candidate slower in every repetition is reported as an observation, not a verdict', () => {
  // No threshold: the report states the separation and both medians only.
  const report = regressionReport(run([entry('saml-16', [100, 110, 105])]), run([entry('saml-16', [200, 210, 205])]));
  assert.equal(report.entries[0].latency.p50_ns.ordering, 'higher in every repetition');
  assert.equal(report.entries[0].latency.p50_ns.median_ratio, 205 / 105);
  const text = summary(report);
  assert.match(text, /saml-16.*higher in every repetition \| 105 \| 205/);
  assert.match(text, /nothing here is a pass or fail verdict/);
  assert.equal(ordering([1, 2], [0, 3]), 'overlapping');
  assert.equal(ordering([5, 6], [1, 2]), 'lower in every repetition');
});

test('a separated case keeps its four table cells in the summary', () => {
  // The case identity must not split the Markdown row into extra columns.
  const report = regressionReport(run([entry('saml-16', [100, 110, 105])]), run([entry('saml-16', [200, 210, 205])]));
  const row = summary(report).split('\n').find(line => line.includes('saml-16'));
  assert.equal(row.split(/(?<!\\)\|/).length - 2, 4, row);
});

test('a one-sample or under-repeated run proves harness operation only', () => {
  // The contract needs at least three repetitions of more than one sample.
  const results = [entry('saml-16', [100])];
  for (const environmentOf of [environment(1, 3), environment(30, 1)]) {
    const smoke = run(results, { cli: { ...run(results).cli, environment: environmentOf } });
    const report = regressionReport(run(results), smoke);
    assert.equal(report.comparable, false);
    assert.match(report.incomparable_reasons.join('\n'), /candidate cli run has .* it proves harness operation only/);
    assert.deepEqual(report.counts, { incomparable: 1 });
  }
});

test('different hosts, builds or corpora are incomparable with their reasons', () => {
  const results = [entry('saml-16', [100, 110, 105])];
  const host = run(results, { cli: { ...run(results).cli, environment: { ...environment(), cpu: 'EPYC' } } });
  const toolchain = run(results, { build: { ...build(), rustc: 'rustc 1.99.0' } });
  const features = run(results, { build: { ...build(), features: { cli: 'benchmark-internals' } } });
  const corpus = run(results, { cli: { ...run(results).cli, corpus: [{ name: 'a', sha256: '2' }] } });
  for (const [candidate, reason] of [[host, /cli environment cpu differs/], [toolchain, /build rustc differs/],
    [features, /build features differs/], [corpus, /corpus digests differ/]]) {
    const report = regressionReport(run(results), candidate);
    assert.equal(report.comparable, false);
    assert.match(report.incomparable_reasons.join('\n'), reason);
    assert.ok(report.entries.every(item => item.status === 'incomparable'));
  }
});

test('cases present on one side only and unsupported cases are explicit', () => {
  const report = regressionReport(
    run([entry('old', [1, 2, 3]), entry('xslt-16', [1, 2, 3], { unsupported: undefined })]),
    run([entry('new', [1, 2, 3]), { ...entry('xslt-16', []), unsupported: 'no XSLT transform' }]));
  const status = Object.fromEntries(report.entries.map(item => [item.case.split(' | ')[3], item.status]));
  assert.deepEqual(status, { old: 'missing in candidate', 'xslt-16': 'unsupported', new: 'missing in baseline' });
  assert.equal(report.entries.find(item => item.status === 'unsupported').candidate, 'no XSLT transform');
});

test('a missing allocation profile stays missing instead of becoming zero', () => {
  const report = regressionReport(run([entry('saml-16', [1, 2, 3])]), run([entry('saml-16', [1, 2, 3], { memory: null })]));
  assert.deepEqual(report.entries[0].allocations, { not_measured: 'candidate' });
});

function withRuns(callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-regression-test-'));
  try {
    const write = (name, value) => {
      const location = path.join(directory, name);
      fs.mkdirSync(location, { recursive: true });
      for (const [file, content] of [['comparison.json', value.cli], ['library.json', value.library], ['build.json', value.build]])
        if (content !== undefined) fs.writeFileSync(path.join(location, file), typeof content === 'string' ? content : JSON.stringify(content));
      return location;
    };
    return callback(write, directory);
  } finally { fs.rmSync(directory, { recursive: true }); }
}

test('an unusable baseline is reported as missing evidence, never as a comparison', () => {
  // A malformed, absent or other-schema baseline yields explicit no-baseline entries.
  const results = [entry('saml-16', [1, 2, 3])];
  withRuns(write => {
    for (const [baseline, reason] of [
      [{ ...run(results), build: undefined }, /build.json is missing/],
      [{ ...run(results), cli: '{not json' }, /comparison.json is not valid JSON/],
      [{ ...run(results), library: { schema: 9, results: [] } }, /library.json has schema 9/],
    ]) {
      const report = regressionReport(loadRun(write(`baseline-${Math.random()}`, baseline)), loadRun(write('candidate', run(results))));
      assert.equal(report.comparable, false);
      assert.equal(report.baseline, null);
      assert.match(report.incomparable_reasons[0], reason);
      assert.deepEqual(report.counts, { 'no baseline': 1 });
    }
  });
});

test('malformed case measurements make a baseline unusable and a candidate fail', () => {
  // Schema-valid files can still carry empty, short or non-numeric repetitions.
  const valid = run([entry('saml-16', [1, 2, 3])]);
  withRuns(write => {
    for (const results of [[entry('saml-16', [])], [entry('saml-16', [100, null, 105])], [entry('saml-16', [100, 110])]]) {
      const malformed = loadRun(write(`malformed-${Math.random()}`, run(results)));
      const report = regressionReport(malformed, valid);
      assert.equal(report.comparable, false);
      assert.match(report.incomparable_reasons[0], /no usable baseline: comparison.json case .*saml-16/);
      assert.throws(() => regressionReport(valid, malformed), /candidate run is unusable: comparison.json case .*saml-16/);
    }
  });
});

test('an unusable candidate fails the report process instead of writing a report', () => {
  // The candidate is this run's own evidence; a broken one is a failure.
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  withRuns((write, directory) => {
    const baseline = write('baseline', run([entry('saml-16', [1, 2, 3])]));
    const candidate = write('candidate', { ...run([]), build: undefined });
    const result = spawnSync(process.execPath, ['scripts/compare-regression.mjs', baseline, candidate, directory], { cwd: root, encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /candidate run is unusable: build.json is missing/);
    assert.equal(fs.existsSync(path.join(directory, 'regression.json')), false);
    const complete = write('complete', run([entry('saml-16', [1, 2, 3])]));
    const written = spawnSync(process.execPath, ['scripts/compare-regression.mjs', baseline, complete, directory], { cwd: root, encoding: 'utf8' });
    assert.equal(written.status, 0, written.stderr);
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, 'regression.json'), 'utf8')).comparable, true);
    assert.equal(fs.readFileSync(path.join(directory, 'regression.md'), 'utf8'), written.stdout);
  });
});
