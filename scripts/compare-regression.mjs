// Compares one comparison run against an earlier one. Only runs measured on the
// same environment, build and corpus are compared; anything else is reported as
// incomparable with its reason. The report records observations, never a pass or
// fail verdict: no fixed latency threshold is established by these baselines.
// Usage: compare-regression.mjs BASELINE_DIR CANDIDATE_DIR OUTPUT_DIR
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// The contract's minimum before drawing any performance conclusion.
export const MIN_REPETITIONS = 3;
const ENVIRONMENT = ['platform', 'architecture', 'cpu', 'samples', 'repetitions'];
const PERCENTILES = ['p50_ns', 'p95_ns', 'p99_ns'];
const ALLOCATIONS = ['allocation_calls', 'allocated_bytes', 'peak_heap_bytes'];

/** One run directory: its two reports and its build identity, or why it is unusable. */
export function loadRun(directory) {
  const run = {};
  for (const [key, file, schema] of [['cli', 'comparison.json', 2], ['library', 'library.json', 1], ['build', 'build.json', 1]]) {
    const location = path.join(directory, file);
    if (!fs.existsSync(location)) return { missing: `${file} is missing` };
    let value;
    try { value = JSON.parse(fs.readFileSync(location, 'utf8')); }
    catch { return { missing: `${file} is not valid JSON` }; }
    if (value?.schema !== schema) return { missing: `${file} has schema ${value?.schema}, expected ${schema}` };
    if (key !== 'build' && !Array.isArray(value.results)) return { missing: `${file} has no results` };
    run[key] = value;
  }
  return run;
}

const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

/** Reasons the two runs cannot be compared; empty when they can. */
export function incomparability(baseline, candidate) {
  const reasons = [];
  for (const [label, run] of [['baseline', baseline], ['candidate', candidate]]) {
    for (const level of ['cli', 'library']) {
      const { samples, repetitions } = run[level].environment ?? {};
      if (!(samples > 1 && repetitions >= MIN_REPETITIONS))
        reasons.push(`${label} ${level} run has ${samples} samples x ${repetitions} repetitions; it proves harness operation only`);
    }
  }
  for (const level of ['cli', 'library'])
    for (const field of ENVIRONMENT)
      if (!same(baseline[level].environment?.[field], candidate[level].environment?.[field]))
        reasons.push(`${level} environment ${field} differs: ${JSON.stringify(baseline[level].environment?.[field])} vs ${JSON.stringify(candidate[level].environment?.[field])}`);
  const { schema: baseSchema, ...baseBuild } = baseline.build;
  const { schema: candidateSchema, ...candidateBuild } = candidate.build;
  for (const field of new Set([...Object.keys(baseBuild), ...Object.keys(candidateBuild)]))
    if (!same(baseBuild[field], candidateBuild[field])) reasons.push(`build ${field} differs`);
  if (!same(baseline.cli.corpus, candidate.cli.corpus)) reasons.push('corpus digests differ');
  return reasons;
}

const key = entry => [entry.level, entry.engine, entry.scenario, entry.name, entry.operation, entry.boundary].join(' | ');
const median = values => {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = sorted.length >> 1;
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};
// Per-repetition peak RSS: library repetitions carry it, CLI samples carry it each.
const rss = repetition => repetition.rss_bytes ?? Math.max(...(repetition.raw ?? []).map(sample => sample.rss_bytes ?? 0));

/** Threshold-free ordering of two repetition sets. */
export function ordering(baseline, candidate) {
  if (Math.min(...candidate) > Math.max(...baseline)) return 'higher in every repetition';
  if (Math.max(...candidate) < Math.min(...baseline)) return 'lower in every repetition';
  return 'overlapping';
}

function metric(baseline, candidate) {
  const base = median(baseline);
  const next = median(candidate);
  return { baseline: baseline, candidate: candidate, baseline_median: base, candidate_median: next,
    median_ratio: base > 0 ? next / base : null, ordering: ordering(baseline, candidate) };
}

/** Pairs one entry from each run that measured the same thing. */
export function compareEntry(baseline, candidate) {
  const latency = Object.fromEntries(PERCENTILES.map(field =>
    [field, metric(baseline.repetitions.map(item => item[field]), candidate.repetitions.map(item => item[field]))]));
  const result = { status: 'compared', latency, rss_bytes: metric(baseline.repetitions.map(rss), candidate.repetitions.map(rss)) };
  // Allocation counts come from one instrumented operation; a missing profile stays missing.
  if (baseline.memory && candidate.memory)
    result.allocations = Object.fromEntries(ALLOCATIONS.map(field => [field,
      { baseline: baseline.memory[field], candidate: candidate.memory[field], change: candidate.memory[field] - baseline.memory[field] }]));
  else result.allocations = { not_measured: baseline.memory ? 'candidate' : candidate.memory ? 'baseline' : 'both' };
  return result;
}

/** The complete report; every entry of either run appears exactly once. */
export function regressionReport(baselineRun, candidateRun) {
  if (candidateRun.missing) throw Error(`candidate run is unusable: ${candidateRun.missing}`);
  const reasons = baselineRun.missing ? [`no usable baseline: ${baselineRun.missing}`] : incomparability(baselineRun, candidateRun);
  const index = run => new Map([...run.cli.results, ...run.library.results].map(entry => [key(entry), entry]));
  const candidates = index(candidateRun);
  const baselines = baselineRun.missing ? new Map() : index(baselineRun);
  const entries = [];
  for (const name of new Set([...baselines.keys(), ...candidates.keys()])) {
    const base = baselines.get(name);
    const next = candidates.get(name);
    let entry;
    if (!next) entry = { status: 'missing in candidate' };
    else if (!base) entry = { status: baselineRun.missing ? 'no baseline' : 'missing in baseline' };
    else if (base.unsupported || next.unsupported)
      entry = { status: 'unsupported', baseline: base.unsupported ?? null, candidate: next.unsupported ?? null };
    else if (reasons.length > 0) entry = { status: 'incomparable' };
    else entry = compareEntry(base, next);
    entries.push({ case: name, ...entry });
  }
  const counts = {};
  for (const entry of entries) {
    const label = entry.status === 'compared' ? `compared, p50 ${entry.latency.p50_ns.ordering}` : entry.status;
    counts[label] = (counts[label] ?? 0) + 1;
  }
  return { schema: 1, generated: new Date().toISOString(), comparable: reasons.length === 0, incomparable_reasons: reasons,
    baseline: baselineRun.missing ? null : { source_revision: baselineRun.cli.source_revision ?? null, generated: baselineRun.cli.generated ?? null },
    candidate: { source_revision: candidateRun.cli.source_revision ?? null, generated: candidateRun.cli.generated ?? null },
    counts, entries };
}

/** A short human summary; the JSON report is the evidence. */
export function summary(report) {
  const lines = ['## Benchmark regression report', '',
    `Candidate ${report.candidate.source_revision ?? 'unknown'}, baseline ${report.baseline?.source_revision ?? 'none'}.`,
    'Observations only: no fixed threshold is applied, and nothing here is a pass or fail verdict.', ''];
  if (!report.comparable) lines.push('Not comparable:', ...report.incomparable_reasons.map(reason => `- ${reason}`), '');
  lines.push('| Outcome | Cases |', '|---|---|', ...Object.entries(report.counts).map(([label, count]) => `| ${label} | ${count} |`));
  const separated = report.entries.filter(entry => entry.status === 'compared' && entry.latency.p50_ns.ordering !== 'overlapping');
  if (separated.length > 0) {
    lines.push('', '| Case | p50 | baseline median ns | candidate median ns |', '|---|---|---|---|');
    for (const entry of separated)
      lines.push(`| ${entry.case} | ${entry.latency.p50_ns.ordering} | ${Math.round(entry.latency.p50_ns.baseline_median)} | ${Math.round(entry.latency.p50_ns.candidate_median)} |`);
  }
  return `${lines.join('\n')}\n`;
}

function main() {
  const [baseline, candidate, output] = process.argv.slice(2);
  if (!baseline || !candidate || !output) throw Error('Usage: compare-regression.mjs BASELINE_DIR CANDIDATE_DIR OUTPUT_DIR');
  const report = regressionReport(loadRun(baseline), loadRun(candidate));
  fs.writeFileSync(path.join(output, 'regression.json'), JSON.stringify(report));
  const text = summary(report);
  fs.writeFileSync(path.join(output, 'regression.md'), text);
  process.stdout.write(text);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
