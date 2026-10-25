import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCENARIOS, caseFiles, documentBody, percentile, resources, tamper, wrap } from './compare-security.mjs';

export const BOUNDARIES = ['parse', 'prepared'];
export const BOUNDARY_DESCRIPTIONS = {
  parse: 'one in-process operation from serialized input to serialized result, parsing included; keys and trust loaded beforehand',
  prepared: 'one in-process operation on an already parsed document, without serialization; a mutating operation receives a fresh copy outside the timer',
};
const WORKLOADS = ['assertion', 'element', 'element_in_place', 'xslt'];

/** Interpret one harness process: measured, rejected, unsupported (with its reason) or failure. */
export function harnessOutcome(result) {
  if (result.error || result.signal) return { kind: 'failed', reason: String(result.error ?? result.signal) };
  if (result.status === 3) return { kind: 'unsupported', reason: result.stderr.trim().replace(/^unsupported: /, '') };
  if (result.status !== 0) return { kind: 'failed', reason: result.stderr.trim() || `exit ${result.status}` };
  const lines = result.stdout.trim().split('\n');
  let report;
  try { report = JSON.parse(lines[lines.length - 1]); }
  catch { return { kind: 'failed', reason: 'malformed harness report' }; }
  return report.rejected === true ? { kind: 'rejected', report } : { kind: 'measured', report };
}

/** Refuse a report that does not describe exactly the requested measurement. */
export function validateReport(report, request) {
  const { engine, scenario, operation, boundary, samples } = request;
  if (report.engine !== engine || report.scenario !== scenario || report.operation !== operation || report.boundary !== boundary)
    throw Error(`report identity differs from request: ${engine} ${scenario} ${operation} ${boundary}`);
  if (!Array.isArray(report.samples_ns) || report.samples_ns.length !== samples || report.samples_ns.some(n => !Number.isSafeInteger(n) || n <= 0))
    throw Error(`invalid timing samples: ${engine} ${scenario} ${operation} ${boundary}`);
  const allocations = report.allocations;
  if (allocations !== null && !['calls', 'bytes', 'peak_bytes'].every(key => Number.isSafeInteger(allocations?.[key]) && allocations[key] >= 0))
    throw Error(`invalid allocation profile: ${engine} ${scenario} ${operation} ${boundary}`);
  if (!Number.isSafeInteger(report.input_bytes) || report.input_bytes <= 0) throw Error('invalid input size');
  return report;
}

/** Engines from the environment; every binary must exist before any work starts. */
export function enginesFrom(environment) {
  const engines = [
    { name: 'xml-sec / xmloxide / RustCrypto', id: 'xml-sec', variable: 'LIBRARY_XMLSEC_BIN', profile: 'LIBRARY_XMLSEC_PROFILE_BIN' },
    { name: 'bergshamra / Uppsala / RustCrypto', id: 'bergshamra', variable: 'LIBRARY_BERGSHAMRA_BIN', profile: 'LIBRARY_BERGSHAMRA_PROFILE_BIN' },
    { name: 'libxmlsec1 / libxml2 / OpenSSL', id: 'libxmlsec1', variable: 'LIBRARY_LIBXMLSEC1_BIN', profile: 'LIBRARY_LIBXMLSEC1_PROFILE_BIN' },
  ];
  return engines.map(engine => {
    const binary = environment[engine.variable];
    if (!binary || !fs.existsSync(binary)) throw Error(`Missing ${engine.variable}`);
    const profile = environment[engine.profile];
    if (profile && !fs.existsSync(profile)) throw Error(`Missing ${engine.profile}`);
    return { ...engine, binary: fs.realpathSync(binary), profileBinary: profile ? fs.realpathSync(profile) : null };
  });
}

function main() {
  const [output, sampleText] = process.argv.slice(2);
  const samples = Number(sampleText);
  if (!output || !/^\d+$/.test(sampleText ?? '') || !Number.isSafeInteger(samples) || samples < 1 || samples > 1000)
    throw Error('Usage: compare-library.mjs COMPARISON_DIR SAMPLES');
  if (!['linux', 'darwin'].includes(process.platform)) throw Error('CPU/RSS requires Linux or macOS');
  const engines = enginesFrom(process.env);
  const root = fs.realpathSync(output);
  const corpus = path.join(root, 'corpus');
  const work = path.join(root, 'library');
  fs.mkdirSync(work); // Refuse to overwrite earlier evidence.
  const file = name => path.join(corpus, name);
  const scratch = name => path.join(work, name);
  // macOS time strips DYLD_*; set loader paths immediately before the child exec.
  const loader = process.platform === 'darwin' && process.env.DYLD_LIBRARY_PATH
    ? ['/usr/bin/env', `DYLD_LIBRARY_PATH=${process.env.DYLD_LIBRARY_PATH}`] : [];
  const invoke = (binary, item, operation, boundary, input, out, count) => spawnSync(loader[0] ?? binary,
    [...loader.slice(1), ...(loader.length ? [binary] : []), item.scenario, operation, boundary, corpus, input, out ?? '-', String(count)],
    { encoding: 'utf8', timeout: 600000, maxBuffer: 64 << 20 });
  const cases = JSON.parse(fs.readFileSync(file('cases.json'))).filter(item => WORKLOADS.includes(item.scenario));
  const results = [];
  for (const item of cases) {
    const { name, scenario } = item;
    const operations = SCENARIOS[scenario];
    const producing = operations.includes('sign') ? 'sign' : 'encrypt';
    const consuming = producing === 'sign' ? 'verify' : 'decrypt';
    const source = file(producing === 'sign' ? caseFiles(item).template : caseFiles(item).plain);
    const plain = producing === 'encrypt' ? fs.readFileSync(source) : null;
    const unsupported = new Map();
    const key = (engine, operation, boundary) => `${engine.id}/${operation}/${boundary}`;
    const probe = (engine, operation, boundary, input, out) => {
      const outcome = harnessOutcome(invoke(engine.binary, item, operation, boundary, input, out, 1));
      if (outcome.kind === 'unsupported') { unsupported.set(key(engine, operation, boundary), outcome.reason); return false; }
      if (outcome.kind !== 'measured') throw Error(`${engine.name} ${operation} ${boundary}, ${name}: ${outcome.reason ?? 'unexpected rejection'}`);
      validateReport(outcome.report, { engine: engine.id, scenario, operation, boundary, samples: 1 });
      return true;
    };
    // Every produced result must be consumed by every engine that consumes this
    // workload before anything is timed. The xml-sec result is the timed input, or
    // the first engine's when xml-sec refuses the input under its default policy.
    const produced = [];
    for (const engine of engines) for (const boundary of BOUNDARIES) {
      const out = scratch(`${name}.${producing}-${engine.id}-${boundary}.xml`);
      if (probe(engine, producing, boundary, source, out)) produced.push({ engine, boundary, out });
    }
    const parsed = produced.filter(entry => entry.boundary === 'parse');
    const canonical = parsed.find(entry => entry.engine.id === 'xml-sec') ?? parsed[0];
    if (!canonical) throw Error(`no engine produced a ${producing} result for ${name}`);
    if (scenario === 'assertion')
      for (const entry of produced)
        if (!fs.readFileSync(entry.out, 'utf8').includes('X509Certificate>')) throw Error(`No signer certificate: ${entry.engine.name}, ${name}`);
    for (const engine of engines) for (const boundary of BOUNDARIES) {
      if (!probe(engine, consuming, boundary, canonical.out, scratch(`${name}.${consuming}-probe.xml`))) continue;
      if (boundary !== 'parse') continue;
      for (const entry of produced) {
        const out = scratch(`${name}.${consuming}-${engine.id}.xml`);
        const outcome = harnessOutcome(invoke(engine.binary, item, consuming, 'parse', entry.out, out, 1));
        if (outcome.kind !== 'measured') throw Error(`${engine.name} cannot ${consuming} ${entry.engine.name} ${entry.boundary} output, ${name}: ${outcome.reason ?? 'rejected'}`);
        // XML results may differ only in the declaration and surrounding whitespace.
        if (plain && documentBody(fs.readFileSync(out)) !== documentBody(plain))
          throw Error(`Plaintext mismatch: ${entry.engine.name} ${entry.boundary} -> ${engine.name}, ${name}`);
      }
      if (consuming === 'verify') {
        const signed = fs.readFileSync(canonical.out, 'utf8');
        const forged = { tampered: tamper(signed, scenario) };
        if (scenario === 'assertion') forged.wrapped = wrap(signed);
        for (const [kind, text] of Object.entries(forged)) {
          const input = scratch(`${name}.${kind}.xml`);
          fs.writeFileSync(input, text);
          const outcome = harnessOutcome(invoke(engine.binary, item, 'reject', 'parse', input, null, 1));
          if (outcome.kind !== 'rejected') throw Error(`Invalid ${kind} rejection: ${engine.name}, ${name}`);
        }
      }
    }
    for (const operation of operations) for (const boundary of BOUNDARIES) {
      const input = operation === producing ? source : canonical.out;
      const supported = engines.filter(engine => !unsupported.has(key(engine, operation, boundary)));
      const entries = supported.map(engine => ({ level: 'library', engine: engine.name, operation, boundary, ...item,
        boundary_description: BOUNDARY_DESCRIPTIONS[boundary], repetitions: [], memory: null }));
      for (let repetition = 0; repetition < 3; repetition++) {
        for (let step = 0; step < supported.length; step++) {
          // Rotate order so no engine always runs first.
          const index = (step + repetition) % supported.length;
          const engine = supported[index];
          const timeArgs = process.platform === 'darwin' ? ['-l'] : ['-f', '__METRICS %U %S %M'];
          const command = [...loader, engine.binary, scenario, operation, boundary, corpus, input, '-', String(samples)];
          const measured = spawnSync('/usr/bin/time', [...timeArgs, ...command], { encoding: 'utf8', timeout: 1800000, maxBuffer: 64 << 20 });
          // GNU time appends its metrics line to the harness's stderr.
          const outcome = harnessOutcome({ ...measured, stderr: measured.stderr?.replace(/\n?__METRICS .*$/s, '') ?? '' });
          if (outcome.kind !== 'measured') throw Error(`${engine.name} ${operation} ${boundary}, ${name}: ${outcome.reason ?? 'rejected'}`);
          const report = validateReport(outcome.report, { engine: engine.id, scenario, operation, boundary, samples });
          const raw = report.samples_ns;
          entries[index].input_bytes = report.input_bytes;
          entries[index].repetitions.push({ raw, p50_ns: percentile(raw, 50), p95_ns: percentile(raw, 95), p99_ns: percentile(raw, 99),
            ...resources(measured.stderr, process.platform), rss_scope: 'whole process including key loading, warmups and every sample' });
        }
      }
      for (let index = 0; index < supported.length; index++) {
        const engine = supported[index];
        if (!engine.profileBinary) continue;
        const outcome = harnessOutcome(invoke(engine.profileBinary, item, operation, boundary, input, null, 1));
        if (outcome.kind !== 'measured') throw Error(`${engine.name} allocation profile ${operation} ${boundary}, ${name}: ${outcome.reason ?? 'rejected'}`);
        const { allocations } = validateReport(outcome.report, { engine: engine.id, scenario, operation, boundary, samples: 1 });
        if (!allocations) throw Error(`${engine.name} profile build reported no allocations`);
        entries[index].memory = { allocation_calls: allocations.calls, allocated_bytes: allocations.bytes, peak_heap_bytes: allocations.peak_bytes,
          scope: 'every heap allocation in the process during one operation, from a separate instrumented build' };
      }
      results.push(...entries);
      for (const engine of engines.filter(engine => unsupported.has(key(engine, operation, boundary))))
        results.push({ level: 'library', engine: engine.name, operation, boundary, ...item, boundary_description: BOUNDARY_DESCRIPTIONS[boundary],
          unsupported: unsupported.get(key(engine, operation, boundary)) });
    }
  }
  const digest = target => createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  const report = { schema: 1, generated: new Date().toISOString(),
    environment: { platform: process.platform, architecture: process.arch, cpu: os.cpus()[0]?.model, node: process.version, samples, repetitions: 3,
      timing: 'in-process monotonic clock around each operation; three warmups per process',
      memory: 'allocation profiles come from separate instrumented builds and are never timed' },
    boundaries: BOUNDARY_DESCRIPTIONS,
    binaries: engines.flatMap(engine => [engine.binary, engine.profileBinary].filter(Boolean).map(binary => ({ engine: engine.id, sha256: digest(binary), bytes: fs.statSync(binary).size }))),
    results };
  fs.writeFileSync(path.join(root, 'library.json'), JSON.stringify(report));
  const measured = results.filter(entry => !entry.unsupported).length;
  console.log(`Validated ${measured} library cases, ${results.length - measured} unsupported; ${samples} samples x 3 repetitions`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
