import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

export function percentile(values, percent) {
  if (!values.length || values.some(x => !Number.isFinite(x) || x < 0)) throw Error('Invalid samples');
  return [...values].sort((a, b) => a - b)[Math.ceil(percent * values.length / 100) - 1];
}

export function resources(text, platform) {
  const match = platform === 'darwin'
    ? text.match(/([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys[\s\S]*?(\d+)\s+maximum resident set size/)
    : text.match(/__METRICS ([\d.]+) ([\d.]+) (\d+)/);
  if (!match) throw Error('Missing process CPU/RSS report');
  return platform === 'darwin'
    ? { cpu_seconds: Number(match[2]) + Number(match[3]), rss_bytes: Number(match[4]) }
    : { cpu_seconds: Number(match[1]) + Number(match[2]), rss_bytes: Number(match[3]) * 1024 };
}

export function heapStats(memcheck, massif) {
  const total = memcheck.match(/total heap usage: ([\d,]+) allocs, [\d,]+ frees, ([\d,]+) bytes allocated/);
  const snapshots = [...massif.matchAll(/mem_heap_B=(\d+)\nmem_heap_extra_B=(\d+)/g)];
  if (!total || !snapshots.length) throw Error('Missing Valgrind allocation/heap report');
  return {
    allocation_calls: Number(total[1].replaceAll(',', '')),
    allocated_bytes: Number(total[2].replaceAll(',', '')),
    peak_heap_bytes: Math.max(...snapshots.map(m => Number(m[1]) + Number(m[2]))),
  };
}

function checked(binary, args, options = {}) {
  const result = spawnSync(binary, args, { encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024, ...options });
  if (result.error || result.signal || result.status !== 0) throw Error(`${binary} failed: ${result.error ?? result.signal ?? result.status}\n${result.stderr}`);
  return result;
}

export function createEvidenceDirectory(output) {
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.mkdirSync(output); // Refuse to overwrite any existing evidence.
}

function main() {
  // Keep system-tool reports independent of the caller's locale.
  process.env.LC_ALL = 'C';
  const [output, sampleText = '30', heapMode = ''] = process.argv.slice(2);
  const samples = Number(sampleText);
  if (!output || !/^\d+$/.test(sampleText) || !Number.isSafeInteger(samples) || samples < 1 || samples > 1000 || !['', '--heap'].includes(heapMode)) throw Error('Usage: compare-security.mjs NEW_OUTPUT_DIR SAMPLES [--heap]');
  if (!['linux', 'darwin'].includes(process.platform)) throw Error('CPU/RSS requires Linux or macOS');
  if (heapMode && process.platform !== 'linux') throw Error('Valgrind heap comparison requires Linux');
  const binaries = ['XML_SEC_BENCH_BIN', 'BERGSHAMRA_BIN', 'XMLSEC1_BIN', 'BENCH_EXPORT_BIN'].map(name => {
    if (!process.env[name]) throw Error(`Missing ${name}`);
    return fs.realpathSync(process.env[name]);
  });
  if (heapMode) checked('valgrind', ['--version']);
  createEvidenceDirectory(output);
  const root = fs.realpathSync(output);
  const corpus = path.join(root, 'corpus');
  checked(binaries[3], ['--export', corpus]);
  const file = name => path.join(corpus, name);
  const engines = [
    { name: 'xml-sec / xmloxide / RustCrypto', binary: binaries[0], backend: ['--xml-backend', 'xmloxide'] },
    { name: 'xml-sec / roxmltree / RustCrypto', binary: binaries[0], backend: ['--xml-backend', 'roxmltree'] },
    { name: 'bergshamra / Uppsala / RustCrypto', binary: binaries[1], berg: true },
    { name: 'libxmlsec1 / libxml2 / OpenSSL', binary: binaries[2] },
  ];
  // macOS time strips DYLD_*; set loader paths immediately before the child exec.
  const loader = process.platform === 'darwin' && process.env.DYLD_LIBRARY_PATH
    ? ['/usr/bin/env', `DYLD_LIBRARY_PATH=${process.env.DYLD_LIBRARY_PATH}`] : [];
  const command = (engine, operation, name, destination, input) => {
    const args = engine.berg ? {
      sign: ['sign', input ?? file(`${name}.template.xml`), '--key-name', `bench:${file('private.pem')}`, '--output', destination],
      verify: ['verify', input ?? file(`${name}.signed.xml`), '--key-name', `bench:${file('public.pem')}`, '--trusted-keys-only'],
      encrypt: ['encrypt', file('encryption.xml'), '--data', file(`${name}.plain.xml`), '--keys-file', file('keys.xml'), '--output', destination],
      decrypt: ['decrypt', input ?? file(`${name}.encrypted.xml`), '--keys-file', file('keys.xml'), '--output', destination],
    }[operation] : {
      sign: ['sign', '--privkey-pem:bench', file('private.pem'), '--id-attr:Id', 'Payload', '--output', destination, input ?? file(`${name}.template.xml`)],
      verify: ['verify', '--pubkey-pem:bench', file('public.pem'), '--id-attr:Id', 'Payload', input ?? file(`${name}.signed.xml`)],
      encrypt: ['encrypt', '--keys-file', file('keys.xml'), '--binary-data', file(`${name}.plain.xml`), '--output', destination, file('encryption.xml')],
      decrypt: ['decrypt', '--keys-file', file('keys.xml'), '--output', destination, input ?? file(`${name}.encrypted.xml`)],
    }[operation];
    return [...loader, engine.binary, args[0], ...(engine.backend ?? []), ...args.slice(1)];
  };
  const invoke = cmd => checked(cmd[0], cmd.slice(1), { stdio: ['ignore', 'ignore', 'pipe'] });
  const cases = JSON.parse(fs.readFileSync(file('cases.json')));
  const results = [];
  const rawDirectory = path.join(root, 'raw');
  fs.mkdirSync(rawDirectory);
  for (const item of cases) {
    const { name } = item;
    const plain = fs.readFileSync(file(`${name}.plain.xml`));
    const tampered = file(`${name}.tampered.xml`);
    fs.writeFileSync(tampered, fs.readFileSync(file(`${name}.signed.xml`), 'utf8').replace('<Payload Id="payload">', '<Payload Id="payload" altered="true">'));
    for (let index = 0; index < engines.length; index++) {
      const engine = engines[index];
      const signed = file(`${name}.signed-${index}.xml`);
      const encrypted = file(`${name}.encrypted-${index}.xml`);
      invoke(command(engine, 'sign', name, signed));
      invoke(command(engine, 'encrypt', name, encrypted));
      for (const verifier of engines) {
        invoke(command(verifier, 'verify', name, null, signed));
        const decrypted = file(`${name}.decrypted.xml`);
        invoke(command(verifier, 'decrypt', name, decrypted, encrypted));
        if (!fs.readFileSync(decrypted).equals(plain)) throw Error(`Plaintext mismatch: ${engine.name} -> ${verifier.name}, ${name}`);
      }
      const invalid = command(engine, 'verify', name, null, tampered);
      const rejection = spawnSync(invalid[0], invalid.slice(1), { encoding: 'utf8', timeout: 120000 });
      // A crash/timeout is not successful verification rejection.
      if (rejection.error || rejection.signal || rejection.status !== 1) throw Error(`Invalid rejection: ${engine.name}, ${name}`);
    }
    fs.copyFileSync(file(`${name}.encrypted-0.xml`), file(`${name}.encrypted.xml`));
    for (const operation of ['sign', 'verify', 'encrypt', 'decrypt']) {
      const entries = engines.map((engine, index) => ({ engine: engine.name, operation, ...item,
        boundary: 'fresh CLI process + key loading + file I/O + operation',
        repetitions: [], memory: null, commands: command(engine, operation, name, file(`${name}.${operation}-${index}.output`)) }));
      for (let repetition = 0; repetition < 3; repetition++) {
        const observations = entries.map(() => []);
        for (let sample = 0; sample < samples; sample++) {
          // Rotate order to avoid giving one engine every first/cold slot.
          for (let step = 0; step < engines.length; step++) {
            const index = (step + sample + repetition) % engines.length;
            const cmd = entries[index].commands;
            const timeArgs = process.platform === 'darwin' ? ['-l'] : ['-f', '__METRICS %U %S %M'];
            const start = performance.now();
            const measured = checked('/usr/bin/time', [...timeArgs, ...cmd], { stdio: ['ignore', 'ignore', 'pipe'] });
            const elapsed = (performance.now() - start) * 1e6;
            observations[index].push({ wall_ns: elapsed, ...resources(measured.stderr, process.platform) });
          }
        }
        observations.forEach((raw, index) => entries[index].repetitions.push({ raw,
          p50_ns: percentile(raw.map(x => x.wall_ns), 50), p95_ns: percentile(raw.map(x => x.wall_ns), 95), p99_ns: percentile(raw.map(x => x.wall_ns), 99) }));
      }
      for (let index = 0; index < entries.length; index++) {
        const entry = entries[index];
        const id = `${name}-${operation}-${index}`;
        const input = operation === 'sign' ? `${name}.template.xml` : operation === 'verify' ? `${name}.signed.xml` : operation === 'encrypt' ? `${name}.plain.xml` : `${name}.encrypted.xml`;
        entry.input_bytes = fs.statSync(file(input)).size;
        entry.output_bytes = operation === 'verify' ? null : fs.statSync(file(`${name}.${operation}-${index}.output`)).size;
        entry.output_amplification = entry.output_bytes === null ? null : entry.output_bytes / entry.input_bytes;
        if (heapMode) {
          const log = path.join(rawDirectory, `${id}.memcheck.txt`);
          const massif = path.join(rawDirectory, `${id}.massif.txt`);
          const cmd = entry.commands;
          checked('valgrind', ['--tool=memcheck', '--leak-check=no', `--log-file=${log}`, ...cmd], { stdio: ['ignore', 'ignore', 'pipe'] });
          checked('valgrind', ['--tool=massif', '--stacks=no', '--time-unit=B', `--massif-out-file=${massif}`, ...cmd], { stdio: ['ignore', 'ignore', 'pipe'] });
          entry.memory = heapStats(fs.readFileSync(log, 'utf8'), fs.readFileSync(massif, 'utf8'));
        }
      }
      results.push(...entries);
    }
  }
  const digest = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  const report = { schema: 1, generated: new Date().toISOString(), source_revision: checked('git', ['rev-parse', 'HEAD']).stdout.trim(),
    environment: { platform: process.platform, architecture: process.arch, cpu: os.cpus()[0]?.model, node: process.version, samples, repetitions: 3,
      timing: 'unprofiled, warm filesystem cache, fresh processes; includes measurement wrapper and process launch',
      memory: 'RSS includes full process lifetime; optional Valgrind heap excludes stacks and non-malloc mmap allocations; profiling timing never used' },
    binaries: binaries.slice(0, 3).map(binary => {
      const cmd = [...loader, binary, '--version'];
      return { sha256: digest(binary), bytes: fs.statSync(binary).size, version: checked(cmd[0], cmd.slice(1)).stdout.trim() };
    }),
    corpus: fs.readdirSync(corpus).filter(name => /\.(template|signed|plain)\.xml$/.test(name) || ['keys.xml', 'encryption.xml', 'private.pem', 'public.pem', 'cases.json'].includes(name)).map(name => ({ name, sha256: digest(file(name)) })), results };
  fs.writeFileSync(path.join(root, 'comparison.json'), JSON.stringify(report));
  console.log(`Validated ${results.length} comparable cases; ${samples} samples x 3 repetitions, heap=${Boolean(heapMode)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
