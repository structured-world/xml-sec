import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, rmSync, realpathSync } from 'node:fs';
import { resolve, join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { platform, release, cpus } from 'node:os';

export function summary(samples) {
  if (!samples.length || samples.some(n => !Number.isSafeInteger(n) || n <= 0)) throw Error('invalid timing samples');
  const sorted = [...samples].sort((a, b) => a - b);
  const percentile = p => sorted[Math.ceil(p * sorted.length) - 1];
  return { p50_ns: percentile(.5), p95_ns: percentile(.95), p99_ns: percentile(.99) };
}

export function validate(result, expectedSamples, sourceBytes, styleBytes, outputBytes, engine, phase) {
  if (result.samples_ns?.length !== expectedSamples || result.source_bytes !== sourceBytes ||
      result.stylesheet_bytes !== styleBytes || result.output_bytes !== outputBytes ||
      result.engine !== engine || result.phase !== phase) throw Error('inconsistent measurement');
  return { ...result, ...summary(result.samples_ns), output_amplification: outputBytes / sourceBytes };
}

export function resources(text, os) {
  const match = os === 'darwin' ? text.match(/(\d+)\s+maximum resident set size/) : text.match(/Maximum resident set size \(kbytes\):\s*(\d+)/);
  if (!match) throw Error('missing process peak RSS');
  return { peak_rss_bytes: Number(match[1]) * (os === 'darwin' ? 1 : 1024), rss_scope: 'whole process including preparation and warmups' };
}

export function checkOutputLocation(output, target) {
  output = canonicalLocation(resolve(output));
  target = canonicalLocation(resolve(target));
  if (output === target || output.startsWith(target + '/')) throw Error('evidence must be outside the cleaned build directory');
}

function canonicalLocation(path) {
  try { return realpathSync(path); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return join(canonicalLocation(dirname(path)), basename(path));
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 32 << 20, timeout: 30 * 60 * 1000, ...options });
  if (result.error || result.status !== 0) throw Error(`${command} failed: ${result.error ?? result.stderr}`);
  return result.stdout;
}

function main() {
  const [directory, count = '100'] = process.argv.slice(2);
  const samples = Number(count);
  if (!directory || !/^[0-9]+$/.test(count) || samples < 1 || samples > 100000) throw Error('usage: benchmark-xslt.mjs NEW_OUTPUT [1..100000 samples]');
  const nativeSource = process.env.LIBXSLT_SOURCE_DIR;
  const pinned = readFileSync('compatibility/libxslt-1.1.45-donor-commit.txt', 'utf8').trim();
  if (!nativeSource || run('git', ['-C', nativeSource, 'rev-parse', 'HEAD']).trim() !== pinned) throw Error('LIBXSLT_SOURCE_DIR must be the pinned libxslt checkout');
  if (run('git', ['-C', nativeSource, 'status', '--porcelain', '--untracked-files=no']).trim()) throw Error('pinned native source has tracked modifications');
  const output = resolve(directory);
  const target = JSON.parse(run('cargo', ['metadata', '--no-deps', '--format-version', '1'])).target_directory;
  checkOutputLocation(output, target);
  mkdirSync(output); // Refuse to overwrite evidence.
  const files = ['Cargo.toml', 'crates/xml-sec-xslt/Cargo.toml', 'src/xslt/lib.rs', 'src/xslt/runtime.rs', 'benches/support/xslt.rs', 'benchmarks/xslt-latency.rs', 'benchmarks/xslt-alloc.rs', 'benchmarks/xslt-oracle.c', 'benchmarks/cmake/libxml2/LibXml2Config.cmake', 'scripts/benchmark-xslt.mjs'];
  const fingerprint = () => files.map(path => [path, createHash('sha256').update(readFileSync(path)).digest('hex')]);
  const before = fingerprint();
  const diff = run('git', ['diff', '--binary', 'HEAD']);
  const environment = { revision: run('git', ['rev-parse', 'HEAD']).trim(), dirty: run('git', ['status', '--porcelain']),
    toolchain: run('rustc', ['-Vv']), os: platform(), release: release(), cpu: cpus()[0]?.model,
    sources: before, samples, repetitions: 3 };
  writeFileSync(join(output, 'environment.json'), JSON.stringify(environment, null, 2));
  run('cargo', ['build', '--release', '-p', 'xml-sec-xslt', '--example', 'xslt_latency', '--features', 'benchmark-internals']);
  writeFileSync(join(output, 'Cargo.lock'), readFileSync('Cargo.lock'));
  writeFileSync(join(output, 'dependencies.json'), run('cargo', ['metadata', '--locked', '--format-version', '1', '--features', 'xml-sec-xslt/benchmark-internals']));
  const nativeBuild = join(output, 'native-build');
  const nativePrefix = join(output, 'native');
  run('cmake', ['-S', nativeSource, '-B', nativeBuild, '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=' + nativePrefix,
    '-DLibXml2_DIR=' + resolve('benchmarks/cmake/libxml2'),
    '-DBUILD_SHARED_LIBS=OFF', '-DCMAKE_INSTALL_LIBDIR=lib', '-DLIBXSLT_WITH_PYTHON=OFF', '-DLIBXSLT_WITH_TESTS=OFF', '-DLIBXSLT_WITH_PROGRAMS=OFF']);
  run('cmake', ['--build', nativeBuild, '--parallel', '2']);
  run('cmake', ['--install', nativeBuild]);
  const nativeEnv = { ...process.env, PKG_CONFIG_PATH: join(nativePrefix, 'lib/pkgconfig') + (process.env.PKG_CONFIG_PATH ? ':' + process.env.PKG_CONFIG_PATH : '') };
  const flags = run('pkg-config', ['--static', '--cflags', '--libs', 'libxslt'], { env: nativeEnv }).trim().split(/\s+/);
  if (run('pkg-config', ['--variable=prefix', 'libxslt'], { env: nativeEnv }).trim() !== nativePrefix ||
      run('pkg-config', ['--modversion', 'libxslt'], { env: nativeEnv }).trim() !== '1.1.45') throw Error('native link configuration escaped the pinned build');
  environment.native_source = pinned;
  environment.native_flags = flags;
  environment.libxml_version = run('pkg-config', ['--modversion', 'libxml-2.0'], { env: nativeEnv }).trim();
  writeFileSync(join(output, 'environment.json'), JSON.stringify(environment, null, 2));
  writeFileSync(join(output, 'native-cmake-cache.txt'), readFileSync(join(nativeBuild, 'CMakeCache.txt')));
  const oracle = join(output, 'xslt-oracle');
  run('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', 'benchmarks/xslt-oracle.c', ...flags, '-o', oracle]);
  const allocationOracle = join(output, 'xslt-oracle-alloc');
  run('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-DXSLT_PROFILE', 'benchmarks/xslt-oracle.c', ...flags, '-o', allocationOracle]);
  const binary = join(target, 'release/examples/xslt_latency');
  const corpus = join(output, 'corpus');
  run(binary, ['--export', corpus]);
  const corpusFiles = ['items', 'amplification'].flatMap(shape => [16, 256].flatMap(size => ['xml', 'xsl', 'expected'].map(extension => join(corpus, `${shape}-${size}.${extension}`))));
  const corpusFingerprint = () => corpusFiles.map(path => [path, createHash('sha256').update(readFileSync(path)).digest('hex')]);
  const corpusBefore = corpusFingerprint();
  writeFileSync(join(output, 'corpus-sha256.json'), JSON.stringify(corpusBefore, null, 2));
  writeFileSync(join(output, 'binaries.json'), JSON.stringify([binary, oracle, allocationOracle].map(path => ({ path, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') })), null, 2));
  const observations = [];
  for (let repetition = 0; repetition < 3; repetition++) {
    for (const shape of ['items', 'amplification']) for (const size of [16, 256]) {
      const base = join(corpus, `${shape}-${size}`);
      const input = readFileSync(base + '.xml');
      const style = readFileSync(base + '.xsl');
      const expected = readFileSync(base + '.expected');
      for (const phase of ['compile', 'tree', 'serialize', 'retained', 'end_to_end']) {
        const engines = repetition % 2 ? ['libxslt', 'xml-sec'] : ['xml-sec', 'libxslt'];
        for (const engine of engines) {
          const name = `${engine}-${shape}-${size}-${phase}-${repetition}`;
          const args = engine === 'xml-sec' ? [phase, shape, String(size), count] : [phase, base + '.xsl', base + '.xml', base + '.expected', count];
          const command = engine === 'xml-sec' ? binary : oracle;
          const resourceFile = join(output, name + '.resources.txt');
          const result = spawnSync('/usr/bin/time', [platform() === 'darwin' ? '-l' : '-v', command, ...args], { encoding: 'utf8', timeout: 120000, maxBuffer: 16 << 20 });
          writeFileSync(resourceFile, result.stderr ?? '');
          if (result.error || result.status !== 0) throw Error(`measurement ${name} failed: ${result.error ?? result.stderr}`);
          const measured = validate(JSON.parse(result.stdout), samples, input.length, style.length, expected.length, engine, phase);
          const record = { ...measured, ...resources(result.stderr, platform()), shape, size, repetition, resources: name + '.resources.txt' };
          writeFileSync(join(output, name + '.json'), JSON.stringify(record, null, 2));
          observations.push(record);
        }
      }
    }
  }
  // Divan instrumentation is deliberately excluded from latency records.
  writeFileSync(join(output, 'allocations.txt'), run('cargo', ['bench', '--locked', '-p', 'xml-sec-xslt', '--bench', 'xslt', '--features', 'benchmark-internals', '--', '--sample-count', '3', '--sample-size', '1']));
  for (const shape of ['items', 'amplification']) for (const size of [16, 256]) {
    const base = join(corpus, `${shape}-${size}`);
    for (const phase of ['compile', 'tree', 'serialize', 'retained', 'end_to_end']) {
      const result = JSON.parse(run(allocationOracle, [phase, base + '.xsl', base + '.xml', base + '.expected', '1']));
      if (!(result.allocation_calls > 0) || !(result.allocated_bytes > 0) || result.extra_peak_xml_bytes < 0) throw Error('native allocation hooks did not observe the phase');
      // Instrumented timings are deliberately not published as latency samples.
      delete result.samples_ns;
      writeFileSync(join(output, `allocations-libxslt-${shape}-${size}-${phase}.json`), JSON.stringify(result, null, 2));
    }
  }
  // Native-aware allocations use separate instrumented processes. They are
  // full-process measurements, not comparable to Divan's per-phase counters.
  if (process.env.XSLT_BENCH_HEAP === '1') {
    for (const shape of ['items', 'amplification']) for (const size of [16, 256]) {
      const base = join(corpus, `${shape}-${size}`);
      for (const phase of ['compile', 'tree', 'serialize', 'retained', 'end_to_end']) {
        const args = [oracle, phase, base + '.xsl', base + '.xml', base + '.expected', '1'];
        const name = `libxslt-${shape}-${size}-${phase}`;
        run('valgrind', ['--tool=memcheck', '--error-exitcode=91', '--log-file=' + join(output, name + '.memcheck.txt'), ...args]);
        run('valgrind', ['--tool=massif', '--massif-out-file=' + join(output, name + '.massif'), ...args]);
      }
    }
  }
  if (JSON.stringify(before) !== JSON.stringify(fingerprint()) || JSON.stringify(corpusBefore) !== JSON.stringify(corpusFingerprint()) || diff !== run('git', ['diff', '--binary', 'HEAD']) || !readFileSync('Cargo.lock').equals(readFileSync(join(output, 'Cargo.lock')))) throw Error('sources, corpus or dependency graph changed during run');
  writeFileSync(join(output, 'results.json'), JSON.stringify({ schema: 1, observations }, null, 2));
  run('cargo', ['clean']);
  rmSync(oracle);
  rmSync(allocationOracle);
  run('cmake', ['--build', nativeBuild, '--target', 'clean']);
  rmSync(nativeBuild, { recursive: true });
  rmSync(nativePrefix, { recursive: true });
  console.log(`XSLT measurements passed; evidence retained in ${output}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
