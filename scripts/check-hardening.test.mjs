import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { checkReport } from './check-coverage-report.mjs';

const report = files => ({ type: 'llvm.coverage.json.export', data: [{
  files: files.map(filename => ({ filename })),
  totals: { lines: { count: 100, covered: 85, percent: 85 } },
}] });

test('coverage identities are unique physical sources, not independently selected percentages', () => {
  // The same embedded source must not contribute two denominators.
  const canonical = name => resolve(name);
  assert.equal(checkReport(report(['/source.rs']), canonical).covered, 85);
  assert.throws(() => checkReport(report(['/source.rs', '/source.rs']), canonical), /Duplicate/);
  assert.throws(() => checkReport(report(['/lib/../source.rs']), canonical), /Noncanonical/);
  for (const invalid of [{}, report([]), { ...report(['/source.rs']), data: [] }]) {
    assert.throws(() => checkReport(invalid, canonical), /nonempty/);
  }
  const invalid = report(['/source.rs']);
  invalid.data[0].totals.lines.covered = 101;
  assert.throws(() => checkReport(invalid, canonical), /totals/);
});

test('the coverage CLI validates reports through symlinked directories', () => {
  // A symlinked checkout must not turn an invalid report into a successful no-op.
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'xml-sec-coverage-cli-')));
  try {
    const linked = join(directory, 'linked');
    symlinkSync(import.meta.dirname, linked, 'dir');
    const source = join(directory, 'source.rs');
    writeFileSync(source, '');
    const fixture = join(directory, 'report.json');
    for (const script of [join(import.meta.dirname, 'check-coverage-report.mjs'),
      join(linked, 'check-coverage-report.mjs')]) {
      const invoke = args => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
      writeFileSync(fixture, JSON.stringify(report([source, source])));
      const duplicate = invoke([fixture]);
      assert.notEqual(duplicate.status, 0, `${script} silently accepted duplicate sources`);
      assert.match(duplicate.stderr, /Duplicate coverage source/);
      writeFileSync(fixture, '{}');
      const malformed = invoke([fixture]);
      assert.notEqual(malformed.status, 0);
      assert.match(malformed.stderr, /Expected one nonempty LLVM coverage export/);
      const usage = invoke([]);
      assert.notEqual(usage.status, 0);
      assert.match(usage.stderr, /Usage: check-coverage-report/);
      writeFileSync(fixture, JSON.stringify(report([source])));
      const valid = invoke([fixture]);
      assert.equal(valid.status, 0, valid.stderr);
      assert.deepEqual(JSON.parse(valid.stdout), { sources: 1, count: 100, covered: 85, percent: 85 });
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function run(phase = 'all', changes = {}) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'xml-sec-hardening-')));
  try {
    const bin = join(directory, 'bin');
    mkdirSync(bin);
    const calls = join(directory, 'calls');
    const flags = join(directory, 'flags');
    const source = join(directory, 'source.rs');
    writeFileSync(source, '');
    const fixture = join(directory, 'coverage.json');
    writeFileSync(fixture, JSON.stringify(report([source])));
    writeFileSync(calls, '');
    writeFileSync(join(bin, 'rustup'), `#!/usr/bin/env bash
printf 'rustup %s\\n' "$*" >> "$CALLS"
if [[ "\${FAIL_PHASE:-}" == rustup ]]; then exit 37; fi
`, { mode: 0o755 });
    writeFileSync(join(bin, 'cargo'), `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$CALLS"
if [[ "$1" == "\${FAIL_PHASE:-}" || "$1 $2" == "\${FAIL_PHASE:-}" ]]; then exit 37; fi
if [[ "$1 $2" == 'llvm-cov show-env' ]]; then
  printf '%s' "\${CARGO_ENCODED_RUSTFLAGS:-}" > "$FLAGS"
  printf 'export CARGO_LLVM_COV=1\\n'
fi
if [[ "$1 $2" == 'llvm-cov report' ]]; then
  previous=''
  for arg in "$@"; do
    # In show-env mode report consumes the existing build; build-selection
    # flags are rejected even though ordinary report help lists some of them.
    if [[ "$arg" == '--workspace' || "$arg" == '--all-features' ]]; then exit 41; fi
    if [[ "$previous" == '--output-path' ]]; then cp "$REPORT_FIXTURE" "$arg"; fi
    previous=$arg
  done
fi
`, { mode: 0o755 });
    const result = spawnSync('/bin/bash', [resolve(import.meta.dirname, 'check-hardening.sh'),
      phase, join(directory, 'evidence')], {
      cwd: resolve(import.meta.dirname, '..'), encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, TMPDIR: directory,
        CALLS: calls, FLAGS: flags, REPORT_FIXTURE: fixture, PKCS11_MODULE: '/test/module',
        RUSTFLAGS: '-Dwarnings', CARGO_ENCODED_RUSTFLAGS: '', FAIL_PHASE: '', ...changes },
    });
    return { ...result, calls: readFileSync(calls, 'utf8'),
      flags: result.status === 0 && ['coverage', 'all'].includes(phase) ? readFileSync(flags, 'utf8') : '' };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('the runner preserves every source and delegates the 85 percent gate to LLVM', () => {
  // No regex/package exclusion or tolerated test failure can manufacture coverage.
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.calls, /deny --all-features check --config deny.toml advisories sources/);
  assert.match(result.calls, /deny --manifest-path fuzz\/Cargo.toml/);
  assert.match(result.calls, /clippy --workspace --lib --all-features -- -D warnings -D unsafe_code/);
  assert.match(result.calls, /nextest run --workspace --features pkcs11 --all-features/);
  assert.ok(result.calls.indexOf('rustup component add llvm-tools-preview')
    < result.calls.indexOf('llvm-cov show-env'));
  assert.match(result.calls, /rustup component add llvm-tools-preview/);
  assert.match(result.calls, /report --package \* --fail-under-lines 85/);
  assert.match(result.calls, /report --package \* --lcov/);
  assert.doesNotMatch(result.calls, /--exclude|--ignore|--filter/);
  assert.match(result.flags, /-Dwarnings/);
  for (const name of ['xml-sec-xslt', 'sxd-document-no-unsafe', 'sxd-xpath-no-unsafe', 'xml-sec-xml-input']) {
    assert.ok(result.flags.includes(name));
  }
  const encoded = '-C\x1flink-arg=one two';
  assert.ok(run('coverage', { CARGO_ENCODED_RUSTFLAGS: encoded }).flags.startsWith(`${encoded}\x1f`));
});

test('every failed gate stops qualification with the original exit status', () => {
  // A report or later command must never mask setup, safety or test failure.
  for (const phase of ['deny', 'clippy', 'rustup', 'llvm-cov clean', 'llvm-cov show-env', 'nextest', 'llvm-cov report']) {
    const result = run('all', { FAIL_PHASE: phase });
    assert.equal(result.status, 37, `${phase}: ${result.stderr}`);
    assert.ok(!result.calls.includes('--lcov'));
  }
});

test('unknown phases fail without invoking Cargo', () => {
  // A typo must not silently skip a required gate.
  const result = run('typo');
  assert.equal(result.status, 2);
  assert.equal(result.calls, '');
});

test('coverage checkout references resolve existing pinned oracle revisions', () => {
  // Validate the actual setup program, not just YAML syntax: a misspelled
  // metadata filename otherwise prevents the coverage runner from starting.
  const workflow = readFileSync(resolve(import.meta.dirname, '../.github/workflows/ci.yml'), 'utf8');
  const coverage = workflow.match(/^  coverage:\n([\s\S]*?)(?=^  [a-z][a-z0-9-]*:)/m)[1];
  const script = coverage.match(/id: coverage-oracles\n        run: \|\n((?: {10}.*\n)+)/)[1]
    .replace(/^ {10}/gm, '');
  const directory = mkdtempSync(join(tmpdir(), 'xml-sec-oracle-pins-'));
  try {
    const output = join(directory, 'output');
    const result = spawnSync('/bin/bash', ['-e', '-o', 'pipefail', '-c', script], {
      cwd: resolve(import.meta.dirname, '..'), encoding: 'utf8',
      env: { ...process.env, GITHUB_OUTPUT: output },
    });
    assert.equal(result.status, 0, result.stderr);
    const pins = Object.fromEntries(readFileSync(output, 'utf8').trim().split('\n').map(line => line.split('=')));
    for (const donor of ['libxmlsec1-1.3.13', 'libxslt-1.1.45']) {
      assert.equal(pins[donor], readFileSync(resolve(import.meta.dirname,
        `../compatibility/${donor}-donor-commit.txt`), 'utf8').trim());
      assert.ok(coverage.includes(`steps.coverage-oracles.outputs['${donor}']`));
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('the required aggregate reaches every job and checks every direct result', () => {
  // These owned workflow blocks use single-line needs; fail on an unconnected
  // job rather than accepting a green subset of the qualification graph.
  const workflow = readFileSync(resolve(import.meta.dirname, '../.github/workflows/ci.yml'), 'utf8');
  const jobs = [...workflow.slice(workflow.indexOf('\njobs:\n')).matchAll(/^  ([a-z][a-z0-9-]*):\n([\s\S]*?)(?=^  [a-z][a-z0-9-]*:|$(?![\s\S]))/gm)];
  const graph = new Map(jobs.map(([, name, body]) => {
    const value = body.match(/^    needs: (.+)$/m)?.[1];
    return [name, { body, needs: value ? value.replace(/[\[\]]/g, '').split(',').map(x => x.trim()) : [] }];
  }));
  assert.ok(graph.size > 10);
  const seen = new Set();
  function visit(name) {
    assert.ok(graph.has(name), `unknown job ${name}`);
    if (seen.has(name)) return;
    seen.add(name);
    for (const dependency of graph.get(name).needs) visit(dependency);
  }
  visit('test');
  assert.deepEqual([...seen].sort(), [...graph.keys()].sort());
  const aggregate = graph.get('test');
  assert.match(aggregate.body, /if: \$\{\{ always\(\) \}\}/);
  for (const name of aggregate.needs) {
    assert.ok(aggregate.body.includes(`test "\${{ needs.${name}.result }}" = "success"`), name);
  }
});
