import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BOUNDARIES, BOUNDARY_DESCRIPTIONS, enginesFrom, harnessOutcome, validateReport } from './compare-library.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const request = { engine: 'xml-sec', scenario: 'assertion', operation: 'verify', boundary: 'parse', samples: 2 };
const report = { ...request, samples_ns: [10, 20], allocations: null, input_bytes: 5, output_bytes: null };

test('harness exit statuses separate unsupported work from failures', () => {
  // An unsupported operation is recorded with its reason, never as a failure or a timing.
  assert.deepEqual(harnessOutcome({ status: 3, stdout: '', stderr: 'unsupported: no XSLT\n' }),
    { kind: 'unsupported', reason: 'no XSLT' });
  assert.equal(harnessOutcome({ status: 4, stdout: '', stderr: 'operation: digest mismatch' }).kind, 'failed');
  assert.equal(harnessOutcome({ status: null, signal: 'SIGKILL', stdout: '', stderr: '' }).kind, 'failed');
  assert.equal(harnessOutcome({ status: 0, stdout: '{"engine":"x","rejected":true}\n', stderr: '' }).kind, 'rejected');
  assert.equal(harnessOutcome({ status: 0, stdout: JSON.stringify(report), stderr: '' }).kind, 'measured');
});

test('malformed or mismatched harness reports are refused', () => {
  // A truncated line or a report for another request must never become a timing entry.
  assert.deepEqual(harnessOutcome({ status: 0, stdout: '{"engine":', stderr: '' }),
    { kind: 'failed', reason: 'malformed harness report' });
  assert.equal(validateReport(report, request), report);
  for (const broken of [
    { ...report, engine: 'bergshamra' },
    { ...report, boundary: 'prepared' },
    { ...report, samples_ns: [10] },
    { ...report, samples_ns: [10, 0] },
    { ...report, samples_ns: [10, 1.5] },
    { ...report, allocations: { calls: 1, bytes: -1, peak_bytes: 0 } },
    { ...report, allocations: { calls: 1 } },
    { ...report, input_bytes: 0 },
  ]) assert.throws(() => validateReport(broken, request));
  assert.equal(validateReport({ ...report, allocations: { calls: 3, bytes: 64, peak_bytes: 32 } }, request).allocations.calls, 3);
});

test('every harness binary must exist before any measurement starts', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-library-test-'));
  try {
    const binary = path.join(directory, 'harness');
    fs.writeFileSync(binary, '');
    const complete = { LIBRARY_XMLSEC_BIN: binary, LIBRARY_BERGSHAMRA_BIN: binary, LIBRARY_LIBXMLSEC1_BIN: binary };
    assert.equal(enginesFrom(complete).length, 3);
    assert.equal(enginesFrom(complete).every(engine => engine.profileBinary === null), true);
    for (const variable of Object.keys(complete)) {
      assert.throws(() => enginesFrom({ ...complete, [variable]: undefined }), new RegExp(`Missing ${variable}`));
      assert.throws(() => enginesFrom({ ...complete, [variable]: path.join(directory, 'absent') }), new RegExp(`Missing ${variable}`));
    }
    // A named profile build that does not exist is an error, not an unprofiled run.
    assert.throws(() => enginesFrom({ ...complete, LIBRARY_XMLSEC_PROFILE_BIN: path.join(directory, 'absent') }),
      /Missing LIBRARY_XMLSEC_PROFILE_BIN/);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test('invalid runner arguments are refused before any work', () => {
  for (const samples of ['0', '1001', 'invalid']) {
    const result = spawnSync(process.execPath, ['scripts/compare-library.mjs', os.tmpdir(), samples], { cwd: root, encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Usage: compare-library\.mjs/);
  }
});

/**
 * A fake harness following the request protocol. `behaviour` selects one defect:
 * accept a forgery, return the wrong plaintext, or lack signing (exit 3).
 */
function fakeHarness(directory, name, behaviour) {
  const file = path.join(directory, name);
  fs.writeFileSync(file, `#!${process.execPath}
const fs = require('node:fs');
const [scenario, operation, boundary, corpus, input, output, samples] = process.argv.slice(2);
const behaviour = ${JSON.stringify(behaviour)};
const signed = '<samlp:Response><saml:Assertion ID="assertion"><ds:Signature><ds:X509Certificate>c</ds:X509Certificate></ds:Signature>'
  + '<saml:Subject><saml:NameID>user@example.invalid</saml:NameID></saml:Subject>'
  + '<saml:AttributeValue>value</saml:AttributeValue></saml:Assertion></samlp:Response>';
if (operation === 'sign' && behaviour === 'no-signing') { console.error('unsupported: cannot sign'); process.exit(3); }
if (operation === 'reject') {
  if (behaviour === 'accept-forgery') { console.error('verification accepted an input it must refuse'); process.exit(4); }
  console.log(JSON.stringify({ engine: ${JSON.stringify(name)}, rejected: true }));
  process.exit(0);
}
const result = { sign: signed, encrypt: '<EncryptedData/>',
  decrypt: behaviour === 'wrong-plaintext' ? '<Other/>' : fs.readFileSync(corpus + '/element-16.plain.xml', 'utf8') }[operation];
if (result !== undefined && output !== '-') fs.writeFileSync(output, result);
console.log(JSON.stringify({ engine: ${JSON.stringify(name)}, scenario, operation, boundary,
  samples_ns: Array.from({ length: Number(samples) }, () => 1000), allocations: null, input_bytes: 10,
  output_bytes: result === undefined ? null : result.length }));
`);
  fs.chmodSync(file, 0o755);
  return file;
}

function runFakeComparison(scenario, behaviours) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'xml-sec-library-run-'));
  const corpus = path.join(directory, 'corpus');
  fs.mkdirSync(corpus);
  fs.writeFileSync(path.join(corpus, 'cases.json'), JSON.stringify([{ name: `${scenario}-16`, scenario, units: 16 }]));
  for (const file of ['assertion-16.template.xml', 'element-16.plain.xml']) fs.writeFileSync(path.join(corpus, file), '<Payment Id="payment"/>');
  const environment = { ...process.env, LIBRARY_XMLSEC_PROFILE_BIN: '', LIBRARY_BERGSHAMRA_PROFILE_BIN: '', LIBRARY_LIBXMLSEC1_PROFILE_BIN: '' };
  for (const [variable, id] of [['LIBRARY_XMLSEC_BIN', 'xml-sec'], ['LIBRARY_BERGSHAMRA_BIN', 'bergshamra'], ['LIBRARY_LIBXMLSEC1_BIN', 'libxmlsec1']])
    environment[variable] = fakeHarness(directory, id, behaviours[id] ?? 'honest');
  const result = spawnSync(process.execPath, ['scripts/compare-library.mjs', directory, '2'], { cwd: root, encoding: 'utf8', env: environment });
  const report = fs.existsSync(path.join(directory, 'library.json')) ? JSON.parse(fs.readFileSync(path.join(directory, 'library.json'), 'utf8')) : null;
  fs.rmSync(directory, { recursive: true });
  return { result, report };
}

test('a verifier that accepts a forgery stops the run before any timing', () => {
  const { result, report } = runFakeComparison('assertion', { bergshamra: 'accept-forgery' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Invalid tampered rejection: bergshamra/);
  assert.equal(report, null);
});

test('a decryptor that returns other plaintext stops the run before any timing', () => {
  const { result, report } = runFakeComparison('element', { libxmlsec1: 'wrong-plaintext' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Plaintext mismatch: .* -> libxmlsec1/);
  assert.equal(report, null);
});

test('an operation an engine lacks is recorded with its reason and never timed', () => {
  const { result, report } = runFakeComparison('assertion', { bergshamra: 'no-signing' });
  assert.equal(result.status, 0, result.stderr);
  const signing = report.results.filter(entry => entry.operation === 'sign');
  const lacking = signing.filter(entry => entry.unsupported);
  assert.deepEqual(lacking.map(entry => [entry.engine, entry.boundary, entry.unsupported]),
    [['bergshamra / Uppsala / RustCrypto', 'parse', 'cannot sign'], ['bergshamra / Uppsala / RustCrypto', 'prepared', 'cannot sign']]);
  assert.ok(lacking.every(entry => !Object.hasOwn(entry, 'repetitions')));
  // Every other engine and operation is measured, three repetitions each.
  assert.equal(report.results.length, 3 * 2 * 2);
  assert.ok(report.results.filter(entry => !entry.unsupported).every(entry => entry.repetitions.length === 3));
});

test('each boundary carries its published description', () => {
  assert.deepEqual(Object.keys(BOUNDARY_DESCRIPTIONS), BOUNDARIES);
});

test('the product dependency graph never contains the competitor', () => {
  // Bergshamra and its crypto crate may be linked only from the separate benchmark project.
  const result = spawnSync('cargo', ['metadata', '--format-version', '1', '--all-features'], { cwd: root, encoding: 'utf8', maxBuffer: 256 << 20 });
  assert.equal(result.status, 0, result.stderr);
  const names = JSON.parse(result.stdout).packages.map(item => item.name);
  assert.ok(names.includes('xml-sec'));
  assert.deepEqual(names.filter(name => name.startsWith('bergshamra') || name === 'kryptering' || name === 'uppsala'), []);
  const competitors = spawnSync('cargo', ['metadata', '--format-version', '1', '--manifest-path', 'benchmarks/competitors/Cargo.toml', '--no-deps'],
    { cwd: root, encoding: 'utf8' });
  assert.equal(competitors.status, 0, competitors.stderr);
  assert.notEqual(JSON.parse(competitors.stdout).workspace_root, root);
});
