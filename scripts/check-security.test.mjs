import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import test from 'node:test';
import { DiagnosticGate } from './check-xml-kernels.mjs';
import { graphs, ownsSource } from './check-security.mjs';

const root = resolve(import.meta.dirname, '..');

test('security scope includes adapters, owned tests and expanded documentation', () => {
  // Physical paths must retain ownership through source and include aliases.
  for (const path of ['src/policy.rs', 'src/provider/key_association.rs',
    'src/operation/tests.rs', 'src/xmldsig/verify/session.rs',
    'src/xmlenc/decrypt.rs', 'crates/xml-sec-xades/src/signature.rs',
    'crates/xml-sec-xades/tests/basic.rs', 'tests/selected_key_receipts.rs',
    'src/xmldsig/../../docs/xmldsig.md', 'src/xmlenc/../../docs/xmlenc.md']) {
    assert.equal(ownsSource(root, path), true, path);
  }
  for (const path of ['src/xslt/runtime.rs', 'src/sxd_xpath/lib.rs',
    'src/parser_xmloxide/tokenizer.rs', 'src/provider_other.rs',
    'crates/xml-sec-config/src/settings.rs', 'tools/xmlsec1/src/args.rs',
    'tests/c14n_golden.rs', '../other/src/provider.rs']) {
    assert.equal(ownsSource(root, path), false, path);
  }
});

test('security qualification preserves global compiler and diagnostic failures', () => {
  // A foreign warning is not this component's debt, but errors cannot be hidden.
  const gate = new DiagnosticGate(root, ownsSource);
  const diagnostic = (file, level = 'warning') => ({ reason: 'compiler-message',
    message: { level, message: 'diagnostic', spans: [{ file_name: file,
      line_start: 1, column_start: 1, is_primary: true }] } });
  gate.accept(diagnostic('src/provider/key_association.rs'));
  gate.accept(diagnostic('src/provider/../provider/key_association.rs'));
  gate.accept(diagnostic('tools/xmlsec1/src/args.rs'));
  assert.equal(gate.failures.length, 1);
  gate.accept(diagnostic('tools/xmlsec1/src/args.rs', 'error'));
  gate.acceptLine('invalid JSON');
  gate.accept({ reason: 'build-finished', success: false });
  assert.equal(gate.failures.length, 4);
  assert.equal(gate.finished, false);
});

test('security entry graphs keep minimal DSig, encryption and adapter isolation', () => {
  // Sibling workspace features may not supply a missing minimal dependency.
  assert.equal(graphs.length, 5);
  assert.deepEqual(graphs[0][1], ['--workspace', '--all-targets', '--all-features']);
  assert.deepEqual(graphs[1][1], ['--workspace', '--all-targets']);
  assert.deepEqual(graphs[2][1], ['-p', 'xml-sec', '--lib', '--no-default-features',
    '--features', 'xmldsig,xml-backend-differential']);
  assert.deepEqual(graphs[3][1], ['-p', 'xml-sec', '--lib', '--no-default-features',
    '--features', 'xmlenc,xml-backend-differential']);
  assert.deepEqual(graphs[4][1], ['-p', 'xml-sec-xades', '--all-targets']);
});
