import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import test from 'node:test';
import { DiagnosticGate } from './check-xml-kernels.mjs';
import { graphs, ownsSource } from './check-xslt.mjs';

const root = resolve(import.meta.dirname, '..');

test('XSLT scope resolves embedded, standalone and benchmark physical sources', () => {
  // Shared physical sources must not disappear behind Cargo entry-point aliases.
  for (const path of ['src/xslt/compiler.rs', 'src/xslt/runtime/tests.rs',
    'crates/xml-sec-xslt/../../src/xslt/xpath.rs',
    'crates/xml-sec-xslt/tests/engine.rs',
    'crates/xml-sec-xslt/../../benchmarks/../benches/support/xslt.rs',
    'benchmarks/xslt-latency.rs', 'benchmarks/xslt-alloc.rs']) {
    assert.equal(ownsSource(root, path), true, path);
  }
  for (const path of ['src/xslt_other/file.rs', '../other/src/xslt/runtime.rs',
    'src/provider.rs', 'src/sxd_xpath/lib.rs']) {
    assert.equal(ownsSource(root, path), false, path);
  }
});

test('XSLT diagnostics use the shared gate without weakening terminal errors', () => {
  // Foreign warnings belong to other components; any compiler error remains fatal.
  const gate = new DiagnosticGate(root, ownsSource);
  const diagnostic = (file, level = 'warning') => ({ reason: 'compiler-message',
    message: { level, message: 'diagnostic', spans: [{ file_name: file,
      line_start: 1, column_start: 1, is_primary: true }] } });
  gate.accept(diagnostic('src/xslt/compiler.rs'));
  gate.accept(diagnostic('crates/xml-sec-xslt/../../src/xslt/compiler.rs'));
  gate.accept(diagnostic('src/provider.rs'));
  assert.equal(gate.failures.length, 1);
  gate.accept(diagnostic('src/provider.rs', 'error'));
  gate.acceptLine('not JSON');
  gate.accept({ reason: 'build-finished', success: false });
  assert.equal(gate.failures.length, 4);
  assert.equal(gate.finished, false);
});

test('XSLT qualification retains separate standalone and embedded feature graphs', () => {
  // No feature union may accidentally supply a missing embedded dependency.
  assert.equal(graphs.length, 4);
  assert.deepEqual(graphs[0][1], ['-p', 'xml-sec-xslt', '--all-targets', '--all-features']);
  assert.deepEqual(graphs[1][1], ['-p', 'xml-sec', '--all-targets', '--features', 'xslt']);
  assert.deepEqual(graphs[2][1], ['--workspace', '--all-targets', '--all-features']);
  assert.deepEqual(graphs[3][1], ['-p', 'xml-sec', '--lib', '--no-default-features',
    '--features', 'xslt,xml-backend-differential']);
});
