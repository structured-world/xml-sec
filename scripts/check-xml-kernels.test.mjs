import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { DiagnosticGate, ownsSource } from './check-xml-kernels.mjs';

const root = resolve(import.meta.dirname, '..');
const warning = (file, extra = {}) => ({ reason: 'compiler-message', message: {
  level: 'warning', message: 'test diagnostic', code: { code: 'clippy::pedantic_test' },
  spans: [{ file_name: file, line_start: 12, column_start: 3, is_primary: true }], ...extra,
} });

test('scope follows physical XML implementations through every crate entry path', () => {
  // A path alias must not hide shared-source diagnostics, and unrelated
  // subsystems remain the responsibility of their own qualification gate.
  for (const path of ['crates/xml-sec-xml-input/src/lib.rs', 'src/document.rs', 'src/xml/dom/tree.rs', 'src/c14n/serialize.rs',
    'src/parser_xmloxide/parser/xml.rs', 'src/parser_roxmltree/parse.rs',
    'vendor/sxd-document-no-unsafe/../../src/sxd_document/parser.rs',
    'vendor/sxd-xpath-no-unsafe/../../src/sxd_xpath/lib.rs',
    'crates/xml-sec-xml-input/src/../../../src/xml_input/shared.rs']) {
    assert.equal(ownsSource(root, path), true, path);
  }
  for (const path of ['src/xmldsig/verify.rs', 'src/xslt/compiler.rs',
    'src/sxd_xpath_other/file.rs', '../other/src/sxd_xpath/lib.rs']) {
    assert.equal(ownsSource(root, path), false, path);
  }
});

test('the gate deduplicates aliases but retains distinct defects and macro callers', () => {
  // Standalone and embedded reports must not inflate counts, while an
  // expansion in an owned caller must not disappear behind a foreign macro.
  const gate = new DiagnosticGate(root, ownsSource);
  gate.accept(warning('src/sxd_xpath/lib.rs'));
  gate.accept(warning('vendor/sxd-xpath-no-unsafe/../../src/sxd_xpath/lib.rs'));
  gate.accept(warning('src/sxd_xpath/lib.rs', { message: 'different defect' }));
  gate.accept(warning('/foreign/macros.rs', { spans: [{ file_name: '/foreign/macros.rs',
    line_start: 1, is_primary: true, expansion: { span: { file_name: 'src/c14n/mod.rs',
      line_start: 20, column_start: 1 } } }] }));
  gate.accept(warning('src/provider.rs'));
  assert.equal(gate.failures.length, 3);
});

test('compiler errors and malformed streams cannot produce successful qualification', () => {
  // A build failure remains terminal even when no owned source span exists.
  const gate = new DiagnosticGate(root, ownsSource);
  gate.accept(warning('src/provider.rs', { level: 'error' }));
  gate.accept({ reason: 'compiler-message', message: { level: 'error', message: 'no span', spans: [] } });
  gate.acceptLine('not cargo JSON');
  gate.accept({ reason: 'build-finished', success: false });
  assert.equal(gate.failures.length, 4);
  assert.equal(gate.failures[1], 'Cargo: no span');
  assert.equal(gate.finished, false);
  gate.accept({ reason: 'build-finished', success: true });
  assert.equal(gate.finished, true);
  assert.equal(gate.failures.length, 4);
});

test('the executable checks every graph and never masks Cargo or diagnostic failures', () => {
  // Exercise the real CLI, including a child that exits successfully after
  // warnings or malformed output. Exit status alone cannot qualify a graph.
  const directory = mkdtempSync(join(tmpdir(), 'xml-sec-kernel-gate-'));
  try {
    const calls = join(directory, 'calls');
    writeFileSync(join(directory, 'cargo'), `#!/usr/bin/env node
import { appendFileSync } from 'node:fs';
appendFileSync(process.env.CALLS, JSON.stringify(process.argv.slice(2)) + '\\n');
const mode = process.env.MODE;
if (mode === 'bad-json') console.log('not JSON');
if (mode === 'invalid-event') console.log('42');
if (mode === 'owned' || mode === 'unrelated') console.log(JSON.stringify({reason:'compiler-message',message:{level:'warning',message:'test',spans:[{file_name:mode === 'owned' ? 'src/sxd_xpath/lib.rs' : 'src/provider.rs',line_start:1,is_primary:true}]}}));
if (mode !== 'missing-end') console.log(JSON.stringify({reason:'build-finished',success:mode !== 'failed-build'}));
process.exitCode = mode === 'exit-failure' ? 37 : 0;
`, { mode: 0o755 });
    for (const mode of ['clean', 'unrelated', 'owned', 'bad-json', 'invalid-event', 'missing-end', 'failed-build', 'exit-failure']) {
      writeFileSync(calls, '');
      const result = spawnSync(process.execPath, [join(import.meta.dirname, 'check-xml-kernels.mjs')], {
        cwd: root, encoding: 'utf8',
        env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, CALLS: calls, MODE: mode },
      });
      const success = mode === 'clean' || mode === 'unrelated';
      assert.equal(result.status === 0, success, `${mode}: ${result.stderr}`);
      const commands = readFileSync(calls, 'utf8').trim().split('\n').map(JSON.parse);
      assert.equal(commands.length, success ? 4 : 1);
      for (const command of commands) {
        assert.equal(command[0], 'clippy');
        assert.ok(command.includes('--force-warn'));
        assert.ok(command.includes('clippy::pedantic'));
        assert.ok(command.includes('--message-format=json'));
      }
      if (success) {
        assert.ok(commands[0].includes('--all-features'));
        assert.ok(commands[1].includes('--all-targets'));
        assert.ok(commands[2].includes('--no-default-features'));
        assert.ok(commands[3].includes('xml-sec-xml-input'));
        assert.ok(commands[3].includes('--no-default-features'));
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
