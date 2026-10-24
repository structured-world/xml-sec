import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { clean } from '../.github/actions/clean-build-output/cleanup.mjs';

const source = path => readFileSync(new URL('../' + path, import.meta.url), 'utf8');

test('dependency saving precedes successful cleanup, with failed builds retained', () => {
  // Reverse post-action order must save before cargo clean, never after it.
  const cache = source('.github/actions/rust-build-cache/action.yml');
  assert.ok(cache.indexOf('uses: ./.github/actions/clean-build-output') < cache.indexOf('uses: Swatinem/rust-cache'));
  assert.match(source('.github/actions/clean-build-output/action.yml'), /post-if: success\(\)/);
  assert.match(cache, /shared-key: \$\{\{ inputs.domain \}\}/);
  assert.match(cache, /save-if: \$\{\{ inputs.save \}\}/);
  assert.doesNotMatch(cache, /add-rust-environment-hash-key: false/);
});

test('cleanup addresses the selected workspace and propagates process failures', () => {
  // Cleanup may not touch another workspace or conceal a failed clean command.
  clean('fuzz/Cargo.toml', 'nightly', (file, args) => {
    assert.equal(file, 'cargo');
    assert.deepEqual(args, ['+nightly', 'clean', '--manifest-path', 'fuzz/Cargo.toml']);
    return { status: 0 };
  });
  for (const result of [{ status: 7 }, { signal: 'SIGTERM' }, { error: new Error('spawn failed') }]) {
    assert.throws(() => clean('Cargo.toml', 'stable', () => result));
  }
  assert.throws(() => clean('', 'stable'));
});

test('saving dependencies cannot remove the toolchain needed by post cleanup', () => {
  // rust-cache bin cleanup can remove runner-provided Cargo/rustup shims.
  const action = source('.github/actions/rust-build-cache/action.yml');
  assert.match(action, /cache-bin: 'false'/);
});

test('PR smoke uses three jobs while long campaigns retain target parallelism', () => {
  // Only runner granularity changes: every campaign target and FIPS remain.
  const workflow = source('.github/workflows/fuzz.yml');
  const expression = workflow.match(/target: \$\{\{ fromJSON\((.*?)\) \}\}/)?.[1];
  assert.ok(expression);
  const arrays = [...expression.matchAll(/'(\[[^']+\])'/g)].map(match => JSON.parse(match[1]));
  assert.deepEqual(arrays[1], ['asan']);
  assert.deepEqual(arrays[0], ['xmldsig_verify', 'xml_semantics', 'security_roundtrip',
    'transform_parameters', 'xslt_execution', 'key_formats', 'policy_compilation', 'provider_operations']);
  assert.match(workflow, /target: provider_operations\n\s+fips: true/);
  assert.match(workflow, /target: xmlsec_oracle\n\s+fips: false/);
  assert.match(workflow, /fuzz-security.sh "\$TARGET" "\$MODE" --cache-managed/);
});

test('legacy corpus cache identities remain independently restorable', () => {
  // Grouping must not discard the evolving corpora already saved by target.
  const action = source('.github/actions/fuzz-corpus/action.yml');
  for (const target of ['xmldsig_verify', 'xml_semantics', 'security_roundtrip', 'transform_parameters',
    'xslt_execution', 'key_formats', 'policy_compilation', 'provider_operations', 'xmlsec_oracle']) {
    assert.ok(action.includes(`path: fuzz/corpus/${target}\n`));
    assert.ok(action.includes(`restore-keys: fuzz-corpus-\$\{\{ runner.os \}\}-${target}-`));
  }
  assert.match(action, /provider_operations-\$\{\{ inputs.fips \}\}/);
});

test('ordinary jobs have one matrix writer per compiler and separate instrumented domains', () => {
  // Compatible readers share dependencies without partial feature writers racing.
  const workflow = source('.github/workflows/ci.yml');
  assert.match(workflow, /save: \$\{\{ matrix.block == 'msrv-extended' \|\| matrix.block == 'stable-extended' \}\}/);
  assert.match(workflow, /save: \$\{\{ !matrix.minimal \}\}/);
  assert.match(workflow, /domain: coverage\n\s+save: 'true'/);
  assert.match(workflow, /check-xslt-conformance.sh --cache-managed/);
  assert.doesNotMatch(workflow, /run: cargo clean/);
  assert.match(workflow, /CARGO_TARGET_DIR: \$\{\{ runner.temp \}\}\/xslt-measurement/);
});

test('cached native oracles still pass installer provenance and capability validation', () => {
  // A cache hit must not bypass validation or share modern and legacy profiles.
  const workflow = source('.github/workflows/ci.yml');
  assert.equal([...workflow.matchAll(/key: xmlsec-oracle-.*-modern-/g)].length, 2);
  assert.equal([...workflow.matchAll(/key: xmlsec-oracle-.*-legacy-/g)].length, 1);
  assert.doesNotMatch(workflow, /if:.*cache-hit/);
  assert.ok(workflow.includes("hashFiles('scripts/install-xmlsec1.sh', 'compatibility/libxmlsec1-1.3.13-donor-commit.txt')"));
  assert.equal([...workflow.matchAll(/(?:bash )?scripts\/install-xmlsec1.sh\n/g)].length, 3);
});
