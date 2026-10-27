import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { clean } from '../.github/actions/clean-build-output/cleanup.mjs';
import { identity } from '../.github/actions/runner-image/identity.mjs';

const source = path => readFileSync(new URL('../' + path, import.meta.url), 'utf8');

test('dependency saving precedes successful cleanup, with failed builds retained', () => {
  // Reverse post-action order must save before cargo clean, never after it.
  const cache = source('.github/actions/rust-build-cache/action.yml');
  assert.ok(cache.indexOf('uses: ./.github/actions/clean-build-output') < cache.indexOf('uses: Swatinem/rust-cache'));
  assert.match(source('.github/actions/clean-build-output/action.yml'), /post-if: success\(\)/);
  assert.match(cache, /shared-key: \$\{\{ inputs.domain \}\}-\$\{\{ steps.image.outputs.identity \}\}/);
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

test('a failed fuzz run keeps its grown corpus although the cache is not saved', () => {
  // actions/cache saves only on success; the artifact is the failed run's only copy.
  const workflow = source('.github/workflows/fuzz.yml');
  assert.match(workflow, /if: failure\(\)\n\s+uses: actions\/upload-artifact@v7\n\s+with:\n\s+name: fuzz-corpus-[^\n]+\n\s+path: fuzz\/corpus\n/);
});

test('benchmark and fuzz evidence is kept for one day', () => {
  // These artifacts serve inspection of a recent run only; no later run reads them.
  const uploads = ['ci.yml', 'benchmark-comparison.yml', 'fuzz.yml'].flatMap(file =>
    [...source(`.github/workflows/${file}`).matchAll(/uses: actions\/upload-artifact@v7\n(?:\s+if: [^\n]+\n)?\s+with:\n\s+name: ([^\n]+)\n[\s\S]*?retention-days: (\d+)/g)]
      .map(([, name, days]) => [name, days]));
  const evidence = uploads.filter(([name]) => /^(benchmark-comparison|benchmark-smoke-|fuzz-)/.test(name));
  assert.equal(evidence.length, 5);
  for (const [name, days] of evidence) assert.equal(days, '1', name);
});

test('the benchmark observatory deletes its site artifact after deploying it', () => {
  // The Pages artifact is consumed by the deployment of the same run only.
  const workflow = source('.github/workflows/benchmarks.yml');
  const deployed = workflow.indexOf('uses: actions/deploy-pages@v5');
  const deleted = workflow.indexOf('gh api --method DELETE "repos/$GITHUB_REPOSITORY/actions/artifacts/$id"');
  assert.ok(deployed >= 0 && deleted > deployed);
  assert.ok(workflow.includes('actions/runs/$GITHUB_RUN_ID/artifacts?name=github-pages'));
  assert.match(workflow, /actions: write/);
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
  assert.equal([...workflow.matchAll(/profile: modern/g)].length, 2);
  assert.equal([...workflow.matchAll(/profile: legacy/g)].length, 1);
  assert.doesNotMatch(workflow, /if:.*cache-hit/);
  assert.ok(source('.github/actions/xmlsec-oracle-cache/action.yml').includes("hashFiles('scripts/install-xmlsec1.sh', 'compatibility/libxmlsec1-1.3.13-donor-commit.txt')"));
  assert.equal([...workflow.matchAll(/(?:bash )?scripts\/install-xmlsec1.sh\n/g)].length, 3);
});

test('runner image identity is read at runtime rather than an empty env context', () => {
  // Hosted-runner ImageOS is process environment, not a workflow env entry.
  assert.doesNotMatch(source('.github/workflows/ci.yml'), /\$\{\{ env.ImageOS \}\}/);
  assert.match(source('.github/actions/rust-build-cache/action.yml'), /steps.image.outputs.identity/);
  assert.match(source('.github/actions/xmlsec-oracle-cache/action.yml'), /steps.image.outputs.identity/);
  for (const image of ['ubuntu24', 'ubuntu26', 'macos26', 'win25']) {
    assert.equal(identity({ ImageOS: image }), image);
  }
  assert.notEqual(identity({ ImageOS: 'ubuntu24' }), identity({ ImageOS: 'ubuntu26' }));
  for (const image of [undefined, '', 'ubuntu24\nother=value']) {
    assert.throws(() => identity({ ImageOS: image }));
  }
});
