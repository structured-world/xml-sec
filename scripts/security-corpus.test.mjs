import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inventory, safePath, audit } from './security-corpus.mjs';

test('inventory retains keyword false positives and all contributing sources', () => {
  // An audit cannot silently discard an advisory merely because it names a wrapper.
  const nvd = { vulnerabilities: [{ cve: {
    id: 'CVE-2025-1', published: '2025-01-01', vulnStatus: 'Rejected',
    descriptions: [{ lang: 'en', value: 'wrapper, not native library' }],
    references: [{ url: 'https://example.org/fix' }],
  } }] };
  const result = inventory({ libxml2: nvd, libxslt: nvd, xmlsec: nvd }, {
    xmlsec1: { 'CVE-2009-0217': { description: 'HMAC truncation' } },
  });
  assert.equal(result.length, 2);
  assert.deepEqual(result[1].products, ['libxml2', 'libxslt', 'xmlsec']);
  assert.equal(result[1].status, 'Rejected');
  assert.deepEqual(result[1].references, ['https://example.org/fix']);
  assert.deepEqual(result[0].sources, ['debian']);
});

test('corpus paths cannot escape their pinned root', () => {
  for (const path of ['../secret', '/etc/passwd', 'a/../../secret', 'a\\b', 'a//b']) {
    assert.throws(() => safePath(path));
  }
  assert.equal(safePath('test/errors/781205.xml'), 'test/errors/781205.xml');
});

test('partial advisory downloads and unclassified records fail closed', () => {
  // A successful HTTP response is not evidence that pagination is complete.
  assert.throws(() => inventory({ libxml2: { totalResults: 2, vulnerabilities: [] } }, {}),
    /all NVD pages/);
  assert.throws(() => audit({ records: [{ id: 'CVE-2099-9999' }] }),
    /every advisory/);
});

test('audit output binds the complete advisory snapshot', () => {
  // Changing evidence text without regenerating the report must be detectable.
  const data = { records: [{ id: 'CVE-2009-0217', description: 'original' }] };
  const before = JSON.parse(audit(data));
  data.records[0].description = 'changed';
  const after = JSON.parse(audit(data));
  assert.notEqual(before.advisorySha256, after.advisorySha256);
  assert.deepEqual(before.records, after.records);
});

test('CPE and alias searches retain evidence without duplicating an advisory', () => {
  // A CPE hit must merge into the real product while an alias remains visible.
  const data = { totalResults: 1, vulnerabilities: [{ cve: {
    id: 'CVE-2025-1', descriptions: [{ lang: 'en', value: 'source evidence' }], references: [],
  } }] };
  const rows = inventory({ 'cpe-libxml2': data, libxml2: data, libxml: data }, {});
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].products, ['libxml2', 'libxml']);
});
