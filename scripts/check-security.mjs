import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, physical } from './check-xml-kernels.mjs';

const directories = ['src/policy/', 'src/provider/', 'src/key_manager/',
  'src/operation/', 'src/key_establishment/', 'src/xmldsig/', 'src/xmlenc/',
  'src/rustcrypto_ml_dsa/', 'src/rustcrypto_sha3/', 'crates/xml-sec-xades/src/',
  'crates/xml-sec-xades/tests/'];
const files = new Set(['src/api.rs', 'src/policy.rs', 'src/provider.rs',
  'src/key_manager.rs', 'src/operation.rs', 'src/key_establishment.rs',
  'src/rsa_encoding.rs', 'src/hard_limits.rs', 'docs/rust-api.md',
  'docs/xmldsig.md', 'docs/xmlenc.md',
  'tests/authenticated_reference_replay.rs', 'tests/aws_lc_provider.rs',
  'tests/base64_transform_integration.rs', 'tests/behavioral_compatibility.rs',
  'tests/cipher_reference.rs', 'tests/cve_security.rs', 'tests/dh_agreement.rs',
  'tests/donor_full_verification_suite.rs', 'tests/donor_interop_suite.rs',
  'tests/donor_negative_vectors.rs', 'tests/ecdsa_signature_integration.rs',
  'tests/historical_security.rs', 'tests/hmac_pipeline.rs',
  'tests/key_establishment.rs', 'tests/merlin_interop.rs',
  'tests/modern_algorithms.rs', 'tests/opc_relationship_transform.rs',
  'tests/phaos_interop.rs', 'tests/pkcs11.rs', 'tests/policy_profiles.rs',
  'tests/reference_integration.rs', 'tests/rsa_encoding.rs',
  'tests/rsa_pss.rs', 'tests/rsa_signature_integration.rs', 'tests/rust_api.rs',
  'tests/saml_idp_integration.rs', 'tests/saml_signing_integration.rs',
  'tests/secret_ownership.rs', 'tests/selected_key_receipts.rs',
  'tests/session_lookups.rs', 'tests/signature_builder.rs',
  'tests/signature_hash_uses.rs', 'tests/signature_pipeline_integration.rs',
  'tests/signing_digest.rs', 'tests/spki_key_structure.rs',
  'tests/transforms_integration.rs', 'tests/uri_integration.rs',
  'tests/verification_evidence.rs', 'tests/x509_chain_integration.rs',
  'tests/xml_integer_inspection.rs', 'tests/xml_qname_inspection.rs',
  'tests/xml_scalar_inspection.rs', 'tests/xml_tree_navigation.rs',
  'tests/xmlenc11_corpus.rs', 'tests/xmlenc_agreement.rs',
  'tests/xmlenc_donor_integration.rs', 'tests/xmlenc_encrypt_integration.rs',
  'tests/xmlenc_nested.rs', 'tests/xmlsec1_interop.rs',
  'tests/xpath_donor_vectors.rs', 'tests/xpath_transform_integration.rs',
  'tests/xslt_transform_integration.rs']);

export function ownsSource(root, filename) {
  const path = relative(physical(root), physical(resolve(root, filename))).split(sep).join('/');
  return !isAbsolute(path) && !path.startsWith('../')
    && (files.has(path) || directories.some(prefix => path.startsWith(prefix)));
}

export const graphs = [
  ['security-workspace-all', ['--workspace', '--all-targets', '--all-features']],
  ['security-workspace-default', ['--workspace', '--all-targets']],
  ['security-dsig-minimal', ['-p', 'xml-sec', '--lib', '--no-default-features',
    '--features', 'xmldsig,xml-backend-differential']],
  ['security-xmlenc-minimal', ['-p', 'xml-sec', '--lib', '--no-default-features',
    '--features', 'xmlenc,xml-backend-differential']],
  ['security-xades', ['-p', 'xml-sec-xades', '--all-targets']],
];

async function main() {
  if (process.argv.length !== 2) throw new Error('Usage: node scripts/check-security.mjs');
  const root = physical(resolve(import.meta.dirname, '..'));
  for (const [name, args] of graphs) await check(root, name, args, ownsSource);
  console.log('Security orchestration pedantic: all entry graphs passed');
}

if (process.argv[1] && physical(process.argv[1]) === physical(fileURLToPath(import.meta.url))) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
