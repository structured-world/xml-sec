//! Public-path fuzz oracles. The same functions run in deterministic tests and libFuzzer.
//!
//! Input bounds below constrain the test campaign, not the product contract.
//! No oracle treats a processing failure as cryptographic success.

use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml_with_backend};
use xml_sec::{XmlBackend, XmlDocument};

mod oracle;
pub use oracle::xmlsec_oracle;

pub const BACKENDS: [XmlBackend; 2] = [XmlBackend::Xmloxide, XmlBackend::Roxmltree];
const MAX_INPUT: usize = 8192;

fn bounded(data: &[u8]) -> &[u8] {
    &data[..data.len().min(MAX_INPUT)]
}

fn payload(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(data.len() * 2);
    for byte in data {
        write!(&mut text, "{byte:02x}").expect("writing to String");
    }
    text
}

struct InlineXsltModule(Vec<u8>);

const MODULE_URI: &str = "urn:fuzz:module";

impl xml_sec_xslt::Resolver for InlineXsltModule {
    fn authorize(&self, access: xml_sec_xslt::ResourceAccess<'_>) -> xml_sec_xslt::Result<()> {
        use xml_sec_xslt::ResourceAccess;
        let granted = match access {
            ResourceAccess::Request(request) => request.uri == MODULE_URI,
            ResourceAccess::Retained { request, identity } => {
                request.uri == MODULE_URI && identity.0 == MODULE_URI
            }
            ResourceAccess::Dependency(identity) => identity.0 == MODULE_URI,
        };
        if granted {
            Ok(())
        } else {
            Err(access.denied(xml_sec_xslt::AccessDenialReason::NotGranted))
        }
    }

    fn resolve(
        &self,
        request: xml_sec_xslt::ResolveRequest<'_>,
    ) -> xml_sec_xslt::Result<xml_sec_xslt::ResolvedResource> {
        self.authorize(xml_sec_xslt::ResourceAccess::Request(request))?;
        // A fresh resolver owns immutable bounded bytes for one campaign input.
        // Its identity is stable within the compilation and execution, never I/O.
        Ok(xml_sec_xslt::ResolvedResource {
            canonical_uri: MODULE_URI.into(),
            identity: xml_sec_xslt::ResourceIdentity(MODULE_URI.into()),
            bytes: self.0.clone(),
            media_type: None,
            encoding: None,
        })
    }
}

pub fn xml_semantics(data: &[u8]) {
    let data = bounded(data);
    for mode in [
        C14nMode::Inclusive1_0,
        C14nMode::Inclusive1_1,
        C14nMode::Exclusive1_0,
    ] {
        for comments in [false, true] {
            let algorithm = C14nAlgorithm::new(mode, comments);
            let left = canonicalize_xml_with_backend(data, &algorithm, BACKENDS[0]);
            let right = canonicalize_xml_with_backend(data, &algorithm, BACKENDS[1]);
            // Only common accepted inputs have a portable byte-equivalence oracle;
            // parser-specific refusals are exercised but are not silently called equal.
            if let (Ok(left), Ok(right)) = (left, right) {
                assert_eq!(left, right, "C14N backend disagreement: {mode:?}");
                let repeated = canonicalize_xml_with_backend(&left, &algorithm, BACKENDS[0])
                    .expect("canonical output is XML");
                assert_eq!(left, repeated, "C14N idempotence");
            }
        }
    }
    let xml = format!("<root><item ID=\"target\">{}</item></root>", payload(data));
    for backend in BACKENDS {
        let mut document =
            XmlDocument::parse_with_backend(xml.clone(), backend).expect("generated XML");
        let original = document.with_view(|view| view.node_for_id("target", &[]).expect("target"));
        document
            .replace_element(original, "<item ID=\"target\">replacement</item>")
            .expect("mutation");
        document.with_view(|view| {
            let replacement = view.node_for_id("target", &[]).expect("new target");
            assert_ne!(
                original, replacement,
                "mutation must change generation identity"
            );
            assert!(
                view.node_order(original).is_err(),
                "stale identity must be rejected"
            );
            assert!(view.node_order(replacement).is_ok());
        });
    }
}

pub fn security_roundtrip(data: &[u8]) {
    use xml_sec::xmldsig::{
        DigestAlgorithm, DsigStatus, HmacSigningKey, HmacVerificationKey, ReferenceBuilder,
        SignContext, SignatureAlgorithm, SignatureBuilder, Transform, VerificationRequest,
        VerifyContext,
    };
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DocumentEncryptionOptions, EncryptedDataBuilder,
        SymmetricKeyDecryptor,
    };
    let data = bounded(data);
    let xml = format!(
        "<root><payload ID=\"target\">{}</payload></root>",
        payload(data)
    );
    let signer = HmacSigningKey::new(vec![0x42; 32]).expect("fixed test key");
    let verifier = HmacVerificationKey::new(vec![0x42; 32]).expect("fixed test key");
    let wrong = HmacVerificationKey::new(vec![0x43; 32]).expect("fixed different key");
    let algorithm = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let builder = SignatureBuilder::new(algorithm.clone(), SignatureAlgorithm::HmacSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#target")
                .transform(Transform::C14n(algorithm)),
        );
    for backend in BACKENDS {
        let signed = SignContext::new(&signer)
            .xml_backend(backend)
            .sign_with_builder(&xml, &builder)
            .expect("generated signature");
        let mut exhausted = xml_sec::policy::SigningPolicy::default();
        exhausted.resources.max_xml_parse_work_bytes = 1;
        assert!(
            SignContext::new(&signer)
                .policy(exhausted)
                .xml_backend(backend)
                .sign_with_builder(&xml, &builder)
                .is_err(),
            "a nested stage cannot reset parse work"
        );
        // Cross-backend verification covers the compiled reference plan and its
        // transform conversions, not just parsing the same document twice.
        for verifier_backend in BACKENDS {
            let context = VerifyContext::new()
                .key(&verifier)
                .xml_backend(verifier_backend);
            assert!(
                !VerifyContext::new()
                    .key(&wrong)
                    .xml_backend(verifier_backend)
                    .verify(&signed)
                    .is_ok_and(|result| result.status == DsigStatus::Valid)
            );
            let mut tampered = XmlDocument::parse_with_backend(signed.clone(), verifier_backend)
                .expect("signed XML");
            let target =
                tampered.with_view(|view| view.node_for_id("target", &[]).expect("target"));
            let targets = [target];
            let evidence = context
                .verify_request(
                    &tampered,
                    &VerificationRequest {
                        expected_targets: &targets,
                        ..VerificationRequest::default()
                    },
                )
                .expect("valid signature and exact requested target");
            assert!(evidence.all_valid());
            assert!(evidence.accepted(&tampered).expect("current proof"));
            let root = tampered.with_view(|view| view.root_element());
            assert!(
                !evidence
                    .covers_element(&tampered, root)
                    .expect("root coverage"),
                "a signed child does not authenticate its unsigned parent"
            );
            tampered
                .replace_element(target, "<payload ID=\"target\">tampered!</payload>")
                .expect("tamper target");
            assert!(
                evidence.accepted(&tampered).is_err(),
                "proof cannot survive a document mutation"
            );
            assert!(
                !context
                    .verify(tampered.as_xml())
                    .is_ok_and(|result| result.status == DsigStatus::Valid),
                "modified authenticated target must not verify"
            );
        }
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .xml_backend(backend)
            .direct_key([0x51; 16])
            .encrypt_document(&xml, DocumentEncryptionOptions::default())
            .expect("encrypt generated XML");
        let key = SymmetricKeyDecryptor::new([0x51; 16]);
        let wrong_key = SymmetricKeyDecryptor::new([0x52; 16]);
        for decrypt_backend in BACKENDS {
            let decrypted = DecryptContext::new(&key)
                .xml_backend(decrypt_backend)
                .decrypt_document(&encrypted, None)
                .expect("decrypt generated ciphertext");
            assert_eq!(decrypted, xml, "cross-backend encryption round trip");
            assert!(
                DecryptContext::new(&wrong_key)
                    .xml_backend(decrypt_backend)
                    .decrypt_document(&encrypted, None)
                    .is_err(),
                "GCM wrong key must fail"
            );
        }
    }
    // Mutated XMLenc inputs reach the public parser and recovery pipeline too.
    if let Ok(input) = std::str::from_utf8(data) {
        let resolver = SymmetricKeyDecryptor::new([0x51; 16]);
        for backend in BACKENDS {
            let _ = DecryptContext::new(&resolver)
                .xml_backend(backend)
                .decrypt(input);
        }
    }
}

pub fn transform_parameters(data: &[u8]) {
    use xml_sec::Document;
    use xml_sec::policy::VerificationPolicy;
    use xml_sec::xmldsig::{
        NodeSet, RelationshipSelector, Transform, TransformData, XPathExpression, XPathFilter,
        XPathFilterOperation, execute_transforms_with_policy,
    };
    let data = bounded(data);
    let Ok(expression) = std::str::from_utf8(data) else {
        return;
    };
    let document = Document::parse("<root><item ID=\"target\">text</item><Signature/></root>")
        .expect("fixed transform document");
    let policy = VerificationPolicy::default();
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let chains = [
        vec![Transform::XPath(XPathExpression::new(expression))],
        vec![Transform::XPathFilter2(vec![XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new(expression),
        )])],
        vec![
            Transform::Relationship(vec![
                RelationshipSelector::SourceId("r1".into()),
                RelationshipSelector::SourceType(expression.into()),
            ]),
            Transform::C14n(algorithm.clone()),
        ],
        vec![Transform::Base64Decode],
        vec![Transform::Base64Decode, Transform::C14n(algorithm)],
    ];
    for (index, chain) in chains.into_iter().enumerate() {
        let input = || {
            if index < 2 {
                TransformData::NodeSet(
                    NodeSet::entire_document_with_comments(&document).expect("fixed node set"),
                )
            } else {
                TransformData::BorrowedBinary(data)
            }
        };
        let first =
            execute_transforms_with_policy(document.root_element(), input(), &chain, &policy);
        let second =
            execute_transforms_with_policy(document.root_element(), input(), &chain, &policy);
        match (first, second) {
            (Ok(first), Ok(second)) => assert_eq!(first, second, "deterministic transform output"),
            (Err(first), Err(second)) => {
                assert_eq!(
                    std::mem::discriminant(&first),
                    std::mem::discriminant(&second),
                    "typed failure class"
                )
            }
            _ => panic!("transform success changed without changing inputs"),
        }
    }
    if let Ok(stylesheet) = xml_sec::xmldsig::XsltStylesheet::new(expression) {
        let mut policy = policy;
        policy.resources.max_xslt_work = 100_000;
        policy.resources.max_xslt_workspace_bytes = 1024 * 1024;
        policy.resources.max_xslt_output_bytes = 64 * 1024;
        let output = execute_transforms_with_policy(
            document.root_element(),
            TransformData::BorrowedBinary(b"<root><item>payload</item></root>"),
            &[Transform::Xslt(stylesheet)],
            &policy,
        );
        if let Ok(output) = output {
            assert!(output.len() <= policy.resources.max_xslt_output_bytes);
        }
    }
}

pub fn xslt_execution(data: &[u8]) {
    use std::sync::Arc;
    use xml_sec_xslt::{
        CompileBudget, Compiler, Document, ExecutionBudget, ExecutionEnvironment, ExecutionOptions,
        NoResolver, Parameters, ParseBudget,
    };
    let data = bounded(data);
    let compiler = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(MAX_INPUT, 0, 32, 1024 * 1024),
    );
    let parse = ParseBudget::new(MAX_INPUT, 1024, 32, 1024, MAX_INPUT, MAX_INPUT)
        .with_owned_bytes(1024 * 1024)
        .with_parse_work_bytes(4 * MAX_INPUT);
    let generated = format!(
        "<root><item>{}</item></root>",
        payload(&data[..data.len().min(1024)])
    );
    let source = Document::parse_with_budget(&generated, None, parse).expect("generated source");
    let budget = ExecutionBudget {
        source_bytes: MAX_INPUT,
        external_documents: 0,
        recursion_depth: 32,
        xpath_evaluations: 1024,
        xpath_operations: 100_000,
        extension_operations: 1024,
        pattern_evaluations: 10_000,
        template_applications: 1024,
        sort_comparisons: 1024,
        key_entries: 1024,
        result_nodes: 1024,
        serialized_bytes: 64 * 1024,
        messages: 16,
        owned_bytes: 1024 * 1024,
    };
    let identity = "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:template match='@*|node()'><xsl:copy><xsl:apply-templates select='@*|node()'/></xsl:copy></xsl:template></xsl:stylesheet>";
    let candidate = std::str::from_utf8(data).ok();
    // The fixed valid stylesheet ensures mutations reach runtime/serialization;
    // the independent arbitrary stylesheet exercises static errors and graphs.
    for text in std::iter::once(identity).chain(candidate) {
        if let Ok(sheet) = compiler.compile(text, Some("urn:fuzz:stylesheet")) {
            let execute = || {
                sheet.execute_reported(
                    &source,
                    &Parameters::default(),
                    ExecutionEnvironment::new(Arc::new(NoResolver)),
                    ExecutionOptions {
                        budget,
                        initial_mode: None,
                        initial_template: None,
                    },
                )
            };
            let first = execute();
            for (used, limit) in [
                (first.usage.external_documents, budget.external_documents),
                (first.usage.xpath_evaluations, budget.xpath_evaluations),
                (first.usage.xpath_operations, budget.xpath_operations),
                (
                    first.usage.extension_operations,
                    budget.extension_operations,
                ),
                (first.usage.pattern_evaluations, budget.pattern_evaluations),
                (
                    first.usage.template_applications,
                    budget.template_applications,
                ),
                (first.usage.sort_comparisons, budget.sort_comparisons),
                (first.usage.key_entries, budget.key_entries),
                (first.usage.serialized_bytes, budget.serialized_bytes),
                (first.usage.result_nodes, budget.result_nodes),
                (first.usage.messages, budget.messages),
            ] {
                assert!(used <= limit, "reported work exceeds admission");
            }
            let second = execute();
            match (first.outcome, second.outcome) {
                (Ok(first), Ok(second)) => {
                    assert_eq!(first.serialized.bytes, second.serialized.bytes)
                }
                (Err(first), Err(second)) => assert_eq!(first.kind(), second.kind()),
                _ => panic!("deterministic XSLT execution changed outcome"),
            }
        }
    }
    // Permission refusals alone do not exercise module graphs. The only granted
    // URI returns this input, so mutations can reach cycles, module parsing and
    // runtime document caching without giving the target ambient I/O authority.
    let resolver = Arc::new(InlineXsltModule(data.to_vec()));
    let graph_compiler = Compiler::new(
        resolver.clone(),
        CompileBudget::new(2 * MAX_INPUT, 4, 32, 1024 * 1024),
    );
    for body in [
        "<xsl:include href='urn:fuzz:module'/>",
        "<xsl:import href='urn:fuzz:module'/>",
        "<xsl:template match='/'><xsl:copy-of select=\"document('urn:fuzz:module')\"/></xsl:template>",
    ] {
        let text = format!(
            "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'>{body}</xsl:stylesheet>"
        );
        if let Ok(sheet) = graph_compiler.compile(&text, Some("urn:fuzz:graph")) {
            let execute = || {
                sheet
                    .execute_with_environment(
                        &source,
                        &Parameters::default(),
                        ExecutionEnvironment::new(resolver.clone()),
                        ExecutionOptions {
                            budget: ExecutionBudget {
                                external_documents: 1,
                                ..budget
                            },
                            initial_mode: None,
                            initial_template: None,
                        },
                    )
                    .map(|result| result.serialized.bytes)
                    .map_err(|error| error.kind())
            };
            assert_eq!(execute(), execute(), "module/document graph replay");
        }
    }
}

pub fn provider_operations(data: &[u8]) {
    use xml_sec::provider::{CryptoProvider, ProviderCapability, RustCryptoProvider};
    use xml_sec::xmldsig::DigestAlgorithm;
    use xml_sec::xmlenc::{DataEncryptionAlgorithm, KeyWrapAlgorithm};
    let data = bounded(data);
    #[cfg(not(feature = "aws-lc-fips"))]
    let providers: &[&dyn CryptoProvider] = &[&RustCryptoProvider];
    #[cfg(feature = "aws-lc-fips")]
    let providers: &[&dyn CryptoProvider] =
        &[&RustCryptoProvider, &xml_sec::provider::AwsLcFipsProvider];
    for algorithm in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ] {
        let mut expected = None;
        for provider in providers.iter() {
            if !provider.supports(ProviderCapability::Digest(algorithm)) {
                continue;
            }
            let mut one = provider.begin_digest(algorithm).expect("advertised digest");
            one.update(data).expect("digest input");
            let one = one.finalize().expect("finalize");
            let mut chunks = provider.begin_digest(algorithm).expect("advertised digest");
            let split = data.len() / 2;
            chunks.update(&data[..split]).expect("first chunk");
            chunks.update(&[]).expect("empty chunk");
            chunks.update(&data[split..]).expect("last chunk");
            assert_eq!(one, chunks.finalize().expect("finalize"), "digest chunking");
            if let Some(expected) = &expected {
                assert_eq!(&one, expected, "provider digest disagreement");
            }
            expected = Some(one);
        }
    }
    for provider in providers.iter() {
        let algorithm = DataEncryptionAlgorithm::Aes128Gcm;
        let key = [0x61; 16];
        let ciphertext = provider
            .encrypt_data(algorithm, &key, data)
            .expect("AES-GCM");
        assert_eq!(
            provider
                .decrypt_data(algorithm, &key, &ciphertext)
                .expect("decrypt"),
            data
        );
        let mut corrupt = ciphertext;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(
            provider.decrypt_data(algorithm, &key, &corrupt).is_err(),
            "GCM authentication"
        );
        let wrapped = provider
            .wrap_key(KeyWrapAlgorithm::AesKw128, &key, &[0x71; 16])
            .expect("wrap");
        assert_eq!(
            provider
                .unwrap_key(KeyWrapAlgorithm::AesKw128, &key, &wrapped)
                .expect("unwrap"),
            [0x71; 16]
        );
        let mut corrupt = wrapped;
        corrupt[0] ^= 1;
        assert!(
            provider
                .unwrap_key(KeyWrapAlgorithm::AesKw128, &key, &corrupt)
                .is_err(),
            "KW integrity"
        );
    }
}

pub fn key_formats(data: &[u8]) {
    use xml_sec::key_manager::{KeyInventory, KeyUsages};
    use xml_sec::policy::{ResourcePolicy, VerificationPolicy};
    let data = bounded(data);
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 1024,
        max_key_import_kdf_memory_bytes: 1024 * 1024,
        ..ResourcePolicy::default()
    };
    let mut inventory = KeyInventory::default();
    let _ = inventory.add_public_der("public".into(), data.to_vec(), &resources);
    let _ = inventory.add_private_der(
        "private".into(),
        data,
        Some(b"fuzz-password"),
        KeyUsages::SIGN,
        &resources,
    );
    let policy = VerificationPolicy {
        resources,
        ..VerificationPolicy::default()
    };
    for backend in BACKENDS {
        let _ = KeyInventory::from_xml_bytes(data, &policy, backend);
    }
}

pub fn policy_compilation(data: &[u8]) {
    use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile};
    use xml_sec::provider::RustCryptoProvider;
    use xml_sec_config::{Configuration, LoadLimits};
    let data = bounded(data);
    let limits = LoadLimits {
        max_bytes: MAX_INPUT,
        max_profiles: 16,
    };
    let context = PolicyCompileContext {
        external_resources: true,
        target_evidence: true,
    };
    if let Ok(input) = std::str::from_utf8(data)
        && let Ok(config) = Configuration::from_str(input, limits)
    {
        for name in config.profile_names() {
            if let Ok(effective) = config.compile(name, &RustCryptoProvider, &context, None) {
                let serialized = effective.to_toml().expect("serialize effective policy");
                let replay = Configuration::from_str(&serialized, LoadLimits::default())
                    .expect("effective policy is a configuration");
                let replay = replay
                    .compile("effective", &RustCryptoProvider, &context, None)
                    .expect("compile effective policy");
                assert!(
                    effective.diff(&replay).is_empty(),
                    "effective-policy round trip"
                );
            }
        }
    }
    let compiler = PolicyCompiler::new(PolicyProfile::Modern, &RustCryptoProvider, None)
        .expect("modern profile");
    let mut layer = compiler.policies().clone();
    let permissive = layer.clone();
    let minimum = layer
        .verification
        .as_ref()
        .expect("verification")
        .key_trust
        .rsa_keys
        .minimum_modulus_bits;
    let limit = usize::from(data.first().copied().unwrap_or(0)) + 1;
    layer
        .verification
        .as_mut()
        .expect("verification")
        .key_trust
        .rsa_keys
        .minimum_modulus_bits = 1024 + usize::from(data.get(1).copied().unwrap_or(0)) * 8;
    layer.signing = None;
    layer
        .verification
        .as_mut()
        .expect("verification")
        .resources
        .max_references = limit;
    let compiled = compiler
        .restrict(&layer)
        .expect("restrict profile")
        .restrict(&permissive)
        .expect("a later layer cannot restore disabled operations")
        .compile(&context)
        .expect("compile restrictive policy");
    assert!(
        compiled
            .verification()
            .expect("verification")
            .resources
            .max_references
            <= limit
    );
    assert!(
        compiled.signing().is_none(),
        "disabled operation cannot be re-enabled"
    );
    assert!(
        compiled
            .verification()
            .expect("verification")
            .key_trust
            .rsa_keys
            .minimum_modulus_bits
            >= minimum,
        "ordinary layers cannot lower key strength"
    );
    let compiler = PolicyCompiler::new(PolicyProfile::Modern, &RustCryptoProvider, None)
        .expect("modern profile");
    let mut impossible = compiler.policies().clone();
    let verification = impossible.verification.as_mut().expect("verification");
    verification.signature_algorithms = Some(std::collections::BTreeSet::from([
        xml_sec::xmldsig::SignatureAlgorithm::HmacSha256,
    ]));
    verification.hmac.minimum_output_bits = 257 + usize::from(data.first().copied().unwrap_or(0));
    assert!(
        compiler
            .restrict(&impossible)
            .expect("contradictory layer admission")
            .compile(&context)
            .is_err(),
        "impossible HMAC width cannot compile"
    );
    // A misspelled security field must never become a permissive default.
    assert!(
        Configuration::from_str(
            "schema_version=1\n[profiles.fuzz]\nbase='Modern'\nunknown_security_field=true",
            limits
        )
        .is_err()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_graph_seed_reaches_cycle_detection_without_io() {
        // The granted in-memory module includes itself. A blanket deny would
        // return Policy instead of proving the graph's static cycle boundary.
        let data = include_bytes!("../seeds/xslt-module-cycle.xsl");
        let resolver = std::sync::Arc::new(InlineXsltModule(data.to_vec()));
        let error = xml_sec_xslt::Compiler::new(
            resolver,
            xml_sec_xslt::CompileBudget::new(16 * 1024, 4, 32, 1024 * 1024),
        )
        .compile(std::str::from_utf8(data).unwrap(), Some("urn:fuzz:graph"))
        .expect_err("self-include is cyclic");
        assert_eq!(error.kind(), xml_sec_xslt::ErrorKind::Static);
        xslt_execution(data);
    }

    #[test]
    fn deterministic_oracles_reach_success_and_refusal_paths() {
        // Keep the harness executable outside libFuzzer and prove structured
        // mutation does not turn every input into an early parser refusal.
        for data in [
            &b""[..],
            b"<root a='1'>text</root>",
            b"\xff\x00",
            b"count(//item)",
            include_bytes!("../seeds/policy.toml"),
            include_bytes!("../seeds/identity.xsl"),
        ] {
            xml_semantics(data);
            security_roundtrip(data);
            transform_parameters(data);
            key_formats(data);
            policy_compilation(data);
            xslt_execution(data);
            provider_operations(data);
        }
    }
}
