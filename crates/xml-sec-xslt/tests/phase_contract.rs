#![cfg(feature = "benchmark-internals")]
#[path = "../../../benches/support/xslt.rs"]
mod support;

use std::sync::{Arc, Mutex};
use xml_sec_xslt::{
    AccessDenialReason, CompileBudget, Compiler, Document, ErrorKind, ExecutionEnvironment,
    NoResolver, Parameters, ResolveRequest, ResolvedResource, Resolver, ResourceAccess,
    ResourceIdentity,
};

#[test]
fn phase_split_preserves_output_and_does_not_reset_serialization_limits() {
    // Measurement hooks must use the same serializer and carried meter as execute.
    let _ = support::PHASES;
    for shape in ["items", "amplification"] {
        for size in [16, 256] {
            let fixture = support::Fixture::new(shape, size);
            let sheet = fixture.compile();
            let source = fixture.parse();
            assert_eq!(
                fixture.execute(&sheet, &source).serialized.bytes,
                fixture.expected
            );
            assert_eq!(
                fixture
                    .tree(&sheet, &source)
                    .serialize()
                    .expect("serialize")
                    .bytes,
                fixture.expected
            );
            let mut options = support::options();
            options.budget.serialized_bytes = 1;
            let tree = sheet
                .measure_tree(
                    &source,
                    &Parameters::new(),
                    ExecutionEnvironment::new(Arc::new(NoResolver)),
                    options.clone(),
                )
                .expect("tree fits");
            assert_eq!(
                tree.serialize().expect_err("serialized limit").kind(),
                ErrorKind::Budget
            );
            assert_eq!(
                sheet
                    .execute(&source, &Parameters::new(), Arc::new(NoResolver), options)
                    .expect_err("same limit")
                    .kind(),
                ErrorKind::Budget
            );
            let tree = fixture.tree(&sheet, &source);
            assert!(tree.result_tree_bytes() > 0);
            let usage = tree.usage();
            let work = usage.xpath_evaluations
                + usage.xpath_operations
                + usage.extension_operations
                + usage.pattern_evaluations
                + usage.template_applications
                + usage.sort_comparisons
                + usage.key_entries
                + usage.result_nodes
                + usage.serialized_bytes
                + usage.messages;
            drop(tree);
            // Admission may conservatively check an upcoming step before its
            // eventual charge. Leave bounded headroom for that check, but less
            // than the known output bytes that serialization must charge.
            assert!(work > fixture.expected.len());
            let ceiling = work + fixture.expected.len() / 2;
            let constrained = sheet
                .measure_tree(
                    &source,
                    &Parameters::new(),
                    ExecutionEnvironment::new(Arc::new(NoResolver)).with_work_ceiling(ceiling),
                    support::options(),
                )
                .expect("tree fits with admission headroom");
            assert_eq!(
                constrained
                    .serialize()
                    .expect_err("remaining work cannot serialize the output")
                    .kind(),
                ErrorKind::Budget
            );
        }
    }
}

#[test]
fn immutable_stylesheet_reuse_is_concurrent_and_execution_limits_are_isolated() {
    // One constrained execution must neither poison nor borrow a neighbor's allowance.
    let fixture = support::Fixture::new("items", 16);
    let sheet = Arc::new(fixture.compile());
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let sheet = Arc::clone(&sheet);
                let fixture = &fixture;
                scope.spawn(move || {
                    let source = fixture.parse();
                    let mut options = support::options();
                    if index % 2 == 0 {
                        options.budget.result_nodes = 1;
                    }
                    let result =
                        sheet.execute(&source, &Parameters::new(), Arc::new(NoResolver), options);
                    if index % 2 == 0 {
                        assert_eq!(result.expect_err("local limit").kind(), ErrorKind::Budget);
                    } else {
                        assert_eq!(
                            result.expect("independent operation").serialized.bytes,
                            fixture.expected
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("worker");
        }
    });
    assert_eq!(
        fixture.execute(&sheet, &fixture.parse()).serialized.bytes,
        fixture.expected
    );
}

struct VersionedModule(Mutex<u8>);
impl Resolver for VersionedModule {
    fn authorize(&self, access: ResourceAccess<'_>) -> xml_sec_xslt::Result<()> {
        let version = *self.0.lock().expect("version");
        let valid = match access {
            ResourceAccess::Request(request) => request.uri == "urn:module",
            ResourceAccess::Dependency(identity) | ResourceAccess::Retained { identity, .. } => {
                identity.0 == format!("module:{version}")
            }
        };
        if valid {
            Ok(())
        } else {
            Err(access.denied(AccessDenialReason::Revoked))
        }
    }
    fn resolve(&self, request: ResolveRequest<'_>) -> xml_sec_xslt::Result<ResolvedResource> {
        self.authorize(ResourceAccess::Request(request))?;
        let version = *self.0.lock().expect("version");
        Ok(ResolvedResource {
            canonical_uri: "urn:module".into(), identity: ResourceIdentity(format!("module:{version}")),
            bytes: format!("<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:template match='/'><out>{version}</out></xsl:template></xsl:stylesheet>").into_bytes(),
            media_type: None, encoding: None,
        })
    }
}

#[test]
fn retained_module_identity_is_not_a_grant_after_resource_replacement() {
    // Equal URIs cannot make an old dependency identity authoritative after replacement.
    let resolver = Arc::new(VersionedModule(Mutex::new(1)));
    let compiler = Compiler::new(
        Arc::clone(&resolver),
        CompileBudget::new(8192, 4, 64, 1 << 20),
    );
    let text = "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:include href='urn:module'/><xsl:output omit-xml-declaration='yes'/></xsl:stylesheet>";
    let first = compiler
        .compile(text, Some("urn:first"))
        .expect("first compile");
    let source = Document::parse("<root/>", None).expect("source");
    assert_eq!(
        first
            .execute(
                &source,
                &Parameters::new(),
                Arc::clone(&resolver),
                support::options()
            )
            .expect("first")
            .serialized
            .bytes,
        b"<out>1</out>\n"
    );
    *resolver.0.lock().expect("version") = 2;
    assert_eq!(
        first
            .execute(
                &source,
                &Parameters::new(),
                Arc::clone(&resolver),
                support::options()
            )
            .expect_err("old dependency revoked")
            .kind(),
        ErrorKind::Policy
    );
    let second = compiler
        .compile(text, Some("urn:second"))
        .expect("replacement compile");
    assert_ne!(first.resource_identities(), second.resource_identities());
    assert_eq!(
        second
            .execute(&source, &Parameters::new(), resolver, support::options())
            .expect("replacement")
            .serialized
            .bytes,
        b"<out>2</out>\n"
    );
}
