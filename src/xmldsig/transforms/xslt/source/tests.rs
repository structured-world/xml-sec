use super::super::super::{TransformError, TransformExecutionBudget, TransformScratch as _};
use crate::c14n::scratch::Native;
use crate::c14n::{C14nAlgorithm, C14nError, NodeVisibility};
use crate::document::DocumentParseSettings;
use crate::policy::{PolicyViolation, ResourcePolicy, resource_name};
use crate::xml::dom::{Document as Dom, Node};
use crate::xslt::Document;

/// A document exercising every construct the canonical form carries:
/// default, prefixed, redeclared and undeclared namespaces, attribute values
/// and text that canonical form escapes, `xml:` attributes, IDs, comments,
/// instructions inside and outside the document element, CDATA, non-ASCII
/// text and constructs on many lines.
const SOURCE: &str = concat!(
    "<?before data?>\n<!--c0-->\n",
    r#"<root xmlns="urn:d" xmlns:a="urn:a" a:x="1&amp;2&lt;3&quot;&#9;&#10;&#13;>" xml:lang="en">"#,
    "\n  text &amp; more &lt; &gt; &#13; end ]]&gt; \u{fc} \u{65e5}\n",
    r#"  <a:child xmlns:b="urn:b" b:y="v&#10;w" xml:space="preserve"> <b:leaf xmlns="">plain</b:leaf>"#,
    "\n    <!--inner&#13;--> <?inner x&#13;y?><?bare?>\n",
    "    <![CDATA[cdata <&> ]]>\n  </a:child>\n",
    r#"  <child2 xml:base="sub/" xml:id="i1" a:k="]]>"><deep xmlns:a="urn:other"><deeper a:z="q">t</deeper></deep></child2>"#,
    "\n  <empty/><a:empty xmlns:c=\"urn:c\"/>\n  tail\n</root>\n<!--after-->\n<?after?>"
);

/// Every node, attribute and namespace node.
struct Everything;

/// A deterministic sample of nodes, attributes and namespace nodes, so
/// owners are omitted while their axes, text or descendants are selected.
struct Sampled(u64);

impl Sampled {
    fn pick(&self, key: u64) -> bool {
        let mut mixed = self.0 ^ key.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        mixed ^= mixed >> 29;
        mixed = mixed.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed ^= mixed >> 32;
        !mixed.is_multiple_of(4)
    }

    fn key(owner: Node<'_, '_>, name: &str) -> u64 {
        name.bytes().fold(
            u64::from(owner.id().get()) ^ 0xCBF2_9CE4_8422_2325,
            |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01B3),
        )
    }
}

impl NodeVisibility for Everything {
    fn contains_node(&self, _node: Node<'_, '_>) -> Result<bool, C14nError> {
        Ok(true)
    }
    fn contains_attribute(
        &self,
        _owner: Node<'_, '_>,
        _namespace: Option<&str>,
        _local_name: &str,
    ) -> Result<bool, C14nError> {
        Ok(true)
    }
    fn contains_namespace(
        &self,
        _owner: Node<'_, '_>,
        _prefix: &str,
        _uri: &str,
    ) -> Result<bool, C14nError> {
        Ok(true)
    }
}

impl NodeVisibility for Sampled {
    fn contains_node(&self, node: Node<'_, '_>) -> Result<bool, C14nError> {
        Ok(self.pick(u64::from(node.id().get())))
    }
    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        _namespace: Option<&str>,
        local_name: &str,
    ) -> Result<bool, C14nError> {
        Ok(self.pick(Self::key(owner, local_name)))
    }
    fn contains_namespace(
        &self,
        owner: Node<'_, '_>,
        prefix: &str,
        _uri: &str,
    ) -> Result<bool, C14nError> {
        Ok(self.pick(Self::key(owner, prefix) ^ 1))
    }
}

/// The engine's document for `visibility`'s canonical octets, applying the
/// XML input policy and parse the transform used before it built the tree
/// directly; a refusal is rendered as text.
fn reparsed(
    document: &Dom<'_>,
    visibility: &dyn NodeVisibility,
    resources: &ResourcePolicy,
) -> Result<Document, String> {
    let budget = TransformExecutionBudget::from_resources(resources);
    let algorithm = C14nAlgorithm::from_uri(super::super::super::DEFAULT_IMPLICIT_C14N_URI)
        .expect("constant URI");
    let mut octets = Vec::new();
    crate::c14n::canonicalize_visible_to_writer_in(
        document,
        visibility,
        (&algorithm, None),
        usize::MAX,
        budget.xml_base_resolution(),
        &mut octets,
        &Native,
    )
    .map_err(|error| error.to_string())?;
    let settings = settings(&budget);
    super::super::super::check_xml_octets(&octets, settings).map_err(|error| error.to_string())?;
    let text = std::str::from_utf8(&octets).expect("canonical form is UTF-8");
    crate::document::preflight_xml_limits(
        text,
        settings,
        budget.xml_parse_work(),
        Native.dom_storage(),
    )
    .map_err(|error| {
        super::super::super::map_transform_xml_parse_error(error, settings).to_string()
    })?;
    super::super::parse_source(
        text,
        None,
        false,
        budget.xslt.max_workspace,
        &budget.xslt,
        budget.xml_parse_work(),
        &Native,
    )
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

/// The engine's document built from the tape of `visibility`'s canonical
/// constructs.
fn built(
    document: &Dom<'_>,
    visibility: &dyn NodeVisibility,
    resources: &ResourcePolicy,
) -> Result<Document, String> {
    let budget = TransformExecutionBudget::from_resources(resources);
    let tape = super::record(
        (document, visibility),
        settings(&budget),
        &budget,
        &Native,
        (budget.xslt.max_workspace, 0),
    )
    .map_err(|error| error.to_string())?;
    super::build(
        &tape,
        budget.xslt.max_workspace,
        &budget,
        budget.xml_parse_work(),
        &Native,
    )
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

fn settings(budget: &TransformExecutionBudget) -> DocumentParseSettings {
    DocumentParseSettings {
        allow_dtd: false,
        ..budget.xml_parse_settings
    }
}

/// Assert both paths give the same tree, with the same line numbers and
/// charges, or the same refusal; returns the tree.
fn same(
    document: &Dom<'_>,
    visibility: &dyn NodeVisibility,
    resources: &ResourcePolicy,
    case: &str,
) -> Result<Document, String> {
    let expected = reparsed(document, visibility, resources);
    let actual = built(document, visibility, resources);
    match (&expected, &actual) {
        (Ok(expected), Ok(actual)) => {
            assert_eq!(actual, expected, "{case}");
            assert_eq!(actual.source_bytes(), expected.source_bytes(), "{case}");
            // Retained bytes are allocation capacities: a value decoded from
            // references grows past its length, one copied from the node-set
            // does not, so the built tree never holds more.
            assert!(
                actual.retained_bytes() <= expected.retained_bytes(),
                "{case}: built {} parsed {}",
                actual.retained_bytes(),
                expected.retained_bytes()
            );
        }
        // The tokenizer reports markup a parse cannot read, such as text
        // outside the document element, by its position; the builder, which
        // reads no text, refuses the same construct as malformed XML.
        (Err(expected), Err(actual)) if expected.contains("XML lexical error") => assert!(
            actual.starts_with(MALFORMED),
            "{case}: {actual} for {expected}"
        ),
        _ => assert_eq!(
            actual.as_ref().err(),
            expected.as_ref().err(),
            "{case}: {}",
            if expected.is_ok() {
                "built refused"
            } else {
                "reparse refused"
            }
        ),
    }
    actual
}

const MALFORMED: &str = "XML input is not well formed: ";

#[test]
fn the_built_source_is_the_parsed_canonical_form() {
    // The node-set input skips serializing its canonical form and parsing it
    // back; whatever the selection, the engine must still see the tree, line
    // numbers and refusals that parse gives, including selections whose
    // canonical form is not a well-formed document.
    let document = Dom::parse(SOURCE).expect("source parses");
    let resources = ResourcePolicy::default();
    let whole = same(&document, &Everything, &resources, "everything")
        .expect("the whole document is well-formed");
    assert!(whole.source_bytes() > SOURCE.len() / 2);
    let (mut trees, mut refusals) = (0, 0);
    for seed in 0..1024 {
        match same(
            &document,
            &Sampled(seed),
            &resources,
            &format!("seed {seed}"),
        ) {
            Ok(_) => trees += 1,
            Err(_) => refusals += 1,
        }
    }
    // Both outcomes must be exercised for the comparison to mean anything.
    assert!(
        trees > 32 && refusals > 32,
        "{trees} trees, {refusals} refusals"
    );
}

#[test]
fn the_built_source_obeys_each_xml_input_limit_as_its_parse_does() {
    // Every structural limit of the XML input policy refuses the built tree at
    // the value that refuses the parse of its canonical octets, and admits it
    // at the next.
    let document = Dom::parse(SOURCE).expect("source parses");
    let sampled: Vec<Sampled> = (0..256)
        .map(Sampled)
        .filter(|visibility| reparsed(&document, visibility, &ResourcePolicy::default()).is_ok())
        .take(24)
        .collect();
    assert!(sampled.len() > 8);
    let selections = core::iter::once(&Everything as &dyn NodeVisibility).chain(
        sampled
            .iter()
            .map(|visibility| visibility as &dyn NodeVisibility),
    );
    let limits: [fn(&mut ResourcePolicy) -> &mut usize; 4] = [
        |resources| &mut resources.max_xml_nodes,
        |resources| &mut resources.max_xml_depth,
        |resources| &mut resources.max_xml_namespace_bindings,
        |resources| &mut resources.max_xml_document_bytes,
    ];
    for (index, visibility) in selections.enumerate() {
        for (kind, limit) in limits.iter().enumerate() {
            let admitted = (0..4096).find(|&value| {
                let mut resources = ResourcePolicy::default();
                *limit(&mut resources) = value;
                let case = format!("selection {index}, limit {kind} = {value}");
                same(&document, visibility, &resources, &case).is_ok()
            });
            assert!(
                admitted.is_some_and(|value| value > 0),
                "selection {index}, limit {kind}: first admitted at {admitted:?}"
            );
        }
    }
}

#[test]
fn tape_growth_admits_the_old_and_the_new_allocation_together() {
    // Growing a full list moves it: the old allocation is live until the
    // replacement holds its copy, so the peak is both. Four events fit a
    // limit of ten; growing to eight needs twelve at the peak and is refused.
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy::default());
    let counters = (std::cell::Cell::new(0), std::cell::Cell::new(0));
    let event = core::mem::size_of::<super::Event<'_>>();
    let mut recorder = super::Recorder::new(&Native, &counters, settings(&budget), 10 * event);
    for _ in 0..4 {
        recorder
            .push(|tape| &mut tape.events, super::Event::End)
            .expect("four events fit");
    }
    assert!(
        recorder
            .push(|tape| &mut tape.events, super::Event::End)
            .is_err()
    );
    assert_eq!(recorder.exceeded, Some(12 * event));
}

#[test]
fn the_tape_is_refused_before_it_grows_past_its_limit() {
    // One text node of escaped characters records one event each. Its tape
    // must be refused before it grows past the workspace, not after the
    // whole node is recorded, so the allocation never outruns the limit by
    // more than one growth.
    let xml = format!("<r>{}</r>", "&amp;".repeat(100_000));
    let document = Dom::parse(&xml).expect("source parses");
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy::default());
    let (limit, held) = (64 * 1024, 100);
    let refused = super::record(
        (&document, &Everything),
        settings(&budget),
        &budget,
        &Native,
        (limit, held),
    );
    match refused {
        Err(TransformError::Policy(PolicyViolation::ResourceLimit {
            resource: resource_name::XSLT_WORKSPACE_BYTES,
            actual,
            ..
        })) => assert!(
            actual > held + limit && actual <= held + 2 * limit,
            "refused at {actual}"
        ),
        other => panic!("expected a workspace refusal: {:?}", other.err()),
    }
}
