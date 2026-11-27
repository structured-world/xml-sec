use super::{Draft, DraftError};
use alloc::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_xades::produce::{Datatype, Event, Value, Writer};
use structured_xades::xml::Name;

const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XMLNS: &str = "http://www.w3.org/2000/xmlns/";

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)))
}

const fn name(namespace: &'static str, local: &'static str) -> Name<'static> {
    Name { namespace, local }
}

fn value(lexical: &str, datatype: Datatype) -> Value<'_> {
    Value { lexical, datatype }
}

fn write(draft: &mut Draft, events: &[Event<'_>]) -> Result<(), DraftError> {
    let work = account();
    for event in events {
        draft.write(*event, &work)?;
    }
    Ok(())
}

fn finished(events: &[Event<'_>]) -> String {
    let mut draft = Draft::new();
    write(&mut draft, events).expect("events are accepted");
    draft.finish().expect("one complete element").0
}

#[test]
fn names_get_one_declaration_per_namespace_scope() {
    // Each namespace is declared once, on the first element that needs it,
    // and children reuse the binding; known namespaces keep familiar prefixes.
    let markup = finished(&[
        Event::Begin(name(XADES, "QualifyingProperties")),
        Event::Begin(name(XADES, "SignedProperties")),
        Event::Begin(name(DS, "DigestMethod")),
        Event::End,
        Event::Begin(name(DS, "DigestValue")),
        Event::End,
        Event::End,
        Event::End,
    ]);
    assert_eq!(
        markup,
        format!(
            "<xades:QualifyingProperties xmlns:xades=\"{XADES}\"><xades:SignedProperties><ds:DigestMethod xmlns:ds=\"{DS}\"/><ds:DigestValue xmlns:ds=\"{DS}\"/></xades:SignedProperties></xades:QualifyingProperties>"
        )
    );
}

#[test]
fn reserved_prefixes_are_refused_for_a_foreign_namespace() {
    // Namespaces in XML 1.0 §3: `xmlns` is never declared, and `xml` binds
    // only the XML namespace; either chosen for another namespace would
    // write namespace-invalid markup.
    const XML: &str = "http://www.w3.org/XML/1998/namespace";
    // The XML namespace is never bound to another prefix or as the default.
    for chosen in [
        ("urn:outer", "xml"),
        ("urn:outer", "xmlns"),
        (XML, "xmlns"),
        (XML, "p"),
        (XML, ""),
        // The xmlns namespace is bound to no prefix, not even as the default.
        (XMLNS, "p"),
        (XMLNS, ""),
    ] {
        assert!(
            matches!(Draft::with_prefixes(&[chosen]), Err(DraftError::Name(_))),
            "{chosen:?}"
        );
    }
    assert!(Draft::with_prefixes(&[(XML, "xml")]).is_ok());
    // Nor is an element in it written under a generated prefix.
    let mut draft = Draft::new();
    assert!(matches!(
        write(&mut draft, &[Event::Begin(name(XMLNS, "a"))]),
        Err(DraftError::Name(_))
    ));
}

/// The expanded names of the elements and attributes of `markup`.
fn expanded(markup: &str) -> Vec<(Option<String>, String)> {
    let document = roxmltree::Document::parse(markup).expect("well-formed");
    let mut names = Vec::new();
    for node in document.descendants().filter(roxmltree::Node::is_element) {
        // roxmltree reports an element under xmlns="" with an empty URI.
        names.push((
            node.tag_name()
                .namespace()
                .filter(|uri| !uri.is_empty())
                .map(String::from),
            node.tag_name().name().into(),
        ));
        for attribute in node.attributes() {
            names.push((
                attribute.namespace().map(String::from),
                attribute.name().into(),
            ));
        }
    }
    names
}

#[test]
fn a_default_namespace_takes_namespaced_attributes_and_plain_children() {
    // Namespaces in XML 1.0 §6.2: a default namespace never applies to an
    // attribute, so a namespaced attribute in it takes a named prefix; a
    // child in no namespace undeclares the default with xmlns="" and the
    // outer default is in scope again after it.
    const OUTER: &str = "urn:outer";
    let mut draft = Draft::with_prefixes(&[(OUTER, "")]).expect("a default namespace");
    write(
        &mut draft,
        &[
            Event::Begin(name(OUTER, "Root")),
            Event::Attribute(name(OUTER, "flag"), value("1", Datatype::String)),
            Event::Begin(name("", "Child")),
            Event::End,
            Event::Begin(name(OUTER, "Sibling")),
            Event::End,
            Event::End,
        ],
    )
    .expect("events are accepted");
    let markup = draft.finish().expect("one complete element").0;
    let outer = Some(String::from(OUTER));
    assert_eq!(
        expanded(&markup),
        [
            (outer.clone(), "Root".into()),
            (outer.clone(), "flag".into()),
            (None, "Child".into()),
            (outer, "Sibling".into()),
        ],
        "{markup}"
    );
}

#[test]
fn a_copied_element_keeps_its_own_namespaces_under_a_default() {
    // Namespaces in XML 1.0 §6.2: a default namespace applies to unprefixed
    // element names. A copied element in no namespace stays in none under
    // the draft's default namespace, and one that declares its own default
    // keeps it.
    const OUTER: &str = "urn:outer";
    let copy = |markup: &str| {
        let mut draft = Draft::with_prefixes(&[(OUTER, "")]).expect("a default namespace");
        let work = account();
        draft
            .write(Event::Begin(name(OUTER, "Role")), &work)
            .expect("begin");
        draft.copied(markup.as_bytes(), &work).expect("copied");
        draft.write(Event::End, &work).expect("end");
        draft.finish().expect("one complete element").0
    };
    let plain = copy("<Role a=\"x > y\">Approver<Inner/></Role>");
    let outer = Some(String::from(OUTER));
    assert_eq!(
        expanded(&plain),
        [
            (outer.clone(), "Role".into()),
            (None, "Role".into()),
            (None, "a".into()),
            (None, "Inner".into()),
        ],
        "{plain}"
    );
    let own = copy("<Role xmlns=\"urn:own\">Approver</Role>");
    assert_eq!(
        expanded(&own),
        [
            (outer, "Role".into()),
            (Some("urn:own".into()), "Role".into())
        ],
        "{own}"
    );
}

#[test]
fn a_fallback_prefix_never_shadows_a_chosen_one() {
    // Namespaces in XML 1.0 §6.1: an inner declaration of a prefix rebinds it
    // for the whole subtree. With `ds` chosen for another namespace, the XMLDSig
    // child must take a different prefix, so the innermost element keeps the
    // chosen namespace; the result is read back with its expanded names.
    const OUTER: &str = "urn:outer";
    let mut draft = Draft::with_prefixes(&[(OUTER, "ds")]).expect("ds is a prefix");
    write(
        &mut draft,
        &[
            Event::Begin(name(OUTER, "Root")),
            Event::Begin(name(DS, "Child")),
            Event::Begin(name(OUTER, "Leaf")),
            Event::End,
            Event::End,
            Event::End,
        ],
    )
    .expect("events are accepted");
    let markup = draft.finish().expect("one complete element").0;
    let document = roxmltree::Document::parse(&markup).expect("well-formed");
    let names: Vec<(Option<&str>, &str)> = document
        .descendants()
        .filter(roxmltree::Node::is_element)
        .map(|node| (node.tag_name().namespace(), node.tag_name().name()))
        .collect();
    assert_eq!(
        names,
        [
            (Some(OUTER), "Root"),
            (Some(DS), "Child"),
            (Some(OUTER), "Leaf")
        ],
        "{markup}"
    );
    // The chosen prefix itself stays bound to the chosen namespace on the
    // XMLDSig child, not rebound there and bound back on the leaf.
    let child = document
        .descendants()
        .find(|node| node.tag_name().name() == "Child")
        .expect("Child");
    assert_eq!(
        child.lookup_namespace_uri(Some("ds")),
        Some(OUTER),
        "{markup}"
    );
}

#[test]
fn an_unknown_namespace_gets_a_generated_prefix() {
    let markup = finished(&[
        Event::Begin(name("urn:other", "a")),
        Event::Attribute(name("urn:attr", "x"), value("1", Datatype::String)),
        Event::End,
    ]);
    assert_eq!(
        markup,
        "<ns1:a xmlns:ns1=\"urn:other\" xmlns:ns2=\"urn:attr\" ns2:x=\"1\"/>"
    );
}

#[test]
fn text_and_attributes_are_escaped_and_binary_is_base64() {
    // Values are character data, never markup; binary bytes are written as
    // unwrapped base64 of exactly those bytes (RFC 4648 §4).
    let bytes: Vec<u8> = (0..=255).collect();
    let markup = finished(&[
        Event::Begin(name(XADES, "a")),
        Event::Attribute(name("", "Target"), value("#x&\"<", Datatype::AnyUri)),
        Event::Text(value("a<b&c>", Datatype::String)),
        Event::Begin(name(XADES, "b")),
        Event::Binary(&bytes),
        Event::End,
        Event::End,
    ]);
    let encoded = structured_base64::STANDARD
        .encode(&bytes)
        .expect("test encoding");
    assert_eq!(
        markup,
        format!(
            "<xades:a xmlns:xades=\"{XADES}\" Target=\"#x&amp;&quot;&lt;\">a&lt;b&amp;c&gt;<xades:b>{encoded}</xades:b></xades:a>"
        )
    );
}

#[test]
fn long_binary_values_cross_chunk_boundaries_unchanged() {
    // Chunks of 768 bytes encode to whole base64 quanta, so the joined output
    // equals one encoding of the complete value.
    let bytes: Vec<u8> = (0..5000_u32)
        .map(|value| u8::try_from(value * 7 % 251).expect("below 251"))
        .collect();
    let markup = finished(&[
        Event::Begin(name(DS, "v")),
        Event::Binary(&bytes),
        Event::End,
    ]);
    let encoded = structured_base64::STANDARD
        .encode(&bytes)
        .expect("test encoding");
    assert!(markup.contains(&encoded));
}

#[test]
fn each_datatype_is_checked_before_it_is_written() {
    // XSD 1.0: an ID is an NCName referenced exactly; anyURI excludes what
    // escaping cannot express; a claimed instant needs its timezone.
    let refused = [
        value("1id", Datatype::Id),
        value(" id", Datatype::Id),
        value("a%zz", Datatype::AnyUri),
        value("2026-10-18T12:00:00", Datatype::ZonedDateTime),
        value("not a time", Datatype::ZonedDateTime),
        value("bad\u{1}", Datatype::String),
    ];
    for refused in refused {
        let mut draft = Draft::new();
        let result = write(
            &mut draft,
            &[Event::Begin(name(XADES, "a")), Event::Text(refused)],
        );
        assert!(
            matches!(result, Err(DraftError::Value { datatype, .. }) if datatype == refused.datatype),
            "{:?}: {result:?}",
            refused.lexical
        );
    }
    finished(&[
        Event::Begin(name(XADES, "SigningTime")),
        Event::Text(value("2026-10-18T12:00:00+02:00", Datatype::ZonedDateTime)),
        Event::End,
    ]);
}

#[test]
fn ids_and_attributes_are_unique() {
    let mut draft = Draft::new();
    let result = write(
        &mut draft,
        &[
            Event::Begin(name(XADES, "a")),
            Event::Attribute(name("", "Id"), value("one", Datatype::Id)),
            Event::Begin(name(XADES, "b")),
            Event::Attribute(name("", "Id"), value("one", Datatype::Id)),
        ],
    );
    assert!(matches!(result, Err(DraftError::DuplicateId(id)) if id == "one"));

    let mut draft = Draft::new();
    let result = write(
        &mut draft,
        &[
            Event::Begin(name(XADES, "a")),
            Event::Attribute(name("", "x"), value("1", Datatype::String)),
            Event::Attribute(name("", "x"), value("2", Datatype::String)),
        ],
    );
    assert!(matches!(result, Err(DraftError::DuplicateAttribute("x"))));

    let mut draft = Draft::new();
    write(
        &mut draft,
        &[
            Event::Begin(name(XADES, "a")),
            Event::Attribute(name("", "Id"), value("first", Datatype::Id)),
            Event::Begin(name(XADES, "b")),
            Event::Attribute(name("", "Id"), value("second", Datatype::Id)),
            Event::End,
            Event::End,
        ],
    )
    .expect("distinct IDs are accepted");
    let (_, ids) = draft.finish().expect("complete element");
    assert_eq!(ids, ["first", "second"]);
}

#[test]
fn events_must_form_exactly_one_balanced_element() {
    let order = |events: &[Event<'_>]| {
        let mut draft = Draft::new();
        write(&mut draft, events)
    };
    assert!(matches!(order(&[Event::End]), Err(DraftError::Order(_))));
    assert!(matches!(
        order(&[Event::Text(value("x", Datatype::String))]),
        Err(DraftError::Order(_))
    ));
    assert!(matches!(
        order(&[Event::Attribute(
            name("", "x"),
            value("1", Datatype::String)
        )]),
        Err(DraftError::Order(_))
    ));
    assert!(matches!(
        order(&[
            Event::Begin(name(XADES, "a")),
            Event::Text(value("t", Datatype::String)),
            Event::Attribute(name("", "x"), value("1", Datatype::String)),
        ]),
        Err(DraftError::Order(_))
    ));
    assert!(matches!(
        order(&[
            Event::Begin(name(XADES, "a")),
            Event::End,
            Event::Begin(name(XADES, "b")),
        ]),
        Err(DraftError::Order(_))
    ));
    assert!(matches!(
        order(&[Event::Begin(name(XADES, "1bad"))]),
        Err(DraftError::Name("1bad"))
    ));
    let mut open = Draft::new();
    write(&mut open, &[Event::Begin(name(XADES, "a"))]).expect("begin");
    assert!(matches!(open.finish(), Err(DraftError::Order(_))));
    assert!(matches!(Draft::new().finish(), Err(DraftError::Order(_))));
}

#[test]
fn work_and_storage_refusals_keep_their_class() {
    // The draft admits every scan and allocation before doing it.
    let starved = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 0)));
    let mut draft = Draft::new();
    assert!(matches!(
        draft.write(Event::Begin(name(XADES, "a")), &starved),
        Err(DraftError::Resource(MemoryError::WorkExceeded))
    ));
    let no_storage = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
    let mut draft = Draft::new();
    assert!(matches!(
        draft.write(Event::Begin(name(XADES, "a")), &no_storage),
        Err(DraftError::Resource(_))
    ));
}
