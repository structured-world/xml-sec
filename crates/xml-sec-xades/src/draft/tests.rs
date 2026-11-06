use super::{Draft, DraftError};
use alloc::sync::Arc;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_xades::produce::{Datatype, Event, Value, Writer};
use structured_xades::xml::Name;

const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

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
    let encoded = STANDARD.encode(&bytes);
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
    let encoded = STANDARD.encode(&bytes);
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
