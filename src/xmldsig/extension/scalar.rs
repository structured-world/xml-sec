//! Exact original XML scalar facts; format acceptance remains with the consumer.

use super::{ScalarError, charge_bytes};
use crate::document::{DocumentView, NodeIdentity};
use crate::xmldsig::LexicalSource;
use structured_asn1::memory::{OwnedVec, Work};

/// A direct non-namespace attribute, already normalized by the XML parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectAttribute<'a> {
    /// Original owner, including document and generation.
    pub owner: NodeIdentity,
    /// Expanded namespace name; default namespaces do not apply to attributes.
    pub namespace: Option<&'a str>,
    /// Original local name.
    pub local_name: &'a str,
    /// XML-normalized value, not schema-normalized or source-byte spelling.
    pub value: &'a str,
}

/// An in-scope namespace binding, not a direct attribute/declaration claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceBinding<'a> {
    /// Original owner.
    pub owner: NodeIdentity,
    /// None denotes the default namespace.
    pub prefix: Option<&'a str>,
    /// In-scope namespace URI.
    pub uri: &'a str,
}

/// Processing refusal and caller refusal keep their independent typed causes.
#[derive(Debug)]
pub enum InspectionError<E> {
    /// Original document or current execution failure.
    Processing(ScalarError),
    /// Original callback error, with no stringification or boxing.
    Visitor(E),
}

fn element<'a>(
    view: DocumentView<'a>,
    owner: NodeIdentity,
    work: &impl Work,
) -> Result<crate::xml::dom::Node<'a, 'a>, ScalarError> {
    charge_bytes(work, 1)?;
    let node = view.resolve_node(owner)?;
    if !node.is_element() {
        return Err(ScalarError::NotElement);
    }
    Ok(node)
}

/// Visit every direct attribute once in source order. Namespace declarations
/// are excluded (Namespaces in XML 1.0 §6.2), including inherited bindings.
/// The callback cannot return a borrow into its temporary inspection scope.
pub fn visit_direct_attributes<W: Work, E>(
    view: DocumentView<'_>,
    owner: NodeIdentity,
    work: &W,
    mut visitor: impl for<'a> FnMut(DirectAttribute<'a>) -> Result<(), E>,
) -> Result<(), InspectionError<E>> {
    let node = element(view, owner, work).map_err(InspectionError::Processing)?;
    for attribute in node.attributes() {
        charge_bytes(work, 1).map_err(InspectionError::Processing)?;
        charge_bytes(work, attribute.name().len()).map_err(InspectionError::Processing)?;
        charge_bytes(work, attribute.namespace().map_or(0, str::len))
            .map_err(InspectionError::Processing)?;
        charge_bytes(work, attribute.value().len()).map_err(InspectionError::Processing)?;
        visitor(DirectAttribute {
            owner,
            namespace: attribute.namespace(),
            local_name: attribute.name(),
            value: attribute.value(),
        })
        .map_err(InspectionError::Visitor)?;
    }
    Ok(())
}

/// Visit the semantic in-scope namespace axis separately from attributes.
/// This does not reconstruct which declarations were written on this element.
pub fn visit_in_scope_namespaces<W: Work, E>(
    view: DocumentView<'_>,
    owner: NodeIdentity,
    work: &W,
    mut visitor: impl for<'a> FnMut(NamespaceBinding<'a>) -> Result<(), E>,
) -> Result<(), InspectionError<E>> {
    let node = element(view, owner, work).map_err(InspectionError::Processing)?;
    let mut xml_seen = false;
    for namespace in node.namespaces() {
        charge_bytes(work, 1).map_err(InspectionError::Processing)?;
        charge_bytes(work, namespace.name().map_or(0, str::len))
            .map_err(InspectionError::Processing)?;
        charge_bytes(work, namespace.uri().len()).map_err(InspectionError::Processing)?;
        // Namespaces in XML 1.0 §§3, 6.2: xml is always bound, whereas
        // xmlns="" removes the default binding rather than naming a namespace.
        // https://www.w3.org/TR/2009/REC-xml-names-20091208/#defaulting
        if namespace.uri().is_empty() {
            continue;
        }
        if namespace.name() == Some("xml") {
            xml_seen = true;
        }
        visitor(NamespaceBinding {
            owner,
            prefix: namespace.name(),
            uri: namespace.uri(),
        })
        .map_err(InspectionError::Visitor)?;
    }
    if !xml_seen {
        const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
        charge_bytes(work, 1 + 3 + XML_NAMESPACE.len()).map_err(InspectionError::Processing)?;
        visitor(NamespaceBinding {
            owner,
            prefix: Some("xml"),
            uri: XML_NAMESPACE,
        })
        .map_err(InspectionError::Visitor)?;
    }
    Ok(())
}

/// Requested base datatype. Other schemas are explicitly unsupported, not invalid.
#[derive(Clone, Copy, Debug)]
pub enum ScalarType<'a> {
    /// XML Schema 1.0 boolean.
    Boolean,
    /// XML Schema 1.0 integer validity, without finite-width conversion.
    Integer,
    /// XML Schema 1.0 QName, expanded in the original owner's namespace scope.
    QName,
    /// XML Schema 1.0 dateTime, not RFC 3339 or XSD 1.1.
    DateTime,
    /// XML Schema 1.0 ID lexical facts, without registering an ID.
    Id,
    /// XML Schema 1.0 anyURI, not a URL/scheme policy.
    AnyUri,
    /// An expanded schema name for which this kernel has no semantics.
    Other {
        /// Original schema namespace URI.
        namespace: &'a str,
        /// Original schema local name.
        local_name: &'a str,
    },
}

/// Exact lexical dateTime components. These are not a normalized UTC instant.
/// In particular hour 24 denotes the following midnight, and absent timezone
/// is not UTC. No comparison or conversion through a finite numeric year occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTimeLexical<'a> {
    /// Year sign; XSD 1.0 has no year zero.
    pub negative_year: bool,
    /// Four or more original year digits, with no precision limit.
    pub year_digits: &'a str,
    /// Gregorian month.
    pub month: u8,
    /// Day within the original month.
    pub day: u8,
    /// Original hour, including the special end-of-day value 24.
    pub hour: u8,
    /// Minute within the hour.
    pub minute: u8,
    /// Whole seconds (0 through 60). This does not certify a UTC leap second.
    pub second: u8,
    /// Exact fractional digits; no rounding or removal of trailing zeros.
    pub fraction_digits: Option<&'a str>,
    /// None preserves an absent timezone; zero denotes explicit UTC.
    pub timezone_minutes: Option<i16>,
}

/// Expanded QName value, not an element/attribute name or a resolved schema type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QNameValue<'a> {
    /// Original in-scope namespace URI, or None when no default binding exists.
    pub namespace: Option<&'a str>,
    /// Validated original local component, without a prefix or whitespace.
    pub local_name: &'a str,
}

/// A supported schema value, preserving exact lexical data when required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarValue<'a> {
    /// Explicit schema boolean.
    Boolean(bool),
    /// Valid arbitrary-precision integer spelling; not a numeric value or a
    /// claim about derived types such as int, nonNegativeInteger or totalDigits.
    Integer,
    /// Expanded original QName, without type-definition lookup or schema loading.
    QName(QNameValue<'a>),
    /// Exact dateTime lexical components, not canonicalized value fields.
    DateTime(DateTimeLexical<'a>),
    /// Collapsed NCName; no ID registration, uniqueness or authentication claim.
    Id(&'a str),
    /// Collapsed anyURI spelling; no escaping, absolutization or fetching.
    AnyUri(&'a str),
}

/// Source and schema outcomes are facts, not processing failures or defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarFact<'a> {
    /// The selected original attribute is absent.
    Absent,
    /// An element child prevents reading simple content.
    ComplexContent,
    /// A present lexical value is outside the requested base datatype.
    Malformed,
    /// A syntactically valid QName uses this prefix without an in-scope binding.
    /// This is a value-interpretation fact, not a terminal processing failure.
    UnboundPrefix(&'a str),
    /// The requested datatype has no implemented semantics.
    Unsupported,
    /// A supported base-datatype value.
    Value(ScalarValue<'a>),
}

/// Original XML-normalized lexical text and its separate schema outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarInspection<'a> {
    /// Original document/generation-bound element.
    pub owner: NodeIdentity,
    /// Original XML text, before schema whitespace collapse; absent/complex has none.
    pub lexical: Option<&'a str>,
    /// Exact base schema outcome.
    pub fact: ScalarFact<'a>,
}

enum Text<'a, W: Work> {
    Borrowed(&'a str),
    Joined(OwnedVec<u8, W>),
}
impl<W: Work> Text<'_, W> {
    fn view(&self) -> &str {
        match self {
            Self::Borrowed(text) => text,
            Self::Joined(bytes) => {
                std::str::from_utf8(bytes).expect("only UTF-8 fragments appended")
            }
        }
    }
}

/// Inspect an original attribute or simple-content source within a paid scope.
/// Temporary joined/collapsed storage is owned by current Work and released
/// when the callback returns; R cannot carry a borrowed temporary scalar.
pub fn with_scalar<W: Work, R, E>(
    view: DocumentView<'_>,
    owner: NodeIdentity,
    source: LexicalSource<'_>,
    datatype: ScalarType<'_>,
    work: &W,
    consume: impl for<'a> FnOnce(ScalarInspection<'a>) -> Result<R, E>,
) -> Result<R, InspectionError<E>> {
    let node = element(view, owner, work).map_err(InspectionError::Processing)?;
    let read = || -> Result<_, ScalarError> {
        match source {
            LexicalSource::Attribute {
                namespace,
                local_name,
            } => {
                for attribute in node.attributes() {
                    charge_bytes(work, 1)?;
                    charge_bytes(work, attribute.name().len())?;
                    charge_bytes(work, attribute.namespace().map_or(0, str::len))?;
                    if attribute.name() == local_name && attribute.namespace() == namespace {
                        admit_scalar_passes(work, attribute.value().len())?;
                        return Ok(Ok(Some(Text::Borrowed(attribute.value()))));
                    }
                }
                Ok(Ok(None))
            }
            LexicalSource::SimpleContent => {
                // Validate structure before creating any joined prefix. A malformed
                // simple-content source must not allocate only to discard the text.
                let mut text_bytes = 0usize;
                let mut child_visits = 0usize;
                for child in node.children() {
                    charge_bytes(work, 1)?;
                    child_visits = child_visits.checked_add(1).ok_or(ScalarError::Resource(
                        structured_asn1::memory::MemoryError::WorkExceeded,
                    ))?;
                    if child.is_element() {
                        return Ok(Err(()));
                    }
                    if child.is_text() {
                        let text = child.text().expect("text node has a text value");
                        text_bytes =
                            text_bytes
                                .checked_add(text.len())
                                .ok_or(ScalarError::Resource(
                                    structured_asn1::memory::MemoryError::WorkExceeded,
                                ))?;
                    }
                }
                // Copies have their own OwnedVec work charge, but admit every
                // subsequent linear pass before constructing a doomed join.
                admit_scalar_passes(work, text_bytes)?;
                // The second traversal also visits comments and PIs, even when
                // no text remains. Admit those visits before the first join.
                charge_bytes(work, child_visits)?;
                let mut value = Text::Borrowed("");
                for child in node.children() {
                    if child.is_element() {
                        return Ok(Err(()));
                    }
                    if !child.is_text() {
                        continue;
                    }
                    let text = child.text().expect("text node has a text value");
                    match &mut value {
                        Text::Borrowed(first) if first.is_empty() => *first = text,
                        Text::Borrowed(first) => {
                            let mut bytes = work.vector();
                            bytes
                                .try_reserve_exact(text_bytes)
                                .map_err(ScalarError::Resource)?;
                            bytes
                                .try_extend_from_slice(first.as_bytes())
                                .map_err(ScalarError::Resource)?;
                            bytes
                                .try_extend_from_slice(text.as_bytes())
                                .map_err(ScalarError::Resource)?;
                            value = Text::Joined(bytes);
                        }
                        Text::Joined(bytes) => bytes
                            .try_extend_from_slice(text.as_bytes())
                            .map_err(ScalarError::Resource)?,
                    }
                }
                Ok(Ok(Some(value)))
            }
        }
    };
    let value = read().map_err(InspectionError::Processing)?;
    let value = match value {
        Err(()) => {
            return consume(ScalarInspection {
                owner,
                lexical: None,
                fact: ScalarFact::ComplexContent,
            })
            .map_err(InspectionError::Visitor);
        }
        Ok(None) => {
            return consume(ScalarInspection {
                owner,
                lexical: None,
                fact: ScalarFact::Absent,
            })
            .map_err(InspectionError::Visitor);
        }
        Ok(Some(value)) => value,
    };
    let lexical = value.view();
    let collapsed = match datatype {
        ScalarType::Other { .. } | ScalarType::Integer | ScalarType::QName => {
            Text::Borrowed(lexical)
        }
        _ => collapse(lexical, work).map_err(InspectionError::Processing)?,
    };
    let text = collapsed.view();
    let fact = match datatype {
        ScalarType::Other { .. } => ScalarFact::Unsupported,
        ScalarType::Boolean => match text {
            "true" | "1" => ScalarFact::Value(ScalarValue::Boolean(true)),
            "false" | "0" => ScalarFact::Value(ScalarValue::Boolean(false)),
            _ => ScalarFact::Malformed,
        },
        ScalarType::Integer => {
            if valid_integer(text) {
                ScalarFact::Value(ScalarValue::Integer)
            } else {
                ScalarFact::Malformed
            }
        }
        ScalarType::QName => {
            inspect_qname(node, text, work).map_err(InspectionError::Processing)?
        }
        ScalarType::DateTime => parse_date_time(text)
            .map(|value| ScalarFact::Value(ScalarValue::DateTime(value)))
            .unwrap_or(ScalarFact::Malformed),
        ScalarType::Id => {
            // XSD 1.0 §3.3.8; this is lexical validity, not uniqueness.
            // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#ID
            if crate::xml::is_xml_ncname(text) {
                ScalarFact::Value(ScalarValue::Id(text))
            } else {
                ScalarFact::Malformed
            }
        }
        ScalarType::AnyUri => {
            if valid_any_uri(text) {
                ScalarFact::Value(ScalarValue::AnyUri(text))
            } else {
                ScalarFact::Malformed
            }
        }
    };
    consume(ScalarInspection {
        owner,
        lexical: Some(lexical),
        fact,
    })
    .map_err(InspectionError::Visitor)
}

fn whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn inspect_qname<'a>(
    node: crate::xml::dom::Node<'a, 'a>,
    text: &'a str,
    work: &impl Work,
) -> Result<ScalarFact<'a>, ScalarError> {
    // XSD 1.0 Part 2 §§3.2.18,4.3.6: a QName contains no internal whitespace,
    // so trimming XML whitespace is collapse-equivalent without a new buffer.
    // Namespaces in XML 1.0 §3 supplies the shared NCName grammar.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#QName
    // https://www.w3.org/TR/2009/REC-xml-names-20091208/#ns-qualnames
    let text = text.trim_matches([' ', '\t', '\r', '\n']);
    let (prefix, local_name) = match text.split_once(':') {
        Some((prefix, local_name)) => {
            if !crate::xml::is_xml_ncname(prefix) {
                return Ok(ScalarFact::Malformed);
            }
            (Some(prefix), local_name)
        }
        None => (None, text),
    };
    if !crate::xml::is_xml_ncname(local_name) {
        return Ok(ScalarFact::Malformed);
    }
    // XSD 1.0 Part 1 §3.15.3: QName *values*, including xsi:type (§2.6.1),
    // use the containing element's bindings, including the default namespace.
    // This differs from the namespace rule for unprefixed attribute *names*.
    // A binding does not resolve the value to any schema declaration (§3.15.4).
    // https://www.w3.org/TR/2004/REC-xmlschema-1-20041028/#src-qname
    let mut namespace = None;
    if prefix == Some("xml") {
        // Namespaces in XML 1.0 §3: xml is bound even without a declaration.
        // https://www.w3.org/TR/2009/REC-xml-names-20091208/#ns-decl
        const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
        charge_bytes(work, 1 + 3 + XML_NAMESPACE.len())?;
        namespace = Some(XML_NAMESPACE);
    } else {
        for binding in node.namespaces() {
            charge_bytes(work, 1)?;
            if let Some(name) = binding.name() {
                charge_bytes(work, name.len())?;
            }
            if binding.name() != prefix {
                continue;
            }
            charge_bytes(work, binding.uri().len())?;
            // An empty default declaration removes the binding (§6.2);
            // it is not a namespace whose name is the empty string.
            // https://www.w3.org/TR/2009/REC-xml-names-20091208/#defaulting
            if !binding.uri().is_empty() {
                namespace = Some(binding.uri());
            }
            break;
        }
    }
    if let Some(prefix) = prefix
        && namespace.is_none()
    {
        return Ok(ScalarFact::UnboundPrefix(prefix));
    }
    Ok(ScalarFact::Value(ScalarValue::QName(QNameValue {
        namespace,
        local_name,
    })))
}

fn valid_integer(text: &str) -> bool {
    // XSD 1.0 §§3.3.13.1,4.3.6: optional sign and one or more ASCII digits
    // after collapse. Internal whitespace always invalidates this grammar, so
    // trimming XML whitespace is equivalent without allocating a collapsed copy.
    // Canonical-form rules (§3.3.13.2) do not restrict lexical validity.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#integer
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#rf-whiteSpace
    let text = text.trim_matches([' ', '\t', '\r', '\n']);
    let digits = match text.as_bytes().first() {
        Some(b'+' | b'-') => &text.as_bytes()[1..],
        _ => text.as_bytes(),
    };
    if digits.is_empty() {
        return false;
    }
    for digit in digits {
        if !digit.is_ascii_digit() {
            return false;
        }
    }
    true
}

fn collapse<'a, W: Work>(input: &'a str, work: &W) -> Result<Text<'a, W>, ScalarError> {
    // XSD 1.0 §4.3.6: only the four XML whitespace characters collapse.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#rf-whiteSpace
    let text = input.trim_matches([' ', '\t', '\r', '\n']);
    let mut previous_space = false;
    let mut needs_copy = false;
    for byte in text.bytes() {
        if whitespace(byte) && (byte != b' ' || previous_space) {
            needs_copy = true;
            break;
        }
        previous_space = byte == b' ';
    }
    if !needs_copy {
        return Ok(Text::Borrowed(text));
    }
    let mut bytes = work.vector();
    bytes
        .try_reserve_exact(text.len())
        .map_err(ScalarError::Resource)?;
    let mut space = false;
    for byte in text.bytes() {
        if whitespace(byte) {
            space = true;
            continue;
        }
        if space {
            bytes.try_push(b' ').map_err(ScalarError::Resource)?;
            space = false;
        }
        bytes.try_push(byte).map_err(ScalarError::Resource)?;
    }
    Ok(Text::Joined(bytes))
}

fn two(input: &str) -> Option<u8> {
    let bytes = input.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return None;
    }
    Some((bytes[0] - b'0') * 10 + bytes[1] - b'0')
}

fn parse_date_time(input: &str) -> Option<DateTimeLexical<'_>> {
    // XSD 1.0 §§3.2.7.1,3.2.7.3 and Appendix E: retain original lexical
    // components, including end-of-day; never substitute XSD 1.1 year zero.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation
    let (negative_year, rest) = input
        .strip_prefix('-')
        .map_or((false, input), |s| (true, s));
    let (year, tail) = rest.split_once('-')?;
    if year.len() < 4 || (year.len() > 4 && year.starts_with('0')) {
        return None;
    }
    let mut modulo = 0u16;
    let mut nonzero = false;
    for digit in year.bytes() {
        if !digit.is_ascii_digit() {
            return None;
        }
        nonzero |= digit != b'0';
        modulo = (modulo * 10 + u16::from(digit - b'0')) % 400;
    }
    if !nonzero {
        return None;
    }
    let (month, tail) = tail.split_once('-')?;
    let (day, tail) = tail.split_once('T')?;
    let month = two(month)?;
    let day = two(day)?;
    let (hour, tail) = tail.split_once(':')?;
    let (minute, tail) = tail.split_once(':')?;
    let hour = two(hour)?;
    let minute = two(minute)?;
    let second = two(tail.get(..2)?)?;
    let mut tail = tail.get(2..)?;
    let fraction_digits = if let Some(fraction) = tail.strip_prefix('.') {
        let end = fraction
            .bytes()
            .position(|c| !c.is_ascii_digit())
            .unwrap_or(fraction.len());
        if end == 0 {
            return None;
        }
        tail = &fraction[end..];
        Some(&fraction[..end])
    } else {
        None
    };
    let timezone_minutes = if tail.is_empty() {
        None
    } else if tail == "Z" {
        Some(0)
    } else {
        let negative = match tail.as_bytes()[0] {
            b'-' => true,
            b'+' => false,
            _ => return None,
        };
        let (h, m) = tail.get(1..)?.split_once(':')?;
        let h = two(h)?;
        let m = two(m)?;
        if h > 14 || m > 59 || (h == 14 && m != 0) {
            return None;
        }
        let offset = i16::from(h) * 60 + i16::from(m);
        Some(if negative { -offset } else { offset })
    };
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if modulo == 0 || (!modulo.is_multiple_of(100) && modulo.is_multiple_of(4)) => 29,
        2 => 28,
        _ => return None,
    };
    // XSD 1.0 Appendix D.1 permits 60 (unlike XSD 1.1 and libxml2).
    // Retain it as a lexical fact: UTC-adjustment validation and arithmetic
    // require a consumer's temporal evidence, not a POSIX normalization here.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#isoformats
    if day == 0 || day > maximum_day || hour > 24 || minute > 59 || second > 60 {
        return None;
    }
    if hour == 24
        && (minute != 0
            || second != 0
            || fraction_digits.is_some_and(|f| f.bytes().any(|d| d != b'0')))
    {
        return None;
    }
    Some(DateTimeLexical {
        negative_year,
        year_digits: year,
        month,
        day,
        hour,
        minute,
        second,
        fraction_digits,
        timezone_minutes,
    })
}

fn escaped(byte: u8) -> bool {
    byte <= 0x20
        || byte >= 0x7f
        || matches!(
            byte,
            b'<' | b'>' | b'"' | b'{' | b'}' | b'|' | b'\\' | b'^' | b'`'
        )
}
fn unreserved(byte: u8) -> bool {
    escaped(byte)
        || byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
        )
}
fn uri_chars(input: &str, extra: &[u8]) -> bool {
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !unreserved(byte) && !extra.contains(&byte) {
            return false;
        }
    }
    true
}
fn admit_scalar_passes(work: &impl Work, bytes: usize) -> Result<(), ScalarError> {
    // UTF-8 validation, whitespace handling and base datatype parsing. OwnedVec
    // separately admits copying; no owned intermediate precedes this bound.
    let bound = bytes.checked_mul(12).ok_or(ScalarError::Resource(
        structured_asn1::memory::MemoryError::WorkExceeded,
    ))?;
    charge_bytes(work, bound)
}

fn valid_any_uri(input: &str) -> bool {
    // XSD 1.0 §3.2.17.1 incorporates RFC 2396 + RFC 2732, not URL scheme
    // validation or implicit XML Base. XLink 1.0 §5.4 escapes spaces/non-ASCII
    // and excluded characters; they are grammar-equivalent to an escaped octet
    // here, so validation needs no escaped copy.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#anyURI
    // https://www.rfc-editor.org/rfc/rfc2396#appendix-A
    let (body, fragment) = input
        .split_once('#')
        .map_or((input, None), |(a, b)| (a, Some(b)));
    if fragment.is_some_and(|f| !uri_chars(f, b";/?:@&=+$,[]")) {
        return false;
    }
    let (path, query) = body
        .split_once('?')
        .map_or((body, None), |(a, b)| (a, Some(b)));
    if query.is_some_and(|q| !uri_chars(q, b";/?:@&=+$,[]")) {
        return false;
    }
    let mut path = path;
    if let Some(colon) = body.find(':') {
        let prefix = &body[..colon];
        if !prefix.contains(['/', '?']) {
            let mut scheme = prefix.bytes();
            if !scheme.next().is_some_and(|c| c.is_ascii_alphabetic())
                || !scheme.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
            {
                return false;
            }
            let rest = &body[colon + 1..];
            if rest.is_empty() {
                return false;
            }
            if !rest.starts_with('/') {
                // RFC 2396 §3 / Appendix A: opaque_part begins with
                // uric_no_slash, not uric. RFC 2732 §3 expands reserved/uric
                // with brackets but does not add them to uric_no_slash.
                // Escaped brackets and brackets after the first token remain legal.
                // https://www.rfc-editor.org/rfc/rfc2396#section-3
                // https://www.rfc-editor.org/rfc/rfc2732#section-3
                if matches!(rest.as_bytes()[0], b'[' | b']') {
                    return false;
                }
                return uri_chars(rest, b";/?:@&=+$,[]");
            }
            path = &path[colon + 1..];
        }
    }
    if let Some(rest) = path.strip_prefix("//") {
        let (authority, suffix) = rest.split_once('/').map_or((rest, ""), |(a, b)| (a, b));
        if authority.contains(['[', ']']) {
            let server = authority
                .rsplit_once('@')
                .map_or(authority, |(user, host)| {
                    if uri_chars(user, b";:&=+$,") {
                        host
                    } else {
                        ""
                    }
                });
            let Some(server) = server.strip_prefix('[') else {
                return false;
            };
            let Some((address, port)) = server.split_once(']') else {
                return false;
            };
            if !valid_ipv6_reference(address) {
                return false;
            }
            if !port.is_empty()
                && !port
                    .strip_prefix(':')
                    .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
            {
                return false;
            }
        } else if !uri_chars(authority, b"$,:;@&=+") {
            return false;
        }
        path = suffix;
    }
    uri_chars(path, b"/;:@&=+$,")
}

fn valid_ipv6_reference(address: &str) -> bool {
    // XSD 1.0 §3.2.17.1 incorporates RFC 2732 §3 and RFC 2373 Appendix B:
    // embedded IPv4 octets are 1*3DIGIT, including leading zeroes. RFC 2373
    // §2.2(3) still requires 8-bit decimal values, not arbitrary three digits.
    // https://www.rfc-editor.org/rfc/rfc2732#section-3
    // https://www.rfc-editor.org/rfc/rfc2373#appendix-B
    if let Some((left, right)) = address.split_once("::") {
        let Some(left) = ipv6_units(left, false) else {
            return false;
        };
        let Some(right) = ipv6_units(right, true) else {
            return false;
        };
        left + right < 8
    } else {
        ipv6_units(address, true) == Some(8)
    }
}

fn ipv6_units(part: &str, allow_ipv4_tail: bool) -> Option<usize> {
    if part.is_empty() {
        return Some(0);
    }
    let mut units = 0;
    let mut groups = part.split(':').peekable();
    while let Some(group) = groups.next() {
        if group.contains('.') {
            if !allow_ipv4_tail || groups.peek().is_some() {
                return None;
            }
            let mut count = 0;
            for octet in group.split('.') {
                if octet.is_empty() || octet.len() > 3 {
                    return None;
                }
                let mut value = 0u16;
                for byte in octet.bytes() {
                    if !byte.is_ascii_digit() {
                        return None;
                    }
                    value = value * 10 + u16::from(byte - b'0');
                }
                if value > 255 {
                    return None;
                }
                count += 1;
            }
            if count != 4 {
                return None;
            }
            units += 2;
        } else {
            if group.is_empty() || group.len() > 4 || !group.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return None;
            }
            units += 1;
        }
        if units > 8 {
            return None;
        }
    }
    Some(units)
}
