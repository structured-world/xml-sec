use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::rc::Rc;

use crate::budget::Meter;
use crate::{BudgetKind, Document, Error, NodeId, NodeKind, Result};

/// XSLT output method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMethod {
    #[default]
    Xml,
    Html,
    Text,
}

/// Compiled `xsl:output` properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputDefinition {
    pub method: OutputMethod,
    pub version: Option<String>,
    pub encoding: String,
    pub omit_xml_declaration: bool,
    pub standalone: Option<bool>,
    pub doctype_public: Option<String>,
    pub doctype_system: Option<String>,
    pub indent: bool,
    pub media_type: Option<String>,
    pub cdata_section_elements: HashSet<crate::ExpandedName>,
    pub(crate) method_explicit: bool,
    pub(crate) encoding_explicit: bool,
    pub(crate) indent_explicit: bool,
    pub(crate) inject_content_type: bool,
}

impl Default for OutputDefinition {
    fn default() -> Self {
        Self {
            method: OutputMethod::Xml,
            version: Some("1.0".into()),
            encoding: "UTF-8".into(),
            omit_xml_declaration: false,
            standalone: None,
            doctype_public: None,
            doctype_system: None,
            indent: false,
            media_type: None,
            cdata_section_elements: HashSet::new(),
            method_explicit: false,
            encoding_explicit: false,
            indent_explicit: false,
            inject_content_type: true,
        }
    }
}

/// Exact serialized result bytes and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedOutput {
    pub bytes: Vec<u8>,
    pub encoding: String,
    pub media_type: Option<String>,
}

enum OutputEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Ascii,
    Latin1,
    Other {
        encoding: &'static encoding_rs::Encoding,
        representable: RefCell<HashMap<char, bool>>,
    },
}

impl OutputEncoding {
    fn new(label: &str) -> Result<Self> {
        if label.eq_ignore_ascii_case("utf-8") {
            Ok(Self::Utf8)
        } else if label.eq_ignore_ascii_case("utf-16") || label.eq_ignore_ascii_case("utf-16le") {
            Ok(Self::Utf16Le)
        } else if label.eq_ignore_ascii_case("utf-16be") {
            Ok(Self::Utf16Be)
        } else if is_ascii_encoding_label(label) {
            Ok(Self::Ascii)
        } else if xml_sec_xml_input::is_latin1_encoding_label(label) {
            Ok(Self::Latin1)
        } else {
            encoding_rs::Encoding::for_label(label.as_bytes())
                .map(|encoding| Self::Other {
                    encoding,
                    representable: RefCell::new(HashMap::new()),
                })
                .ok_or_else(|| Error::Serialization(format!("unsupported output encoding {label}")))
        }
    }

    fn represents(&self, character: char) -> bool {
        match self {
            Self::Utf8 | Self::Utf16Le | Self::Utf16Be => true,
            Self::Ascii => character.is_ascii(),
            Self::Latin1 => u32::from(character) <= 0xff,
            Self::Other {
                encoding,
                representable,
            } => {
                if let Some(value) = representable.borrow().get(&character) {
                    return *value;
                }
                let mut bytes = [0_u8; 4];
                let value = !encoding.encode(character.encode_utf8(&mut bytes)).2;
                representable.borrow_mut().insert(character, value);
                value
            }
        }
    }
}

fn is_ascii_encoding_label(label: &str) -> bool {
    [
        "us-ascii",
        "ascii",
        "ansi_x3.4-1968",
        "ansi_x3.4-1986",
        "iso-ir-6",
        "iso_646.irv:1991",
        "iso646-us",
        "ibm367",
        "cp367",
        "csascii",
        "us",
    ]
    .iter()
    .any(|alias| label.eq_ignore_ascii_case(alias))
}

pub(crate) fn serialize(
    document: &Document,
    definition: &OutputDefinition,
    meter: &mut Meter,
) -> Result<SerializedOutput> {
    serialize_charged(document, definition, meter, BudgetKind::SerializedBytes)
}

pub(crate) fn serialize_fragment(document: &Document, meter: &mut Meter) -> Result<String> {
    let mut definition = OutputDefinition {
        omit_xml_declaration: true,
        ..OutputDefinition::default()
    };
    definition.method_explicit = true;
    definition.indent_explicit = true;
    let (used, limit) = meter.usage(BudgetKind::OwnedBytes)?;
    let mut counter = RenderBuffer::counting(
        EncodingCounter::new(&OutputEncoding::Utf8),
        BudgetKind::OwnedBytes,
        used,
        limit,
    );
    render(document, &definition, &OutputEncoding::Utf8, &mut counter)?;
    let bytes = counter.len();
    meter.charge(BudgetKind::OwnedBytes, bytes)?;
    let mut text = RenderBuffer::Text(String::with_capacity(bytes));
    render(document, &definition, &OutputEncoding::Utf8, &mut text)?;
    Ok(text.into_string())
}

fn serialize_charged(
    document: &Document,
    definition: &OutputDefinition,
    meter: &mut Meter,
    budget_kind: BudgetKind,
) -> Result<SerializedOutput> {
    let mut definition = Cow::Borrowed(definition);
    if !definition.method_explicit
        && first_element(document)
            .is_some_and(|node| matches!(&node.kind, NodeKind::Element { name, .. } if name.namespace.is_none() && name.local.eq_ignore_ascii_case("html")))
    {
        definition.to_mut().method = OutputMethod::Html;
    }
    if definition.method == OutputMethod::Html && !definition.indent_explicit {
        definition.to_mut().indent = true;
    }
    if definition.method == OutputMethod::Xml {
        let version = definition.version.as_deref().unwrap_or("1.0");
        if !matches!(version, "1.0" | "1.1") {
            return Err(Error::Serialization(format!(
                "unsupported XML output version `{version}`; supported versions are 1.0 and 1.1"
            )));
        }
    }
    let encoding = OutputEncoding::new(&definition.encoding)?;
    let (used, limit) = meter.usage(budget_kind)?;
    let mut counter =
        RenderBuffer::counting(EncodingCounter::new(&encoding), budget_kind, used, limit);
    render(document, &definition, &encoding, &mut counter)?;
    let text_bytes = counter.len();
    let encoded_bytes = counter.encoded_len()?;
    meter.check_additional(budget_kind, encoded_bytes)?;
    meter.charge(BudgetKind::OwnedBytes, text_bytes)?;
    let mut text = RenderBuffer::Text(String::with_capacity(text_bytes));
    render(document, &definition, &encoding, &mut text)?;
    let text = text.into_string();
    if definition.method == OutputMethod::Xml {
        validate_xml_characters(&text, definition.version.as_deref().unwrap_or("1.0"))?;
    }
    if definition.method == OutputMethod::Text {
        validate_text_encoding(&text, &encoding, &definition.encoding)?;
    } else {
        reject_unrepresentable_markup(&text, &encoding, "serialized output")?;
    }
    let bytes = encode(
        text,
        text_bytes,
        encoded_bytes,
        &encoding,
        meter,
        budget_kind,
    )?;
    Ok(SerializedOutput {
        bytes,
        encoding: definition.encoding.clone(),
        media_type: definition.media_type.clone().or_else(|| {
            Some(
                match definition.method {
                    OutputMethod::Xml => "text/xml",
                    OutputMethod::Html => "text/html",
                    OutputMethod::Text => "text/plain",
                }
                .into(),
            )
        }),
    })
}

fn render(
    document: &Document,
    definition: &OutputDefinition,
    encoding: &OutputEncoding,
    text: &mut RenderBuffer,
) -> Result<()> {
    if definition.method == OutputMethod::Xml && !definition.omit_xml_declaration {
        text.push_str("<?xml version=\"");
        text.push_str(definition.version.as_deref().unwrap_or("1.0"));
        text.push('"');
        if definition.encoding_explicit {
            text.push_str(" encoding=\"");
            text.push_str(&definition.encoding);
            text.push('"');
        }
        if let Some(standalone) = definition.standalone {
            text.push_str(if standalone {
                " standalone=\"yes\""
            } else {
                " standalone=\"no\""
            });
        }
        text.push_str("?>");
        text.push('\n');
    }
    let children = &document
        .node(document.root())
        .ok_or_else(|| Error::Serialization("missing result root".into()))?
        .children;
    let document_element = children.iter().copied().find(|child| {
        document
            .node(*child)
            .is_some_and(|node| matches!(node.kind, NodeKind::Element { .. }))
    });
    for (index, child) in children.iter().enumerate() {
        if Some(*child) == document_element {
            render_doctype(document, *child, definition, encoding, text)?;
        }
        serialize_node(
            document,
            *child,
            definition,
            encoding,
            text,
            RenderContext::root(),
        )?;
        if definition.method == OutputMethod::Xml
            && (definition.indent || !definition.omit_xml_declaration)
            && index + 1 < children.len()
            && document
                .node(*child)
                .is_some_and(|node| matches!(node.kind, NodeKind::Comment(_)))
        {
            text.push('\n');
        }
    }
    if definition.method != OutputMethod::Text
        && !(definition.indent_explicit && !definition.indent)
    {
        text.push('\n');
    }
    Ok(())
}

fn render_doctype(
    document: &Document,
    element: NodeId,
    definition: &OutputDefinition,
    encoding: &OutputEncoding,
    text: &mut RenderBuffer,
) -> Result<()> {
    if definition.doctype_system.is_none()
        && !(definition.method == OutputMethod::Html
            && (definition.doctype_public.is_some() || definition.version.as_deref() == Some("5")))
    {
        return Ok(());
    }
    if definition.method == OutputMethod::Xml
        && let Some(public) = &definition.doctype_public
    {
        validate_xml_public_identifier(public)?;
    }
    let Some(NodeKind::Element { name, prefix, .. }) =
        document.node(element).map(|node| &node.kind)
    else {
        return Err(Error::Serialization(
            "document element disappeared during serialization".into(),
        ));
    };
    text.push_str("<!DOCTYPE ");
    push_name(prefix.as_deref(), &name.local, encoding, text)?;
    match (&definition.doctype_public, &definition.doctype_system) {
        (Some(public), Some(system)) => {
            text.push_str(" PUBLIC ");
            push_external_identifier_literal(public, "public identifier", encoding, text)?;
            text.push(' ');
            push_external_identifier_literal(system, "system identifier", encoding, text)?;
        }
        (Some(public), None) if definition.method == OutputMethod::Html => {
            text.push_str(" PUBLIC ");
            push_external_identifier_literal(public, "public identifier", encoding, text)?;
        }
        (Some(_), None) => {}
        (None, Some(system)) => {
            text.push_str(" SYSTEM ");
            push_external_identifier_literal(system, "system identifier", encoding, text)?;
        }
        (None, None) => {}
    }
    text.push('>');
    text.push('\n');
    Ok(())
}

fn validate_xml_public_identifier(value: &str) -> Result<()> {
    if value.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | '\r'
                    | '\n'
                    | '-'
                    | '\''
                    | '('
                    | ')'
                    | '+'
                    | ','
                    | '.'
                    | '/'
                    | ':'
                    | '='
                    | '?'
                    | ';'
                    | '!'
                    | '*'
                    | '#'
                    | '@'
                    | '$'
                    | '_'
                    | '%'
            )
    }) {
        Ok(())
    } else {
        Err(Error::Serialization(
            "doctype public identifier contains a character outside XML PubidChar".into(),
        ))
    }
}

fn push_external_identifier_literal(
    value: &str,
    kind: &str,
    encoding: &OutputEncoding,
    output: &mut RenderBuffer,
) -> Result<()> {
    reject_unrepresentable_markup(value, encoding, kind)?;
    let delimiter = if !value.contains('"') {
        '"'
    } else if !value.contains('\'') {
        '\''
    } else {
        return Err(Error::Serialization(format!(
            "doctype {kind} contains both quote delimiters"
        )));
    };
    output.push(delimiter);
    output.push_str(value);
    output.push(delimiter);
    Ok(())
}

enum RenderBuffer {
    Count {
        counter: EncodingCounter,
        kind: BudgetKind,
        used: usize,
        limit: usize,
        exceeded: Option<usize>,
    },
    Text(String),
}

impl RenderBuffer {
    fn counting(counter: EncodingCounter, kind: BudgetKind, used: usize, limit: usize) -> Self {
        Self::Count {
            counter,
            kind,
            used,
            limit,
            exceeded: None,
        }
    }

    fn push_str(&mut self, value: &str) {
        match self {
            Self::Count {
                counter,
                used,
                limit,
                exceeded,
                ..
            } => {
                if exceeded.is_some() {
                    return;
                }
                counter.push_str(value);
                let actual = used.saturating_add(counter.encoded_bytes);
                if actual > *limit {
                    *exceeded = Some(actual);
                }
            }
            Self::Text(output) => output.push_str(value),
        }
    }

    fn push(&mut self, value: char) {
        match self {
            Self::Count { .. } => {
                let mut buffer = [0_u8; 4];
                self.push_str(value.encode_utf8(&mut buffer));
            }
            Self::Text(output) => output.push(value),
        }
    }

    fn push_repeated(&mut self, byte: u8, count: usize) -> Result<()> {
        const CHUNK_SIZE: usize = 64;
        let chunk = [byte; CHUNK_SIZE];
        let chunk = std::str::from_utf8(&chunk)
            .map_err(|_| Error::Serialization("non-ASCII repeated render byte".into()))?;
        let mut remaining = count;
        while remaining >= CHUNK_SIZE {
            self.push_str(chunk);
            self.ensure_within_limit()?;
            remaining -= CHUNK_SIZE;
        }
        if remaining > 0 {
            self.push_str(&chunk[..remaining]);
            self.ensure_within_limit()?;
        }
        Ok(())
    }

    fn ensure_within_limit(&self) -> Result<()> {
        if let Self::Count {
            kind,
            limit,
            exceeded: Some(actual),
            ..
        } = self
        {
            return Err(Error::Budget {
                kind: *kind,
                limit: *limit,
                actual: *actual,
            });
        }
        Ok(())
    }

    const fn len(&self) -> usize {
        match self {
            Self::Count { counter, .. } => counter.utf8_bytes,
            Self::Text(output) => output.len(),
        }
    }

    fn into_string(self) -> String {
        match self {
            Self::Text(output) => output,
            Self::Count { .. } => unreachable!("counting buffer does not contain rendered text"),
        }
    }

    fn encoded_len(&mut self) -> Result<usize> {
        match self {
            Self::Count {
                counter,
                used,
                limit,
                exceeded,
                ..
            } => {
                let encoded = counter.finish();
                let actual = used.saturating_add(encoded);
                if actual > *limit {
                    *exceeded = Some(actual);
                }
                self.ensure_within_limit()?;
                Ok(encoded)
            }
            Self::Text(output) => Ok(output.len()),
        }
    }
}

impl std::fmt::Write for RenderBuffer {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.push_str(value);
        Ok(())
    }
}

enum EncodingCounterKind {
    Utf8,
    Ascii,
    Latin1,
    Utf16,
    Other(encoding_rs::Encoder),
}

struct EncodingCounter {
    utf8_bytes: usize,
    encoded_bytes: usize,
    kind: EncodingCounterKind,
    finished: bool,
}

impl EncodingCounter {
    fn new(encoding: &OutputEncoding) -> Self {
        let kind = match encoding {
            OutputEncoding::Utf8 => EncodingCounterKind::Utf8,
            OutputEncoding::Ascii => EncodingCounterKind::Ascii,
            OutputEncoding::Latin1 => EncodingCounterKind::Latin1,
            OutputEncoding::Utf16Le | OutputEncoding::Utf16Be => EncodingCounterKind::Utf16,
            OutputEncoding::Other { encoding, .. } => {
                EncodingCounterKind::Other(encoding.new_encoder())
            }
        };
        let encoded_bytes = matches!(kind, EncodingCounterKind::Utf16)
            .then_some(2)
            .unwrap_or(0);
        Self {
            utf8_bytes: 0,
            encoded_bytes,
            kind,
            finished: false,
        }
    }

    fn push_str(&mut self, value: &str) {
        self.utf8_bytes = self.utf8_bytes.saturating_add(value.len());
        match &mut self.kind {
            EncodingCounterKind::Utf8 => {
                self.encoded_bytes = self.encoded_bytes.saturating_add(value.len())
            }
            EncodingCounterKind::Ascii | EncodingCounterKind::Latin1 => {
                self.encoded_bytes = self.encoded_bytes.saturating_add(value.chars().count());
            }
            EncodingCounterKind::Utf16 => {
                self.encoded_bytes = self
                    .encoded_bytes
                    .saturating_add(value.encode_utf16().count().saturating_mul(2));
            }
            EncodingCounterKind::Other(encoder) => {
                self.encoded_bytes = self
                    .encoded_bytes
                    .saturating_add(count_encoded(encoder, value, false));
            }
        }
    }

    fn finish(&mut self) -> usize {
        if !self.finished {
            if let EncodingCounterKind::Other(encoder) = &mut self.kind {
                self.encoded_bytes = self
                    .encoded_bytes
                    .saturating_add(count_encoded(encoder, "", true));
            }
            self.finished = true;
        }
        self.encoded_bytes
    }
}

fn count_encoded(encoder: &mut encoding_rs::Encoder, mut source: &str, last: bool) -> usize {
    let mut total = 0usize;
    let mut buffer = [0_u8; 4096];
    loop {
        let (result, read, written, _) = encoder.encode_from_utf8(source, &mut buffer, last);
        total = total.saturating_add(written);
        source = &source[read..];
        match result {
            encoding_rs::CoderResult::InputEmpty => break,
            encoding_rs::CoderResult::OutputFull => {}
        }
    }
    total
}

#[derive(Clone)]
struct RenderContext {
    depth: usize,
    parent: Option<NodeId>,
    parent_mixed: bool,
    in_scope_namespaces: Rc<Vec<(Option<String>, String)>>,
}

impl RenderContext {
    fn root() -> Self {
        Self {
            depth: 0,
            parent: None,
            parent_mixed: false,
            in_scope_namespaces: Rc::new(vec![]),
        }
    }
}

enum RenderTask {
    Node(NodeId, RenderContext),
    CdataRange {
        parent: NodeId,
        start: usize,
        end: usize,
    },
    CloseElement {
        id: NodeId,
        depth: usize,
        mixed: bool,
        parent_mixed: bool,
        has_element_child: bool,
        html_void: bool,
    },
}

fn serialize_node(
    document: &Document,
    id: NodeId,
    definition: &OutputDefinition,
    encoding: &OutputEncoding,
    output: &mut RenderBuffer,
    context: RenderContext,
) -> Result<()> {
    let mut tasks = vec![RenderTask::Node(id, context)];
    while let Some(task) = tasks.pop() {
        output.ensure_within_limit()?;
        if let RenderTask::CdataRange { parent, start, end } = task {
            push_cdata_range(
                document,
                parent,
                start,
                end,
                definition.version.as_deref().unwrap_or("1.0"),
                encoding,
                output,
            )?;
            continue;
        }
        if let RenderTask::CloseElement {
            id,
            depth,
            mixed,
            parent_mixed,
            has_element_child,
            html_void,
        } = task
        {
            if definition.indent && !mixed && !parent_mixed && has_element_child {
                output.push('\n');
                output.push_repeated(b' ', depth.saturating_mul(2))?;
            }
            if !html_void {
                let Some(NodeKind::Element { name, prefix, .. }) =
                    document.node(id).map(|node| &node.kind)
                else {
                    return Err(Error::Serialization(
                        "result element disappeared during serialization".into(),
                    ));
                };
                output.push_str("</");
                push_name(prefix.as_deref(), &name.local, encoding, output)?;
                output.push('>');
            }
            continue;
        }
        let RenderTask::Node(id, context) = task else {
            unreachable!("render task variants were handled above")
        };
        let node = document
            .node(id)
            .ok_or_else(|| Error::Serialization("invalid result node".into()))?;
        match &node.kind {
            NodeKind::Root => {
                for child in node.children.iter().rev() {
                    tasks.push(RenderTask::Node(*child, context.clone()));
                }
            }
            NodeKind::Text {
                value,
                disable_output_escaping,
            } => {
                let parent_name = context.parent.and_then(|parent| {
                    document.node(parent).and_then(|node| match &node.kind {
                        NodeKind::Element { name, .. } => Some(name),
                        _ => None,
                    })
                });
                if definition.method == OutputMethod::Text
                    || parent_name.is_some_and(|name| {
                        definition.method == OutputMethod::Html
                            && name.namespace.is_none()
                            && ["script", "style"]
                                .iter()
                                .any(|candidate| name.local.eq_ignore_ascii_case(candidate))
                    })
                {
                    if definition.method == OutputMethod::Html {
                        reject_unrepresentable_markup(value, encoding, "HTML raw text")?;
                    }
                    output.push_str(value);
                } else if *disable_output_escaping {
                    push_xml_raw_text(
                        value,
                        definition.version.as_deref().unwrap_or("1.0"),
                        encoding,
                        output,
                    );
                // XSLT 1.0 section 16.1 defines cdata-section-elements only for XML output;
                // HTML has separate escaping rules in section 16.2:
                // https://www.w3.org/TR/1999/REC-xslt-19991116#output
                } else if definition.method == OutputMethod::Xml
                    && parent_name
                        .is_some_and(|name| definition.cdata_section_elements.contains(name))
                {
                    push_cdata(
                        value,
                        definition.version.as_deref().unwrap_or("1.0"),
                        encoding,
                        output,
                    );
                } else {
                    escape_text(
                        value,
                        definition.version.as_deref().unwrap_or("1.0"),
                        encoding,
                        output,
                    );
                }
            }
            NodeKind::Comment(value) if definition.method != OutputMethod::Text => {
                reject_xml11_restricted_markup(value, definition, "comment")?;
                reject_unrepresentable_markup(value, encoding, "comment")?;
                output.push_str("<!--");
                output.push_str(value);
                output.push_str("-->");
            }
            NodeKind::ProcessingInstruction { target, value }
                if definition.method != OutputMethod::Text =>
            {
                if let Some(value) = value {
                    reject_xml11_restricted_markup(value, definition, "processing instruction")?;
                    reject_unrepresentable_markup(value, encoding, "processing instruction")?;
                }
                reject_unrepresentable_markup(target, encoding, "processing-instruction target")?;
                output.push_str("<?");
                output.push_str(target);
                if let Some(value) = value {
                    output.push(' ');
                    output.push_str(value);
                }
                output.push_str(if definition.method == OutputMethod::Html {
                    ">"
                } else {
                    "?>"
                });
            }
            NodeKind::Element { .. } if definition.method == OutputMethod::Text => {
                for child in node.children.iter().rev() {
                    tasks.push(RenderTask::Node(*child, context.clone()));
                }
            }
            NodeKind::Element {
                name,
                prefix,
                attributes,
                namespaces,
            } if definition.method != OutputMethod::Text => {
                let mixed = node.children.iter().any(|child| {
                    matches!(
                        document.node(*child).map(|child| &child.kind),
                        Some(NodeKind::Text { value, .. }) if !value.is_empty()
                    )
                });
                if definition.indent && context.depth > 0 && !context.parent_mixed {
                    output.push('\n');
                    output.push_repeated(b' ', context.depth.saturating_mul(2))?;
                }
                output.push('<');
                push_name(prefix.as_deref(), &name.local, encoding, output)?;
                let mut current_namespaces = context.in_scope_namespaces.clone();
                let inherited_default_namespace = current_namespaces
                    .iter()
                    .rev()
                    .find(|(prefix, _)| prefix.is_none())
                    .map(|(_, uri)| uri.as_str());
                let inherits_empty_default_namespace =
                    inherited_default_namespace.is_none_or(str::is_empty);
                if name.namespace.is_none()
                    && inherited_default_namespace.is_some_and(|uri| !uri.is_empty())
                    && !namespaces
                        .iter()
                        .any(|namespace| namespace.prefix.is_none() && namespace.uri.is_empty())
                {
                    output.push_str(" xmlns=\"\"");
                    let current_namespaces = Rc::make_mut(&mut current_namespaces);
                    if let Some(existing) = current_namespaces
                        .iter_mut()
                        .find(|(prefix, _)| prefix.is_none())
                    {
                        existing.1.clear();
                    } else {
                        current_namespaces.push((None, String::new()));
                    }
                }
                let element_namespace_index = prefix.as_ref().and_then(|_| {
                    namespaces.iter().position(|namespace| {
                        namespace.prefix.as_deref() == prefix.as_deref()
                            && Some(namespace.uri.as_str()) == name.namespace.as_deref()
                    })
                });
                let ordered_namespaces = element_namespace_index
                    .into_iter()
                    .map(|index| &namespaces[index])
                    .chain(
                        namespaces
                            .iter()
                            .enumerate()
                            .filter_map(|(index, namespace)| {
                                (Some(index) != element_namespace_index).then_some(namespace)
                            }),
                    );
                for namespace in ordered_namespaces {
                    if namespace.prefix.as_deref() == Some("xml")
                        && namespace.uri == "http://www.w3.org/XML/1998/namespace"
                    {
                        continue;
                    }
                    if namespace.prefix.is_none()
                        && namespace.uri.is_empty()
                        && inherits_empty_default_namespace
                    {
                        continue;
                    }
                    let binding = (namespace.prefix.clone(), namespace.uri.clone());
                    if current_namespaces
                        .iter()
                        .rev()
                        .find(|(prefix, _)| prefix == &namespace.prefix)
                        .is_some_and(|(_, uri)| uri == &namespace.uri)
                    {
                        continue;
                    }
                    output.push_str(" xmlns");
                    if let Some(prefix) = &namespace.prefix {
                        output.push(':');
                        reject_unrepresentable_markup(prefix, encoding, "namespace prefix")?;
                        output.push_str(prefix);
                    }
                    output.push_str("=\"");
                    escape_attribute(
                        &namespace.uri,
                        definition.version.as_deref().unwrap_or("1.0"),
                        encoding,
                        output,
                    );
                    output.push('"');
                    let current_namespaces = Rc::make_mut(&mut current_namespaces);
                    if let Some(existing) = current_namespaces
                        .iter_mut()
                        .find(|(prefix, _)| prefix == &namespace.prefix)
                    {
                        *existing = binding;
                    } else {
                        current_namespaces.push(binding);
                    }
                }
                for attribute in attributes {
                    output.push(' ');
                    push_name(
                        attribute.prefix.as_deref(),
                        &attribute.name.local,
                        encoding,
                        output,
                    )?;
                    if definition.method == OutputMethod::Html
                        && name.namespace.is_none()
                        && attribute.name.namespace.is_none()
                        && is_html_boolean_attribute(&name.local, &attribute.name.local)
                        && attribute.value.eq_ignore_ascii_case(&attribute.name.local)
                    {
                        continue;
                    }
                    output.push_str("=\"");
                    if definition.method == OutputMethod::Html
                        && name.namespace.is_none()
                        && attribute.name.namespace.is_none()
                        && is_html_uri_attribute(&name.local, &attribute.name.local)
                    {
                        escape_html_attribute(&escape_html_uri(&attribute.value), encoding, output);
                    } else if definition.method == OutputMethod::Html {
                        escape_html_attribute(&attribute.value, encoding, output);
                    } else {
                        escape_attribute(
                            &attribute.value,
                            definition.version.as_deref().unwrap_or("1.0"),
                            encoding,
                            output,
                        );
                    }
                    output.push('"');
                }
                if node.children.is_empty() && definition.method == OutputMethod::Xml {
                    output.push_str(
                        if name.namespace.as_deref() == Some("http://www.w3.org/1999/xhtml")
                            && definition
                                .doctype_public
                                .as_deref()
                                .is_some_and(|public| public.contains("XHTML"))
                        {
                            " />"
                        } else {
                            "/>"
                        },
                    );
                    continue;
                }
                output.push('>');
                let html_head = name.local.eq_ignore_ascii_case("head")
                    && ((definition.method == OutputMethod::Html
                        && is_html_output_namespace(name.namespace.as_deref()))
                        || (name.namespace.as_deref() == Some("http://www.w3.org/1999/xhtml")
                            && definition
                                .doctype_public
                                .as_deref()
                                .is_some_and(|public| public.contains("XHTML"))));
                if definition.inject_content_type && html_head {
                    if definition.indent {
                        output.push('\n');
                        output.push_repeated(
                            b' ',
                            context.depth.saturating_add(1).saturating_mul(2),
                        )?;
                    }
                    if definition.method == OutputMethod::Html {
                        output.push_str("<meta charset=\"");
                        escape_attribute(
                            &definition.encoding,
                            definition.version.as_deref().unwrap_or("1.0"),
                            encoding,
                            output,
                        );
                        output.push_str("\">");
                    } else {
                        output.push_str(
                            "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=",
                        );
                        escape_attribute(
                            &definition.encoding,
                            definition.version.as_deref().unwrap_or("1.0"),
                            encoding,
                            output,
                        );
                        output.push_str("\" />");
                    }
                }
                let cdata = definition.method == OutputMethod::Xml
                    && definition.cdata_section_elements.contains(name);
                let child_context = RenderContext {
                    depth: context.depth + 1,
                    parent: Some(id),
                    parent_mixed: context.parent_mixed || mixed,
                    in_scope_namespaces: current_namespaces,
                };
                let mut child_tasks = Vec::new();
                let mut index = 0usize;
                while index < node.children.len() {
                    let child = node.children[index];
                    if definition.inject_content_type
                        && html_head
                        && document.node(child).is_some_and(is_html_encoding_meta)
                    {
                        index += 1;
                        continue;
                    }
                    if cdata
                        && let Some(NodeKind::Text {
                            value: _,
                            disable_output_escaping: false,
                        }) = document.node(child).map(|node| &node.kind)
                    {
                        let start = index;
                        index += 1;
                        while let Some(next) = node.children.get(index)
                            && let Some(NodeKind::Text {
                                value: _,
                                disable_output_escaping: false,
                            }) = document.node(*next).map(|node| &node.kind)
                        {
                            index += 1;
                        }
                        child_tasks.push(RenderTask::CdataRange {
                            parent: id,
                            start,
                            end: index,
                        });
                        continue;
                    }
                    child_tasks.push(RenderTask::Node(child, child_context.clone()));
                    index += 1;
                }
                let html_void = definition.method == OutputMethod::Html
                    && name.namespace.is_none()
                    && [
                        "area", "base", "basefont", "br", "col", "frame", "hr", "img", "input",
                        "isindex", "link", "meta", "param",
                    ]
                    .iter()
                    .any(|candidate| name.local.eq_ignore_ascii_case(candidate));
                tasks.push(RenderTask::CloseElement {
                    id,
                    depth: context.depth,
                    mixed,
                    parent_mixed: context.parent_mixed,
                    has_element_child: node.children.iter().any(|child| {
                        matches!(
                            document.node(*child).map(|node| &node.kind),
                            Some(NodeKind::Element { .. })
                        )
                    }),
                    html_void,
                });
                for child in child_tasks.into_iter().rev() {
                    tasks.push(child);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn is_html_output_namespace(namespace: Option<&str>) -> bool {
    matches!(namespace, None | Some("http://www.w3.org/TR/REC-html40"))
}

fn push_cdata(value: &str, version: &str, encoding: &OutputEncoding, output: &mut RenderBuffer) {
    output.push_str("<![CDATA[");
    CdataWriter::new(version, encoding, output).write_and_finish(value);
    output.push_str("]]>");
}

fn push_cdata_range(
    document: &Document,
    parent: NodeId,
    start: usize,
    end: usize,
    version: &str,
    encoding: &OutputEncoding,
    output: &mut RenderBuffer,
) -> Result<()> {
    let children = &document
        .node(parent)
        .ok_or_else(|| Error::Serialization("CDATA parent disappeared".into()))?
        .children;
    let children = children
        .get(start..end)
        .ok_or_else(|| Error::Serialization("CDATA text range is stale".into()))?;
    output.push_str("<![CDATA[");
    let mut writer = CdataWriter::new(version, encoding, output);
    for child in children {
        let Some(NodeKind::Text {
            value,
            disable_output_escaping: false,
        }) = document.node(*child).map(|node| &node.kind)
        else {
            return Err(Error::Serialization(
                "CDATA text run changed during serialization".into(),
            ));
        };
        writer.write(value);
    }
    writer.finish();
    output.push_str("]]>");
    Ok(())
}

struct CdataWriter<'a> {
    version: &'a str,
    encoding: &'a OutputEncoding,
    output: &'a mut RenderBuffer,
    trailing_brackets: usize,
}

impl<'a> CdataWriter<'a> {
    fn new(version: &'a str, encoding: &'a OutputEncoding, output: &'a mut RenderBuffer) -> Self {
        Self {
            version,
            encoding,
            output,
            trailing_brackets: 0,
        }
    }

    fn write_and_finish(mut self, value: &str) {
        self.write(value);
        self.finish();
    }

    fn write(&mut self, value: &str) {
        let mut start = 0usize;
        for (offset, character) in value.char_indices() {
            let reference = if self.version == "1.1" && is_xml11_restricted(character) {
                Some(true)
            } else if !self.encoding.represents(character) {
                Some(false)
            } else {
                None
            };
            let Some(hexadecimal) = reference else {
                continue;
            };
            self.push_segment(&value[start..offset]);
            self.flush_trailing_brackets();
            self.output.push_str("]]>");
            if hexadecimal {
                push_hex_reference(self.output, character);
            } else {
                push_decimal_reference(self.output, character);
            }
            self.output.push_str("<![CDATA[");
            start = offset + character.len_utf8();
        }
        self.push_segment(&value[start..]);
    }

    fn finish(mut self) {
        self.flush_trailing_brackets();
    }

    fn push_segment(&mut self, value: &str) {
        let trailing_brackets = value
            .as_bytes()
            .iter()
            .rev()
            .take(2)
            .take_while(|byte| **byte == b']')
            .count();
        let body_end = value.len() - trailing_brackets;
        let body = &value[..body_end];
        if body.is_empty() {
            let total = self.trailing_brackets + trailing_brackets;
            self.push_brackets(total.saturating_sub(2));
            self.trailing_brackets = total.min(2);
            return;
        }

        let leading_brackets = body
            .as_bytes()
            .iter()
            .take_while(|byte| **byte == b']')
            .count();
        if body.as_bytes().get(leading_brackets) == Some(&b'>')
            && self.trailing_brackets + leading_brackets >= 2
        {
            let excess = self.trailing_brackets + leading_brackets - 2;
            let pending_excess = excess.min(self.trailing_brackets);
            self.push_brackets(pending_excess);
            let body_excess = excess - pending_excess;
            self.output.push_str(&body[..body_excess]);
            self.output.push_str("]]]]><![CDATA[>");
            push_cdata_segment(&body[leading_brackets + 1..], self.output);
        } else {
            self.flush_trailing_brackets();
            push_cdata_segment(body, self.output);
        }
        self.trailing_brackets = trailing_brackets;
    }

    fn flush_trailing_brackets(&mut self) {
        self.push_brackets(self.trailing_brackets);
        self.trailing_brackets = 0;
    }

    fn push_brackets(&mut self, count: usize) {
        for _ in 0..count {
            self.output.push(']');
        }
    }
}

fn push_cdata_segment(value: &str, output: &mut RenderBuffer) {
    // Preserve the two closing brackets as character data before opening a
    // new section; `]]><![CDATA[>` would silently delete them.
    let mut fragments = value.split("]]>");
    if let Some(first) = fragments.next() {
        output.push_str(first);
    }
    for fragment in fragments {
        output.push_str("]]]]><![CDATA[>");
        output.push_str(fragment);
    }
}

fn push_xml_raw_text(
    value: &str,
    version: &str,
    encoding: &OutputEncoding,
    output: &mut RenderBuffer,
) {
    for character in value.chars() {
        if version == "1.1" && is_xml11_restricted(character) {
            push_hex_reference(output, character);
        } else if !encoding.represents(character) {
            push_decimal_reference(output, character);
        } else {
            output.push(character);
        }
    }
}

fn push_hex_reference(output: &mut RenderBuffer, character: char) {
    write!(output, "&#x{:X};", u32::from(character))
        .expect("writing character reference to render buffer cannot fail");
}

fn push_decimal_reference(output: &mut RenderBuffer, character: char) {
    write!(output, "&#{};", u32::from(character))
        .expect("writing character reference to render buffer cannot fail");
}

fn reject_xml11_restricted_markup(
    value: &str,
    definition: &OutputDefinition,
    kind: &str,
) -> Result<()> {
    if definition.method == OutputMethod::Xml
        && definition.version.as_deref() == Some("1.1")
        && value.chars().any(is_xml11_restricted)
    {
        return Err(Error::Serialization(format!(
            "XML 1.1 {kind} cannot contain restricted control characters"
        )));
    }
    Ok(())
}

fn is_html_uri_attribute(element: &str, attribute: &str) -> bool {
    (attribute.eq_ignore_ascii_case("action") && element.eq_ignore_ascii_case("form"))
        || (attribute.eq_ignore_ascii_case("cite")
            && ascii_eq_any(element, &["blockquote", "q", "del", "ins"]))
        || (attribute.eq_ignore_ascii_case("href")
            && ascii_eq_any(element, &["a", "area", "link", "base"]))
        || (attribute.eq_ignore_ascii_case("longdesc")
            && ascii_eq_any(element, &["img", "frame", "iframe"]))
        || (attribute.eq_ignore_ascii_case("name") && element.eq_ignore_ascii_case("a"))
        || (attribute.eq_ignore_ascii_case("src")
            && ascii_eq_any(element, &["img", "input", "frame", "iframe", "script"]))
        || (attribute.eq_ignore_ascii_case("usemap")
            && ascii_eq_any(element, &["img", "input", "object"]))
}

fn escape_html_uri(value: &str) -> Cow<'_, str> {
    // libxslt's HTML serializer ignores leading XML whitespace in URI
    // attributes, then percent-encodes spaces in the remaining value.
    let value = value.trim_start_matches([' ', '\t', '\r', '\n']);
    if value.bytes().all(|byte| byte != b' ' && byte.is_ascii()) {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte == b' ' || !byte.is_ascii() {
            write!(&mut escaped, "%{byte:02X}").expect("writing to String cannot fail");
        } else {
            escaped.push(char::from(byte));
        }
    }
    Cow::Owned(escaped)
}

fn is_html_encoding_meta(node: &crate::Node) -> bool {
    let NodeKind::Element {
        name, attributes, ..
    } = &node.kind
    else {
        return false;
    };
    (name.namespace.is_none() || name.namespace.as_deref() == Some("http://www.w3.org/1999/xhtml"))
        && name.local.eq_ignore_ascii_case("meta")
        && attributes.iter().any(|attribute| {
            attribute.name.namespace.is_none()
                && (attribute.name.local.eq_ignore_ascii_case("charset")
                    || (attribute.name.local.eq_ignore_ascii_case("http-equiv")
                        && attribute.value.eq_ignore_ascii_case("content-type")))
        })
}

fn push_name(
    prefix: Option<&str>,
    local: &str,
    encoding: &OutputEncoding,
    output: &mut RenderBuffer,
) -> Result<()> {
    if let Some(prefix) = prefix {
        reject_unrepresentable_markup(prefix, encoding, "XML name")?;
        output.push_str(prefix);
        output.push(':');
    }
    reject_unrepresentable_markup(local, encoding, "XML name")?;
    output.push_str(local);
    Ok(())
}

fn escape_text(value: &str, version: &str, encoding: &OutputEncoding, output: &mut RenderBuffer) {
    for character in value.chars() {
        if version == "1.1" && is_xml11_restricted(character) {
            push_hex_reference(output, character);
            continue;
        } else if !encoding.represents(character) {
            push_decimal_reference(output, character);
            continue;
        }
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\r' => output.push_str("&#13;"),
            _ => output.push(character),
        }
    }
}

fn escape_attribute(
    value: &str,
    version: &str,
    encoding: &OutputEncoding,
    output: &mut RenderBuffer,
) {
    for character in value.chars() {
        if version == "1.1" && is_xml11_restricted(character) {
            push_hex_reference(output, character);
            continue;
        } else if !encoding.represents(character) {
            push_decimal_reference(output, character);
            continue;
        }
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '"' => output.push_str("&quot;"),
            '\r' => output.push_str("&#13;"),
            '\n' => output.push_str("&#10;"),
            '\t' => output.push_str("&#9;"),
            _ => output.push(character),
        }
    }
}

fn is_xml11_restricted(character: char) -> bool {
    matches!(
        u32::from(character),
        0x1..=0x8 | 0xB..=0xC | 0xE..=0x1F | 0x7F..=0x84 | 0x86..=0x9F
    )
}

fn is_html_boolean_attribute(element: &str, attribute: &str) -> bool {
    (attribute.eq_ignore_ascii_case("nohref") && element.eq_ignore_ascii_case("area"))
        || (attribute.eq_ignore_ascii_case("compact")
            && ascii_eq_any(element, &["dir", "menu", "ol", "ul", "dl"]))
        || (attribute.eq_ignore_ascii_case("noresize") && element.eq_ignore_ascii_case("frame"))
        || (attribute.eq_ignore_ascii_case("noshade") && element.eq_ignore_ascii_case("hr"))
        || (attribute.eq_ignore_ascii_case("ismap") && ascii_eq_any(element, &["img", "input"]))
        || (attribute.eq_ignore_ascii_case("checked") && element.eq_ignore_ascii_case("input"))
        || (attribute.eq_ignore_ascii_case("declare") && element.eq_ignore_ascii_case("object"))
        || (attribute.eq_ignore_ascii_case("selected") && element.eq_ignore_ascii_case("option"))
        || (attribute.eq_ignore_ascii_case("defer") && element.eq_ignore_ascii_case("script"))
        || (attribute.eq_ignore_ascii_case("multiple") && element.eq_ignore_ascii_case("select"))
        || (attribute.eq_ignore_ascii_case("nowrap") && ascii_eq_any(element, &["td", "th"]))
        || (attribute.eq_ignore_ascii_case("readonly")
            && ascii_eq_any(element, &["input", "textarea"]))
        || (attribute.eq_ignore_ascii_case("disabled")
            && ascii_eq_any(
                element,
                &[
                    "button", "input", "optgroup", "option", "select", "textarea",
                ],
            ))
}

fn ascii_eq_any(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn escape_html_attribute(value: &str, encoding: &OutputEncoding, output: &mut RenderBuffer) {
    for character in value.chars() {
        if !encoding.represents(character) {
            push_decimal_reference(output, character);
            continue;
        }
        match character {
            '&' => output.push_str("&amp;"),
            '"' => output.push_str("&quot;"),
            _ => output.push(character),
        }
    }
}

fn reject_unrepresentable_markup(value: &str, encoding: &OutputEncoding, kind: &str) -> Result<()> {
    if let Some(character) = value
        .chars()
        .find(|character| !encoding.represents(*character))
    {
        return Err(Error::Serialization(format!(
            "{kind} character `{character}` is not representable in the output encoding"
        )));
    }
    Ok(())
}

fn encode(
    value: String,
    utf8_bytes: usize,
    encoded_bytes: usize,
    encoding: &OutputEncoding,
    meter: &mut Meter,
    budget_kind: BudgetKind,
) -> Result<Vec<u8>> {
    meter.charge(budget_kind, encoded_bytes)?;
    if matches!(encoding, OutputEncoding::Utf8 | OutputEncoding::Ascii) {
        if matches!(encoding, OutputEncoding::Ascii) && !value.is_ascii() {
            return Err(Error::Serialization(
                "non-ASCII character reached the US-ASCII encoder without escaping".into(),
            ));
        }
        return Ok(value.into_bytes());
    }
    meter.charge(BudgetKind::OwnedBytes, encoded_bytes)?;
    if matches!(encoding, OutputEncoding::Latin1) {
        let mut bytes = Vec::with_capacity(encoded_bytes);
        for character in value.chars() {
            let byte = u8::try_from(u32::from(character)).map_err(|_| {
                Error::Serialization(format!(
                    "character `{character}` reached the Latin-1 encoder without escaping"
                ))
            })?;
            bytes.push(byte);
        }
        meter.release_owned_bytes(utf8_bytes);
        return Ok(bytes);
    }
    if matches!(encoding, OutputEncoding::Utf16Le) {
        let mut bytes = Vec::with_capacity(encoded_bytes);
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        meter.release_owned_bytes(utf8_bytes);
        return Ok(bytes);
    }
    if matches!(encoding, OutputEncoding::Utf16Be) {
        let mut bytes = Vec::with_capacity(encoded_bytes);
        bytes.extend_from_slice(&[0xFE, 0xFF]);
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        meter.release_owned_bytes(utf8_bytes);
        return Ok(bytes);
    }
    let OutputEncoding::Other { encoding, .. } = encoding else {
        unreachable!("all built-in output encodings returned above")
    };
    let mut encoder = encoding.new_encoder();
    let mut source = value.as_str();
    let mut bytes = Vec::with_capacity(encoded_bytes);
    let mut buffer = [0_u8; 4096];
    loop {
        let (result, read, written, _) = encoder.encode_from_utf8(source, &mut buffer, true);
        bytes.extend_from_slice(&buffer[..written]);
        source = &source[read..];
        match result {
            encoding_rs::CoderResult::InputEmpty => break,
            encoding_rs::CoderResult::OutputFull => {}
        }
    }
    meter.release_owned_bytes(utf8_bytes);
    Ok(bytes)
}

fn validate_text_encoding(value: &str, encoding: &OutputEncoding, label: &str) -> Result<()> {
    let legacy_encoding = match encoding {
        OutputEncoding::Utf8 | OutputEncoding::Utf16Le | OutputEncoding::Utf16Be => return Ok(()),
        OutputEncoding::Ascii => {
            if let Some(character) = value.chars().find(|character| !character.is_ascii()) {
                return Err(Error::Serialization(format!(
                    "text output character `{character}` is not representable in {label}"
                )));
            }
            return Ok(());
        }
        OutputEncoding::Latin1 => {
            if let Some(character) = value.chars().find(|character| u32::from(*character) > 0xff) {
                return Err(Error::Serialization(format!(
                    "text output character `{character}` is not representable in {label}"
                )));
            }
            return Ok(());
        }
        OutputEncoding::Other { encoding, .. } => *encoding,
    };
    let (_, _, had_errors) = legacy_encoding.encode(value);
    if had_errors {
        let character = value.chars().find(|character| {
            let mut bytes = [0_u8; 4];
            let encoded = character.encode_utf8(&mut bytes);
            legacy_encoding.encode(encoded).2
        });
        return Err(Error::Serialization(format!(
            "text output character `{}` is not representable in {label}",
            character.unwrap_or('\u{fffd}')
        )));
    }
    Ok(())
}

fn first_element(document: &Document) -> Option<&crate::Node> {
    document
        .node(document.root())?
        .children
        .iter()
        .filter_map(|id| document.node(*id))
        .find(|node| matches!(node.kind, NodeKind::Element { .. }))
}

fn validate_xml_characters(value: &str, version: &str) -> Result<()> {
    for character in value.chars() {
        let code = u32::from(character);
        let valid = if version == "1.1" {
            matches!(code, 0x1..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
        } else {
            crate::lexical::is_xml10_character(character)
        };
        if !valid {
            return Err(Error::Serialization(format!(
                "character U+{code:04X} is forbidden by XML {version}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        EncodingCounter, OutputDefinition, OutputEncoding, OutputMethod, RenderBuffer,
        push_cdata_range, serialize,
    };
    use crate::budget::Meter;
    use crate::{BudgetKind, Document, ExecutionBudget, NodeKind};

    #[test]
    fn counting_buffer_rejects_repeated_indentation_beyond_the_encoded_limit() {
        // Indentation is emitted without a temporary repeated String, and counting stops before
        // work can exceed the configured serialized-output ceiling.
        let mut output = RenderBuffer::counting(
            EncodingCounter::new(&OutputEncoding::Utf8),
            crate::BudgetKind::SerializedBytes,
            0,
            6,
        );
        output.push_str("<a>");
        assert!(output.push_repeated(b' ', 4).is_err());
    }

    #[test]
    fn legacy_encoding_reuses_character_representability_results() {
        let encoding = OutputEncoding::new("windows-1252").expect("encoding is registered");
        assert!(encoding.represents('€'));
        assert!(encoding.represents('€'));
        let OutputEncoding::Other { representable, .. } = encoding else {
            panic!("windows-1252 uses the cached encoding path");
        };
        assert_eq!(representable.into_inner().len(), 1);
    }

    #[test]
    fn cdata_range_preserves_terminators_split_across_text_nodes() {
        // A result tree may retain adjacent text nodes. CDATA serialization must treat their
        // concatenation as one stream so a cross-node `]]>` cannot escape into XML markup.
        let mut document = Document::parse("<out/>", None).expect("result document parses");
        let parent = document
            .nodes()
            .find_map(|(id, node)| matches!(node.kind, NodeKind::Element { .. }).then_some(id))
            .expect("result element exists");
        document.push(
            parent,
            NodeKind::Text {
                value: "left]]".into(),
                disable_output_escaping: false,
            },
            None,
        );
        document.push(
            parent,
            NodeKind::Text {
                value: "><tag/>right".into(),
                disable_output_escaping: false,
            },
            None,
        );
        let mut output = RenderBuffer::Text(String::new());
        push_cdata_range(
            &document,
            parent,
            0,
            2,
            "1.0",
            &OutputEncoding::Utf8,
            &mut output,
        )
        .expect("CDATA range serializes");

        let serialized = format!("<out>{}</out>", output.into_string());
        let reparsed = Document::parse(&serialized, None).expect("serialized CDATA reparses");
        assert_eq!(reparsed.string_value(reparsed.root()), "left]]><tag/>right");
    }

    #[test]
    fn transcoding_reserves_utf8_and_encoded_buffers_concurrently() {
        // UTF-16 allocation overlaps the rendered UTF-8 workspace; a peak-live-memory budget
        // smaller than both buffers together must reject before allocating the second buffer.
        let document = Document::parse("<root>abcdefgh</root>", None).expect("document parses");
        let definition = OutputDefinition {
            method: OutputMethod::Text,
            encoding: "UTF-16".into(),
            ..OutputDefinition::default()
        };
        let limits = ExecutionBudget {
            source_bytes: 0,
            external_documents: 0,
            recursion_depth: 1,
            xpath_evaluations: 0,
            template_applications: 0,
            sort_comparisons: 0,
            key_entries: 0,
            result_nodes: 0,
            serialized_bytes: 64,
            messages: 0,
            owned_bytes: 25,
        };
        let mut meter = Meter::new(limits, 0).expect("zero source bytes fit");
        assert!(matches!(
            serialize(&document, &definition, &mut meter),
            Err(crate::Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));

        let mut limits = limits;
        limits.owned_bytes = 26;
        let mut meter = Meter::new(limits, 0).expect("zero source bytes fit");
        let output = serialize(&document, &definition, &mut meter)
            .expect("combined UTF-8 and UTF-16 buffers fit exactly");
        assert_eq!(output.bytes.len(), 18);
        assert_eq!(
            meter
                .usage(BudgetKind::OwnedBytes)
                .expect("owned-byte usage is available")
                .0,
            18
        );
    }
}
