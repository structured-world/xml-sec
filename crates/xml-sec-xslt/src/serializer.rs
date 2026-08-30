use std::collections::HashSet;

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

#[derive(Clone, Copy)]
enum OutputEncoding {
    Unicode,
    Latin1,
    Other(&'static encoding_rs::Encoding),
}

impl OutputEncoding {
    fn new(label: &str) -> Result<Self> {
        if label.eq_ignore_ascii_case("utf-8")
            || label.eq_ignore_ascii_case("utf-16")
            || label.eq_ignore_ascii_case("utf-16le")
            || label.eq_ignore_ascii_case("utf-16be")
        {
            Ok(Self::Unicode)
        } else if label.eq_ignore_ascii_case("iso-8859-1") || label.eq_ignore_ascii_case("latin1") {
            Ok(Self::Latin1)
        } else {
            encoding_rs::Encoding::for_label(label.as_bytes())
                .map(Self::Other)
                .ok_or_else(|| Error::Serialization(format!("unsupported output encoding {label}")))
        }
    }

    fn represents(self, character: char) -> bool {
        match self {
            Self::Unicode => true,
            Self::Latin1 => u32::from(character) <= 0xff,
            Self::Other(encoding) => {
                let mut bytes = [0_u8; 4];
                !encoding.encode(character.encode_utf8(&mut bytes)).2
            }
        }
    }
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
        EncodingCounter::new("UTF-8")?,
        BudgetKind::OwnedBytes,
        used,
        limit,
    );
    render(document, &definition, OutputEncoding::Unicode, &mut counter)?;
    let bytes = counter.len();
    meter.charge(BudgetKind::OwnedBytes, bytes)?;
    let mut text = RenderBuffer::Text(String::with_capacity(bytes));
    render(document, &definition, OutputEncoding::Unicode, &mut text)?;
    Ok(text.into_string())
}

fn serialize_charged(
    document: &Document,
    definition: &OutputDefinition,
    meter: &mut Meter,
    budget_kind: BudgetKind,
) -> Result<SerializedOutput> {
    let mut definition = definition.clone();
    if !definition.method_explicit
        && first_element(document)
            .is_some_and(|node| matches!(&node.kind, NodeKind::Element { name, .. } if name.namespace.is_none() && name.local.eq_ignore_ascii_case("html")))
    {
        definition.method = OutputMethod::Html;
    }
    if definition.method == OutputMethod::Html && !definition.indent_explicit {
        definition.indent = true;
    }
    let encoding = OutputEncoding::new(&definition.encoding)?;
    let (used, limit) = meter.usage(budget_kind)?;
    let mut counter = RenderBuffer::counting(
        EncodingCounter::new(&definition.encoding)?,
        budget_kind,
        used,
        limit,
    );
    render(document, &definition, encoding, &mut counter)?;
    let text_bytes = counter.len();
    let encoded_bytes = counter.encoded_len()?;
    meter.check_additional(budget_kind, encoded_bytes)?;
    meter.charge(BudgetKind::OwnedBytes, text_bytes)?;
    let mut text = RenderBuffer::Text(String::with_capacity(text_bytes));
    render(document, &definition, encoding, &mut text)?;
    let text = text.into_string();
    if definition.method == OutputMethod::Xml {
        validate_xml_characters(&text, definition.version.as_deref().unwrap_or("1.0"))?;
    }
    if definition.method == OutputMethod::Text {
        validate_text_encoding(&text, &definition.encoding)?;
    } else {
        reject_unrepresentable_markup(&text, encoding, "serialized output")?;
    }
    let bytes = encode(&text, &definition.encoding, meter, budget_kind)?;
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
    encoding: OutputEncoding,
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
    encoding: OutputEncoding,
    text: &mut RenderBuffer,
) -> Result<()> {
    if definition.doctype_system.is_none()
        && !(definition.method == OutputMethod::Html
            && (definition.doctype_public.is_some() || definition.version.as_deref() == Some("5")))
    {
        return Ok(());
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

fn push_external_identifier_literal(
    value: &str,
    kind: &str,
    encoding: OutputEncoding,
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

enum EncodingCounterKind {
    Utf8,
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
    fn new(label: &str) -> Result<Self> {
        let kind = if label.eq_ignore_ascii_case("utf-8") {
            EncodingCounterKind::Utf8
        } else if label.eq_ignore_ascii_case("iso-8859-1") || label.eq_ignore_ascii_case("latin1") {
            EncodingCounterKind::Latin1
        } else if matches!(
            label.to_ascii_lowercase().as_str(),
            "utf-16" | "utf-16le" | "utf-16be"
        ) {
            EncodingCounterKind::Utf16
        } else {
            let encoding = encoding_rs::Encoding::for_label(label.as_bytes()).ok_or_else(|| {
                Error::Serialization(format!("unsupported output encoding {label}"))
            })?;
            EncodingCounterKind::Other(encoding.new_encoder())
        };
        let encoded_bytes = matches!(kind, EncodingCounterKind::Utf16)
            .then_some(2)
            .unwrap_or(0);
        Ok(Self {
            utf8_bytes: 0,
            encoded_bytes,
            kind,
            finished: false,
        })
    }

    fn push_str(&mut self, value: &str) {
        self.utf8_bytes = self.utf8_bytes.saturating_add(value.len());
        match &mut self.kind {
            EncodingCounterKind::Utf8 => {
                self.encoded_bytes = self.encoded_bytes.saturating_add(value.len())
            }
            EncodingCounterKind::Latin1 => {
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
    parent_name: Option<crate::ExpandedName>,
    parent_mixed: bool,
    in_scope_namespaces: Vec<(Option<String>, String)>,
}

impl RenderContext {
    fn root() -> Self {
        Self {
            depth: 0,
            parent_name: None,
            parent_mixed: false,
            in_scope_namespaces: vec![],
        }
    }
}

enum RenderTask {
    Node(NodeId, RenderContext),
    Cdata(String),
    CloseElement {
        name: crate::ExpandedName,
        prefix: Option<String>,
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
    encoding: OutputEncoding,
    output: &mut RenderBuffer,
    context: RenderContext,
) -> Result<()> {
    let mut tasks = vec![RenderTask::Node(id, context)];
    while let Some(task) = tasks.pop() {
        output.ensure_within_limit()?;
        if let RenderTask::Cdata(value) = task {
            push_cdata(
                &value,
                definition.version.as_deref().unwrap_or("1.0"),
                encoding,
                output,
            );
            continue;
        }
        if let RenderTask::CloseElement {
            name,
            prefix,
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
                if definition.method == OutputMethod::Text
                    || context.parent_name.as_ref().is_some_and(|name| {
                        definition.method == OutputMethod::Html
                            && name.namespace.is_none()
                            && matches!(
                                name.local.to_ascii_lowercase().as_str(),
                                "script" | "style"
                            )
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
                } else if context
                    .parent_name
                    .as_ref()
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
                    if let Some(existing) = current_namespaces
                        .iter_mut()
                        .find(|(prefix, _)| prefix.is_none())
                    {
                        existing.1.clear();
                    } else {
                        current_namespaces.push((None, String::new()));
                    }
                }
                let mut ordered_namespaces = namespaces.iter().collect::<Vec<_>>();
                if prefix.is_some()
                    && let Some(index) = ordered_namespaces.iter().position(|namespace| {
                        namespace.prefix.as_deref() == prefix.as_deref()
                            && Some(namespace.uri.as_str()) == name.namespace.as_deref()
                    })
                {
                    let element_namespace = ordered_namespaces.remove(index);
                    ordered_namespaces.insert(0, element_namespace);
                }
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
                    && (definition.method == OutputMethod::Html
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
                let cdata = definition.cdata_section_elements.contains(name);
                let child_context = RenderContext {
                    depth: context.depth + 1,
                    parent_name: Some(name.clone()),
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
                        && let Some(NodeKind::Text { value, .. }) =
                            document.node(child).map(|node| &node.kind)
                    {
                        let mut combined = value.clone();
                        index += 1;
                        while let Some(next) = node.children.get(index)
                            && let Some(NodeKind::Text { value, .. }) =
                                document.node(*next).map(|node| &node.kind)
                        {
                            combined.push_str(value);
                            index += 1;
                        }
                        child_tasks.push(RenderTask::Cdata(combined));
                        continue;
                    }
                    child_tasks.push(RenderTask::Node(child, child_context.clone()));
                    index += 1;
                }
                let html_void = definition.method == OutputMethod::Html
                    && name.namespace.is_none()
                    && matches!(
                        name.local.to_ascii_lowercase().as_str(),
                        "area"
                            | "base"
                            | "basefont"
                            | "br"
                            | "col"
                            | "frame"
                            | "hr"
                            | "img"
                            | "input"
                            | "isindex"
                            | "link"
                            | "meta"
                            | "param"
                    );
                tasks.push(RenderTask::CloseElement {
                    name: name.clone(),
                    prefix: prefix.clone(),
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

fn push_cdata(value: &str, version: &str, encoding: OutputEncoding, output: &mut RenderBuffer) {
    output.push_str("<![CDATA[");
    let mut start = 0usize;
    for (offset, character) in value.char_indices() {
        if version == "1.1" && is_xml11_restricted(character) {
            push_cdata_segment(&value[start..offset], output);
            output.push_str("]]>");
            output.push_str(&format!("&#x{:X};", u32::from(character)));
            output.push_str("<![CDATA[");
            start = offset + character.len_utf8();
        } else if !encoding.represents(character) {
            push_cdata_segment(&value[start..offset], output);
            output.push_str("]]>");
            output.push_str(&format!("&#{};", u32::from(character)));
            output.push_str("<![CDATA[");
            start = offset + character.len_utf8();
        }
    }
    push_cdata_segment(&value[start..], output);
    output.push_str("]]>");
}

fn push_cdata_segment(value: &str, output: &mut RenderBuffer) {
    // Preserve the two closing brackets as character data before opening a
    // new section; `]]><![CDATA[>` would silently delete them.
    output.push_str(&value.replace("]]>", "]]]]><![CDATA[>"));
}

fn push_xml_raw_text(
    value: &str,
    version: &str,
    encoding: OutputEncoding,
    output: &mut RenderBuffer,
) {
    for character in value.chars() {
        if version == "1.1" && is_xml11_restricted(character) {
            output.push_str(&format!("&#x{:X};", u32::from(character)));
        } else if !encoding.represents(character) {
            output.push_str(&format!("&#{};", u32::from(character)));
        } else {
            output.push(character);
        }
    }
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
    let element = element.to_ascii_lowercase();
    let attribute = attribute.to_ascii_lowercase();
    matches!(
        (element.as_str(), attribute.as_str()),
        ("form", "action")
            | ("blockquote" | "q" | "del" | "ins", "cite")
            | ("a" | "area" | "link" | "base", "href")
            | ("img" | "frame" | "iframe", "longdesc")
            | ("a", "name")
            | ("img" | "input" | "frame" | "iframe" | "script", "src")
            | ("img" | "input" | "object", "usemap")
    )
}

fn escape_html_uri(value: &str) -> String {
    use std::fmt::Write as _;

    // libxslt's HTML serializer ignores leading XML whitespace in URI
    // attributes, then percent-encodes spaces in the remaining value.
    let value = value.trim_start_matches([' ', '\t', '\r', '\n']);
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte == b' ' || !byte.is_ascii() {
            write!(&mut escaped, "%{byte:02X}").expect("writing to String cannot fail");
        } else {
            escaped.push(char::from(byte));
        }
    }
    escaped
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
    encoding: OutputEncoding,
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

fn escape_text(value: &str, version: &str, encoding: OutputEncoding, output: &mut RenderBuffer) {
    for character in value.chars() {
        if version == "1.1" && is_xml11_restricted(character) {
            output.push_str(&format!("&#x{:X};", u32::from(character)));
            continue;
        } else if !encoding.represents(character) {
            output.push_str(&format!("&#{};", u32::from(character)));
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
    encoding: OutputEncoding,
    output: &mut RenderBuffer,
) {
    for character in value.chars() {
        if version == "1.1" && is_xml11_restricted(character) {
            output.push_str(&format!("&#x{:X};", u32::from(character)));
            continue;
        } else if !encoding.represents(character) {
            output.push_str(&format!("&#{};", u32::from(character)));
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
    let element = element.to_ascii_lowercase();
    let attribute = attribute.to_ascii_lowercase();
    matches!(
        (element.as_str(), attribute.as_str()),
        ("area", "nohref")
            | ("button", "disabled")
            | ("dir" | "menu" | "ol" | "ul", "compact")
            | ("dl", "compact")
            | ("frame", "noresize")
            | ("hr", "noshade")
            | ("img" | "input", "ismap")
            | ("input", "checked" | "disabled" | "readonly")
            | ("object", "declare")
            | ("optgroup", "disabled")
            | ("option", "selected" | "disabled")
            | ("script", "defer")
            | ("select", "multiple" | "disabled")
            | ("td" | "th", "nowrap")
            | ("textarea", "disabled" | "readonly")
    )
}

fn escape_html_attribute(value: &str, encoding: OutputEncoding, output: &mut RenderBuffer) {
    for character in value.chars() {
        if !encoding.represents(character) {
            output.push_str(&format!("&#{};", u32::from(character)));
            continue;
        }
        match character {
            '&' => output.push_str("&amp;"),
            '"' => output.push_str("&quot;"),
            _ => output.push(character),
        }
    }
}

fn reject_unrepresentable_markup(value: &str, encoding: OutputEncoding, kind: &str) -> Result<()> {
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

fn encode(value: &str, label: &str, meter: &mut Meter, budget_kind: BudgetKind) -> Result<Vec<u8>> {
    if label.eq_ignore_ascii_case("utf-8") {
        meter.charge(budget_kind, value.len())?;
        return Ok(value.as_bytes().to_vec());
    }
    if label.eq_ignore_ascii_case("iso-8859-1") || label.eq_ignore_ascii_case("latin1") {
        let mut bytes = Vec::with_capacity(value.chars().count());
        for character in value.chars() {
            let byte = u8::try_from(u32::from(character)).map_err(|_| {
                Error::Serialization(format!(
                    "character `{character}` reached the Latin-1 encoder without escaping"
                ))
            })?;
            meter.charge(budget_kind, 1)?;
            bytes.push(byte);
        }
        return Ok(bytes);
    }
    if label.eq_ignore_ascii_case("utf-16") || label.eq_ignore_ascii_case("utf-16le") {
        let units = value.encode_utf16().count();
        let length = units
            .checked_mul(2)
            .and_then(|length| length.checked_add(2))
            .unwrap_or(usize::MAX);
        meter.charge(budget_kind, length)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        return Ok(bytes);
    }
    if label.eq_ignore_ascii_case("utf-16be") {
        let units = value.encode_utf16().count();
        let length = units
            .checked_mul(2)
            .and_then(|length| length.checked_add(2))
            .unwrap_or(usize::MAX);
        meter.charge(budget_kind, length)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(&[0xFE, 0xFF]);
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        return Ok(bytes);
    }
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes())
        .ok_or_else(|| Error::Serialization(format!("unsupported output encoding {label}")))?;
    let mut encoder = encoding.new_encoder();
    let mut source = value;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let (result, read, written, _) = encoder.encode_from_utf8(source, &mut buffer, true);
        meter.charge(budget_kind, written)?;
        bytes.extend_from_slice(&buffer[..written]);
        source = &source[read..];
        match result {
            encoding_rs::CoderResult::InputEmpty => break,
            encoding_rs::CoderResult::OutputFull => {}
        }
    }
    Ok(bytes)
}

fn validate_text_encoding(value: &str, label: &str) -> Result<()> {
    if label.eq_ignore_ascii_case("utf-8")
        || label.eq_ignore_ascii_case("utf-16")
        || label.eq_ignore_ascii_case("utf-16le")
        || label.eq_ignore_ascii_case("utf-16be")
    {
        return Ok(());
    }
    if label.eq_ignore_ascii_case("iso-8859-1") || label.eq_ignore_ascii_case("latin1") {
        if let Some(character) = value.chars().find(|character| u32::from(*character) > 0xff) {
            return Err(Error::Serialization(format!(
                "text output character `{character}` is not representable in {label}"
            )));
        }
        return Ok(());
    }
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes())
        .ok_or_else(|| Error::Serialization(format!("unsupported output encoding {label}")))?;
    let (_, _, had_errors) = encoding.encode(value);
    if had_errors {
        let character = value.chars().find(|character| {
            let mut bytes = [0_u8; 4];
            let encoded = character.encode_utf8(&mut bytes);
            encoding.encode(encoded).2
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
            matches!(code, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
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
    use super::{EncodingCounter, RenderBuffer};

    #[test]
    fn counting_buffer_rejects_repeated_indentation_beyond_the_encoded_limit() {
        // Indentation is emitted without a temporary repeated String, and counting stops before
        // work can exceed the configured serialized-output ceiling.
        let mut output = RenderBuffer::counting(
            EncodingCounter::new("UTF-8").expect("UTF-8 output encoding is supported"),
            crate::BudgetKind::SerializedBytes,
            0,
            6,
        );
        output.push_str("<a>");
        assert!(output.push_repeated(b' ', 4).is_err());
    }
}
