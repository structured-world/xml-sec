//! Core XML 1.0 parser state machine.
//!
//! Implements a hand-rolled recursive descent parser for XML 1.0 (Fifth Edition).
//! See <https://www.w3.org/TR/xml/> for the specification.

use crate::xml::dom::storage::names::{NameStorage, Names};
use crate::xml::dom::storage::{Native, Storage, Values};
use crate::xml::dom::{PositionRecorder, SourceKind, SourceNode};

use crate::parser_xmloxide::error::{ErrorSeverity, ParseDiagnostic};
use crate::parser_xmloxide::tree::{Attribute, Document, NodeId, NodeKind};
use crate::parser_xmloxide::validation::dtd::{
    AttributeDecl, AttributeType, EntityKind, parse_dtd_in, serialize_dtd_in,
};

use super::ParseOptions;
use super::input::{
    NamespaceResolver, ParserInput, XML_NAMESPACE, XMLNS_NAMESPACE, find_invalid_xml_char,
    may_contain_invalid_xml_chars, parse_cdata_content, parse_comment_content, parse_pi_content,
    parse_xml_decl, split_name,
};

type ParseError<S = Native> = crate::parser_xmloxide::error::ParseError<
    <S as Storage>::FrozenText,
    <S as Storage>::Values<ParseDiagnostic<<S as Storage>::FrozenText>>,
>;

struct QualifiedName<'a> {
    prefix: Option<&'a str>,
    local: &'a str,
}

impl core::fmt::Display for QualifiedName<'_> {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(prefix) = self.prefix {
            write!(output, "{prefix}:")?;
        }
        output.write_str(self.local)
    }
}

fn admit_attribute_comparison<S: Storage>(
    storage: S,
    left: &Attribute<S>,
    right: &Attribute<S>,
) -> Result<(), crate::xml::dom::ParseError> {
    storage.charge(left.name.len() + right.name.len())?;
    storage.charge(
        left.prefix.as_deref().map_or(0, str::len) + right.prefix.as_deref().map_or(0, str::len),
    )?;
    storage.charge(
        left.namespace.as_deref().map_or(0, str::len)
            + right.namespace.as_deref().map_or(0, str::len),
    )
}

/// Default maximum amplification factor for entity/attribute expansion.
///
/// libxml2 uses a factor of 5 — if the expanded output exceeds 5x the input
/// size due to default attribute application or entity expansion, the document
/// is rejected as a potential denial-of-service attack.
const DEFAULT_MAX_AMPLIFICATION: usize = 5;

/// Maximum nesting depth of general entity expansion in content.
///
/// Bounds the recursion when an entity's replacement text references other
/// entities (XML 1.0 §4.4 "Included"). Recursion is already rejected by the
/// DTD parser (WFC: No Recursion), so this is defense-in-depth for
/// resolver-provided external entities and stack safety.
const MAX_ENTITY_DEPTH: u32 = 32;

/// A parsed document with the source ranges of its nodes.
pub(crate) type Located<S> = (Document<S>, <S as Storage>::Values<SourceNode>);
type Finished<S> = (Document<S>, Option<PositionRecorder<S>>);

/// The core XML parser.
pub(crate) struct XmlParser<'a, S: NameStorage = Native> {
    /// Shared low-level input state (position, peek, advance, name parsing, etc.).
    input: ParserInput<'a, S>,
    /// The document being built.
    doc: Document<S>,
    /// Parser options.
    options: ParseOptions,
    /// Namespace resolver managing the scope stack.
    ns: NamespaceResolver<S>,
    /// Tokenized attribute names indexed by their element name. The complete
    /// declarations remain in `attr_defaults`; reads borrow both lookup keys.
    attr_types: S::Names<S::Text, S::Names<S::Text, ()>>,
    /// DTD attribute default value declarations, keyed by element name.
    /// Used for applying default/fixed attributes from ATTLIST.
    attr_defaults: S::Names<S::Text, S::Values<AttributeDecl<S>>>,
    storage: S,
    /// Total input size in bytes, used for amplification factor checking.
    input_size: usize,
    /// Running total of bytes added through default attribute expansion.
    expansion_size: usize,
    /// Current nesting depth of general entity expansion (0 = document level).
    entity_depth: u32,
    /// Source ranges of the nodes, when the caller has no lexical sidecar.
    positions: Option<PositionRecorder<S>>,
}

impl<'a> XmlParser<'a> {
    pub fn new(input: &'a str, options: &ParseOptions) -> Result<Self, ParseError> {
        let mut parser = Self::with_storage(input, options, Native)?;
        parser
            .input
            .set_entity_resolver(options.entity_resolver.clone());
        Ok(parser)
    }
}

impl<'a, S: NameStorage> XmlParser<'a, S> {
    pub(crate) fn with_storage(
        input: &'a str,
        options: &ParseOptions,
        storage: S,
    ) -> Result<Self, ParseError<S>> {
        let mut pi = ParserInput::with_storage(input, storage)?;
        pi.set_recover(options.recover);
        pi.set_max_depth(options.max_depth);
        pi.set_max_name_length(options.max_name_length);
        pi.set_max_entity_expansions(options.max_entity_expansions);

        // Pre-size the node arena — roughly 1 node per 30 bytes of input.
        let estimated_nodes = (input.len() / 30).max(64);
        Ok(Self {
            input: pi,
            doc: Document::try_with_storage(estimated_nodes, storage)?,
            options: options.clone(),
            ns: NamespaceResolver::with_storage(storage)?,
            attr_types: storage.names(),
            attr_defaults: storage.names(),
            storage,
            input_size: input.len(),
            expansion_size: 0,
            entity_depth: 0,
            positions: None,
        })
    }

    /// Main parse entry point. Parses the entire document.
    pub fn parse(self) -> Result<Document<S>, ParseError<S>> {
        self.parse_tree().map(|(document, _)| document)
    }

    /// Parses a document without a DOCTYPE and returns its nodes' source ranges,
    /// in the order the projector visits them.
    pub(crate) fn parse_recording_positions(mut self) -> Result<Located<S>, ParseError<S>> {
        self.positions = Some(PositionRecorder::new(self.storage)?);
        let (document, positions) = self.parse_tree()?;
        let positions = positions.expect("recording was enabled above");
        Ok((document, positions.into_nodes()))
    }

    fn parse_tree(mut self) -> Result<Finished<S>, ParseError<S>> {
        // Parse optional XML declaration — must be at the very start of the
        // document with no leading whitespace (XML 1.0 §2.8).
        if self.input.looking_at(b"<?xml ")
            || self.input.looking_at(b"<?xml\t")
            || self.input.looking_at(b"<?xml\r")
        {
            self.parse_xml_declaration()?;
            // Skip whitespace immediately after the XML declaration — the
            // serializer always emits its own newline after the declaration.
            self.input.skip_whitespace()?;
        } else if !self.input.at_end() {
            // If there's no XML declaration, skip any leading whitespace.
            // Leading whitespace before a non-declaration is tolerated
            // (it will be handled as misc content).
            let had_leading_ws = self.input.skip_whitespace()?;
            // But if the whitespace was hiding an XML declaration, that's an error
            if had_leading_ws
                && (self.input.looking_at(b"<?xml ")
                    || self.input.looking_at(b"<?xml\t")
                    || self.input.looking_at(b"<?xml\r"))
            {
                return Err(self
                    .input
                    .fatal("XML declaration must be at the start of the document"));
            }
        }

        // Parse prolog content (comments, PIs, whitespace before root element)
        self.parse_misc(self.doc.root())?;

        // Parse optional DOCTYPE declaration
        if self.input.looking_at(b"<!DOCTYPE") || self.input.looking_at(b"<!doctype") {
            self.parse_doctype(self.doc.root())?;
            self.parse_misc(self.doc.root())?; // more misc after doctype
        }

        // Parse root element (required by XML 1.0 §2.1)
        if self.input.peek() == Some(b'<')
            && self
                .input
                .peek_at(1)
                .is_some_and(|b| b != b'!' && b != b'?')
        {
            self.parse_element(self.doc.root())?;
        } else if self.options.recover {
            self.input
                .push_diagnostic(ErrorSeverity::Error, "missing root element")?;
        } else {
            return Err(self.input.fatal("missing root element"));
        }

        // Parse trailing content (comments, PIs after root element)
        self.parse_misc(self.doc.root())?;

        self.input.skip_whitespace()?;
        if !self.input.at_end() && !self.options.recover {
            return Err(self.input.fatal("content after document element"));
        }

        // Sync diagnostics from input to document before returning.
        self.doc.diagnostics = self.input.diagnostics;

        // Parsing is complete and the parser is consumed. Moving the arena
        // avoids Document::default allocating a replacement tree on return.
        Ok((self.doc, self.positions))
    }

    // --- XML Declaration ---
    // See XML 1.0 §2.8: [23] XMLDecl

    fn parse_xml_declaration(&mut self) -> Result<(), ParseError<S>> {
        let decl = parse_xml_decl(&mut self.input)?;
        // XML 1.0 §2.8 allows a later 1.x only to a processor implementing that
        // version's character model. This parser implements XML 1.0.
        if decl.version != "1.0" {
            return Err(self.input.fatal("unsupported XML version"));
        }
        self.doc.version = Some(self.storage.text(decl.version)?);
        self.doc.encoding = self.storage.optional_text(decl.encoding)?;
        self.doc.standalone = decl.standalone;
        Ok(())
    }

    // --- Misc (comments, PIs, whitespace) ---

    fn parse_misc(&mut self, parent: NodeId) -> Result<(), ParseError<S>> {
        loop {
            // Preserve document-level whitespace as text nodes (matches libxml2).
            // libxml2 normalizes prolog/epilog whitespace to a single `\n`
            // regardless of how many blank lines appear in the source.
            let ws = self.input.consume_whitespace()?;
            if !ws.is_empty() {
                let ws_node = self.doc.try_create_node(NodeKind::Text {
                    content: self.storage.text("\n")?,
                })?;
                self.doc.append_child(parent, ws_node);
            }
            if self.input.at_end() {
                break;
            }
            if self.input.looking_at(b"<!--") {
                self.parse_comment(parent)?;
            } else if self.input.looking_at(b"<?") {
                self.parse_processing_instruction(parent)?;
            } else {
                break;
            }
        }
        Ok(())
    }

    // --- DOCTYPE Declaration ---
    // See XML 1.0 §2.8: [28] doctypedecl

    fn scan_internal_subset(&mut self) -> Result<&'a str, ParseError<S>> {
        self.input.advance(1)?;
        let start = self.input.pos();
        // Quoted values and comments do not contribute bracket delimiters.
        let mut depth: u32 = 1;
        while !self.input.at_end() && depth > 0 {
            if self.input.looking_at(b"<!--") {
                self.input.advance(4)?;
                while !self.input.at_end() && !self.input.looking_at(b"-->") {
                    self.input.advance(1)?;
                }
                if !self.input.at_end() {
                    self.input.advance(3)?;
                }
            } else if let Some(quote @ (b'"' | b'\'')) = self.input.peek() {
                self.input.advance(1)?;
                while !self.input.at_end() && self.input.peek() != Some(quote) {
                    self.input.advance(1)?;
                }
                if !self.input.at_end() {
                    self.input.advance(1)?;
                }
            } else if self.input.peek() == Some(b'[') {
                depth += 1;
                self.input.advance(1)?;
            } else if self.input.peek() == Some(b']') {
                depth -= 1;
                self.input.advance(1)?;
            } else {
                self.input.advance(1)?;
            }
        }
        if depth > 0 {
            return Err(self
                .input
                .fatal("unexpected end of input in internal subset"));
        }
        let end = self.input.pos() - 1;
        core::str::from_utf8(self.input.slice(start, end))
            .map_err(|_| self.input.fatal("invalid UTF-8 in internal subset"))
    }

    fn parse_doctype(&mut self, parent: NodeId) -> Result<(), ParseError<S>> {
        // Consume <!DOCTYPE (case-insensitive match already checked by caller)
        self.input.expect_str(b"<!DOCTYPE")?;
        self.input.skip_whitespace_required()?;

        // Read the root element name
        let name = self.input.parse_name()?;

        self.input.skip_whitespace()?;

        // Check for external ID: SYSTEM or PUBLIC
        let mut system_id = None;
        let mut public_id = None;

        if self.input.looking_at(b"SYSTEM") {
            self.input.expect_str(b"SYSTEM")?;
            self.input.skip_whitespace_required()?;
            system_id = Some(self.input.parse_quoted_value()?);
            self.input.skip_whitespace()?;
        } else if self.input.looking_at(b"PUBLIC") {
            self.input.expect_str(b"PUBLIC")?;
            self.input.skip_whitespace_required()?;
            let pid = self.input.parse_quoted_value()?;
            // Validate public ID characters per XML 1.0 §2.3 [13].
            self.input.validate_pubid(pid)?;
            public_id = Some(pid);
            self.input.skip_whitespace_required()?;
            system_id = Some(self.input.parse_quoted_value()?);
            self.input.skip_whitespace()?;
        }

        // Flag whether there's an external DTD subset. Per XML 1.0 §4.1 WFC:
        // Entity Declared, undeclared entities are not WF errors when the
        // document references an unread external DTD subset.
        if system_id.is_some() || public_id.is_some() {
            self.input.has_external_dtd = true;
        }

        // Parse optional internal subset: [ ... ]
        let mut internal_subset = None;
        if self.input.peek() == Some(b'[') {
            let subset_text = self.scan_internal_subset()?;

            {
                // Detect parameter entity references in the internal subset.
                // Per XML 1.0 §4.1 WFC: Entity Declared, their presence
                // means undeclared general entities are not WF errors.
                self.storage.charge(subset_text.len())?;
                if subset_text.contains('%') {
                    self.input.has_pe_references = true;
                }

                match parse_dtd_in(subset_text, self.storage) {
                    Ok(dtd) => {
                        // Serialize while the ordered declarations are intact,
                        // then move runtime tables instead of cloning payloads.
                        let serialized = serialize_dtd_in(&dtd, self.storage)?;
                        if !serialized.is_empty() {
                            internal_subset = Some(serialized);
                        }
                        // Runtime resolution uses the declaration table's
                        // exact owning layout: no second table or rehash.
                        self.input.entity_map = dtd.entities;

                        // Wire attribute type declarations for namespace
                        // URI normalization (XML 1.0 §3.3.3).
                        for (element_name, attrs) in dtd.attributes.entries(self.storage)? {
                            let mut tokenized = self.storage.names();
                            for attr_decl in &**attrs {
                                self.storage.charge(1)?;
                                if !matches!(attr_decl.attribute_type, AttributeType::CData) {
                                    tokenized.insert(
                                        self.storage.text(&attr_decl.attribute_name)?,
                                        (),
                                    )?;
                                }
                            }
                            if tokenized.len() != 0 {
                                self.attr_types
                                    .insert(self.storage.text(element_name.as_ref())?, tokenized)?;
                            }
                        }

                        // There is one document type declaration. These are
                        // already grouped, ordered declaration lists.
                        self.attr_defaults = dtd.attributes;
                    }
                    Err(e) => {
                        if matches!(e, ParseError::<S>::Resource(_)) {
                            return Err(e);
                        }
                        let message = e.message().expect("resource refusal returned above");
                        if self.options.recover {
                            self.input.push_diagnostic(
                                ErrorSeverity::Warning,
                                format_args!("error parsing DTD internal subset: {message}"),
                            )?;
                        } else {
                            return Err(self
                                .input
                                .fatal(format_args!("error in DTD internal subset: {message}")));
                        }
                    }
                }
            }

            self.input.skip_whitespace()?;
        }

        self.input.expect_byte(b'>')?;

        let doctype_id = self.doc.try_create_node(NodeKind::DocumentType {
            name: self.storage.text(name)?,
            system_id: self.storage.optional_text(system_id)?,
            public_id: self.storage.optional_text(public_id)?,
            internal_subset,
        })?;
        self.doc.append_child(parent, doctype_id);
        Ok(())
    }

    // --- Elements ---
    // See XML 1.0 §3.1: [40] STag, [42] ETag, [44] EmptyElemTag

    fn parse_element(&mut self, parent: NodeId) -> Result<NodeId, ParseError<S>> {
        let (root, open) = self.parse_element_start(parent)?;
        let mut pending = self.storage.values(0)?;
        if let Some(scope) = open {
            pending.push((root, scope))?;
        }
        while let Some(&(element, scope)) = pending.last() {
            self.storage.charge(1)?;
            if self.input.looking_at(b"</") {
                self.parse_element_end(element, scope)?;
                pending.pop();
            } else if self.input.at_end() {
                return Err(self
                    .input
                    .fatal("unexpected end of input in element content"));
            } else if self.input.looking_at(b"<![CDATA[") {
                self.parse_cdata(element)?;
            } else if self.input.looking_at(b"<!--") {
                self.parse_comment(element)?;
            } else if self.input.looking_at(b"<?") {
                self.parse_processing_instruction(element)?;
            } else if self.input.peek() == Some(b'<') {
                let (child, open) = self.parse_element_start(element)?;
                if let Some(scope) = open {
                    pending.push((child, scope))?;
                }
            } else {
                self.parse_char_data(element)?;
            }
        }
        Ok(root)
    }

    fn check_attribute_spellings(
        &mut self,
        attributes: &[Attribute<S>],
    ) -> Result<(), ParseError<S>> {
        // XML 1.0 §3.1 WFC: Unique Att Spec; retain the first diagnostic.
        if attributes.len() >= 2 {
            'outer: for i in 1..attributes.len() {
                for j in 0..i {
                    admit_attribute_comparison(self.storage, &attributes[i], &attributes[j])?;
                    if attributes[i].name.as_ref() == attributes[j].name.as_ref()
                        && attributes[i].prefix.as_deref() == attributes[j].prefix.as_deref()
                    {
                        let full_name = QualifiedName {
                            prefix: attributes[i].prefix.as_deref(),
                            local: &attributes[i].name,
                        };
                        if self.options.recover {
                            self.input.push_diagnostic(
                                ErrorSeverity::Error,
                                format_args!("duplicate attribute: '{full_name}'"),
                            )?;
                        } else {
                            return Err(self
                                .input
                                .fatal(format_args!("duplicate attribute: '{full_name}'")));
                        }
                        break 'outer;
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_attribute_defaults(
        &mut self,
        name: &str,
        attributes: &mut S::Values<Attribute<S>>,
    ) -> Result<(), ParseError<S>> {
        // XML 1.0 §3.3.2 requires both FIXED and ordinary defaults when absent.
        // Namespace declarations retain their existing leading insertion order.
        if let Some(defaults) = if self.attr_defaults.len() == 0 {
            None
        } else {
            self.attr_defaults.get(name, self.storage)?
        } {
            let mut insert_pos = 0;
            for attr_decl in &**defaults {
                self.storage.charge(1)?;
                let default_value = match &attr_decl.default {
                    crate::parser_xmloxide::validation::dtd::AttributeDefault::Fixed(v)
                    | crate::parser_xmloxide::validation::dtd::AttributeDefault::Default(v) => {
                        Some(v.as_ref())
                    }
                    _ => None,
                };
                if let Some(value) = default_value {
                    let attr_name = &attr_decl.attribute_name;
                    let (decl_pfx, decl_local) = split_name(attr_name);
                    let mut already_present = false;
                    for attribute in &**attributes {
                        self.storage
                            .charge(attribute.name.len() + decl_local.len())?;
                        if attribute.name.as_ref() == decl_local
                            && attribute.prefix.as_deref() == decl_pfx
                        {
                            already_present = true;
                            break;
                        }
                    }
                    if !already_present {
                        self.expansion_size += attr_name.len() + value.len();
                        let (decl_prefix, decl_local) = split_name(attr_name);
                        let attr = Attribute {
                            name: self.storage.text(decl_local)?,
                            value: self.storage.text(value)?,
                            prefix: self.storage.optional_text(decl_prefix)?,
                            namespace: None,
                            raw_value: None,
                        };
                        if attr_name.as_ref() == "xmlns" || attr_name.starts_with("xmlns:") {
                            self.storage.charge(attributes.len() - insert_pos)?;
                            attributes.push(attr)?;
                            attributes[insert_pos..].rotate_right(1);
                            insert_pos += 1;
                        } else {
                            attributes.push(attr)?;
                        }
                    }
                }
            }
            if self.expansion_size > self.input_size.saturating_mul(DEFAULT_MAX_AMPLIFICATION) {
                return Err(self
                    .input
                    .fatal("maximum entity amplification factor exceeded"));
            }
        }
        Ok(())
    }

    fn check_element_qname(
        &mut self,
        prefix: Option<&str>,
        local_name: &str,
    ) -> Result<(), ParseError<S>> {
        if prefix.is_some() && local_name.contains(':') {
            let msg = "QName contains multiple colons";
            if self.options.recover {
                self.input.push_diagnostic(ErrorSeverity::Error, msg)?;
            } else {
                return Err(self.input.fatal(msg));
            }
        }
        // Namespaces in XML 1.0 §3 reserves xmlns for attribute declarations.
        if prefix == Some("xmlns") {
            if self.options.recover {
                self.input.push_diagnostic(
                    ErrorSeverity::Error,
                    "elements must not have the prefix 'xmlns'",
                )?;
            } else {
                return Err(self
                    .input
                    .fatal("elements must not have the prefix 'xmlns'"));
            }
        }
        Ok(())
    }

    fn resolve_attribute_namespaces(
        &mut self,
        attributes: &mut [Attribute<S>],
    ) -> Result<bool, ParseError<S>> {
        let has_prefixed_attrs = !attributes.is_empty()
            && attributes
                .iter()
                .any(|a| a.prefix.is_some() && a.prefix.as_deref() != Some("xmlns"));
        if has_prefixed_attrs {
            for attr in attributes {
                if let Some(pfx) = &attr.prefix {
                    if pfx.as_ref() == "xmlns" {
                        continue;
                    }
                    let resolved = self
                        .storage
                        .optional_text(self.ns.resolve(Some(pfx.as_ref()))?)?;
                    if pfx.as_ref() != "xml" && resolved.is_none() {
                        if self.options.recover {
                            self.input.push_diagnostic(
                                ErrorSeverity::Error,
                                format_args!("unbound namespace prefix '{pfx}' on attribute"),
                            )?;
                        } else {
                            return Err(self.input.fatal(format_args!(
                                "unbound namespace prefix '{pfx}' on attribute"
                            )));
                        }
                    }
                    attr.namespace = resolved;
                }
            }
        }
        Ok(has_prefixed_attrs)
    }

    fn check_expanded_attributes(
        &mut self,
        attributes: &[Attribute<S>],
    ) -> Result<(), ParseError<S>> {
        // Namespaces in XML 1.0 §6.3 compares expanded, not lexical, names.
        let ns_attr_count = attributes.iter().filter(|a| a.namespace.is_some()).count();
        if ns_attr_count >= 2 {
            'ns_outer: for i in 1..attributes.len() {
                if attributes[i].namespace.is_none() {
                    continue;
                }
                for j in 0..i {
                    admit_attribute_comparison(self.storage, &attributes[i], &attributes[j])?;
                    if attributes[j].namespace.is_none() {
                        continue;
                    }
                    if attributes[i].namespace.as_deref() == attributes[j].namespace.as_deref()
                        && attributes[i].name.as_ref() == attributes[j].name.as_ref()
                    {
                        let ns = attributes[i]
                            .namespace
                            .as_deref()
                            .expect("namespace checked above");
                        if self.options.recover {
                            self.input.push_diagnostic(
                                ErrorSeverity::Error,
                                format_args!(
                                    "namespace-aware duplicate attribute: '{{{ns}}}:{}'",
                                    attributes[i].name
                                ),
                            )?;
                        } else {
                            return Err(self.input.fatal(format_args!(
                                "namespace-aware duplicate attribute: '{{{ns}}}:{}'",
                                attributes[i].name
                            )));
                        }
                        break 'ns_outer;
                    }
                }
            }
        }
        Ok(())
    }

    fn namespace_error(&mut self, message: impl core::fmt::Display) -> Result<(), ParseError<S>> {
        if self.options.recover {
            self.input.push_diagnostic(ErrorSeverity::Error, message)
        } else {
            Err(self.input.fatal(message))
        }
    }

    fn bind_prefixed_declaration(
        &mut self,
        name: &str,
        attr: &Attribute<S>,
        index: usize,
        stripped: &mut S::Values<usize>,
    ) -> Result<(), ParseError<S>> {
        let declared_prefix = &attr.name;
        if declared_prefix.is_empty() {
            self.namespace_error("namespace prefix must not be empty (invalid QName 'xmlns:')")?;
            return Ok(());
        }
        if declared_prefix.contains(':') {
            self.namespace_error("QName contains multiple colons")?;
        }
        // XML 1.0 §3.3.3 applies declared non-CDATA normalization to the URI too.
        let ns_value = if self.attr_types.len() == 0 {
            self.storage.text(&attr.value)?
        } else {
            let attr_qname = self
                .storage
                .formatted(format_args!("xmlns:{declared_prefix}"))?;
            self.normalize_attr_value_by_type(name, &attr_qname, &attr.value)?
        };
        if ns_value.is_empty() {
            self.namespace_error(format_args!(
                "namespace prefix '{declared_prefix}' cannot be undeclared in XML 1.0"
            ))?;
        }
        if declared_prefix.as_ref() == "xmlns" {
            self.namespace_error("the 'xmlns' prefix must not be declared")?;
        }
        if declared_prefix.as_ref() == "xml" && ns_value.as_ref() != XML_NAMESPACE {
            self.namespace_error("the 'xml' prefix must be bound to the XML namespace")?;
            // Recovery removes only this invalid rebinding, after duplicate checks.
            stripped.push(index)?;
            return Ok(());
        }
        if declared_prefix.as_ref() != "xml" && ns_value.as_ref() == XML_NAMESPACE {
            self.namespace_error("only the 'xml' prefix may be bound to the XML namespace")?;
        }
        if ns_value.as_ref() == XMLNS_NAMESPACE {
            self.namespace_error("the xmlns namespace must not be bound to any prefix")?;
        }
        self.ns
            .bind(Some(self.storage.text(&attr.name)?), ns_value)?;
        Ok(())
    }

    fn bind_default_declaration(
        &mut self,
        name: &str,
        attr: &Attribute<S>,
    ) -> Result<(), ParseError<S>> {
        let ns_value = if self.attr_types.len() == 0 {
            self.storage.text(&attr.value)?
        } else {
            self.normalize_attr_value_by_type(name, "xmlns", &attr.value)?
        };
        if ns_value.as_ref() == XML_NAMESPACE {
            self.namespace_error(
                "the xml namespace must not be declared as the default namespace",
            )?;
        }
        if ns_value.as_ref() == XMLNS_NAMESPACE {
            self.namespace_error(
                "the xmlns namespace must not be declared as the default namespace",
            )?;
        }
        self.ns.bind(None, ns_value)?;
        Ok(())
    }

    fn bind_attribute_declarations(
        &mut self,
        name: &str,
        attributes: &[Attribute<S>],
        has_ns_decls: bool,
        stripped: &mut S::Values<usize>,
    ) -> Result<(), ParseError<S>> {
        for (index, attr) in attributes.iter().enumerate() {
            if has_ns_decls && attr.prefix.as_deref() == Some("xmlns") {
                self.bind_prefixed_declaration(name, attr, index, stripped)?;
            } else if has_ns_decls && attr.prefix.is_none() && attr.name.as_ref() == "xmlns" {
                self.bind_default_declaration(name, attr)?;
            } else if attr.prefix.is_some() && attr.name.contains(':') {
                self.namespace_error("QName contains multiple colons")?;
            }
        }
        Ok(())
    }

    fn parse_element_start(
        &mut self,
        parent: NodeId,
    ) -> Result<(NodeId, Option<bool>), ParseError<S>> {
        self.input.increment_depth()?;
        if let Some(positions) = &mut self.positions {
            positions.start_element(self.input.pos())?;
        }
        self.input.expect_byte(b'<')?;
        let name = self.input.parse_name()?;
        let mut attributes = self.storage.values(0)?;

        // Parse attributes
        loop {
            let had_ws = self.input.skip_whitespace()?;
            if self.input.peek() == Some(b'>') || self.input.looking_at(b"/>") {
                break;
            }
            if !had_ws {
                return Err(self.input.fatal("whitespace required between attributes"));
            }
            let attr = self.parse_attribute()?;
            attributes.push(attr)?;
        }

        self.check_attribute_spellings(&attributes)?;
        self.apply_attribute_defaults(name, &mut attributes)?;

        // --- Namespace processing (Namespaces in XML 1.0 section 3) ---

        // Check for namespace declarations to skip namespace scope push/pop
        // when not needed. Skip the scan entirely when there are no attributes.
        let has_ns_decls = !attributes.is_empty()
            && attributes.iter().any(|a| {
                a.prefix.as_deref() == Some("xmlns")
                    || (a.prefix.is_none() && a.name.as_ref() == "xmlns")
            });
        if has_ns_decls {
            self.ns.push_scope()?;
        }

        // Split into prefix and local name for namespace processing.
        let (prefix, local_name) = split_name(name);

        self.check_element_qname(prefix, local_name)?;

        // Scan attributes for namespace declarations and bind them,
        // with validation of namespace constraints.
        // In recovery mode, some invalid attributes may be stripped.
        let mut strip_attr_indices = self.storage.values(0)?;
        self.bind_attribute_declarations(name, &attributes, has_ns_decls, &mut strip_attr_indices)?;

        // Resolve the element's namespace URI from its prefix.
        let elem_ns = self.storage.optional_text(self.ns.resolve(prefix)?)?;

        // Check for unbound element prefix.
        if let Some(pfx) = prefix
            && pfx != "xml"
            && elem_ns.is_none()
        {
            if self.options.recover {
                self.input.push_diagnostic(
                    ErrorSeverity::Error,
                    format_args!("unbound namespace prefix '{pfx}'"),
                )?;
            } else {
                return Err(self
                    .input
                    .fatal(format_args!("unbound namespace prefix '{pfx}'")));
            }
        }

        if self.resolve_attribute_namespaces(&mut attributes)? {
            self.check_expanded_attributes(&attributes)?;
        }

        // Remove stripped attributes (e.g., invalid xmlns:xml rebindings).
        if !strip_attr_indices.is_empty() {
            // Remove in reverse order to preserve indices.
            for &idx in strip_attr_indices.iter().rev() {
                self.storage.charge(attributes.len() - idx)?;
                attributes[idx..].rotate_left(1);
                attributes.pop();
            }
        }

        // The lexical QName remains borrowed through validation. Copy only
        // the parts actually owned by the completed element node.
        let (elem_prefix, elem_local) = split_name(name);
        let elem_prefix_owned = self.storage.optional_text(elem_prefix)?;
        let elem_local_owned = self.storage.text(elem_local)?;
        // Auto-populate id_map for "id" attributes (enables element_by_id
        // and fast CSS #id selectors without requiring DTD validation).
        let elem_id = self.doc.try_create_node(NodeKind::Element {
            name: elem_local_owned,
            prefix: elem_prefix_owned,
            namespace: elem_ns,
            attributes,
        })?;
        self.doc.append_child(parent, elem_id);

        self.doc.try_register_element_id(elem_id)?;

        // Empty element tag <foo/>
        if self.input.looking_at(b"/>") {
            self.input.advance(2)?;
            if let Some(positions) = &mut self.positions {
                positions.end_element(self.input.pos());
            }
            if has_ns_decls {
                self.ns.pop_scope()?;
            }
            self.input.decrement_depth();
            return Ok((elem_id, None));
        }

        // Start tag close >
        self.input.expect_byte(b'>')?;

        Ok((elem_id, Some(has_ns_decls)))
    }

    fn parse_element_end(
        &mut self,
        elem_id: NodeId,
        has_ns_decls: bool,
    ) -> Result<(), ParseError<S>> {
        // Match the end tag against the node's retained parts without
        // formatting or allocating another qualified name.
        self.input.expect_str(b"</")?;
        let (match_prefix, match_local) = {
            let node = self.doc.node(elem_id);
            match &node.kind {
                NodeKind::Element { name, prefix, .. } => (prefix.as_deref(), name.as_ref()),
                _ => unreachable!(),
            }
        };
        if let Some(end_name) = self.input.parse_name_eq_parts(match_prefix, match_local)? {
            let expected = QualifiedName {
                prefix: match_prefix,
                local: match_local,
            };
            if self.options.recover {
                self.input.push_diagnostic(
                    ErrorSeverity::Error,
                    format_args!("mismatched end tag: expected </{expected}>, found </{end_name}>"),
                )?;
            } else {
                return Err(self.input.fatal(format_args!(
                    "mismatched end tag: expected </{expected}>, found </{end_name}>"
                )));
            }
        }
        self.input.skip_whitespace()?;
        self.input.expect_byte(b'>')?;
        if let Some(positions) = &mut self.positions {
            positions.end_element(self.input.pos());
        }

        // Pop the namespace scope when leaving this element (only if we pushed).
        if has_ns_decls {
            self.ns.pop_scope()?;
        }
        self.input.decrement_depth();

        Ok(())
    }

    /// Normalizes an attribute value based on its DTD-declared type.
    ///
    /// For non-CDATA types (e.g., NMTOKEN, ID, IDREF), collapses whitespace:
    /// trim leading/trailing whitespace, reduce internal whitespace sequences
    /// to single spaces (XML 1.0 §3.3.3).
    fn normalize_attr_value_by_type(
        &self,
        element_name: &str,
        attr_name: &str,
        value: &str,
    ) -> Result<S::Text, ParseError<S>> {
        let mut normalized = self.storage.text(value)?;
        if let Some(attributes) = self.attr_types.get(element_name, self.storage)?
            && attributes.get(attr_name, self.storage)?.is_some()
        {
            // XML 1.0 Fifth Edition §3.3.3: after character-reference and
            // literal-whitespace processing, only space (#x20) is collapsed.
            // Unicode whitespace and referenced tabs are not spaces.
            // https://www.w3.org/TR/2008/REC-xml-20081126/#AVNormalize
            self.storage.normalize_id(&mut normalized)?;
        }
        Ok(normalized)
    }

    // --- Character Data ---
    // See XML 1.0 §2.4: [14] CharData

    fn parse_char_data(&mut self, parent: NodeId) -> Result<(), ParseError<S>> {
        let source_start = self.input.pos();
        let mut text = self.storage.text("")?;

        while !self.input.at_end() {
            // Bulk scan: find the next `<`, `&`, or `]]>` boundary and
            // consume all safe bytes in one go.
            let safe_len = self.input.scan_char_data()?;
            if safe_len > 0 {
                let start = self.input.pos();
                let chunk = core::str::from_utf8(self.input.slice(start, start + safe_len))
                    .map_err(|_| self.input.fatal("invalid UTF-8 in character data"))?;
                // Fast byte-level pre-check for invalid XML chars (0x7F,
                // U+FFFE, U+FFFF). Skips the expensive char-by-char
                // validation for the 99.9% of chunks that are clean.
                self.storage.charge(chunk.len())?;
                let bad_char = if may_contain_invalid_xml_chars(chunk.as_bytes()) {
                    self.storage.charge(chunk.len())?;
                    find_invalid_xml_char(chunk)
                } else {
                    None
                };
                // Append text with CR normalization if needed (XML 1.0 §2.11)
                super::input::append_normalized_line_ends(self.storage, &mut text, chunk)?;
                // chunk borrow released — safe to mutably borrow self.input
                self.input.advance_counting_lines(safe_len)?;
                if let Some(bad) = bad_char {
                    if self.options.recover {
                        self.input.push_diagnostic(
                            ErrorSeverity::Error,
                            format_args!("invalid XML character: U+{:04X}", bad as u32),
                        )?;
                    } else {
                        return Err(self
                            .input
                            .fatal(format_args!("invalid XML character: U+{:04X}", bad as u32)));
                    }
                }
                continue;
            }

            if self.input.peek() == Some(b'<') {
                break;
            }

            // XML 1.0 §2.4: "]]>" is forbidden in character data
            if self.input.looking_at(b"]]>") {
                if self.options.recover {
                    self.input.push_diagnostic(
                        ErrorSeverity::Error,
                        "']]>' not allowed in character data",
                    )?;
                    self.storage.append(&mut text, "]]>")?;
                    self.input.advance(3)?;
                    continue;
                }
                return Err(self.input.fatal("']]>' not allowed in character data"));
            }

            if self.input.peek() == Some(b'&') {
                // A named general entity reference in content (not a char ref,
                // not a builtin) is included per XML 1.0 §4.4: an EntityRef
                // node is created and the entity's replacement text is parsed
                // as content, attached as children of the EntityRef node.
                // Skip the peek for builtins at byte level to avoid String allocation.
                if self.input.peek_at(1) != Some(b'#') && !self.is_looking_at_builtin_entity_ref() {
                    // Flush accumulated text before the entity ref
                    if !text.is_empty() {
                        let empty = self.storage.text("")?;
                        let text_id = self.doc.try_create_node(NodeKind::Text {
                            content: core::mem::replace(&mut text, empty),
                        })?;
                        self.doc.append_child(parent, text_id);
                    }
                    self.parse_entity_ref_in_content(parent)?;
                    continue;
                }
                self.input.parse_reference_into(&mut text)?;
            } else {
                let ch = self.input.next_char()?;
                self.storage
                    .append(&mut text, ch.encode_utf8(&mut [0; 4]))?;
            }
        }

        if !text.is_empty() {
            // Strip blank text nodes if configured
            if self.options.no_blanks {
                self.storage.charge(text.len())?;
                if text.chars().all(char::is_whitespace) {
                    return Ok(());
                }
            }
            let text_id = self.doc.try_create_node(NodeKind::Text { content: text })?;
            self.doc.append_child(parent, text_id);
            if let Some(positions) = &mut self.positions {
                positions.leaf(SourceKind::Text, source_start..self.input.pos())?;
            }
        }

        Ok(())
    }

    /// Parses a general entity reference (`&name;`) appearing in element
    /// content per XML 1.0 §4.4 ("Included").
    ///
    /// Creates an `EntityRef` node under `parent`, then parses the entity's
    /// replacement text (XML 1.0 §4.5: character references expanded at
    /// declaration time) as content, attaching the resulting nodes as
    /// children of the `EntityRef` node.
    fn parse_entity_ref_in_content(&mut self, parent: NodeId) -> Result<(), ParseError<S>> {
        // Consume `&name;`
        self.input.advance(1)?; // '&'
        let name = self.input.parse_name()?;
        self.input.expect_byte(b';')?;

        // Resolve the replacement text (XML 1.0 §4.5). Only a declared entity
        // substitutes anything, so only it counts against the expansion limit.
        let declaration = self.input.entity_map.get(name, self.storage)?;
        if declaration.is_some() {
            self.input.entity_expansions += 1;
            self.input.check_entity_expansions()?;
        }
        let replacement: Option<S::Text> =
            if let Some(crate::parser_xmloxide::validation::dtd::EntityDecl {
                kind: EntityKind::Internal(raw),
                ..
            }) = declaration
            {
                Some(
                    crate::parser_xmloxide::validation::dtd::expand_char_refs_only(
                        raw,
                        self.storage,
                    )?,
                )
            } else if let Some(crate::parser_xmloxide::validation::dtd::EntityDecl {
                kind:
                    EntityKind::External {
                        system_id,
                        public_id,
                    },
                ..
            }) = declaration
            {
                if let Some(resolver) = self.input.external_entity_resolver() {
                    let request = crate::parser_xmloxide::parser::ExternalEntityRequest {
                        name,
                        system_id,
                        public_id: public_id.as_deref(),
                    };
                    if let Some(resolved) = resolver(request) {
                        // External parsed entities may begin with a text
                        // declaration (XML 1.0 §4.3.1) which is not content.
                        self.storage.charge(resolved.len())?;
                        Some(self.storage.text(strip_text_declaration(&resolved))?)
                    } else {
                        return Err(self.input.fatal(format_args!(
                            "reference to external entity '{name}' is not supported"
                        )));
                    }
                } else {
                    return Err(self.input.fatal(format_args!(
                        "reference to external entity '{name}' is not supported"
                    )));
                }
            } else if self.input.has_pe_references || self.input.has_external_dtd {
                // Undeclared entity in tolerant mode (external DTD or PE refs
                // present, XML 1.0 §4.1 WFC: Entity Declared): preserve the
                // reference without a value.
                None
            } else if self.options.recover {
                self.input.push_diagnostic(
                    ErrorSeverity::Warning,
                    format_args!("unknown entity reference: &{name};"),
                )?;
                None
            } else {
                return Err(self
                    .input
                    .fatal(format_args!("unknown entity reference: &{name};")));
            };

        let ref_id = self.doc.try_create_node(NodeKind::EntityRef {
            name: self.storage.text(name)?,
            value: self.storage.optional_text(replacement.as_deref())?,
        })?;
        self.doc.append_child(parent, ref_id);

        let Some(replacement) = replacement else {
            return Ok(());
        };
        if replacement.is_empty() {
            return Ok(());
        }

        // Amplification guard (matches libxml2's max amplification factor).
        self.expansion_size += replacement.len();
        if self.expansion_size > self.input_size.saturating_mul(DEFAULT_MAX_AMPLIFICATION) {
            return Err(self
                .input
                .fatal("maximum entity amplification factor exceeded"));
        }

        self.storage.charge(replacement.len())?;
        if replacement.bytes().any(|byte| byte == b'<' || byte == b'&') {
            self.parse_replacement_as_content(name, &replacement, ref_id)?;
            return Ok(());
        }
        // Fast path: plain character data, without markup or references.
        let mut content = self.storage.text("")?;
        super::input::append_normalized_line_ends(self.storage, &mut content, &replacement)?;
        let text_id = self.doc.try_create_node(NodeKind::Text { content })?;
        self.doc.append_child(ref_id, text_id);
        Ok(())
    }

    /// Parses an entity's replacement text as XML content (XML 1.0 §4.3.2:
    /// the replacement text must match the `content` production), attaching
    /// the parsed nodes as children of `ref_id`.
    ///
    /// A nested sub-parser is used so the replacement text is processed with
    /// the same entity declarations, namespace scope, options, and security
    /// counters as the outer document.
    fn parse_replacement_as_content(
        &mut self,
        entity_name: &str,
        replacement: &str,
        ref_id: NodeId,
    ) -> Result<(), ParseError<S>> {
        if self.entity_depth >= MAX_ENTITY_DEPTH {
            return Err(self.input.fatal(format_args!(
                "entity '{entity_name}' exceeds maximum entity nesting depth"
            )));
        }

        let mut sub = XmlParser::with_storage(replacement, &self.options, self.storage)?;
        sub.input.inherit_entity_resolver(&self.input);
        sub.entity_depth = self.entity_depth + 1;
        sub.input_size = self.input_size;
        sub.expansion_size = self.expansion_size;
        // Inherit the element nesting depth so total depth across entity
        // expansions stays bounded by max_depth (a fresh counter per
        // sub-parser would allow MAX_ENTITY_DEPTH * max_depth stack frames —
        // enough to overflow the stack).
        sub.input.set_depth(self.input.depth());
        // Move shared state into the sub-parser (returned below).
        core::mem::swap(&mut sub.input.entity_map, &mut self.input.entity_map);
        sub.input.has_pe_references = self.input.has_pe_references;
        sub.input.has_external_dtd = self.input.has_external_dtd;
        sub.input.entity_expansions = self.input.entity_expansions;
        core::mem::swap(&mut sub.attr_types, &mut self.attr_types);
        core::mem::swap(&mut sub.attr_defaults, &mut self.attr_defaults);
        core::mem::swap(&mut sub.ns, &mut self.ns);

        let sub_root = sub.doc.root();
        let result = sub.parse_content_fragment(sub_root);

        // Restore shared state regardless of outcome.
        core::mem::swap(&mut self.input.entity_map, &mut sub.input.entity_map);
        self.input.entity_expansions = sub.input.entity_expansions;
        core::mem::swap(&mut self.attr_types, &mut sub.attr_types);
        core::mem::swap(&mut self.attr_defaults, &mut sub.attr_defaults);
        core::mem::swap(&mut self.ns, &mut sub.ns);
        self.expansion_size = sub.expansion_size;
        if !sub.input.diagnostics.is_empty() {
            for diagnostic in sub.input.diagnostics.drain_all()? {
                self.input.diagnostics.push(diagnostic)?;
            }
        }

        if let Err(e) = result {
            if matches!(e, ParseError::<S>::Resource(_)) {
                return Err(e);
            }
            let message = e.message().expect("resource refusal returned above");
            // Propagate security-limit errors and already-wrapped entity
            // errors unchanged to avoid nested message wrapping.
            if message.contains("exceeded")
                || message.contains("replacement text is not well-formed")
            {
                return Err(e);
            }
            return Err(self.input.fatal(format_args!(
                "entity '{entity_name}' replacement text is not well-formed \
                 XML content: {message}"
            )));
        }

        // Graft the parsed nodes into our arena under the EntityRef node.
        self.doc.try_graft_children(sub.doc, ref_id)?;
        Ok(())
    }

    /// Parses content until end of input (used for entity replacement text,
    /// which must match the `content` production — XML 1.0 §4.3.2).
    ///
    /// Unlike [`parse_content`](Self::parse_content), end of input is the
    /// normal termination and an end tag (`</`) is an error (it would close
    /// an element opened outside the entity — WFC violation).
    fn parse_content_fragment(&mut self, parent: NodeId) -> Result<(), ParseError<S>> {
        while !self.input.at_end() {
            if self.input.looking_at(b"</") {
                return Err(self.input.fatal("unbalanced end tag"));
            }
            if self.input.looking_at(b"<![CDATA[") {
                self.parse_cdata(parent)?;
            } else if self.input.looking_at(b"<!--") {
                self.parse_comment(parent)?;
            } else if self.input.looking_at(b"<?") {
                self.parse_processing_instruction(parent)?;
            } else if self.input.peek() == Some(b'<') {
                self.parse_element(parent)?;
            } else {
                self.parse_char_data(parent)?;
            }
        }
        Ok(())
    }

    /// Checks if the input is positioned at a builtin entity reference
    /// (`&amp;`, `&lt;`, `&gt;`, `&apos;`, `&quot;`) using byte-level
    /// checks. Other names go directly to the ordinary XML Name parser.
    #[inline]
    fn is_looking_at_builtin_entity_ref(&self) -> bool {
        let remaining = self.input.remaining();
        if remaining.len() < 4 || remaining[0] != b'&' {
            return false;
        }
        let after_amp = &remaining[1..];
        after_amp.starts_with(b"lt;")
            || after_amp.starts_with(b"gt;")
            || after_amp.starts_with(b"amp;")
            || after_amp.starts_with(b"apos;")
            || after_amp.starts_with(b"quot;")
    }

    /// Checks if all entity references (`&name;`) in a raw attribute value
    /// text are declared in the entity map. Returns false if any undeclared
    /// entity ref is found (these should not be preserved via `raw_value`).
    fn all_entity_refs_declared(&self, raw: &str) -> Result<bool, ParseError<S>> {
        self.storage.charge(raw.len())?;
        let bytes = raw.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'&' && i + 1 < bytes.len() && bytes[i + 1] != b'#' {
                // Attribute parsing already validated XML 1.0 §2.3 Name.
                // Locate its ASCII delimiter without restricting Unicode names
                // to an unrelated ASCII-only grammar.
                // https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Name
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b';' {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b';' {
                    let name = &raw[i + 1..j];
                    if !is_builtin_entity(name)
                        && self.input.entity_map.get(name, self.storage)?.is_none()
                    {
                        return Ok(false);
                    }
                    i = j + 1;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        Ok(true)
    }

    // --- Attributes ---
    // See XML 1.0 §3.1: [41] Attribute

    fn parse_attribute(&mut self) -> Result<Attribute<S>, ParseError<S>> {
        let name = self.input.parse_name()?;
        self.input.skip_whitespace()?;
        self.input.expect_byte(b'=')?;
        self.input.skip_whitespace()?;

        // Capture raw attribute value text (before entity expansion) so we
        // can preserve entity references during serialization.
        let raw_start = self.input.pos();
        let value = self.input.parse_attribute_value()?;
        let raw_end = self.input.pos();

        // Extract raw value (between quotes) — the raw slice includes the
        // outer quote chars, so trim them. Skip entirely when the raw bytes
        // contain no '&' (most attributes have no entity references).
        let raw_value = if raw_end > raw_start + 2 {
            let raw_bytes = self.input.slice(raw_start + 1, raw_end - 1);
            self.storage.charge(raw_bytes.len())?;
            if raw_bytes.contains(&b'&') {
                let raw_str = core::str::from_utf8(raw_bytes)
                    .map_err(|_| self.input.fatal("invalid UTF-8 in raw attribute value"))?;
                // Only store raw_value if it differs from the expanded value
                // (i.e., it contained entity references that got expanded) AND
                // all entity references in the raw value are declared (not
                // undeclared entities that expanded to empty string).
                self.storage.charge(raw_str.len() + value.len())?;
                if raw_str != value.as_ref() && self.all_entity_refs_declared(raw_str)? {
                    Some(self.storage.text(raw_str)?)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let (prefix, local_name) = split_name(name);

        Ok(Attribute {
            name: self.storage.text(local_name)?,
            value,
            prefix: self.storage.optional_text(prefix)?,
            namespace: None,
            raw_value,
        })
    }

    // --- Comments ---
    // See XML 1.0 §2.5: [15] Comment

    fn parse_comment(&mut self, parent: NodeId) -> Result<(), ParseError<S>> {
        let start = self.input.pos();
        let content = parse_comment_content(&mut self.input)?;
        let comment_id = self.doc.try_create_node(NodeKind::Comment {
            content: self.storage.text(content)?,
        })?;
        self.doc.append_child(parent, comment_id);
        if let Some(positions) = &mut self.positions {
            positions.leaf(SourceKind::Comment, start..self.input.pos())?;
        }
        Ok(())
    }

    // --- CDATA Sections ---
    // See XML 1.0 §2.7: [18] CDSect

    fn parse_cdata(&mut self, parent: NodeId) -> Result<(), ParseError<S>> {
        let start = self.input.pos();
        let content = parse_cdata_content(&mut self.input)?;
        let cdata_id = self.doc.try_create_node(NodeKind::CData {
            content: self.storage.text(content)?,
        })?;
        self.doc.append_child(parent, cdata_id);
        if let Some(positions) = &mut self.positions {
            positions.leaf(SourceKind::CData, start..self.input.pos())?;
        }
        Ok(())
    }

    // --- Processing Instructions ---
    // See XML 1.0 §2.6: [16] PI

    fn parse_processing_instruction(&mut self, parent: NodeId) -> Result<(), ParseError<S>> {
        let start = self.input.pos();
        let (target, data) = parse_pi_content(&mut self.input)?;
        let pi_id = self.doc.try_create_node(NodeKind::ProcessingInstruction {
            target: self.storage.text(target)?,
            data: self.storage.optional_text(data)?,
        })?;
        self.doc.append_child(parent, pi_id);
        if let Some(positions) = &mut self.positions {
            positions.leaf(SourceKind::Pi, start..self.input.pos())?;
        }
        Ok(())
    }
}

/// Strips an optional leading text declaration (`<?xml ...?>`) from external
/// parsed entity text (XML 1.0 §4.3.1: `TextDecl`).
fn strip_text_declaration(s: &str) -> &str {
    let rest = s.strip_prefix("<?xml").filter(|r| {
        r.starts_with(' ') || r.starts_with('\t') || r.starts_with('\r') || r.starts_with('\n')
    });
    if let Some(rest) = rest
        && let Some(end) = rest.find("?>")
    {
        return &rest[end + 2..];
    }
    s
}

/// Returns true if the entity name is one of the five XML builtin entities.
fn is_builtin_entity(name: &str) -> bool {
    matches!(name, "amp" | "lt" | "gt" | "apos" | "quot")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::parser_xmloxide::tree::Document;

    #[cfg(feature = "xmldsig")]
    #[test]
    fn scoped_parser_owns_dom_and_entity_fragments_in_current_execution() {
        // The DTD tables move into runtime state; markup entities graft all
        // sibling/parent links without a native payload copy or budget reset.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };
        const SOURCE: &str = "<!DOCTYPE root [<!ENTITY leaf '<p:a id=\"nested\">A</p:a><p:b>B</p:b>'><!ENTITY parent '&leaf;'><!ATTLIST root xmlns:p CDATA 'urn:test' mode NMTOKEN ' on '>]><root id='root'>&parent;<tail/></root>";
        let run = |capacity, local, aggregate| {
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, aggregate)));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: local,
                    ..Default::default()
                },
                memory.clone(),
            );
            let cursor = parser.read(&[], 0).unwrap();
            let execution = cursor.execution();
            let result =
                XmlParser::with_storage(SOURCE, &ParseOptions::default(), Accounted(&execution))
                    .and_then(XmlParser::parse);
            let refusal = match result {
                Ok(document) => {
                    let root = document.root_element().unwrap();
                    assert_eq!(document.attribute(root, "mode"), Some(" on "));
                    let outer = document.first_child(root).unwrap();
                    let inner = document.first_child(outer).unwrap();
                    let a = document.first_child(inner).unwrap();
                    let b = document.next_sibling(a).unwrap();
                    assert_eq!(document.node_name(a), Some("a"));
                    assert_eq!(document.node_name(b), Some("b"));
                    assert_eq!(document.node_namespace(a), Some("urn:test"));
                    assert_eq!(document.parent(a), Some(inner));
                    assert_eq!(document.parent(b), Some(inner));
                    assert_eq!(document.prev_sibling(b), Some(a));
                    assert_eq!(document.last_child(inner), Some(b));
                    assert_eq!(
                        document.node_name(document.next_sibling(outer).unwrap()),
                        Some("tail")
                    );
                    assert!(memory.used() > SOURCE.len());
                    drop(document);
                    None
                }
                Err(crate::parser_xmloxide::error::ParseError::Resource(
                    crate::xml::dom::ParseError::SharedExecution(error),
                )) => Some(error),
                Err(error) => panic!("unexpected syntax or allocation failure: {error}"),
            };
            assert_eq!(memory.used(), 0);
            refusal
        };
        assert_eq!(run(1 << 20, 1 << 24, 1 << 24), None);
        assert_eq!(run(1 << 20, 0, 1 << 24), Some(MemoryError::WorkExceeded));
        assert_eq!(run(1 << 20, 1 << 24, 0), Some(MemoryError::WorkExceeded));
        assert_eq!(run(0, 1 << 24, 1 << 24), Some(MemoryError::LimitExceeded));
    }

    #[test]
    fn undeclared_unicode_attribute_entity_has_no_retained_raw_value() {
        // XML 1.0 Fifth Edition §2.3 Names permits Unicode entity names.
        // An unread external subset permits omission (§4.1 Entity Declared),
        // but an absent declaration cannot authorize retained raw output.
        // https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Name
        let document = parse("<!DOCTYPE root SYSTEM 'urn:unread'><root a='&β;'/>");
        let root = document.root_element().unwrap();
        let attribute = &document.attributes(root)[0];
        assert_eq!(attribute.value, "");
        assert!(attribute.raw_value.is_none());
    }

    fn parse(input: &str) -> Document {
        Document::parse_str(input).unwrap_or_else(|e| panic!("parse failed: {e}"))
    }

    #[test]
    fn returning_document_does_not_allocate_a_replacement_arena() {
        // Returning the completed tree must move its arena rather than create
        // a second 64-node document only to discard that replacement parser.
        let before = crate::parser_xmloxide::tree::ARENA_CONSTRUCTIONS.with(std::cell::Cell::get);
        let document = parse("<root/>");
        let after = crate::parser_xmloxide::tree::ARENA_CONSTRUCTIONS.with(std::cell::Cell::get);
        assert_eq!(after - before, 1);
        assert_eq!(
            document.node_name(document.root_element().unwrap()),
            Some("root")
        );
    }

    #[test]
    fn tokenized_attribute_collapse_does_not_strip_unicode_or_character_reference_tabs() {
        // The final tokenized-attribute step collapses #x20 only. Unicode
        // whitespace and tabs produced by character references remain data.
        let options = ParseOptions::default();
        let mut parser = XmlParser::new(
            "<!DOCTYPE root [<!ATTLIST root xmlns NMTOKENS #IMPLIED>]>",
            &options,
        )
        .unwrap();
        parser.parse_doctype(parser.doc.root()).unwrap();
        assert_eq!(
            parser
                .normalize_attr_value_by_type("root", "xmlns", " a  b\u{a0}c \t ")
                .unwrap(),
            "a b\u{a0}c \t"
        );
    }

    #[test]
    fn test_parse_empty_element() {
        let doc = parse("<root/>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("root"));
        assert_eq!(doc.first_child(root), None);
    }

    #[test]
    fn test_parse_element_with_text() {
        let doc = parse("<greeting>Hello, world!</greeting>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("greeting"));
        assert_eq!(doc.text_content(root), "Hello, world!");
    }

    #[test]
    fn test_parse_nested_elements() {
        let doc = parse("<a><b><c/></b></a>");
        let a = doc.root_element().unwrap();
        assert_eq!(doc.node_name(a), Some("a"));

        let b = doc.first_child(a).unwrap();
        assert_eq!(doc.node_name(b), Some("b"));

        let c = doc.first_child(b).unwrap();
        assert_eq!(doc.node_name(c), Some("c"));
    }

    #[test]
    fn test_parse_attributes() {
        let doc = parse("<div id=\"main\" class=\"big\"/>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.attribute(root, "id"), Some("main"));
        assert_eq!(doc.attribute(root, "class"), Some("big"));
    }

    #[test]
    fn test_parse_single_quoted_attributes() {
        let doc = parse("<div id='main'/>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.attribute(root, "id"), Some("main"));
    }

    #[test]
    fn test_parse_xml_declaration() {
        let doc = parse("<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>");
        assert_eq!(doc.version.as_deref(), Some("1.0"));
        assert_eq!(doc.encoding.as_deref(), Some("UTF-8"));
    }

    #[test]
    fn test_parse_xml_declaration_standalone() {
        let doc = parse("<?xml version=\"1.0\" standalone=\"yes\"?><root/>");
        assert_eq!(doc.standalone, Some(true));
    }

    #[test]
    fn test_parse_comment() {
        let doc = parse("<root><!-- hello --></root>");
        let root = doc.root_element().unwrap();
        let child = doc.first_child(root).unwrap();
        assert_eq!(doc.node_text(child), Some(" hello "));
    }

    #[test]
    fn test_parse_cdata() {
        let doc = parse("<root><![CDATA[x < 1 && y > 2]]></root>");
        let root = doc.root_element().unwrap();
        let child = doc.first_child(root).unwrap();
        assert_eq!(doc.node_text(child), Some("x < 1 && y > 2"));
    }

    #[test]
    fn test_parse_processing_instruction() {
        let doc = parse("<?my-pi some data?><root/>");
        let pi = doc.first_child(doc.root()).unwrap();
        assert_eq!(doc.node_name(pi), Some("my-pi"));
        assert_eq!(doc.node_text(pi), Some("some data"));
    }

    #[test]
    fn test_parse_entity_references() {
        let doc = parse("<root>&amp; &lt; &gt; &apos; &quot;</root>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.text_content(root), "& < > ' \"");
    }

    #[test]
    fn test_parse_char_reference_decimal() {
        let doc = parse("<root>&#65;</root>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.text_content(root), "A");
    }

    #[test]
    fn test_parse_char_reference_hex() {
        let doc = parse("<root>&#x41;</root>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.text_content(root), "A");
    }

    #[test]
    fn test_parse_mixed_content() {
        let doc = parse("<p>Hello <b>world</b>!</p>");
        let p = doc.root_element().unwrap();
        let children: Vec<_> = doc.children(p).collect();
        assert_eq!(children.len(), 3); // "Hello ", <b>, "!"

        assert_eq!(doc.node_text(children[0]), Some("Hello "));
        assert_eq!(doc.node_name(children[1]), Some("b"));
        assert_eq!(doc.text_content(children[1]), "world");
        assert_eq!(doc.node_text(children[2]), Some("!"));
    }

    #[test]
    fn test_parse_prefixed_element() {
        let doc = parse("<svg:rect xmlns:svg=\"http://www.w3.org/2000/svg\"/>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("rect"));
        match &doc.node(root).kind {
            NodeKind::Element { prefix, .. } => {
                assert_eq!(prefix.as_deref(), Some("svg"));
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_prefixed_attribute() {
        let doc = parse("<root xml:lang=\"en\"/>");
        let root = doc.root_element().unwrap();
        let attrs = doc.attributes(root);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, "lang");
        assert_eq!(attrs[0].prefix.as_deref(), Some("xml"));
        assert_eq!(attrs[0].value, "en");
    }

    #[test]
    fn test_parse_error_mismatched_tags() {
        let result = Document::parse_str("<a></b>");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_unexpected_eof() {
        let result = Document::parse_str("<a>");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_no_root() {
        let result = Document::parse_str("");
        // XML 1.0 §2.1 requires a root element
        assert!(result.is_err());
    }

    /// The XML declaration prefix that `serialize()` always emits.
    const DECL: &str = "<?xml version=\"1.0\"?>\n";

    #[test]
    fn test_roundtrip_simple() {
        let input = "<root><child>text</child></root>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(output, format!("{DECL}{input}\n"));
    }

    #[test]
    fn test_roundtrip_attributes() {
        let input = "<root attr=\"value\"><child id=\"1\"/></root>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(output, format!("{DECL}{input}\n"));
    }

    #[test]
    fn test_roundtrip_entities() {
        let input = "<root>&amp; &lt; &gt;</root>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        // After parsing, entities are resolved to characters.
        // Serialization re-escapes them.
        assert_eq!(output, format!("{DECL}<root>&amp; &lt; &gt;</root>\n"));
    }

    #[test]
    fn test_roundtrip_comment() {
        let input = "<root><!-- comment --></root>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(output, format!("{DECL}{input}\n"));
    }

    #[test]
    fn test_roundtrip_cdata() {
        let input = "<root><![CDATA[data & stuff]]></root>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(output, format!("{DECL}{input}\n"));
    }

    #[test]
    fn test_roundtrip_pi() {
        let input = "<?target data?><root/>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(output, format!("{DECL}{input}\n"));
    }

    #[test]
    fn test_roundtrip_xml_declaration() {
        let input = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(
            output,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root/>\n"
        );
    }

    #[test]
    fn test_whitespace_in_attribute_value() {
        let doc = parse("<root attr=\"a\tb\nc\"/>");
        let root = doc.root_element().unwrap();
        // Tabs and newlines in attribute values are normalized to spaces
        assert_eq!(doc.attribute(root, "attr"), Some("a b c"));
    }

    #[test]
    fn test_name_chars() {
        use super::super::input::{is_name_char, is_name_start_char};

        assert!(is_name_start_char('A'));
        assert!(is_name_start_char('z'));
        assert!(is_name_start_char('_'));
        assert!(is_name_start_char(':'));
        assert!(!is_name_start_char('0'));
        assert!(!is_name_start_char('-'));

        assert!(is_name_char('A'));
        assert!(is_name_char('0'));
        assert!(is_name_char('-'));
        assert!(is_name_char('.'));
        assert!(!is_name_char(' '));
    }

    #[test]
    fn test_parse_doctype_simple() {
        let doc = parse("<!DOCTYPE html><html/>");
        let root = doc.root();
        let children: Vec<_> = doc.children(root).collect();
        assert_eq!(children.len(), 2);

        match &doc.node(children[0]).kind {
            NodeKind::DocumentType {
                name,
                system_id,
                public_id,
                ..
            } => {
                assert_eq!(name, "html");
                assert_eq!(*system_id, None);
                assert_eq!(*public_id, None);
            }
            other => panic!("expected DocumentType, got {other:?}"),
        }

        assert_eq!(doc.node_name(children[1]), Some("html"));
    }

    #[test]
    fn test_parse_doctype_system() {
        let doc = parse("<!DOCTYPE root SYSTEM \"root.dtd\"><root/>");
        let root = doc.root();
        let children: Vec<_> = doc.children(root).collect();
        assert_eq!(children.len(), 2);

        match &doc.node(children[0]).kind {
            NodeKind::DocumentType {
                name,
                system_id,
                public_id,
                ..
            } => {
                assert_eq!(name, "root");
                assert_eq!(system_id.as_deref(), Some("root.dtd"));
                assert_eq!(*public_id, None);
            }
            other => panic!("expected DocumentType, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_doctype_public() {
        let doc = parse(
            "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" \
             \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\"><html/>",
        );
        let root = doc.root();
        let children: Vec<_> = doc.children(root).collect();
        assert_eq!(children.len(), 2);

        match &doc.node(children[0]).kind {
            NodeKind::DocumentType {
                name,
                system_id,
                public_id,
                ..
            } => {
                assert_eq!(name, "html");
                assert_eq!(public_id.as_deref(), Some("-//W3C//DTD XHTML 1.0//EN"));
                assert_eq!(
                    system_id.as_deref(),
                    Some("http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd")
                );
            }
            other => panic!("expected DocumentType, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_doctype_internal_subset() {
        let doc = parse("<!DOCTYPE root [<!ELEMENT root (#PCDATA)>]><root/>");
        let root = doc.root();
        let children: Vec<_> = doc.children(root).collect();
        assert_eq!(children.len(), 2);

        match &doc.node(children[0]).kind {
            NodeKind::DocumentType {
                name,
                system_id,
                public_id,
                ..
            } => {
                assert_eq!(name, "root");
                assert_eq!(*system_id, None);
                assert_eq!(*public_id, None);
            }
            other => panic!("expected DocumentType, got {other:?}"),
        }

        assert_eq!(doc.node_name(children[1]), Some("root"));
    }

    #[test]
    fn test_parse_doctype_multiline_internal_subset() {
        let input =
            "<!DOCTYPE root [\n<!ELEMENT y (#PCDATA|x|x)*>\n<!ELEMENT root ANY>\n]>\n\n<root/>";
        let doc = parse(input);
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("root"));
    }

    #[test]
    fn test_parse_doctype_with_entity() {
        let input = "<!DOCTYPE doc [\n<!ELEMENT doc (#PCDATA)>\n<!ENTITY rsqb \"]\">\n]>\n<doc>&rsqb;</doc>";
        let doc = parse(input);
        let root = doc.root_element().unwrap();
        assert_eq!(doc.text_content(root), "]");
    }

    #[test]
    fn test_parse_doctype_content_model() {
        let input = "<!DOCTYPE violation [\n<!ELEMENT violation (a,a,a,b)>\n<!ELEMENT a EMPTY>\n<!ELEMENT b EMPTY>\n]>\n<violation>\n    <a/>\n    <a/>\n    <b/>\n</violation>";
        let doc = parse(input);
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("violation"));
    }

    #[test]
    fn test_parse_doctype_with_crlf() {
        // Test with CRLF line endings (like the OASIS conformance tests)
        let input =
            "<!DOCTYPE doc\r\n[\r\n<!ELEMENT doc ANY>\r\n<!ELEMENT a (doc?)>\r\n]>\r\n<doc/>";
        let doc = parse(input);
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("doc"));
    }

    #[test]
    fn test_parse_doctype_attlist() {
        let input = "<!DOCTYPE root [\n<!ELEMENT root EMPTY>\n<!ATTLIST root\n    token\tNMTOKEN\t\t#REQUIRED\n    >\n\n    <!-- comment -->\n]>\n<root token=\"dev@null\"/>";
        let doc = parse(input);
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("root"));
    }

    #[test]
    fn test_parse_doctype_comment_with_apostrophe() {
        // Apostrophes in DTD comments must not confuse the bracket scanner
        let input = "<!DOCTYPE root [\n<!ELEMENT root ANY>\n<!-- can't break -->\n]>\n<root/>";
        let doc = parse(input);
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("root"));
    }

    #[test]
    fn test_roundtrip_doctype() {
        // Simple DOCTYPE (no whitespace between DOCTYPE and root in input)
        let input = "<!DOCTYPE html><html/>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(output, format!("{DECL}<!DOCTYPE html><html/>\n"));

        // DOCTYPE with SYSTEM
        let input = "<!DOCTYPE root SYSTEM \"root.dtd\"><root/>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(
            output,
            format!("{DECL}<!DOCTYPE root SYSTEM \"root.dtd\"><root/>\n")
        );

        // DOCTYPE with PUBLIC
        let input = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" \
                      \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\"><html/>";
        let doc = parse(input);
        let output = crate::parser_xmloxide::serial::serialize(&doc);
        assert_eq!(
            output,
            format!(
                "{DECL}<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" \
                 \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\"><html/>\n"
            )
        );
    }

    // --- Namespace resolution tests ---

    #[test]
    fn test_parse_default_namespace() {
        let doc = parse("<root xmlns=\"http://example.com\"/>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_namespace(root), Some("http://example.com"));
    }

    #[test]
    fn test_parse_prefixed_namespace() {
        let doc = parse("<ns:root xmlns:ns=\"http://example.com\"/>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_name(root), Some("root"));
        assert_eq!(doc.node_namespace(root), Some("http://example.com"));
        match &doc.node(root).kind {
            NodeKind::Element { prefix, .. } => {
                assert_eq!(prefix.as_deref(), Some("ns"));
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_nested_namespace() {
        // Child elements inherit the default namespace from the parent.
        let doc = parse("<root xmlns=\"http://example.com\"><child/></root>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_namespace(root), Some("http://example.com"));

        let child = doc.first_child(root).unwrap();
        assert_eq!(doc.node_name(child), Some("child"));
        assert_eq!(doc.node_namespace(child), Some("http://example.com"));
    }

    #[test]
    fn test_parse_namespace_override() {
        // A child element can override the parent's default namespace.
        let doc = parse(
            "<root xmlns=\"http://example.com\">\
             <child xmlns=\"http://other.com\"/>\
             </root>",
        );
        let root = doc.root_element().unwrap();
        assert_eq!(doc.node_namespace(root), Some("http://example.com"));

        let child = doc.first_child(root).unwrap();
        assert_eq!(doc.node_namespace(child), Some("http://other.com"));
    }

    #[test]
    fn test_parse_xml_namespace() {
        // The xml: prefix is always bound to the XML namespace URI.
        let doc = parse("<root xml:lang=\"en\"/>");
        let root = doc.root_element().unwrap();
        let attrs = doc.attributes(root);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, "lang");
        assert_eq!(attrs[0].prefix.as_deref(), Some("xml"));
        assert_eq!(
            attrs[0].namespace.as_deref(),
            Some("http://www.w3.org/XML/1998/namespace")
        );
    }

    #[test]
    fn test_parse_attribute_namespace() {
        // Prefixed attributes get their namespace resolved.
        let doc = parse("<root xmlns:app=\"http://example.com/app\" app:version=\"2.0\"/>");
        let root = doc.root_element().unwrap();
        let attrs = doc.attributes(root);

        // Find the app:version attribute
        let version_attr = attrs.iter().find(|a| a.name == "version").unwrap();
        assert_eq!(version_attr.prefix.as_deref(), Some("app"));
        assert_eq!(
            version_attr.namespace.as_deref(),
            Some("http://example.com/app")
        );

        // The xmlns:app attribute should not have a resolved namespace itself.
        let xmlns_attr = attrs.iter().find(|a| a.name == "app").unwrap();
        assert_eq!(xmlns_attr.prefix.as_deref(), Some("xmlns"));
        assert_eq!(xmlns_attr.namespace, None);
    }

    // -- General entity inclusion in content (issue #43) --------------------
    //
    // XML 1.0 §4.4 "Included": a general entity referenced in content has
    // its replacement text parsed as content. §4.5: character references in
    // the declaration are expanded when the replacement text is built.

    #[test]
    fn test_parse_entity_charref_replacement() {
        let doc = parse("<!DOCTYPE d [<!ENTITY e \"caf&#233;\">]><d>&e;</d>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.text_content(root), "caf\u{e9}");
    }

    #[test]
    fn test_parse_entity_nested_reference() {
        let doc = parse("<!DOCTYPE d [<!ENTITY a \"XYZ\"><!ENTITY b \"&a;\">]><d>&b;</d>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.text_content(root), "XYZ");
        // Tree shape: EntityRef(b) -> EntityRef(a) -> Text("XYZ").
        let outer = doc.first_child(root).unwrap();
        let NodeKind::EntityRef { ref name, .. } = doc.node(outer).kind else {
            panic!("expected EntityRef, got {:?}", doc.node(outer).kind);
        };
        assert_eq!(name, "b");
        let inner = doc.first_child(outer).unwrap();
        let NodeKind::EntityRef { ref name, .. } = doc.node(inner).kind else {
            panic!("expected EntityRef, got {:?}", doc.node(inner).kind);
        };
        assert_eq!(name, "a");
    }

    #[test]
    fn test_parse_entity_amp_double_reference() {
        // "&#38;amp;" builds replacement text "&amp;", which is then parsed
        // as content, yielding "&".
        let doc = parse("<!DOCTYPE d [<!ENTITY e \"&#38;amp;\">]><d>&e;</d>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.text_content(root), "&");
    }

    #[test]
    fn test_parse_entity_markup_content() {
        // Markup in the replacement text becomes real element children of
        // the EntityRef node — not escaped text.
        let doc = parse("<!DOCTYPE d [<!ENTITY e \"<b>hi</b>\">]><d>&e;</d>");
        let root = doc.root_element().unwrap();
        assert_eq!(doc.text_content(root), "hi");
        let entity_ref = doc.first_child(root).unwrap();
        let element = doc.first_child(entity_ref).unwrap();
        assert_eq!(doc.node_name(element), Some("b"));
        // Serialization re-emits the entity reference, preserving roundtrip.
        let out = crate::parser_xmloxide::serial::serialize(&doc);
        assert!(
            out.contains("<d>&e;</d>"),
            "unexpected serialization: {out}"
        );
    }

    #[test]
    fn unicode_entity_names_use_the_same_content_parser() {
        // Dispatch must not use an ASCII-only duplicate of XML's Name grammar:
        // a general entity includes markup, irrespective of its name spelling.
        let doc = parse("<!DOCTYPE root [<!ENTITY \u{540d} '<child/>'>]><root>&\u{540d};</root>");
        let root = doc.root_element().unwrap();
        let reference = doc.first_child(root).unwrap();
        assert!(
            matches!(&doc.node(reference).kind, NodeKind::EntityRef { name, .. } if name == "\u{540d}")
        );
        let child = doc.first_child(reference).unwrap();
        assert_eq!(doc.node_name(child), Some("child"));
    }

    #[test]
    fn test_parse_entity_charref_markup() {
        // "&#60;b>hi&#60;/b>" expands to "<b>hi</b>" at declaration time
        // (§4.5) and must be parsed as markup at reference time.
        let doc = parse("<!DOCTYPE d [<!ENTITY e \"&#60;b>hi&#60;/b>\">]><d>&e;</d>");
        let root = doc.root_element().unwrap();
        let entity_ref = doc.first_child(root).unwrap();
        let element = doc.first_child(entity_ref).unwrap();
        assert_eq!(doc.node_name(element), Some("b"));
        assert_eq!(doc.text_content(root), "hi");
    }

    #[test]
    fn test_parse_entity_markup_roundtrip() {
        // parse -> serialize -> parse must preserve the element structure
        // inside the entity expansion.
        let input = "<!DOCTYPE d [<!ENTITY e \"<b>hi</b>\">]><d>&e;</d>";
        let doc = parse(input);
        let out = crate::parser_xmloxide::serial::serialize(&doc);
        let doc2 = parse(&out);
        let root2 = doc2.root_element().unwrap();
        assert_eq!(doc2.text_content(root2), "hi");
        let entity_ref = doc2.first_child(root2).unwrap();
        let element = doc2.first_child(entity_ref).unwrap();
        assert_eq!(doc2.node_name(element), Some("b"));
    }

    #[test]
    fn test_parse_entity_unbalanced_markup_rejected() {
        // §4.3.2: replacement text must match the content production; an
        // unbalanced start tag is not well-formed.
        let result = Document::parse_str("<!DOCTYPE d [<!ENTITY e \"<b>hi\">]><d>&e;</d>");
        assert!(
            result.is_err(),
            "unbalanced entity content must be rejected"
        );
    }

    #[test]
    fn test_parse_entity_split_tags_rejected() {
        // A start tag in one entity and its end tag in another violates
        // WFC: Element Type Match within the replacement text.
        let result = Document::parse_str(
            "<!DOCTYPE d [<!ENTITY open \"<b>\"><!ENTITY close \"</b>\">]><d>&open;hi&close;</d>",
        );
        assert!(result.is_err(), "split tag pair must be rejected");
    }

    #[test]
    fn test_parse_entity_namespace_inherited() {
        // Elements produced by entity expansion resolve namespaces in scope
        // at the point of reference.
        let doc = parse("<!DOCTYPE d [<!ENTITY e \"<b/>\">]><d xmlns=\"urn:x\">&e;</d>");
        let root = doc.root_element().unwrap();
        let entity_ref = doc.first_child(root).unwrap();
        let element = doc.first_child(entity_ref).unwrap();
        let NodeKind::Element { ref namespace, .. } = doc.node(element).kind else {
            panic!("expected Element, got {:?}", doc.node(element).kind);
        };
        assert_eq!(namespace.as_deref(), Some("urn:x"));
    }

    #[test]
    fn test_parse_entity_nesting_depth_limit() {
        // A 40-deep reference chain exceeds MAX_ENTITY_DEPTH when expanded.
        use std::fmt::Write as _;
        let mut dtd = String::from("<!ENTITY e0 \"<b/>\">");
        for i in 1..40u32 {
            let _ = write!(dtd, "<!ENTITY e{i} \"<b>&e{};</b>\">", i - 1);
        }
        let xml = format!("<!DOCTYPE d [{dtd}]><d>&e39;</d>");
        let result = Document::parse_str(&xml);
        let Err(err) = result else {
            panic!("expected depth-limited parse to fail");
        };
        assert!(
            err.syntax_message().contains("depth"),
            "unexpected error message: {}",
            err.syntax_message()
        );
    }

    #[test]
    fn test_parse_entity_amplification_rejected() {
        // Many references to a large entity trip the amplification guard
        // (or the expansion counter) — billion-laughs protection.
        let mut xml = String::from(
            "<!DOCTYPE d [<!ENTITY a \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\">\
             <!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">\
             <!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">\
             <!ENTITY e \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\">]><d>",
        );
        for _ in 0..20 {
            xml.push_str("&e;");
        }
        xml.push_str("</d>");
        let result = Document::parse_str(&xml);
        let Err(err) = result else {
            panic!("expected amplification attack to be rejected");
        };
        assert!(
            err.syntax_message().contains("amplification")
                || err.syntax_message().contains("expansion limit"),
            "unexpected error message: {}",
            err.syntax_message()
        );
    }
}
