//! Borrowed parameter views shared by template-owned and original instructions.

use super::TransformError;
use super::{RelationshipSelector, Transform, XPathHereNodes, source::Source};
use super::{
    XPathDocumentIdentity, XPathExpression, XPathFilter, XPathFilterOperation, XPathHereSemantics,
};
use crate::c14n::C14nAlgorithm;
use crate::c14n::scratch::{Accounted, Native, Scratch};
use crate::xml::dom::Node;
use crate::xml::dom::NodeId;
use crate::xmldsig::parse::ParseError;
use structured_asn1::memory::{OwnedText, OwnedVec, Work};

pub(crate) enum Diagnostic {
    XPath,
    Unsupported,
    #[cfg(feature = "xslt")]
    Xslt,
}

fn current_text<W: Work>(
    arguments: std::fmt::Arguments<'_>,
    work: &W,
) -> Result<OwnedText, TransformError> {
    use crate::xml::dom::storage::Storage as _;
    match crate::xml::dom::storage::Accounted(work).formatted(arguments) {
        Ok(message) => Ok(message.into_owned()),
        Err(crate::xml::dom::ParseError::SharedExecution(cause)) => Err(cause.into()),
        Err(cause) => Err(TransformError::XmlParse(
            crate::document::XmlDocumentError::Parse(cause),
        )),
    }
}

pub(crate) fn current_diagnostic<W: Work>(
    kind: Diagnostic,
    arguments: std::fmt::Arguments<'_>,
    work: &W,
) -> TransformError {
    match current_text(arguments, work) {
        Ok(message) => match kind {
            Diagnostic::XPath => TransformError::AccountedXPath(message),
            Diagnostic::Unsupported => TransformError::AccountedUnsupportedTransform(message),
            #[cfg(feature = "xslt")]
            Diagnostic::Xslt => TransformError::AccountedXslt(message),
        },
        Err(cause) => cause,
    }
}

pub(crate) trait Expression {
    fn expression(&self) -> &str;
    fn namespaces(&self) -> impl Iterator<Item = (&str, &str)>;
    fn here_context_node(&self, semantics: XPathHereSemantics) -> Option<NodeId>;
    fn parsed_document_identity(&self) -> Option<XPathDocumentIdentity>;
}

impl Expression for XPathExpression {
    fn expression(&self) -> &str {
        self.expression()
    }

    fn namespaces(&self) -> impl Iterator<Item = (&str, &str)> {
        self.namespaces()
            .iter()
            .map(|(prefix, uri)| (prefix.as_str(), uri.as_str()))
    }

    fn here_context_node(&self, semantics: XPathHereSemantics) -> Option<NodeId> {
        self.here_context_node(semantics)
    }

    fn parsed_document_identity(&self) -> Option<XPathDocumentIdentity> {
        self.parsed_document_identity()
    }
}

pub(crate) trait Filter {
    type Expression: Expression;
    fn operation(&self) -> XPathFilterOperation;
    fn xpath(&self) -> &Self::Expression;
}

impl Filter for XPathFilter {
    type Expression = XPathExpression;

    fn operation(&self) -> XPathFilterOperation {
        self.operation()
    }

    fn xpath(&self) -> &Self::Expression {
        self.xpath()
    }
}

pub(crate) trait Selector {
    fn parameter(&self) -> (&'static str, &'static str, &str);
}

impl Selector for RelationshipSelector {
    fn parameter(&self) -> (&'static str, &'static str, &str) {
        self.parameter()
    }
}

pub(crate) trait Instruction: Sized {
    type Expression: Expression;
    type Filter: Filter<Expression = Self::Expression>;
    type Selector: Selector;
    fn view(&self) -> View<'_, Self>;

    fn algorithm_uri(&self) -> &'static str {
        match self.view() {
            View::Enveloped => super::ENVELOPED_SIGNATURE_URI,
            View::ExcludeSignatures | View::XPath(_) => super::XPATH_TRANSFORM_URI,
            View::Filter2(_) => super::XPATH_FILTER2_TRANSFORM_URI,
            View::C14n(algorithm, _) => algorithm.uri(),
            View::Base64 => super::BASE64_TRANSFORM_URI,
            View::Relationship(_) => super::RELATIONSHIP_TRANSFORM_URI,
            #[cfg(feature = "xslt")]
            View::Xslt(_) => super::XSLT_TRANSFORM_URI,
        }
    }
}

pub(crate) enum View<'a, I: Instruction> {
    Enveloped,
    ExcludeSignatures,
    XPath(&'a I::Expression),
    Filter2(&'a [I::Filter]),
    C14n(&'a C14nAlgorithm, Option<&'a str>),
    Base64,
    Relationship(&'a [I::Selector]),
    /// Stylesheet parameter.
    #[cfg(feature = "xslt")]
    Xslt(super::xslt::XsltParameter<'a>),
}

impl Instruction for Transform {
    type Expression = XPathExpression;
    type Filter = XPathFilter;
    type Selector = RelationshipSelector;

    fn view(&self) -> View<'_, Self> {
        match self {
            Self::Enveloped => View::Enveloped,
            Self::XpathExcludeAllSignatures => View::ExcludeSignatures,
            Self::XPath(expression) => View::XPath(expression),
            Self::XPathFilter2(filters) => View::Filter2(filters),
            Self::C14n(algorithm) => View::C14n(algorithm, None),
            Self::Base64Decode => View::Base64,
            Self::Relationship(selectors) => View::Relationship(selectors),
            #[cfg(feature = "xslt")]
            Self::Xslt(stylesheet) => {
                View::Xslt(super::xslt::XsltParameter::Stylesheet(stylesheet))
            }
        }
    }
}

pub(crate) trait ParseStorage<'a>: Scratch {
    type Expression: Expression;
    type Filter: Filter<Expression = Self::Expression>;
    type Selector: Selector;
    type Instruction: Instruction<Expression = Self::Expression, Filter = Self::Filter, Selector = Self::Selector>;
    fn validate_xpath(
        &self,
        source: &str,
        bytes: usize,
        complexity: usize,
    ) -> Result<(), TransformError>;
    fn diagnostic(&self, kind: Diagnostic, arguments: std::fmt::Arguments<'_>) -> TransformError;
    /// Structural diagnostic owned by this storage, as transform diagnostics are.
    fn structure(&self, arguments: std::fmt::Arguments<'_>) -> ParseError;
    /// Unsupported-algorithm diagnostic owned by this storage.
    fn unsupported_algorithm(&self, uri: &str) -> ParseError;
    fn unsupported(&self, arguments: std::fmt::Arguments<'_>) -> TransformError {
        self.diagnostic(Diagnostic::Unsupported, arguments)
    }
    fn xpath_error(&self, arguments: std::fmt::Arguments<'_>) -> TransformError {
        self.diagnostic(Diagnostic::XPath, arguments)
    }
    fn expression(
        &self,
        source: Source<'a, Self::Text>,
        node: Node<'a, 'a>,
        here: XPathHereNodes,
    ) -> Self::Expression;
    fn filter(&self, operation: XPathFilterOperation, expression: Self::Expression)
    -> Self::Filter;
    fn selector(&self, id: bool, value: &'a str) -> Self::Selector;
    fn enveloped(&self) -> Self::Instruction;
    fn exclude_signatures(&self) -> Self::Instruction;
    fn base64(&self) -> Self::Instruction;
    fn xpath(&self, expression: Self::Expression) -> Self::Instruction;
    fn filters(&self, filters: Self::Values<Self::Filter>) -> Self::Instruction;
    fn relationships(&self, selectors: Self::Values<Self::Selector>) -> Self::Instruction;
    fn canonicalization(
        &self,
        algorithm: C14nAlgorithm,
        prefixes: Option<&'a str>,
    ) -> Self::Instruction;
    /// The stylesheet of an original `<Transform>`, whose content is `source`.
    #[cfg(feature = "xslt")]
    fn xslt(&self, transform: Node<'a, 'a>, source: &'a str) -> Self::Instruction;
}

impl<'a> ParseStorage<'a> for Native {
    type Expression = XPathExpression;
    type Filter = XPathFilter;
    type Selector = RelationshipSelector;
    type Instruction = Transform;

    fn diagnostic(&self, kind: Diagnostic, arguments: std::fmt::Arguments<'_>) -> TransformError {
        let message = std::fmt::format(arguments);
        match kind {
            Diagnostic::XPath => TransformError::XPath(message),
            Diagnostic::Unsupported => TransformError::UnsupportedTransform(message),
            #[cfg(feature = "xslt")]
            Diagnostic::Xslt => TransformError::Xslt(message),
        }
    }

    fn structure(&self, arguments: std::fmt::Arguments<'_>) -> ParseError {
        ParseError::InvalidStructure(std::fmt::format(arguments))
    }

    fn unsupported_algorithm(&self, uri: &str) -> ParseError {
        ParseError::UnsupportedAlgorithm {
            uri: uri.to_owned(),
        }
    }

    fn validate_xpath(
        &self,
        source: &str,
        bytes: usize,
        complexity: usize,
    ) -> Result<(), TransformError> {
        crate::xmldsig::xpath::compile_native_xpath(source, bytes, complexity).map(|_| ())
    }

    fn expression(
        &self,
        source: Source<'a, String>,
        node: Node<'a, 'a>,
        here: XPathHereNodes,
    ) -> XPathExpression {
        XPathExpression {
            expression: source.into_string(),
            namespaces: node
                .namespaces()
                .filter_map(|binding| {
                    binding
                        .name()
                        .map(|prefix| (prefix.to_owned(), binding.uri().to_owned()))
                })
                .collect(),
            here_nodes: Some(here),
        }
    }
    fn filter(&self, operation: XPathFilterOperation, expression: XPathExpression) -> XPathFilter {
        XPathFilter::new(operation, expression)
    }
    fn selector(&self, id: bool, value: &'a str) -> RelationshipSelector {
        if id {
            RelationshipSelector::SourceId(value.to_owned())
        } else {
            RelationshipSelector::SourceType(value.to_owned())
        }
    }
    fn enveloped(&self) -> Transform {
        Transform::Enveloped
    }
    fn exclude_signatures(&self) -> Transform {
        Transform::XpathExcludeAllSignatures
    }
    fn base64(&self) -> Transform {
        Transform::Base64Decode
    }
    fn xpath(&self, expression: XPathExpression) -> Transform {
        Transform::XPath(expression)
    }
    fn filters(&self, filters: Vec<XPathFilter>) -> Transform {
        Transform::XPathFilter2(filters)
    }
    fn relationships(&self, selectors: Vec<RelationshipSelector>) -> Transform {
        Transform::Relationship(selectors)
    }
    fn canonicalization(
        &self,
        mut algorithm: C14nAlgorithm,
        prefixes: Option<&'a str>,
    ) -> Transform {
        if let Some(prefixes) = prefixes {
            algorithm = algorithm.with_prefix_list(prefixes);
        }
        Transform::C14n(algorithm)
    }
    #[cfg(feature = "xslt")]
    fn xslt(&self, transform: Node<'a, 'a>, source: &'a str) -> Transform {
        // The source is the markup of a parsed `<Transform>`, which `XsltStylesheet::new`
        // would only parse again; keep it as is.
        Transform::Xslt(super::XsltStylesheet::from_parsed(transform, source))
    }
}

pub(crate) struct OriginalExpression<'a> {
    source: Source<'a, OwnedText>,
    node: Node<'a, 'a>,
    here: XPathHereNodes,
}

impl Expression for OriginalExpression<'_> {
    fn expression(&self) -> &str {
        self.source.as_ref()
    }
    fn namespaces(&self) -> impl Iterator<Item = (&str, &str)> {
        self.node
            .namespaces()
            .filter_map(|binding| binding.name().map(|prefix| (prefix, binding.uri())))
    }
    fn here_context_node(&self, semantics: XPathHereSemantics) -> Option<NodeId> {
        Some(match semantics {
            XPathHereSemantics::Specification => self.here.specification_xpath_element,
            XPathHereSemantics::XmlSecLegacy => self.here.xmlsec_legacy_transform_element,
        })
    }
    fn parsed_document_identity(&self) -> Option<XPathDocumentIdentity> {
        Some(self.here.document)
    }
}

pub(crate) struct OriginalFilter<'a> {
    operation: XPathFilterOperation,
    expression: OriginalExpression<'a>,
}
impl<'a> Filter for OriginalFilter<'a> {
    type Expression = OriginalExpression<'a>;
    fn operation(&self) -> XPathFilterOperation {
        self.operation
    }
    fn xpath(&self) -> &Self::Expression {
        &self.expression
    }
}

pub(crate) struct OriginalSelector<'a> {
    id: bool,
    value: &'a str,
}
impl Selector for OriginalSelector<'_> {
    fn parameter(&self) -> (&'static str, &'static str, &str) {
        if self.id {
            ("RelationshipReference", "SourceId", self.value)
        } else {
            ("RelationshipsGroupReference", "SourceType", self.value)
        }
    }
}

// Only immutable parameter views escape bounded construction. Erasing the
// construction Work moves existing owners/charges, not their data or account,
// and keeps slot layout independent of Memory versus a scoped Execution.
pub(crate) enum OriginalInstruction<'a> {
    Enveloped,
    ExcludeSignatures,
    Base64,
    XPath(OriginalExpression<'a>),
    Filters(OwnedVec<OriginalFilter<'a>>),
    Relationships(OwnedVec<OriginalSelector<'a>>),
    Canonicalization(C14nAlgorithm, Option<&'a str>),
    /// The original `<Transform>` element.
    #[cfg(feature = "xslt")]
    Xslt(Node<'a, 'a>),
}
impl<'a> Instruction for OriginalInstruction<'a> {
    type Expression = OriginalExpression<'a>;
    type Filter = OriginalFilter<'a>;
    type Selector = OriginalSelector<'a>;
    fn view(&self) -> View<'_, Self> {
        match self {
            Self::Enveloped => View::Enveloped,
            Self::ExcludeSignatures => View::ExcludeSignatures,
            Self::Base64 => View::Base64,
            Self::XPath(expression) => View::XPath(expression),
            Self::Filters(filters) => View::Filter2(filters),
            Self::Relationships(selectors) => View::Relationship(selectors),
            Self::Canonicalization(algorithm, prefixes) => View::C14n(algorithm, *prefixes),
            #[cfg(feature = "xslt")]
            Self::Xslt(transform) => View::Xslt(super::xslt::XsltParameter::Transform(*transform)),
        }
    }
}
impl<'a, W: Work> ParseStorage<'a> for Accounted<'_, W> {
    type Expression = OriginalExpression<'a>;
    type Filter = OriginalFilter<'a>;
    type Selector = OriginalSelector<'a>;
    type Instruction = OriginalInstruction<'a>;

    fn diagnostic(&self, kind: Diagnostic, arguments: std::fmt::Arguments<'_>) -> TransformError {
        current_diagnostic(kind, arguments, self.0)
    }

    fn structure(&self, arguments: std::fmt::Arguments<'_>) -> ParseError {
        current_text(arguments, self.0)
            .map_or_else(ParseError::Transform, ParseError::AccountedInvalidStructure)
    }

    fn unsupported_algorithm(&self, uri: &str) -> ParseError {
        current_text(format_args!("{uri}"), self.0).map_or_else(ParseError::Transform, |uri| {
            ParseError::AccountedUnsupportedAlgorithm { uri }
        })
    }

    fn validate_xpath(
        &self,
        source: &str,
        _bytes: usize,
        _complexity: usize,
    ) -> Result<(), TransformError> {
        crate::xmldsig::xpath::validate_xpath_current(source, self)
    }
    fn expression(
        &self,
        source: Source<'a, OwnedText<W>>,
        node: Node<'a, 'a>,
        here: XPathHereNodes,
    ) -> Self::Expression {
        OriginalExpression {
            source: source.map_owned(OwnedText::into_owned),
            node,
            here,
        }
    }
    fn filter(
        &self,
        operation: XPathFilterOperation,
        expression: Self::Expression,
    ) -> Self::Filter {
        OriginalFilter {
            operation,
            expression,
        }
    }
    fn selector(&self, id: bool, value: &'a str) -> Self::Selector {
        OriginalSelector { id, value }
    }
    fn enveloped(&self) -> Self::Instruction {
        OriginalInstruction::Enveloped
    }
    fn exclude_signatures(&self) -> Self::Instruction {
        OriginalInstruction::ExcludeSignatures
    }
    fn base64(&self) -> Self::Instruction {
        OriginalInstruction::Base64
    }
    fn xpath(&self, expression: Self::Expression) -> Self::Instruction {
        OriginalInstruction::XPath(expression)
    }
    fn filters(&self, filters: OwnedVec<Self::Filter, W>) -> Self::Instruction {
        OriginalInstruction::Filters(filters.into_owned())
    }
    fn relationships(&self, selectors: OwnedVec<Self::Selector, W>) -> Self::Instruction {
        OriginalInstruction::Relationships(selectors.into_owned())
    }
    fn canonicalization(
        &self,
        algorithm: C14nAlgorithm,
        prefixes: Option<&'a str>,
    ) -> Self::Instruction {
        OriginalInstruction::Canonicalization(algorithm, prefixes)
    }
    #[cfg(feature = "xslt")]
    fn xslt(&self, transform: Node<'a, 'a>, _source: &'a str) -> Self::Instruction {
        // The markup and inherited declarations are read from the element when executed.
        OriginalInstruction::Xslt(transform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmldsig::transforms::{
        XPathSignatureParseBudget, parse_reference_transforms_in, parse_transforms,
    };
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

    #[test]
    fn malformed_parameter_diagnostics_keep_current_capacity_and_refusal() {
        // A retained instruction may contain a large unknown URI or Filter
        // value. Error handling must not copy it into an unaccounted String.
        let value = "x".repeat(65536);
        for (child, xpath) in [
            (
                format!("<Transform Algorithm='urn:unknown:{value}'/>"),
                false,
            ),
            (
                format!(
                    "<Transform Algorithm='http://www.w3.org/2002/06/xmldsig-filter2'><f:XPath xmlns:f='http://www.w3.org/2002/06/xmldsig-filter2' Filter='{value}'>/</f:XPath></Transform>"
                ),
                true,
            ),
        ] {
            let xml = format!(
                "<Transforms xmlns='http://www.w3.org/2000/09/xmldsig#'>{child}</Transforms>"
            );
            let document =
                crate::xml::dom::Document::parse(&xml).expect("well-formed parameter XML");
            for bytes in [4096, 1 << 20] {
                let work = Memory::new(Arc::new(MemoryAccount::new(bytes, 1 << 24)));
                let error = parse_reference_transforms_in(
                    document.root_element(),
                    super::super::XMLDSIG_NS,
                    &mut XPathSignatureParseBudget::default(),
                    &Accounted(&work),
                )
                .err()
                .expect("invalid parameter must be rejected");
                if bytes == 4096 {
                    assert!(matches!(
                        error,
                        TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                            MemoryError::LimitExceeded
                        ))
                    ));
                    assert_eq!(work.used(), 0);
                } else {
                    let message = match &error {
                        TransformError::AccountedXPath(message) if xpath => message,
                        TransformError::AccountedUnsupportedTransform(message) if !xpath => message,
                        _ => panic!("unexpected diagnostic: {error}"),
                    };
                    assert!(message.ends_with(&value));
                    assert_eq!(work.used(), message.capacity());
                }
                drop(error);
                assert_eq!(work.used(), 0);
            }
        }
    }

    #[test]
    fn original_xpath_borrows_source_and_effective_namespace_bindings() {
        // Parameters already owned by the original semantic document need no
        // duplicate strings/map. Here identity and namespace meaning remain exact.
        let document = crate::xml::dom::Document::parse(concat!(
            "<Transforms xmlns='http://www.w3.org/2000/09/xmldsig#' xmlns:p='urn:original'>",
            "<Transform Algorithm='http://www.w3.org/TR/1999/REC-xpath-19991116'>",
            "<XPath>count(//p:item)</XPath></Transform></Transforms>"
        ))
        .expect("fixed parameter XML");
        let work = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let original = parse_reference_transforms_in(
            document.root_element(),
            super::super::XMLDSIG_NS,
            &mut XPathSignatureParseBudget::default(),
            &Accounted(&work),
        )
        .expect("original parameters");
        let native = parse_transforms(document.root_element()).expect("template-owned parameters");
        let View::XPath(original_expression) = original[0].view() else {
            panic!("expected original XPath");
        };
        let Transform::XPath(native_expression) = &native[0] else {
            panic!("expected native XPath");
        };
        assert_eq!(
            original_expression.expression(),
            native_expression.expression()
        );
        let native_bindings =
            Expression::namespaces(native_expression).collect::<std::collections::BTreeMap<_, _>>();
        let original_bindings = original_expression
            .namespaces()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(original_bindings, native_bindings);
        let xpath = document
            .root_element()
            .first_element_child()
            .expect("Transform")
            .first_element_child()
            .expect("XPath");
        assert!(std::ptr::eq(
            original_expression.expression().as_ptr(),
            xpath.text().expect("XPath source").as_ptr()
        ));
        assert_eq!(
            original_expression.here_context_node(XPathHereSemantics::Specification),
            Some(xpath.id())
        );
        assert_eq!(
            work.used(),
            original.capacity() * std::mem::size_of_val(&original[0])
        );
        drop(original);
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn original_xpath_join_cannot_use_the_chain_reservation_as_its_owner() {
        // A split lexical value must acquire its own live allocation before
        // concatenation, not hide behind the enclosing instruction's charge.
        let plain = crate::xml::dom::Document::parse(concat!(
            "<Transforms xmlns='http://www.w3.org/2000/09/xmldsig#'>",
            "<Transform Algorithm='http://www.w3.org/TR/1999/REC-xpath-19991116'>",
            "<XPath>count(//item)</XPath></Transform></Transforms>"
        ))
        .expect("fixed contiguous source");
        let split = crate::xml::dom::Document::parse(concat!(
            "<Transforms xmlns='http://www.w3.org/2000/09/xmldsig#'>",
            "<Transform Algorithm='http://www.w3.org/TR/1999/REC-xpath-19991116'>",
            "<XPath>count(<!--split-->//item)</XPath></Transform></Transforms>"
        ))
        .expect("fixed fragmented source");
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let chain = parse_reference_transforms_in(
            plain.root_element(),
            super::super::XMLDSIG_NS,
            &mut XPathSignatureParseBudget::default(),
            &Accounted(&memory),
        )
        .expect("borrowed source");
        let chain_bytes = memory.used();
        drop(chain);
        assert_eq!(memory.used(), 0);
        let current = Memory::new(Arc::new(MemoryAccount::new(chain_bytes, 1 << 20)));
        let result = parse_reference_transforms_in(
            split.root_element(),
            super::super::XMLDSIG_NS,
            &mut XPathSignatureParseBudget::default(),
            &Accounted(&current),
        );
        assert!(matches!(
            result,
            Err(TransformError::C14n(
                crate::c14n::C14nError::SharedExecution(MemoryError::LimitExceeded)
            ))
        ));
        assert_eq!(current.used(), 0);
    }
}
