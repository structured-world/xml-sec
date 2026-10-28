//! Fail-closed semantic comparison of both XML parser adapters.

use super::{
    Document, LexicalPreflight, ParseError, ParsingOptions, XmlBackendImplementation,
    roxmltree::RoxmltreeBackend, xmloxide::XmloxideBackend,
};

pub(super) struct DifferentialBackend;

impl XmlBackendImplementation for DifferentialBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError> {
        parse_pair(
            || RoxmltreeBackend::parse(input, options, preflight),
            || XmloxideBackend::parse(input, options, preflight),
            preflight.doctype_range(),
        )
    }
}

fn parse_pair<'input>(
    left: impl FnOnce() -> Result<Document<'input>, ParseError>,
    right: impl FnOnce() -> Result<Document<'input>, ParseError>,
    doctype: Option<&core::ops::Range<usize>>,
) -> Result<Document<'input>, ParseError> {
    parse_pair_in(left, right, doctype, super::storage::Native)
}

#[cfg(feature = "xmldsig")]
pub(super) fn parse_in<'input, 'w, W: structured_asn1::memory::Work>(
    input: &'input str,
    options: ParsingOptions,
    preflight: &LexicalPreflight<'input, super::storage::Accounted<'w, W>>,
    storage: super::storage::Accounted<'w, W>,
) -> Result<Document<'input, super::storage::Accounted<'w, W>>, super::AccountedParseError> {
    parse_pair_in(
        || RoxmltreeBackend::parse_in(input, options, preflight, storage),
        || XmloxideBackend::parse_in(input, options, preflight, storage),
        preflight.doctype_range(),
        storage,
    )
}

fn parse_pair_in<'input, S: super::tree::comparison::ComparisonStorage>(
    left: impl FnOnce() -> Result<Document<'input, S>, S::ParseFailure>,
    right: impl FnOnce() -> Result<Document<'input, S>, S::ParseFailure>,
    doctype: Option<&core::ops::Range<usize>>,
    storage: S,
) -> Result<Document<'input, S>, S::ParseFailure>
where
    S::ParseFailure: Failure,
{
    let roxmltree = left();
    if let Err(error) = &roxmltree
        && error.kind().resource()
    {
        return roxmltree;
    }
    let xmloxide = right();
    if let Err(error) = &xmloxide
        && error.kind().resource()
    {
        return xmloxide;
    }
    match (roxmltree, xmloxide) {
        (Ok(roxmltree), Ok(xmloxide)) => {
            roxmltree.ensure_semantically_equivalent_in(&xmloxide, doctype, storage)?;
            Ok(xmloxide)
        }
        (Err(left), Err(right)) if left.kind().equivalent(right.kind()) => Err(right),
        (left, right) => Err(S::divergence(storage.formatted(format_args!(
            "roxmltree {}, xmloxide {}",
            outcome(&left),
            outcome(&right),
        ))?)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    Allocation,
    #[cfg(feature = "xmldsig")]
    Execution,
    Bytes,
    Dtd,
    Nodes,
    Entities,
    EntityWork,
    Positions,
    Depth,
    Namespaces,
    Unavailable,
    Malformed,
    SourceMap,
    Divergence,
}
impl FailureKind {
    fn resource(self) -> bool {
        match self {
            Self::Allocation => true,
            #[cfg(feature = "xmldsig")]
            Self::Execution => true,
            _ => false,
        }
    }
    fn equivalent(self, other: Self) -> bool {
        self == other && !self.resource() && !matches!(self, Self::Unavailable | Self::Divergence)
    }
    fn label(self) -> &'static str {
        match self {
            Self::Allocation => "allocation refused",
            #[cfg(feature = "xmldsig")]
            Self::Execution => "execution refused",
            Self::Bytes => "rejected by byte limit",
            Self::Dtd => "rejected as DTD-disabled",
            Self::Nodes => "rejected by node limit",
            Self::Entities => "rejected by entity expansion limit",
            Self::EntityWork => "rejected by entity expansion-work limit",
            Self::Positions => "rejected by source-position limit",
            Self::Depth => "rejected by depth limit",
            Self::Namespaces => "rejected by namespace binding limit",
            Self::Unavailable => "rejected as unavailable",
            Self::Malformed => "rejected as malformed",
            Self::SourceMap => "rejected by source mapping",
            Self::Divergence => "reported nested divergence",
        }
    }
}
trait Failure {
    fn kind(&self) -> FailureKind;
}
impl Failure for ParseError {
    fn kind(&self) -> FailureKind {
        match self {
            ParseError::AllocationFailed => FailureKind::Allocation,
            #[cfg(feature = "xmldsig")]
            ParseError::SharedExecution(_) => FailureKind::Execution,
            ParseError::ByteLimitReached { .. } => FailureKind::Bytes,
            ParseError::DtdDetected => FailureKind::Dtd,
            ParseError::NodesLimitReached => FailureKind::Nodes,
            ParseError::EntityExpansionLimitReached { .. } => FailureKind::Entities,
            ParseError::EntityExpansionWorkLimitReached { .. } => FailureKind::EntityWork,
            ParseError::SourcePositionLimitReached { .. } => FailureKind::Positions,
            ParseError::DepthLimitReached { .. } => FailureKind::Depth,
            ParseError::NamespaceBindingLimitReached { .. } => FailureKind::Namespaces,
            ParseError::BackendUnavailable { .. } => FailureKind::Unavailable,
            ParseError::Backend { .. } => FailureKind::Malformed,
            ParseError::SourceMapMismatch { .. } => FailureKind::SourceMap,
            ParseError::BackendDivergence { .. } => FailureKind::Divergence,
        }
    }
}

#[cfg(feature = "xmldsig")]
impl Failure for super::AccountedParseError {
    fn kind(&self) -> FailureKind {
        use super::AccountedParseError;
        match self {
            AccountedParseError::Semantic(error)
            | AccountedParseError::Xmloxide(crate::parser_xmloxide::error::ParseError::Resource(
                error,
            )) => error.kind(),
            AccountedParseError::Lexical(crate::xml_input::lexical::Error::Resource(_))
            | AccountedParseError::Roxmltree(crate::parser_roxmltree::Error::SharedExecution(_)) => {
                FailureKind::Execution
            }
            AccountedParseError::Roxmltree(crate::parser_roxmltree::Error::AllocationFailed) => {
                FailureKind::Allocation
            }
            AccountedParseError::Roxmltree(crate::parser_roxmltree::Error::DtdDetected) => {
                FailureKind::Dtd
            }
            AccountedParseError::Roxmltree(crate::parser_roxmltree::Error::NodesLimitReached) => {
                FailureKind::Nodes
            }
            AccountedParseError::Divergence(_) => FailureKind::Divergence,
            _ => FailureKind::Malformed,
        }
    }
}

fn outcome<T, E: Failure>(result: &Result<T, E>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(error) => error.kind().label(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_refusal_is_terminal_before_the_second_backend() {
        // Resource refusal is not XML rejection or backend disagreement. Do
        // not execute another parser after the operation has been exhausted.
        let second_called = std::cell::Cell::new(false);
        let result = parse_pair(
            || Err(ParseError::AllocationFailed),
            || {
                second_called.set(true);
                Err(ParseError::DtdDetected)
            },
            None,
        );
        assert!(matches!(result, Err(ParseError::AllocationFailed)));
        assert!(!second_called.get());
    }
}
