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
        let roxmltree = RoxmltreeBackend::parse(input, options, preflight);
        let xmloxide = XmloxideBackend::parse(input, options, preflight);

        match (roxmltree, xmloxide) {
            (Ok(roxmltree), Ok(xmloxide)) => {
                roxmltree.ensure_semantically_equivalent(&xmloxide, preflight.doctype_range())?;
                Ok(xmloxide)
            }
            (Err(left), Err(right)) if equivalent_rejection(&left, &right) => Err(right),
            (left, right) => Err(ParseError::BackendDivergence {
                reason: acceptance_summary(&left, &right),
            }),
        }
    }
}

fn equivalent_rejection(left: &ParseError, right: &ParseError) -> bool {
    matches!(
        (left, right),
        (
            ParseError::ByteLimitReached { .. },
            ParseError::ByteLimitReached { .. }
        ) | (ParseError::DtdDetected, ParseError::DtdDetected)
            | (ParseError::NodesLimitReached, ParseError::NodesLimitReached)
            | (
                ParseError::EntityExpansionLimitReached { .. },
                ParseError::EntityExpansionLimitReached { .. }
            )
            | (
                ParseError::EntityExpansionWorkLimitReached { .. },
                ParseError::EntityExpansionWorkLimitReached { .. }
            )
            | (
                ParseError::SourcePositionLimitReached { .. },
                ParseError::SourcePositionLimitReached { .. }
            )
            | (
                ParseError::DepthLimitReached { .. },
                ParseError::DepthLimitReached { .. }
            )
            | (ParseError::Backend { .. }, ParseError::Backend { .. })
    )
}

fn acceptance_summary(
    roxmltree: &Result<Document<'_>, ParseError>,
    xmloxide: &Result<Document<'_>, ParseError>,
) -> String {
    let state = |result: &Result<Document<'_>, ParseError>| match result {
        Ok(_) => "accepted",
        Err(ParseError::ByteLimitReached { .. }) => "rejected by byte limit",
        Err(ParseError::DtdDetected) => "rejected as DTD-disabled",
        Err(ParseError::NodesLimitReached) => "rejected by node limit",
        Err(ParseError::EntityExpansionLimitReached { .. }) => "rejected by entity expansion limit",
        Err(ParseError::EntityExpansionWorkLimitReached { .. }) => {
            "rejected by entity expansion-work limit"
        }
        Err(ParseError::SourcePositionLimitReached { .. }) => "rejected by source-position limit",
        Err(ParseError::DepthLimitReached { .. }) => "rejected by depth limit",
        Err(ParseError::BackendUnavailable { .. }) => "rejected as unavailable",
        Err(ParseError::Backend { .. }) => "rejected as malformed",
        Err(ParseError::BackendDivergence { .. }) => "reported nested divergence",
    };
    format!(
        "roxmltree {}, xmloxide {}",
        state(roxmltree),
        state(xmloxide)
    )
}
