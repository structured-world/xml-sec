//! A prepared backend DOM for measuring its projection independently. Only
//! roxmltree has one: xmloxide builds the semantic arena as it parses.

use super::{Document, LexicalPreflight, ParseError, XmlBackend};
use crate::parser_roxmltree;

pub(crate) struct Projection<'a> {
    input: &'a str,
    preflight: LexicalPreflight<'a>,
    parsed: parser_roxmltree::Document<'a>,
}

impl<'a> Projection<'a> {
    pub(crate) fn new(input: &'a str, backend: XmlBackend) -> Result<Self, ParseError> {
        if backend != XmlBackend::Roxmltree {
            return Err(ParseError::BackendUnavailable { backend });
        }
        let preflight = LexicalPreflight::scan(input, false)?;
        let parsed = parser_roxmltree::Document::parse(input).map_err(|e| ParseError::Backend {
            backend: "roxmltree",
            message: e.to_string(),
        })?;
        Ok(Self {
            input,
            preflight,
            parsed,
        })
    }

    pub(crate) fn project(self) -> Result<Document<'a>, ParseError> {
        super::roxmltree::project(self.input, &self.parsed, &self.preflight)
    }
}
