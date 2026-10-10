//! Prepared backend DOMs for measuring the real projection independently.

use super::{Document, LexicalPreflight, ParseError, ParsingOptions, XmlBackend};

enum Parsed<'a> {
    Roxmltree(::roxmltree::Document<'a>),
    Xmloxide(::xmloxide::Document),
}

pub(crate) struct Projection<'a> {
    input: &'a str,
    preflight: LexicalPreflight<'a>,
    parsed: Parsed<'a>,
}

impl<'a> Projection<'a> {
    pub(crate) fn new(input: &'a str, backend: XmlBackend) -> Result<Self, ParseError> {
        let preflight = LexicalPreflight::scan(input, false)?;
        let parsed = match backend {
            XmlBackend::Roxmltree => {
                Parsed::Roxmltree(::roxmltree::Document::parse(input).map_err(|e| {
                    ParseError::Backend {
                        backend: "roxmltree",
                        message: e.to_string(),
                    }
                })?)
            }
            XmlBackend::Xmloxide => Parsed::Xmloxide(
                ::xmloxide::parser::parse_str_with_options(
                    input,
                    &super::xmloxide::backend_options(),
                )
                .map_err(|e| ParseError::Backend {
                    backend: "xmloxide",
                    message: e.to_string(),
                })?,
            ),
            XmlBackend::Differential => return Err(ParseError::BackendUnavailable { backend }),
        };
        Ok(Self {
            input,
            preflight,
            parsed,
        })
    }

    pub(crate) fn project(&self) -> Result<Document<'a>, ParseError> {
        match &self.parsed {
            Parsed::Roxmltree(parsed) => {
                super::roxmltree::project(self.input, parsed, &self.preflight)
            }
            Parsed::Xmloxide(parsed) => super::xmloxide::project(
                self.input,
                parsed,
                ParsingOptions::default(),
                &self.preflight,
            ),
        }
    }
}
