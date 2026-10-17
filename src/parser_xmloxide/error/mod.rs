//! Error types and diagnostics for XML parsing.
//!
//! This module provides structured error reporting with source location tracking,
//! matching libxml2's error reporting model. Errors carry line, column, and byte
//! offset information for precise diagnostics.
//!
//! The parser supports **error recovery mode**: it collects errors into a
//! `Vec<ParseDiagnostic>` while still producing a (possibly partial) tree.

use std::fmt;

/// Severity level for a parse diagnostic, matching libxml2's `xmlErrorLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorSeverity {
    /// A non-fatal issue that doesn't prevent parsing.
    Warning,
    /// A recoverable error — the parser can continue but the document is malformed.
    Error,
    /// An unrecoverable error — parsing must stop.
    Fatal,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Fatal => write!(f, "fatal error"),
        }
    }
}

/// Source location within an XML document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SourceLocation {
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number (in characters, not bytes).
    pub column: u32,
    /// 0-based byte offset from the start of the input.
    pub byte_offset: usize,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// A single diagnostic emitted during parsing.
///
/// Diagnostics are collected when the parser operates in recovery mode,
/// allowing it to produce a partial tree even when the input is malformed.
#[derive(Debug, Clone)]
pub struct ParseDiagnostic<L = String> {
    /// The severity of this diagnostic.
    pub severity: ErrorSeverity,
    /// Human-readable error message.
    pub message: L,
    /// Where in the source this error occurred.
    pub location: SourceLocation,
}

impl<L: fmt::Display> fmt::Display for ParseDiagnostic<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} at {}",
            self.severity, self.message, self.location
        )
    }
}

/// The error type returned when XML parsing fails.
#[derive(Debug, Clone)]
pub enum ParseError<L = String, D = Vec<ParseDiagnostic<L>>> {
    /// Original syntax diagnostic and its retained, preceding diagnostics.
    Syntax {
        message: L,
        location: SourceLocation,
        diagnostics: D,
    },
    /// A construction refusal is terminal, not malformed XML.
    Resource(crate::xml::dom::ParseError),
}

impl<L, D> ParseError<L, D> {
    pub fn message(&self) -> Option<&L> {
        match self {
            Self::Syntax { message, .. } => Some(message),
            Self::Resource(_) => None,
        }
    }
    #[cfg(test)]
    pub(crate) fn syntax_message(&self) -> &L {
        self.message()
            .expect("expected a syntax rejection, not a resource refusal")
    }
}

impl<L, D> From<crate::xml::dom::ParseError> for ParseError<L, D> {
    fn from(error: crate::xml::dom::ParseError) -> Self {
        Self::Resource(error)
    }
}

impl<L: fmt::Display, D> fmt::Display for ParseError<L, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax {
                message, location, ..
            } => write!(f, "parse error at {location}: {message}"),
            Self::Resource(error) => write!(f, "XML parser construction: {error}"),
        }
    }
}

impl<L: fmt::Debug + fmt::Display, D: fmt::Debug> std::error::Error for ParseError<L, D> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resource(error) => Some(error),
            Self::Syntax { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_refusal_does_not_fabricate_a_syntax_message() {
        // An exhausted construction must retain its typed cause without
        // allocating a label or being accepted as malformed XML instead.
        let error: ParseError = crate::xml::dom::ParseError::AllocationFailed.into();
        assert!(error.message().is_none());
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<crate::xml::dom::ParseError>()
                .is_some()
        );
    }

    #[test]
    fn test_source_location_display() {
        let loc = SourceLocation {
            line: 10,
            column: 5,
            byte_offset: 42,
        };
        assert_eq!(loc.to_string(), "10:5");
    }

    #[test]
    fn test_parse_error_display() {
        let err: ParseError = ParseError::Syntax {
            message: "unexpected end of input".to_string(),
            location: SourceLocation {
                line: 1,
                column: 15,
                byte_offset: 14,
            },
            diagnostics: vec![],
        };
        assert_eq!(
            err.to_string(),
            "parse error at 1:15: unexpected end of input"
        );
    }

    #[test]
    fn test_parse_diagnostic_display() {
        let diag = ParseDiagnostic {
            severity: ErrorSeverity::Warning,
            message: "attribute value not quoted".to_string(),
            location: SourceLocation {
                line: 3,
                column: 10,
                byte_offset: 50,
            },
        };
        assert_eq!(
            diag.to_string(),
            "warning: attribute value not quoted at 3:10"
        );
    }

    #[test]
    fn test_error_severity_display() {
        assert_eq!(ErrorSeverity::Warning.to_string(), "warning");
        assert_eq!(ErrorSeverity::Error.to_string(), "error");
        assert_eq!(ErrorSeverity::Fatal.to_string(), "fatal error");
    }

    #[test]
    fn test_parse_error_is_error_trait() {
        let err: ParseError = ParseError::Syntax {
            message: "test".to_string(),
            location: SourceLocation::default(),
            diagnostics: vec![],
        };
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }
}
