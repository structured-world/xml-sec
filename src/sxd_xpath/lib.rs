//! # SXD-XPath
//!
//! This is a pure-Rust implementation of `XPath`, a language for
//! addressing parts of an XML document. It aims to implement [version
//! 1.0 of the XPath specification][spec].
//!
//! `XPath` is wonderful for quickly navigating the complicated
//! hierarchy that is present in many XML documents while having a
//! concise syntax.
//!
//! [spec]: https://www.w3.org/TR/xpath/
//!
//! ### Examples
//!
//! The quickest way to evaluate an `XPath` against an XML document is
//! to use [`evaluate_xpath`][evaluate_xpath].
//!
//! ```
//! # #[cfg(not(feature = "embedded"))]
//! # {
//! use sxd_document_no_unsafe::parser;
//! use sxd_xpath_no_unsafe::{evaluate_xpath, Value};
//!
//! let package = parser::parse("<root>hello</root>").expect("failed to parse XML");
//! let document = package.as_document();
//!
//! let value = evaluate_xpath(&document, "/root").expect("XPath evaluation failed");
//!
//! assert_eq!("hello", value.string());
//! # }
//! ```
//!
//! Evaluating an `XPath` returns a [`Value`][], representing the
//! primary `XPath` types.
//!
//! For more complex needs, `XPath` parsing and evaluation can be split
//! apart. This allows the user to specify namespaces, variables,
//! extra functions, and which node evaluation should begin with. You
//! may also compile an `XPath` once and reuse it multiple times.
//!
//! Parsing is handled with the [`Factory`][] and evaluation relies on
//! the [`Context`][]. Similar functionality to above can be
//! accomplished:
//!
//! ```
//! # #[cfg(not(feature = "embedded"))]
//! # {
//! use sxd_document_no_unsafe::parser;
//! use sxd_xpath_no_unsafe::{Factory, Context, Value};
//!
//! let package = parser::parse("<root>hello</root>")
//!     .expect("failed to parse XML");
//! let document = package.as_document();
//!
//! let factory = Factory::new();
//! let xpath = factory.build("/root").expect("Could not compile XPath");
//!
//! let context = Context::new();
//!
//! let value = xpath.evaluate(&context, document.root())
//!     .expect("XPath evaluation failed");
//!
//! assert_eq!("hello", value.string());
//! # }
//! ```
//!
//! See [`Context`][] for details on how to customize the
//! evaluation of the `XPath`.
//!
//! [evaluate_xpath]: fn.evaluate_xpath.html
//! [`Value`]: enum.Value.html
//! [`Factory`]: struct.Factory.html
//! [`Context`]: context/struct.Context.html
//!
//! ### Programmatically-created XML
//!
//! The `XPath` specification assumes certain properties about the XML
//! being processed. If you are processing XML that was parsed from
//! text, this will be true by construction. If you have
//! programmatically created XML, please note the following cases.
//!
//! #### Namespaces
//!
//! If you have programmatically created XML with namespaces but not
//! defined prefixes, some `XPath` behavior may be confusing:
//!
//! 1. The `name` method will not include a prefix, even if the
//!    element or attribute has a namespace.
//! 2. The `namespace` axis will not include namespaces without
//!    prefixes.
//!
//! #### Document order
//!
//! If you have programmatically created XML but not attached the
//! nodes to the document, some `XPath` behavior may be confusing:
//!
//! 1. These nodes have no [*document order*]. If you create a
//!    variable containing these nodes and apply a predicate to them,
//!    these nodes will appear after any nodes that are present in the
//!    document, but the relative order of the nodes is undefined.
//!
//! [*document order*]: https://www.w3.org/TR/xpath/#dt-document-order

// Ignoring these as our MSRV predates the suggestions
#![allow(
    clippy::legacy_numeric_constants,
    clippy::match_like_matches_macro,
    clippy::option_as_ref_deref,
    clippy::clone_on_copy // Node, Namespace, Evaluation are Copy only in default build
)]

#[cfg(not(any(feature = "no-unsafe", feature = "raw-pointer-backend")))]
compile_error!("select either `no-unsafe` or `raw-pointer-backend`");

// Cargo's all-feature verification enables both selectors. Safe precedence keeps that profile
// free of raw pointers; selecting the legacy backend requires disabling default features.

#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use snafu::{ResultExt, Snafu};
use std::borrow::ToOwned;
use std::string;
use sxd_document_no_unsafe::dom::Document;
use sxd_document_no_unsafe::{PrefixedName, QName};

use crate::parser::Parser;
use crate::token::{AxisName, Token};
use crate::tokenizer::{TokenDeabbreviator, Tokenizer};

pub use crate::context::Context;

#[macro_use]
pub mod macros;
#[cfg(feature = "embedded")]
pub(crate) mod arena;
pub(crate) mod axis;
pub mod context;
pub(crate) mod expression;
pub mod function;
pub(crate) mod grammar;
pub(crate) mod node_test;
pub mod nodeset;
pub(crate) mod parser;
pub(crate) mod runtime;
pub(crate) mod token;
pub(crate) mod tokenizer;

// These belong in the the document

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedPrefixedName {
    prefix: Option<String>,
    local_part: String,
}

impl<'a> From<&'a str> for OwnedPrefixedName {
    fn from(local_part: &'a str) -> Self {
        OwnedPrefixedName {
            prefix: None,
            local_part: local_part.into(),
        }
    }
}

impl<'a> From<(&'a str, &'a str)> for OwnedPrefixedName {
    fn from((prefix, local_part): (&'a str, &'a str)) -> Self {
        OwnedPrefixedName {
            prefix: Some(prefix.into()),
            local_part: local_part.into(),
        }
    }
}

impl<'a> From<PrefixedName<'a>> for OwnedPrefixedName {
    fn from(name: PrefixedName<'a>) -> Self {
        OwnedPrefixedName {
            prefix: name.prefix().map(Into::into),
            local_part: name.local_part().into(),
        }
    }
}

impl<'a> From<&'a OwnedPrefixedName> for OwnedPrefixedName {
    fn from(name: &'a OwnedPrefixedName) -> Self {
        name.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedQName {
    namespace_uri: Option<String>,
    local_part: String,
}

impl<'a> From<&'a str> for OwnedQName {
    fn from(local_part: &'a str) -> Self {
        OwnedQName {
            namespace_uri: None,
            local_part: local_part.into(),
        }
    }
}

impl<'a> From<(&'a str, &'a str)> for OwnedQName {
    fn from((namespace_uri, local_part): (&'a str, &'a str)) -> Self {
        OwnedQName {
            namespace_uri: Some(namespace_uri.into()),
            local_part: local_part.into(),
        }
    }
}

impl<'a> From<QName<'a>> for OwnedQName {
    fn from(name: QName<'a>) -> Self {
        OwnedQName {
            namespace_uri: name.namespace_uri().map(Into::into),
            local_part: name.local_part().into(),
        }
    }
}

impl OwnedQName {
    #[must_use]
    pub fn local_part(&self) -> &str {
        &self.local_part
    }
    #[must_use]
    pub fn namespace_uri(&self) -> Option<&str> {
        self.namespace_uri.as_deref()
    }
}

pub(crate) type LiteralValue = Value<'static>;

struct FormattedLength(usize);

impl std::fmt::Write for FormattedLength {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.0 = self.0.saturating_add(value.len());
        Ok(())
    }
}

pub(crate) fn write_xpath_number(
    output: &mut impl std::fmt::Write,
    number: f64,
) -> std::fmt::Result {
    if number.is_infinite() {
        output.write_str(if number.signum() < 0.0 {
            "-Infinity"
        } else {
            "Infinity"
        })
    } else if number == 0.0 {
        output.write_char('0')
    } else {
        write!(output, "{number}")
    }
}

/// The primary types of values that an `XPath` expression accepts
/// as an argument or returns as a result.
#[derive(Debug)]
#[cfg_attr(not(feature = "embedded"), derive(Clone))]
pub enum Value<'d> {
    /// A true or false value
    Boolean(bool),
    /// A IEEE-754 double-precision floating point number
    Number(f64),
    /// A string
    String(string::String),
    /// Immutable string capacity retained independently of its producing query.
    #[cfg(feature = "embedded")]
    AccountedString(structured_asn1::memory::OwnedText),
    /// An XSLT 1.0 result-tree fragment. It is truthy but is not navigable as a node-set.
    ResultTreeFragment(u64, std::sync::Arc<string::String>),
    /// A collection of unique nodes
    Nodeset(nodeset::Nodeset<'d>),
}

impl PartialEq for Value<'_> {
    fn eq(&self, other: &Self) -> bool {
        if let (Some(left), Some(right)) = (self.string_text(), other.string_text()) {
            return left == right;
        }
        match (self, other) {
            (Self::Boolean(left), Self::Boolean(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => left == right,
            (Self::Nodeset(left), Self::Nodeset(right)) => left == right,
            (
                Self::ResultTreeFragment(left_id, left),
                Self::ResultTreeFragment(right_id, right),
            ) => left_id == right_id && left == right,
            _ => false,
        }
    }
}

pub(crate) fn str_to_num(s: &str) -> f64 {
    let lexical = s.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'));
    let unsigned = lexical.strip_prefix('-').unwrap_or(lexical);
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    let has_digit = !integer.is_empty() || fraction.is_some_and(|value| !value.is_empty());
    let valid = !unsigned.is_empty()
        && has_digit
        && parts.next().is_none()
        && integer.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.is_none_or(|value| value.bytes().all(|byte| byte.is_ascii_digit()));
    if valid {
        lexical.parse().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

#[inline]
pub(crate) fn xpath_size_number(value: usize) -> f64 {
    // XPath 1.0 §§3.5, 4.1 projects counts/positions into binary64 Number.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#numbers
    // Both 32-bit limbs and the multiplication by 2^32 are exact in binary64;
    // only their sum rounds, to nearest with ties to even, like Rust's integer cast.
    #[cfg(target_pointer_width = "64")]
    {
        let bytes = value.to_le_bytes();
        let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let high = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if high == 0 {
            return f64::from(low);
        }
        f64::from(high) * 4_294_967_296.0 + f64::from(low)
    }
    #[cfg(target_pointer_width = "32")]
    {
        f64::from(u32::from_le_bytes(value.to_le_bytes()))
    }
    #[cfg(target_pointer_width = "16")]
    {
        f64::from(u16::from_le_bytes(value.to_le_bytes()))
    }
}

#[inline]
pub(crate) fn same_xpath_number(left: f64, right: f64) -> bool {
    // XPath 1.0 3.4 and 3.5 require IEEE equality, not a tolerance:
    // NaN is unequal to itself; the two signed zeros compare equal.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#booleans
    left.partial_cmp(&right) == Some(std::cmp::Ordering::Equal)
}

pub(crate) fn node_to_num_with_context(
    context: &context::Evaluation<'_, '_>,
    node: &nodeset::Node<'_>,
) -> Result<f64, function::Error> {
    Ok(str_to_num(&node.string_value_with_context(context)?))
}

impl<'d> Value<'d> {
    pub(crate) fn string_text(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            #[cfg(feature = "embedded")]
            Self::AccountedString(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn scalar_text(&self) -> Option<&str> {
        match self {
            Self::ResultTreeFragment(_, value) => Some(value),
            _ => self.string_text(),
        }
    }
    /// Materialize an evaluation-owned value only after reserving its copies and containers.
    pub(crate) fn clone_with_context(
        &self,
        context: &context::Evaluation<'_, 'd>,
    ) -> Result<Self, function::Error> {
        let copy_string = |text: &str| {
            context.charge_work(text.len())?;
            context.reserve_temporary_allocation(text.len())?;
            Ok::<_, function::Error>(text.to_owned())
        };
        Ok(match self {
            Self::Boolean(value) => Self::Boolean(*value),
            Self::Number(value) => Self::Number(*value),
            Self::String(text) => Self::String(copy_string(text)?),
            #[cfg(feature = "embedded")]
            Self::AccountedString(text) => Self::String(copy_string(text)?),
            Self::Nodeset(nodes) => Self::Nodeset(nodes.clone_with_context(context)?),
            Self::ResultTreeFragment(identity, text) => {
                Self::ResultTreeFragment(*identity, std::sync::Arc::clone(text))
            }
        })
    }

    /// Return the UTF-8 byte length of this value's `XPath` string conversion without allocating it.
    ///
    /// # Panics
    /// Panics for an execution-owned node-set, which requires a current-query
    /// API, or if the internal numeric formatter violates its infallible sink contract.
    #[must_use]
    pub fn string_len(&self) -> usize {
        match self {
            Value::Boolean(true) => 4,
            Value::Boolean(false) => 5,
            Value::Number(number) => {
                let mut length = FormattedLength(0);
                write_xpath_number(&mut length, *number).expect("length sink cannot fail");
                length.0
            }
            Value::String(value) => value.len(),
            #[cfg(feature = "embedded")]
            Value::AccountedString(value) => value.len(),
            Value::ResultTreeFragment(_, value) => value.len(),
            Value::Nodeset(nodes) => nodes
                .document_order_first()
                .map_or(0, |node| node.string_value_len()),
        }
    }

    #[must_use]
    pub fn boolean(&self) -> bool {
        match *self {
            Self::Boolean(val) => val,
            Self::Number(n) => n != 0.0 && !n.is_nan(),
            Self::String(ref s) => !s.is_empty(),
            #[cfg(feature = "embedded")]
            Self::AccountedString(ref s) => !s.is_empty(),
            Self::ResultTreeFragment(..) => true,
            Self::Nodeset(ref nodeset) => nodeset.size() > 0,
        }
    }

    #[must_use]
    pub fn into_boolean(self) -> bool {
        self.boolean()
    }

    /// Convert this value to an `XPath` number under the evaluator's work and allocation budgets.
    ///
    /// # Errors
    /// Returns the evaluator's resource refusal if traversal or conversion cannot
    /// be admitted. Non-numeric text produces NaN under the language contract.
    pub fn number(&self, context: &context::Evaluation<'_, '_>) -> Result<f64, function::Error> {
        self.number_in(context, runtime::Native)
    }

    pub(crate) fn number_in<R: runtime::Runtime>(
        &self,
        context: &context::Evaluation<'_, '_>,
        runtime: R,
    ) -> Result<f64, function::Error> {
        let parse_text = |value: &str| {
            context.charge_work(value.len())?;
            Ok(str_to_num(value))
        };
        match self {
            Self::Boolean(value) => Ok(if *value { 1.0 } else { 0.0 }),
            Self::Number(value) => Ok(*value),
            Self::String(value) => parse_text(value),
            #[cfg(feature = "embedded")]
            Self::AccountedString(value) => parse_text(value),
            Self::ResultTreeFragment(_, value) => parse_text(value),
            Self::Nodeset(nodes) => match nodes.document_order_first_in(context, runtime)? {
                Some(node) => runtime.node_number(context, &node),
                None => Ok(f64::NAN),
            },
        }
    }

    /// Materializes the unscoped string conversion.
    ///
    /// # Panics
    /// Panics for an execution-owned node-set, which requires a current-query
    /// API, or if the internal numeric formatter violates its infallible sink contract.
    #[must_use]
    pub fn string(&self) -> string::String {
        match *self {
            Self::Boolean(v) => v.to_string(),
            Self::Number(n) => {
                let mut value = std::string::String::with_capacity(self.string_len());
                write_xpath_number(&mut value, n).expect("String formatting cannot fail");
                value
            }
            Self::String(ref val) => val.clone(),
            #[cfg(feature = "embedded")]
            Self::AccountedString(ref val) => val.as_str().to_owned(),
            Self::ResultTreeFragment(_, ref val) => val.as_ref().clone(),
            Self::Nodeset(ref ns) => match ns.document_order_first() {
                Some(n) => n.string_value(),
                None => string::String::new(),
            },
        }
    }

    #[must_use]
    pub fn into_string(self) -> string::String {
        match self {
            Self::String(val) => val,
            Self::ResultTreeFragment(_, val) => {
                std::sync::Arc::try_unwrap(val).unwrap_or_else(|value| value.as_ref().clone())
            }
            other => other.string(),
        }
    }
}

macro_rules! from_impl {
    ($raw:ty, $variant:expr) => {
        impl<'d> From<$raw> for Value<'d> {
            fn from(other: $raw) -> Value<'d> {
                $variant(other)
            }
        }
    };
}

from_impl!(bool, Value::Boolean);
from_impl!(f64, Value::Number);
from_impl!(String, Value::String);
impl<'a, 'd> From<&'a str> for Value<'d> {
    fn from(other: &'a str) -> Value<'d> {
        Value::String(other.into())
    }
}
from_impl!(nodeset::Nodeset<'d>, Value::Nodeset);

macro_rules! partial_eq_impl {
    ($raw:ty, $variant:pat => $b:expr) => {
        impl<'d> PartialEq<$raw> for Value<'d> {
            fn eq(&self, other: &$raw) -> bool {
                match *self {
                    $variant => $b == other,
                    _ => false,
                }
            }
        }

        impl<'d> PartialEq<Value<'d>> for $raw {
            fn eq(&self, other: &Value<'d>) -> bool {
                match *other {
                    $variant => $b == self,
                    _ => false,
                }
            }
        }
    };
}

partial_eq_impl!(bool, Value::Boolean(ref v) => v);
partial_eq_impl!(f64, Value::Number(ref v) => v);
impl PartialEq<str> for Value<'_> {
    fn eq(&self, other: &str) -> bool {
        self.string_text() == Some(other)
    }
}
impl PartialEq<&str> for Value<'_> {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}
impl PartialEq<String> for Value<'_> {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}
impl PartialEq<Value<'_>> for String {
    fn eq(&self, other: &Value<'_>) -> bool {
        other == self
    }
}
impl PartialEq<Value<'_>> for &str {
    fn eq(&self, other: &Value<'_>) -> bool {
        other == self
    }
}
partial_eq_impl!(nodeset::Nodeset<'d>, Value::Nodeset(ref v) => v);

/// A compiled `XPath`. Construct via [`Factory`][].
///
/// [`Factory`]: struct.Factory.html
#[derive(Debug)]
pub struct XPath(Box<dyn expression::Expression + 'static>);

impl XPath {
    /// Returns the maximum evaluator call depth represented by this compiled expression.
    #[must_use]
    pub fn ast_depth(&self) -> usize {
        self.0.ast_depth()
    }

    /// Evaluate this expression in the given context.
    ///
    /// # Examples
    ///
    /// The most common case is to pass in a reference to a [`Context`][]:
    ///
    /// ```rust,no_run
    /// # #[cfg(not(feature = "embedded"))]
    /// # mod example {
    /// use sxd_document_no_unsafe::dom::Document;
    /// use sxd_xpath_no_unsafe::{XPath, Context};
    ///
    /// fn my_evaluate(doc: Document, xpath: XPath) {
    ///     let mut context = Context::new();
    ///     let value = xpath.evaluate(&context, doc.root());
    ///     println!("The result was: {:?}", value);
    /// }
    ///
    /// # fn main() {}
    /// # }
    /// ```
    ///
    /// [`Context`]: context/struct.Context.html
    ///
    /// # Errors
    /// Returns evaluation errors, including unresolved functions or variables,
    /// invalid conversions, and resource refusals from the supplied context.
    pub fn evaluate<'d, N>(
        &self,
        context: &context::ScopedContext<'_, 'd>,
        node: N,
    ) -> Result<Value<'d>, ExecutionError>
    where
        N: Into<nodeset::Node<'d>>,
    {
        let context = context::Evaluation::new(context, node.into());
        expression::Expression::evaluate(&self.0, &context).map_err(ExecutionError)
    }
}

/// The primary entrypoint to convert an `XPath` represented as a string
/// to a structure that can be evaluated.
pub struct Factory {
    parser: Parser<'static>,
}

// A build owns its account on the stack. Successful token payloads and AST allocations remain
// live until that build returns; temporary vector replacements release their old capacity.
pub(crate) struct ParseBudget {
    limit: usize,
    used: std::cell::Cell<usize>,
    failure: std::cell::Cell<Option<(usize, usize)>>,
}

impl ParseBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: std::cell::Cell::new(0),
            failure: std::cell::Cell::new(None),
        }
    }

    pub(crate) fn charge(&self, bytes: usize) -> Result<(), parser::Error> {
        if let Some((limit, actual)) = self.failure.get() {
            return Err(parser::Error::AllocationLimit { limit, actual });
        }
        let actual = self.used.get().checked_add(bytes);
        if actual.is_none_or(|actual| actual > self.limit) {
            let actual = actual.unwrap_or(usize::MAX);
            self.failure.set(Some((self.limit, actual)));
            return Err(parser::Error::AllocationLimit {
                limit: self.limit,
                actual,
            });
        }
        self.used.set(actual.expect("checked allocation sum"));
        Ok(())
    }

    pub(crate) fn release(&self, bytes: usize) {
        self.used.set(
            self.used
                .get()
                .checked_sub(bytes)
                .expect("released parser allocation was charged"),
        );
    }
}

impl Factory {
    #[must_use]
    pub fn new() -> Factory {
        Factory {
            parser: Parser::new(),
        }
    }

    /// Compiles the given string into an `XPath` structure.
    ///
    /// # Errors
    /// Returns a syntax error or parser safety-limit refusal.
    pub fn build(&self, xpath: &str) -> Result<XPath, ParserError> {
        let tokenizer = Tokenizer::new(xpath);
        let deabbreviator = TokenDeabbreviator::new(tokenizer);

        self.parser
            .parse(deabbreviator)
            .map(XPath)
            .map_err(Into::into)
    }

    /// Compile with a maximum live heap-payload budget for token and AST storage.
    ///
    /// The input is borrowed. Fixed-size stack workspaces and allocator metadata are not heap
    /// payload. Every owned payload, AST node and vector capacity is checked before allocation;
    /// a failed build does not consume the allowance of subsequent builds. The returned AST
    /// remains owned by the caller; this limit is not an evaluator allocation budget.
    ///
    /// # Errors
    /// Returns syntax, parser safety-limit, allocation, or owned-byte-limit errors.
    pub fn build_bounded(xpath: &str, owned_bytes: usize) -> Result<XPath, ParserError> {
        let budget = ParseBudget::new(owned_bytes);
        let tokenizer = Tokenizer::with_budget(xpath, &budget);
        let result = Parser::with_budget(&budget).parse(TokenDeabbreviator::new(tokenizer));
        // Parser lookahead deliberately treats an erroneous token as a non-match. A failed
        // allocation must survive that syntax-error path rather than becoming ExtraUnparsedTokens.
        if let Some((limit, actual)) = budget.failure.get() {
            return Err(ParserError(parser::Error::AllocationLimit {
                limit,
                actual,
            }));
        }
        result.map(XPath).map_err(Into::into)
    }
}

impl Default for Factory {
    fn default() -> Self {
        Factory::new()
    }
}

/// Reports whether a syntactically valid `XPath` can traverse the attribute axis.
///
/// The tokenizer performs the same whitespace handling and abbreviated-axis expansion as
/// [`Factory`], so callers do not need to infer axis semantics from source substrings.
#[must_use]
pub fn expression_uses_attribute_axis(xpath: &str) -> bool {
    TokenDeabbreviator::new(Tokenizer::new(xpath))
        .any(|token| matches!(token, Ok(Token::Axis(AxisName::Attribute))))
}

/// Inspect the attribute axis with bounded transient token storage. Tokens are discarded after
/// inspection; their payload allowance is reusable for the next token rather than cumulative.
///
/// # Errors
/// Returns an owned-byte-limit error if a token cannot be admitted. This
/// inspection does not replace syntax validation with [`Factory::build`].
pub fn expression_uses_attribute_axis_bounded(
    xpath: &str,
    owned_bytes: usize,
) -> Result<bool, ParserError> {
    let budget = ParseBudget::new(owned_bytes);
    let tokens = TokenDeabbreviator::new(Tokenizer::with_budget(xpath, &budget));
    for token in tokens {
        if let Some((limit, actual)) = budget.failure.get() {
            return Err(ParserError(parser::Error::AllocationLimit {
                limit,
                actual,
            }));
        }
        let attribute = matches!(&token, Ok(Token::Axis(AxisName::Attribute)));
        drop(token);
        budget.release(budget.used.get());
        if attribute {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Errors that may occur when parsing an `XPath`
#[derive(Debug, Snafu, Clone, PartialEq)]
pub struct ParserError(parser::Error);

impl ParserError {
    /// Heap payload retained by this diagnostic, excluding the error value itself.
    /// Callers formatting an owned message must account for overlap with this payload.
    #[must_use]
    pub fn owned_bytes(&self) -> usize {
        match &self.0 {
            parser::Error::UnexpectedToken { token } => match token {
                Token::Literal(value) => value.capacity(),
                Token::Function(name) | Token::Variable(name) => {
                    name.prefix.as_ref().map_or(0, String::capacity) + name.local_part.capacity()
                }
                Token::NameTest(name) => {
                    name.prefix.as_ref().map_or(0, String::capacity) + name.local_part.capacity()
                }
                Token::NodeTest(token::NodeTestName::ProcessingInstruction(value)) => {
                    value.as_ref().map_or(0, String::capacity)
                }
                _ => 0,
            },
            _ => 0,
        }
    }

    /// The owned-byte limit and attempted live payload, if allocation was refused.
    #[must_use]
    pub fn allocation_limit(&self) -> Option<(usize, usize)> {
        match self.0 {
            parser::Error::AllocationLimit { limit, actual } => Some((limit, actual)),
            _ => None,
        }
    }
}

/// Errors that may occur when executing an `XPath`
#[derive(Debug, Snafu, Clone, PartialEq)]
pub struct ExecutionError(expression::Error);

/// The failure modes of executing an `XPath`.
#[derive(Debug, Snafu, Clone, PartialEq)]
#[snafu(context(suffix(false)))]
pub enum Error {
    /// The `XPath` was syntactically invalid
    #[snafu(display("Unable to parse XPath: {}", source))]
    Parsing { source: ParserError },
    /// The `XPath` could not be executed
    #[snafu(display("Unable to execute XPath: {}", source))]
    Executing { source: ExecutionError },
}

/// Easily evaluate an `XPath` expression
///
/// The core `XPath` 1.0 functions will be available, and no variables
/// or namespaces will be defined. The root of the document is the
/// context node.
///
/// If you will be evaluating multiple expressions or the same `XPath`
/// multiple times, this may not be the most performant solution.
///
/// # Errors
/// Returns the parsing or execution error without hiding its cause.
///
/// # Examples
///
/// ```
/// # #[cfg(not(feature = "embedded"))]
/// # {
/// use sxd_document_no_unsafe::parser;
/// use sxd_xpath_no_unsafe::{evaluate_xpath, Value};
///
/// let package = parser::parse("<root><a>1</a><b>2</b></root>").expect("failed to parse the XML");
/// let document = package.as_document();
///
/// assert_eq!(Ok(Value::Number(3.0)), evaluate_xpath(&document, "/*/a + /*/b"));
/// # }
/// ```
pub fn evaluate_xpath<'d>(document: &'d Document<'d>, xpath: &str) -> Result<Value<'d>, Error> {
    let factory = Factory::new();
    let expression = factory.build(xpath).context(Parsing)?;

    let context = Context::new();

    expression
        .evaluate(&context, document.root())
        .context(Executing)
}

#[cfg(test)]
mod number_tests;

#[cfg(test)]
mod test {
    #[test]
    fn parser_budget_overflow_remains_a_sticky_failure() {
        // Arithmetic overflow must fail even when the caller requests usize::MAX bytes.
        let budget = super::ParseBudget::new(usize::MAX);
        assert!(budget.charge(usize::MAX).is_ok());
        assert!(budget.charge(1).is_err());
        assert!(budget.charge(0).is_err());
    }

    use std::borrow::ToOwned;

    use sxd_document_no_unsafe::{self, Package, dom};

    use super::*;

    fn number(value: &Value<'_>) -> f64 {
        let package = Package::new();
        let document = package.as_document();
        let context = Context::new();
        let evaluation = context::Evaluation::new(&context, document.root().into());
        value
            .number(&evaluation)
            .expect("test numeric conversion fits the default budget")
    }

    #[cfg(feature = "embedded")]
    #[test]
    fn current_number_conversion_funds_ordering_and_text_together() {
        // number(node-set) selects the first node in document order, then
        // converts its complete string-value with current-owned scratch only.
        use std::{cell::Cell, sync::Arc};
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        let first = document.create_element("first");
        let last = document.create_element("last");
        document.root().append_child(root);
        root.append_child(first);
        root.append_child(last);
        first.append_child(document.create_text("1"));
        first.append_child(document.create_text("2"));
        last.append_child(document.create_text("99"));
        let value = Value::Nodeset(nodeset![last, first]);
        let mut context = Context::new();
        context.set_string_allocation_limit(0);
        let evaluation = context::Evaluation::new(&context, root.into());
        for bytes in [0, 65536] {
            let work = Memory::new(Arc::new(MemoryAccount::new(bytes, 65536)));
            let failure = Cell::new(None);
            let result = value.number_in(
                &evaluation,
                runtime::Accounted {
                    work: &work,
                    failure: &failure,
                },
            );
            if bytes == 0 {
                assert!(result.is_err());
                assert_eq!(failure.get(), Some(MemoryError::LimitExceeded));
            } else {
                assert!(super::same_xpath_number(
                    result.expect("current conversion"),
                    12.0
                ));
                assert_eq!(failure.get(), None);
            }
            assert_eq!(work.used(), 0);
        }
        assert_eq!(context.string_allocation_exceeded(), None);
    }

    #[test]
    fn string_and_fragment_numbers_precharge_lexical_work() {
        // Trimming and numeric validation inspect attacker-controlled text even for NaN.
        // Both owned strings and shared RTF strings must cross the same work gate first.
        let package = Package::new();
        let document = package.as_document();
        for text in [" 1.5 ", "not-a-number", "\u{a0}1"] {
            for value in [
                Value::String(text.into()),
                Value::ResultTreeFragment(1, std::sync::Arc::new(text.into())),
            ] {
                for limit in [text.len() - 1, text.len()] {
                    let mut context = Context::without_core_functions();
                    context.set_evaluation_work_limit(limit);
                    let evaluation = context::Evaluation::new(&context, document.root().into());
                    let result = value.number(&evaluation);
                    if limit < text.len() {
                        assert!(result.is_err());
                        assert_eq!(context.evaluation_work_exceeded(), Some(text.len()));
                        assert_eq!(context.evaluation_work_used(), 0);
                    } else {
                        let result = result.expect("exact lexical work fits");
                        if text == " 1.5 " {
                            assert!(super::same_xpath_number(result, 1.5));
                        } else {
                            assert!(result.is_nan());
                        }
                        assert_eq!(context.evaluation_work_used(), text.len());
                    }
                }
            }
        }
        let mut context = Context::without_core_functions();
        context.set_evaluation_work_limit(0);
        let evaluation = context::Evaluation::new(&context, document.root().into());
        assert!(super::same_xpath_number(
            Value::Boolean(true).number(&evaluation).unwrap(),
            1.0
        ));
        assert!(super::same_xpath_number(
            Value::Number(2.0).number(&evaluation).unwrap(),
            2.0
        ));
        assert_eq!(context.evaluation_work_used(), 0);
    }

    #[test]
    fn number_of_string_is_ieee_754_number() {
        let v = Value::String("1.5".to_owned());
        assert!(super::same_xpath_number(1.5, number(&v)));
    }

    #[test]
    fn number_of_string_with_negative_is_negative_number() {
        let v = Value::String("-1.5".to_owned());
        assert!(super::same_xpath_number(-1.5, number(&v)));
    }

    #[test]
    fn number_of_string_with_surrounding_whitespace_is_number_without_whitespace() {
        let v = Value::String("\r\n1.5 \t".to_owned());
        assert!(super::same_xpath_number(1.5, number(&v)));
    }

    #[test]
    fn number_of_string_rejects_non_xml_unicode_whitespace() {
        // XPath 1.0 refers to XML S, not Unicode White_Space; NBSP therefore
        // remains part of the lexical value and makes conversion return NaN.
        assert!(number(&Value::String("\u{a0}1".into())).is_nan());
        assert!(number(&Value::String("1\u{a0}".into())).is_nan());
    }

    #[test]
    fn number_of_garbage_string_is_nan() {
        let v = Value::String("I am not an IEEE 754 number".to_owned());
        assert!(number(&v).is_nan());
    }

    #[test]
    fn number_of_boolean_true_is_1() {
        let v = Value::Boolean(true);
        assert!(super::same_xpath_number(1.0, number(&v)));
    }

    #[test]
    fn number_of_boolean_false_is_0() {
        let v = Value::Boolean(false);
        assert!(super::same_xpath_number(0.0, number(&v)));
    }

    #[test]
    fn number_of_nodeset_is_number_value_of_first_node_in_document_order() {
        let package = Package::new();
        let doc = package.as_document();

        let c1 = doc.create_comment("42.42");
        let c2 = doc.create_comment("1234");
        doc.root().append_child(c1);
        doc.root().append_child(c2);

        let v = Value::Nodeset(nodeset![c2, c1]);
        assert!(super::same_xpath_number(42.42, number(&v)));
    }

    #[test]
    fn string_of_true_is_true() {
        let v = Value::Boolean(true);
        assert_eq!("true", v.string());
    }

    #[test]
    fn string_of_false_is_false() {
        let v = Value::Boolean(false);
        assert_eq!("false", v.string());
    }

    #[test]
    fn string_of_nan_is_nan() {
        let v = Value::Number(f64::NAN);
        assert_eq!("NaN", v.string());
    }

    #[test]
    fn string_of_positive_zero_is_zero() {
        let v = Value::Number(0.0);
        assert_eq!("0", v.string());
    }

    #[test]
    fn string_of_negative_zero_is_zero() {
        let v = Value::Number(-0.0);
        assert_eq!("0", v.string());
    }

    #[test]
    fn string_of_positive_infinity_is_infinity() {
        let v = Value::Number(f64::INFINITY);
        assert_eq!("Infinity", v.string());
    }

    #[test]
    fn string_of_negative_infinity_is_minus_infinity() {
        let v = Value::Number(f64::NEG_INFINITY);
        assert_eq!("-Infinity", v.string());
    }

    #[test]
    fn string_of_integer_has_no_decimal() {
        let v = Value::Number(-42.0);
        assert_eq!("-42", v.string());
    }

    #[test]
    fn string_of_decimal_has_fractional_part() {
        let v = Value::Number(1.2);
        assert_eq!("1.2", v.string());
    }

    #[test]
    fn string_of_nodeset_is_string_value_of_first_node_in_document_order() {
        let package = Package::new();
        let doc = package.as_document();

        let c1 = doc.create_comment("comment 1");
        let c2 = doc.create_comment("comment 2");
        doc.root().append_child(c1);
        doc.root().append_child(c2);

        let v = Value::Nodeset(nodeset![c2, c1]);
        assert_eq!("comment 1", v.string());
    }

    fn with_document<F>(xml: &str, f: F)
    where
        F: FnOnce(dom::Document<'_>),
    {
        let package = sxd_document_no_unsafe::parser::parse(xml).expect("Unable to parse test XML");
        f(package.as_document());
    }

    #[test]
    fn xpath_evaluation_success() {
        with_document("<root><child>content</child></root>", |doc| {
            let result = evaluate_xpath(&doc, "/root/child");

            assert_eq!(Ok("content".to_owned()), result.map(|v| v.string()));
        });
    }

    #[test]
    fn xpath_evaluation_parsing_error() {
        with_document("<root><child>content</child></root>", |doc| {
            let result = evaluate_xpath(&doc, "/root/child/");

            let expected_error = crate::parser::TrailingSlash
                .fail()
                .map_err(ParserError::from)
                .context(Parsing);
            assert_eq!(expected_error, result);
        });
    }

    #[test]
    fn xpath_evaluation_execution_error() {
        with_document("<root><child>content</child></root>", |doc| {
            let result = evaluate_xpath(&doc, "$foo");

            let expected_error = crate::expression::UnknownVariable { name: "foo" }
                .fail()
                .map_err(ExecutionError::from)
                .context(Executing);
            assert_eq!(expected_error, result);
        });
    }

    #[test]
    fn malformed_token_stream_is_fused_after_the_first_error() {
        let mut tokens = TokenDeabbreviator::new(Tokenizer::new("\u{0}"));
        assert!(tokens.next().expect("one tokenizer result").is_err());
        assert!(tokens.next().is_none());
    }

    #[test]
    fn bounded_parser_charges_literal_payload_not_lexical_length_times_nodes() {
        // One large literal owns one payload and one AST node, regardless of its contents.
        let payload = " / * ".repeat(200_000);
        let source = format!("'{payload}'");
        let required = payload.len() + std::mem::size_of::<expression::Literal>();
        let factory = Factory::new();
        assert!(Factory::build_bounded(&source, required).is_ok());
        let error = Factory::build_bounded(&source, required - 1).unwrap_err();
        assert_eq!(error.allocation_limit(), Some((required - 1, required)));
        assert!(factory.build("1").is_ok());
    }

    #[test]
    fn bounded_parser_checks_ast_and_vector_growth_and_preserves_errors() {
        // Allocation failures must be typed, including failures hidden by token lookahead.
        let factory = Factory::new();
        for source in [
            "1",
            "$name",
            "a/b/c",
            "f(1,2,3,4,5)",
            "a[1][2]",
            "1+2",
            "//a",
        ] {
            assert!(
                Factory::build_bounded(source, 0)
                    .unwrap_err()
                    .allocation_limit()
                    .is_some()
            );
            assert!(Factory::build_bounded(source, 16_384).is_ok());
        }
        for source in ["'unterminated", "f(1,)", "a/", "1 +", "!"] {
            assert_eq!(
                factory.build(source).unwrap_err(),
                Factory::build_bounded(source, 16_384).unwrap_err()
            );
        }
        // Parentheses allocate no AST nodes and must not accumulate per-rule heap charges.
        let nested = format!("{}1{}", "(".repeat(32), ")".repeat(32));
        assert!(
            Factory::build_bounded(&nested, std::mem::size_of::<expression::Literal>()).is_ok()
        );
    }

    #[test]
    fn parser_rejects_expression_nesting_above_its_safety_ceiling() {
        let expression = format!("{}1", "-".repeat(300));
        assert!(Factory::new().build(&expression).is_err());
    }

    #[test]
    fn comma_forces_a_following_operator_name_to_be_a_node_test() {
        with_document("<root><div>ok</div></root>", |doc| {
            let xpath = Factory::new()
                .build("concat('x', /root/div/text())")
                .expect("name after comma parses");
            let value = xpath
                .evaluate(&Context::new(), doc.root())
                .expect("XPath evaluates");
            assert_eq!(value.string(), "xok");
        });
    }

    #[test]
    fn undeclared_node_test_prefix_returns_an_execution_error() {
        with_document("<root><item/></root>", |doc| {
            let xpath = Factory::new()
                .build("//missing:item")
                .expect("XPath syntax parses");
            assert!(xpath.evaluate(&Context::new(), doc.root()).is_err());
        });
    }

    #[test]
    fn undeclared_node_test_prefix_fails_without_axis_candidates() {
        // Namespace resolution is expression semantics, not a side effect of visiting a match.
        with_document("<root/>", |doc| {
            let xpath = Factory::new()
                .build("/root/missing:item")
                .expect("XPath syntax parses");
            assert!(xpath.evaluate(&Context::new(), doc.root()).is_err());
        });
    }
}
