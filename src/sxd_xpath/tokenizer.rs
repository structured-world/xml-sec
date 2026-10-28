#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use alloc::string::String;
use snafu::Snafu;
use sxd_document_no_unsafe::PrefixedName;
use sxd_document_no_unsafe::str::XmlStr;
use winnow::Parser;
use winnow::combinator::{alt, opt, peek, preceded};
use winnow::error::ParserError;
use winnow::stream::Stream;
use winnow::token::literal;

use crate::OwnedPrefixedName;
use crate::node_test;
use crate::token::{
    AxisName, BorrowedToken as Token, NodeTestName, Token as OwnedToken, TokenData,
};

pub(crate) struct BorrowedTokenizer<'a> {
    xpath: &'a str,
    start: usize,
    prefer_recognition_of_operator_names: bool,
}

/// A failed token alternative and how much input remained where it failed.
/// Among alternatives the furthest failure is reported, the later one on a
/// tie; a fatal error ends the alternatives at once.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Failure {
    remaining: usize,
    error: Error,
}

impl Failure {
    /// Name a recoverable failure; a fatal error keeps its own cause.
    fn expect(self, error: Error) -> Self {
        if self.error.recoverable() {
            Self { error, ..self }
        } else {
            self
        }
    }
}

impl<'a> ParserError<&'a str> for Failure {
    type Inner = Self;

    fn from_input(input: &&'a str) -> Self {
        Self {
            remaining: input.len(),
            error: Error::ExpectedToken,
        }
    }

    fn or(self, other: Self) -> Self {
        if other.remaining <= self.remaining {
            other
        } else {
            self
        }
    }

    fn is_backtrack(&self) -> bool {
        self.error.recoverable()
    }

    fn into_inner(self) -> Result<Self, Self> {
        Ok(self)
    }
}

type Input<'a> = &'a str;

/// `parser`, with a recoverable failure named `error`.
fn expecting<'a, O>(
    parser: impl Parser<Input<'a>, O, Failure>,
    error: Error,
) -> impl Parser<Input<'a>, O, Failure> {
    parser.map_err(move |failure: Failure| failure.expect(error))
}

/// A nonempty run of one XML character class.
fn class<'a>(end: fn(&&'a str) -> Option<usize>) -> impl Parser<Input<'a>, &'a str, Failure> {
    move |input: &mut Input<'a>| match end(input) {
        Some(length) => Ok(input.next_slice(length)),
        None => Err(Failure::from_input(input)),
    }
}

fn space<'a>(input: &mut Input<'a>) -> Result<&'a str, Failure> {
    class(<&str as XmlStr>::end_of_space).parse_next(input)
}

fn decimal_chars<'a>(input: &mut Input<'a>) -> Result<&'a str, Failure> {
    class(<&str as XmlStr>::end_of_decimal_chars).parse_next(input)
}

fn ncname<'a>(input: &mut Input<'a>) -> Result<&'a str, Failure> {
    class(<&str as XmlStr>::end_of_ncname).parse_next(input)
}

/// An XML [prefixed name](http://www.w3.org/TR/REC-xml-names/#NT-QName).
fn prefixed_name<'a>(input: &mut Input<'a>) -> Result<PrefixedName<'a>, Failure> {
    let prefix = ncname(input)?;
    let local = opt(preceded(literal(":"), ncname)).parse_next(input)?;
    Ok(match local {
        Some(local) => PrefixedName::with_prefix(Some(prefix), local),
        None => PrefixedName::new(prefix),
    })
}

type Identifier<T> = (&'static str, T);

/// The first table entry the input starts with, in table order.
fn identifier<'a, T: Clone>(table: &'static [Identifier<T>]) -> impl Parser<Input<'a>, T, Failure> {
    move |input: &mut Input<'a>| {
        for (text, value) in table {
            if input.starts_with(text) {
                input.next_slice(text.len());
                return Ok(value.clone());
            }
        }
        Err(Failure::from_input(input))
    }
}

pub type TokenResult = Result<OwnedToken, Error>;
pub(crate) type BorrowedTokenResult<'a> = Result<Token<'a>, Error>;

#[derive(Debug, Snafu, Copy, Clone, PartialEq)]
#[snafu(context(suffix(false)))]
#[cfg_attr(test, snafu(visibility(pub(crate))))]
pub enum Error {
    /// token payload allocation exceeded the build budget
    AllocationLimit,
    /// expected a single or double quote
    ExpectedQuote,
    /// expected a number
    ExpectedNumber,
    /// Expected the current node token
    ExpectedCurrentNode,
    /// expected a named operator
    ExpectedNamedOperator,
    /// expected an axis name
    ExpectedAxis,
    /// expected an axis separator
    ExpectedAxisSeparator,
    /// expected a node test
    ExpectedNodeTest,
    /// expected an optionally prefixed name
    ExpectedPrefixedName,
    /// expected a name test
    ExpectedNameTest,
    /// expected a variable reference
    ExpectedVariableReference,
    /// expected a token
    ExpectedToken,
    /// expected a left parenthesis
    ExpectedLeftParenthesis,
    /// internal error
    NotTokenizingNamedOperators,
    /// mismatched quote character
    MismatchedQuoteCharacters,
    /// unable to create token
    UnableToCreateToken,
}

impl Error {
    /// A fatal error ends the alternatives instead of trying the next one.
    fn recoverable(self) -> bool {
        !matches!(
            self,
            Self::AllocationLimit | Self::MismatchedQuoteCharacters | Self::UnableToCreateToken
        )
    }
}

static SINGLE_CHAR_TOKENS: [Identifier<Token<'static>>; 13] = [
    ("/", Token::Slash),
    ("(", Token::LeftParen),
    (")", Token::RightParen),
    ("[", Token::LeftBracket),
    ("]", Token::RightBracket),
    ("@", Token::AtSign),
    ("+", Token::PlusSign),
    ("-", Token::MinusSign),
    ("|", Token::Pipe),
    ("=", Token::Equal),
    ("<", Token::LessThan),
    (">", Token::GreaterThan),
    (",", Token::Comma),
];

static TWO_CHAR_TOKENS: [Identifier<Token<'static>>; 5] = [
    ("<=", Token::LessThanOrEqual),
    (">=", Token::GreaterThanOrEqual),
    ("!=", Token::NotEqual),
    ("//", Token::DoubleSlash),
    ("..", Token::ParentNode),
];

static NAMED_OPERATORS: [Identifier<Token<'static>>; 5] = [
    ("and", Token::And),
    ("or", Token::Or),
    ("mod", Token::Remainder),
    ("div", Token::Divide),
    ("*", Token::Multiply),
];

// These will be matched in order, so substrings should come later.
static AXES: [Identifier<AxisName>; 13] = [
    ("ancestor-or-self", AxisName::AncestorOrSelf),
    ("ancestor", AxisName::Ancestor),
    ("attribute", AxisName::Attribute),
    ("child", AxisName::Child),
    ("descendant-or-self", AxisName::DescendantOrSelf),
    ("descendant", AxisName::Descendant),
    ("following-sibling", AxisName::FollowingSibling),
    ("following", AxisName::Following),
    ("namespace", AxisName::Namespace),
    ("parent", AxisName::Parent),
    ("preceding-sibling", AxisName::PrecedingSibling),
    ("preceding", AxisName::Preceding),
    ("self", AxisName::SelfAxis),
];

static NODE_TESTS: [Identifier<NodeTestName<&'static str>>; 4] = [
    ("comment", NodeTestName::Comment),
    ("text", NodeTestName::Text),
    (
        "processing-instruction",
        NodeTestName::ProcessingInstruction(None),
    ),
    ("node", NodeTestName::Node),
];

/// A string delimited by `quote`; an unterminated one is fatal.
fn quoted<'a>(quote: &'static str) -> impl Parser<Input<'a>, &'a str, Failure> {
    move |input: &mut Input<'a>| {
        expecting(literal(quote), Error::ExpectedQuote).parse_next(input)?;
        let end = input.find(quote).unwrap_or(input.len());
        let value = input.next_slice(end);
        expecting(literal(quote), Error::MismatchedQuoteCharacters).parse_next(input)?;
        Ok(value)
    }
}

fn parse_literal<'a>(input: &mut Input<'a>) -> Result<&'a str, Failure> {
    alt((quoted("\x22"), quoted("\x27"))).parse_next(input)
}

fn parse_quoted_literal<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    parse_literal.map(Token::Literal).parse_next(input)
}

fn parse_number<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    let with_integer = (decimal_chars, opt((literal("."), opt(decimal_chars)))).void();
    let without_integer = (literal("."), decimal_chars).void();
    let number = alt((
        expecting(with_integer, Error::ExpectedNumber),
        expecting(without_integer, Error::ExpectedNumber),
    ))
    .take()
    .parse_next(input)?;
    // Only decimal digits and one point were accepted, so this always parses.
    Ok(Token::Number(number.parse().expect("validated number")))
}

fn parse_current_node<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    expecting(literal("."), Error::ExpectedCurrentNode)
        .value(Token::CurrentNode)
        .parse_next(input)
}

fn parse_named_operators<'a>(
    input: &mut Input<'a>,
    prefer_named_ops: bool,
) -> Result<Token<'a>, Failure> {
    if prefer_named_ops {
        expecting(identifier(&NAMED_OPERATORS), Error::ExpectedNamedOperator).parse_next(input)
    } else {
        Err(Failure {
            remaining: input.len(),
            error: Error::NotTokenizingNamedOperators,
        })
    }
}

fn parse_axis_specifier<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    // AXES lists a name before any name it prefixes, so the first match is the
    // whole axis name.
    let axis = expecting(identifier(&AXES), Error::ExpectedAxis).parse_next(input)?;
    expecting(literal("::"), Error::ExpectedAxisSeparator).parse_next(input)?;
    Ok(Token::Axis(axis))
}

fn parse_node_type<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    let without_arg = (
        identifier(&NODE_TESTS),
        opt(space),
        literal("("),
        opt(space),
        literal(")"),
    )
        .map(|(node_type, ..)| Token::NodeTest(node_type));
    let with_arg = |input: &mut Input<'a>| {
        expecting(literal("processing-instruction"), Error::ExpectedNodeTest).parse_next(input)?;
        opt(space).parse_next(input)?;
        expecting(literal("("), Error::ExpectedNodeTest).parse_next(input)?;
        opt(space).parse_next(input)?;
        let target = expecting(parse_literal, Error::ExpectedNodeTest).parse_next(input)?;
        opt(space).parse_next(input)?;
        expecting(literal(")"), Error::ExpectedNodeTest).parse_next(input)?;
        Ok(Token::NodeTest(NodeTestName::ProcessingInstruction(Some(
            target,
        ))))
    };
    alt((expecting(without_arg, Error::ExpectedNodeTest), with_arg)).parse_next(input)
}

fn parse_function_call<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    let name = expecting(prefixed_name, Error::ExpectedPrefixedName).parse_next(input)?;
    // The left parenthesis decides the token but stays for the next one.
    expecting(peek(literal("(")), Error::ExpectedLeftParenthesis).parse_next(input)?;
    Ok(Token::Function(name))
}

fn parse_name_test<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    let wildcard = literal("*").map(|local_part| node_test::NameTest {
        prefix: None,
        local_part,
    });
    let prefixed_wildcard =
        (ncname, literal(":"), literal("*")).map(|(prefix, _, local_part)| node_test::NameTest {
            prefix: Some(prefix),
            local_part,
        });
    let name = prefixed_name.map(|name| node_test::NameTest {
        prefix: name.prefix(),
        local_part: name.local_part(),
    });
    expecting(
        alt((wildcard, prefixed_wildcard, name)),
        Error::ExpectedNameTest,
    )
    .map(Token::NameTest)
    .parse_next(input)
}

/// Punctuation and operator symbols; two-character symbols win over their prefixes.
fn parse_symbol<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    let token = expecting(
        alt((
            identifier(&TWO_CHAR_TOKENS),
            identifier(&SINGLE_CHAR_TOKENS),
        )),
        Error::ExpectedToken,
    )
    .parse_next(input)?;
    Ok(token)
}

fn parse_variable_reference<'a>(input: &mut Input<'a>) -> Result<Token<'a>, Failure> {
    expecting(literal("$"), Error::ExpectedVariableReference).parse_next(input)?;
    let name = expecting(prefixed_name, Error::ExpectedPrefixedName).parse_next(input)?;
    Ok(Token::Variable(name))
}

impl<'input> BorrowedTokenizer<'input> {
    pub fn new(xpath: &'input str) -> Self {
        BorrowedTokenizer {
            xpath,
            start: 0,
            prefer_recognition_of_operator_names: false,
        }
    }

    pub fn has_more_tokens(&self) -> bool {
        self.xpath.len() > self.start
    }

    fn parse_token(&self, input: &mut Input<'input>) -> Result<Token<'input>, Failure> {
        opt(space).parse_next(input)?;
        let prefer_named_ops = self.prefer_recognition_of_operator_names;
        // Alternatives in priority order; `alt` takes at most nine, and nesting
        // keeps the furthest-failure choice because that choice is associative.
        let token = alt((
            parse_symbol,
            parse_quoted_literal,
            parse_number,
            parse_current_node,
            |input: &mut Input<'input>| parse_named_operators(input, prefer_named_ops),
            parse_axis_specifier,
            parse_node_type,
            parse_function_call,
            alt((parse_name_test, parse_variable_reference)),
        ))
        .parse_next(input)?;
        opt(space).parse_next(input)?;
        Ok(token)
    }

    fn raw_next_token(&mut self) -> BorrowedTokenResult<'input> {
        let mut input = &self.xpath[self.start..];
        match self.parse_token(&mut input) {
            Ok(token) => {
                self.start = self.xpath.len() - input.len();
                Ok(token)
            }
            // No progress at all is reported as no token, not as the last
            // alternative's expectation.
            Err(failure) if self.xpath.len() - failure.remaining == self.start => {
                UnableToCreateToken.fail()
            }
            Err(failure) => Err(failure.error),
        }
    }

    fn next_token(&mut self) -> BorrowedTokenResult<'input> {
        let token = self.raw_next_token()?;

        // XPath 1.0 3.7 lexical disambiguation:
        // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
        self.prefer_recognition_of_operator_names =
            !(token.precedes_node_test() || token.precedes_expression() || token.is_operator());

        Ok(token)
    }
}

impl<'input> Iterator for BorrowedTokenizer<'input> {
    type Item = BorrowedTokenResult<'input>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_more_tokens() {
            let token = self.next_token();
            if token.is_err() {
                self.start = self.xpath.len();
            }
            Some(token)
        } else {
            None
        }
    }
}

/// The public/native adapter materializes only the successfully recognized
/// token, after admitting its complete payload. The shared lexer also exposes
/// source borrows for direct arena construction without owned token text.
pub struct Tokenizer<'a> {
    lexical: BorrowedTokenizer<'a>,
    budget: Option<&'a crate::ParseBudget>,
}

impl<'a> Tokenizer<'a> {
    pub fn new(xpath: &'a str) -> Self {
        Self {
            lexical: BorrowedTokenizer::new(xpath),
            budget: None,
        }
    }

    pub fn with_budget(xpath: &'a str, budget: &'a crate::ParseBudget) -> Self {
        Self {
            lexical: BorrowedTokenizer::new(xpath),
            budget: Some(budget),
        }
    }

    pub fn has_more_tokens(&self) -> bool {
        self.lexical.has_more_tokens()
    }
}

impl Iterator for Tokenizer<'_> {
    type Item = TokenResult;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.has_more_tokens() {
            return None;
        }
        let token = self.lexical.next_token();
        let result = token.and_then(|token| {
            if let Some(budget) = self.budget
                && budget.charge(token.payload_bytes()).is_err()
            {
                return Err(Error::AllocationLimit);
            }
            Ok(token.into_owned())
        });
        if result.is_err() {
            self.lexical.start = self.lexical.xpath.len();
        }
        Some(result)
    }
}

pub struct TokenDeabbreviator<I, N = OwnedPrefixedName, T = String> {
    source: I,
    buffer: [Option<TokenData<N, T>>; 3],
}

// Avoid adding the first element to the buffer, but keep the
// expansion values nicely co-located.
macro_rules! deabbrev {
    ($this:expr, $head:expr $(, $tail:expr)*) => {{
        for (slot, token) in $this.buffer.iter_mut().zip([$( $tail, )*]) {
            *slot = Some(token);
        }
        $head
    }}
}

impl<I, N, T> TokenDeabbreviator<I, N, T> {
    pub fn new(source: I) -> Self {
        TokenDeabbreviator {
            source,
            buffer: [None, None, None],
        }
    }

    fn expand_token(&mut self, token: TokenData<N, T>) -> TokenData<N, T> {
        match token {
            TokenData::AtSign => deabbrev!(self, TokenData::Axis(AxisName::Attribute)),
            TokenData::DoubleSlash => deabbrev!(
                self,
                TokenData::Slash,
                TokenData::Axis(AxisName::DescendantOrSelf),
                TokenData::NodeTest(NodeTestName::Node),
                TokenData::Slash
            ),
            TokenData::CurrentNode => deabbrev!(
                self,
                TokenData::Axis(AxisName::SelfAxis),
                TokenData::NodeTest(NodeTestName::Node)
            ),
            TokenData::ParentNode => deabbrev!(
                self,
                TokenData::Axis(AxisName::Parent),
                TokenData::NodeTest(NodeTestName::Node)
            ),
            _ => token,
        }
    }
}

impl<I, N, T> Iterator for TokenDeabbreviator<I, N, T>
where
    I: Iterator<Item = Result<TokenData<N, T>, Error>>,
{
    type Item = Result<TokenData<N, T>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(tok) = self.buffer[0].take() {
            self.buffer.rotate_left(1);
            return Some(Ok(tok));
        }

        let token = self.source.next();

        match token {
            None | Some(Err(_)) => token,
            Some(Ok(token)) => Some(Ok(self.expand_token(token))),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn borrowed_lexer_keeps_literal_and_name_payloads_in_original_source() {
        // The arena input must not first allocate owned names/literals. Verify
        // actual source pointers, not just equal text from an accidental copy.
        let source = "f:p('β', $v:x) / a:b";
        let mut lexer = super::BorrowedTokenizer::new(source);
        let super::Token::Function(name) = lexer
            .next()
            .expect("function token")
            .expect("lexical success")
        else {
            panic!("function expected");
        };
        assert_eq!(name.prefix(), Some("f"));
        assert!(std::ptr::eq(
            name.local_part().as_ptr(),
            source[2..].as_ptr()
        ));
        assert!(matches!(lexer.next(), Some(Ok(super::Token::LeftParen))));
        let super::Token::Literal(literal) = lexer
            .next()
            .expect("literal token")
            .expect("lexical success")
        else {
            panic!("literal expected");
        };
        assert_eq!(literal, "β");
        assert!(std::ptr::eq(
            literal.as_ptr(),
            source[source.find('β').expect("literal offset")..].as_ptr()
        ));
        assert!(matches!(lexer.next(), Some(Ok(super::Token::Comma))));
        let super::Token::Variable(name) = lexer
            .next()
            .expect("variable token")
            .expect("lexical success")
        else {
            panic!("variable expected");
        };
        assert_eq!(name.prefix(), Some("v"));
        assert!(std::ptr::eq(
            name.local_part().as_ptr(),
            source[source.find("x)").expect("variable offset")..].as_ptr()
        ));
        assert!(matches!(lexer.next(), Some(Ok(super::Token::RightParen))));
        assert!(matches!(lexer.next(), Some(Ok(super::Token::Slash))));
        let super::Token::NameTest(name) = lexer
            .next()
            .expect("name-test token")
            .expect("lexical success")
        else {
            panic!("name test expected");
        };
        assert_eq!(name.prefix, Some("a"));
        assert!(std::ptr::eq(
            name.local_part.as_ptr(),
            source[source.len() - 1..].as_ptr()
        ));
        assert!(lexer.next().is_none());
    }

    #[test]
    fn deabbreviation_preserves_borrowed_payloads() {
        // Synthetic axis/node tokens may expand in the fixed stack buffer;
        // real QName payloads must stay borrowed through the same expansion.
        let source = "//p:β/@q:x";
        let mut lexer = super::TokenDeabbreviator::new(super::BorrowedTokenizer::new(source));
        assert!(matches!(lexer.next(), Some(Ok(super::Token::Slash))));
        assert!(matches!(
            lexer.next(),
            Some(Ok(super::Token::Axis(super::AxisName::DescendantOrSelf)))
        ));
        assert!(matches!(
            lexer.next(),
            Some(Ok(super::Token::NodeTest(super::NodeTestName::Node)))
        ));
        assert!(matches!(lexer.next(), Some(Ok(super::Token::Slash))));
        let super::Token::NameTest(name) = lexer
            .next()
            .expect("name-test token")
            .expect("lexical success")
        else {
            panic!("name test expected");
        };
        assert_eq!(name.prefix, Some("p"));
        assert!(std::ptr::eq(name.local_part.as_ptr(), source[4..].as_ptr()));
        assert!(matches!(lexer.next(), Some(Ok(super::Token::Slash))));
        assert!(matches!(
            lexer.next(),
            Some(Ok(super::Token::Axis(super::AxisName::Attribute)))
        ));
        let super::Token::NameTest(name) = lexer
            .next()
            .expect("attribute-test token")
            .expect("lexical success")
        else {
            panic!("attribute test expected");
        };
        assert_eq!(name.prefix, Some("q"));
        assert!(std::ptr::eq(
            name.local_part.as_ptr(),
            source[source.len() - 1..].as_ptr()
        ));
        assert!(lexer.next().is_none());
    }

    #[test]
    fn failure_selection_keeps_furthest_latest_and_fatal_errors() {
        // Freeze the alternatives' error selection independently of the lexer:
        // the furthest failure wins, the later one on a tie, and a fatal error
        // stops further alternatives instead of competing with them.
        use winnow::error::ParserError;
        let failure = |remaining, error| super::Failure { remaining, error };
        let start = failure(2, super::Error::ExpectedQuote);
        let later = failure(1, super::Error::ExpectedNumber);
        assert_eq!(later.or(start), later);
        assert_eq!(start.or(later), later);
        let tie = failure(1, super::Error::ExpectedAxis);
        assert_eq!(later.or(tie), tie);
        assert!(start.is_backtrack());
        let fatal = failure(2, super::Error::MismatchedQuoteCharacters);
        assert!(!fatal.is_backtrack());
        assert_eq!(
            fatal.expect(super::Error::ExpectedNodeTest),
            fatal,
            "a fatal cause is never renamed into a recoverable one"
        );
    }

    #[test]
    fn diagnostic_selection_has_independent_expected_errors() {
        // Explicit lexer contracts, not a comparison of two callers of the same lexer:
        // nonrecoverable quote errors win; no progress produces UnableToCreateToken.
        for (source, expected) in [
            ("!", super::Error::UnableToCreateToken),
            ("'unterminated", super::Error::MismatchedQuoteCharacters),
            ("\"unterminated", super::Error::MismatchedQuoteCharacters),
        ] {
            assert_eq!(super::Tokenizer::new(source).next(), Some(Err(expected)));
        }
    }

    use std::borrow::ToOwned;

    use crate::node_test;
    use crate::token::{AxisName, NodeTestName, Token};

    use super::Error::*;
    use super::{Error, TokenDeabbreviator, TokenResult, Tokenizer};

    fn is_finished(tokenizer: &Tokenizer) -> bool {
        !tokenizer.has_more_tokens()
    }

    fn all_tokens_raw<I>(tokenizer: I) -> Result<Vec<Token>, Error>
    where
        I: Iterator<Item = TokenResult>,
    {
        tokenizer.collect()
    }

    fn all_tokens<I>(tokenizer: I) -> Vec<Token>
    where
        I: Iterator<Item = TokenResult>,
    {
        match all_tokens_raw(tokenizer) {
            Ok(toks) => toks,
            Err(msg) => panic!("{msg:?}"),
        }
    }

    fn name_test(local_part: &str) -> Token {
        Token::NameTest(node_test::NameTest {
            prefix: None,
            local_part: local_part.to_owned(),
        })
    }

    #[test]
    fn empty_string_has_no_tokens() {
        let tokenizer = Tokenizer::new("");
        assert!(is_finished(&tokenizer));
    }

    #[test]
    fn tokenizes_simple_string() {
        let tokenizer = Tokenizer::new("hello");

        assert_eq!(all_tokens(tokenizer), vec![name_test("hello")]);
    }

    #[test]
    fn tokenizes_grandchild_selector() {
        let tokenizer = Tokenizer::new("hello/world");

        assert_eq!(
            all_tokens(tokenizer),
            vec![name_test("hello"), Token::Slash, name_test("world")]
        );
    }

    #[test]
    fn tokenizes_great_grandchild_selector() {
        let tokenizer = Tokenizer::new("hello/there/world");

        assert_eq!(
            all_tokens(tokenizer),
            vec![
                name_test("hello"),
                Token::Slash,
                name_test("there"),
                Token::Slash,
                name_test("world")
            ]
        );
    }

    #[test]
    fn tokenizes_qualified_names() {
        let tokenizer = Tokenizer::new("ns:foo");

        let name = node_test::NameTest {
            prefix: Some("ns".to_owned()),
            local_part: "foo".to_owned(),
        };
        assert_eq!(all_tokens(tokenizer), vec![Token::NameTest(name)]);
    }

    #[test]
    fn ignores_whitespace_around_tokens() {
        let tokenizer = Tokenizer::new(" @\t@\n@\r");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::AtSign, Token::AtSign, Token::AtSign]
        );
    }

    #[test]
    fn tokenizes_wildcard_name_test() {
        let tokenizer = Tokenizer::new("*");

        assert_eq!(all_tokens(tokenizer), vec![name_test("*")]);
    }

    #[test]
    fn tokenizes_axis_selector() {
        let tokenizer = Tokenizer::new("ancestor::world");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Axis(AxisName::Ancestor), name_test("world")]
        );
    }

    #[test]
    fn tokenizes_axis_selector_that_contains_another_axis() {
        let tokenizer = Tokenizer::new("ancestor-or-self::world");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Axis(AxisName::AncestorOrSelf), name_test("world")]
        );
    }

    #[test]
    fn tokenizes_single_slash() {
        let tokenizer = Tokenizer::new("/");

        assert_eq!(all_tokens(tokenizer), vec![Token::Slash]);
    }

    #[test]
    fn tokenizes_double_slash() {
        let tokenizer = Tokenizer::new("//");

        assert_eq!(all_tokens(tokenizer), vec![Token::DoubleSlash]);
    }

    #[test]
    fn tokenizes_double_slash_separator() {
        let tokenizer = Tokenizer::new("hello//world");

        assert_eq!(
            all_tokens(tokenizer),
            vec![name_test("hello"), Token::DoubleSlash, name_test("world")]
        );
    }

    #[test]
    fn tokenizes_left_paren() {
        let tokenizer = Tokenizer::new("(");

        assert_eq!(all_tokens(tokenizer), vec![Token::LeftParen]);
    }

    #[test]
    fn tokenizes_right_paren() {
        let tokenizer = Tokenizer::new(")");

        assert_eq!(all_tokens(tokenizer), vec![Token::RightParen]);
    }

    #[test]
    fn tokenizes_at_sign() {
        let tokenizer = Tokenizer::new("@");

        assert_eq!(all_tokens(tokenizer), vec![Token::AtSign]);
    }

    #[test]
    fn tokenizes_single_dot() {
        let tokenizer = Tokenizer::new(".");

        assert_eq!(all_tokens(tokenizer), vec![Token::CurrentNode]);
    }

    #[test]
    fn tokenizes_double_dot() {
        let tokenizer = Tokenizer::new("..");

        assert_eq!(all_tokens(tokenizer), vec![Token::ParentNode]);
    }

    #[test]
    fn tokenizes_integral_number() {
        let tokenizer = Tokenizer::new("42");

        assert_eq!(all_tokens(tokenizer), vec![Token::Number(42.0)]);
    }

    #[test]
    fn tokenizes_decimal_number() {
        let tokenizer = Tokenizer::new("42.42");

        assert_eq!(all_tokens(tokenizer), vec![Token::Number(42.42)]);
    }

    #[test]
    fn tokenizes_decimal_number_without_integral_part() {
        let tokenizer = Tokenizer::new(".40");

        assert_eq!(all_tokens(tokenizer), vec![Token::Number(0.40)]);
    }

    #[test]
    fn tokenizes_left_bracket() {
        let tokenizer = Tokenizer::new("[");

        assert_eq!(all_tokens(tokenizer), vec![Token::LeftBracket]);
    }

    #[test]
    fn tokenizes_right_bracket() {
        let tokenizer = Tokenizer::new("]");

        assert_eq!(all_tokens(tokenizer), vec![Token::RightBracket]);
    }

    #[test]
    fn tokenizes_apostrophe_literal() {
        let tokenizer = Tokenizer::new("'hello!'");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Literal("hello!".to_owned())]
        );
    }

    #[test]
    fn tokenizes_double_quote_literal() {
        let tokenizer = Tokenizer::new("\"1.23\"");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Literal("1.23".to_owned())]
        );
    }

    #[test]
    fn tokenizes_variable_reference() {
        let tokenizer = Tokenizer::new("$yo");

        assert_eq!(all_tokens(tokenizer), vec![Token::Variable("yo".into())]);
    }

    #[test]
    fn tokenizes_variable_reference_prefixed_name() {
        let tokenizer = Tokenizer::new("$yo:dawg");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Variable(("yo", "dawg").into())]
        );
    }

    #[test]
    fn tokenizes_plus_sign() {
        let tokenizer = Tokenizer::new("+");

        assert_eq!(all_tokens(tokenizer), vec![Token::PlusSign]);
    }

    #[test]
    fn tokenizes_minus_sign() {
        let tokenizer = Tokenizer::new("-");

        assert_eq!(all_tokens(tokenizer), vec![Token::MinusSign]);
    }

    #[test]
    fn tokenizes_pipe() {
        let tokenizer = Tokenizer::new("|");

        assert_eq!(all_tokens(tokenizer), vec![Token::Pipe]);
    }

    #[test]
    fn tokenizes_equal_sign() {
        let tokenizer = Tokenizer::new("=");

        assert_eq!(all_tokens(tokenizer), vec![Token::Equal]);
    }

    #[test]
    fn tokenizes_not_equal_sign() {
        let tokenizer = Tokenizer::new("!=");

        assert_eq!(all_tokens(tokenizer), vec![Token::NotEqual]);
    }

    #[test]
    fn tokenizes_less_than() {
        let tokenizer = Tokenizer::new("<");

        assert_eq!(all_tokens(tokenizer), vec![Token::LessThan]);
    }

    #[test]
    fn tokenizes_less_than_or_equal() {
        let tokenizer = Tokenizer::new("<=");

        assert_eq!(all_tokens(tokenizer), vec![Token::LessThanOrEqual]);
    }

    #[test]
    fn tokenizes_greater_than() {
        let tokenizer = Tokenizer::new(">");

        assert_eq!(all_tokens(tokenizer), vec![Token::GreaterThan]);
    }

    #[test]
    fn tokenizes_greater_than_or_equal() {
        let tokenizer = Tokenizer::new(">=");

        assert_eq!(all_tokens(tokenizer), vec![Token::GreaterThanOrEqual]);
    }

    #[test]
    fn special_preceding_token_forces_named_operator_and() {
        let tokenizer = Tokenizer::new("1andz2");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Number(1.0), Token::And, name_test("z2")]
        );
    }

    #[test]
    fn special_preceding_token_forces_named_operator_or() {
        let tokenizer = Tokenizer::new("2oror");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Number(2.0), Token::Or, name_test("or")]
        );
    }

    #[test]
    fn special_preceding_token_forces_named_operator_mod() {
        let tokenizer = Tokenizer::new("3moddiv");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Number(3.0), Token::Remainder, name_test("div")]
        );
    }

    #[test]
    fn special_preceding_token_forces_named_operator_div() {
        let tokenizer = Tokenizer::new("1divz2");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Number(1.0), Token::Divide, name_test("z2")]
        );
    }

    #[test]
    fn special_preceding_token_forces_named_operator_multiply() {
        let tokenizer = Tokenizer::new("1*2");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::Number(1.0), Token::Multiply, Token::Number(2.0)]
        );
    }

    #[test]
    fn tokenizes_node_test_without_args() {
        let tokenizer = Tokenizer::new("text()");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::NodeTest(NodeTestName::Text)]
        );
    }

    #[test]
    fn tokenizes_xml_whitespace_inside_node_test_parentheses() {
        // XPath 1.0 productions [35] and [38] tokenize the parentheses separately, so XML
        // whitespace may separate them: https://www.w3.org/TR/xpath/#location-paths
        for source in [
            "node( )",
            "node ()",
            "text(\t)",
            "comment(\r\n)",
            "processing-instruction( 'target' )",
            "processing-instruction ('target')",
        ] {
            assert!(
                all_tokens(Tokenizer::new(source))
                    .iter()
                    .any(|token| matches!(token, Token::NodeTest(_))),
                "{source} must remain a node test"
            );
        }
    }

    #[test]
    fn tokenizes_processing_instruction_node_test_without_args() {
        let tokenizer = Tokenizer::new("processing-instruction()");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::NodeTest(NodeTestName::ProcessingInstruction(None))]
        );
    }

    #[test]
    fn tokenizes_processing_instruction_node_test_with_args() {
        let tokenizer = Tokenizer::new("processing-instruction('hi')");

        assert_eq!(
            all_tokens(tokenizer),
            vec![Token::NodeTest(NodeTestName::ProcessingInstruction(Some(
                "hi".to_owned()
            )))]
        );
    }

    #[test]
    fn tokenizes_function_call() {
        let tokenizer = Tokenizer::new("hello()");

        assert_eq!(
            all_tokens(tokenizer),
            vec![
                Token::Function("hello".into()),
                Token::LeftParen,
                Token::RightParen
            ]
        );
    }

    #[test]
    fn tokenizes_function_call_with_argument() {
        let tokenizer = Tokenizer::new("hello(1)");

        assert_eq!(
            all_tokens(tokenizer),
            vec![
                Token::Function("hello".into()),
                Token::LeftParen,
                Token::Number(1.0),
                Token::RightParen
            ]
        );
    }

    #[test]
    fn tokenizes_function_call_with_multiple_arguments() {
        let tokenizer = Tokenizer::new("hello(1, 2)");

        assert_eq!(
            all_tokens(tokenizer),
            vec![
                Token::Function("hello".into()),
                Token::LeftParen,
                Token::Number(1.0),
                Token::Comma,
                Token::Number(2.0),
                Token::RightParen
            ]
        );
    }

    #[test]
    fn tokenizes_function_call_with_prefixed_name() {
        let tokenizer = Tokenizer::new("ns:hello()");

        assert_eq!(
            all_tokens(tokenizer),
            vec![
                Token::Function(("ns", "hello").into()),
                Token::LeftParen,
                Token::RightParen
            ]
        );
    }

    #[test]
    fn exception_thrown_when_nothing_was_tokenized() {
        let tokenizer = Tokenizer::new("!");
        let res = all_tokens_raw(tokenizer);

        assert_eq!(Err(UnableToCreateToken), res);
    }

    #[test]
    fn exception_thrown_when_name_test_has_no_local_name() {
        let tokenizer = Tokenizer::new("ns:");
        let res = all_tokens_raw(tokenizer);

        assert_eq!(Err(UnableToCreateToken), res);
    }

    #[test]
    fn exception_thrown_when_quote_characters_mismatched() {
        let tokenizer = Tokenizer::new("'hello\"");
        let res = all_tokens_raw(tokenizer);

        assert_eq!(Err(MismatchedQuoteCharacters), res);
    }

    #[test]
    fn converts_at_sign_to_attribute_axis() {
        let input_tokens: Vec<TokenResult> = vec![Ok(Token::AtSign)];

        let deabbrv = TokenDeabbreviator::new(input_tokens.into_iter());

        assert_eq!(all_tokens(deabbrv), vec![Token::Axis(AxisName::Attribute)]);
    }

    #[test]
    fn converts_double_slash_to_descendant_or_self() {
        let input_tokens: Vec<TokenResult> = vec![Ok(Token::DoubleSlash)];

        let deabbrv = TokenDeabbreviator::new(input_tokens.into_iter());

        assert_eq!(
            all_tokens(deabbrv),
            vec![
                Token::Slash,
                Token::Axis(AxisName::DescendantOrSelf),
                Token::NodeTest(NodeTestName::Node),
                Token::Slash
            ]
        );
    }

    #[test]
    fn converts_current_node_to_self_node() {
        let input_tokens: Vec<TokenResult> = vec![Ok(Token::CurrentNode)];

        let deabbrv = TokenDeabbreviator::new(input_tokens.into_iter());

        assert_eq!(
            all_tokens(deabbrv),
            vec![
                Token::Axis(AxisName::SelfAxis),
                Token::NodeTest(NodeTestName::Node)
            ]
        );
    }

    #[test]
    fn converts_parent_node_to_parent_node() {
        let input_tokens: Vec<TokenResult> = vec![Ok(Token::ParentNode)];

        let deabbrv = TokenDeabbreviator::new(input_tokens.into_iter());

        assert_eq!(
            all_tokens(deabbrv),
            vec![
                Token::Axis(AxisName::Parent),
                Token::NodeTest(NodeTestName::Node)
            ]
        );
    }
}
