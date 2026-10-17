#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use peresil::{self, Identifier, Recoverable, StringPoint, try_parse};
use snafu::Snafu;
use sxd_document_no_unsafe::parser::XmlParseExt;

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

type XPathProgress<'a, T, E> = peresil::Progress<StringPoint<'a>, T, E>;

// The old ParseMaster accumulated every diagnostic and raw_next_token retained only the last
// one at the furthest position. Keep precisely that selection without a diagnostic Vec.
struct XPathMaster<'a> {
    failure: Option<(StringPoint<'a>, Error)>,
}

impl<'a> XPathMaster<'a> {
    fn consume<T>(&mut self, progress: XPathProgress<'a, T, Error>) {
        if let peresil::Status::Failure(error) = progress.status
            && (!error.recoverable()
                || self
                    .failure
                    .as_ref()
                    .is_none_or(|(point, _)| progress.point >= *point))
        {
            self.failure = Some((progress.point, error));
        }
    }

    fn alternate<T>(&mut self) -> XPathAlternate<'_, 'a, T> {
        XPathAlternate {
            master: self,
            current: None,
        }
    }

    fn finish<T>(&mut self, progress: XPathProgress<'a, T, Error>) -> XPathProgress<'a, T, Error> {
        if matches!(progress.status, peresil::Status::Success(_)) {
            return progress;
        }
        self.consume(progress);
        let (point, error) = self
            .failure
            .take()
            .expect("failed alternative supplies a diagnostic");
        peresil::Progress::failure(point, error)
    }
}

struct XPathAlternate<'m, 'a, T> {
    master: &'m mut XPathMaster<'a>,
    current: Option<XPathProgress<'a, T, Error>>,
}

impl<'a, T> XPathAlternate<'_, 'a, T> {
    fn one(
        mut self,
        parser: impl FnOnce(&mut XPathMaster<'a>) -> XPathProgress<'a, T, Error>,
    ) -> Self {
        if self.current.as_ref().is_none_or(|progress| matches!(&progress.status, peresil::Status::Failure(error) if error.recoverable())) {
            let next = parser(self.master);
            if let Some(previous) = self.current.take() {
                self.master.consume(previous);
            }
            self.current = Some(next);
        }
        self
    }

    fn finish(self) -> XPathProgress<'a, T, Error> {
        self.current.expect("at least one alternative")
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

impl Recoverable for Error {
    fn recoverable(&self) -> bool {
        use self::Error::*;
        match *self {
            AllocationLimit | MismatchedQuoteCharacters | UnableToCreateToken => false,
            _ => true,
        }
    }
}

trait ProgressExt<P, T, E>: Sized {
    fn context<C, E2>(self, context: C) -> peresil::Progress<P, T, E2>
    where
        C: snafu::IntoError<E2, Source = snafu::NoneError>,
        E2: std::error::Error + snafu::ErrorCompat;
}

impl<P, T, E> ProgressExt<P, T, E> for peresil::Progress<P, T, E> {
    fn context<C, E2>(self, context: C) -> peresil::Progress<P, T, E2>
    where
        C: snafu::IntoError<E2, Source = snafu::NoneError>,
        E2: std::error::Error + snafu::ErrorCompat,
    {
        self.map_err(|_| context.into_error(snafu::NoneError))
    }
}

trait XPathParseExt<'a> {
    fn consume_quoted_string(&self, quote: &str) -> XPathProgress<'a, &'a str, ()>;
}

impl<'a> XPathParseExt<'a> for StringPoint<'a> {
    fn consume_quoted_string(&self, quote: &str) -> XPathProgress<'a, &'a str, ()> {
        let end_of_str = self.s.find(quote).or(Some(self.s.len()));
        self.consume_to(end_of_str)
    }
}

static SINGLE_CHAR_TOKENS: [Identifier<'static, Token<'static>>; 13] = [
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

static TWO_CHAR_TOKENS: [Identifier<'static, Token<'static>>; 5] = [
    ("<=", Token::LessThanOrEqual),
    (">=", Token::GreaterThanOrEqual),
    ("!=", Token::NotEqual),
    ("//", Token::DoubleSlash),
    ("..", Token::ParentNode),
];

static NAMED_OPERATORS: [Identifier<'static, Token<'static>>; 5] = [
    ("and", Token::And),
    ("or", Token::Or),
    ("mod", Token::Remainder),
    ("div", Token::Divide),
    ("*", Token::Multiply),
];

// These will be matched in order, so substrings should come later.
static AXES: [Identifier<'static, AxisName>; 13] = [
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

static NODE_TESTS: [Identifier<'static, NodeTestName<&'static str>>; 4] = [
    ("comment", NodeTestName::Comment),
    ("text", NodeTestName::Text),
    (
        "processing-instruction",
        NodeTestName::ProcessingInstruction(None),
    ),
    ("node", NodeTestName::Node),
];

fn parse_literal<'a>(
    pm: &mut XPathMaster<'a>,
    p: StringPoint<'a>,
) -> XPathProgress<'a, &'a str, Error> {
    fn with_quote<'a>(p: StringPoint<'a>, quote: &str) -> XPathProgress<'a, &'a str, Error> {
        let (p, _) = try_parse!(p.consume_literal(quote).context(ExpectedQuote));
        let (p, v) = try_parse!(p.consume_quoted_string(quote).map_err(|_| unreachable!()));
        let (p, _) = try_parse!(p.consume_literal(quote).context(MismatchedQuoteCharacters));

        peresil::Progress::success(p, v)
    }

    pm.alternate()
        .one(|_| with_quote(p, "\x22")) // "
        .one(|_| with_quote(p, "\x27")) // '
        .finish()
}

fn parse_quoted_literal<'a>(
    pm: &mut XPathMaster<'a>,
    p: StringPoint<'a>,
) -> XPathProgress<'a, Token<'a>, Error> {
    let (p, value) = try_parse!(parse_literal(pm, p));
    peresil::Progress::success(p, Token::Literal(value))
}

fn parse_number<'a>(
    pm: &mut XPathMaster<'a>,
    p: StringPoint<'a>,
) -> XPathProgress<'a, Token<'a>, Error> {
    fn fractional_part(p: StringPoint<'_>) -> XPathProgress<'_, (), ()> {
        let (p, _) = try_parse!(p.consume_literal("."));
        let (p, _) = p.consume_decimal_chars().optional(p);

        peresil::Progress::success(p, ())
    }

    fn with_integer(p: StringPoint<'_>) -> XPathProgress<'_, (), ()> {
        let (p, _) = try_parse!(p.consume_decimal_chars());
        let (p, _) = fractional_part(p).optional(p);

        peresil::Progress::success(p, ())
    }

    fn without_integer(p: StringPoint<'_>) -> XPathProgress<'_, (), ()> {
        let (p, _) = try_parse!(p.consume_literal("."));
        let (p, _) = try_parse!(p.consume_decimal_chars());

        peresil::Progress::success(p, ())
    }

    let before_p = p;

    let (p, _) = try_parse!({
        pm.alternate()
            .one(|_| with_integer(p).context(ExpectedNumber))
            .one(|_| without_integer(p).context(ExpectedNumber))
            .finish()
    });

    let num = before_p.to(p);
    // Should always be able to parse as we've pre-validated with our own parser
    let num = num.parse().expect("Could not parse number");

    peresil::Progress::success(p, Token::Number(num))
}

fn parse_current_node(p: StringPoint<'_>) -> XPathProgress<'_, Token<'_>, Error> {
    let (p, _) = try_parse!(p.consume_literal(".").context(ExpectedCurrentNode));

    peresil::Progress::success(p, Token::CurrentNode)
}

fn parse_named_operators(
    p: StringPoint<'_>,
    prefer_named_ops: bool,
) -> XPathProgress<'_, Token<'_>, Error> {
    if prefer_named_ops {
        p.consume_identifier(&NAMED_OPERATORS)
            .context(ExpectedNamedOperator)
    } else {
        // This is ugly, but we have to return some error
        peresil::Progress::failure(p, Error::NotTokenizingNamedOperators)
    }
}

fn parse_axis_specifier(p: StringPoint<'_>) -> XPathProgress<'_, Token<'_>, Error> {
    // Ideally, we would check for the pair of the name and the ::,
    // then loop. This would prevent us from having to order AXES.
    let (p, axis) = try_parse!(p.consume_identifier(&AXES).context(ExpectedAxis));
    let (p, _) = try_parse!(p.consume_literal("::").context(ExpectedAxisSeparator));

    peresil::Progress::success(p, Token::Axis(axis))
}

fn parse_node_type<'a>(
    pm: &mut XPathMaster<'a>,
    p: StringPoint<'a>,
) -> XPathProgress<'a, Token<'a>, Error> {
    fn without_arg(p: StringPoint<'_>) -> XPathProgress<'_, Token<'_>, ()> {
        let (p, node_type) = try_parse!(p.consume_identifier(&NODE_TESTS));
        let (p, _) = p.consume_space().optional(p);
        let (p, _) = try_parse!(p.consume_literal("("));
        let (p, _) = p.consume_space().optional(p);
        let (p, _) = try_parse!(p.consume_literal(")"));

        peresil::Progress::success(p, Token::NodeTest(node_type))
    }

    fn with_arg<'a>(
        pm: &mut XPathMaster<'a>,
        p: StringPoint<'a>,
    ) -> XPathProgress<'a, Token<'a>, Error> {
        let (p, _) = try_parse!(
            p.consume_literal("processing-instruction")
                .context(ExpectedNodeTest)
        );
        let (p, _) = p.consume_space().optional(p);
        let (p, _) = try_parse!(p.consume_literal("(").context(ExpectedNodeTest));
        let (p, _) = p.consume_space().optional(p);
        let (p, arg) = try_parse!(parse_literal(pm, p).context(ExpectedNodeTest));
        let (p, _) = p.consume_space().optional(p);
        let (p, _) = try_parse!(p.consume_literal(")").context(ExpectedNodeTest));

        let name = NodeTestName::ProcessingInstruction(Some(arg));
        peresil::Progress::success(p, Token::NodeTest(name))
    }

    pm.alternate()
        .one(|_| without_arg(p).context(ExpectedNodeTest))
        .one(|pm| with_arg(pm, p))
        .finish()
}

fn parse_function_call(p: StringPoint<'_>) -> XPathProgress<'_, Token<'_>, Error> {
    let (p, name) = try_parse!(p.consume_prefixed_name().context(ExpectedPrefixedName));
    // Do not advance the point here. We want to know if there *is* a
    // left-paren, but do not want to actually consume it here.
    try_parse!(p.consume_literal("(").context(ExpectedLeftParenthesis));

    peresil::Progress::success(p, Token::Function(name))
}

fn parse_name_test<'a>(
    pm: &mut XPathMaster<'a>,
    p: StringPoint<'a>,
) -> XPathProgress<'a, Token<'a>, Error> {
    fn wildcard(p: StringPoint<'_>) -> XPathProgress<'_, Token<'_>, Error> {
        let (p, wc) = try_parse!(p.consume_literal("*").context(ExpectedNameTest));

        let name = node_test::NameTest {
            prefix: None,
            local_part: wc,
        };
        peresil::Progress::success(p, Token::NameTest(name))
    }

    fn prefixed_wildcard(p: StringPoint<'_>) -> XPathProgress<'_, Token<'_>, Error> {
        let (p, prefix) = try_parse!(p.consume_ncname().context(ExpectedNameTest));
        let (p, _) = try_parse!(p.consume_literal(":").context(ExpectedNameTest));
        let (p, wc) = try_parse!(p.consume_literal("*").context(ExpectedNameTest));

        let name = node_test::NameTest {
            prefix: Some(prefix),
            local_part: wc,
        };
        peresil::Progress::success(p, Token::NameTest(name))
    }

    fn prefixed_name(p: StringPoint<'_>) -> XPathProgress<'_, Token<'_>, Error> {
        let (p, name) = try_parse!(p.consume_prefixed_name().context(ExpectedNameTest));
        peresil::Progress::success(
            p,
            Token::NameTest(node_test::NameTest {
                prefix: name.prefix(),
                local_part: name.local_part(),
            }),
        )
    }

    pm.alternate()
        .one(|_| wildcard(p))
        .one(|_| prefixed_wildcard(p))
        .one(|_| prefixed_name(p))
        .finish()
}

fn parse_variable_reference(p: StringPoint<'_>) -> XPathProgress<'_, Token<'_>, Error> {
    let (p, _) = try_parse!(p.consume_literal("$").context(ExpectedVariableReference));
    let (p, name) = try_parse!(p.consume_prefixed_name().context(ExpectedPrefixedName));

    peresil::Progress::success(p, Token::Variable(name))
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

    fn parse_token<'a>(
        &self,
        pm: &mut XPathMaster<'a>,
        p: StringPoint<'a>,
    ) -> XPathProgress<'a, Token<'a>, Error> {
        let (p, _) = p.consume_space().optional(p);

        let (p, tok) = try_parse!({
            pm.alternate()
                .one(|_| {
                    p.consume_identifier(&TWO_CHAR_TOKENS)
                        .context(ExpectedToken)
                })
                .one(|_| {
                    p.consume_identifier(&SINGLE_CHAR_TOKENS)
                        .context(ExpectedToken)
                })
                .one(|pm| parse_quoted_literal(pm, p))
                .one(|pm| parse_number(pm, p))
                .one(|_| parse_current_node(p))
                .one(|_| parse_named_operators(p, self.prefer_recognition_of_operator_names))
                .one(|_| parse_axis_specifier(p))
                .one(|pm| parse_node_type(pm, p))
                .one(|_| parse_function_call(p))
                .one(|pm| parse_name_test(pm, p))
                .one(|_| parse_variable_reference(p))
                .finish()
        });

        let (p, _) = p.consume_space().optional(p);

        peresil::Progress::success(p, tok)
    }

    fn raw_next_token(&mut self) -> BorrowedTokenResult<'input> {
        let mut pm = XPathMaster { failure: None };
        let p = StringPoint {
            s: &self.xpath[self.start..],
            offset: self.start,
        };

        let r = self.parse_token(&mut pm, p);
        match pm.finish(r) {
            peresil::Progress {
                status: peresil::Status::Success(data),
                point,
            } => {
                self.start = point.offset;
                Ok(data)
            }
            peresil::Progress {
                status: peresil::Status::Failure(error),
                point,
            } => {
                if point.offset == self.start {
                    UnableToCreateToken.fail()
                } else {
                    Err(error)
                }
            }
        }
    }

    fn next_token(&mut self) -> BorrowedTokenResult<'input> {
        let token = self.raw_next_token()?;

        if !(token.precedes_node_test() || token.precedes_expression() || token.is_operator()) {
            // See http://www.w3.org/TR/xpath/#exprlex
            self.prefer_recognition_of_operator_names = true;
        } else {
            self.prefer_recognition_of_operator_names = false;
        }

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
    fn diagnostic_collector_keeps_furthest_latest_and_fatal_errors() {
        // Freeze the collector's selection independently of both factory entrypoints.
        let start = peresil::StringPoint::new("ab");
        let later = start.consume_literal("a").point;
        let mut master = super::XPathMaster { failure: None };
        master.consume::<()>(peresil::Progress::failure(
            later,
            super::Error::ExpectedNumber,
        ));
        master.consume::<()>(peresil::Progress::failure(
            start,
            super::Error::ExpectedQuote,
        ));
        assert_eq!(master.failure, Some((later, super::Error::ExpectedNumber)));
        master.consume::<()>(peresil::Progress::failure(
            later,
            super::Error::ExpectedAxis,
        ));
        assert_eq!(master.failure, Some((later, super::Error::ExpectedAxis)));
        master.consume::<()>(peresil::Progress::failure(
            start,
            super::Error::MismatchedQuoteCharacters,
        ));
        assert_eq!(
            master.failure,
            Some((start, super::Error::MismatchedQuoteCharacters))
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
            Err(msg) => panic!("{:?}", msg),
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
