#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use snafu::Snafu;

use super::grammar::{self, Binary, Builder, Fault, Node, Test};
use crate::Value;
use crate::axis::Axis;
use crate::expression::{self, SubExpression};
use crate::node_test::SubNodeTest;
use crate::token::Token;
use crate::tokenizer::{self, TokenResult};

#[cfg(test)]
const MAX_EXPRESSION_NESTING: usize = grammar::MAX_DEPTH;

#[allow(missing_copy_implementations)]
pub struct Parser<'a> {
    budget: Option<&'a crate::ParseBudget>,
}

impl<'a> Parser<'a> {
    pub fn new() -> Self {
        Self { budget: None }
    }

    pub fn with_budget(budget: &'a crate::ParseBudget) -> Self {
        Self {
            budget: Some(budget),
        }
    }

    fn charge(&self, bytes: usize) -> Result<(), Error> {
        self.budget.map_or(Ok(()), |budget| budget.charge(bytes))
    }

    fn boxed<T: expression::Expression + 'static>(&self, value: T) -> Result<SubExpression, Error> {
        self.charge(std::mem::size_of::<T>())?;
        Ok(Box::new(value))
    }

    fn push<T>(&self, values: &mut Vec<T>, value: T) -> Result<(), Error> {
        if values.len() == values.capacity() {
            let (capacity, bytes) = self.vector_growth::<T>(values.capacity())?;
            self.charge(bytes)?;
            // Allocate beside the old buffer so the reservation models the real overlap.
            let mut replacement = Vec::with_capacity(capacity);
            replacement.append(values);
            let old_bytes = values.capacity() * std::mem::size_of::<T>();
            *values = replacement;
            if let Some(budget) = self.budget {
                budget.release(old_bytes);
            }
        }
        values.push(value);
        Ok(())
    }

    fn vector_growth<T>(&self, old_capacity: usize) -> Result<(usize, usize), Error> {
        let overflow = || Error::AllocationLimit {
            limit: self.budget.map_or(usize::MAX, |budget| budget.limit),
            actual: usize::MAX,
        };
        let capacity = old_capacity.checked_mul(2).ok_or_else(overflow)?.max(4);
        let bytes = capacity
            .checked_mul(std::mem::size_of::<T>())
            .ok_or_else(overflow)?;
        if bytes > isize::MAX as usize {
            return Err(overflow());
        }
        Ok((capacity, bytes))
    }

    pub fn parse<I>(&self, source: I) -> ParseResult<SubExpression>
    where
        I: Iterator<Item = TokenResult>,
    {
        grammar::Grammar::new(self)
            .parse(source)
            .map_err(Into::into)
    }

    #[cfg(test)]
    fn parse_node_test<I>(
        &self,
        source: &mut std::iter::Peekable<I>,
    ) -> Result<Option<SubNodeTest>, Error>
    where
        I: Iterator<Item = TokenResult>,
    {
        if !matches!(source.peek(), Some(Ok(Token::NodeTest(_)))) {
            return Ok(None);
        }
        match source
            .next()
            .expect("peeked token")
            .map_err(|source| Error::Tokenizer { source })?
        {
            Token::NodeTest(test) => Ok(Some(native_test(Test::Kind(test)))),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Snafu, Clone, PartialEq)]
#[snafu(context(suffix(false)))]
#[cfg_attr(test, snafu(visibility(pub(crate))))]
pub enum Error {
    /// live parser heap payload would exceed the caller's allowance
    AllocationLimit { limit: usize, actual: usize },
    /// XPath was empty
    NoXPath,
    /// empty predicate
    EmptyPredicate,
    /// extra unparsed tokens
    ExtraUnparsedTokens,
    /// expression grammar nesting exceeded the parser safety ceiling
    NestingLimit,
    /// ran out of input
    RanOutOfInput,
    /// right hand side of expression is missing
    RightHandSideExpressionMissing,
    /// function argument is missing
    ArgumentMissing,
    #[snafu(display("tokenizer error: {}", source))]
    Tokenizer { source: tokenizer::Error },
    /// trailing slash
    TrailingSlash,
    #[snafu(display("unexpected token: {:?}", token))]
    UnexpectedToken { token: Token },
}

pub type ParseResult<T = Option<SubExpression>> = Result<T, Error>;

impl From<Fault<Token>> for Error {
    fn from(fault: Fault<Token>) -> Self {
        match fault {
            Fault::NoXPath => Self::NoXPath,
            Fault::EmptyPredicate => Self::EmptyPredicate,
            Fault::ExtraUnparsedTokens => Self::ExtraUnparsedTokens,
            Fault::NestingLimit => Self::NestingLimit,
            Fault::RanOutOfInput => Self::RanOutOfInput,
            Fault::RightHandSideExpressionMissing => Self::RightHandSideExpressionMissing,
            Fault::ArgumentMissing => Self::ArgumentMissing,
            Fault::Tokenizer(source) => Self::Tokenizer { source },
            Fault::TrailingSlash => Self::TrailingSlash,
            Fault::UnexpectedToken(token) => Self::UnexpectedToken { token },
            Fault::AllocationLimit { limit, actual } => Self::AllocationLimit { limit, actual },
            // The native builder has no shared allocator. A scoped allocation
            // failure must never be converted to this legacy parser error.
            #[cfg(feature = "embedded")]
            Fault::Resource(_) => unreachable!("resource failure from native builder"),
        }
    }
}

fn native_failure(error: Error) -> Fault<Token> {
    match error {
        Error::AllocationLimit { limit, actual } => Fault::AllocationLimit { limit, actual },
        _ => unreachable!("non-allocation failure from native storage"),
    }
}

fn native_test(test: Test<String>) -> SubNodeTest {
    test.into()
}

impl Builder for Parser<'_> {
    type Name = crate::OwnedPrefixedName;
    type Text = String;
    type Expression = SubExpression;
    type Predicate = expression::Predicate;
    type Step = expression::Step;
    type List<T> = Vec<T>;

    fn list<T>(&self) -> Vec<T> {
        Vec::new()
    }

    fn inspect(&self) -> Result<(), Fault<Token>> {
        Ok(())
    }

    fn push<T>(&self, list: &mut Vec<T>, value: T) -> Result<(), Fault<Token>> {
        self.push(list, value).map_err(native_failure)
    }

    fn node(&self, node: Node<Self>, _depth: usize) -> Result<SubExpression, Fault<Token>> {
        match node {
            Node::Context => self.boxed(expression::ContextNode).map_err(native_failure),
            Node::Root => self.boxed(expression::RootNode).map_err(native_failure),
            Node::Number(value) => self
                .boxed(expression::Literal::from(Value::Number(value)))
                .map_err(native_failure),
            Node::String(value) => self
                .boxed(expression::Literal::from(Value::String(value)))
                .map_err(native_failure),
            Node::Variable(name) => self
                .boxed(expression::Variable { name })
                .map_err(native_failure),
            Node::Function(name, arguments) => self
                .boxed(expression::Function { name, arguments })
                .map_err(native_failure),
            Node::Negate(expression) => self
                .boxed(expression::Negation { expression })
                .map_err(native_failure),
            Node::Path(start, steps) => {
                self.charge(std::mem::size_of::<expression::Path>())
                    .map_err(native_failure)?;
                Ok(expression::Path::new(start, steps))
            }
            Node::Filter(selector, predicate) => {
                self.charge(std::mem::size_of::<expression::Filter>())
                    .map_err(native_failure)?;
                Ok(expression::Filter::new(selector, predicate))
            }
            Node::Binary(operation, left, right) => {
                let (size, constructor): (
                    usize,
                    fn(SubExpression, SubExpression) -> SubExpression,
                ) = match operation {
                    Binary::Or => (std::mem::size_of::<expression::Or>(), expression::Or::new),
                    Binary::And => (std::mem::size_of::<expression::And>(), expression::And::new),
                    Binary::Equal => (
                        std::mem::size_of::<expression::Equal>(),
                        expression::Equal::new,
                    ),
                    Binary::NotEqual => (
                        std::mem::size_of::<expression::NotEqual>(),
                        expression::NotEqual::new,
                    ),
                    Binary::Less => (
                        std::mem::size_of::<expression::Relational>(),
                        expression::Relational::less_than,
                    ),
                    Binary::LessEqual => (
                        std::mem::size_of::<expression::Relational>(),
                        expression::Relational::less_than_or_equal,
                    ),
                    Binary::Greater => (
                        std::mem::size_of::<expression::Relational>(),
                        expression::Relational::greater_than,
                    ),
                    Binary::GreaterEqual => (
                        std::mem::size_of::<expression::Relational>(),
                        expression::Relational::greater_than_or_equal,
                    ),
                    Binary::Add => (
                        std::mem::size_of::<expression::Math>(),
                        expression::Math::addition,
                    ),
                    Binary::Subtract => (
                        std::mem::size_of::<expression::Math>(),
                        expression::Math::subtraction,
                    ),
                    Binary::Multiply => (
                        std::mem::size_of::<expression::Math>(),
                        expression::Math::multiplication,
                    ),
                    Binary::Divide => (
                        std::mem::size_of::<expression::Math>(),
                        expression::Math::division,
                    ),
                    Binary::Remainder => (
                        std::mem::size_of::<expression::Math>(),
                        expression::Math::remainder,
                    ),
                    Binary::Union => (
                        std::mem::size_of::<expression::Union>(),
                        expression::Union::new,
                    ),
                };
                self.charge(size).map_err(native_failure)?;
                Ok(constructor(left, right))
            }
        }
    }

    fn depth(&self, expression: &SubExpression) -> usize {
        expression.ast_depth()
    }

    fn predicate(&self, expression: SubExpression) -> expression::Predicate {
        expression::Predicate { expression }
    }

    fn step(
        &self,
        axis: Axis,
        test: Test<String>,
        predicates: Vec<expression::Predicate>,
        _depth: usize,
    ) -> expression::Step {
        expression::Step::from_predicates(axis, native_test(test), predicates)
    }

    fn step_depth(&self, step: &expression::Step) -> usize {
        step.ast_depth()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn vector_growth_charges_overlap_then_releases_old_capacity() {
        // The fifth u64 needs an eight-slot buffer beside the existing four-slot buffer.
        for limit in [95, 96] {
            let budget = crate::ParseBudget::new(limit);
            let parser = super::Parser::with_budget(&budget);
            let mut values = Vec::new();
            for value in 0u64..4 {
                parser.push(&mut values, value).unwrap();
            }
            assert_eq!(budget.used.get(), 32);
            let result = parser.push(&mut values, 4);
            if limit == 95 {
                assert!(matches!(
                    result,
                    Err(super::Error::AllocationLimit { actual: 96, .. })
                ));
                assert_eq!(values, [0, 1, 2, 3]);
                assert_eq!(budget.used.get(), 32);
            } else {
                result.unwrap();
                assert_eq!(values.capacity(), 8);
                assert_eq!(budget.used.get(), 64);
            }
        }
    }

    #[test]
    fn vector_growth_rejects_overflow_before_allocation() {
        // Even an unlimited public factory must not wrap a capacity or exceed Layout bounds.
        let parser = super::Parser::new();
        for capacity in [usize::MAX, isize::MAX as usize / 8] {
            assert!(matches!(
                parser.vector_growth::<u64>(capacity),
                Err(super::Error::AllocationLimit {
                    actual: usize::MAX,
                    ..
                })
            ));
        }
        assert_eq!(parser.vector_growth::<u64>(4), Ok((8, 64)));
    }

    #[test]
    fn processing_instruction_node_test_has_no_separate_heap_owner() {
        // A targetless PI test has no string payload. The step stores this
        // grammar variant inline, so merely parsing it cannot allocate a Box.
        let budget = crate::ParseBudget::new(0);
        let parser = super::Parser::with_budget(&budget);
        let mut tokens = std::iter::once(Ok(Token::NodeTest(NodeTestName::ProcessingInstruction(
            None,
        ))))
        .peekable();
        assert!(matches!(
            parser.parse_node_test(&mut tokens),
            Ok(Some(crate::node_test::SubNodeTest::ProcessingInstruction(
                _
            )))
        ));
        assert_eq!(budget.used.get(), 0);
        assert!(tokens.next().is_none());
    }

    use snafu::ResultExt;
    use std::borrow::ToOwned;
    use sxd_document_no_unsafe::Package;
    use sxd_document_no_unsafe::dom::{self, Document, Element, Root, Text};

    use crate::Value;
    use crate::Value::{Boolean, Number, String};
    use crate::context::{self, Context};
    use crate::expression::{Expression, SubExpression};
    use crate::node_test;
    use crate::nodeset::Node;
    use crate::token::{AxisName, NodeTestName, Token};
    use crate::tokenizer::{self, TokenResult};

    use super::*;

    macro_rules! tokens(
        ($($e:expr),*) => (vec![$(Ok($e),)*]);
        ($($e:expr),+,) => (tokens!($($e),+))
    );

    fn name_test(local_part: &str) -> Token {
        Token::NameTest(node_test::NameTest {
            prefix: None,
            local_part: local_part.to_owned(),
        })
    }

    trait ApproxEq {
        fn is_approx_eq(&self, other: &Self) -> bool;
    }

    impl ApproxEq for f64 {
        fn is_approx_eq(&self, other: &f64) -> bool {
            (*self - *other).abs() < 1.0e-6
        }
    }

    impl<'d> ApproxEq for Value<'d> {
        fn is_approx_eq(&self, other: &Value<'d>) -> bool {
            match (self, other) {
                (Number(x), Number(y)) => x.is_approx_eq(y),
                _ => panic!("It's nonsensical to compare these quantities"),
            }
        }
    }

    macro_rules! assert_approx_eq(
        ($a:expr, $b:expr) => ({
            let (a, b) = (&$a, &$b);
            assert!(a.is_approx_eq(b),
                    "{:?} is not approximately equal to {:?}", *a, *b);
        })
    );

    struct TestDoc<'d>(Document<'d>);

    impl<'d> TestDoc<'d> {
        fn root(&'d self) -> Root<'d> {
            self.0.root()
        }

        fn top_node(&'d self) -> Element<'d> {
            let doc = &self.0;

            let kids = doc.root().children();
            match kids.len() {
                0 => {
                    let n = doc.create_element("the-top-node");
                    doc.root().append_child(n);
                    n
                }
                1 => kids[0].element().expect("not an element"),
                _ => panic!("Too many top nodes"),
            }
        }

        fn add_top_child(&'d self, name: &str) -> Element<'d> {
            self.add_child(self.top_node(), name)
        }

        fn add_child(&'d self, parent: Element<'d>, name: &str) -> Element<'d> {
            let doc = &self.0;

            let n = doc.create_element(name);
            parent.append_child(n);
            n
        }

        fn add_text(&'d self, parent: Element<'d>, value: &str) -> Text<'d> {
            let doc = &self.0;

            let tn = doc.create_text(value);
            parent.append_child(tn);
            tn
        }

        fn add_comment(&'d self, parent: Element<'d>, value: &str) -> dom::Comment<'d> {
            let cn = self.0.create_comment(value);
            parent.append_child(cn);
            cn
        }

        fn add_processing_instruction(
            &'d self,
            parent: Element<'d>,
            name: &str,
            value: Option<&str>,
        ) -> dom::ProcessingInstruction<'d> {
            let pi = self.0.create_processing_instruction(name, value);
            parent.append_child(pi);
            pi
        }
    }

    struct Exercise<'d> {
        doc: &'d TestDoc<'d>,
        context: Context<'d>,
        parser: Parser<'static>,
    }

    impl<'d> Exercise<'d> {
        fn new(doc: &'d TestDoc<'d>) -> Exercise<'d> {
            Exercise {
                doc,
                context: Context::new(),
                parser: Parser::new(),
            }
        }

        fn parse_raw(&self, tokens: Vec<TokenResult>) -> ParseResult<SubExpression> {
            self.parser.parse(tokens.into_iter())
        }

        fn parse(&self, tokens: Vec<TokenResult>) -> SubExpression {
            self.parse_raw(tokens).expect("Unable to parse expression")
        }

        fn evaluate<E>(&self, expr: E) -> Value<'d>
        where
            E: Expression,
        {
            self.evaluate_on(expr, self.doc.top_node())
        }

        fn evaluate_on<E, N>(&self, expr: E, node: N) -> Value<'d>
        where
            E: Expression,
            N: Into<Node<'d>>,
        {
            let context = context::Evaluation::new(&self.context, node.into());
            expr.evaluate(&context)
                .expect("Unable to evaluate expression")
        }
    }

    #[test]
    fn parses_string_as_child() {
        let tokens = tokens![name_test("hello")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let hello = doc.add_top_child("hello");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![hello], ex.evaluate_on(expr, doc.top_node()));
    }

    #[test]
    fn parses_two_strings_as_grandchild() {
        let tokens = tokens![name_test("hello"), Token::Slash, name_test("world")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let hello = doc.add_top_child("hello");
        let world = doc.add_child(hello, "world");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![world], ex.evaluate_on(expr, doc.top_node()));
    }

    #[test]
    fn parses_self_axis() {
        let tokens = tokens![Token::Axis(AxisName::SelfAxis), name_test("the-top-node")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(
            nodeset![doc.top_node()],
            ex.evaluate_on(expr, doc.top_node())
        );
    }

    #[test]
    fn parses_parent_axis() {
        let tokens = tokens![Token::Axis(AxisName::Parent), name_test("the-top-node")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let hello = doc.add_top_child("hello");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![doc.top_node()], ex.evaluate_on(expr, hello));
    }

    #[test]
    fn parses_child_axis() {
        let tokens = tokens![Token::Axis(AxisName::Child), name_test("*")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let two = doc.add_child(one, "two");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![two], ex.evaluate_on(expr, one));
    }

    #[test]
    fn parses_descendant_axis() {
        let tokens = tokens![Token::Axis(AxisName::Descendant), name_test("two")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let two = doc.add_child(one, "two");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![two], ex.evaluate_on(expr, doc.top_node()));
    }

    #[test]
    fn parses_descendant_or_self_axis() {
        let tokens = tokens![Token::Axis(AxisName::DescendantOrSelf), name_test("*")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let two = doc.add_child(one, "two");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![one, two], ex.evaluate_on(expr, one));
    }

    #[test]
    fn parses_attribute_axis() {
        let tokens = tokens![Token::Axis(AxisName::Attribute), name_test("*")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let attr = one.set_attribute_value("hello", "world");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![attr], ex.evaluate_on(expr, one));
    }

    #[test]
    fn parses_namespace_axis() {
        let tokens = tokens![Token::Axis(AxisName::Namespace), name_test("prefix")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        one.register_prefix("prefix", "uri");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        match ex.evaluate_on(expr, one) {
            Value::Nodeset(ns) => {
                assert_eq!(1, ns.size());
                match ns.into_iter().next() {
                    Some(Node::Namespace(ns)) => {
                        assert_eq!("prefix", ns.prefix());
                        assert_eq!("uri", ns.uri());
                    }
                    _ => panic!("Not a namespace node"),
                }
            }
            _ => panic!("Did not get the namespace node"),
        }
    }

    #[test]
    fn parses_child_with_same_name_as_an_axis() {
        let tokens = tokens![name_test("self")];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let element = doc.add_top_child("self");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![element], ex.evaluate_on(expr, doc.top_node()));
    }

    #[test]
    fn parses_node_node_test() {
        let tokens = tokens![Token::NodeTest(NodeTestName::Node)];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let two = doc.add_child(one, "two");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![two], ex.evaluate_on(expr, one));
    }

    #[test]
    fn parses_comment_node_test() {
        let tokens = tokens![Token::NodeTest(NodeTestName::Comment)];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let two = doc.add_comment(one, "two");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![two], ex.evaluate_on(expr, one));
    }

    #[test]
    fn parses_text_node_test() {
        let tokens = tokens![Token::NodeTest(NodeTestName::Text)];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let text = doc.add_text(one, "text");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![text], ex.evaluate_on(expr, one));
    }

    #[test]
    fn parses_processing_instruction_node_test() {
        let tokens = tokens![Token::NodeTest(NodeTestName::ProcessingInstruction(Some(
            "name".to_owned()
        )))];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let two = doc.add_processing_instruction(one, "name", None);

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![two], ex.evaluate_on(expr, one));
    }

    #[test]
    fn parses_axis_and_node_test() {
        let tokens = tokens![
            Token::Axis(AxisName::SelfAxis),
            Token::NodeTest(NodeTestName::Text),
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let one = doc.add_top_child("one");
        let text = doc.add_text(one, "text");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![text], ex.evaluate_on(expr, text));
    }

    #[test]
    fn numeric_predicate_selects_indexed_node() {
        let tokens = tokens![
            name_test("*"),
            Token::LeftBracket,
            Token::Number(2.0),
            Token::RightBracket
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        doc.add_top_child("first");
        let second = doc.add_top_child("second");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![second], ex.evaluate_on(expr, doc.top_node()));
    }

    #[test]
    fn string_literal() {
        let tokens = tokens![Token::Literal("string".to_owned())];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(String("string".to_owned()), ex.evaluate(expr));
    }

    #[test]
    fn predicate_accepts_any_expression() {
        let tokens = tokens![
            name_test("*"),
            Token::LeftBracket,
            Token::Function("true".into()),
            Token::LeftParen,
            Token::RightParen,
            Token::Or,
            Token::Function("false".into()),
            Token::LeftParen,
            Token::RightParen,
            Token::RightBracket
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let first = doc.add_top_child("first");
        let second = doc.add_top_child("second");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(
            nodeset![first, second],
            ex.evaluate_on(expr, doc.top_node())
        );
    }

    #[test]
    fn true_function_predicate_selects_all_nodes() {
        let tokens = tokens![
            name_test("*"),
            Token::LeftBracket,
            Token::Function("true".into()),
            Token::LeftParen,
            Token::RightParen,
            Token::RightBracket
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let first = doc.add_top_child("first");
        let second = doc.add_top_child("second");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(
            nodeset![first, second],
            ex.evaluate_on(expr, doc.top_node())
        );
    }

    #[test]
    fn false_function_predicate_selects_no_nodes() {
        let tokens = tokens![
            name_test("*"),
            Token::LeftBracket,
            Token::Function("false".into()),
            Token::LeftParen,
            Token::RightParen,
            Token::RightBracket
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        doc.add_top_child("first");
        doc.add_top_child("second");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![], ex.evaluate_on(expr, doc.top_node()));
    }

    #[test]
    fn multiple_predicates() {
        let tokens = tokens![
            name_test("*"),
            Token::LeftBracket,
            Token::Number(2.0),
            Token::RightBracket,
            Token::LeftBracket,
            Token::Number(1.0),
            Token::RightBracket
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        doc.add_top_child("first");
        let second = doc.add_top_child("second");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![second], ex.evaluate_on(expr, doc.top_node()));
    }

    #[test]
    fn functions_accept_arguments() {
        let tokens = tokens![
            Token::Function("not".into()),
            Token::LeftParen,
            Token::Function("true".into()),
            Token::LeftParen,
            Token::RightParen,
            Token::RightParen,
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(false), ex.evaluate(expr));
    }

    #[test]
    fn functions_accept_any_expression_as_an_argument() {
        let tokens = tokens![
            Token::Function("not".into()),
            Token::LeftParen,
            Token::Function("true".into()),
            Token::LeftParen,
            Token::RightParen,
            Token::Or,
            Token::Function("false".into()),
            Token::LeftParen,
            Token::RightParen,
            Token::RightParen,
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(false), ex.evaluate(expr));
    }

    #[test]
    fn numeric_literal() {
        let tokens = tokens![Token::Number(3.2)];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(3.2), ex.evaluate(expr));
    }

    #[test]
    fn addition_of_two_numbers() {
        let tokens = tokens![Token::Number(1.1), Token::PlusSign, Token::Number(2.2)];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(3.3), ex.evaluate(expr));
    }

    #[test]
    fn addition_of_multiple_numbers() {
        let tokens = tokens![
            Token::Number(1.1),
            Token::PlusSign,
            Token::Number(2.2),
            Token::PlusSign,
            Token::Number(3.3)
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(6.6), ex.evaluate(expr));
    }

    #[test]
    fn subtraction_of_two_numbers() {
        let tokens = tokens![Token::Number(1.1), Token::MinusSign, Token::Number(2.2),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(-1.1), ex.evaluate(expr));
    }

    #[test]
    fn additive_expression_is_left_associative() {
        let tokens = tokens![
            Token::Number(1.1),
            Token::MinusSign,
            Token::Number(2.2),
            Token::MinusSign,
            Token::Number(3.3),
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(-4.4), ex.evaluate(expr));
    }

    #[test]
    fn multiplication_of_two_numbers() {
        let tokens = tokens![Token::Number(1.1), Token::Multiply, Token::Number(2.2),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(2.42), ex.evaluate(expr));
    }

    #[test]
    fn division_of_two_numbers() {
        let tokens = tokens![Token::Number(7.1), Token::Divide, Token::Number(0.1),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(71.0), ex.evaluate(expr));
    }

    #[test]
    fn remainder_of_two_numbers() {
        let tokens = tokens![Token::Number(7.1), Token::Remainder, Token::Number(3.0),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(1.1), ex.evaluate(expr));
    }

    #[test]
    fn unary_negation() {
        let tokens = tokens![Token::MinusSign, Token::Number(7.2),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(-7.2), ex.evaluate(expr));
    }

    #[test]
    fn repeated_unary_negation() {
        let tokens = tokens![
            Token::MinusSign,
            Token::MinusSign,
            Token::MinusSign,
            Token::Number(7.2),
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(-7.2), ex.evaluate(expr));
    }

    #[test]
    fn top_level_function_call() {
        let tokens = tokens![
            Token::Function("true".into()),
            Token::LeftParen,
            Token::RightParen,
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(true), ex.evaluate(expr));
    }

    #[test]
    fn or_expression() {
        let tokens = tokens![
            Token::Function("true".into()),
            Token::LeftParen,
            Token::RightParen,
            Token::Or,
            Token::Function("false".into()),
            Token::LeftParen,
            Token::RightParen,
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(true), ex.evaluate(expr));
    }

    #[test]
    fn and_expression() {
        let tokens = tokens![Token::Number(1.2), Token::And, Token::Number(0.0),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(false), ex.evaluate(expr));
    }

    #[test]
    fn equality_expression() {
        let tokens = tokens![Token::Number(1.2), Token::Equal, Token::Number(1.1),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(false), ex.evaluate(expr));
    }

    #[test]
    fn inequality_expression() {
        let tokens = tokens![Token::Number(1.2), Token::NotEqual, Token::Number(1.2),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(false), ex.evaluate(expr));
    }

    #[test]
    fn less_than_expression() {
        let tokens = tokens![Token::Number(1.2), Token::LessThan, Token::Number(1.2),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(false), ex.evaluate(expr));
    }

    #[test]
    fn less_than_or_equal_expression() {
        let tokens = tokens![
            Token::Number(1.2),
            Token::LessThanOrEqual,
            Token::Number(1.2),
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(true), ex.evaluate(expr));
    }

    #[test]
    fn greater_than_expression() {
        let tokens = tokens![Token::Number(1.2), Token::GreaterThan, Token::Number(1.2),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(false), ex.evaluate(expr));
    }

    #[test]
    fn greater_than_or_equal_expression() {
        let tokens = tokens![
            Token::Number(1.2),
            Token::GreaterThanOrEqual,
            Token::Number(1.2),
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(Boolean(true), ex.evaluate(expr));
    }

    #[test]
    fn nested_expression() {
        let tokens = tokens![Token::LeftParen, Token::Number(1.1), Token::RightParen,];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(1.1), ex.evaluate(expr));
    }

    #[test]
    fn deeply_nested_expression_is_rejected_at_the_nesting_ceiling() {
        let mut tokens = vec![Ok(Token::MinusSign); MAX_EXPRESSION_NESTING + 1];
        tokens.push(Ok(Token::Number(1.0)));
        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        assert_eq!(Some(Error::NestingLimit), ex.parse_raw(tokens).err());
    }

    #[test]
    fn variable_reference() {
        let tokens = tokens![Token::Variable("variable-name".into())];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let mut ex = Exercise::new(&doc);
        ex.context.set_variable("variable-name", 12.3);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(12.3), ex.evaluate(expr));
    }

    #[test]
    fn variable_reference_prefixed_name() {
        let tokens = tokens![Token::Variable(("ns", "variable-name").into())];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let mut ex = Exercise::new(&doc);
        ex.context.set_namespace("ns", "uri:vars");
        ex.context.set_variable(("uri:vars", "variable-name"), 12.3);
        let expr = ex.parse(tokens);

        assert_approx_eq!(Number(12.3), ex.evaluate(expr));
    }

    #[test]
    fn filter_expression() {
        let tokens = tokens![
            Token::Variable("variable".into()),
            Token::LeftBracket,
            Token::Number(0.0),
            Token::RightBracket,
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let value = nodeset![
            doc.add_top_child("first-node"),
            doc.add_top_child("second-node"),
        ];

        let mut ex = Exercise::new(&doc);
        ex.context.set_variable("variable", value);

        let expr = ex.parse(tokens);

        assert_eq!(nodeset![], ex.evaluate(expr));
    }

    #[test]
    fn filter_expression_and_relative_path() {
        let tokens = tokens![
            Token::Variable("variable".into()),
            Token::Slash,
            name_test("child"),
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let parent = doc.add_top_child("parent");
        let child = doc.add_child(parent, "child");

        let value = nodeset![parent];

        let mut ex = Exercise::new(&doc);
        ex.context.set_variable("variable", value);

        let expr = ex.parse(tokens);

        assert_eq!(nodeset![child], ex.evaluate(expr));
    }

    #[test]
    fn union_expression() {
        let tokens = tokens![
            Token::Variable("variable1".into()),
            Token::Pipe,
            Token::Variable("variable2".into()),
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let node1 = doc.add_top_child("first-node");
        let node2 = doc.add_top_child("second-node");

        let mut ex = Exercise::new(&doc);
        ex.context.set_variable("variable1", nodeset![node1]);
        ex.context.set_variable("variable2", nodeset![node2]);

        let expr = ex.parse(tokens);

        assert_eq!(nodeset![node1, node2], ex.evaluate(expr));
    }

    #[test]
    fn absolute_path_expression() {
        let tokens = tokens![Token::Slash,];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let node1 = doc.add_top_child("first-node");
        let node2 = doc.add_child(node1, "second-node");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![doc.root()], ex.evaluate_on(expr, node2));
    }

    #[test]
    fn absolute_path_with_child_expression() {
        let tokens = tokens![Token::Slash, name_test("*"),];

        let package = Package::new();
        let doc = TestDoc(package.as_document());
        let node1 = doc.add_top_child("first-node");
        let node2 = doc.add_child(node1, "second-node");

        let ex = Exercise::new(&doc);
        let expr = ex.parse(tokens);

        assert_eq!(nodeset![doc.top_node()], ex.evaluate_on(expr, node2));
    }

    #[test]
    fn unexpected_token_is_reported_as_an_error() {
        let tokens = tokens![Token::Function("does-not-matter".into()), Token::RightParen];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parser.parse(tokens.into_iter());
        assert_eq!(
            Some(Error::UnexpectedToken {
                token: Token::RightParen
            }),
            res.err()
        );
    }

    #[test]
    fn no_xpath_error() {
        let tokens = tokens![];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parse_raw(tokens);
        assert_eq!(Some(Error::NoXPath), res.err());
    }

    #[test]
    fn binary_operator_without_right_hand_side_is_reported_as_an_error() {
        let tokens = tokens![Token::Literal("left".to_owned()), Token::And];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parse_raw(tokens);
        assert_eq!(Some(Error::RightHandSideExpressionMissing), res.err());
    }

    #[test]
    fn unary_operator_without_right_hand_side_is_reported_as_an_error() {
        let tokens = tokens![Token::MinusSign,];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parser.parse(tokens.into_iter());
        assert_eq!(Some(Error::RightHandSideExpressionMissing), res.err());
    }

    #[test]
    fn empty_predicate_is_reported_as_an_error() {
        let tokens = tokens![name_test("*"), Token::LeftBracket, Token::RightBracket,];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parse_raw(tokens);
        assert_eq!(Some(Error::EmptyPredicate), res.err());
    }

    #[test]
    fn relative_path_with_trailing_slash_is_reported_as_an_error() {
        let tokens = tokens![name_test("*"), Token::Slash,];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parse_raw(tokens);
        assert_eq!(Some(Error::TrailingSlash), res.err());
    }

    #[test]
    fn filter_expression_with_trailing_slash_is_reported_as_an_error() {
        let tokens = tokens![Token::Variable("variable".into()), Token::Slash,];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parse_raw(tokens);
        assert_eq!(Some(Error::TrailingSlash), res.err());
    }

    #[test]
    fn running_out_of_input_is_reported_as_an_error() {
        let tokens = tokens![Token::Function("func".into())];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parse_raw(tokens);
        assert_eq!(Some(Error::RanOutOfInput), res.err());
    }

    #[test]
    fn having_extra_tokens_is_reported_as_an_error() {
        let tokens = tokens![Token::LeftBracket];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parse_raw(tokens);
        assert_eq!(Some(Error::ExtraUnparsedTokens), res.err());
    }

    #[test]
    fn a_tokenizer_error_is_reported_as_an_error() {
        let tokens = vec![
            Ok(Token::Function("func".into())),
            Err(tokenizer::Error::UnableToCreateToken),
        ];

        let package = Package::new();
        let doc = TestDoc(package.as_document());

        let ex = Exercise::new(&doc);
        let res = ex.parse_raw(tokens);
        assert_eq!(
            tokenizer::UnableToCreateToken
                .fail::<()>()
                .context(Tokenizer)
                .err(),
            res.err()
        );
    }
}
