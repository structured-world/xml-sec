//! XPath 1.0 grammar independent of expression ownership.
//!
//! The builder receives children directly, never an already allocated native
//! tree. Borrowed lexer payloads can therefore remain original-source slices.

use std::cell::Cell;
use std::iter::Peekable;
use std::ops::{Deref, DerefMut};

use crate::axis::{Axis, AxisLike, PrincipalNodeType};
use crate::node_test::NameTest;
use crate::token::{AxisName, NodeTestName, TokenData as Token};
use crate::tokenizer;

#[cfg(feature = "embedded")]
use crate::hard_limits::xpath as limits;
#[cfg(not(feature = "embedded"))]
#[path = "../hard_limits/xpath.rs"]
mod limits;

pub(super) const MAX_DEPTH: usize = limits::MAX_DEPTH;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Fault<T> {
    NoXPath,
    EmptyPredicate,
    ExtraUnparsedTokens,
    NestingLimit,
    RanOutOfInput,
    RightHandSideExpressionMissing,
    ArgumentMissing,
    Tokenizer(tokenizer::Error),
    TrailingSlash,
    UnexpectedToken(T),
    AllocationLimit {
        limit: usize,
        actual: usize,
    },
    #[cfg(feature = "embedded")]
    Resource(structured_asn1::memory::MemoryError),
}

impl<T: std::fmt::Debug> std::fmt::Display for Fault<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoXPath => f.write_str("XPath was empty"),
            Self::EmptyPredicate => f.write_str("empty predicate"),
            Self::ExtraUnparsedTokens => f.write_str("extra unparsed tokens"),
            Self::NestingLimit => f.write_str("XPath nesting limit exceeded"),
            Self::RanOutOfInput => f.write_str("ran out of input"),
            Self::RightHandSideExpressionMissing => f.write_str("right hand side is missing"),
            Self::ArgumentMissing => f.write_str("function argument is missing"),
            Self::Tokenizer(source) => write!(f, "tokenizer error: {source}"),
            Self::TrailingSlash => f.write_str("trailing slash"),
            Self::UnexpectedToken(token) => write!(f, "unexpected token: {token:?}"),
            Self::AllocationLimit { limit, actual } => {
                write!(f, "allocation limit {limit} exceeded by {actual}")
            }
            #[cfg(feature = "embedded")]
            Self::Resource(cause) => cause.fmt(f),
        }
    }
}

pub(super) type Failure<B> = Fault<Token<<B as Builder>::Name, <B as Builder>::Text>>;
type Result<B, T> = std::result::Result<T, Failure<B>>;
type Optional<B> = Result<B, Option<<B as Builder>::Expression>>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Binary {
    Or,
    And,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    Union,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Test<T> {
    Kind(NodeTestName<T>),
    Name(PrincipalNodeType, NameTest<T>),
}

pub(super) enum Node<B: Builder> {
    Context,
    Root,
    Number(f64),
    String(B::Text),
    Variable(B::Name),
    Function(B::Name, B::List<B::Expression>),
    Negate(B::Expression),
    Binary(Binary, B::Expression, B::Expression),
    Filter(B::Expression, B::Expression),
    Path(B::Expression, B::List<B::Step>),
}

pub(super) trait Builder: Sized {
    type Name: PartialEq;
    type Text: PartialEq;
    type Expression;
    type Predicate;
    type Step;
    type List<T>: Deref<Target = [T]> + DerefMut;

    fn list<T>(&self) -> Self::List<T>;
    fn inspect(&self) -> Result<Self, ()>;
    fn push<T>(&self, list: &mut Self::List<T>, value: T) -> Result<Self, ()>;
    fn node(&self, node: Node<Self>, depth: usize) -> Result<Self, Self::Expression>;
    fn depth(&self, expression: &Self::Expression) -> usize;
    fn predicate(&self, expression: Self::Expression) -> Self::Predicate;
    fn step(
        &self,
        axis: Axis,
        test: Test<Self::Text>,
        predicates: Self::List<Self::Predicate>,
        depth: usize,
    ) -> Self::Step;
    fn step_depth(&self, step: &Self::Step) -> usize;
}

pub(super) struct Grammar<'b, B: Builder> {
    builder: &'b B,
    nesting: Cell<usize>,
}

type Source<I> = Peekable<I>;

impl<'b, B: Builder> Grammar<'b, B> {
    pub fn new(builder: &'b B) -> Self {
        Self {
            builder,
            nesting: Cell::new(0),
        }
    }

    fn nested<T>(&self, action: impl FnOnce() -> Result<B, T>) -> Result<B, T> {
        let depth = self.nesting.get();
        if depth >= MAX_DEPTH {
            return Err(Fault::NestingLimit);
        }
        self.nesting.set(depth + 1);
        let result = action();
        self.nesting.set(depth);
        result
    }

    fn make(&self, node: Node<B>, depth: usize) -> Result<B, B::Expression> {
        if depth > MAX_DEPTH {
            return Err(Fault::NestingLimit);
        }
        self.builder.node(node, depth)
    }

    fn next<I>(&self, source: &mut Source<I>) -> Result<B, Token<B::Name, B::Text>>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        self.builder.inspect()?;
        source
            .next()
            .ok_or(Fault::RanOutOfInput)?
            .map_err(Fault::Tokenizer)
    }

    fn is<I>(&self, source: &mut Source<I>, token: &Token<B::Name, B::Text>) -> bool
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        matches!(source.peek(), Some(Ok(next)) if next == token)
    }

    fn consume<I>(&self, source: &mut Source<I>, expected: Token<B::Name, B::Text>) -> Result<B, ()>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        let token = self.next(source)?;
        if token != expected {
            return Err(Fault::UnexpectedToken(token));
        }
        Ok(())
    }

    fn axis<I>(&self, source: &mut Source<I>) -> Result<B, Axis>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        if !matches!(source.peek(), Some(Ok(Token::Axis(_)))) {
            return Ok(Axis::Child);
        }
        let Token::Axis(axis) = self.next(source)? else {
            unreachable!()
        };
        Ok(match axis {
            AxisName::Ancestor => Axis::Ancestor,
            AxisName::AncestorOrSelf => Axis::AncestorOrSelf,
            AxisName::Attribute => Axis::Attribute,
            AxisName::Child => Axis::Child,
            AxisName::Descendant => Axis::Descendant,
            AxisName::DescendantOrSelf => Axis::DescendantOrSelf,
            AxisName::Following => Axis::Following,
            AxisName::FollowingSibling => Axis::FollowingSibling,
            AxisName::Namespace => Axis::Namespace,
            AxisName::Parent => Axis::Parent,
            AxisName::Preceding => Axis::Preceding,
            AxisName::PrecedingSibling => Axis::PrecedingSibling,
            AxisName::SelfAxis => Axis::SelfAxis,
        })
    }

    fn step<I>(&self, source: &mut Source<I>) -> Result<B, Option<B::Step>>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        self.builder.inspect()?;
        let axis = self.axis(source)?;
        let test = match source.peek() {
            Some(Ok(Token::NodeTest(_))) => {
                let Token::NodeTest(test) = self.next(source)? else {
                    unreachable!()
                };
                Test::Kind(test)
            }
            Some(Ok(Token::NameTest(_))) => {
                let Token::NameTest(test) = self.next(source)? else {
                    unreachable!()
                };
                Test::Name(axis.principal_node_type(), test)
            }
            _ => return Ok(None),
        };
        let mut predicates = self.builder.list();
        let mut depth = 0;
        while self.is(source, &Token::LeftBracket) {
            let predicate = self.predicate(source)?;
            depth = depth.max(self.builder.depth(&predicate));
            self.builder
                .push(&mut predicates, self.builder.predicate(predicate))?;
        }
        Ok(Some(self.builder.step(axis, test, predicates, depth)))
    }

    fn predicate<I>(&self, source: &mut Source<I>) -> Result<B, B::Expression>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        self.consume(source, Token::LeftBracket)?;
        let result = self
            .nested(|| self.binary(source, 0))?
            .ok_or(Fault::EmptyPredicate)?;
        self.consume(source, Token::RightBracket)?;
        Ok(result)
    }

    fn relative<I>(
        &self,
        source: &mut Source<I>,
        start: B::Expression,
        first: B::Step,
    ) -> Result<B, B::Expression>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        let mut depth = self
            .builder
            .depth(&start)
            .max(self.builder.step_depth(&first));
        let mut steps = self.builder.list();
        self.builder.push(&mut steps, first)?;
        while self.is(source, &Token::Slash) {
            self.consume(source, Token::Slash)?;
            let step = self.step(source)?.ok_or(Fault::TrailingSlash)?;
            depth = depth.max(self.builder.step_depth(&step));
            self.builder.push(&mut steps, step)?;
        }
        self.make(Node::Path(start, steps), depth + 1)
    }

    fn primary<I>(&self, source: &mut Source<I>) -> Optional<B>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        self.builder.inspect()?;
        let node = match source.peek() {
            Some(Ok(Token::Variable(_))) => {
                let Token::Variable(name) = self.next(source)? else {
                    unreachable!()
                };
                Node::Variable(name)
            }
            Some(Ok(Token::Literal(_))) => {
                let Token::Literal(value) = self.next(source)? else {
                    unreachable!()
                };
                Node::String(value)
            }
            Some(Ok(Token::Number(_))) => {
                let Token::Number(value) = self.next(source)? else {
                    unreachable!()
                };
                Node::Number(value)
            }
            Some(Ok(Token::LeftParen)) => {
                self.consume(source, Token::LeftParen)?;
                let value = self.nested(|| self.binary(source, 0))?;
                self.consume(source, Token::RightParen)?;
                return Ok(value);
            }
            Some(Ok(Token::Function(_))) => {
                let Token::Function(name) = self.next(source)? else {
                    unreachable!()
                };
                self.consume(source, Token::LeftParen)?;
                let mut arguments = self.builder.list();
                let mut depth = 0;
                if let Some(argument) = self.nested(|| self.binary(source, 0))? {
                    depth = self.builder.depth(&argument);
                    self.builder.push(&mut arguments, argument)?;
                    while self.is(source, &Token::Comma) {
                        self.consume(source, Token::Comma)?;
                        let argument = self
                            .nested(|| self.binary(source, 0))?
                            .ok_or(Fault::ArgumentMissing)?;
                        depth = depth.max(self.builder.depth(&argument));
                        self.builder.push(&mut arguments, argument)?;
                    }
                }
                self.consume(source, Token::RightParen)?;
                return self
                    .make(Node::Function(name, arguments), depth + 1)
                    .map(Some);
            }
            _ => return Ok(None),
        };
        self.make(node, 1).map(Some)
    }

    fn path<I>(&self, source: &mut Source<I>) -> Optional<B>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        if self.is(source, &Token::Slash) {
            self.consume(source, Token::Slash)?;
            let root = self.make(Node::Root, 1)?;
            return match self.step(source)? {
                Some(step) => self.relative(source, root, step).map(Some),
                None => Ok(Some(root)),
            };
        }
        if let Some(step) = self.step(source)? {
            let context = self.make(Node::Context, 1)?;
            return self.relative(source, context, step).map(Some);
        }
        let Some(mut expression) = self.primary(source)? else {
            return Ok(None);
        };
        while self.is(source, &Token::LeftBracket) {
            let predicate = self.predicate(source)?;
            let depth = 1 + self
                .builder
                .depth(&expression)
                .max(self.builder.depth(&predicate));
            expression = self.make(Node::Filter(expression, predicate), depth)?;
        }
        if self.is(source, &Token::Slash) {
            self.consume(source, Token::Slash)?;
            let step = self.step(source)?.ok_or(Fault::TrailingSlash)?;
            expression = self.relative(source, expression, step)?;
        }
        Ok(Some(expression))
    }

    fn unary<I>(&self, source: &mut Source<I>) -> Optional<B>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        // XPath 1.0 §3.5: UnionExpr binds more tightly than unary minus.
        // https://www.w3.org/TR/1999/REC-xpath-19991116/#numbers
        if self.is(source, &Token::MinusSign) {
            self.consume(source, Token::MinusSign)?;
            let value = self
                .nested(|| self.unary(source))?
                .ok_or(Fault::RightHandSideExpressionMissing)?;
            let depth = 1 + self.builder.depth(&value);
            return self.make(Node::Negate(value), depth).map(Some);
        }
        self.binary(source, 7)
    }

    fn binary<I>(&self, source: &mut Source<I>, level: u8) -> Optional<B>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        self.builder.inspect()?;
        let mut left = match self.child(source, level)? {
            Some(value) => value,
            None => return Ok(None),
        };
        loop {
            self.builder.inspect()?;
            let operation = match (level, source.peek()) {
                (0, Some(Ok(Token::Or))) => Binary::Or,
                (1, Some(Ok(Token::And))) => Binary::And,
                (2, Some(Ok(Token::Equal))) => Binary::Equal,
                (2, Some(Ok(Token::NotEqual))) => Binary::NotEqual,
                (3, Some(Ok(Token::LessThan))) => Binary::Less,
                (3, Some(Ok(Token::LessThanOrEqual))) => Binary::LessEqual,
                (3, Some(Ok(Token::GreaterThan))) => Binary::Greater,
                (3, Some(Ok(Token::GreaterThanOrEqual))) => Binary::GreaterEqual,
                (4, Some(Ok(Token::PlusSign))) => Binary::Add,
                (4, Some(Ok(Token::MinusSign))) => Binary::Subtract,
                (5, Some(Ok(Token::Multiply))) => Binary::Multiply,
                (5, Some(Ok(Token::Divide))) => Binary::Divide,
                (5, Some(Ok(Token::Remainder))) => Binary::Remainder,
                (7, Some(Ok(Token::Pipe))) => Binary::Union,
                _ => break,
            };
            self.next(source)?;
            let right = self
                .child(source, level)?
                .ok_or(Fault::RightHandSideExpressionMissing)?;
            let depth = 1 + self.builder.depth(&left).max(self.builder.depth(&right));
            left = self.make(Node::Binary(operation, left, right), depth)?;
        }
        Ok(Some(left))
    }

    fn child<I>(&self, source: &mut Source<I>, level: u8) -> Optional<B>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        match level {
            5 => self.unary(source),
            7 => self.path(source),
            _ => self.binary(source, level + 1),
        }
    }

    pub fn parse<I>(&self, source: I) -> Result<B, B::Expression>
    where
        I: Iterator<Item = std::result::Result<Token<B::Name, B::Text>, tokenizer::Error>>,
    {
        let mut source = source.peekable();
        let expression = self.binary(&mut source, 0)?;
        if source.peek().is_some() {
            return Err(Fault::ExtraUnparsedTokens);
        }
        expression.ok_or(Fault::NoXPath)
    }
}
