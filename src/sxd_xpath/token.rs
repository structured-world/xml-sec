use crate::OwnedPrefixedName;
use crate::node_test;
#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use alloc::{borrow::ToOwned, string::String};
use sxd_document_no_unsafe::PrefixedName;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AxisName {
    Ancestor,
    AncestorOrSelf,
    Attribute,
    Child,
    Descendant,
    DescendantOrSelf,
    Following,
    FollowingSibling,
    Namespace,
    Parent,
    Preceding,
    PrecedingSibling,
    SelfAxis,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NodeTestName<T = String> {
    Comment,
    Text,
    ProcessingInstruction(Option<T>),
    Node,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenData<N, T> {
    And,
    AtSign,
    Comma,
    CurrentNode,
    Divide,
    DoubleSlash,
    Equal,
    GreaterThan,
    GreaterThanOrEqual,
    LeftBracket,
    LeftParen,
    LessThan,
    LessThanOrEqual,
    Literal(T),
    MinusSign,
    Multiply,
    NotEqual,
    Number(f64),
    Or,
    ParentNode,
    Pipe,
    PlusSign,
    Remainder,
    RightBracket,
    RightParen,
    Slash,

    // Specializations
    Axis(AxisName),
    Function(N),
    NameTest(node_test::NameTest<T>),
    NodeTest(NodeTestName<T>),
    Variable(N),
}

pub type Token = TokenData<OwnedPrefixedName, String>;
pub type BorrowedToken<'a> = TokenData<PrefixedName<'a>, &'a str>;

impl<N, T> TokenData<N, T> {
    pub fn precedes_node_test(&self) -> bool {
        match *self {
            Self::AtSign | Self::Axis(..) => true,
            _ => false,
        }
    }

    pub fn precedes_expression(&self) -> bool {
        match *self {
            Self::LeftParen | Self::LeftBracket | Self::Comma => true,
            _ => false,
        }
    }

    pub fn is_operator(&self) -> bool {
        match *self {
            Self::Slash
            | Self::DoubleSlash
            | Self::PlusSign
            | Self::MinusSign
            | Self::Pipe
            | Self::Equal
            | Self::NotEqual
            | Self::LessThan
            | Self::LessThanOrEqual
            | Self::GreaterThan
            | Self::GreaterThanOrEqual
            | Self::And
            | Self::Or
            | Self::Remainder
            | Self::Divide
            | Self::Multiply => true,
            _ => false,
        }
    }
}

impl BorrowedToken<'_> {
    pub(super) fn payload_bytes(&self) -> usize {
        match self {
            Self::Literal(value) => value.len(),
            Self::Function(name) | Self::Variable(name) => {
                name.prefix().map_or(0, str::len) + name.local_part().len()
            }
            Self::NameTest(name) => name.prefix.map_or(0, str::len) + name.local_part.len(),
            Self::NodeTest(NodeTestName::ProcessingInstruction(Some(target))) => target.len(),
            _ => 0,
        }
    }

    pub(super) fn into_owned(self) -> Token {
        match self {
            Self::Literal(value) => Token::Literal(value.to_owned()),
            Self::Function(name) => Token::Function(name.into()),
            Self::Variable(name) => Token::Variable(name.into()),
            Self::NameTest(name) => Token::NameTest(node_test::NameTest {
                prefix: name.prefix.map(str::to_owned),
                local_part: name.local_part.to_owned(),
            }),
            Self::NodeTest(name) => Token::NodeTest(match name {
                NodeTestName::Node => NodeTestName::Node,
                NodeTestName::Text => NodeTestName::Text,
                NodeTestName::Comment => NodeTestName::Comment,
                NodeTestName::ProcessingInstruction(target) => {
                    NodeTestName::ProcessingInstruction(target.map(str::to_owned))
                }
            }),
            Self::Axis(axis) => Token::Axis(axis),
            Self::Number(number) => Token::Number(number),
            Self::And => Token::And,
            Self::AtSign => Token::AtSign,
            Self::Comma => Token::Comma,
            Self::CurrentNode => Token::CurrentNode,
            Self::Divide => Token::Divide,
            Self::DoubleSlash => Token::DoubleSlash,
            Self::Equal => Token::Equal,
            Self::GreaterThan => Token::GreaterThan,
            Self::GreaterThanOrEqual => Token::GreaterThanOrEqual,
            Self::LeftBracket => Token::LeftBracket,
            Self::LeftParen => Token::LeftParen,
            Self::LessThan => Token::LessThan,
            Self::LessThanOrEqual => Token::LessThanOrEqual,
            Self::MinusSign => Token::MinusSign,
            Self::Multiply => Token::Multiply,
            Self::NotEqual => Token::NotEqual,
            Self::Or => Token::Or,
            Self::ParentNode => Token::ParentNode,
            Self::Pipe => Token::Pipe,
            Self::PlusSign => Token::PlusSign,
            Self::Remainder => Token::Remainder,
            Self::RightBracket => Token::RightBracket,
            Self::RightParen => Token::RightParen,
            Self::Slash => Token::Slash,
        }
    }
}
