//! Support for registering and creating XPath functions.

use snafu::Snafu;
use std::borrow::ToOwned;
use std::ops::Index;
use sxd_document_no_unsafe::XmlChar;

use crate::context;
use crate::nodeset::Nodeset;
use crate::{Value, node_to_num_with_context};

/// Types that can be used as XPath functions.
pub trait Function {
    /// Evaluate this function in a specific context with a specific
    /// set of arguments.
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error>;
}

/// Represents the kind of an XPath value without carrying a value.
#[derive(Debug, Copy, Clone, PartialEq, Hash)]
pub enum ArgumentType {
    Boolean,
    Number,
    String,
    ResultTreeFragment,
    Nodeset,
}

impl<'a> From<&'a Value<'a>> for ArgumentType {
    fn from(other: &'a Value<'a>) -> ArgumentType {
        match *other {
            Value::Boolean(..) => ArgumentType::Boolean,
            Value::Number(..) => ArgumentType::Number,
            Value::String(..) => ArgumentType::String,
            Value::ResultTreeFragment(..) => ArgumentType::ResultTreeFragment,
            Value::Nodeset(..) => ArgumentType::Nodeset,
        }
    }
}

/// The errors that may occur while evaluating a function
#[derive(Debug, Snafu, Clone, PartialEq, Hash)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("too many arguments, expected {} but had {}", expected, actual))]
    TooManyArguments { expected: usize, actual: usize },
    #[snafu(display("not enough arguments, expected {} but had {}", expected, actual))]
    NotEnoughArguments { expected: usize, actual: usize },
    #[snafu(display("attempted to use an argument that was not present"))]
    ArgumentMissing,
    #[snafu(display("argument was expected to be a nodeset but was a {:?}", actual))]
    ArgumentNotANodeset { actual: ArgumentType },
    #[snafu(display("could not evaluate function: {}", what))]
    Other { what: String },
}

impl Error {
    fn not_a_nodeset(actual: &Value<'_>) -> Error {
        Error::ArgumentNotANodeset {
            actual: actual.into(),
        }
    }
}

/// Provides common utility functions for dealing with function
/// argument lists.
pub struct Args<'d>(pub Vec<Value<'d>>);

impl<'d> Args<'d> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Ensures that there are at least the requested number of arguments.
    pub fn at_least(&self, minimum: usize) -> Result<(), Error> {
        let actual = self.0.len();
        if actual < minimum {
            Err(Error::NotEnoughArguments {
                expected: minimum,
                actual,
            })
        } else {
            Ok(())
        }
    }

    /// Ensures that there are no more than the requested number of arguments.
    pub fn at_most(&self, maximum: usize) -> Result<(), Error> {
        let actual = self.0.len();
        if actual > maximum {
            Err(Error::TooManyArguments {
                expected: maximum,
                actual,
            })
        } else {
            Ok(())
        }
    }

    /// Ensures that there are exactly the requested number of arguments.
    pub fn exactly(&self, expected: usize) -> Result<(), Error> {
        let actual = self.0.len();
        if actual < expected {
            Err(Error::NotEnoughArguments { expected, actual })
        } else if actual > expected {
            Err(Error::TooManyArguments { expected, actual })
        } else {
            Ok(())
        }
    }

    /// Removes the **last** argument and ensures it is a boolean. If
    /// the argument is not a boolean, it is converted to one.
    pub fn pop_boolean(&mut self) -> Result<bool, Error> {
        let v = self.0.pop().ok_or(Error::ArgumentMissing)?;
        Ok(v.into_boolean())
    }

    /// Removes the **last** argument and ensures it is a number. If
    /// the argument is not a number, it is converted to one.
    pub fn pop_number(&mut self, context: &context::Evaluation<'_, '_>) -> Result<f64, Error> {
        let value = self.0.pop().ok_or(Error::ArgumentMissing)?;
        value.number(context)
    }

    /// Removes the **last** argument and ensures it is a string. If
    /// the argument is not a string, it is converted to one.
    pub fn pop_string(&mut self, context: &context::Evaluation<'_, '_>) -> Result<String, Error> {
        let v = self.0.last().ok_or(Error::ArgumentMissing)?;
        reserve_string_conversion(context, v)?;
        let v = self.0.pop().expect("argument presence was checked");
        Ok(v.into_string())
    }

    /// Removes the **last** argument and ensures it is a nodeset. If
    /// the argument is not a nodeset, a type mismatch error is
    /// returned.
    pub fn pop_nodeset(&mut self) -> Result<Nodeset<'d>, Error> {
        let v = self.0.pop().ok_or(Error::ArgumentMissing)?;
        match v {
            Value::Nodeset(v) => Ok(v),
            a => Err(Error::not_a_nodeset(&a)),
        }
    }

    /// Removes the **last** argument. If no argument is present, the
    /// context node is returned as a nodeset.
    fn pop_value_or_context_node<'c>(
        &mut self,
        context: &context::Evaluation<'c, 'd>,
    ) -> Value<'d> {
        self.0
            .pop()
            .unwrap_or_else(|| Value::Nodeset(nodeset![context.node.clone()]))
    }

    /// Removes the **last** argument if it is a string. If no
    /// argument is present, the context node is converted to a string
    /// and returned. If there is an argument but it is not a string,
    /// it is converted to one.
    fn pop_string_value_or_context_node(
        &mut self,
        context: &context::Evaluation<'_, '_>,
    ) -> Result<String, Error> {
        if self.0.is_empty() {
            context.node.string_value_with_context(context)
        } else {
            self.pop_string(context)
        }
    }

    /// Removes the **last** argument if it is a nodeset. If no
    /// argument is present, the context node is added to a nodeset
    /// and returned. If there is an argument but it is not a nodeset,
    /// a type mismatch error is returned.
    fn pop_nodeset_or_context_node<'c>(
        &mut self,
        context: &context::Evaluation<'c, 'd>,
    ) -> Result<Nodeset<'d>, Error> {
        match self.0.pop() {
            Some(Value::Nodeset(ns)) => Ok(ns),
            Some(arg) => Err(Error::not_a_nodeset(&arg)),
            None => Ok(nodeset![context.node.clone()]),
        }
    }
}

fn reserve_string_conversion(
    context: &context::Evaluation<'_, '_>,
    value: &Value<'_>,
) -> Result<(), Error> {
    if matches!(value, Value::String(_) | Value::ResultTreeFragment(..)) {
        Ok(())
    } else {
        context.reserve_string_allocation(value.string_len())
    }
}

impl<'d> Index<usize> for Args<'d> {
    type Output = Value<'d>;

    fn index(&self, index: usize) -> &Value<'d> {
        self.0.index(index)
    }
}

struct Last;

impl Function for Last {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let args = Args(args);
        args.exactly(0)?;
        Ok(Value::Number(context.size as f64))
    }
}

struct Position;

impl Function for Position {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let args = Args(args);
        args.exactly(0)?;
        Ok(Value::Number(context.position as f64))
    }
}

struct Count;

impl Function for Count {
    fn evaluate<'c, 'd>(
        &self,
        _context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.exactly(1)?;
        let arg = args.pop_nodeset()?;
        Ok(Value::Number(arg.size() as f64))
    }
}

struct LocalName;

impl Function for LocalName {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.at_most(1)?;
        let arg = args.pop_nodeset_or_context_node(context)?;
        let name = arg
            .document_order_first_with_context(context)?
            .and_then(|n| n.expanded_name())
            .map(|q| q.local_part().to_owned())
            .unwrap_or_default();
        Ok(Value::String(name))
    }
}

struct NamespaceUri;

impl Function for NamespaceUri {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.at_most(1)?;
        let arg = args.pop_nodeset_or_context_node(context)?;
        let name = arg
            .document_order_first_with_context(context)?
            .and_then(|n| n.expanded_name())
            .and_then(|q| q.namespace_uri().map(|s| s.to_owned()))
            .unwrap_or_default();
        Ok(Value::String(name))
    }
}

struct Name;

impl Function for Name {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.at_most(1)?;
        let arg = args.pop_nodeset_or_context_node(context)?;
        let name = arg
            .document_order_first_with_context(context)?
            .and_then(|n| n.prefixed_name())
            .unwrap_or_else(String::new);
        Ok(Value::String(name))
    }
}

struct StringFn;

impl Function for StringFn {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.at_most(1)?;
        Ok(Value::String(
            args.pop_string_value_or_context_node(context)?,
        ))
    }
}

struct Concat;

impl Function for Concat {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let args = Args(args);
        args.at_least(2)?;
        let length = args
            .0
            .iter()
            .try_fold(0usize, |total, value| total.checked_add(value.string_len()))
            .unwrap_or(usize::MAX);
        context.reserve_string_allocation(length)?;
        let mut output = String::with_capacity(length);
        for value in args.0 {
            value.append_string(&mut output);
        }
        Ok(Value::String(output))
    }
}

struct TwoStringPredicate(fn(&str, &str) -> bool);

impl Function for TwoStringPredicate {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.exactly(2)?;
        let second = args.pop_string(context)?;
        let first = args.pop_string(context)?;
        let v = self.0(&first, &second);
        Ok(Value::Boolean(v))
    }
}

fn starts_with() -> TwoStringPredicate {
    fn imp(a: &str, b: &str) -> bool {
        str::starts_with(a, b)
    }
    TwoStringPredicate(imp)
}
fn contains() -> TwoStringPredicate {
    fn imp(a: &str, b: &str) -> bool {
        str::contains(a, b)
    }
    TwoStringPredicate(imp)
}

struct SubstringCommon(for<'s> fn(&'s str, &'s str) -> &'s str);

impl Function for SubstringCommon {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.exactly(2)?;
        let second = args.pop_string(context)?;
        let first = args.pop_string(context)?;
        let s = self.0(&first, &second);
        context.reserve_string_allocation(s.len())?;
        Ok(Value::String(s.to_owned()))
    }
}

fn substring_before() -> SubstringCommon {
    fn inner<'a>(haystack: &'a str, needle: &'a str) -> &'a str {
        match haystack.find(needle) {
            Some(pos) => &haystack[..pos],
            None => "",
        }
    }
    SubstringCommon(inner)
}

fn substring_after() -> SubstringCommon {
    fn inner<'a>(haystack: &'a str, needle: &'a str) -> &'a str {
        match haystack.find(needle) {
            Some(pos) => &haystack[pos + needle.len()..],
            None => "",
        }
    }
    SubstringCommon(inner)
}

struct Substring;

impl Function for Substring {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.at_least(2)?;
        args.at_most(3)?;

        let len = if args.len() == 3 {
            let len = args.pop_number(context)?;
            Some(round_ties_to_positive_infinity(len))
        } else {
            None
        };

        let start = args.pop_number(context)?;
        let start = round_ties_to_positive_infinity(start);
        let s = args.pop_string(context)?;
        context.reserve_string_allocation(s.len())?;

        let mut selected_chars = String::with_capacity(s.len());
        selected_chars.extend(s.chars().enumerate().filter_map(|(p, s)| {
            let p = (p + 1) as f64; // 1-based indexing
            if p >= start && len.is_none_or(|len| p < start + len) {
                Some(s)
            } else {
                None
            }
        }));

        Ok(Value::String(selected_chars))
    }
}

struct StringLength;

impl Function for StringLength {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.at_most(1)?;
        let arg = args.pop_value_or_context_node(context);
        Ok(Value::Number(arg.string_char_len() as f64))
    }
}

struct NormalizeSpace;

impl Function for NormalizeSpace {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.at_most(1)?;
        let arg = args.pop_string_value_or_context_node(context)?;
        let length = arg
            .split(XmlChar::is_space_char)
            .filter(|part| !part.is_empty())
            .try_fold((0usize, false), |(length, has_part), part| {
                length
                    .checked_add(usize::from(has_part))
                    .and_then(|length| length.checked_add(part.len()))
                    .map(|length| (length, true))
            })
            .map(|(length, _)| length)
            .unwrap_or(usize::MAX);
        context.reserve_string_allocation(length)?;
        let mut normalized = String::with_capacity(length);
        for part in arg
            .split(XmlChar::is_space_char)
            .filter(|part| !part.is_empty())
        {
            if !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push_str(part);
        }
        Ok(Value::String(normalized))
    }
}

struct Translate;

impl Function for Translate {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.exactly(3)?;

        let source_bytes = args.0[0].string_len();
        let map_capacity = args.0[1].string_len();
        let map_bytes =
            map_capacity.saturating_mul(std::mem::size_of::<(char, usize, Option<char>)>());
        let result_bytes = source_bytes.saturating_mul(char::MAX.len_utf8());
        context.reserve_string_allocation(map_bytes.saturating_add(result_bytes))?;

        let to = args.pop_string(context)?;
        let from = args.pop_string(context)?;
        let s = args.pop_string(context)?;

        let mut replacements = Vec::with_capacity(from.chars().count());
        let mut to = to.chars();
        replacements.extend(
            from.chars()
                .enumerate()
                .map(|(index, from)| (from, index, to.next())),
        );
        replacements.sort_unstable_by_key(|&(from, index, _)| (from, index));
        replacements.dedup_by_key(|replacement| replacement.0);

        let s = s
            .chars()
            .filter_map(|c| {
                replacements
                    .binary_search_by_key(&c, |replacement| replacement.0)
                    .map_or(Some(c), |index| replacements[index].2)
            })
            .collect();

        Ok(Value::String(s))
    }
}

struct BooleanFn;

impl Function for BooleanFn {
    fn evaluate<'c, 'd>(
        &self,
        _context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let args = Args(args);
        args.exactly(1)?;
        Ok(Value::Boolean(args[0].boolean()))
    }
}

struct Not;

impl Function for Not {
    fn evaluate<'c, 'd>(
        &self,
        _context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.exactly(1)?;
        let arg = args.pop_boolean()?;
        Ok(Value::Boolean(!arg))
    }
}

struct BooleanLiteral(bool);

impl Function for BooleanLiteral {
    fn evaluate<'c, 'd>(
        &self,
        _context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let args = Args(args);
        args.exactly(0)?;
        Ok(Value::Boolean(self.0))
    }
}

fn true_fn() -> BooleanLiteral {
    BooleanLiteral(true)
}
fn false_fn() -> BooleanLiteral {
    BooleanLiteral(false)
}

struct NumberFn;

impl Function for NumberFn {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.at_most(1)?;
        let arg = args.pop_value_or_context_node(context);
        Ok(Value::Number(arg.number(context)?))
    }
}

struct Sum;

impl Function for Sum {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.exactly(1)?;
        let arg = args.pop_nodeset()?;
        let mut r = 0.0;
        for node in arg.iter() {
            r += node_to_num_with_context(context, &node)?;
        }
        Ok(Value::Number(r))
    }
}

struct NumberConvert(fn(f64) -> f64);

impl Function for NumberConvert {
    fn evaluate<'c, 'd>(
        &self,
        context: &context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        let mut args = Args(args);
        args.exactly(1)?;
        let arg = args.pop_number(context)?;
        Ok(Value::Number(self.0(arg)))
    }
}

fn floor() -> NumberConvert {
    NumberConvert(f64::floor)
}
fn ceiling() -> NumberConvert {
    NumberConvert(f64::ceil)
}

// https://stackoverflow.com/a/28124775/155423
fn round_ties_to_positive_infinity(x: f64) -> f64 {
    let y = x.floor();
    if x == y {
        x
    } else {
        let z = (2.0 * x - y).floor();
        // Should use copysign
        if x.is_sign_positive() ^ z.is_sign_positive() {
            -z
        } else {
            z
        }
    }
}

fn round() -> NumberConvert {
    NumberConvert(round_ties_to_positive_infinity)
}

/// Adds the [XPath 1.0 core function library][corelib].
///
/// [corelib]: https://www.w3.org/TR/xpath/#corelib
pub fn register_core_functions(context: &mut context::Context<'_>) {
    context.set_function("last", Last);
    context.set_function("position", Position);
    context.set_function("count", Count);
    context.set_function("local-name", LocalName);
    context.set_function("namespace-uri", NamespaceUri);
    context.set_function("name", Name);
    context.set_function("string", StringFn);
    context.set_function("concat", Concat);
    context.set_function("starts-with", starts_with());
    context.set_function("contains", contains());
    context.set_function("substring-before", substring_before());
    context.set_function("substring-after", substring_after());
    context.set_function("substring", Substring);
    context.set_function("string-length", StringLength);
    context.set_function("normalize-space", NormalizeSpace);
    context.set_function("translate", Translate);
    context.set_function("boolean", BooleanFn);
    context.set_function("not", Not);
    context.set_function("true", true_fn());
    context.set_function("false", false_fn());
    context.set_function("number", NumberFn);
    context.set_function("sum", Sum);
    context.set_function("floor", floor());
    context.set_function("ceiling", ceiling());
    context.set_function("round", round());
}

#[cfg(test)]
mod test {
    use std::borrow::ToOwned;
    use std::{f64, fmt};

    use sxd_document_no_unsafe::Package;

    use crate::context;
    use crate::nodeset::{Node, Nodeset};
    use crate::{LiteralValue, Value};

    use super::{
        BooleanFn, Concat, Count, Error, Function, Last, LocalName, Name, NamespaceUri,
        NormalizeSpace, NumberFn, Position, StringFn, StringLength, Substring, Sum, Translate,
        ceiling, contains, floor, round, starts_with, substring_after, substring_before,
    };

    /// Converts each argument into a `Value` and packs them into a
    /// vector.
    macro_rules! args {
        ( $($val:expr,)* ) => {
            vec![
                $( Value::from($val), )*
            ]
        };
        ( $($val:expr),* ) => {
            args![$($val, )*]
        };
    }

    struct Setup<'d> {
        context: context::Context<'d>,
    }

    impl<'d> Setup<'d> {
        fn new() -> Setup<'d> {
            Setup {
                context: context::Context::without_core_functions(),
            }
        }

        fn evaluate<N, F>(&self, node: N, f: F, args: Vec<Value<'d>>) -> Result<Value<'d>, Error>
        where
            N: Into<Node<'d>>,
            F: Function,
        {
            let context = context::Evaluation::new(&self.context, node.into());
            f.evaluate(&context, args)
        }
    }

    fn evaluate_literal<F, F2, T>(f: F, args: Vec<LiteralValue>, rf: F2) -> T
    where
        F: Function,
        F2: FnOnce(Result<Value<'_>, Error>) -> T,
    {
        let package = Package::new();
        let doc = package.as_document();
        let setup = Setup::new();

        rf(setup.evaluate(doc.root(), f, args))
    }

    #[test]
    fn last_returns_context_size() {
        evaluate_literal(Last, args![], |r| {
            assert_eq!(Ok(Value::Number(1.0)), r);
        });
    }

    #[test]
    fn position_returns_context_position() {
        evaluate_literal(Position, args![], |r| {
            assert_eq!(Ok(Value::Number(1.0)), r);
        });
    }

    #[test]
    fn count_counts_nodes_in_nodeset() {
        let package = Package::new();
        let doc = package.as_document();
        let setup = Setup::new();

        let r = setup.evaluate(doc.root(), Count, args![nodeset![doc.root()]]);

        assert_eq!(Ok(Value::Number(1.0)), r);
    }

    #[test]
    fn local_name_gets_name_of_element() {
        let package = Package::new();
        let doc = package.as_document();
        let setup = Setup::new();

        let e = doc.create_element(("uri", "wow"));
        doc.root().append_child(e);

        let r = setup.evaluate(doc.root(), LocalName, args![nodeset![e]]);

        assert_eq!(Ok(Value::String("wow".to_owned())), r);
    }

    #[test]
    fn local_name_is_empty_for_empty_nodeset() {
        evaluate_literal(LocalName, args![nodeset![]], |r| {
            assert_eq!(Ok(Value::String("".to_owned())), r);
        });
    }

    #[test]
    fn namespace_uri_gets_uri_of_element() {
        let package = Package::new();
        let doc = package.as_document();
        let setup = Setup::new();

        let e = doc.create_element(("uri", "wow"));
        doc.root().append_child(e);

        let r = setup.evaluate(doc.root(), NamespaceUri, args![nodeset![e]]);

        assert_eq!(Ok(Value::String("uri".to_owned())), r);
    }

    #[test]
    fn name_uses_declared_prefix() {
        let package = Package::new();
        let doc = package.as_document();
        let setup = Setup::new();

        let e = doc.create_element(("uri", "wow"));
        e.register_prefix("prefix", "uri");
        doc.root().append_child(e);

        let r = setup.evaluate(doc.root(), Name, args![nodeset![e]]);

        assert_eq!(Ok(Value::String("prefix:wow".to_owned())), r);
    }

    #[test]
    fn string_converts_to_string() {
        evaluate_literal(StringFn, args![true], |r| {
            assert_eq!(Ok(Value::String("true".to_owned())), r);
        });
    }

    #[test]
    fn concat_combines_strings() {
        evaluate_literal(Concat, args!["hello", " ", "world"], |r| {
            assert_eq!(Ok(Value::String("hello world".to_owned())), r);
        });
    }

    #[test]
    fn concat_checks_the_context_string_allocation_budget_before_allocating() {
        // concat must reject its aggregate reservation before constructing an oversized String.
        let package = Package::new();
        let document = package.as_document();
        let mut setup = Setup::new();
        setup.context.set_string_allocation_limit(3);
        let error = setup
            .evaluate(document.root(), Concat, args!["ab", "cd"])
            .expect_err("four-byte concat must exceed the three-byte allocation budget");
        assert!(error.to_string().contains("string allocation budget"));
    }

    #[test]
    fn concat_bounds_nodeset_string_values_before_output_allocation() {
        // A node-set string value is attacker-controlled and must remain under
        // the same reservation that gates the final concat allocation.
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        root.append_child(document.create_text("oversized"));
        document.root().append_child(root);
        let mut nodes = Nodeset::new();
        nodes.add(root);
        let mut setup = Setup::new();
        setup.context.set_string_allocation_limit(4);
        let error = setup
            .evaluate(
                document.root(),
                Concat,
                vec![Value::Nodeset(nodes), "x".into()],
            )
            .expect_err("node-set concat must be bounded before output allocation");
        assert!(error.to_string().contains("string allocation budget"));
    }

    #[test]
    fn starts_with_checks_prefixes() {
        evaluate_literal(starts_with(), args!["hello", "he"], |r| {
            assert_eq!(Ok(Value::Boolean(true)), r);
        });
    }

    #[test]
    fn contains_looks_for_a_needle() {
        evaluate_literal(contains(), args!["astronomer", "ono"], |r| {
            assert_eq!(Ok(Value::Boolean(true)), r);
        });
    }

    #[test]
    fn string_predicates_bound_nodeset_argument_conversion() {
        // Predicate results retain no string, so the argument conversion itself must consume
        // the allocation budget before materializing an attacker-controlled node string-value.
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        root.append_child(document.create_text("oversized"));
        document.root().append_child(root);
        let mut nodes = Nodeset::new();
        nodes.add(root);
        let mut setup = Setup::new();
        setup.context.set_string_allocation_limit(4);
        let error = setup
            .evaluate(
                document.root(),
                contains(),
                vec![Value::Nodeset(nodes), "size".into()],
            )
            .expect_err("node-set conversion must exceed the four-byte allocation budget");
        assert!(error.to_string().contains("string allocation budget"));
    }

    #[test]
    fn number_and_sum_bound_nodeset_string_materialization() {
        // Numeric conversion has a scalar result, but its node string-value workspace is still
        // attacker-controlled and must cross the context allocation gate before allocation.
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        let first = document.create_element("item");
        first.append_child(document.create_text("1234"));
        root.append_child(first);
        document.root().append_child(root);

        {
            let mut setup = Setup::new();
            setup.context.set_string_allocation_limit(3);
            let error = setup
                .evaluate(
                    document.root(),
                    NumberFn,
                    vec![Value::Nodeset(nodeset![first.clone()])],
                )
                .expect_err("four-byte numeric workspace must exceed a three-byte budget");
            assert!(error.to_string().contains("string allocation budget"));
        }
        {
            let mut setup = Setup::new();
            setup.context.set_string_allocation_limit(3);
            let error = setup
                .evaluate(document.root(), Sum, vec![Value::Nodeset(nodeset![first])])
                .expect_err("four-byte sum workspace must exceed a three-byte budget");
            assert!(error.to_string().contains("string allocation budget"));
        }
    }

    #[test]
    fn substring_before_slices_before() {
        evaluate_literal(substring_before(), args!["1999/04/01", "/"], |r| {
            assert_eq!(Ok(Value::String("1999".to_owned())), r);
        });
    }

    #[test]
    fn substring_after_slices_after() {
        evaluate_literal(substring_after(), args!["1999/04/01", "/"], |r| {
            assert_eq!(Ok(Value::String("04/01".to_owned())), r);
        });
    }

    #[test]
    fn substring_functions_bound_nodeset_argument_conversion() {
        // Both the converted input and copied result are owned strings and must be reserved
        // before either allocation occurs.
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        root.append_child(document.create_text("oversized"));
        document.root().append_child(root);
        let mut nodes = Nodeset::new();
        nodes.add(root);
        let mut setup = Setup::new();
        setup.context.set_string_allocation_limit(8);
        let error = setup
            .evaluate(
                document.root(),
                substring_before(),
                vec![Value::Nodeset(nodes), "size".into()],
            )
            .expect_err("node-set conversion must exceed the eight-byte allocation budget");
        assert!(error.to_string().contains("string allocation budget"));
    }

    #[test]
    fn substring_is_one_indexed() {
        evaluate_literal(Substring, args!["あいうえお", 2.0], |r| {
            assert_eq!(Ok(Value::String("いうえお".to_owned())), r);
        });
    }

    #[test]
    fn substring_has_optional_length() {
        evaluate_literal(Substring, args!["あいうえお", 2.0, 3.0], |r| {
            assert_eq!(Ok(Value::String("いうえ".to_owned())), r);
        });
    }

    #[test]
    fn substring_without_length_accepts_negative_infinity_start() {
        // XPath 1.0 section 4.2 selects every finite character position when the rounded start
        // is negative infinity and no upper bound was supplied.
        // https://www.w3.org/TR/1999/REC-xpath-19991116#function-substring
        evaluate_literal(Substring, args!["abc", f64::NEG_INFINITY], |result| {
            assert_eq!(Ok(Value::String("abc".to_owned())), result);
        });
    }

    fn substring_test(s: &str, start: f64, len: f64) -> String {
        evaluate_literal(Substring, args![s, start, len], |r| match r {
            Ok(Value::String(s)) => s,
            r => panic!("substring failed: {:?}", r),
        })
    }

    #[test]
    fn substring_rounds_values() {
        assert_eq!("いうえ", substring_test("あいうえお", 1.5, 2.6));
    }

    #[test]
    fn substring_is_a_window_of_the_characters() {
        assert_eq!("あい", substring_test("あいうえお", 0.0, 3.0));
    }

    #[test]
    fn substring_with_nan_start_is_empty() {
        assert_eq!("", substring_test("あいうえお", f64::NAN, 3.0));
    }

    #[test]
    fn substring_with_nan_len_is_empty() {
        assert_eq!("", substring_test("あいうえお", 1.0, f64::NAN));
    }

    #[test]
    fn substring_with_infinite_len_goes_to_end_of_string() {
        assert_eq!(
            "あいうえお",
            substring_test("あいうえお", -42.0, f64::INFINITY)
        );
    }

    #[test]
    fn substring_with_negative_infinity_start_is_empty() {
        assert_eq!(
            "",
            substring_test("あいうえお", f64::NEG_INFINITY, f64::INFINITY)
        );
    }

    #[test]
    fn string_length_counts_characters() {
        evaluate_literal(StringLength, args!["日本語"], |r| {
            assert_eq!(Ok(Value::Number(3.0)), r);
        });
    }

    #[test]
    fn string_length_does_not_materialize_nodeset_string_values() {
        // XPath string-length only observes code points, so a zero allocation budget must not
        // force an otherwise unnecessary copy of a node-set string-value.
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        root.append_child(document.create_text("日本語"));
        document.root().append_child(root);
        let mut nodes = Nodeset::new();
        nodes.add(root);
        let mut setup = Setup::new();
        setup.context.set_string_allocation_limit(0);
        assert_eq!(
            Ok(Value::Number(3.0)),
            setup.evaluate(document.root(), StringLength, vec![Value::Nodeset(nodes)])
        );
    }

    #[test]
    fn normalize_space_removes_leading_space() {
        evaluate_literal(NormalizeSpace, args!["\t hello"], |r| {
            assert_eq!(Ok(Value::String("hello".to_owned())), r);
        });
    }

    #[test]
    fn normalize_space_removes_trailing_space() {
        evaluate_literal(NormalizeSpace, args!["hello\r\n"], |r| {
            assert_eq!(Ok(Value::String("hello".to_owned())), r);
        });
    }

    #[test]
    fn normalize_space_squashes_intermediate_space() {
        evaluate_literal(NormalizeSpace, args!["hello\t\r\n world"], |r| {
            assert_eq!(Ok(Value::String("hello world".to_owned())), r);
        });
    }

    #[test]
    fn normalize_space_checks_the_string_allocation_budget_before_allocating() {
        // Tokenization must not allocate an intermediate vector outside the context budget.
        let package = Package::new();
        let document = package.as_document();
        let mut setup = Setup::new();
        setup.context.set_string_allocation_limit(3);
        let error = setup
            .evaluate(document.root(), NormalizeSpace, args!["a b c"])
            .expect_err("five-byte normalized output exceeds the allocation budget");
        assert!(error.to_string().contains("string allocation budget"));
    }

    fn translate_test(s: &str, from: &str, to: &str) -> String {
        evaluate_literal(Translate, args![s, from, to], |r| match r {
            Ok(Value::String(s)) => s,
            r => panic!("translate failed: {:?}", r),
        })
    }

    #[test]
    fn translate_replaces_characters() {
        assert_eq!("イエ", translate_test("いえ", "あいうえお", "アイウエオ"));
    }

    #[test]
    fn translate_reserves_workspace_before_allocating() {
        // All translate inputs and its output are attacker-controlled. The call must fail before
        // constructing conversion strings, the replacement index, or the result.
        let package = Package::new();
        let document = package.as_document();
        let mut setup = Setup::new();
        setup.context.set_string_allocation_limit(3);
        let error = setup
            .evaluate(document.root(), Translate, args!["abcd", "a", ""])
            .expect_err("translate workspace must exceed the three-byte allocation budget");
        assert!(error.to_string().contains("string allocation budget"));
    }

    #[test]
    fn translate_charges_one_character_replacement_storage() {
        // Derive the target-dependent tuple layout from the production representation instead of
        // assuming a 64-bit ABI.
        let required = std::mem::size_of::<(char, usize, Option<char>)>() + char::MAX.len_utf8();
        let package = Package::new();
        let document = package.as_document();
        let mut setup = Setup::new();
        setup
            .context
            .set_string_allocation_limit(required.saturating_sub(1));
        let error = setup
            .evaluate(document.root(), Translate, args!["a", "a", "b"])
            .expect_err("replacement table and result must cross the allocation gate");
        assert!(error.to_string().contains("string allocation budget"));

        setup.context.set_string_allocation_limit(required);
        assert_eq!(
            setup.evaluate(document.root(), Translate, args!["a", "a", "b"]),
            Ok(Value::String("b".into()))
        );
    }

    #[test]
    fn translate_removes_characters_without_replacement() {
        assert_eq!("イ", translate_test("いえ", "あいうえお", "アイ"));
    }

    #[test]
    fn translate_replaces_each_char_only_once() {
        assert_eq!("b", translate_test("a", "ab", "bc"));
    }

    #[test]
    fn translate_uses_first_replacement() {
        assert_eq!("b", translate_test("a", "aa", "bc"));
    }

    #[test]
    fn translate_ignores_extra_replacements() {
        assert_eq!("b", translate_test("a", "a", "bc"));
    }

    #[test]
    fn boolean_converts_to_boolean() {
        evaluate_literal(BooleanFn, args!["false"], |r| {
            assert_eq!(Ok(Value::Boolean(true)), r);
        });
    }

    #[test]
    fn number_converts_to_number() {
        evaluate_literal(NumberFn, args![" -1.2 "], |r| {
            assert_eq!(Ok(Value::Number(-1.2)), r);
        });
    }

    #[test]
    fn number_fails_with_nan() {
        evaluate_literal(NumberFn, args![" nope "], |r| assert_number(f64::NAN, r));
    }

    #[test]
    fn sum_adds_up_nodeset() {
        let package = Package::new();
        let doc = package.as_document();
        let setup = Setup::new();

        let c = doc.create_comment("-32.0");
        let t = doc.create_text("98.7");

        let r = setup.evaluate(doc.root(), Sum, args![nodeset![c, t]]);

        assert_eq!(Ok(Value::Number(66.7)), r);
    }

    /// By default, NaN != NaN and -0.0 == 0.0. We don't want either
    /// of those to be true.
    struct PedanticNumber(f64);

    impl PedanticNumber {
        fn non_nan_key(&self) -> (bool, bool, f64) {
            (self.0.is_finite(), self.0.is_sign_positive(), self.0)
        }
    }

    impl PartialEq for PedanticNumber {
        fn eq(&self, other: &Self) -> bool {
            if self.0.is_nan() {
                other.0.is_nan()
            } else {
                self.non_nan_key() == other.non_nan_key()
            }
        }
    }

    impl fmt::Debug for PedanticNumber {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{{ {}, NaN: {}, finite: {}, positive: {} }}",
                self.0,
                self.0.is_nan(),
                self.0.is_finite(),
                self.0.is_sign_positive()
            )
        }
    }

    fn assert_number(expected: f64, actual: Result<Value<'_>, Error>) {
        match actual {
            Ok(Value::Number(n)) => assert_eq!(PedanticNumber(n), PedanticNumber(expected)),
            _ => panic!("{:?} did not evaluate correctly", actual),
        }
    }

    #[test]
    fn floor_rounds_down() {
        evaluate_literal(floor(), args![199.99], |r| assert_number(199.0, r));
    }

    #[test]
    fn ceiling_rounds_up() {
        evaluate_literal(ceiling(), args![199.99], |r| assert_number(200.0, r));
    }

    #[test]
    fn round_nan_to_nan() {
        evaluate_literal(round(), args![f64::NAN], |r| assert_number(f64::NAN, r));
    }

    #[test]
    fn round_pos_inf_to_pos_inf() {
        evaluate_literal(round(), args![f64::INFINITY], |r| {
            assert_number(f64::INFINITY, r)
        });
    }

    #[test]
    fn round_neg_inf_to_neg_inf() {
        evaluate_literal(round(), args![f64::NEG_INFINITY], |r| {
            assert_number(f64::NEG_INFINITY, r)
        });
    }

    #[test]
    fn round_pos_zero_to_pos_zero() {
        evaluate_literal(round(), args![0.0], |r| assert_number(0.0, r));
    }

    #[test]
    fn round_neg_zero_to_neg_zero() {
        evaluate_literal(round(), args![-0.0], |r| assert_number(-0.0, r));
    }

    #[test]
    fn round_neg_zero_point_five_to_neg_zero() {
        evaluate_literal(round(), args![-0.5], |r| assert_number(-0.0, r));
    }

    #[test]
    fn round_neg_five_to_neg_five() {
        evaluate_literal(round(), args![-5.0], |r| assert_number(-5.0, r));
    }

    #[test]
    fn round_pos_zero_point_five_to_pos_one() {
        evaluate_literal(round(), args![0.5], |r| assert_number(1.0, r));
    }
}
