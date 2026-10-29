//! Support for registering and creating `XPath` functions.

#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
// `core` below names this module's core function library, not the crate.
use ::core::ops::Index;
use alloc::{borrow::Cow, string::String, vec::Vec};
#[cfg(feature = "embedded")]
use alloc::{borrow::ToOwned, boxed::Box, string::ToString};
use snafu::Snafu;

use crate::Value;
use crate::context;
use crate::nodeset::Nodeset;

#[path = "function/core.rs"]
pub(crate) mod core;

pub(crate) enum Resolved<'a> {
    Core(core::Core),
    Extension(&'a dyn Function),
}

impl<'a> Resolved<'a> {
    pub(crate) fn native(self) -> &'a dyn Function {
        match self {
            Self::Core(core) => core.native(),
            Self::Extension(function) => function,
        }
    }
}

/// Types that can be used as `XPath` functions.
pub trait Function {
    /// Evaluate this function in a specific context with a specific
    /// set of arguments.
    ///
    /// # Errors
    /// Returns arity, type, resource, or extension errors from evaluation.
    fn evaluate<'d>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        mut args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, Error> {
        self.evaluate_borrowed(context, &mut args)
    }

    /// Borrow admitted slots without copying them into a native `Vec`.
    ///
    /// # Errors
    /// Returns `BorrowedArgumentsUnsupported` unless implemented by the function;
    /// implementations preserve their arity, type, resource, and extension errors.
    fn evaluate_borrowed<'d>(
        &self,
        _context: &context::Evaluation<'_, 'd>,
        _args: &mut [Value<'d>],
    ) -> Result<Value<'d>, Error> {
        Err(Error::BorrowedArgumentsUnsupported)
    }
}

/// Represents the kind of an `XPath` value without carrying a value.
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
            #[cfg(feature = "embedded")]
            Value::AccountedString(..) => ArgumentType::String,
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
    /// The embedding callback stopped processing; it retains the typed cause.
    #[snafu(display("processing stopped by the embedding callback"))]
    ProcessingStopped,
    #[snafu(display("extension does not support borrowed argument storage"))]
    BorrowedArgumentsUnsupported,
    #[snafu(display("could not evaluate function: {}", what))]
    Other { what: String },
    /// A fixed diagnostic has no allocation to admit or retain.
    #[snafu(display("could not evaluate function: {}", what))]
    Static { what: &'static str },
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
pub trait ArgumentList<'d>:
    ::core::ops::Deref<Target = [Value<'d>]> + ::core::ops::DerefMut
{
    fn pop(&mut self) -> Option<Value<'d>>;
}

impl<'d> ArgumentList<'d> for Vec<Value<'d>> {
    fn pop(&mut self) -> Option<Value<'d>> {
        Vec::pop(self)
    }
}

impl<'d> ArgumentList<'d> for &mut [Value<'d>] {
    fn pop(&mut self) -> Option<Value<'d>> {
        let slots = ::core::mem::take(self);
        let (last, rest) = slots.split_last_mut()?;
        *self = rest;
        // Vacated slots remain initialized until the caller drops its buffer.
        // Moving a value neither clones it nor frees the admitted capacity.
        Some(::core::mem::replace(last, Value::Boolean(false)))
    }
}

pub struct Args<'d, A = Vec<Value<'d>>>(pub A, ::core::marker::PhantomData<&'d ()>);

impl<'d, A: ArgumentList<'d>> Args<'d, A> {
    pub fn new(values: A) -> Self {
        Self(values, ::core::marker::PhantomData)
    }

    /// Remove the last argument without coercion.
    ///
    /// # Errors
    /// Returns `ArgumentMissing` when no argument remains.
    pub fn pop_value(&mut self) -> Result<Value<'d>, Error> {
        self.0.pop().ok_or(Error::ArgumentMissing)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Ensures that there are at least the requested number of arguments.
    ///
    /// # Errors
    /// Returns `NotEnoughArguments` when the minimum is not met.
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
    ///
    /// # Errors
    /// Returns `TooManyArguments` when the maximum is exceeded.
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
    ///
    /// # Errors
    /// Returns `NotEnoughArguments` or `TooManyArguments` for an arity mismatch.
    pub fn exactly(&self, expected: usize) -> Result<(), Error> {
        let actual = self.0.len();
        match actual.cmp(&expected) {
            ::core::cmp::Ordering::Less => Err(Error::NotEnoughArguments { expected, actual }),
            ::core::cmp::Ordering::Greater => Err(Error::TooManyArguments { expected, actual }),
            ::core::cmp::Ordering::Equal => Ok(()),
        }
    }

    /// Removes the **last** argument and ensures it is a boolean. If
    /// the argument is not a boolean, it is converted to one.
    ///
    /// # Errors
    /// Returns `ArgumentMissing` when no argument remains.
    pub fn pop_boolean(&mut self) -> Result<bool, Error> {
        let v = self.0.pop().ok_or(Error::ArgumentMissing)?;
        Ok(v.into_boolean())
    }

    /// Removes the **last** argument and ensures it is a number. If
    /// the argument is not a number, it is converted to one.
    ///
    /// # Errors
    /// Returns `ArgumentMissing` or the traversal/resource error from coercion.
    pub fn pop_number(&mut self, context: &context::Evaluation<'_, '_>) -> Result<f64, Error> {
        let value = self.0.pop().ok_or(Error::ArgumentMissing)?;
        value.number(context)
    }

    /// Removes the **last** argument and ensures it is a string. If
    /// the argument is not a string, it is converted to one.
    ///
    /// # Errors
    /// Returns `ArgumentMissing` or the traversal/resource error from coercion.
    pub fn pop_string(&mut self, context: &context::Evaluation<'_, '_>) -> Result<String, Error> {
        match self.0.pop().ok_or(Error::ArgumentMissing)? {
            Value::String(value) => Ok(value),
            #[cfg(feature = "embedded")]
            Value::AccountedString(value) => {
                context.charge_work(value.len())?;
                context.reserve_string_allocation(value.len())?;
                Ok(value.as_str().to_owned())
            }
            Value::ResultTreeFragment(_, value) => match alloc::sync::Arc::try_unwrap(value) {
                Ok(value) => Ok(value),
                Err(value) => {
                    context.charge_work(value.len())?;
                    context.reserve_string_allocation(value.len())?;
                    Ok(value.as_ref().clone())
                }
            },
            Value::Nodeset(nodes) => match nodes.document_order_first_with_context(context)? {
                Some(node) => node.string_value_with_context(context),
                None => Ok(String::new()),
            },
            value => {
                context.reserve_string_allocation(value.string_len())?;
                Ok(value.into_string())
            }
        }
    }

    /// Removes the **last** argument and ensures it is a nodeset. If
    /// the argument is not a nodeset, a type mismatch error is
    /// returned.
    ///
    /// # Errors
    /// Returns `ArgumentMissing` or `ArgumentNotANodeset` without coercion.
    pub fn pop_nodeset(&mut self) -> Result<Nodeset<'d>, Error> {
        let v = self.0.pop().ok_or(Error::ArgumentMissing)?;
        match v {
            Value::Nodeset(v) => Ok(v),
            a => Err(Error::not_a_nodeset(&a)),
        }
    }
}

impl<'d, A: ArgumentList<'d>> Index<usize> for Args<'d, A> {
    type Output = Value<'d>;

    fn index(&self, index: usize) -> &Value<'d> {
        self.0.index(index)
    }
}

impl Function for core::Core {
    fn evaluate_borrowed<'d>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        args: &mut [Value<'d>],
    ) -> Result<Value<'d>, Error> {
        self.evaluate_in(context, args, crate::runtime::Native)
    }
}

pub(crate) fn append_metered_string(
    output: &mut String,
    text: &str,
    context: &context::Evaluation<'_, '_>,
) -> Result<(), Error> {
    context.charge_work(text.len())?;
    let required = output.len().checked_add(text.len()).ok_or(Error::Static {
        what: "XPath string size overflow",
    })?;
    if required > output.capacity() {
        let old_capacity = output.capacity();
        let capacity = required.max(old_capacity.saturating_mul(2));
        context.charge_work(output.len())?;
        // A relocating allocator can retain the old block until the copy completes.
        context.reserve_string_allocation(capacity)?;
        if output.try_reserve_exact(capacity - output.len()).is_err() {
            context.release_temporary_allocation(capacity)?;
            return Err(Error::Static {
                what: "XPath string allocation failed",
            });
        }
        context.release_temporary_allocation(old_capacity)?;
    }
    output.push_str(text);
    Ok(())
}

/// Borrow existing string values or coerce under the evaluation's traversal and memory limits.
/// Consumers must additionally charge their own lexical processing of the returned text.
///
/// # Errors
/// Returns the traversal or resource error before an inadmissible coercion.
pub fn string_argument_view<'a>(
    value: &'a Value<'_>,
    context: &context::Evaluation<'_, '_>,
) -> Result<Cow<'a, str>, Error> {
    match value {
        Value::String(text) => Ok(Cow::Borrowed(text)),
        #[cfg(feature = "embedded")]
        Value::AccountedString(text) => Ok(Cow::Borrowed(text)),
        Value::ResultTreeFragment(_, text) => Ok(Cow::Borrowed(text)),
        Value::Nodeset(nodes) => match nodes.document_order_first_with_context(context)? {
            Some(node) => node.string_value_with_context(context).map(Cow::Owned),
            None => Ok(Cow::Borrowed("")),
        },
        _ => {
            context.reserve_temporary_allocation(value.string_len())?;
            Ok(Cow::Owned(value.string()))
        }
    }
}

// IEEE 754 floor and ceiling; core has no float rounding without std.
#[cfg(any(feature = "std", not(feature = "embedded")))]
fn ieee_floor(x: f64) -> f64 {
    x.floor()
}
#[cfg(any(feature = "std", not(feature = "embedded")))]
fn ieee_ceil(x: f64) -> f64 {
    x.ceil()
}
#[cfg(all(feature = "embedded", not(feature = "std")))]
fn ieee_floor(x: f64) -> f64 {
    libm::floor(x)
}
#[cfg(all(feature = "embedded", not(feature = "std")))]
fn ieee_ceil(x: f64) -> f64 {
    libm::ceil(x)
}

// XPath 1.0 4.4 preserves signed zero and infinities when already integral.
// https://www.w3.org/TR/1999/REC-xpath-19991116/#function-round
fn round_ties_to_positive_infinity(x: f64) -> f64 {
    let y = ieee_floor(x);
    if super::same_xpath_number(x, y) {
        x
    } else {
        let z = ieee_floor(2.0 * x - y);
        // Should use copysign
        if x.is_sign_positive() ^ z.is_sign_positive() {
            -z
        } else {
            z
        }
    }
}

pub(super) use core::CORE_NAMES;
pub use core::register_core_functions;

#[cfg(test)]
use core::Core::{
    Boolean as BooleanFn, Concat, Count, Last, LocalName, Name, NamespaceUri,
    Normalize as NormalizeSpace, Number as NumberFn, Position, String as StringFn, StringLength,
    Substring, Sum, Translate,
};

#[cfg(test)]
macro_rules! test_function {
    ($($name:ident => $kind:ident),* $(,)?) => {
        $(const fn $name() -> core::Core { core::Core::$kind })*
    };
}
#[cfg(test)]
test_function! {
    starts_with => StartsWith, contains => Contains, substring_before => Before,
    substring_after => After,
    floor => Floor, ceiling => Ceiling, round => Round,
}

#[cfg(test)]
mod test {
    use std::borrow::ToOwned;
    use std::fmt;

    #[cfg(feature = "embedded")]
    use super::sxd_document_no_unsafe;
    use sxd_document_no_unsafe::Package;

    use crate::context;
    use crate::nodeset::{Node, Nodeset};
    use crate::{LiteralValue, Value};

    use super::{
        BooleanFn, Concat, Count, Error, Function, Last, LocalName, Name, NamespaceUri,
        NormalizeSpace, NumberFn, Position, StringFn, StringLength, Substring, Sum, Translate,
        ceiling, contains, floor, round, starts_with, substring_after, substring_before,
    };

    #[test]
    fn native_text_growth_admits_the_old_and_new_allocation() {
        // A reallocating builder may hold both blocks during relocation;
        // reserving only the capacity delta would let the live peak escape.
        let package = Package::new();
        let mut context = context::Context::new();
        context.set_string_allocation_limit(64);
        let evaluation = context::Evaluation::new(&context, package.as_document().root().into());
        let mut text = String::new();
        super::append_metered_string(&mut text, &"a".repeat(32), &evaluation).unwrap();
        let error = super::append_metered_string(&mut text, "b", &evaluation)
            .expect_err("32 old plus 64 new does not fit 64");
        assert!(error.to_string().contains("allocation budget"));
        assert_eq!(text, "a".repeat(32));
        assert_eq!(context.string_allocation_exceeded(), Some(96));
    }

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

        fn evaluate<N>(
            &self,
            node: N,
            f: super::core::Core,
            args: Vec<Value<'d>>,
        ) -> Result<Value<'d>, Error>
        where
            N: Into<Node<'d>>,
        {
            let context = context::Evaluation::new(&self.context, node.into());
            f.evaluate(&context, args)
        }
    }

    fn evaluate_literal<F2, T>(f: super::core::Core, args: Vec<LiteralValue>, rf: F2) -> T
    where
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
            assert_eq!(Ok(Value::String(String::new())), r);
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
            r => panic!("substring failed: {r:?}"),
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
            r => panic!("translate failed: {r:?}"),
        })
    }

    #[test]
    fn translate_replaces_characters() {
        assert_eq!("イエ", translate_test("いえ", "あいうえお", "アイウエオ"));
    }

    #[test]
    fn name_functions_reserve_output_before_materializing() {
        // QName access must not clone strings or construct a default node-set outside the gate.
        let package = Package::new();
        let document = package.as_document();
        let node = document.create_element(sxd_document_no_unsafe::QName::with_namespace_uri(
            Some("urn:test"),
            "element",
        ));
        node.register_prefix("p", "urn:test");
        document.root().append_child(node);
        for function in [
            Box::new(LocalName) as Box<dyn Function>,
            Box::new(NamespaceUri),
            Box::new(Name),
        ] {
            let mut context = crate::Context::new();
            context.set_string_allocation_limit(0);
            let evaluation = context::Evaluation::new(&context, node.into());
            assert!(function.evaluate(&evaluation, vec![]).is_err());
        }
    }

    #[test]
    fn core_string_functions_obey_work_on_owned_arguments() {
        // Coercion-free arguments still require scanning/copying inside each core function.
        let cases: Vec<(Box<dyn super::Function>, Vec<Value<'_>>)> = vec![
            (Box::new(super::Concat), args!["abc", "def"]),
            (Box::new(super::starts_with()), args!["abc", "ab"]),
            (Box::new(super::contains()), args!["abc", "bc"]),
            (Box::new(super::substring_before()), args!["abc", "b"]),
            (Box::new(super::substring_after()), args!["abc", "b"]),
            (Box::new(super::Substring), args!["abc", 1.0]),
            (Box::new(super::StringLength), args!["abc"]),
            (Box::new(super::NormalizeSpace), args![" a b "]),
        ];
        let package = Package::new();
        let document = package.as_document();
        for (function, args) in cases {
            let mut context = crate::Context::new();
            context.set_evaluation_work_limit(0);
            let evaluation = context::Evaluation::new(&context, document.root().into());
            assert!(
                function.evaluate(&evaluation, args).is_err(),
                "core string work must not bypass the gate"
            );
        }
    }

    #[test]
    fn node_string_arguments_obey_work_before_coercion() {
        // Every function using Args must use the metered node string visitor, not string_len().
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        root.append_child(document.create_text("payload"));
        document.root().append_child(root);
        let mut setup = Setup::new();
        setup.context.set_evaluation_work_limit(0);
        let evaluation = context::Evaluation::new(&setup.context, document.root().into());
        let mut args = super::Args::new(vec![Value::Nodeset(nodeset![root])]);
        assert!(
            args.pop_string(&evaluation).is_err(),
            "coercion must reject before traversing"
        );
    }

    #[test]
    fn translate_obeys_work_budget() {
        // Pre-owned strings still require map construction and per-character searches.
        let package = Package::new();
        let document = package.as_document();
        let mut setup = Setup::new();
        setup.context.set_evaluation_work_limit(0);
        let error = setup
            .evaluate(document.root(), Translate, args!["abc", "abc", "xyz"])
            .expect_err("translate must charge work before building its map");
        assert!(error.to_string().contains("work budget"));
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
        // assuming a 64-bit ABI. The UTF-8 scratch is on the stack; the heap
        // owns one replacement tuple and the actual one-byte output.
        let required = std::mem::size_of::<(char, usize, Option<char>)>() + "b".len();
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
        evaluate_literal(NumberFn, args![" nope "], |r| assert_number(f64::NAN, &r));
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

    #[test]
    fn sum_uses_document_order_independent_of_nodeset_hash_seed() {
        let package = Package::new();
        let doc = package.as_document();
        let elements = ["10000000000000000", "1", "-10000000000000000"].map(|value| {
            let element = doc.create_element("n");
            element.append_child(doc.create_text(value));
            doc.root().append_child(element);
            element
        });
        let setup = Setup::new();
        for _ in 0..100 {
            let result = setup.evaluate(
                doc.root(),
                Sum,
                args![nodeset![elements[0], elements[1], elements[2]]],
            );
            assert_eq!(Ok(Value::Number(0.0)), result);
        }
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

    fn assert_number(expected: f64, actual: &Result<Value<'_>, Error>) {
        match actual {
            Ok(Value::Number(n)) => assert_eq!(PedanticNumber(*n), PedanticNumber(expected)),
            _ => panic!("{actual:?} did not evaluate correctly"),
        }
    }

    #[test]
    fn floor_rounds_down() {
        evaluate_literal(floor(), args![199.99], |r| assert_number(199.0, &r));
    }

    #[test]
    fn ceiling_rounds_up() {
        evaluate_literal(ceiling(), args![199.99], |r| assert_number(200.0, &r));
    }

    #[test]
    fn round_nan_to_nan() {
        evaluate_literal(round(), args![f64::NAN], |r| assert_number(f64::NAN, &r));
    }

    #[test]
    fn round_pos_inf_to_pos_inf() {
        evaluate_literal(round(), args![f64::INFINITY], |r| {
            assert_number(f64::INFINITY, &r);
        });
    }

    #[test]
    fn round_neg_inf_to_neg_inf() {
        evaluate_literal(round(), args![f64::NEG_INFINITY], |r| {
            assert_number(f64::NEG_INFINITY, &r);
        });
    }

    #[test]
    fn round_pos_zero_to_pos_zero() {
        evaluate_literal(round(), args![0.0], |r| assert_number(0.0, &r));
    }

    #[test]
    fn round_neg_zero_to_neg_zero() {
        evaluate_literal(round(), args![-0.0], |r| assert_number(-0.0, &r));
    }

    #[test]
    fn round_neg_zero_point_five_to_neg_zero() {
        evaluate_literal(round(), args![-0.5], |r| assert_number(-0.0, &r));
    }

    #[test]
    fn round_neg_five_to_neg_five() {
        evaluate_literal(round(), args![-5.0], |r| assert_number(-5.0, &r));
    }

    #[test]
    fn round_pos_zero_point_five_to_pos_one() {
        evaluate_literal(round(), args![0.5], |r| assert_number(1.0, &r));
    }
}
