#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use snafu::{ResultExt, Snafu};
use std::fmt;
use sxd_document_no_unsafe::{PrefixedName, QName};

use crate::Value::{Boolean, Number};
use crate::axis::{Axis, AxisLike};
use crate::context;
use crate::function;
use crate::node_test::NodeTest;
use crate::nodeset::{Nodeset, OrderedNodes};
use crate::{LiteralValue, OwnedPrefixedName, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameKind {
    Function,
    Variable,
    Namespace,
}

impl fmt::Display for NameKind {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Function => "function",
            Self::Variable => "variable",
            Self::Namespace => "namespace prefix",
        })
    }
}

#[cfg(feature = "embedded")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NameText {
    pub(crate) prefix: Option<structured_asn1::memory::SharedString>,
    pub(crate) local: structured_asn1::memory::SharedString,
}

#[cfg(feature = "embedded")]
impl fmt::Display for NameText {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(prefix) = &self.prefix {
            write!(output, "{prefix}:")?;
        }
        write!(output, "{}", self.local)
    }
}

#[derive(Debug, Snafu, Clone, PartialEq, Hash)]
#[snafu(context(suffix(false)))]
#[cfg_attr(test, snafu(visibility(pub(crate))))]
pub enum Error {
    /// expression did not evaluate to a nodeset
    NotANodeset,
    #[snafu(display("unknown function {:?}", name))]
    UnknownFunction { name: OwnedPrefixedName },
    #[snafu(display("unknown variable {:?}", name))]
    UnknownVariable { name: OwnedPrefixedName },
    #[snafu(display("unknown namespace prefix {}", prefix))]
    UnknownNamespace { prefix: String },
    /// The diagnostic owns actual capacity admitted by the failing query.
    #[cfg(feature = "embedded")]
    #[snafu(display("unknown {kind} {name}"))]
    CurrentName { kind: NameKind, name: NameText },
    #[snafu(display("error while evaluating function: {}", source))]
    FunctionEvaluation { source: function::Error },
}

impl From<function::Error> for Error {
    fn from(source: function::Error) -> Self {
        Self::FunctionEvaluation { source }
    }
}

fn value_into_nodeset(v: Value<'_>) -> Result<Nodeset<'_>, Error> {
    match v {
        Value::Nodeset(ns) => Ok(ns),
        _ => Err(Error::NotANodeset),
    }
}

// In these cases, we use document order. From the spec:
//
// > `(preceding::foo)[1]` returns the first `foo` element in document
// > order, because the axis that applies to the `[1]` predicate is
// > the child axis
//
fn value_into_ordered_nodes<'d>(
    context: &context::Evaluation<'_, 'd>,
    v: Value<'d>,
) -> Result<OrderedNodes<'d>, Error> {
    match v {
        Value::Nodeset(ns) => ns
            .document_order_with_context(context)
            .map(Into::into)
            .map_err(|source| Error::FunctionEvaluation { source }),
        _ => Err(Error::NotANodeset),
    }
}

pub trait Expression: fmt::Debug {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error>;

    fn ast_depth(&self) -> usize {
        1
    }
}

impl<T: ?Sized> Expression for Box<T>
where
    T: Expression,
{
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        context.admit_expression_step()?;
        (**self).evaluate(context)
    }

    fn ast_depth(&self) -> usize {
        (**self).ast_depth()
    }
}

pub type SubExpression = Box<dyn Expression + 'static>;

impl<T: Expression + ?Sized> Expression for &T {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        (**self).evaluate(context)
    }

    fn ast_depth(&self) -> usize {
        (**self).ast_depth()
    }
}

macro_rules! binary_constructor(
    ($t:ident) => (
        impl $t {
            #[allow(clippy::new_ret_no_self)]
            pub fn new(left: SubExpression, right: SubExpression) -> SubExpression {
                Box::new($t{ left, right })
            }
        }
    );
);

fn binary_ast_depth<L: Expression, R: Expression>(left: &L, right: &R) -> usize {
    1usize.saturating_add(left.ast_depth().max(right.ast_depth()))
}

#[derive(Debug)]
pub struct And<L = SubExpression, R = L> {
    pub left: L,
    pub right: R,
}

binary_constructor!(And);

impl<L: Expression, R: Expression> Expression for And<L, R> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        let left = self.left.evaluate(context)?.boolean();
        let v = left && self.right.evaluate(context)?.boolean();
        Ok(Boolean(v))
    }

    fn ast_depth(&self) -> usize {
        binary_ast_depth(&self.left, &self.right)
    }
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct ContextNode;

impl Expression for ContextNode {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        Self::evaluate_in(context, crate::runtime::Native)
    }
}

impl ContextNode {
    fn evaluate_in<'d, R: crate::runtime::Runtime>(
        context: &context::Evaluation<'_, 'd>,
        runtime: R,
    ) -> Result<Value<'d>, Error> {
        use crate::runtime::Set;
        let mut nodes = runtime.set();
        nodes
            .insert(
                context,
                runtime
                    .clone_node(context, &context.node)
                    .context(FunctionEvaluation)?,
            )
            .context(FunctionEvaluation)?;
        Ok(Value::Nodeset(nodes.finish()))
    }
}

#[derive(Debug)]
pub struct Equal<L = SubExpression, R = L> {
    pub left: L,
    pub right: R,
}

binary_constructor!(Equal);

impl<L: Expression, R: Expression> Equal<L, R> {
    fn boolean_evaluate(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        let left_val = self.left.evaluate(context)?;
        let right_val = self.right.evaluate(context)?;

        compare_equality_values(context, &left_val, &right_val, Equality::Equal)
    }
}

impl<L: Expression, R: Expression> Expression for Equal<L, R> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        self.boolean_evaluate(context).map(Boolean)
    }

    fn ast_depth(&self) -> usize {
        binary_ast_depth(&self.left, &self.right)
    }
}

#[derive(Debug)]
pub struct NotEqual<L = SubExpression, R = L> {
    left: L,
    right: R,
}

impl NotEqual {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(NotEqual { left, right })
    }
}

impl<L: Expression, R: Expression> Expression for NotEqual<L, R> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        let left = self.left.evaluate(context)?;
        let right = self.right.evaluate(context)?;
        compare_equality_values(context, &left, &right, Equality::NotEqual).map(Boolean)
    }

    fn ast_depth(&self) -> usize {
        binary_ast_depth(&self.left, &self.right)
    }
}

#[derive(Clone, Copy)]
enum Equality {
    Equal,
    NotEqual,
}

impl Equality {
    fn strings(
        self,
        context: &context::Evaluation<'_, '_>,
        left: &str,
        right: &str,
    ) -> Result<bool, Error> {
        if left.len() != right.len() {
            return Ok(self.result(false));
        }
        context
            .charge_work(left.len())
            .context(FunctionEvaluation)?;
        Ok(match self {
            Self::Equal => left == right,
            Self::NotEqual => left != right,
        })
    }

    fn numbers(self, left: f64, right: f64) -> bool {
        self.result(super::same_xpath_number(left, right))
    }

    fn booleans(self, left: bool, right: bool) -> bool {
        match self {
            Self::Equal => left == right,
            Self::NotEqual => left != right,
        }
    }

    fn result(self, equal: bool) -> bool {
        match self {
            Self::Equal => equal,
            Self::NotEqual => !equal,
        }
    }
}

fn compare_nodesets<'d, R: crate::runtime::Runtime>(
    context: &context::Evaluation<'_, 'd>,
    left: &Nodeset<'d>,
    right: &Nodeset<'d>,
    comparison: Equality,
    runtime: R,
) -> Result<bool, Error> {
    let (materialized, compared) = if left.size() <= right.size() {
        (left, right)
    } else {
        (right, left)
    };
    for node in runtime.nodes(materialized).context(FunctionEvaluation)? {
        let value = runtime
            .node_text(context, node)
            .context(FunctionEvaluation)?;
        for candidate in runtime.nodes(compared).context(FunctionEvaluation)? {
            context.charge_work(1).context(FunctionEvaluation)?;
            if comparison.result(
                runtime
                    .node_equals(context, candidate, &value)
                    .context(FunctionEvaluation)?,
            ) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn compare_nodes_with_string<R: crate::runtime::Runtime>(
    context: &context::Evaluation<'_, '_>,
    nodes: &Nodeset<'_>,
    value: &str,
    comparison: Equality,
    runtime: R,
) -> Result<bool, Error> {
    for node in runtime.nodes(nodes).context(FunctionEvaluation)? {
        context.charge_work(1).context(FunctionEvaluation)?;
        if comparison.result(
            runtime
                .node_equals(context, node, value)
                .context(FunctionEvaluation)?,
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn compare_equality_values<'d>(
    context: &context::Evaluation<'_, 'd>,
    left: &Value<'d>,
    right: &Value<'d>,
    comparison: Equality,
) -> Result<bool, Error> {
    compare_equality_values_in(context, left, right, comparison, crate::runtime::Native)
}

fn compare_equality_values_in<'d, R: crate::runtime::Runtime>(
    context: &context::Evaluation<'_, 'd>,
    left: &Value<'d>,
    right: &Value<'d>,
    comparison: Equality,
    runtime: R,
) -> Result<bool, Error> {
    let result = match (left, right) {
        (Value::Nodeset(left), Value::Nodeset(right)) => {
            return compare_nodesets(context, left, right, comparison, runtime);
        }
        (Value::Nodeset(nodes), Boolean(value)) | (Boolean(value), Value::Nodeset(nodes)) => {
            comparison.booleans(nodes.size() != 0, *value)
        }
        (Value::Nodeset(nodes), Number(value)) | (Number(value), Value::Nodeset(nodes)) => {
            for node in runtime.nodes(nodes).context(FunctionEvaluation)? {
                context.charge_work(1).context(FunctionEvaluation)?;
                let number = runtime
                    .node_number(context, node)
                    .context(FunctionEvaluation)?;
                if comparison.numbers(number, *value) {
                    return Ok(true);
                }
            }
            false
        }
        (Value::Nodeset(nodes), value) | (value, Value::Nodeset(nodes)) => {
            compare_nodes_with_string(
                context,
                nodes,
                value.scalar_text().expect("remaining scalar is text"),
                comparison,
                runtime,
            )?
        }
        (Boolean(_), _) | (_, Boolean(_)) => comparison.booleans(left.boolean(), right.boolean()),
        (Number(_), _) | (_, Number(_)) => comparison.numbers(
            left.number_in(context, runtime)
                .context(FunctionEvaluation)?,
            right
                .number_in(context, runtime)
                .context(FunctionEvaluation)?,
        ),
        (left, right) => comparison.strings(
            context,
            left.scalar_text().expect("remaining scalar is text"),
            right.scalar_text().expect("remaining scalar is text"),
        )?,
    };
    Ok(result)
}

#[derive(Debug)]
pub struct Function {
    pub name: OwnedPrefixedName,
    pub arguments: Vec<SubExpression>,
}

impl Expression for Function {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        call_function(
            context,
            PrefixedName::with_prefix(self.name.prefix.as_deref(), &self.name.local_part),
            self.arguments.iter(),
        )
    }

    fn ast_depth(&self) -> usize {
        1usize.saturating_add(
            self.arguments
                .iter()
                .map(Expression::ast_depth)
                .max()
                .unwrap_or(0),
        )
    }
}

fn call_function<'d, E: Expression>(
    context: &context::Evaluation<'_, 'd>,
    original: PrefixedName<'_>,
    arguments: impl ExactSizeIterator<Item = E>,
) -> Result<Value<'d>, Error> {
    call_function_in(context, original, arguments, crate::runtime::Native)
}

fn call_function_in<'d, E: Expression, R: crate::runtime::Runtime>(
    context: &context::Evaluation<'_, 'd>,
    original: PrefixedName<'_>,
    arguments: impl ExactSizeIterator<Item = E>,
    runtime: R,
) -> Result<Value<'d>, Error> {
    use crate::runtime::List as _;
    let name = resolve_name_in(context, original, runtime)?;
    let Some(fun) = context.resolve_function(name) else {
        return Err(runtime.name_error(NameKind::Function, original)?);
    };
    let bytes = arguments
        .len()
        .checked_mul(std::mem::size_of::<Value<'_>>())
        .filter(|bytes| isize::try_from(*bytes).is_ok())
        .ok_or_else(|| crate::function::Error::Other {
            what: "XPath argument storage exceeds addressable memory".into(),
        })
        .context(FunctionEvaluation)?;
    if !R::ACCOUNTED {
        context
            .reserve_temporary_allocation(bytes)
            .context(FunctionEvaluation)?;
    }
    let mut args = runtime.list();
    args.reserve(arguments.len()).context(FunctionEvaluation)?;
    for argument in arguments {
        args.push(argument.evaluate(context)?)
            .context(FunctionEvaluation)?;
    }
    runtime
        .invoke(fun, context, args)
        .context(FunctionEvaluation)
}

#[derive(Debug)]
pub struct Literal {
    value: LiteralValue,
}

impl From<LiteralValue> for Literal {
    fn from(other: LiteralValue) -> Literal {
        Literal { value: other }
    }
}

impl Expression for Literal {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        self.value
            .clone_with_context(context)
            .context(FunctionEvaluation)
    }
}

pub struct Math<L = SubExpression, R = L> {
    left: L,
    right: R,
    operation: fn(f64, f64) -> f64,
}

fn add(a: f64, b: f64) -> f64 {
    a + b
}
fn subtract(a: f64, b: f64) -> f64 {
    a - b
}
fn multiply(a: f64, b: f64) -> f64 {
    a * b
}
fn divide(a: f64, b: f64) -> f64 {
    a / b
}
fn modulus(a: f64, b: f64) -> f64 {
    a % b
}

impl Math {
    pub fn addition(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Math {
            left,
            right,
            operation: add,
        })
    }

    pub fn subtraction(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Math {
            left,
            right,
            operation: subtract,
        })
    }

    pub fn multiplication(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Math {
            left,
            right,
            operation: multiply,
        })
    }

    pub fn division(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Math {
            left,
            right,
            operation: divide,
        })
    }

    pub fn remainder(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Math {
            left,
            right,
            operation: modulus,
        })
    }
}

impl<L: Expression, R: Expression> Expression for Math<L, R> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        self.evaluate_in(context, crate::runtime::Native)
    }

    fn ast_depth(&self) -> usize {
        binary_ast_depth(&self.left, &self.right)
    }
}

impl<L: Expression, R: Expression> Math<L, R> {
    fn evaluate_in<'d, S: crate::runtime::Runtime>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        runtime: S,
    ) -> Result<Value<'d>, Error> {
        let left = self.left.evaluate(context)?;
        let right = self.right.evaluate(context)?;
        let op = self.operation;
        let left = left
            .number_in(context, runtime)
            .context(FunctionEvaluation)?;
        let right = right
            .number_in(context, runtime)
            .context(FunctionEvaluation)?;
        Ok(Number(op(left, right)))
    }
}

impl<L: fmt::Debug, R: fmt::Debug> fmt::Debug for Math<L, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Math {{ left: {:?}, right: {:?} }}",
            self.left, self.right
        )
    }
}

#[derive(Debug)]
pub struct Negation<E = SubExpression> {
    pub expression: E,
}

impl<E: Expression> Expression for Negation<E> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        self.evaluate_in(context, crate::runtime::Native)
    }

    fn ast_depth(&self) -> usize {
        1usize.saturating_add(self.expression.ast_depth())
    }
}

impl<E: Expression> Negation<E> {
    fn evaluate_in<'d, R: crate::runtime::Runtime>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        runtime: R,
    ) -> Result<Value<'d>, Error> {
        let value = self.expression.evaluate(context)?;
        value
            .number_in(context, runtime)
            .map(|number| Number(-number))
            .context(FunctionEvaluation)
    }
}

#[derive(Debug)]
pub struct Or<L = SubExpression, R = L> {
    left: L,
    right: R,
}

binary_constructor!(Or);

impl<L: Expression, R: Expression> Expression for Or<L, R> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        let left = self.left.evaluate(context)?.boolean();
        let v = left || self.right.evaluate(context)?.boolean();
        Ok(Boolean(v))
    }

    fn ast_depth(&self) -> usize {
        binary_ast_depth(&self.left, &self.right)
    }
}

#[derive(Debug)]
pub struct Path {
    start_point: SubExpression,
    steps: Vec<Step>,
}

impl Path {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(start_point: SubExpression, steps: Vec<Step>) -> SubExpression {
        Box::new(Path { start_point, steps })
    }
}

impl Expression for Path {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        let result = self.start_point.evaluate(context)?;
        let mut result = value_into_nodeset(result)?;

        for step in &self.steps {
            result = step.evaluate(context, &result)?;
        }

        Ok(Value::Nodeset(result))
    }

    fn ast_depth(&self) -> usize {
        1usize.saturating_add(
            self.start_point.ast_depth().max(
                self.steps
                    .iter()
                    .map(ParameterizedStep::ast_depth)
                    .max()
                    .unwrap_or(0),
            ),
        )
    }
}

#[derive(Debug)]
pub struct Filter<E = SubExpression> {
    node_selector: E,
    predicate: Predicate<E>,
}

impl Filter {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(node_selector: SubExpression, predicate: SubExpression) -> SubExpression {
        let predicate = Predicate {
            expression: predicate,
        };
        Box::new(Filter {
            node_selector,
            predicate,
        })
    }
}

impl<E: Expression> Expression for Filter<E> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        self.node_selector
            .evaluate(context)
            .and_then(|value| value_into_ordered_nodes(context, value))
            .and_then(|nodes| self.predicate.select(context, nodes))
            .map(|nodes| Value::Nodeset(nodes.into()))
    }

    fn ast_depth(&self) -> usize {
        1usize.saturating_add(
            self.node_selector
                .ast_depth()
                .max(self.predicate.expression.ast_depth()),
        )
    }
}

pub struct Relational<L = SubExpression, R = L> {
    pub left: L,
    pub right: R,
    pub operation: fn(f64, f64) -> bool,
}

fn less_than(left: f64, right: f64) -> bool {
    left < right
}
fn less_than_or_equal(left: f64, right: f64) -> bool {
    left <= right
}
fn greater_than(left: f64, right: f64) -> bool {
    left > right
}
fn greater_than_or_equal(left: f64, right: f64) -> bool {
    left >= right
}

impl Relational {
    pub fn less_than(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Relational {
            left,
            right,
            operation: less_than,
        })
    }

    pub fn less_than_or_equal(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Relational {
            left,
            right,
            operation: less_than_or_equal,
        })
    }

    pub fn greater_than(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Relational {
            left,
            right,
            operation: greater_than,
        })
    }

    pub fn greater_than_or_equal(left: SubExpression, right: SubExpression) -> SubExpression {
        Box::new(Relational {
            left,
            right,
            operation: greater_than_or_equal,
        })
    }
}

impl<L: Expression, R: Expression> Expression for Relational<L, R> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        let left_val = self.left.evaluate(context)?;
        let right_val = self.right.evaluate(context)?;
        let op = self.operation;
        let result = compare_relational_values(context, &left_val, &right_val, op)?;
        Ok(Boolean(result))
    }

    fn ast_depth(&self) -> usize {
        binary_ast_depth(&self.left, &self.right)
    }
}

fn compare_relational_values(
    context: &context::Evaluation<'_, '_>,
    left: &Value<'_>,
    right: &Value<'_>,
    operation: fn(f64, f64) -> bool,
) -> Result<bool, Error> {
    compare_relational_values_in(context, left, right, operation, crate::runtime::Native)
}

fn compare_relational_values_in<R: crate::runtime::Runtime>(
    context: &context::Evaluation<'_, '_>,
    left: &Value<'_>,
    right: &Value<'_>,
    operation: fn(f64, f64) -> bool,
    runtime: R,
) -> Result<bool, Error> {
    match (left, right) {
        (Value::Nodeset(left), Value::Nodeset(right)) => {
            if left.size() <= right.size() {
                let left = collect_node_numbers_in(context, left, runtime)?;
                for right in runtime.nodes(right).context(FunctionEvaluation)? {
                    context.charge_work(1).context(FunctionEvaluation)?;
                    let right = runtime
                        .node_number(context, right)
                        .context(FunctionEvaluation)?;
                    for left in left.iter() {
                        context.charge_work(1).context(FunctionEvaluation)?;
                        if operation(*left, right) {
                            return Ok(true);
                        }
                    }
                }
            } else {
                let right = collect_node_numbers_in(context, right, runtime)?;
                for left in runtime.nodes(left).context(FunctionEvaluation)? {
                    context.charge_work(1).context(FunctionEvaluation)?;
                    let left = runtime
                        .node_number(context, left)
                        .context(FunctionEvaluation)?;
                    for right in right.iter() {
                        context.charge_work(1).context(FunctionEvaluation)?;
                        if operation(left, *right) {
                            return Ok(true);
                        }
                    }
                }
            }
            Ok(false)
        }
        (Value::Nodeset(left), right) => {
            let right = right
                .number_in(context, runtime)
                .context(FunctionEvaluation)?;
            for left in runtime.nodes(left).context(FunctionEvaluation)? {
                context.charge_work(1).context(FunctionEvaluation)?;
                let left = runtime
                    .node_number(context, left)
                    .context(FunctionEvaluation)?;
                if operation(left, right) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        (left, Value::Nodeset(right)) => {
            let left = left
                .number_in(context, runtime)
                .context(FunctionEvaluation)?;
            for right in runtime.nodes(right).context(FunctionEvaluation)? {
                context.charge_work(1).context(FunctionEvaluation)?;
                let right = runtime
                    .node_number(context, right)
                    .context(FunctionEvaluation)?;
                if operation(left, right) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        (left, right) => Ok(operation(
            left.number_in(context, runtime)
                .context(FunctionEvaluation)?,
            right
                .number_in(context, runtime)
                .context(FunctionEvaluation)?,
        )),
    }
}

fn collect_node_numbers_in<R: crate::runtime::Runtime>(
    context: &context::Evaluation<'_, '_>,
    nodes: &Nodeset<'_>,
    runtime: R,
) -> Result<R::List<f64>, Error> {
    use crate::runtime::List;
    if nodes.size() > usize::MAX / std::mem::size_of::<f64>() {
        return Err(Error::FunctionEvaluation {
            source: function::Error::Other {
                what: "XPath numeric workspace size overflow".into(),
            },
        });
    }
    if !R::ACCOUNTED {
        context
            .reserve_string_allocation(nodes.size() * std::mem::size_of::<f64>())
            .context(FunctionEvaluation)?;
    }
    let mut values = runtime.list();
    values.reserve(nodes.size()).context(FunctionEvaluation)?;
    for node in runtime.nodes(nodes).context(FunctionEvaluation)? {
        context.charge_work(1).context(FunctionEvaluation)?;
        values
            .push(
                runtime
                    .node_number(context, node)
                    .context(FunctionEvaluation)?,
            )
            .context(FunctionEvaluation)?;
    }
    Ok(values)
}

impl<L: fmt::Debug, R: fmt::Debug> fmt::Debug for Relational<L, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Relational {{ left: {:?}, right: {:?} }}",
            self.left, self.right
        )
    }
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct RootNode;

impl Expression for RootNode {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        Self::evaluate_in(context, crate::runtime::Native)
    }
}

impl RootNode {
    fn evaluate_in<'d, R: crate::runtime::Runtime>(
        context: &context::Evaluation<'_, 'd>,
        runtime: R,
    ) -> Result<Value<'d>, Error> {
        use crate::runtime::Set;
        // XPath 1.0 section 2.1 roots an absolute location path in the document containing
        // the current context node, which an embedding may project into a larger package.
        // https://www.w3.org/TR/1999/REC-xpath-19991116/#location-paths
        let node = runtime
            .clone_node(context, &context.node)
            .context(FunctionEvaluation)?;
        let mut nodes = runtime.set();
        nodes
            .insert(context, context.document_root_for(node))
            .context(FunctionEvaluation)?;
        Ok(Value::Nodeset(nodes.finish()))
    }
}

#[derive(Debug)]
pub(crate) struct Predicate<E = SubExpression> {
    pub expression: E,
}

impl<E: Expression> Predicate<E> {
    fn select<'d>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        nodes: OrderedNodes<'d>,
    ) -> Result<OrderedNodes<'d>, Error> {
        self.select_in::<crate::runtime::Native>(context, Vec::from(nodes))
            .map(OrderedNodes::from)
    }

    fn select_in<'d, R: crate::runtime::Runtime>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        mut nodes: R::List<crate::nodeset::Node<'d>>,
    ) -> Result<R::List<crate::nodeset::Node<'d>>, Error> {
        use crate::runtime::List;
        let size = nodes.len();
        let mut kept = 0;
        for index in 0..size {
            // Move the candidate into its context instead of cloning namespace
            // strings. The root handle only initializes the vacated slot and
            // is never exposed to the expression or returned as a result.
            let vacant = crate::nodeset::Node::Root(nodes[index].document().root());
            let node = std::mem::replace(&mut nodes[index], vacant);
            let mut child = context.new_context_for(node);
            child.position = index + 1;
            child.size = size;
            if self.matches(&child)? {
                nodes[kept] = child.node;
                kept += 1;
            }
        }
        nodes.truncate(kept);
        Ok(nodes)
    }

    fn matches(&self, context: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
        context.charge_work(1).context(FunctionEvaluation)?;
        let value = self.expression.evaluate(context)?;

        let v = match value {
            Number(v) => super::same_xpath_number(super::xpath_size_number(context.position), v),
            _ => value.boolean(),
        };

        Ok(v)
    }
}

pub type Step = ParameterizedStep<Axis>;
pub type StepTest = crate::node_test::SubNodeTest;

#[derive(Debug)]
pub struct ParameterizedStep<A, T = StepTest> {
    axis: A,
    node_test: T,
    predicates: Vec<Predicate>,
}

impl<A, T> ParameterizedStep<A, T>
where
    A: AxisLike,
    T: NodeTest,
{
    // The bounded parser builds the final predicate representation directly, avoiding an
    // overlapping conversion allocation whose capacity would otherwise need a second charge.
    pub(crate) fn from_predicates(axis: A, node_test: T, predicates: Vec<Predicate>) -> Self {
        ParameterizedStep {
            axis,
            node_test,
            predicates,
        }
    }

    fn evaluate<'d>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        starting_nodes: &Nodeset<'d>,
    ) -> Result<Nodeset<'d>, Error> {
        // For every starting node, we collect new nodes based on the
        // axis and node-test. We evaluate the predicates on each node.

        // This seems like a likely place where we could differ from
        // the spec, so thorough testing is key.

        select_step(
            context,
            &self.axis,
            &self.node_test,
            &self.predicates.iter().map(|p| &p.expression),
            starting_nodes,
            crate::runtime::Native,
        )
    }

    pub(super) fn ast_depth(&self) -> usize {
        self.predicates
            .iter()
            .map(|predicate| predicate.expression.ast_depth())
            .max()
            .unwrap_or(0)
    }
}

fn select_step<'d, E: Expression, R: crate::runtime::Runtime>(
    context: &context::Evaluation<'_, 'd>,
    axis: &impl AxisLike,
    test: &impl NodeTest,
    predicates: &(impl Iterator<Item = E> + Clone),
    starting_nodes: &Nodeset<'d>,
    runtime: R,
) -> Result<Nodeset<'d>, Error> {
    use crate::runtime::Set;
    let mut unique = runtime.set();
    for node in runtime.nodes(starting_nodes).context(FunctionEvaluation)? {
        let node = runtime
            .clone_node(context, node)
            .context(FunctionEvaluation)?;
        let child_context = context.new_context_for(node);
        let mut nodes = axis.select_nodes_in(&child_context, test, runtime)?;
        for expression in (*predicates).clone() {
            nodes = Predicate { expression }.select_in::<R>(context, nodes)?;
        }
        // Preserve axis order while moving candidates out of admitted slots.
        for index in 0..nodes.len() {
            let vacant = crate::nodeset::Node::Root(nodes[index].document().root());
            let node = std::mem::replace(&mut nodes[index], vacant);
            unique.insert(context, node).context(FunctionEvaluation)?;
        }
    }
    Ok(unique.finish())
}

#[derive(Debug)]
pub struct Union<L = SubExpression, R = L> {
    pub left: L,
    pub right: R,
}

binary_constructor!(Union);

impl<L: Expression, R: Expression> Expression for Union<L, R> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        self.evaluate_in(context, crate::runtime::Native)
    }

    fn ast_depth(&self) -> usize {
        binary_ast_depth(&self.left, &self.right)
    }
}

impl<L: Expression, R: Expression> Union<L, R> {
    fn evaluate_in<'d, S: crate::runtime::Runtime>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        runtime: S,
    ) -> Result<Value<'d>, Error> {
        use crate::runtime::Set;
        let left = value_into_nodeset(self.left.evaluate(context)?)?;
        let right = value_into_nodeset(self.right.evaluate(context)?)?;
        let mut left = runtime
            .open_set(context, left)
            .context(FunctionEvaluation)?;
        runtime
            .merge(context, &mut left, right)
            .context(FunctionEvaluation)?;
        Ok(Value::Nodeset(left.finish()))
    }
}

fn resolve_prefixed_name<'a>(
    context: &'a context::Evaluation<'_, '_>,
    name: &'a OwnedPrefixedName,
) -> Result<QName<'a>, Error> {
    resolve_name_parts(
        context,
        PrefixedName::with_prefix(name.prefix.as_deref(), &name.local_part),
    )
}

fn resolve_name_parts<'a>(
    context: &'a context::Evaluation<'_, '_>,
    name: PrefixedName<'a>,
) -> Result<QName<'a>, Error> {
    resolve_name_in(context, name, crate::runtime::Native)
}

fn resolve_name_in<'a, R: crate::runtime::Runtime>(
    context: &'a context::Evaluation<'_, '_>,
    name: PrefixedName<'a>,
    runtime: R,
) -> Result<QName<'a>, Error> {
    // What about a "default" namespace?
    let ns_uri = match name.prefix() {
        None => None,
        Some(prefix) => match context.namespace_for(prefix).context(FunctionEvaluation)? {
            None => return Err(runtime.name_error(NameKind::Namespace, PrefixedName::new(prefix))?),
            Some(uri) => Some(uri),
        },
    };

    Ok(QName::with_namespace_uri(ns_uri, name.local_part()))
}

#[derive(Debug)]
pub struct Variable {
    pub name: OwnedPrefixedName,
}

impl Expression for Variable {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        use crate::runtime::Runtime as _;
        let name = resolve_prefixed_name(context, &self.name)?;
        let Some(value) = context.value_of(name) else {
            return Err(crate::runtime::Native.name_error(
                NameKind::Variable,
                PrefixedName::with_prefix(self.name.prefix.as_deref(), &self.name.local_part),
            )?);
        };
        crate::runtime::Native
            .clone_value(context, value)
            .context(FunctionEvaluation)
    }
}

#[cfg(feature = "embedded")]
#[derive(Clone, Copy)]
pub(super) struct ArenaExpression<'p, 's, R: crate::runtime::Runtime> {
    pub program: &'p super::arena::Program<'s>,
    pub handle: super::arena::Handle,
    pub runtime: R,
}

#[cfg(feature = "embedded")]
impl<R: crate::runtime::Runtime> fmt::Debug for ArenaExpression<'_, '_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("XPathEntry")
            .field(&self.handle.index)
            .finish()
    }
}

#[cfg(feature = "embedded")]
impl<R: crate::runtime::Runtime> ArenaExpression<'_, '_, R> {
    fn evaluate_binary<'d>(
        &self,
        context: &context::Evaluation<'_, 'd>,
        operation: super::grammar::Binary,
        left: super::arena::Handle,
        right: super::arena::Handle,
    ) -> Result<Value<'d>, Error> {
        use super::grammar::Binary;
        let child = |handle| ArenaExpression {
            program: self.program,
            handle,
            runtime: self.runtime,
        };
        let left = child(left);
        let right = child(right);
        match operation {
            Binary::Or => Or { left, right }.evaluate(context),
            Binary::And => And { left, right }.evaluate(context),
            Binary::Equal | Binary::NotEqual => {
                let comparison = if operation == Binary::Equal {
                    Equality::Equal
                } else {
                    Equality::NotEqual
                };
                let left = left.evaluate(context)?;
                let right = right.evaluate(context)?;
                compare_equality_values_in(context, &left, &right, comparison, self.runtime)
                    .map(Boolean)
            }
            Binary::Union => Union { left, right }.evaluate_in(context, self.runtime),
            Binary::Add
            | Binary::Subtract
            | Binary::Multiply
            | Binary::Divide
            | Binary::Remainder => {
                let operation = match operation {
                    Binary::Add => add,
                    Binary::Subtract => subtract,
                    Binary::Multiply => multiply,
                    Binary::Divide => divide,
                    Binary::Remainder => modulus,
                    _ => unreachable!("arithmetic operators are selected above"),
                };
                Math {
                    left,
                    right,
                    operation,
                }
                .evaluate_in(context, self.runtime)
            }
            Binary::Less | Binary::LessEqual | Binary::Greater | Binary::GreaterEqual => {
                let operation = match operation {
                    Binary::Less => less_than,
                    Binary::LessEqual => less_than_or_equal,
                    Binary::Greater => greater_than,
                    Binary::GreaterEqual => greater_than_or_equal,
                    _ => unreachable!("relational operators are selected above"),
                };
                let left = left.evaluate(context)?;
                let right = right.evaluate(context)?;
                compare_relational_values_in(context, &left, &right, operation, self.runtime)
                    .map(Boolean)
            }
        }
    }
}

#[cfg(feature = "embedded")]
impl<R: crate::runtime::Runtime> Expression for ArenaExpression<'_, '_, R> {
    fn evaluate<'d>(&self, context: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
        use super::arena::Entry;
        context.admit_expression_step()?;
        let child = |handle| ArenaExpression {
            program: self.program,
            handle,
            runtime: self.runtime,
        };
        match &self.program.nodes[self.handle.index] {
            Entry::Context => ContextNode::evaluate_in(context, self.runtime),
            Entry::Root => RootNode::evaluate_in(context, self.runtime),
            Entry::Number(number) => Ok(Number(*number)),
            Entry::String(text) => self
                .runtime
                .literal(context, text)
                .context(FunctionEvaluation),
            Entry::Variable(original) => {
                let name = resolve_name_in(context, *original, self.runtime)?;
                let Some(value) = context.value_of(name) else {
                    return Err(self.runtime.name_error(NameKind::Variable, *original)?);
                };
                self.runtime
                    .clone_value(context, value)
                    .context(FunctionEvaluation)
            }
            Entry::Function(name, arguments) => call_function_in(
                context,
                *name,
                arguments.iter().copied().map(child),
                self.runtime,
            ),
            Entry::Negate(value) => Negation {
                expression: child(*value),
            }
            .evaluate_in(context, self.runtime),
            Entry::Filter(selector, predicate) => {
                use crate::runtime::List;
                use crate::runtime::Set;
                let source = value_into_nodeset(child(*selector).evaluate(context)?)?;
                let ordered = source
                    .document_order_in(context, self.runtime)
                    .context(FunctionEvaluation)?;
                let mut selected = Predicate {
                    expression: child(*predicate),
                }
                .select_in::<R>(context, ordered)?;
                let mut nodes = self.runtime.set();
                for index in 0..selected.len() {
                    let vacant = crate::nodeset::Node::Root(selected[index].document().root());
                    let node = std::mem::replace(&mut selected[index], vacant);
                    nodes.insert(context, node).context(FunctionEvaluation)?;
                }
                selected.truncate(0);
                Ok(Value::Nodeset(nodes.finish()))
            }
            Entry::Path(start, steps) => {
                let mut nodes = value_into_nodeset(child(*start).evaluate(context)?)?;
                for step in &**steps {
                    let test = crate::node_test::SubNodeTest::from(step.test);
                    nodes = select_step(
                        context,
                        &step.axis,
                        &test,
                        &step.predicates.iter().copied().map(child),
                        &nodes,
                        self.runtime,
                    )?;
                }
                Ok(Value::Nodeset(nodes))
            }
            Entry::Binary(operation, left, right) => {
                self.evaluate_binary(context, *operation, *left, *right)
            }
        }
    }

    fn ast_depth(&self) -> usize {
        self.handle.depth
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "embedded")]
    #[test]
    fn current_predicate_compacts_original_slots_without_a_second_allocation() {
        // Predicate positions/size use the original axis list; accepted nodes
        // stay in that allocation, including its retained spare capacity.
        use crate::runtime::{List, Runtime};
        use structured_asn1::memory::{Memory, MemoryAccount};
        #[derive(Debug)]
        struct Third;
        impl Expression for Third {
            fn evaluate<'d>(
                &self,
                context: &context::Evaluation<'_, 'd>,
            ) -> Result<Value<'d>, Error> {
                assert_eq!(context.size, 3);
                Ok(Number(3.0))
            }
        }
        let package = Package::new();
        let document = package.as_document();
        let nodes = [
            document.create_element("one"),
            document.create_element("two"),
            document.create_element("three"),
        ];
        let current = Memory::new(std::sync::Arc::new(MemoryAccount::new(65536, 65536)));
        let failure = std::cell::Cell::new(None);
        let runtime = crate::runtime::Accounted {
            work: &current,
            failure: &failure,
        };
        let context = Context::new();
        let evaluation = context::Evaluation::new(&context, document.root().into());
        let mut candidates = runtime.list();
        for node in nodes {
            runtime
                .push(&evaluation, &mut candidates, node.into())
                .expect("candidate slot");
        }
        let pointer = candidates.as_ptr();
        let capacity = candidates.capacity();
        let used = current.used();
        let selected = Predicate { expression: Third }
            .select_in::<crate::runtime::Accounted<'_, Memory>>(&evaluation, candidates)
            .expect("third predicate position");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], crate::nodeset::Node::Element(nodes[2]));
        assert_eq!(selected.as_ptr(), pointer);
        assert_eq!(selected.capacity(), capacity);
        assert_eq!(current.used(), used);
        assert_eq!(failure.get(), None);
        drop(selected);
        assert_eq!(current.used(), 0);
    }
    #[cfg(feature = "embedded")]
    #[test]
    fn numeric_workspace_refuses_current_capacity_before_conversion() {
        // A retained node-set must not finance a later comparison's workspace.
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let current = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 4096)));
        let failure = std::cell::Cell::new(None);
        let package = Package::new();
        let document = package.as_document();
        let element = document.create_element("n");
        element.append_child(document.create_text("12"));
        let mut nodes = crate::nodeset::Nodeset::new();
        nodes.add(element);
        let context = crate::Context::new();
        let evaluation = crate::context::Evaluation::new(&context, element.into());
        let result = super::collect_node_numbers_in(
            &evaluation,
            &nodes,
            crate::runtime::Accounted {
                work: &current,
                failure: &failure,
            },
        );
        assert!(result.is_err());
        assert_eq!(failure.get(), Some(MemoryError::LimitExceeded));
        assert_eq!(current.used(), 0);
    }

    #[cfg(feature = "embedded")]
    #[test]
    fn nodeset_comparison_text_uses_current_owner_and_preserves_existential_inequality() {
        // Equal and not-equal are independent existential comparisons in
        // XPath 1.0 §3.4, not complements for node-sets containing distinct values.
        // https://www.w3.org/TR/1999/REC-xpath-19991116/#booleans
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let package = Package::new();
        let document = package.as_document();
        let first = document.create_element("n");
        first.append_child(document.create_text("same"));
        let second = document.create_element("n");
        second.append_child(document.create_text("other"));
        let mut left = crate::nodeset::Nodeset::new();
        left.add(first);
        let mut right = crate::nodeset::Nodeset::new();
        right.add(first);
        right.add(second);
        let left = Value::Nodeset(left);
        let right = Value::Nodeset(right);
        let context = crate::Context::new();
        let evaluation = crate::context::Evaluation::new(&context, first.into());
        for bytes in [0, 65536] {
            for comparison in [super::Equality::Equal, super::Equality::NotEqual] {
                let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(bytes, 65536)));
                let failure = std::cell::Cell::new(None);
                let result = super::compare_equality_values_in(
                    &evaluation,
                    &left,
                    &right,
                    comparison,
                    crate::runtime::Accounted {
                        work: &work,
                        failure: &failure,
                    },
                );
                if bytes == 0 {
                    assert!(result.is_err());
                    assert_eq!(failure.get(), Some(MemoryError::LimitExceeded));
                } else {
                    assert_eq!(result, Ok(true));
                    assert_eq!(failure.get(), None);
                }
                assert_eq!(work.used(), 0);
            }
        }
    }
    use std::borrow::ToOwned;
    use std::cell::RefCell;
    use std::rc::Rc;

    use sxd_document_no_unsafe::Package;
    use sxd_document_no_unsafe::dom::Document;

    use super::*;
    use crate::Value::{self, Boolean, Number, String};
    use crate::axis::AxisLike;
    use crate::context::{self, Context};
    use crate::function;
    use crate::node_test::NodeTest;

    #[test]
    fn evaluator_containers_reserve_before_materialization() {
        // Both a root singleton and an argument vector allocate before any result
        // escapes; even an eventual arity error must not bypass the allocation gate.
        for source in ["/", "count(0,0,0,0,0,0,0,0)"] {
            let package = Package::new();
            let mut context = Context::new();
            context.set_string_allocation_limit(0);
            let expression = crate::Factory::new().build(source).expect("valid syntax");
            let error = expression
                .evaluate(&context, package.as_document().root())
                .expect_err("container requires storage");
            assert!(
                error.to_string().contains("allocation budget"),
                "{source}: {error}"
            );
        }
    }

    #[test]
    fn fragment_equality_reserves_lexical_work() {
        // Arc-backed values clone without scanning; comparison must charge its own bytes.
        let package = Package::new();
        let mut context = Context::new();
        context.set_variable(
            "left",
            Value::ResultTreeFragment(1, std::sync::Arc::new("x".repeat(4096))),
        );
        context.set_variable(
            "right",
            Value::ResultTreeFragment(2, std::sync::Arc::new("x".repeat(4096))),
        );
        context.set_evaluation_work_limit(0);
        let expression = crate::Factory::new()
            .build("$left = $right")
            .expect("valid equality");
        let error = expression
            .evaluate(&context, package.as_document().root())
            .expect_err("comparison needs work");
        assert!(error.to_string().contains("budget"));

        // Unequal lengths decide equality without traversing either string.
        let mut context = Context::new();
        context.set_evaluation_work_limit(0);
        let evaluation = context::Evaluation::new(&context, package.as_document().root().into());
        assert!(
            !Equality::Equal
                .strings(&evaluation, "x", "longer")
                .expect("length gate")
        );
        assert!(
            Equality::NotEqual
                .strings(&evaluation, "x", "longer")
                .expect("length gate")
        );
    }

    #[test]
    fn union_reserves_growth_before_combining_variables() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let left = setup.doc.create_element("left");
        let right = setup.doc.create_element("right");
        setup.context.set_variable("left", crate::nodeset![left]);
        setup.context.set_variable("right", crate::nodeset![right]);
        setup.context.set_string_allocation_limit(0);
        let expression = Union::new(
            Box::new(Variable {
                name: "left".into(),
            }),
            Box::new(Variable {
                name: "right".into(),
            }),
        );

        assert!(matches!(
            expression.evaluate(&setup.context()),
            Err(Error::FunctionEvaluation { .. })
        ));
    }

    #[test]
    fn nodeset_equality_charges_each_candidate_comparison() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let left = setup.doc.create_text("");
        let right = setup.doc.create_text("different");
        setup.context.set_variable("left", crate::nodeset![left]);
        setup.context.set_variable("right", crate::nodeset![right]);
        setup.context.set_evaluation_work_limit(0);
        let expression = Equal::new(
            Box::new(Variable {
                name: "left".into(),
            }),
            Box::new(Variable {
                name: "right".into(),
            }),
        );

        assert!(matches!(
            expression.evaluate(&setup.context()),
            Err(Error::FunctionEvaluation { .. })
        ));
    }

    #[test]
    fn numeric_nodeset_conversions_consume_evaluation_work() {
        // Numeric comparison materializes each candidate's XPath string-value and must therefore
        // cross the same work gate as string comparisons.
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let value = setup.doc.create_text("");
        setup.context.set_variable("value", crate::nodeset![value]);
        setup.context.set_variable("empty", crate::nodeset![]);
        setup.context.set_evaluation_work_limit(0);

        let equality = Equal::new(
            Box::new(Variable {
                name: "value".into(),
            }),
            Box::new(Literal {
                value: Value::Number(1.0),
            }),
        );
        let relational = Relational::less_than(
            Box::new(Variable {
                name: "value".into(),
            }),
            Box::new(Variable {
                name: "empty".into(),
            }),
        );

        for expression in [equality, relational] {
            assert!(matches!(
                expression.evaluate(&setup.context()),
                Err(Error::FunctionEvaluation { .. })
            ));
        }
    }

    #[derive(Debug)]
    struct FailExpression;
    impl Expression for FailExpression {
        fn evaluate<'d>(&self, _: &context::Evaluation<'_, 'd>) -> Result<Value<'d>, Error> {
            panic!("Should never be called");
        }
    }

    struct Setup<'d> {
        doc: Document<'d>,
        context: Context<'d>,
    }

    impl<'d> Setup<'d> {
        fn new(package: &'d Package) -> Setup<'d> {
            Setup {
                doc: package.as_document(),
                context: Context::without_core_functions(),
            }
        }

        fn context(&self) -> context::Evaluation<'_, 'd> {
            let node = self.doc.create_element("test");
            context::Evaluation::new(&self.context, node.into())
        }
    }

    #[test]
    fn expression_and_returns_logical_and() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let left = Box::new(Literal {
            value: Value::Boolean(true),
        });
        let right = Box::new(Literal {
            value: Value::Boolean(true),
        });

        let expr = And { left, right };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(true)));
    }

    #[test]
    fn expression_and_short_circuits_when_left_argument_is_false() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let left = Box::new(Literal {
            value: Value::Boolean(false),
        });
        let right = Box::new(FailExpression);

        let expr = And { left, right };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(false)));
    }

    #[test]
    fn expression_equal_intersects_string_values_of_two_nodesets() {
        let package = Package::new();
        let mut setup = Setup::new(&package);

        let string_value_1 = setup.doc.create_text("same");
        let string_value_2 = setup.doc.create_text("same");

        setup.context.set_variable("left", nodeset![string_value_1]);
        setup
            .context
            .set_variable("right", nodeset![string_value_2]);

        let left = Box::new(Variable {
            name: "left".into(),
        });
        let right = Box::new(Variable {
            name: "right".into(),
        });

        let expr = Equal { left, right };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(true)));
    }

    #[test]
    fn expression_equal_compares_number_value_of_nodeset_to_number() {
        let package = Package::new();
        let mut setup = Setup::new(&package);

        let string_value = setup.doc.create_text("3.14");
        setup.context.set_variable("left", nodeset![string_value]);

        let left = Box::new(Variable {
            name: "left".into(),
        });
        let right = Box::new(Literal {
            value: Value::Number(6.3),
        });

        let expr = Equal { left, right };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(false)));
    }

    #[test]
    fn expression_equal_compares_string_value_of_nodeset_to_string() {
        let package = Package::new();
        let mut setup = Setup::new(&package);

        let string_value_1 = setup.doc.create_text("gravy");
        let string_value_2 = setup.doc.create_text("boat");
        setup
            .context
            .set_variable("left", nodeset![string_value_1, string_value_2]);

        let left = Box::new(Variable {
            name: "left".into(),
        });
        let right = Box::new(Literal {
            value: Value::String("boat".to_owned()),
        });

        let expr = Equal { left, right };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(true)));
    }

    #[test]
    fn expression_equality_reserves_node_string_values_before_allocation() {
        let package = Package::new();
        let document = package.as_document();
        let left_value = document.create_text("four");
        let right_value = document.create_text("four");

        let expression = Equal {
            left: Box::new(Variable {
                name: "left".into(),
            }),
            right: Box::new(Variable {
                name: "right".into(),
            }),
        };

        let mut insufficient = Context::without_core_functions();
        insufficient.set_variable("left", nodeset![left_value.clone()]);
        insufficient.set_variable("right", nodeset![right_value.clone()]);
        // Each variable owns a copied one-node SwissTable before comparison starts.
        let variable_storage = 2
            * crate::nodeset::hashset_growth_bytes::<crate::nodeset::Node<'_>>(0)
                .expect("one-node set storage is representable");
        insufficient.set_string_allocation_limit(variable_storage + 3);
        let context_node = document.create_element("test");
        let evaluation = context::Evaluation::new(&insufficient, context_node.clone().into());
        assert!(matches!(
            expression.evaluate(&evaluation),
            Err(Error::FunctionEvaluation { source: function::Error::Other { what } })
                if what.contains("allocation budget")
        ));

        let mut exact = Context::without_core_functions();
        exact.set_variable("left", nodeset![left_value]);
        exact.set_variable("right", nodeset![right_value]);
        exact.set_string_allocation_limit(variable_storage + 4);
        let evaluation = context::Evaluation::new(&exact, context_node.into());
        assert_eq!(expression.evaluate(&evaluation), Ok(Boolean(true)));
    }

    #[test]
    fn arithmetic_and_relational_expressions_bound_node_numeric_conversion() {
        // Arithmetic and relational operators share XPath's node-set-to-number conversion. Its
        // temporary string must be charged even though both operator results are scalar.
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let value = setup.doc.create_text("1234");
        setup.context.set_variable("value", nodeset![value]);
        setup.context.set_string_allocation_limit(3);

        let variable = || {
            Box::new(Variable {
                name: "value".into(),
            }) as SubExpression
        };
        let literal = || {
            Box::new(Literal {
                value: Value::Number(0.0),
            }) as SubExpression
        };
        let expressions: [SubExpression; 2] = [
            Math::addition(variable(), literal()),
            Relational::greater_than(variable(), literal()),
        ];
        for expression in expressions {
            let error = expression
                .evaluate(&setup.context())
                .expect_err("numeric conversion must cross the string allocation gate");
            assert!(matches!(
                error,
                Error::FunctionEvaluation {
                    source: function::Error::Other { what }
                } if what.contains("allocation budget")
            ));
        }
    }

    #[test]
    fn result_tree_fragment_equality_checks_every_nodeset_value_symmetrically() {
        let package = Package::new();
        let setup = Setup::new(&package);
        let first = setup.doc.create_text("first");
        let matching = setup.doc.create_text("matching");
        let nodes = Value::Nodeset(nodeset![first, matching]);
        let fragment = Value::ResultTreeFragment(1, std::sync::Arc::new("matching".into()));
        let context = setup.context();
        assert_eq!(
            compare_equality_values(&context, &nodes, &fragment, Equality::Equal),
            Ok(true)
        );
        assert_eq!(
            compare_equality_values(&context, &fragment, &nodes, Equality::Equal),
            Ok(true)
        );
    }

    #[test]
    fn expression_equal_compares_as_boolean_if_one_argument_is_a_boolean() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let actual_bool = Box::new(Literal {
            value: Value::Boolean(false),
        });
        let truthy_str = Box::new(Literal {
            value: Value::String("hello".to_owned()),
        });

        let expr = Equal {
            left: actual_bool,
            right: truthy_str,
        };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(false)));
    }

    #[test]
    fn expression_equal_compares_as_number_if_one_argument_is_a_number() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let actual_number = Box::new(Literal {
            value: Value::Number(-42.0),
        });
        let number_str = Box::new(Literal {
            value: Value::String("-42.0".to_owned()),
        });

        let expr = Equal {
            left: number_str,
            right: actual_number,
        };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(true)));
    }

    #[test]
    fn expression_equal_compares_as_string_otherwise() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let a_str = Box::new(Literal {
            value: Value::String("hello".to_owned()),
        });
        let b_str = Box::new(Literal {
            value: Value::String("World".to_owned()),
        });

        let expr = Equal {
            left: a_str,
            right: b_str,
        };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(false)));
    }

    #[test]
    fn expression_not_equal_negates_equality() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let a_str = Box::new(Literal {
            value: Value::Boolean(true),
        });
        let b_str = Box::new(Literal {
            value: Value::Boolean(false),
        });

        let expr = NotEqual::new(a_str, b_str);

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(true)));
    }

    #[test]
    fn expression_not_equal_requires_a_node_for_nodeset_comparisons() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        setup.context.set_variable("empty", nodeset![]);

        let expr = NotEqual::new(
            Box::new(Variable {
                name: "empty".into(),
            }),
            Box::new(Literal {
                value: Value::String(std::string::String::new()),
            }),
        );

        assert_eq!(expr.evaluate(&setup.context()), Ok(Boolean(false)));
    }

    #[test]
    fn expression_not_equal_uses_existential_nodeset_semantics() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        let same = setup.doc.create_text("same");
        let different = setup.doc.create_text("different");
        setup
            .context
            .set_variable("values", nodeset![same, different]);

        let expr = NotEqual::new(
            Box::new(Variable {
                name: "values".into(),
            }),
            Box::new(Literal {
                value: Value::String("same".to_owned()),
            }),
        );

        assert_eq!(expr.evaluate(&setup.context()), Ok(Boolean(true)));
    }

    struct StubFunction {
        value: &'static str,
    }

    impl function::Function for StubFunction {
        fn evaluate<'d>(
            &self,
            _: &context::Evaluation<'_, 'd>,
            _: Vec<Value<'d>>,
        ) -> Result<Value<'d>, function::Error> {
            Ok(String(self.value.to_owned()))
        }
    }

    #[test]
    fn expression_function_evaluates_input_arguments() {
        let package = Package::new();
        let mut setup = Setup::new(&package);

        let arg_expr: Box<dyn Expression> = Box::new(Literal {
            value: Value::Boolean(true),
        });
        setup.context.set_function(
            "test-fn",
            StubFunction {
                value: "the function ran",
            },
        );

        let expr = Function {
            name: "test-fn".into(),
            arguments: vec![arg_expr],
        };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(String("the function ran".to_owned())));
    }

    #[test]
    fn expression_function_unknown_function_is_reported_as_an_error() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let expr = Function {
            name: "unknown-fn".into(),
            arguments: vec![],
        };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, UnknownFunction { name: "unknown-fn" }.fail());
    }

    #[test]
    fn expression_math_does_basic_math() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let left = Box::new(Literal {
            value: Value::Number(10.0),
        });
        let right = Box::new(Literal {
            value: Value::Number(5.0),
        });

        let expr = Math::multiplication(left, right);

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Number(50.0)));
    }

    #[test]
    fn filter_with_numeric_predicate_selects_that_node() {
        let package = Package::new();
        let mut setup = Setup::new(&package);

        let input_node_1 = setup.doc.create_element("one");
        let input_node_2 = setup.doc.create_element("two");
        let input_nodeset = nodeset![input_node_1, input_node_2];

        setup.context.set_variable("nodes", input_nodeset);

        // We need to give these elements some kind of document order
        let parent = setup.doc.create_element("parent");
        setup.doc.root().append_child(parent);
        parent.append_child(input_node_1);
        parent.append_child(input_node_2);

        let selected_nodes = Box::new(Variable {
            name: "nodes".into(),
        });
        let predicate = Box::new(Literal {
            value: Value::Number(1.0),
        });

        let expr = Filter::new(selected_nodes, predicate);

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Value::Nodeset(nodeset![input_node_1])));
    }

    #[test]
    fn filter_with_false_predicate_selects_no_nodes() {
        let package = Package::new();
        let mut setup = Setup::new(&package);

        let input_node_1 = setup.doc.create_element("one");
        let input_node_2 = setup.doc.create_element("two");
        let input_nodeset = nodeset![input_node_1, input_node_2];

        setup.context.set_variable("nodes", input_nodeset);

        let selected_nodes = Box::new(Variable {
            name: "nodes".into(),
        });
        let predicate = Box::new(Literal {
            value: Value::Boolean(false),
        });

        let expr = Filter::new(selected_nodes, predicate);

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Value::Nodeset(nodeset![])));
    }

    #[test]
    fn expression_relational_does_basic_comparisons() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let left = Box::new(Literal {
            value: Value::Number(10.0),
        });
        let right = Box::new(Literal {
            value: Value::Number(5.0),
        });

        let expr = Relational::less_than(left, right);

        let context = setup.context();
        let res = expr.evaluate(&context);
        assert_eq!(res, Ok(Boolean(false)));
    }

    #[test]
    fn expression_root_node_finds_the_root() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let expr = RootNode;

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Value::Nodeset(nodeset![setup.doc.root()])));
    }

    #[derive(Debug, Clone)]
    struct MockAxis {
        calls: Rc<RefCell<usize>>,
    }

    impl MockAxis {
        fn new() -> MockAxis {
            MockAxis {
                calls: Rc::new(RefCell::new(0)),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.borrow()
        }
    }

    impl AxisLike for MockAxis {
        fn select_nodes_in<'d, R: crate::runtime::Runtime>(
            &self,
            _context: &context::Evaluation<'_, 'd>,
            _node_test: &dyn NodeTest,
            runtime: R,
        ) -> Result<R::List<crate::nodeset::Node<'d>>, Error> {
            *self.calls.borrow_mut() += 1;
            Ok(runtime.list())
        }
    }

    #[derive(Debug)]
    struct DummyNodeTest;
    impl NodeTest for DummyNodeTest {
        fn matches(&self, _: &context::Evaluation<'_, '_>) -> Result<bool, Error> {
            Ok(false)
        }
    }

    #[test]
    fn step_delegates_to_the_axis() {
        let package = Package::new();
        let setup = Setup::new(&package);

        let axis = MockAxis::new();
        let node_test = DummyNodeTest;

        let expr = ParameterizedStep::from_predicates(axis.clone(), Box::new(node_test), vec![]);

        let context = setup.context();
        expr.evaluate(&context, &nodeset![context.node.clone()])
            .unwrap();

        assert_eq!(1, axis.calls());
    }

    #[test]
    fn expression_union_combines_nodesets() {
        let package = Package::new();
        let mut setup = Setup::new(&package);

        let left_node = setup.doc.create_element("left");
        let nodes = nodeset![left_node];
        setup.context.set_variable("left", nodes);
        let left = Box::new(Variable {
            name: "left".into(),
        });

        let right_node = setup.doc.create_element("right");
        let nodes = nodeset![right_node];
        setup.context.set_variable("right", nodes);
        let right = Box::new(Variable {
            name: "right".into(),
        });

        let expr = Union { left, right };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Value::Nodeset(nodeset![left_node, right_node])));
    }

    #[test]
    fn expression_variable_looks_up_the_variable() {
        let package = Package::new();
        let mut setup = Setup::new(&package);
        setup.context.set_variable("foo", true);

        let expr = Variable { name: "foo".into() };

        let context = setup.context();
        let res = expr.evaluate(&context);

        assert_eq!(res, Ok(Boolean(true)));
    }
}
