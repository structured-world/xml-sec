//! Support for the various types of contexts before and during XPath
//! evaluation.

use sxd_document_no_unsafe::QName;

use std::cell::Cell;
use std::collections::HashMap;
use std::iter;

use crate::function;
use crate::nodeset::{Node, OrderedNodes};
use crate::{OwnedQName, Value};

/// A mapping of names to XPath functions.
type Functions = HashMap<OwnedQName, Box<dyn function::Function + 'static>>;
/// A mapping of names to XPath variables.
type Variables<'d> = HashMap<OwnedQName, Value<'d>>;
/// A mapping of namespace prefixes to namespace URIs.
type Namespaces = HashMap<String, String>;

/// Contains the context in which XPath expressions are executed. The
/// context contains functions, variables, and namespace mappings.
///
/// ### Examples
///
/// A complete example showing all optional settings.
///
/// ```
/// use std::collections::HashMap;
/// use sxd_document_no_unsafe::parser;
/// use sxd_xpath_no_unsafe::{Factory, Context, Value};
/// use sxd_xpath_no_unsafe::{context, function};
///
/// struct Sigmoid;
/// impl function::Function for Sigmoid {
///     fn evaluate<'c, 'd>(&self,
///                         context: &context::Evaluation<'c, 'd>,
///                         args: Vec<Value<'d>>)
///                         -> Result<Value<'d>, function::Error>
///     {
///         let mut args = function::Args(args);
///         args.exactly(1)?;
///         let val = args.pop_number(context)?;
///
///         let computed = (1.0 + (-val).exp()).recip();
///
///         Ok(Value::Number(computed))
///     }
/// }
///
/// let package = parser::parse("<thing xmlns:ns0='net:brain' ns0:bonus='1' />")
///     .expect("failed to parse XML");
/// let document = package.as_document();
/// let node = document.root().children()[0];
///
/// let mut context = Context::new();
/// context.set_function("sigmoid", Sigmoid);
/// context.set_variable("t", 2.0);
/// context.set_namespace("neural", "net:brain");
///
/// let xpath = "sigmoid(@neural:bonus + $t)";
///
/// let factory = Factory::new();
/// let xpath = factory.build(xpath).expect("Could not compile XPath");
///
/// let value = xpath.evaluate(&context, node).expect("XPath evaluation failed");
/// let evaluation = context::Evaluation::new(&context, node.into());
///
/// let number = value.number(&evaluation).expect("numeric conversion failed");
/// assert_eq!(0.952, (number * 1000.0).trunc() / 1000.0);
/// ```
///
/// Note that we are using a custom function (`sigmoid`), a variable
/// (`$t`), and a namespace (`neural:`). The current node is passed to
/// the `evaluate` method and is not the root of the tree but the
/// top-most element.
///
pub struct Context<'d> {
    functions: Functions,
    variables: Variables<'d>,
    namespaces: Namespaces,
    string_allocations: StringAllocationBudget,
    document_root_resolver: Option<fn(Node<'d>) -> Node<'d>>,
}

#[derive(Default)]
struct StringAllocationBudget {
    limit: Option<usize>,
    used: Cell<usize>,
    exceeded: Cell<Option<usize>>,
}

impl<'d> Context<'d> {
    /// Registers the core XPath 1.0 functions.
    pub fn new() -> Self {
        let mut context = Self::without_core_functions();
        function::register_core_functions(&mut context);
        context
    }

    /// No functions, variables or namespaces will be defined.
    pub fn without_core_functions() -> Self {
        Context {
            functions: Default::default(),
            variables: Default::default(),
            namespaces: Default::default(),
            string_allocations: StringAllocationBudget::default(),
            document_root_resolver: None,
        }
    }

    /// Limit cumulative core-function string allocations on this context.
    ///
    /// The counter and the first exceeded total persist across evaluations that reuse this
    /// context. Calling this method sets a new limit and resets both values, allowing an embedding
    /// runtime to establish a fresh operation budget explicitly.
    pub fn set_string_allocation_limit(&mut self, limit: usize) {
        self.string_allocations.limit = Some(limit);
        self.string_allocations.used.set(0);
        self.string_allocations.exceeded.set(None);
    }

    /// Override how the root of the document containing a context node is resolved.
    pub fn set_document_root_resolver(&mut self, resolver: fn(Node<'d>) -> Node<'d>) {
        self.document_root_resolver = Some(resolver);
    }

    /// Return the first attempted total that exceeded the current context-scoped limit.
    pub fn string_allocation_exceeded(&self) -> Option<usize> {
        self.string_allocations.exceeded.get()
    }

    /// Reserve bytes in the context-scoped temporary allocation budget.
    pub fn reserve_temporary_allocation(&self, bytes: usize) -> Result<(), function::Error> {
        reserve_allocation(&self.string_allocations, bytes)
    }

    /// Register a function within the context
    pub fn set_function<N, F>(&mut self, name: N, function: F)
    where
        N: Into<OwnedQName>,
        F: function::Function + 'static,
    {
        self.functions.insert(name.into(), Box::new(function));
    }

    /// Register a variable within the context
    pub fn set_variable<N, V>(&mut self, name: N, value: V)
    where
        N: Into<OwnedQName>,
        V: Into<Value<'d>>,
    {
        self.variables.insert(name.into(), value.into());
    }

    /// Register a namespace prefix within the context
    pub fn set_namespace(&mut self, prefix: &str, uri: &str) {
        self.namespaces.insert(prefix.into(), uri.into());
    }
}

impl<'d> Default for Context<'d> {
    fn default() -> Self {
        Context::new()
    }
}

/// The context during evaluation of an XPath expression.
///
/// Clients of this library will use this when implementing custom
/// functions.
///
/// # Lifetimes
///
/// We track two separate lifetimes: that of the user-provided context
/// (`'c`) and that of the document (`'d`). This allows the
/// user-provided context to live shorter than the document.
#[derive(Clone)]
pub struct Evaluation<'c, 'd> {
    /// The context node
    pub node: Node<'d>,
    /// The context position
    pub position: usize,
    /// The context size
    pub size: usize,
    functions: &'c Functions,
    variables: &'c Variables<'d>,
    namespaces: &'c Namespaces,
    string_allocations: &'c StringAllocationBudget,
    document_root_resolver: Option<fn(Node<'d>) -> Node<'d>>,
}

#[cfg(not(feature = "no-unsafe"))]
impl<'c, 'd> Copy for Evaluation<'c, 'd> {}

impl<'c, 'd> Evaluation<'c, 'd> {
    /// Prepares the context used while evaluating the XPath expression
    pub fn new(context: &'c Context<'d>, node: Node<'d>) -> Evaluation<'c, 'd> {
        Evaluation {
            node,
            functions: &context.functions,
            variables: &context.variables,
            namespaces: &context.namespaces,
            string_allocations: &context.string_allocations,
            document_root_resolver: context.document_root_resolver,
            position: 1,
            size: 1,
        }
    }

    /// Creates a new context node using the provided node
    pub fn new_context_for<N>(&self, node: N) -> Evaluation<'c, 'd>
    where
        N: Into<Node<'d>>,
    {
        Evaluation {
            node: node.into(),
            ..*self
        }
    }

    /// Looks up the function with the given name
    pub fn function_for_name(&self, name: QName<'_>) -> Option<&'c dyn function::Function> {
        // FIXME: remove allocation
        let name = name.into();
        self.functions.get(&name).map(AsRef::as_ref)
    }

    /// Looks up the value of the variable
    pub fn value_of(&self, name: QName<'_>) -> Option<&Value<'d>> {
        // FIXME: remove allocation
        let name = name.into();
        self.variables.get(&name)
    }

    /// Looks up the namespace URI for the given prefix
    pub fn namespace_for(&self, prefix: &str) -> Option<&str> {
        self.namespaces.get(prefix).map(String::as_str)
    }

    pub(crate) fn document_root_for(&self, node: Node<'d>) -> Node<'d> {
        if let Some(resolver) = self.document_root_resolver {
            resolver(node)
        } else {
            node.document().root().into()
        }
    }

    /// Reserve bytes before an extension function allocates an XPath string result.
    pub fn reserve_string_allocation(&self, bytes: usize) -> Result<(), function::Error> {
        self.reserve_temporary_allocation(bytes)
    }

    /// Reserve bytes in the context-scoped temporary allocation budget.
    pub fn reserve_temporary_allocation(&self, bytes: usize) -> Result<(), function::Error> {
        reserve_allocation(self.string_allocations, bytes)
    }

    /// Yields a new `Evaluation` context for each node in the nodeset.
    pub fn new_contexts_for(self, nodes: OrderedNodes<'d>) -> EvaluationNodesetIter<'c, 'd> {
        let sz = nodes.size();
        EvaluationNodesetIter {
            parent: self,
            nodes: Vec::from(nodes).into_iter().enumerate(),
            size: sz,
        }
    }
}

fn reserve_allocation(
    budget: &StringAllocationBudget,
    bytes: usize,
) -> Result<(), function::Error> {
    let actual = budget.used.get().saturating_add(bytes);
    if budget.limit.is_some_and(|limit| actual > limit) {
        budget.exceeded.set(Some(actual));
        return Err(function::Error::Other {
            what: "XPath string allocation budget exceeded".into(),
        });
    }
    budget.used.set(actual);
    Ok(())
}

/// An iterator for the contexts of each node in a nodeset
pub struct EvaluationNodesetIter<'c, 'd> {
    parent: Evaluation<'c, 'd>,
    nodes: iter::Enumerate<::std::vec::IntoIter<Node<'d>>>,
    size: usize,
}

impl<'c, 'd> Iterator for EvaluationNodesetIter<'c, 'd> {
    type Item = Evaluation<'c, 'd>;

    fn next(&mut self) -> Option<Evaluation<'c, 'd>> {
        self.nodes.next().map(|(idx, node)| Evaluation {
            node,
            position: idx + 1,
            size: self.size,
            ..self.parent
        })
    }
}
