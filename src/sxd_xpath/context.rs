//! Support for the various types of contexts before and during `XPath`
//! evaluation.

#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use sxd_document_no_unsafe::QName;

use alloc::{boxed::Box, string::String, vec::Vec};
use core::cell::Cell;
use core::iter;
#[cfg(any(feature = "std", not(feature = "embedded")))]
use std::collections::{HashMap, hash_map::RandomState};
#[cfg(any(feature = "std", not(feature = "embedded")))]
use std::hash::{BuildHasher, Hash, Hasher};

use crate::collections::Map;
use crate::function;
use crate::nodeset::{Node, OrderedNodes};
use crate::{OwnedQName, Value};

/// A mapping of names to `XPath` functions.
type Functions<'f> = QNameMap<Box<dyn function::Function + 'f>>;
/// A mapping of names to `XPath` variables.
type Variables<'d> = QNameMap<Value<'d>>;
/// A mapping of namespace prefixes to namespace URIs.
type Namespaces = Map<String, String>;

// A root resolver works for the input node's document lifetime; it must not
// pin an otherwise empty context to one document or make that lifetime invariant.
type RootResolver = for<'node> fn(Node<'node>) -> Node<'node>;

#[cfg(feature = "embedded")]
type FunctionView<'f> = &'f [(QName<'f>, &'f dyn function::Function)];
#[cfg(feature = "embedded")]
pub(crate) trait NamespaceLookup {
    fn namespace_for(&self, prefix: &str) -> Result<Option<&str>, function::Error>;
}

#[cfg(feature = "embedded")]
fn view_function<'f>(
    functions: FunctionView<'f>,
    name: QName<'_>,
) -> Option<&'f dyn function::Function> {
    for (candidate, function) in functions.iter().rev() {
        if *candidate == name {
            return Some(*function);
        }
    }
    None
}

/// Caller-registered functions and variables. Without std there is no hash
/// seed; these few application-chosen names are then scanned in order.
#[cfg(all(feature = "embedded", not(feature = "std")))]
struct QNameMap<V> {
    entries: Vec<(OwnedQName, V)>,
}

#[cfg(all(feature = "embedded", not(feature = "std")))]
impl<V> Default for QNameMap<V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

#[cfg(all(feature = "embedded", not(feature = "std")))]
impl<V> QNameMap<V> {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn insert(&mut self, name: OwnedQName, value: V) {
        if let Some((_, previous)) = self
            .entries
            .iter_mut()
            .find(|(candidate, _)| candidate == &name)
        {
            *previous = value;
        } else {
            self.entries.push((name, value));
        }
    }

    fn get(&self, name: QName<'_>) -> Option<&V> {
        self.entries.iter().find_map(|(candidate, value)| {
            (candidate.namespace_uri() == name.namespace_uri()
                && candidate.local_part() == name.local_part())
            .then_some(value)
        })
    }
}

#[cfg(any(feature = "std", not(feature = "embedded")))]
struct QNameMap<V> {
    buckets: HashMap<u64, Vec<(OwnedQName, V)>>,
    names: RandomState,
}

#[cfg(any(feature = "std", not(feature = "embedded")))]
impl<V> Default for QNameMap<V> {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
            names: RandomState::new(),
        }
    }
}

#[cfg(any(feature = "std", not(feature = "embedded")))]
impl<V> QNameMap<V> {
    fn len(&self) -> usize {
        self.buckets.values().map(Vec::len).sum()
    }

    fn hash(&self, namespace: Option<&str>, local: &str) -> u64 {
        let mut hasher = self.names.build_hasher();
        namespace.hash(&mut hasher);
        local.hash(&mut hasher);
        hasher.finish()
    }

    fn insert(&mut self, name: OwnedQName, value: V) {
        let hash = self.hash(name.namespace_uri(), name.local_part());
        let bucket = self.buckets.entry(hash).or_default();
        if let Some((_, previous)) = bucket.iter_mut().find(|(candidate, _)| candidate == &name) {
            *previous = value;
        } else {
            bucket.push((name, value));
        }
    }

    fn get(&self, name: QName<'_>) -> Option<&V> {
        if self.buckets.is_empty() {
            return None;
        }
        let hash = self.hash(name.namespace_uri(), name.local_part());
        self.buckets
            .get(&hash)?
            .iter()
            .find_map(|(candidate, value)| {
                (candidate.namespace_uri() == name.namespace_uri()
                    && candidate.local_part() == name.local_part())
                .then_some(value)
            })
    }
}

/// Contains the context in which `XPath` expressions are executed. The
/// context contains functions, variables, and namespace mappings.
///
/// ### Examples
///
/// A complete example showing all optional settings.
///
/// ```
/// # #[cfg(not(feature = "embedded"))]
/// # {
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
///         let mut args = function::Args::new(args);
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
/// # }
/// ```
///
/// Note that we are using a custom function (`sigmoid`), a variable
/// (`$t`), and a namespace (`neural:`). The current node is passed to
/// the `evaluate` method and is not the root of the tree but the
/// top-most element.
///
pub type Context<'d> = ScopedContext<'static, 'd>;

/// An `XPath` context whose function captures and document values have independent lifetimes.
/// Borrowed callbacks need only outlive evaluation, not the XML document they inspect.
pub struct ScopedContext<'f, 'd> {
    functions: Functions<'f>,
    core_functions: bool,
    #[cfg(feature = "embedded")]
    function_view: FunctionView<'f>,
    #[cfg(feature = "embedded")]
    namespace_lookup: Option<&'f dyn NamespaceLookup>,
    variables: Variables<'d>,
    namespaces: Namespaces,
    string_allocations: StringAllocationBudget,
    evaluation_work: WorkBudget,
    extension_work: WorkBudget,
    work_admission: Option<&'f dyn Fn(usize) -> Result<(), function::Error>>,
    document_root_resolver: Option<RootResolver>,
}

#[derive(Default)]
struct StringAllocationBudget {
    limit: Option<usize>,
    used: Cell<usize>,
    exceeded: Cell<Option<usize>>,
}

#[derive(Default)]
struct WorkBudget {
    limit: Option<usize>,
    used: Cell<usize>,
    exceeded: Cell<Option<usize>>,
}

impl<'f, 'd> ScopedContext<'f, 'd> {
    /// Registers the core `XPath` 1.0 functions.
    #[must_use]
    pub fn new() -> Self {
        let mut context = Self::without_core_functions();
        context.core_functions = true;
        context
    }

    /// No functions, variables or namespaces will be defined.
    #[must_use]
    pub fn without_core_functions() -> Self {
        Self {
            functions: Functions::default(),
            core_functions: false,
            #[cfg(feature = "embedded")]
            function_view: &[],
            #[cfg(feature = "embedded")]
            namespace_lookup: None,
            variables: Variables::default(),
            namespaces: Namespaces::default(),
            string_allocations: StringAllocationBudget::default(),
            evaluation_work: WorkBudget::default(),
            extension_work: WorkBudget::default(),
            work_admission: None,
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
    pub fn set_document_root_resolver(&mut self, resolver: RootResolver) {
        self.document_root_resolver = Some(resolver);
    }

    /// Return the first attempted total that exceeded the current context-scoped limit.
    pub fn string_allocation_exceeded(&self) -> Option<usize> {
        self.string_allocations.exceeded.get()
    }

    /// Return allocation bytes retained by values produced during evaluation.
    #[doc(hidden)]
    pub fn string_allocation_used(&self) -> usize {
        self.string_allocations.used.get()
    }

    /// Limit primitive traversal, predicate, comparison, and result-insertion work.
    pub fn set_evaluation_work_limit(&mut self, limit: usize) {
        self.evaluation_work.limit = Some(limit);
        self.evaluation_work.used.set(0);
        self.evaluation_work.exceeded.set(None);
    }

    /// Return work successfully charged by the current evaluation.
    pub fn evaluation_work_used(&self) -> usize {
        self.evaluation_work.used.get()
    }

    /// Return the first attempted total beyond the current work limit.
    pub fn evaluation_work_exceeded(&self) -> Option<usize> {
        self.evaluation_work.exceeded.get()
    }

    /// Admit primitive work in a borrowing embedding execution before running it.
    /// The callback neither allocates a new context nor replaces the independent
    /// `XPath` limit. A refusal must retain its original cause in the embedding.
    pub fn set_work_admission(
        &mut self,
        admission: &'f dyn Fn(usize) -> Result<(), function::Error>,
    ) {
        self.work_admission = Some(admission);
    }

    /// Charge primitive setup work performed while constructing this `XPath` context.
    ///
    /// # Errors
    /// Returns the admission callback's refusal or a local work-limit error.
    /// Work already admitted before a later refusal remains spent.
    pub fn charge_work(&self, units: usize) -> Result<(), function::Error> {
        if let Some(admission) = self.work_admission {
            admission(units)?;
        }
        charge_work_budget(
            &self.evaluation_work,
            units,
            "XPath evaluation work budget exceeded",
        )
    }

    /// Limit work performed inside extension functions.
    pub fn set_extension_work_limit(&mut self, limit: usize) {
        self.extension_work.limit = Some(limit);
        self.extension_work.used.set(0);
        self.extension_work.exceeded.set(None);
    }

    /// Return extension work successfully charged by the current evaluation.
    pub fn extension_work_used(&self) -> usize {
        self.extension_work.used.get()
    }

    /// Return the first attempted total beyond the extension-work limit.
    pub fn extension_work_exceeded(&self) -> Option<usize> {
        self.extension_work.exceeded.get()
    }

    /// Reserve bytes in the context-scoped temporary allocation budget.
    ///
    /// # Errors
    /// Returns an allocation-limit error if the attempted total overflows or
    /// exceeds the configured allowance.
    pub fn reserve_temporary_allocation(&self, bytes: usize) -> Result<(), function::Error> {
        reserve_allocation(&self.string_allocations, bytes)
    }

    /// Register a function within the context. Its state may borrow for the context lifetime.
    pub fn set_function<N, F>(&mut self, name: N, function: F)
    where
        N: Into<OwnedQName>,
        F: function::Function + 'f,
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

    /// Borrows embedding-owned extension objects without boxing or copying
    /// names. Owned overrides still take precedence; duplicate view names use
    /// the last binding, matching repeated `set_function` calls.
    #[cfg(feature = "embedded")]
    pub(crate) fn set_function_view(&mut self, functions: FunctionView<'f>) {
        self.function_view = functions;
    }

    /// Resolves original namespace bindings through embedding-owned storage.
    /// It replaces this context's namespace map without allocating another one.
    #[cfg(feature = "embedded")]
    pub(crate) fn set_namespace_lookup(&mut self, lookup: &'f dyn NamespaceLookup) {
        self.namespace_lookup = Some(lookup);
    }

    /// Number of distinct registered functions, for embedding allocation-bound assertions.
    #[doc(hidden)]
    pub fn function_count(&self) -> usize {
        let mut count = self.functions.len();
        #[cfg(feature = "embedded")]
        for (index, (name, _)) in self.function_view.iter().enumerate() {
            if self.functions.get(*name).is_some()
                || view_function(&self.function_view[index + 1..], *name).is_some()
            {
                continue;
            }
            count += 1;
        }
        if self.core_functions {
            for name in function::CORE_NAMES {
                let name = QName::new(name);
                if self.functions.get(name).is_some() {
                    continue;
                }
                #[cfg(feature = "embedded")]
                if view_function(self.function_view, name).is_some() {
                    continue;
                }
                count += 1;
            }
        }
        count
    }
}

impl Default for ScopedContext<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}

/// The context during evaluation of an `XPath` expression.
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
    functions: &'c Functions<'c>,
    core_functions: bool,
    #[cfg(feature = "embedded")]
    function_view: FunctionView<'c>,
    #[cfg(feature = "embedded")]
    namespace_lookup: Option<&'c dyn NamespaceLookup>,
    variables: &'c Variables<'d>,
    namespaces: &'c Namespaces,
    string_allocations: &'c StringAllocationBudget,
    work: &'c WorkBudget,
    extension_work: &'c WorkBudget,
    work_admission: Option<&'c dyn Fn(usize) -> Result<(), function::Error>>,
    document_root_resolver: Option<RootResolver>,
}

#[cfg(not(feature = "no-unsafe"))]
impl<'c, 'd> Copy for Evaluation<'c, 'd> {}

impl<'c, 'd> Evaluation<'c, 'd> {
    /// Prepares the context used while evaluating the `XPath` expression
    pub fn new(context: &'c ScopedContext<'_, 'd>, node: Node<'d>) -> Evaluation<'c, 'd> {
        Evaluation {
            node,
            functions: &context.functions,
            core_functions: context.core_functions,
            #[cfg(feature = "embedded")]
            function_view: context.function_view,
            #[cfg(feature = "embedded")]
            namespace_lookup: context.namespace_lookup,
            variables: &context.variables,
            namespaces: &context.namespaces,
            string_allocations: &context.string_allocations,
            work: &context.evaluation_work,
            extension_work: &context.extension_work,
            work_admission: context.work_admission,
            document_root_resolver: context.document_root_resolver,
            position: 1,
            size: 1,
        }
    }

    /// Creates a new context node using the provided node
    #[must_use]
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
        self.resolve_function(name).map(function::Resolved::native)
    }

    pub(crate) fn resolve_function(&self, name: QName<'_>) -> Option<function::Resolved<'c>> {
        if let Some(function) = self.functions.get(name) {
            return Some(function::Resolved::Extension(function.as_ref()));
        }
        #[cfg(feature = "embedded")]
        if let Some(function) = view_function(self.function_view, name) {
            return Some(function::Resolved::Extension(function));
        }
        if self.core_functions && name.namespace_uri().is_none() {
            return function::core::Core::lookup(name.local_part()).map(function::Resolved::Core);
        }
        None
    }

    /// Looks up the value of the variable
    #[must_use]
    pub fn value_of(&self, name: QName<'_>) -> Option<&Value<'d>> {
        self.variables.get(name)
    }

    /// Looks up the namespace URI for the given prefix
    ///
    /// # Errors
    /// Returns an embedding namespace resolver's refusal unchanged.
    pub fn namespace_for(&self, prefix: &str) -> Result<Option<&str>, function::Error> {
        #[cfg(feature = "embedded")]
        if let Some(lookup) = self.namespace_lookup {
            return lookup.namespace_for(prefix);
        }
        Ok(self.namespaces.get(prefix).map(String::as_str))
    }

    pub(crate) fn document_root_for(&self, node: Node<'d>) -> Node<'d> {
        if let Some(resolver) = self.document_root_resolver {
            resolver(node)
        } else {
            node.document().root().into()
        }
    }

    /// Reserve bytes before an extension function allocates an `XPath` string result.
    ///
    /// # Errors
    /// Returns an allocation-limit error if the total overflows or exceeds the allowance.
    pub fn reserve_string_allocation(&self, bytes: usize) -> Result<(), function::Error> {
        self.reserve_temporary_allocation(bytes)
    }

    /// Reserve bytes in the context-scoped temporary allocation budget.
    ///
    /// # Errors
    /// Returns an allocation-limit error if the total overflows or exceeds the allowance.
    pub fn reserve_temporary_allocation(&self, bytes: usize) -> Result<(), function::Error> {
        reserve_allocation(self.string_allocations, bytes)
    }

    /// Release bytes after temporary extension storage is destroyed or superseded.
    ///
    /// # Errors
    /// Returns an accounting error if more bytes are released than were reserved.
    pub fn release_temporary_allocation(&self, bytes: usize) -> Result<(), function::Error> {
        release_allocation(self.string_allocations, bytes)
    }

    /// Admit structural AST entry in the borrowing current execution.
    pub(crate) fn admit_expression_step(&self) -> Result<(), function::Error> {
        // Structural AST entry is current-execution admission, not a change
        // to the embedding's existing primitive-work policy or native counters.
        // Native contexts have no callback and need no counter mutation here.
        if let Some(admission) = self.work_admission {
            admission(1)?;
        }
        Ok(())
    }

    /// Charge primitive `XPath` evaluation work before performing it.
    ///
    /// # Errors
    /// Returns the admission callback's refusal or a local work-limit error.
    /// Work already admitted before a later refusal remains spent.
    pub fn charge_work(&self, units: usize) -> Result<(), function::Error> {
        if let Some(admission) = self.work_admission {
            admission(units)?;
        }
        charge_work_budget(self.work, units, "XPath evaluation work budget exceeded")
    }

    /// Charge extension-internal work before performing it.
    ///
    /// # Errors
    /// Returns the admission callback's refusal or an extension-work-limit error.
    /// Work already admitted before a later refusal remains spent.
    pub fn charge_extension_work(&self, units: usize) -> Result<(), function::Error> {
        if let Some(admission) = self.work_admission {
            admission(units)?;
        }
        charge_work_budget(
            self.extension_work,
            units,
            "XPath extension work budget exceeded",
        )
    }

    /// Yields a new `Evaluation` context for each node in the nodeset.
    #[must_use]
    pub fn new_contexts_for(self, nodes: OrderedNodes<'d>) -> EvaluationNodesetIter<'c, 'd> {
        let sz = nodes.size();
        EvaluationNodesetIter {
            parent: self,
            nodes: Vec::from(nodes).into_iter().enumerate(),
            size: sz,
        }
    }
}

fn charge_work_budget(
    budget: &WorkBudget,
    units: usize,
    message: &'static str,
) -> Result<(), function::Error> {
    let Some(actual) = budget.used.get().checked_add(units) else {
        if budget.exceeded.get().is_none() {
            budget.exceeded.set(Some(usize::MAX));
        }
        return Err(function::Error::Other {
            what: message.into(),
        });
    };
    if budget.limit.is_some_and(|limit| actual > limit) {
        if budget.exceeded.get().is_none() {
            budget.exceeded.set(Some(actual));
        }
        return Err(function::Error::Other {
            what: message.into(),
        });
    }
    budget.used.set(actual);
    Ok(())
}

fn reserve_allocation(
    budget: &StringAllocationBudget,
    bytes: usize,
) -> Result<(), function::Error> {
    let Some(actual) = budget.used.get().checked_add(bytes) else {
        if budget.exceeded.get().is_none() {
            budget.exceeded.set(Some(usize::MAX));
        }
        return Err(function::Error::Other {
            what: "XPath string allocation budget exceeded".into(),
        });
    };
    if budget.limit.is_some_and(|limit| actual > limit) {
        if budget.exceeded.get().is_none() {
            budget.exceeded.set(Some(actual));
        }
        return Err(function::Error::Other {
            what: "XPath string allocation budget exceeded".into(),
        });
    }
    budget.used.set(actual);
    Ok(())
}

fn release_allocation(
    budget: &StringAllocationBudget,
    bytes: usize,
) -> Result<(), function::Error> {
    let Some(retained) = budget.used.get().checked_sub(bytes) else {
        return Err(function::Error::Other {
            what: "released XPath allocation exceeds reserved allocation".into(),
        });
    };
    budget.used.set(retained);
    Ok(())
}

/// An iterator for the contexts of each node in a nodeset
pub struct EvaluationNodesetIter<'c, 'd> {
    parent: Evaluation<'c, 'd>,
    nodes: iter::Enumerate<alloc::vec::IntoIter<Node<'d>>>,
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "embedded")]
    #[test]
    fn borrowed_function_view_preserves_owned_overrides_and_unique_count() {
        // XML extensions can live on the stack. View replacement and owned
        // overrides must retain the same last-binding lookup/count semantics.
        struct Literal(bool);
        impl crate::function::Function for Literal {
            fn evaluate<'d>(
                &self,
                _: &super::Evaluation<'_, 'd>,
                _: Vec<crate::Value<'d>>,
            ) -> Result<crate::Value<'d>, crate::function::Error> {
                Ok(crate::Value::Boolean(self.0))
            }
        }
        let yes = Literal(true);
        let no = Literal(false);
        let functions: [(
            sxd_document_no_unsafe::QName<'_>,
            &dyn crate::function::Function,
        ); 3] = [
            (sxd_document_no_unsafe::QName::new("true"), &no),
            (sxd_document_no_unsafe::QName::new("borrowed"), &yes),
            (sxd_document_no_unsafe::QName::new("borrowed"), &no),
        ];
        let mut context = super::ScopedContext::new();
        context.set_function_view(&functions);
        assert!(context.functions.buckets.is_empty());
        assert_eq!(context.function_count(), 26);
        let package = sxd_document_no_unsafe::Package::new();
        let root = package.as_document().root();
        for source in ["true()", "borrowed()"] {
            assert_eq!(
                crate::Factory::new()
                    .build(source)
                    .unwrap()
                    .evaluate(&context, root)
                    .unwrap(),
                crate::Value::Boolean(false)
            );
        }
        context.set_function("borrowed", Literal(true));
        assert_eq!(context.function_count(), 26);
        assert_eq!(
            crate::Factory::new()
                .build("borrowed()")
                .unwrap()
                .evaluate(&context, root)
                .unwrap(),
            crate::Value::Boolean(true)
        );
    }

    #[cfg(feature = "embedded")]
    #[test]
    fn namespace_refusal_is_terminal_not_an_unbound_prefix() {
        // Refusing the embedding's current-work lookup must not allocate an
        // UnknownNamespace string after that refusal, even on empty axes.
        struct Refused;
        impl super::NamespaceLookup for Refused {
            fn namespace_for(&self, _: &str) -> Result<Option<&str>, crate::function::Error> {
                Err(crate::function::Error::ProcessingStopped)
            }
        }
        let lookup = Refused;
        let mut context = super::ScopedContext::new();
        context.set_namespace_lookup(&lookup);
        let package = sxd_document_no_unsafe::Package::new();
        for source in ["p:missing", "p:missing()", "$p:missing"] {
            let error = crate::Factory::new()
                .build(source)
                .unwrap()
                .evaluate(&context, package.as_document().root())
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    super::super::ExecutionError(crate::expression::Error::FunctionEvaluation {
                        source: crate::function::Error::ProcessingStopped
                    })
                ),
                "{source}: {error:?}"
            );
        }
    }

    #[test]
    fn core_library_has_no_per_query_heap_registry() {
        // A fresh security query must not allocate an unaccounted registry of
        // immutable core functions before current-execution admission exists.
        let context = super::ScopedContext::new();
        assert!(context.functions.buckets.is_empty());
        assert_eq!(context.function_count(), 25);
        let package = sxd_document_no_unsafe::Package::new();
        let evaluation = super::Evaluation::new(&context, package.as_document().root().into());
        assert!(
            evaluation
                .function_for_name(sxd_document_no_unsafe::QName::new("count"))
                .is_some()
        );
        assert!(
            evaluation
                .function_for_name(sxd_document_no_unsafe::QName::with_namespace_uri(
                    Some("urn:foreign"),
                    "count"
                ))
                .is_none()
        );
    }

    #[test]
    fn static_core_library_preserves_override_and_registration_order() {
        // Custom overrides win until explicit core registration replaces
        // them, exactly as with the former eagerly allocated registry.
        struct False;
        impl crate::function::Function for False {
            fn evaluate<'d>(
                &self,
                _: &super::Evaluation<'_, 'd>,
                _: Vec<crate::Value<'d>>,
            ) -> Result<crate::Value<'d>, crate::function::Error> {
                Ok(crate::Value::Boolean(false))
            }
        }
        let package = sxd_document_no_unsafe::Package::new();
        let root = package.as_document().root();
        let xpath = crate::Factory::new().build("true()").unwrap();
        let mut context = super::ScopedContext::without_core_functions();
        assert_eq!(context.function_count(), 0);
        assert!(xpath.evaluate(&context, root).is_err());
        crate::function::register_core_functions(&mut context);
        assert_eq!(context.function_count(), 25);
        assert_eq!(
            xpath.evaluate(&context, root).unwrap(),
            crate::Value::Boolean(true)
        );
        let mut context = super::ScopedContext::new();
        context.set_function("true", False);
        assert_eq!(context.function_count(), 25);
        assert_eq!(
            xpath.evaluate(&context, root).unwrap(),
            crate::Value::Boolean(false)
        );
        crate::function::register_core_functions(&mut context);
        assert_eq!(context.function_count(), 25);
        assert_eq!(
            xpath.evaluate(&context, root).unwrap(),
            crate::Value::Boolean(true)
        );
    }

    use super::Context;
    #[cfg(feature = "embedded")]
    use super::sxd_document_no_unsafe;

    #[test]
    fn current_admission_is_shared_by_setup_children_and_extensions() {
        // Derived node contexts keep the same borrowed execution. A refusal
        // happens before the independent XPath counter is advanced.
        let remaining = std::cell::Cell::new(4_usize);
        let admission = |units| {
            let available = remaining.get();
            if units > available {
                return Err(crate::function::Error::ProcessingStopped);
            }
            remaining.set(available - units);
            Ok(())
        };
        let mut context = super::ScopedContext::without_core_functions();
        context.set_work_admission(&admission);
        context.charge_work(1).expect("setup admission");
        let package = sxd_document_no_unsafe::Package::new();
        let root = package.as_document().root();
        let evaluation = super::Evaluation::new(&context, root.into());
        let child = evaluation.new_context_for(root);
        child.charge_work(2).expect("derived context admission");
        child.charge_extension_work(1).expect("extension admission");
        assert_eq!(remaining.get(), 0);
        assert_eq!(context.evaluation_work_used(), 3);
        assert_eq!(context.extension_work_used(), 1);
        assert_eq!(
            child.charge_work(1),
            Err(crate::function::Error::ProcessingStopped)
        );
        assert_eq!(
            child.charge_extension_work(1),
            Err(crate::function::Error::ProcessingStopped)
        );
        assert_eq!(context.evaluation_work_used(), 3);
        assert_eq!(context.extension_work_used(), 1);
    }

    #[test]
    fn root_expression_admits_work_before_calling_a_function() {
        // Even a single function-call expression must not get a free first AST
        // step. Refusal cannot invoke an extension or allocate a string cause.
        struct Observe<'a>(&'a std::cell::Cell<usize>);
        impl crate::function::Function for Observe<'_> {
            fn evaluate<'d>(
                &self,
                _: &super::Evaluation<'_, 'd>,
                _: Vec<crate::Value<'d>>,
            ) -> Result<crate::Value<'d>, crate::function::Error> {
                self.0.set(self.0.get() + 1);
                Ok(crate::Value::Boolean(true))
            }
        }
        let calls = std::cell::Cell::new(0);
        let admissions = std::cell::Cell::new(0);
        let remaining = std::cell::Cell::new(0_usize);
        let admission = |units| {
            admissions.set(admissions.get() + 1);
            if units > remaining.get() {
                return Err(crate::function::Error::ProcessingStopped);
            }
            remaining.set(remaining.get() - units);
            Ok(())
        };
        let mut context = super::ScopedContext::without_core_functions();
        context.set_function("observe", Observe(&calls));
        context.set_work_admission(&admission);
        let package = sxd_document_no_unsafe::Package::new();
        let xpath = crate::Factory::new()
            .build("observe()")
            .expect("valid observing function");
        let error = xpath
            .evaluate(&context, package.as_document().root())
            .expect_err("the root AST step needs current work");
        assert!(matches!(
            error,
            super::super::ExecutionError(crate::expression::Error::FunctionEvaluation {
                source: crate::function::Error::ProcessingStopped
            })
        ));
        assert_eq!(admissions.get(), 1);
        assert_eq!(calls.get(), 0);
        assert_eq!(context.evaluation_work_used(), 0);

        // Paying the root does not pay its children: the first function below
        // a binary AST node must also refuse before any observing side effect.
        remaining.set(1);
        admissions.set(0);
        let binary = crate::Factory::new()
            .build("observe() and observe()")
            .expect("valid binary expression");
        binary
            .evaluate(&context, package.as_document().root())
            .expect_err("the first child still needs current work");
        assert_eq!(admissions.get(), 2);
        assert_eq!(calls.get(), 0);
        assert_eq!(remaining.get(), 0);
    }

    #[test]
    fn registered_functions_borrow_context_scoped_state() {
        // Permission callbacks must borrow caller state without cloning an Arc or allocating
        // another ownership wrapper on every XPath evaluation.
        struct Borrowed<'a>(&'a std::cell::Cell<usize>);
        impl crate::function::Function for Borrowed<'_> {
            fn evaluate<'d>(
                &self,
                _: &super::Evaluation<'_, 'd>,
                _: Vec<crate::Value<'d>>,
            ) -> Result<crate::Value<'d>, crate::function::Error> {
                self.0.set(self.0.get() + 1);
                Ok(crate::Value::Boolean(true))
            }
        }
        let calls = std::cell::Cell::new(0);
        let mut context = super::ScopedContext::new();
        context.set_function("borrowed", Borrowed(&calls));
        // The document is destroyed before this context. Function capture lifetimes must not
        // force it to outlive the context's destructor when no document value is retained.
        let package = sxd_document_no_unsafe::Package::new();
        let expression = crate::Factory::new()
            .build("borrowed()")
            .expect("XPath compiles");
        assert_eq!(
            expression
                .evaluate(&context, package.as_document().root())
                .expect("borrowed callback executes"),
            crate::Value::Boolean(true)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn qname_lookup_does_not_allocate() {
        let mut context = Context::new();
        context.set_variable(("urn:test", "value"), 1.0);
        context.set_string_allocation_limit(0);
        let package = sxd_document_no_unsafe::Package::new();
        let evaluation = super::Evaluation::new(&context, package.as_document().root().into());
        let name = sxd_document_no_unsafe::QName::with_namespace_uri(Some("urn:test"), "value");

        assert!(evaluation.value_of(name).is_some());
        assert_eq!(context.string_allocation_exceeded(), None);
    }

    #[test]
    fn allocation_budget_preserves_first_exceeded_total() {
        let mut context = Context::new();
        context.set_string_allocation_limit(4);

        assert!(context.reserve_temporary_allocation(5).is_err());
        assert!(context.reserve_temporary_allocation(9).is_err());
        assert_eq!(context.string_allocation_exceeded(), Some(5));
    }

    #[test]
    fn work_budget_preserves_first_exceeded_total() {
        let mut context = Context::new();
        context.set_evaluation_work_limit(4);
        let package = sxd_document_no_unsafe::Package::new();
        let evaluation = super::Evaluation::new(&context, package.as_document().root().into());

        assert!(evaluation.charge_work(5).is_err());
        assert!(evaluation.charge_work(9).is_err());
        assert_eq!(context.evaluation_work_exceeded(), Some(5));
    }

    #[test]
    fn extension_work_budget_preserves_first_exceeded_total() {
        let mut context = Context::new();
        context.set_extension_work_limit(4);
        let package = sxd_document_no_unsafe::Package::new();
        let evaluation = super::Evaluation::new(&context, package.as_document().root().into());

        assert!(evaluation.charge_extension_work(5).is_err());
        assert!(evaluation.charge_extension_work(9).is_err());
        assert_eq!(context.extension_work_exceeded(), Some(5));
    }

    #[test]
    fn work_budget_rejects_counter_overflow() {
        let mut context = Context::new();
        context.set_evaluation_work_limit(usize::MAX);
        let package = sxd_document_no_unsafe::Package::new();
        let evaluation = super::Evaluation::new(&context, package.as_document().root().into());

        assert!(evaluation.charge_work(usize::MAX).is_ok());
        assert!(evaluation.charge_work(1).is_err());
    }

    #[test]
    fn allocation_budget_rejects_counter_overflow() {
        let mut context = Context::new();
        context.set_string_allocation_limit(usize::MAX);
        let package = sxd_document_no_unsafe::Package::new();
        let evaluation = super::Evaluation::new(&context, package.as_document().root().into());

        assert!(evaluation.reserve_temporary_allocation(usize::MAX).is_ok());
        assert!(evaluation.reserve_temporary_allocation(1).is_err());
    }

    #[test]
    fn allocation_budget_reuses_released_temporary_storage() {
        let mut context = Context::new();
        context.set_string_allocation_limit(8);
        let package = sxd_document_no_unsafe::Package::new();
        let evaluation = super::Evaluation::new(&context, package.as_document().root().into());

        evaluation
            .reserve_temporary_allocation(8)
            .expect("initial temporary allocation fits");
        evaluation
            .release_temporary_allocation(8)
            .expect("reserved temporary allocation can be released");

        assert!(evaluation.reserve_temporary_allocation(8).is_ok());
    }

    #[test]
    fn allocation_budget_rejects_releasing_unreserved_storage() {
        let context = Context::new();
        let package = sxd_document_no_unsafe::Package::new();
        let evaluation = super::Evaluation::new(&context, package.as_document().root().into());

        let error = evaluation
            .release_temporary_allocation(1)
            .expect_err("unreserved storage must return an evaluation error");

        assert!(error.to_string().contains("exceeds reserved allocation"));
    }
}
