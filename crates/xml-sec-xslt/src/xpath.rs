use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use sxd_document_no_unsafe::dom::{Document as SxdDocument, Element as SxdElement};
use sxd_document_no_unsafe::{Package, QName};
use sxd_xpath_no_unsafe::{Context, Factory, Value as SxdValue, XPath, function, nodeset};

use crate::budget::{Meter, reserve_temporary_vec_slot};
use crate::compiler::{DecimalFormat, Expression, NameTest, Pattern, normalize_xpath_for_sxd};
use crate::expression::innermost_namespaced_call;
use crate::lexical::{is_ncname, is_ncname_char};
use crate::resolver::decode_resource;
use crate::runtime::{SourceProcessing, apply_whitespace_rules};
use crate::{
    BudgetKind, Clock, Document, Error, ErrorKind, ExpandedName, ExtensionPolicy, Node, NodeId,
    NodeKind, NodeReference, ResolvePurpose, ResolvedResource, Resolver, ResourceIdentity, Result,
    Value,
};

pub(crate) type SourceNode = NodeReference;

pub(crate) trait VariableBindings {
    fn get(&self, name: &ExpandedName) -> Option<&Value>;

    fn visit(&self, visitor: &mut dyn FnMut(&ExpandedName, &Value));

    fn result_tree_fragment(&self, identity: u64) -> Option<Arc<Document>>;
}

impl VariableBindings for HashMap<ExpandedName, Value> {
    fn get(&self, name: &ExpandedName) -> Option<&Value> {
        HashMap::get(self, name)
    }

    fn visit(&self, visitor: &mut dyn FnMut(&ExpandedName, &Value)) {
        for (name, value) in self {
            visitor(name, value);
        }
    }

    fn result_tree_fragment(&self, identity: u64) -> Option<Arc<Document>> {
        self.values().find_map(|value| match value {
            Value::ResultTreeFragment(document) if document.identity() == identity => {
                Some(Arc::clone(document))
            }
            _ => None,
        })
    }
}

struct VariableOverlay<'a> {
    base: &'a dyn VariableBindings,
    additions: HashMap<ExpandedName, Value>,
}

impl<'a> VariableOverlay<'a> {
    fn new(base: &'a dyn VariableBindings) -> Self {
        Self {
            base,
            additions: HashMap::new(),
        }
    }

    fn insert(&mut self, name: ExpandedName, value: Value) {
        self.additions.insert(name, value);
    }
}

impl VariableBindings for VariableOverlay<'_> {
    fn get(&self, name: &ExpandedName) -> Option<&Value> {
        self.additions.get(name).or_else(|| self.base.get(name))
    }

    fn visit(&self, visitor: &mut dyn FnMut(&ExpandedName, &Value)) {
        self.base.visit(&mut |name, value| {
            if !self.additions.contains_key(name) {
                visitor(name, value);
            }
        });
        for (name, value) in &self.additions {
            visitor(name, value);
        }
    }

    fn result_tree_fragment(&self, identity: u64) -> Option<Arc<Document>> {
        self.additions
            .values()
            .find_map(|value| match value {
                Value::ResultTreeFragment(document) if document.identity() == identity => {
                    Some(Arc::clone(document))
                }
                _ => None,
            })
            .or_else(|| self.base.result_tree_fragment(identity))
    }
}

enum PreparedExtensionCalls<'a> {
    Borrowed {
        expression: &'a Expression,
        variables: &'a dyn VariableBindings,
    },
    Rewritten {
        expression: Expression,
        variables: VariableOverlay<'a>,
    },
}

impl<'a> PreparedExtensionCalls<'a> {
    fn parts(&'a self) -> (&'a Expression, &'a dyn VariableBindings) {
        match self {
            Self::Borrowed {
                expression,
                variables,
            } => (expression, *variables),
            Self::Rewritten {
                expression,
                variables,
            } => (expression, variables),
        }
    }
}
const CONTEXT_NS: &str = "urn:structured-world:xml-sec:xslt:context";
const DOCUMENTS_ELEMENT: &str = "__xml_sec_documents";
const DOCUMENT_ELEMENT: &str = "__xml_sec_document";
const EXTENSION_CONTEXT_NS: &str = "urn:structured-world:xml-sec:xslt:extensions";
pub(crate) const EXSLT_COMMON_NS: &str = "http://exslt.org/common";
const EXSLT_STRINGS_NS: &str = "http://exslt.org/strings";
const EXSLT_MATH_NS: &str = "http://exslt.org/math";
const EXSLT_SETS_NS: &str = "http://exslt.org/sets";
const EXSLT_DYNAMIC_NS: &str = "http://exslt.org/dynamic";
const EXSLT_CRYPTO_NS: &str = "http://exslt.org/crypto";
const LIBXSLT_TEST_NS: &str = "http://xmlsoft.org/XSLT/";
const LIBXSLT_TEST_PLUGIN_NS: &str = "http://xmlsoft.org/xslt/testplugin";
const SAXON_NS: &str = "http://icl.com/saxon";
const LIBXSLT_NS: &str = "http://xmlsoft.org/XSLT/namespace";
const XT_NS: &str = "http://www.jclark.com/xt";
const XALAN_REDIRECT_NS: &str = "org.apache.xalan.xslt.extensions.Redirect";

fn is_prepared_extension_call(namespace: &str, local: &str) -> bool {
    matches!(
        (namespace, local),
        (EXSLT_COMMON_NS | LIBXSLT_NS | SAXON_NS | XT_NS, "node-set")
            | (EXSLT_COMMON_NS, "object-type")
            | (EXSLT_STRINGS_NS, "split")
            | (EXSLT_STRINGS_NS, "tokenize")
            | (EXSLT_STRINGS_NS, "replace")
            | (EXSLT_DYNAMIC_NS, "evaluate")
            | (EXSLT_DYNAMIC_NS, "map")
            | (SAXON_NS, "expression")
            | (SAXON_NS, "eval")
            | (SAXON_NS, "evaluate")
            | (SAXON_NS, "line-number")
    )
}

pub(crate) struct EvaluatorSourceOptions {
    pub(crate) processing: SourceProcessing,
    pub(crate) whitespace: Arc<[(NameTest, bool, usize, usize)]>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) extension_policy: ExtensionPolicy,
}

pub(crate) struct PreparedEvaluatorSource {
    pub(crate) document: Document,
    pub(crate) remap: Option<HashMap<NodeId, NodeId>>,
    pub(crate) remap_owned_bytes: usize,
    resource_identities: HashMap<ResourceIdentity, ResolvedResource>,
}

pub(crate) fn prepare_evaluator_source(
    source: &Document,
    resolver: &dyn Resolver,
    meter: &mut Meter,
    options: &EvaluatorSourceOptions,
) -> Result<PreparedEvaluatorSource> {
    let mut resource_identities = HashMap::new();
    let (mut document, include_remap) = if options.processing == SourceProcessing::XInclude {
        let expanded = expand_xinclude_document(
            source,
            resolver,
            meter,
            &mut resource_identities,
            &mut Vec::new(),
            0,
        )?;
        (expanded.document, expanded.principal_mapping)
    } else {
        meter.charge(BudgetKind::OwnedBytes, source.estimated_clone_bytes())?;
        (source.clone(), None)
    };
    let (whitespace_remap, whitespace_remap_owned_bytes) =
        apply_whitespace_rules(&mut document, &options.whitespace, meter)?
            .map_or((None, 0), |(remap, bytes)| (Some(remap), bytes));
    let (remap, remap_owned_bytes) = compose_node_remaps(
        include_remap,
        whitespace_remap,
        whitespace_remap_owned_bytes,
        meter,
    )?;
    Ok(PreparedEvaluatorSource {
        document,
        remap,
        remap_owned_bytes,
        resource_identities,
    })
}

fn compose_node_remaps(
    first: Option<HashMap<NodeId, NodeId>>,
    second: Option<HashMap<NodeId, NodeId>>,
    second_owned_bytes: usize,
    meter: &mut Meter,
) -> Result<(Option<HashMap<NodeId, NodeId>>, usize)> {
    match (first, second) {
        (None, None) => Ok((None, 0)),
        (Some(remap), None) => Ok((Some(remap), 0)),
        (None, Some(remap)) => Ok((Some(remap), second_owned_bytes)),
        (Some(first), Some(second)) => {
            let entry_bytes = xinclude_remap_bytes(1);
            let requested_bytes = first.len().saturating_mul(entry_bytes);
            meter.charge(BudgetKind::OwnedBytes, requested_bytes)?;
            let mut composed = HashMap::new();
            if let Err(error) = composed.try_reserve(first.len()) {
                meter.release_owned_bytes(requested_bytes);
                return Err(Error::Dynamic(format!(
                    "failed to reserve composed node remap: {error}"
                )));
            }
            let retained_bytes = composed.capacity().saturating_mul(entry_bytes);
            if retained_bytes < requested_bytes {
                meter.release_owned_bytes(requested_bytes - retained_bytes);
            } else if retained_bytes > requested_bytes
                && let Err(error) =
                    meter.charge(BudgetKind::OwnedBytes, retained_bytes - requested_bytes)
            {
                meter.release_owned_bytes(requested_bytes);
                return Err(error);
            }
            for (original, intermediate) in first {
                if let Some(final_id) = second.get(&intermediate).copied() {
                    composed.insert(original, final_id);
                }
            }
            drop(second);
            meter.release_owned_bytes(second_owned_bytes);
            Ok((Some(composed), retained_bytes))
        }
    }
}

fn source_node_owner(node: &SourceNode) -> NodeId {
    match node {
        SourceNode::Node(node) => *node,
        SourceNode::Attribute { owner, .. } | SourceNode::Namespace { owner, .. } => *owner,
    }
}

fn source_base_uri(source: &Document, node: &SourceNode) -> Option<String> {
    source
        .node(source_node_owner(node))
        .and_then(|node| node.base_uri.clone())
}

type PatternCacheKey = (String, Vec<(String, String)>, NodeId);

fn pattern_cache_entry_owned_bytes(key: &PatternCacheKey, node_count: usize) -> usize {
    let namespace_bytes = key.1.iter().fold(0usize, |total, (prefix, uri)| {
        total
            .saturating_add(std::mem::size_of::<(String, String)>())
            .saturating_add(prefix.len())
            .saturating_add(uri.len())
    });
    std::mem::size_of::<PatternCacheKey>()
        .saturating_add(key.0.len())
        .saturating_add(namespace_bytes)
        // Hash tables retain control bytes and spare capacity in addition to each node value.
        .saturating_add(
            node_count
                .saturating_mul(std::mem::size_of::<SourceNode>())
                .saturating_mul(2),
        )
}

fn clear_pattern_cache(
    cache: &mut HashMap<PatternCacheKey, HashSet<SourceNode>>,
    meter: &mut Meter,
) {
    let retired = std::mem::take(cache);
    let released = retired.iter().fold(0usize, |total, (key, nodes)| {
        total.saturating_add(pattern_cache_entry_owned_bytes(key, nodes.len()))
    });
    drop(retired);
    meter.release_owned_bytes(released);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DocumentRequest {
    href: String,
    base_uri: Option<String>,
    empty_document: Option<usize>,
}

impl DocumentRequest {
    fn relative_to(
        href: String,
        base_uri: Option<String>,
        logical_document: Option<usize>,
    ) -> Self {
        let empty_resource = href
            .find('#')
            .map_or(href.is_empty(), |fragment| fragment == 0);
        Self {
            href,
            base_uri,
            empty_document: empty_resource.then_some(logical_document).flatten(),
        }
    }
}

fn document_cache_key_owned_bytes(request: &DocumentRequest) -> usize {
    std::mem::size_of::<DocumentRequest>()
        .saturating_mul(2)
        .saturating_add(request.href.len().saturating_mul(2))
        .saturating_add(
            request
                .base_uri
                .as_ref()
                .map_or(0, |base_uri| base_uri.len().saturating_mul(2)),
        )
}

fn charge_document_cache_keys(request: &DocumentRequest, meter: &mut Meter) -> Result<()> {
    meter.charge(
        BudgetKind::OwnedBytes,
        document_cache_key_owned_bytes(request),
    )
}

fn seed_document_cache(
    request: DocumentRequest,
    root: NodeId,
    maps: &NodeMaps,
    documents: &mut HashMap<DocumentRequest, Vec<SourceNode>>,
    document_roots: &mut HashMap<DocumentRequest, Vec<NodePath>>,
    meter: &mut Meter,
) -> Result<()> {
    charge_document_cache_keys(&request, meter)?;
    let root = SourceNode::Node(root);
    document_roots.insert(
        request.clone(),
        maps.forward.get(&root).cloned().into_iter().collect(),
    );
    documents.insert(request, vec![root]);
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct CustomFunctionCall {
    pub(crate) name: ExpandedName,
    pub(crate) node: SourceNode,
    pub(crate) position: usize,
    pub(crate) size: usize,
    pub(crate) arguments: Vec<Value>,
}

#[derive(Default)]
pub(crate) struct CustomCallSession {
    state: Rc<RefCell<CustomCallState>>,
}

#[derive(Default)]
struct CustomCallState {
    cursor: usize,
    pending: Option<Rc<DeferredCustomCall>>,
    last_requested: Option<Rc<DeferredCustomCall>>,
    completed: Vec<CompletedCustomCall>,
    retained_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeferredCustomCall {
    name: ExpandedName,
    node: NodePath,
    position: usize,
    size: usize,
    arguments: Vec<DeferredXPathValue>,
}

struct CompletedCustomCall {
    call: Rc<DeferredCustomCall>,
    result: DeferredXPathValue,
    fragment: Option<Arc<Document>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeferredXPathValue {
    Boolean(bool),
    Number(u64),
    String(String),
    ResultTreeFragment { identity: u64, value: String },
    NodeSet(Vec<NodePath>),
}

impl DeferredCustomCall {
    fn owned_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.name.local.len())
            .saturating_add(self.name.namespace.as_deref().map_or(0, str::len))
            .saturating_add(self.node.owned_bytes())
            .saturating_add(
                self.arguments
                    .iter()
                    .map(DeferredXPathValue::owned_bytes)
                    .sum::<usize>(),
            )
    }
}

impl DeferredXPathValue {
    fn owned_bytes(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::Boolean(_) | Self::Number(_) => 0,
            Self::String(value) | Self::ResultTreeFragment { value, .. } => value.len(),
            Self::NodeSet(paths) => paths.iter().map(NodePath::owned_bytes).sum(),
        })
    }
}

impl CustomCallSession {
    fn begin_attempt(&self) {
        let mut state = self.state.borrow_mut();
        state.cursor = 0;
        state.pending = None;
    }

    fn fragment(&self, identity: u64) -> Option<Arc<Document>> {
        let state = self.state.borrow();
        state
            .completed
            .iter()
            .filter_map(|completed| completed.fragment.as_ref())
            .find(|document| document.identity() == identity)
            .cloned()
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.state.borrow().retained_bytes
    }
}

struct DeferredStylesheetFunction {
    name: ExpandedName,
    session: Rc<RefCell<CustomCallState>>,
}

impl function::Function for DeferredStylesheetFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        arguments: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        context.reserve_string_allocation(deferred_call_size(
            &self.name,
            &context.node,
            &arguments,
        ))?;
        let call = DeferredCustomCall {
            name: self.name.clone(),
            node: typed_path_to(&context.node),
            position: context.position,
            size: context.size,
            arguments: arguments
                .into_iter()
                .map(defer_sxd_value)
                .collect::<std::result::Result<Vec<_>, _>>()?,
        };
        let mut state = self.session.borrow_mut();
        let cursor = state.cursor;
        state.cursor = state.cursor.saturating_add(1);
        if let Some(completed) = state.completed.get(cursor) {
            if *completed.call != call {
                return Err(function::Error::Other {
                    what: "stylesheet function continuation diverged".into(),
                });
            }
            return restore_sxd_value(&completed.result, context.node.document().root().into());
        }
        if state.pending.is_some() {
            return Err(function::Error::Other {
                what: "multiple pending stylesheet function calls".into(),
            });
        }
        state.pending = Some(Rc::new(call));
        Err(function::Error::Other {
            what: "stylesheet function evaluation suspended".into(),
        })
    }
}

fn deferred_call_size(
    name: &ExpandedName,
    node: &nodeset::Node<'_>,
    arguments: &[SxdValue<'_>],
) -> usize {
    std::mem::size_of::<DeferredCustomCall>()
        .saturating_add(name.local.len())
        .saturating_add(name.namespace.as_deref().map_or(0, str::len))
        .saturating_add(sxd_node_path_size(node))
        .saturating_add(arguments.iter().map(deferred_sxd_value_size).sum::<usize>())
}

fn deferred_sxd_value_size(value: &SxdValue<'_>) -> usize {
    std::mem::size_of::<DeferredXPathValue>().saturating_add(match value {
        SxdValue::Boolean(_) | SxdValue::Number(_) => 0,
        // Scalar payloads move out of the argument values; only their enum slots are new here.
        SxdValue::String(_) | SxdValue::ResultTreeFragment(_, _) => 0,
        SxdValue::Nodeset(nodes) => nodes.iter().map(|node| sxd_node_path_size(&node)).sum(),
    })
}

fn sxd_node_path_size(node: &nodeset::Node<'_>) -> usize {
    let mut depth = 0usize;
    let mut current = match node {
        nodeset::Node::Attribute(attribute) => attribute.parent().map(nodeset::Node::Element),
        nodeset::Node::Namespace(namespace) => Some(nodeset::Node::Element(namespace.parent)),
        node => Some(node.clone()),
    };
    while let Some(node) = current {
        current = node.parent();
        if current.is_some() {
            depth = depth.saturating_add(1);
        }
    }
    std::mem::size_of::<NodePath>()
        .saturating_add(depth.saturating_mul(std::mem::size_of::<usize>()))
        .saturating_add(match node {
            nodeset::Node::Attribute(attribute) => {
                let name = attribute.name();
                let name = name.get();
                name.namespace_uri().map_or(0, str::len) + name.local_part().len()
            }
            nodeset::Node::Namespace(namespace) => namespace.prefix().len() + namespace.uri().len(),
            _ => 0,
        })
}

fn defer_sxd_value(
    value: SxdValue<'_>,
) -> std::result::Result<DeferredXPathValue, function::Error> {
    Ok(match value {
        SxdValue::Boolean(value) => DeferredXPathValue::Boolean(value),
        SxdValue::Number(value) => DeferredXPathValue::Number(value.to_bits()),
        SxdValue::String(value) => DeferredXPathValue::String(value),
        SxdValue::ResultTreeFragment(identity, value) => {
            DeferredXPathValue::ResultTreeFragment { identity, value }
        }
        SxdValue::Nodeset(nodes) => {
            DeferredXPathValue::NodeSet(nodes.document_order().iter().map(typed_path_to).collect())
        }
    })
}

fn restore_sxd_value<'d>(
    value: &DeferredXPathValue,
    root: nodeset::Node<'d>,
) -> std::result::Result<SxdValue<'d>, function::Error> {
    Ok(match value {
        DeferredXPathValue::Boolean(value) => SxdValue::Boolean(*value),
        DeferredXPathValue::Number(bits) => SxdValue::Number(f64::from_bits(*bits)),
        DeferredXPathValue::String(value) => SxdValue::String(value.clone()),
        DeferredXPathValue::ResultTreeFragment { identity, value } => {
            SxdValue::ResultTreeFragment(*identity, value.clone())
        }
        DeferredXPathValue::NodeSet(paths) => {
            let mut nodes = nodeset::Nodeset::new();
            for path in paths {
                let node = resolve_node_path(root.clone(), path).ok_or_else(|| {
                    function::Error::Other {
                        what: "stylesheet function continuation node is stale".into(),
                    }
                })?;
                nodes.add(node);
            }
            SxdValue::Nodeset(nodes)
        }
    })
}

pub(crate) struct Evaluator {
    pub(crate) source: Document,
    package: Package,
    maps: NodeMaps,
    node_base_uris: Rc<RefCell<HashMap<NodePath, Option<String>>>>,
    expressions: RefCell<HashMap<String, XPath>>,
    pattern_matches: HashMap<PatternCacheKey, HashSet<SourceNode>>,
    generated_ids: Rc<RefCell<GeneratedIdCache>>,
    id_index: Rc<RefCell<IdIndex>>,
    key_index: Rc<RefCell<KeyIndex>>,
    unparsed_entity_index: Rc<RefCell<Vec<HashMap<String, String>>>>,
    decimal_formats: Rc<Vec<DecimalFormat>>,
    stylesheet_functions: Arc<HashSet<ExpandedName>>,
    resolver: Arc<dyn Resolver>,
    documents: HashMap<DocumentRequest, Vec<SourceNode>>,
    document_roots: Rc<RefCell<HashMap<DocumentRequest, Vec<NodePath>>>>,
    pending_document_requests: Rc<RefCell<HashSet<DocumentRequest>>>,
    resource_identities: HashMap<ResourceIdentity, ResolvedResource>,
    resource_documents: HashMap<ResourceIdentity, SourceNode>,
    result_tree_fragments: HashMap<u64, SourceNode>,
    dynamic_evaluation_depth: usize,
    source_processing: SourceProcessing,
    whitespace: Arc<[(NameTest, bool, usize, usize)]>,
    clock: Arc<dyn Clock>,
    extension_policy: ExtensionPolicy,
}

struct TemporaryStrings {
    values: Vec<String>,
    reserved_owned_bytes: usize,
}

impl TemporaryStrings {
    fn release(self, meter: &mut Meter) {
        meter.release_owned_bytes(self.reserved_owned_bytes);
    }
}

impl Evaluator {
    pub(crate) fn new<R: Resolver + 'static>(
        prepared_source: PreparedEvaluatorSource,
        principal_stylesheet: &Document,
        principal_base_uri: Option<String>,
        module_documents: &[(String, Document)],
        resolver: Arc<R>,
        meter: &mut Meter,
        source_options: EvaluatorSourceOptions,
    ) -> Result<Self> {
        // SXD receives the normalized semantic tree, not the caller's parser-specific
        // lexical node layout. Typed paths then make every cross-model identity explicit.
        let PreparedEvaluatorSource {
            document,
            remap: _,
            remap_owned_bytes: _,
            resource_identities,
        } = prepared_source;
        let mut source = document;
        reserve_stylesheet_imports(principal_stylesheet, module_documents, meter)?;
        let stylesheet_root = source.import(principal_stylesheet);
        let module_roots = module_documents
            .iter()
            .map(|(uri, document)| (uri.clone(), source.import(document)))
            .collect::<Vec<_>>();
        let package = project_semantic_document(&source, meter)?;
        let maps = NodeMaps::new(&source, meter)?;
        let mut id_index = Vec::new();
        extend_id_index(&source, &maps, 0, &mut id_index, meter)?;
        let unparsed_entity_index = build_unparsed_entity_index(&source, meter)?;
        meter_node_base_uri_entries(&source, maps.reverse.iter(), meter)?;
        let node_base_uris = Rc::new(RefCell::new(
            maps.reverse
                .iter()
                .map(|(path, node)| (path.clone(), source_base_uri(&source, node)))
                .collect(),
        ));
        let principal_request = DocumentRequest {
            href: String::new(),
            base_uri: principal_base_uri,
            empty_document: None,
        };
        let mut document_root_entries = HashMap::new();
        let mut documents = HashMap::new();
        seed_document_cache(
            principal_request,
            stylesheet_root,
            &maps,
            &mut documents,
            &mut document_root_entries,
            meter,
        )?;
        let source_root = source.root();
        let source_request = DocumentRequest {
            href: String::new(),
            base_uri: source_base_uri(&source, &SourceNode::Node(source_root)),
            empty_document: source.logical_roots().binary_search(&source_root).ok(),
        };
        seed_document_cache(
            source_request,
            source_root,
            &maps,
            &mut documents,
            &mut document_root_entries,
            meter,
        )?;
        for (uri, root) in module_roots {
            let request = DocumentRequest {
                href: String::new(),
                base_uri: Some(uri),
                empty_document: None,
            };
            seed_document_cache(
                request,
                root,
                &maps,
                &mut documents,
                &mut document_root_entries,
                meter,
            )?;
        }
        let document_roots = Rc::new(RefCell::new(document_root_entries));
        let pending_document_requests = Rc::new(RefCell::new(HashSet::new()));
        Ok(Self {
            source,
            package,
            maps,
            node_base_uris,
            expressions: RefCell::new(HashMap::new()),
            pattern_matches: HashMap::new(),
            generated_ids: Rc::new(RefCell::new(GeneratedIdCache::default())),
            id_index: Rc::new(RefCell::new(id_index)),
            key_index: Rc::new(RefCell::new(HashMap::new())),
            unparsed_entity_index: Rc::new(RefCell::new(unparsed_entity_index)),
            decimal_formats: Rc::new(Vec::new()),
            stylesheet_functions: Arc::new(HashSet::new()),
            resolver,
            documents,
            document_roots,
            pending_document_requests,
            resource_identities,
            resource_documents: HashMap::new(),
            result_tree_fragments: HashMap::new(),
            dynamic_evaluation_depth: 0,
            source_processing: source_options.processing,
            whitespace: source_options.whitespace,
            clock: source_options.clock,
            extension_policy: source_options.extension_policy,
        })
    }

    pub(crate) fn initialize_xslt(
        &mut self,
        decimal_formats: &[DecimalFormat],
        extension_functions: impl IntoIterator<Item = ExpandedName>,
    ) {
        self.decimal_formats = Rc::new(decimal_formats.to_vec());
        self.stylesheet_functions = Arc::new(extension_functions.into_iter().collect());
    }

    pub(crate) fn append_key_entry(
        &mut self,
        name: ExpandedName,
        value: String,
        node: &SourceNode,
        meter: &mut Meter,
    ) -> Result<()> {
        let mut index = self.key_index.borrow_mut();
        let Some(sxd) = self
            .maps
            .to_sxd(self.package.as_document().root().into(), node)
        else {
            return Ok(());
        };
        let document_index = self
            .source
            .logical_root_for(node)
            .and_then(|root| {
                self.source
                    .logical_roots()
                    .iter()
                    .position(|candidate| *candidate == root)
            })
            .ok_or_else(|| Error::Dynamic("key node has no logical document".into()))?;
        let path = typed_path_to(&sxd);
        meter.charge(BudgetKind::KeyEntries, 1)?;
        let path_bytes = path.owned_bytes();
        let retained_key_bytes = std::mem::size_of::<(ExpandedName, String, usize)>()
            .saturating_add(name.local.len())
            .saturating_add(name.namespace.as_deref().map_or(0, str::len))
            .saturating_add(value.len());
        match index.entry((name, value, document_index)) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                meter.charge(BudgetKind::OwnedBytes, path_bytes)?;
                entry.get_mut().push(path);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                meter.charge(
                    BudgetKind::OwnedBytes,
                    retained_key_bytes.saturating_add(path_bytes),
                )?;
                entry.insert(vec![path]);
            }
        }
        Ok(())
    }

    pub(crate) fn finish_key_index(&mut self, meter: &mut Meter) {
        clear_pattern_cache(&mut self.pattern_matches, meter);
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "XPath dynamic context and its budget/continuation state are independent inputs"
    )]
    pub(crate) fn evaluate(
        &mut self,
        expression: &Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
        variables: &dyn VariableBindings,
        meter: &mut Meter,
        custom_calls: Option<&CustomCallSession>,
    ) -> Result<XPathValue> {
        loop {
            self.pending_document_requests.borrow_mut().clear();
            if let Some(custom_calls) = custom_calls {
                custom_calls.begin_attempt();
            }
            let prepared = self.prepare_extension_calls(
                expression,
                node,
                position,
                size,
                variables,
                meter,
                custom_calls,
            )?;
            let (prepared, augmented) = prepared.parts();
            let value = if let Some(name) =
                variable_reference_name(prepared.source.trim(), &prepared.namespaces)
                && let Some(Value::StoredExpression(source)) = augmented.get(&name)
            {
                XPathValue::StoredExpression(source.clone())
            } else {
                self.evaluate_core(
                    prepared,
                    node,
                    position,
                    size,
                    augmented,
                    meter,
                    custom_calls,
                )?
            };
            let requested = self
                .pending_document_requests
                .borrow_mut()
                .drain()
                .collect::<Vec<_>>();
            if requested.is_empty() {
                return Ok(value);
            }
            let prepared_count = self.documents.len();
            self.prepare_document_requests(requested, augmented, meter)?;
            if self.documents.len() == prepared_count {
                return Err(Error::Dynamic(
                    "document() resolution made no progress".into(),
                ));
            }
        }
    }

    pub(crate) fn document_order(&self, mut nodes: Vec<SourceNode>) -> Vec<SourceNode> {
        nodes.sort_by_key(|node| self.maps.order.get(node).copied());
        nodes.dedup();
        nodes
    }

    pub(crate) fn take_custom_function_call(
        &self,
        session: &CustomCallSession,
        variables: &dyn VariableBindings,
        meter: &mut Meter,
    ) -> Result<Option<CustomFunctionCall>> {
        let pending = {
            let mut state = session.state.borrow_mut();
            let pending = state.pending.take();
            if let Some(pending) = pending.as_ref() {
                let retained = pending.owned_bytes();
                meter.charge(BudgetKind::OwnedBytes, retained)?;
                state.retained_bytes = state.retained_bytes.saturating_add(retained);
            }
            state.last_requested = pending.clone();
            pending
        };
        pending
            .map(|pending| {
                let node = self
                    .maps
                    .reverse
                    .get(&pending.node)
                    .cloned()
                    .ok_or_else(|| Error::Dynamic("stylesheet function context is stale".into()))?;
                let arguments = pending
                    .arguments
                    .iter()
                    .map(|argument| self.project_deferred_value(argument, session, variables))
                    .collect::<Result<Vec<_>>>()?;
                Ok(CustomFunctionCall {
                    name: pending.name.clone(),
                    node,
                    position: pending.position,
                    size: pending.size,
                    arguments,
                })
            })
            .transpose()
    }

    pub(crate) fn complete_custom_function_call(
        &self,
        session: &CustomCallSession,
        value: Value,
        meter: &mut Meter,
    ) -> Result<()> {
        let retained = self.deferred_public_value_size(&value)?;
        meter.charge(BudgetKind::OwnedBytes, retained)?;
        let mut state = session.state.borrow_mut();
        let call = state
            .last_requested
            .take()
            .ok_or_else(|| Error::Dynamic("stylesheet function continuation is missing".into()))?;
        let (result, fragment) = self.defer_public_value(value)?;
        state.retained_bytes = state.retained_bytes.saturating_add(retained);
        state.completed.push(CompletedCustomCall {
            call,
            result,
            fragment,
        });
        Ok(())
    }

    fn deferred_public_value_size(&self, value: &Value) -> Result<usize> {
        let payload = match value {
            Value::Boolean(_) | Value::Number(_) => 0,
            Value::String(value) | Value::StoredExpression(value) => value.len(),
            Value::NodeSet(nodes) => nodes.iter().try_fold(0usize, |total, node| {
                let path = self.maps.forward.get(node).ok_or_else(|| {
                    Error::Dynamic("stylesheet function result node is stale".into())
                })?;
                Ok::<_, Error>(total.saturating_add(path.owned_bytes()))
            })?,
            Value::ResultTreeFragment(document) => {
                let mut string_bytes = 0usize;
                document.visit_string_value(document.root(), |value| {
                    string_bytes = string_bytes.saturating_add(value.len());
                });
                std::mem::size_of::<Arc<Document>>().saturating_add(string_bytes)
            }
        };
        Ok(std::mem::size_of::<DeferredXPathValue>().saturating_add(payload))
    }

    fn project_deferred_value(
        &self,
        value: &DeferredXPathValue,
        session: &CustomCallSession,
        variables: &dyn VariableBindings,
    ) -> Result<Value> {
        Ok(match value {
            DeferredXPathValue::Boolean(value) => Value::Boolean(*value),
            DeferredXPathValue::Number(bits) => Value::Number(f64::from_bits(*bits)),
            DeferredXPathValue::String(value) => Value::String(value.clone()),
            DeferredXPathValue::NodeSet(paths) => Value::NodeSet(
                paths
                    .iter()
                    .map(|path| {
                        self.maps.reverse.get(path).cloned().ok_or_else(|| {
                            Error::Dynamic("stylesheet function argument node is stale".into())
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            DeferredXPathValue::ResultTreeFragment { identity, .. } => variables
                .result_tree_fragment(*identity)
                .or_else(|| session.fragment(*identity))
                .map(Value::ResultTreeFragment)
                .ok_or_else(|| Error::Dynamic("stale result-tree-fragment identity".into()))?,
        })
    }

    fn defer_public_value(
        &self,
        value: Value,
    ) -> Result<(DeferredXPathValue, Option<Arc<Document>>)> {
        Ok(match value {
            Value::Boolean(value) => (DeferredXPathValue::Boolean(value), None),
            Value::Number(value) => (DeferredXPathValue::Number(value.to_bits()), None),
            Value::String(value) | Value::StoredExpression(value) => {
                (DeferredXPathValue::String(value), None)
            }
            Value::NodeSet(nodes) => (
                DeferredXPathValue::NodeSet(
                    nodes
                        .iter()
                        .map(|node| {
                            self.maps.forward.get(node).cloned().ok_or_else(|| {
                                Error::Dynamic("stylesheet function result node is stale".into())
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                ),
                None,
            ),
            Value::ResultTreeFragment(document) => {
                let deferred = DeferredXPathValue::ResultTreeFragment {
                    identity: document.identity(),
                    value: document.string_value(document.root()),
                };
                (deferred, Some(document))
            }
        })
    }

    fn import_result_tree_fragment(
        &mut self,
        fragment: &Document,
        meter: &mut Meter,
    ) -> Result<SourceNode> {
        let identity = fragment.identity();
        if let Some(root) = self.result_tree_fragments.get(&identity) {
            return Ok(root.clone());
        }
        let root = self.import_document(fragment, meter)?;
        self.result_tree_fragments.insert(identity, root.clone());
        Ok(root)
    }

    fn import_document(&mut self, document: &Document, meter: &mut Meter) -> Result<SourceNode> {
        meter.charge(BudgetKind::OwnedBytes, semantic_projection_size(document))?;
        let first_new_node = self.source.nodes().len();
        let logical_root = self.source.import(document);
        let sxd_document = self.package.as_document();
        let documents = sxd_document
            .root()
            .children()
            .into_iter()
            .find_map(|child| child.element())
            .ok_or_else(|| Error::Dynamic("semantic projection root is missing".into()))?;
        project_logical_root(&self.source, logical_root, sxd_document, documents)?;
        self.maps.extend(&self.source, first_new_node, meter)?;
        extend_id_index(
            &self.source,
            &self.maps,
            first_new_node,
            &mut self.id_index.borrow_mut(),
            meter,
        )?;
        append_unparsed_entity_document(
            &self.source,
            logical_root,
            &mut self.unparsed_entity_index.borrow_mut(),
            meter,
        )?;
        meter_node_base_uri_entries(
            &self.source,
            self.maps
                .reverse
                .iter()
                .filter(|(_, node)| source_node_owner(node).0 >= first_new_node),
            meter,
        )?;
        self.node_base_uris.borrow_mut().extend(
            self.maps
                .reverse
                .iter()
                .filter(|(_, node)| source_node_owner(node).0 >= first_new_node)
                .map(|(path, node)| (path.clone(), source_base_uri(&self.source, node))),
        );
        // Pattern results are keyed by logical root. Importing a separate document adds a
        // new root but cannot change the nodes selected in roots that were already projected.
        // Retaining those entries avoids re-running every complex template pattern whenever
        // document() lazily imports another resource.
        let root = SourceNode::Node(logical_root);
        let logical_document = self.source.logical_roots().len() - 1;
        let empty_uri = DocumentRequest::relative_to(
            String::new(),
            source_base_uri(&self.source, &root),
            Some(logical_document),
        );
        self.cache_document(empty_uri, vec![root.clone()], meter)?;
        Ok(root)
    }

    fn cache_document(
        &mut self,
        request: DocumentRequest,
        nodes: Vec<SourceNode>,
        meter: &mut Meter,
    ) -> Result<()> {
        if self.documents.contains_key(&request) {
            return Ok(());
        }
        charge_document_cache_keys(&request, meter)?;
        let roots = nodes
            .iter()
            .filter_map(|node| self.maps.forward.get(node).cloned())
            .collect();
        self.document_roots
            .borrow_mut()
            .insert(request.clone(), roots);
        self.documents.insert(request, nodes);
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "extension preparation preserves the complete XPath dynamic context"
    )]
    fn prepare_extension_calls<'a>(
        &mut self,
        expression: &'a Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
        variables: &'a dyn VariableBindings,
        meter: &mut Meter,
        custom_calls: Option<&CustomCallSession>,
    ) -> Result<PreparedExtensionCalls<'a>> {
        if innermost_namespaced_call(
            &expression.source,
            &expression.namespaces,
            is_prepared_extension_call,
        )
        .is_none()
        {
            return Ok(PreparedExtensionCalls::Borrowed {
                expression,
                variables,
            });
        }
        let (extension_prefix, extension_namespace) = unused_internal_namespace(
            &expression.namespaces,
            "__xml_sec_ext",
            EXTENSION_CONTEXT_NS,
        );
        let extension_prefix = extension_prefix.into_owned();
        let extension_namespace = extension_namespace.into_owned();
        let mut prepared_expression = expression.clone();
        Arc::make_mut(&mut prepared_expression.namespaces)
            .push((extension_prefix.clone(), extension_namespace.clone()));
        let expression = &prepared_expression;
        let mut source = expression.source.clone();
        let mut augmented = VariableOverlay::new(variables);
        let mut stored_expressions = HashSet::new();
        let mut variable_index = 0usize;
        while let Some(call) =
            innermost_namespaced_call(&source, &expression.namespaces, is_prepared_extension_call)
        {
            let kind = match (call.namespace.as_str(), call.local.as_str()) {
                (EXSLT_COMMON_NS | LIBXSLT_NS | SAXON_NS | XT_NS, "node-set") => {
                    ExtensionCallKind::NodeSet
                }
                (EXSLT_COMMON_NS, "object-type") => ExtensionCallKind::ObjectType,
                (EXSLT_STRINGS_NS, "split") => ExtensionCallKind::Split,
                (EXSLT_STRINGS_NS, "tokenize") => ExtensionCallKind::Tokenize,
                (EXSLT_STRINGS_NS, "replace") => ExtensionCallKind::Replace,
                (EXSLT_DYNAMIC_NS, "evaluate") => ExtensionCallKind::DynamicEvaluate,
                (EXSLT_DYNAMIC_NS, "map") => ExtensionCallKind::DynamicMap,
                (SAXON_NS, "expression") => ExtensionCallKind::SaxonExpression,
                (SAXON_NS, "eval") => ExtensionCallKind::SaxonEval,
                (SAXON_NS, "evaluate") => ExtensionCallKind::SaxonEvaluate,
                (SAXON_NS, "line-number") => ExtensionCallKind::SaxonLineNumber,
                _ => unreachable!("extension call predicate admits only known functions"),
            };
            let is_stored_expression = matches!(kind, ExtensionCallKind::SaxonExpression);
            let value = match kind {
                ExtensionCallKind::NodeSet => {
                    if call.arguments.len() != 1 {
                        return Err(Error::Dynamic(
                            "exsl:node-set() requires one argument".into(),
                        ));
                    }
                    let argument = call.arguments[0].trim();
                    if let Some(name) = variable_reference_name(argument, &expression.namespaces)
                        && let Some(Value::ResultTreeFragment(fragment)) = augmented.get(&name)
                    {
                        let fragment = fragment.clone();
                        Value::NodeSet(vec![self.import_result_tree_fragment(&fragment, meter)?])
                    } else {
                        let value = self.evaluate_core(
                            &expression.derived(argument),
                            node,
                            position,
                            size,
                            &augmented,
                            meter,
                            custom_calls,
                        )?;
                        match value {
                            XPathValue::NodeSet(nodes) => Value::NodeSet(nodes),
                            value => {
                                let fragment = text_document(&value.string(self), meter)?;
                                let root = self.import_document(&fragment, meter)?;
                                let nodes = self.children(&root);
                                Value::NodeSet(nodes)
                            }
                        }
                    }
                }
                ExtensionCallKind::ObjectType => {
                    if call.arguments.len() != 1 {
                        return Err(Error::Dynamic(
                            "exsl:object-type() requires one argument".into(),
                        ));
                    }
                    let argument = call.arguments[0].trim();
                    let declared_name = variable_reference_name(argument, &expression.namespaces);
                    let declared = declared_name.as_ref().and_then(|name| augmented.get(name));
                    let object_type = if declared_name.as_ref().is_some_and(|name| {
                        stored_expressions.contains(name)
                            || matches!(augmented.get(name), Some(Value::StoredExpression(_)))
                    }) {
                        "external"
                    } else {
                        match declared {
                            Some(Value::ResultTreeFragment(_)) => "RTF",
                            Some(Value::NodeSet(_)) => "node-set",
                            Some(Value::Boolean(_)) => "boolean",
                            Some(Value::Number(_)) => "number",
                            Some(Value::String(_)) => "string",
                            Some(Value::StoredExpression(_)) => "external",
                            None => match self.evaluate_core(
                                &expression.derived(argument),
                                node,
                                position,
                                size,
                                &augmented,
                                meter,
                                custom_calls,
                            )? {
                                XPathValue::NodeSet(_) => "node-set",
                                XPathValue::ResultTreeFragment(_) => "RTF",
                                XPathValue::Boolean(_) => "boolean",
                                XPathValue::Number(_) => "number",
                                XPathValue::String(_) => "string",
                                XPathValue::StoredExpression(_) => "external",
                            },
                        }
                    };
                    Value::String(object_type.into())
                }
                ExtensionCallKind::Split | ExtensionCallKind::Tokenize => {
                    if !(1..=2).contains(&call.arguments.len()) {
                        return Err(Error::Dynamic(format!(
                            "{}() requires one or two arguments",
                            call.display_name
                        )));
                    }
                    let input = self
                        .evaluate_core(
                            &expression.derived(call.arguments[0].clone()),
                            node,
                            position,
                            size,
                            &augmented,
                            meter,
                            custom_calls,
                        )?
                        .into_temporary_string(self, meter)?;
                    let delimiter = if let Some(argument) = call.arguments.get(1) {
                        match self
                            .evaluate_core(
                                &expression.derived(argument.clone()),
                                node,
                                position,
                                size,
                                &augmented,
                                meter,
                                custom_calls,
                            )?
                            .into_temporary_string(self, meter)
                        {
                            Ok((value, reserved)) => (Cow::Owned(value), reserved),
                            Err(error) => {
                                meter.release_owned_bytes(input.1);
                                return Err(error);
                            }
                        }
                    } else {
                        // EXSLT gives tokenize() all four XML whitespace delimiters by default,
                        // while split() defaults to one space character:
                        // https://exslt.github.io/str/functions/tokenize/index.html
                        (
                            Cow::Borrowed(match kind {
                                ExtensionCallKind::Tokenize => " \t\r\n",
                                ExtensionCallKind::Split => " ",
                                _ => unreachable!(),
                            }),
                            0,
                        )
                    };
                    let nodes = (|| {
                        let fragment = token_document(&input.0, &delimiter.0, kind, meter)?;
                        let root = self.import_document(&fragment, meter)?;
                        Ok(self.children(&root))
                    })();
                    debug_assert!(input.1.checked_add(delimiter.1).is_some());
                    meter.release_owned_bytes(input.1 + delimiter.1);
                    let nodes = nodes?;
                    Value::NodeSet(nodes)
                }
                ExtensionCallKind::Replace => {
                    if call.arguments.len() != 3 {
                        return Err(Error::Dynamic(
                            "str:replace() requires three arguments".into(),
                        ));
                    }
                    let (input, input_owned_bytes) = self
                        .evaluate_core(
                            &expression.derived(call.arguments[0].clone()),
                            node,
                            position,
                            size,
                            &augmented,
                            meter,
                            custom_calls,
                        )?
                        .into_temporary_string(self, meter)?;
                    let searches = match self.evaluate_extension_strings(
                        expression.derived(call.arguments[1].clone()),
                        node,
                        position,
                        size,
                        &augmented,
                        meter,
                        custom_calls,
                    ) {
                        Ok(searches) => searches,
                        Err(error) => {
                            meter.release_owned_bytes(input_owned_bytes);
                            return Err(error);
                        }
                    };
                    let replacements = match self.evaluate_extension_strings(
                        expression.derived(call.arguments[2].clone()),
                        node,
                        position,
                        size,
                        &augmented,
                        meter,
                        custom_calls,
                    ) {
                        Ok(replacements) => replacements,
                        Err(error) => {
                            meter.release_owned_bytes(input_owned_bytes);
                            searches.release(meter);
                            return Err(error);
                        }
                    };
                    // libxslt implements the earlier str:replace contract by converting each
                    // replacement node to its XPath string-value. The current EXSLT text instead
                    // specifies node copies; preserving libxslt behavior is required for drop-in
                    // compatibility. https://exslt.github.io/str/functions/replace/index.html
                    let replaced =
                        replace_exslt_string(&input, &searches.values, &replacements.values, meter);
                    meter.release_owned_bytes(input_owned_bytes);
                    searches.release(meter);
                    replacements.release(meter);
                    let replaced = replaced?;
                    let fragment = text_document(&replaced, meter);
                    meter.release_owned_bytes(replaced.len());
                    let fragment = fragment?;
                    let root = self.import_document(&fragment, meter)?;
                    let nodes = self.children(&root);
                    Value::NodeSet(nodes)
                }
                ExtensionCallKind::DynamicEvaluate | ExtensionCallKind::SaxonEvaluate => {
                    if call.arguments.len() != 1 {
                        return Err(Error::Dynamic(format!(
                            "{}() requires one argument",
                            call.display_name
                        )));
                    }
                    let dynamic_source = self
                        .evaluate_core(
                            &expression.derived(call.arguments[0].clone()),
                            node,
                            position,
                            size,
                            &augmented,
                            meter,
                            custom_calls,
                        )?
                        .string(self);
                    if dynamic_source.is_empty() {
                        Value::NodeSet(Vec::new())
                    } else {
                        match self.evaluate_dynamic(
                            &expression.derived(dynamic_source),
                            node,
                            position,
                            size,
                            &augmented,
                            meter,
                            custom_calls,
                        ) {
                            Ok(value) => xpath_value_to_public(value),
                            Err(error)
                                if kind == ExtensionCallKind::DynamicEvaluate
                                    && dynamic_expression_error_is_recoverable(&error) =>
                            {
                                Value::NodeSet(Vec::new())
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
                ExtensionCallKind::SaxonExpression => {
                    if call.arguments.len() != 1 {
                        return Err(Error::Dynamic(
                            "saxon:expression() requires one argument".into(),
                        ));
                    }
                    let stored = self
                        .evaluate_core(
                            &expression.derived(call.arguments[0].clone()),
                            node,
                            position,
                            size,
                            &augmented,
                            meter,
                            custom_calls,
                        )?
                        .string(self);
                    validate_dynamic_expression(&stored, &expression.namespaces)?;
                    Value::StoredExpression(stored)
                }
                ExtensionCallKind::SaxonEval => {
                    if call.arguments.len() != 1 {
                        return Err(Error::Dynamic("saxon:eval() requires one argument".into()));
                    }
                    let Some(name) =
                        variable_reference_name(call.arguments[0].trim(), &expression.namespaces)
                    else {
                        return Err(Error::Dynamic(
                            "saxon:eval() requires a stored expression".into(),
                        ));
                    };
                    let Some(Value::StoredExpression(dynamic_source)) = augmented.get(&name) else {
                        return Err(Error::Dynamic("stored XPath expression is missing".into()));
                    };
                    xpath_value_to_public(self.evaluate_dynamic(
                        &expression.derived(dynamic_source.clone()),
                        node,
                        position,
                        size,
                        &augmented,
                        meter,
                        custom_calls,
                    )?)
                }
                ExtensionCallKind::SaxonLineNumber => {
                    if call.arguments.len() != 1 {
                        return Err(Error::Dynamic(
                            "saxon:line-number() requires one argument".into(),
                        ));
                    }
                    let value = self.evaluate_core(
                        &expression.derived(call.arguments[0].clone()),
                        node,
                        position,
                        size,
                        &augmented,
                        meter,
                        custom_calls,
                    )?;
                    let line = match value {
                        XPathValue::NodeSet(nodes) => nodes
                            .first()
                            .and_then(|node| self.source.source_line(node))
                            .unwrap_or(0),
                        _ => 0,
                    };
                    Value::Number(line as f64)
                }
                ExtensionCallKind::DynamicMap => {
                    if call.arguments.len() != 2 {
                        return Err(Error::Dynamic("dyn:map() requires two arguments".into()));
                    }
                    let XPathValue::NodeSet(nodes) = self.evaluate_core(
                        &expression.derived(call.arguments[0].clone()),
                        node,
                        position,
                        size,
                        &augmented,
                        meter,
                        custom_calls,
                    )?
                    else {
                        return Err(Error::Dynamic("dyn:map() requires a node-set".into()));
                    };
                    let dynamic_source = self
                        .evaluate_core(
                            &expression.derived(call.arguments[1].clone()),
                            node,
                            position,
                            size,
                            &augmented,
                            meter,
                            custom_calls,
                        )?
                        .string(self);
                    let nodes = self.document_order(nodes);
                    let mut result_nodes = Vec::new();
                    let mut seen = HashSet::new();
                    let mut scalars = Vec::new();
                    let total = nodes.len();
                    for (index, mapped_node) in nodes.iter().enumerate() {
                        let value = match self.evaluate_dynamic(
                            &expression.derived(dynamic_source.clone()),
                            mapped_node,
                            index + 1,
                            total,
                            &augmented,
                            meter,
                            custom_calls,
                        ) {
                            Ok(value) => value,
                            Err(error) if dynamic_expression_error_is_recoverable(&error) => {
                                continue;
                            }
                            Err(error) => return Err(error),
                        };
                        match value {
                            XPathValue::NodeSet(nodes) => {
                                for node in nodes {
                                    if seen.insert(node.clone()) {
                                        result_nodes.push(node);
                                    }
                                }
                            }
                            XPathValue::Boolean(value) => scalars
                                .push(("boolean", if value { "true" } else { "false" }.into())),
                            XPathValue::Number(value) => {
                                scalars.push(("number", crate::value::format_xpath_number(value)))
                            }
                            XPathValue::String(value) => scalars.push(("string", value)),
                            XPathValue::StoredExpression(value) => scalars.push(("string", value)),
                            XPathValue::ResultTreeFragment(document) => {
                                scalars.push(("string", document.string_value(document.root())))
                            }
                        }
                    }
                    if !scalars.is_empty() {
                        let fragment = dynamic_map_document(&scalars, meter)?;
                        let root = self.import_document(&fragment, meter)?;
                        result_nodes.extend(self.children(&root));
                    }
                    Value::NodeSet(result_nodes)
                }
            };
            let local = format!("value{variable_index}");
            variable_index += 1;
            augmented.insert(
                ExpandedName::new(Some(extension_namespace.as_str()), local.clone()),
                value,
            );
            if is_stored_expression {
                stored_expressions.insert(ExpandedName::new(
                    Some(extension_namespace.as_str()),
                    local.clone(),
                ));
            }
            source.replace_range(
                call.start..call.end,
                &format!("${extension_prefix}:{local}"),
            );
        }
        let rewritten = expression.derived(source);
        Ok(PreparedExtensionCalls::Rewritten {
            expression: rewritten,
            variables: augmented,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "extension arguments preserve the complete XPath dynamic context"
    )]
    fn evaluate_extension_strings(
        &self,
        expression: Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
        variables: &dyn VariableBindings,
        meter: &mut Meter,
        custom_calls: Option<&CustomCallSession>,
    ) -> Result<TemporaryStrings> {
        let value = self.evaluate_core(
            &expression,
            node,
            position,
            size,
            variables,
            meter,
            custom_calls,
        )?;
        let mut values = Vec::new();
        let mut reserved_owned_bytes = 0usize;
        let materialized = (|| {
            match value {
                XPathValue::NodeSet(nodes) => {
                    for node in self.document_order(nodes) {
                        reserve_temporary_vec_slot(&mut values, meter, &mut reserved_owned_bytes)?;
                        let length = self.string_value_len(&node);
                        meter.charge(BudgetKind::OwnedBytes, length)?;
                        reserved_owned_bytes = reserved_owned_bytes.saturating_add(length);
                        values.push(self.string_value_with_capacity(&node, length));
                    }
                }
                value => {
                    reserve_temporary_vec_slot(&mut values, meter, &mut reserved_owned_bytes)?;
                    let (value, temporary_bytes) = value.into_temporary_string(self, meter)?;
                    reserved_owned_bytes = reserved_owned_bytes.saturating_add(temporary_bytes);
                    values.push(value);
                }
            }
            Ok(())
        })();
        if let Err(error) = materialized {
            meter.release_owned_bytes(reserved_owned_bytes);
            return Err(error);
        }
        Ok(TemporaryStrings {
            values,
            reserved_owned_bytes,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "dynamic XPath preserves the caller's complete evaluation context"
    )]
    fn evaluate_dynamic(
        &mut self,
        expression: &Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
        variables: &dyn VariableBindings,
        meter: &mut Meter,
        custom_calls: Option<&CustomCallSession>,
    ) -> Result<XPathValue> {
        validate_dynamic_expression(&expression.source, &expression.namespaces)?;
        self.dynamic_evaluation_depth = self.dynamic_evaluation_depth.saturating_add(1);
        let depth = self.dynamic_evaluation_depth;
        let result = meter.recursion(depth.saturating_mul(32)).and_then(|()| {
            self.evaluate(
                expression,
                node,
                position,
                size,
                variables,
                meter,
                custom_calls,
            )
        });
        self.dynamic_evaluation_depth -= 1;
        result
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the XPath engine requires every component of its dynamic context"
    )]
    fn evaluate_core(
        &self,
        expression: &Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
        variables: &dyn VariableBindings,
        meter: &mut Meter,
        custom_calls: Option<&CustomCallSession>,
    ) -> Result<XPathValue> {
        let document = self.package.as_document();
        let context_node = self
            .maps
            .to_sxd(document.root().into(), node)
            .ok_or_else(|| Error::Dynamic("XPath context node is stale".into()))?;
        let normalized = normalize_xpath_for_sxd(&expression.source);
        let isolated = hide_projection_elements_from_axes(&normalized);
        let context_namespace =
            (isolated.contains("position") || isolated.contains("last")).then(|| {
                unused_internal_namespace(&expression.namespaces, "__xml_sec_ctx", CONTEXT_NS)
            });
        let rewritten = context_namespace.as_ref().map_or_else(
            || Cow::Borrowed(isolated.as_ref()),
            |(prefix, _)| rewrite_outer_context_functions(&isolated, prefix),
        );
        if !self.expressions.borrow().contains_key(rewritten.as_ref()) {
            // One input byte can produce at most one parser token. This conservative
            // node-sized allowance bounds the retained AST and cache key before insertion.
            let retained_bytes = rewritten
                .len()
                .saturating_mul(128)
                .saturating_add(std::mem::size_of::<XPath>());
            meter.charge(BudgetKind::OwnedBytes, retained_bytes)?;
            let xpath = Factory::new().build(&rewritten).map_err(|error| {
                Error::Static(format!(
                    "invalid XPath expression `{}`: {error}",
                    expression.source
                ))
            })?;
            self.expressions
                .borrow_mut()
                .insert(rewritten.as_ref().to_owned(), xpath);
        }
        let mut context = Context::new();
        context.set_document_root_resolver(projected_document_root);
        let (owned_bytes, owned_bytes_limit) = meter.usage(BudgetKind::OwnedBytes)?;
        context.set_string_allocation_limit(owned_bytes_limit.saturating_sub(owned_bytes));
        for (prefix, uri) in expression.namespaces.iter() {
            context.set_namespace(prefix, uri);
        }
        context.set_namespace("xml", "http://www.w3.org/XML/1998/namespace");
        if let Some((prefix, namespace)) = &context_namespace {
            context.set_namespace(prefix, namespace);
            context.set_variable((namespace.as_ref(), "position"), position as f64);
            context.set_variable((namespace.as_ref(), "last"), size as f64);
        }
        context.set_function(
            "current",
            CurrentNode {
                path: typed_path_to(&context_node),
            },
        );
        // XPath function objects must own their static namespace context. Share one
        // materialization across all functions registered for this evaluation.
        let function_namespaces = Arc::clone(&expression.namespaces);
        context.set_function(
            "key",
            KeyFunction {
                index: Rc::clone(&self.key_index),
                namespaces: Arc::clone(&function_namespaces),
            },
        );
        context.set_function(
            "format-number",
            FormatNumberFunction {
                formats: Rc::clone(&self.decimal_formats),
                namespaces: Arc::clone(&function_namespaces),
            },
        );
        context.set_function(
            "generate-id",
            GenerateId {
                assigned: self.generated_ids.clone(),
            },
        );
        context.set_function(
            "id",
            IdFunction {
                nodes_by_document: Rc::clone(&self.id_index),
            },
        );
        context.set_function("name", NodeNameFunction::Qualified);
        context.set_function("local-name", NodeNameFunction::Local);
        context.set_function("namespace-uri", NodeNameFunction::NamespaceUri);
        context.set_function(
            "system-property",
            SystemProperty {
                namespaces: Arc::clone(&function_namespaces),
            },
        );
        context.set_function(
            "element-available",
            ElementAvailable {
                namespaces: Arc::clone(&function_namespaces),
            },
        );
        context.set_function(
            "unparsed-entity-uri",
            UnparsedEntityUriFunction {
                documents: Rc::clone(&self.unparsed_entity_index),
            },
        );
        context.set_function("lang", LangFunction);
        register_exslt_functions(&mut context, Arc::clone(&self.clock), self.extension_policy);
        context.set_function(
            "function-available",
            FunctionAvailable {
                namespaces: function_namespaces,
                stylesheet_functions: Arc::clone(&self.stylesheet_functions),
            },
        );
        context.set_function(
            "document",
            DocumentFunction {
                static_base_uri: expression.static_base_uri.clone(),
                roots: Rc::clone(&self.document_roots),
                pending: Rc::clone(&self.pending_document_requests),
                node_base_uris: Rc::clone(&self.node_base_uris),
            },
        );
        if let Some(custom_calls) = custom_calls {
            for name in self.stylesheet_functions.iter() {
                let qname: sxd_xpath_no_unsafe::OwnedQName = name.namespace.as_deref().map_or_else(
                    || name.local.as_str().into(),
                    |namespace| (namespace, name.local.as_str()).into(),
                );
                context.set_function(
                    qname,
                    DeferredStylesheetFunction {
                        name: name.clone(),
                        session: Rc::clone(&custom_calls.state),
                    },
                );
            }
        }
        let mut variable_projection_error = false;
        variables.visit(&mut |name, value| {
            if variable_projection_error {
                return;
            }
            let qname: sxd_xpath_no_unsafe::OwnedQName = name.namespace.as_deref().map_or_else(
                || name.local.as_str().into(),
                |namespace| (namespace, name.local.as_str()).into(),
            );
            match value {
                Value::Boolean(value) => context.set_variable(qname, *value),
                Value::Number(value) => context.set_variable(qname, *value),
                Value::String(value) => {
                    let reservation = context.reserve_temporary_allocation(value.len());
                    if reservation.is_err() {
                        variable_projection_error = true;
                        return;
                    }
                    context.set_variable(qname, value.clone());
                }
                Value::StoredExpression(value) => {
                    let reservation = context.reserve_temporary_allocation(value.len());
                    if reservation.is_err() {
                        variable_projection_error = true;
                        return;
                    }
                    context.set_variable(qname, value.clone())
                }
                Value::ResultTreeFragment(document) => {
                    let length = document.string_value_len(document.root());
                    let reservation = context.reserve_temporary_allocation(length);
                    if reservation.is_err() {
                        variable_projection_error = true;
                        return;
                    }
                    context.set_variable(
                        qname,
                        SxdValue::ResultTreeFragment(
                            document.identity(),
                            document.string_value_with_capacity(document.root(), length),
                        ),
                    );
                }
                Value::NodeSet(nodes) => {
                    let mut set = nodeset::Nodeset::new();
                    for reference in nodes {
                        if let Some(node) = self.maps.to_sxd(document.root().into(), reference) {
                            if !set.contains(node.clone()) {
                                let reservation = context
                                    .reserve_temporary_allocation(std::mem::size_of_val(&node));
                                if reservation.is_err() {
                                    variable_projection_error = true;
                                    return;
                                }
                            }
                            set.add(node);
                        }
                    }
                    context.set_variable(qname, set);
                }
            }
        });
        if variable_projection_error {
            let attempted = context
                .string_allocation_exceeded()
                .expect("failed XPath allocation records its attempted total");
            return Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: owned_bytes_limit,
                actual: owned_bytes.saturating_add(attempted),
            });
        }
        let expressions = self.expressions.borrow();
        let xpath = expressions
            .get(rewritten.as_ref())
            .expect("compiled XPath was inserted into the execution cache");
        let generated_id_bytes_before = self.generated_ids.borrow().owned_bytes;
        let evaluation = xpath.evaluate(&context, context_node);
        let generated_id_bytes = self
            .generated_ids
            .borrow()
            .owned_bytes
            .saturating_sub(generated_id_bytes_before);
        meter.charge(BudgetKind::OwnedBytes, generated_id_bytes)?;
        let value = match evaluation {
            Ok(value) => value,
            Err(error) => {
                if let Some(attempted) = context.string_allocation_exceeded() {
                    return Err(Error::Budget {
                        kind: BudgetKind::OwnedBytes,
                        limit: owned_bytes_limit,
                        actual: owned_bytes.saturating_add(attempted),
                    });
                }
                let message = error.to_string();
                // sxd-xpath keeps its execution error enum private. A namespaced
                // unknown function is nevertheless unambiguous: XPath 1.0 has no
                // namespaced core functions, so this is an unavailable extension
                // capability rather than a dynamic failure of the stylesheet.
                return Err(
                    if message.starts_with("unknown function") && message.contains("prefix: Some(")
                    {
                        Error::Unsupported(format!(
                            "XPath extension function in `{}`: {message}",
                            expression.source
                        ))
                    } else {
                        Error::Dynamic(format!("XPath `{}` failed: {message}", expression.source))
                    },
                );
            }
        };
        if let SxdValue::ResultTreeFragment(identity, _) = value {
            return variables
                .result_tree_fragment(identity)
                .map(XPathValue::ResultTreeFragment)
                .or_else(|| {
                    custom_calls
                        .and_then(|session| session.fragment(identity))
                        .map(XPathValue::ResultTreeFragment)
                })
                .ok_or_else(|| Error::Dynamic("stale result-tree-fragment identity".into()));
        }
        self.maps
            .project_value(self.package.as_document().root().into(), value)
    }

    fn prepare_document_requests(
        &mut self,
        requested: Vec<DocumentRequest>,
        variables: &dyn VariableBindings,
        meter: &mut Meter,
    ) -> Result<()> {
        let mut fragments = Vec::new();
        for request in requested {
            if self.documents.contains_key(&request) {
                continue;
            }
            let fragment_offset = request.href.find('#').map(|index| index + 1);
            let resource_uri =
                fragment_offset.map_or(request.href.as_str(), |offset| &request.href[..offset - 1]);
            let resource_request = DocumentRequest {
                href: resource_uri.to_owned(),
                base_uri: request.base_uri.clone(),
                empty_document: request.empty_document.filter(|_| resource_uri.is_empty()),
            };
            let root = if let Some(nodes) = self.documents.get(&resource_request) {
                nodes.first().cloned()
            } else {
                meter.charge(BudgetKind::ExternalDocuments, 1)?;
                let resource = match self.resolver.resolve(
                    resource_uri,
                    request.base_uri.as_deref(),
                    ResolvePurpose::Document,
                ) {
                    Ok(resource) => resource,
                    Err(Error::ResourceNotFound { .. }) => {
                        self.cache_document(resource_request.clone(), Vec::new(), meter)?;
                        self.cache_document(request, Vec::new(), meter)?;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let identity_is_new = match self.resource_identities.get(&resource.identity) {
                    Some(previous) if previous != &resource => {
                        return Err(Error::StaleResource {
                            identity: resource.identity,
                        });
                    }
                    Some(_) => false,
                    None => true,
                };
                if let Some(root) = self.resource_documents.get(&resource.identity).cloned() {
                    self.cache_document(resource_request.clone(), vec![root.clone()], meter)?;
                    Some(root)
                } else {
                    let xml = decode_resource_for_xml_parse(
                        &resource.bytes,
                        resource.encoding.as_deref(),
                        meter,
                    )?;
                    let document = Document::parse(&xml, Some(&resource.canonical_uri))?;
                    let (mut document, expanded_reservation) =
                        if self.source_processing == SourceProcessing::XInclude {
                            let mut stack = vec![resource.identity.clone()];
                            let expanded = expand_xinclude_document(
                                &document,
                                self.resolver.as_ref(),
                                meter,
                                &mut self.resource_identities,
                                &mut stack,
                                1,
                            )?;
                            (expanded.document, Some(expanded.retained_owned_bytes))
                        } else {
                            (document, None)
                        };
                    if let Some((remap, remap_owned_bytes)) =
                        apply_whitespace_rules(&mut document, &self.whitespace, meter)?
                    {
                        drop(remap);
                        meter.release_owned_bytes(remap_owned_bytes);
                    }
                    let root = self.import_document(&document, meter)?;
                    if let Some(reservation) = expanded_reservation {
                        meter.release_owned_bytes(reservation);
                    }
                    meter.release_owned_bytes(xml.len().saturating_mul(2));
                    if identity_is_new {
                        self.resource_identities
                            .insert(resource.identity.clone(), resource.clone());
                    } else {
                        meter.release_owned_bytes(resource.bytes.len());
                    }
                    self.resource_documents
                        .insert(resource.identity, root.clone());
                    self.cache_document(resource_request.clone(), vec![root.clone()], meter)?;
                    Some(root)
                }
            };
            let Some(root) = root else {
                self.cache_document(request, Vec::new(), meter)?;
                continue;
            };
            if let Some(fragment_offset) = fragment_offset {
                fragments.push((request, root, fragment_offset));
            } else if request != resource_request {
                self.cache_document(request, vec![root], meter)?;
            }
        }
        for (request, root, fragment_offset) in fragments {
            let raw_fragment = &request.href[fragment_offset..];
            let (fragment, reserved_bytes) = decode_document_fragment(raw_fragment, meter)?;
            let Some(expression) = fragment
                .strip_prefix("xpointer(")
                .and_then(|fragment| fragment.strip_suffix(')'))
            else {
                if !is_ncname(&fragment) {
                    meter.release_owned_bytes(reserved_bytes);
                    return Err(Error::Unsupported(format!(
                        "document fragment `{fragment}`"
                    )));
                }
                let SourceNode::Node(logical_root) = root else {
                    meter.release_owned_bytes(reserved_bytes);
                    return Err(Error::Dynamic(
                        "document fragment root is not a document node".into(),
                    ));
                };
                let selected = self
                    .source
                    .ids()
                    .find_map(|(value, root, owner)| {
                        (root == logical_root && value == fragment)
                            .then_some(SourceNode::Node(owner))
                    })
                    .into_iter()
                    .collect();
                meter.release_owned_bytes(reserved_bytes);
                self.cache_document(request, selected, meter)?;
                continue;
            };
            let selected = self.evaluate_core(
                &Expression::generated(expression, Vec::new()),
                &root,
                1,
                1,
                variables,
                meter,
                None,
            );
            meter.release_owned_bytes(reserved_bytes);
            let selected = selected?;
            let XPathValue::NodeSet(nodes) = selected else {
                return Err(Error::Dynamic(format!(
                    "document fragment `{fragment}` did not select nodes"
                )));
            };
            self.cache_document(request, nodes, meter)?;
        }
        Ok(())
    }

    pub(crate) fn matches(
        &mut self,
        pattern: &Pattern,
        node: &SourceNode,
        variables: &HashMap<ExpandedName, Value>,
        meter: &mut Meter,
    ) -> Result<bool> {
        let source = pattern.source.trim();
        if source == "/" {
            return Ok(self
                .source
                .logical_root_for(node)
                .is_some_and(|root| matches!(node, SourceNode::Node(id) if *id == root)));
        }
        let logical_root = self
            .source
            .logical_root_for(node)
            .ok_or_else(|| Error::Dynamic("template candidate has no logical document".into()))?;
        for branch in split_pattern_branches(source) {
            let branch = branch.trim();
            if let Some(matches) =
                self.matches_simple_node_pattern(branch, &pattern.namespaces, node)?
            {
                if matches {
                    return Ok(true);
                }
                continue;
            }
            if let Some(matches) =
                self.matches_simple_attribute_pattern(branch, &pattern.namespaces, node)?
            {
                if matches {
                    return Ok(true);
                }
                continue;
            }
            let expression = if branch.starts_with('/')
                || branch.starts_with("id(")
                || branch.starts_with("key(")
            {
                branch.to_owned()
            } else {
                format!("//{branch}")
            };
            let uses_current = crate::expression::has_unprefixed_function_call(branch, "current");
            let cache_key = (!branch.contains('$') && !uses_current)
                .then(|| (expression.clone(), pattern.namespaces.clone(), logical_root));
            if let Some(cached) = cache_key
                .as_ref()
                .and_then(|key| self.pattern_matches.get(key))
            {
                if cached.contains(node) {
                    return Ok(true);
                }
                continue;
            }
            let root_node = SourceNode::Node(logical_root);
            let evaluation_node = if uses_current { node } else { &root_node };
            let value = self.evaluate(
                &Expression::generated(expression, pattern.namespaces.clone()),
                evaluation_node,
                1,
                1,
                variables,
                meter,
                None,
            )?;
            if let XPathValue::NodeSet(nodes) = value {
                let matches = nodes.contains(node);
                if let Some(cache_key) = cache_key {
                    meter.charge(
                        BudgetKind::OwnedBytes,
                        pattern_cache_entry_owned_bytes(&cache_key, nodes.len()),
                    )?;
                    self.pattern_matches
                        .insert(cache_key, nodes.into_iter().collect());
                }
                if matches {
                    return Ok(true);
                }
            } else {
                return Err(Error::Dynamic(format!(
                    "template pattern `{branch}` did not select a node-set"
                )));
            }
        }
        Ok(false)
    }

    pub(crate) fn pattern_terminal_rejects(
        &self,
        pattern: &Pattern,
        node: &SourceNode,
    ) -> Result<bool> {
        let mut saw_definitive_branch = false;
        for branch in split_pattern_branches(pattern.source.trim()) {
            let terminal = terminal_pattern_node_test(branch);
            if terminal.is_empty() {
                return Ok(false);
            }
            let candidate = if terminal.starts_with('@') {
                self.matches_simple_attribute_pattern(terminal, &pattern.namespaces, node)?
            } else {
                self.matches_simple_node_pattern(terminal, &pattern.namespaces, node)?
            };
            match candidate {
                Some(true) => return Ok(false),
                Some(false) => saw_definitive_branch = true,
                None => return Ok(false),
            }
        }
        Ok(saw_definitive_branch)
    }

    fn matches_simple_node_pattern(
        &self,
        pattern: &str,
        namespaces: &[(String, String)],
        node: &SourceNode,
    ) -> Result<Option<bool>> {
        let SourceNode::Node(id) = node else {
            return Ok(None);
        };
        let kind = &self
            .source
            .node(*id)
            .ok_or_else(|| Error::Dynamic("template node candidate is stale".into()))?
            .kind;
        if let Some(path) = simple_absolute_element_pattern_path(pattern) {
            let mut current = Some(*id);
            for segment in path.rsplit('/') {
                let segment = segment.trim_matches(crate::lexical::is_xml_whitespace);
                let Some(current_id) = current else {
                    return Ok(Some(false));
                };
                let Some(current_node) = self.source.node(current_id) else {
                    return Err(Error::Dynamic("template node candidate is stale".into()));
                };
                let NodeKind::Element { name, .. } = &current_node.kind else {
                    return Ok(Some(false));
                };
                if !element_pattern_name_matches(segment, name, namespaces)? {
                    return Ok(Some(false));
                }
                current = current_node.parent;
            }
            let matches_root = current
                .and_then(|parent| self.source.node(parent))
                .is_some_and(|node| matches!(node.kind, NodeKind::Root));
            return Ok(Some(matches_root));
        }
        if let Some((lexical, predicate)) = pattern.strip_suffix(']').and_then(|value| {
            let (lexical, predicate) = value.split_once("[@")?;
            (!predicate.contains(['[', ']'])).then_some((lexical, predicate))
        }) && let Some((attribute_name, expected)) = predicate.split_once('=')
            && let attribute_name = attribute_name.trim()
            && is_ncname(attribute_name)
            && let Some(expected) = quoted_pattern_literal(expected.trim())
        {
            let NodeKind::Element {
                name, attributes, ..
            } = kind
            else {
                return Ok(Some(false));
            };
            let lexical = lexical.trim_matches(crate::lexical::is_xml_whitespace);
            return Ok(Some(
                (lexical == "*" || element_pattern_name_matches(lexical, name, namespaces)?)
                    && attributes.iter().any(|attribute| {
                        attribute.name.namespace.is_none()
                            && attribute.name.local == attribute_name
                            && attribute.value == expected
                    }),
            ));
        }
        let result = match pattern {
            // A bare NodeTest pattern is a child/attribute-axis pattern; document
            // roots are selected only by the dedicated `/` pattern.
            "node()" => Some(!matches!(kind, NodeKind::Root)),
            "text()" => Some(matches!(kind, NodeKind::Text { .. })),
            "comment()" => Some(matches!(kind, NodeKind::Comment(_))),
            "processing-instruction()" => {
                Some(matches!(kind, NodeKind::ProcessingInstruction { .. }))
            }
            "*" => Some(matches!(kind, NodeKind::Element { .. })),
            lexical
                if !lexical.contains(['/', '[', '(', ')', '|', '@']) && !lexical.contains("::") =>
            {
                let NodeKind::Element { name, .. } = kind else {
                    return Ok(Some(false));
                };
                Some(element_pattern_name_matches(lexical, name, namespaces)?)
            }
            _ => None,
        };
        Ok(result)
    }

    fn matches_simple_attribute_pattern(
        &self,
        pattern: &str,
        namespaces: &[(String, String)],
        node: &SourceNode,
    ) -> Result<Option<bool>> {
        let Some(lexical) = crate::lexical::strip_xpath_attribute_axis(pattern) else {
            return Ok(None);
        };
        if lexical.contains(['/', '[', '(', ')']) {
            return Ok(None);
        }
        let SourceNode::Attribute { owner, index } = node else {
            return Ok(Some(false));
        };
        let attribute = self
            .source
            .node(*owner)
            .and_then(|node| match &node.kind {
                NodeKind::Element { attributes, .. } => attributes.get(*index),
                _ => None,
            })
            .ok_or_else(|| Error::Dynamic("template attribute candidate is stale".into()))?;
        if lexical == "*" {
            return Ok(Some(true));
        }
        if let Some((prefix, local)) = lexical.split_once(':') {
            let namespace = namespaces
                .iter()
                .find(|(candidate, _)| candidate == prefix)
                .map(|(_, namespace)| namespace.as_str())
                .ok_or_else(|| Error::Static(format!("unbound pattern prefix {prefix}")))?;
            return Ok(Some(
                attribute.name.namespace.as_deref() == Some(namespace)
                    && (local == "*" || attribute.name.local == local),
            ));
        }
        Ok(Some(
            attribute.name.namespace.is_none() && attribute.name.local == lexical,
        ))
    }

    pub(crate) fn children(&self, node: &SourceNode) -> Vec<SourceNode> {
        match node {
            SourceNode::Node(id) => self
                .source
                .node(*id)
                .map(|node| {
                    node.children
                        .iter()
                        .copied()
                        .map(SourceNode::Node)
                        .collect()
                })
                .unwrap_or_default(),
            SourceNode::Attribute { .. } | SourceNode::Namespace { .. } => Vec::new(),
        }
    }

    pub(crate) fn attributes(&self, node: &SourceNode) -> Vec<SourceNode> {
        let SourceNode::Node(owner) = node else {
            return Vec::new();
        };
        let count = self
            .source
            .node(*owner)
            .and_then(|node| match &node.kind {
                NodeKind::Element { attributes, .. } => Some(attributes.len()),
                _ => None,
            })
            .unwrap_or_default();
        (0..count)
            .map(|index| SourceNode::Attribute {
                owner: *owner,
                index,
            })
            .collect()
    }

    pub(crate) fn preceding_nonempty_comment(&self, node: &SourceNode) -> Vec<SourceNode> {
        let SourceNode::Node(id) = node else {
            return Vec::new();
        };
        let Some(parent) = self.source.node(*id).and_then(|node| node.parent) else {
            return Vec::new();
        };
        let Some(parent) = self.source.node(parent) else {
            return Vec::new();
        };
        let Some(position) = parent.children.iter().position(|child| child == id) else {
            return Vec::new();
        };
        parent.children[..position]
            .iter()
            .rev()
            .find(|candidate| {
                !self
                    .source
                    .string_value(**candidate)
                    .trim_matches(crate::lexical::is_xml_whitespace)
                    .is_empty()
            })
            .filter(|candidate| {
                self.source
                    .node(**candidate)
                    .is_some_and(|node| matches!(node.kind, NodeKind::Comment(_)))
            })
            .map(|candidate| vec![SourceNode::Node(*candidate)])
            .unwrap_or_default()
    }

    pub(crate) fn select_child_axis(
        &self,
        expression: &Expression,
        node: &SourceNode,
    ) -> Result<Option<Vec<SourceNode>>> {
        let source = expression.source.trim();
        if source.contains('|') && source != "*|text()" {
            return Ok(None);
        }
        let steps = source.split('/').collect::<Vec<_>>();
        if steps.is_empty()
            || steps.iter().any(|step| {
                step.is_empty()
                    || (step.contains(['[', ']', '(', ')', '@'])
                        && !matches!(*step, "text()" | "*|text()"))
                    || step.contains("::")
            })
        {
            return Ok(None);
        }
        if steps
            .iter()
            .any(|step| !matches!(*step, "*" | "text()" | "*|text()") && !is_lexical_qname(step))
        {
            return Ok(None);
        }

        let mut selected = vec![node.clone()];
        for step in steps {
            let mut next = Vec::new();
            for parent in &selected {
                for child in self.children(parent) {
                    let SourceNode::Node(id) = child else {
                        continue;
                    };
                    let Some(candidate) = self.source.node(id) else {
                        continue;
                    };
                    let matches = match step {
                        "*" => matches!(candidate.kind, NodeKind::Element { .. }),
                        "text()" => matches!(candidate.kind, NodeKind::Text { .. }),
                        "*|text()" => matches!(
                            candidate.kind,
                            NodeKind::Element { .. } | NodeKind::Text { .. }
                        ),
                        lexical => match &candidate.kind {
                            NodeKind::Element { name, .. } => {
                                element_pattern_name_matches(lexical, name, &expression.namespaces)?
                            }
                            _ => false,
                        },
                    };
                    if matches {
                        next.push(SourceNode::Node(id));
                    }
                }
            }
            selected = next;
        }
        Ok(Some(selected))
    }

    pub(crate) fn string_value(&self, node: &SourceNode) -> String {
        self.string_value_with_capacity(node, 0)
    }

    fn string_value_with_capacity(&self, node: &SourceNode, capacity: usize) -> String {
        let mut output = String::with_capacity(capacity);
        match node {
            SourceNode::Node(id) => return self.source.string_value_with_capacity(*id, capacity),
            SourceNode::Attribute { owner, index } => self
                .source
                .node(*owner)
                .and_then(|node| match &node.kind {
                    NodeKind::Element { attributes, .. } => attributes
                        .get(*index)
                        .map(|attribute| attribute.value.as_str()),
                    _ => None,
                })
                .map(|value| output.push_str(value)),
            SourceNode::Namespace { owner, index } => self
                .source
                .node(*owner)
                .and_then(|node| match &node.kind {
                    NodeKind::Element { namespaces, .. } => namespaces
                        .get(*index)
                        .map(|namespace| namespace.uri.as_str()),
                    _ => None,
                })
                .map(|value| output.push_str(value)),
        };
        output
    }

    pub(crate) fn string_value_len(&self, node: &SourceNode) -> usize {
        let mut length = 0usize;
        self.visit_string_value(node, |value| {
            debug_assert!(length.checked_add(value.len()).is_some());
            length += value.len();
        });
        length
    }

    pub(crate) fn visit_string_value(&self, node: &SourceNode, mut visit: impl FnMut(&str)) {
        match node {
            SourceNode::Node(id) => self.source.visit_string_value(*id, visit),
            SourceNode::Attribute { owner, index } => {
                if let Some(value) = self.source.node(*owner).and_then(|node| match &node.kind {
                    NodeKind::Element { attributes, .. } => attributes
                        .get(*index)
                        .map(|attribute| attribute.value.as_str()),
                    _ => None,
                }) {
                    visit(value);
                }
            }
            SourceNode::Namespace { owner, index } => {
                if let Some(value) = self.source.node(*owner).and_then(|node| match &node.kind {
                    NodeKind::Element { namespaces, .. } => namespaces
                        .get(*index)
                        .map(|namespace| namespace.uri.as_str()),
                    _ => None,
                }) {
                    visit(value);
                }
            }
        }
    }

    pub(crate) fn is_text_node(&self, node: &SourceNode) -> bool {
        matches!(node, SourceNode::Node(id) if self.source.node(*id).is_some_and(|node| matches!(node.kind, NodeKind::Text { .. })))
    }

    pub(crate) fn is_element_node(&self, node: &SourceNode) -> bool {
        matches!(node, SourceNode::Node(id) if self.source.node(*id).is_some_and(|node| matches!(node.kind, NodeKind::Element { .. })))
    }

    pub(crate) fn visit_qualified_name(&self, node: &SourceNode, mut visit: impl FnMut(&str)) {
        if let SourceNode::Namespace { owner, index } = node {
            if let Some(prefix) = self.source.node(*owner).and_then(|node| match &node.kind {
                NodeKind::Element { namespaces, .. } => namespaces
                    .get(*index)
                    .and_then(|namespace| namespace.prefix.as_deref()),
                _ => None,
            }) {
                visit(prefix);
            }
            return;
        }
        let named = match node {
            SourceNode::Node(id) => self.source.node(*id).and_then(|node| match &node.kind {
                NodeKind::Element { name, prefix, .. } => Some((name, prefix.as_deref())),
                _ => None,
            }),
            SourceNode::Attribute { owner, index } => {
                self.source.node(*owner).and_then(|node| match &node.kind {
                    NodeKind::Element { attributes, .. } => attributes
                        .get(*index)
                        .map(|attribute| (&attribute.name, attribute.prefix.as_deref())),
                    _ => None,
                })
            }
            SourceNode::Namespace { .. } => None,
        };
        if let SourceNode::Node(id) = node
            && let Some(node) = self.source.node(*id)
            && let NodeKind::ProcessingInstruction { target, .. } = &node.kind
        {
            visit(target);
            return;
        }
        let Some((name, prefix)) = named else {
            return;
        };
        if let Some(prefix) = prefix {
            visit(prefix);
            visit(":");
        }
        visit(&name.local);
    }

    pub(crate) fn relative_nodes(
        &self,
        path: &str,
        node: &SourceNode,
        namespaces: &[(String, String)],
        meter: &mut Meter,
    ) -> Result<Option<(Vec<SourceNode>, usize)>> {
        let mut reserved_owned_bytes = 0usize;
        let result = (|| {
            let mut selected = Vec::new();
            reserve_temporary_vec_slot(&mut selected, meter, &mut reserved_owned_bytes)?;
            selected.push(node.clone());
            for step in path.split('/') {
                if step == "." {
                    continue;
                }
                let mut next = Vec::new();
                match step {
                    ".." => {
                        for parent in selected.iter().filter_map(|node| self.parent_node(node)) {
                            reserve_temporary_vec_slot(
                                &mut next,
                                meter,
                                &mut reserved_owned_bytes,
                            )?;
                            next.push(parent);
                        }
                    }
                    "text()" => {
                        for parent in &selected {
                            let SourceNode::Node(parent) = parent else {
                                continue;
                            };
                            let Some(parent) = self.source.node(*parent) else {
                                continue;
                            };
                            for child in &parent.children {
                                let candidate = SourceNode::Node(*child);
                                if self.is_text_node(&candidate) {
                                    reserve_temporary_vec_slot(
                                        &mut next,
                                        meter,
                                        &mut reserved_owned_bytes,
                                    )?;
                                    next.push(candidate);
                                }
                            }
                        }
                    }
                    attribute if attribute.starts_with('@') => {
                        let lexical = &attribute[1..];
                        for parent in &selected {
                            let SourceNode::Node(owner) = parent else {
                                continue;
                            };
                            let owner = *owner;
                            let attribute_count =
                                self.source.node(owner).map_or(0, |node| match &node.kind {
                                    NodeKind::Element { attributes, .. } => attributes.len(),
                                    _ => 0,
                                });
                            for index in 0..attribute_count {
                                let candidate = SourceNode::Attribute { owner, index };
                                if self.attribute_name_matches(&candidate, lexical, namespaces)? {
                                    reserve_temporary_vec_slot(
                                        &mut next,
                                        meter,
                                        &mut reserved_owned_bytes,
                                    )?;
                                    next.push(candidate);
                                }
                            }
                        }
                    }
                    lexical if is_lexical_qname(lexical) => {
                        for parent in &selected {
                            let SourceNode::Node(parent) = parent else {
                                continue;
                            };
                            let Some(parent) = self.source.node(*parent) else {
                                continue;
                            };
                            for child in &parent.children {
                                let matches = self.source.node(*child).is_some_and(|node| {
                                    matches!(&node.kind, NodeKind::Element { name, .. } if element_pattern_name_matches(lexical, name, namespaces).unwrap_or(false))
                                });
                                if matches {
                                    reserve_temporary_vec_slot(
                                        &mut next,
                                        meter,
                                        &mut reserved_owned_bytes,
                                    )?;
                                    next.push(SourceNode::Node(*child));
                                }
                            }
                        }
                    }
                    _ => return Ok(None),
                }
                let retired_bytes = selected
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceNode>());
                drop(selected);
                meter.release_owned_bytes(retired_bytes);
                reserved_owned_bytes -= retired_bytes;
                selected = next;
            }
            Ok(Some((selected, reserved_owned_bytes)))
        })();
        if result.is_err() || matches!(result, Ok(None)) {
            meter.release_owned_bytes(reserved_owned_bytes);
        }
        result
    }

    fn parent_node(&self, node: &SourceNode) -> Option<SourceNode> {
        match node {
            SourceNode::Node(id) => self.source.node(*id)?.parent.map(SourceNode::Node),
            SourceNode::Attribute { owner, .. } | SourceNode::Namespace { owner, .. } => {
                self.source.node(*owner).map(|_| SourceNode::Node(*owner))
            }
        }
    }

    fn attribute_name_matches(
        &self,
        node: &SourceNode,
        lexical: &str,
        namespaces: &[(String, String)],
    ) -> Result<bool> {
        let SourceNode::Attribute { owner, index } = node else {
            return Ok(false);
        };
        let Some(attribute) = self.source.node(*owner).and_then(|node| match &node.kind {
            NodeKind::Element { attributes, .. } => attributes.get(*index),
            _ => None,
        }) else {
            return Ok(false);
        };
        element_pattern_name_matches(lexical, &attribute.name, namespaces)
    }
}

fn reserve_stylesheet_imports(
    principal_stylesheet: &Document,
    module_documents: &[(String, Document)],
    meter: &mut Meter,
) -> Result<()> {
    let clone_bytes = module_documents.iter().fold(
        principal_stylesheet.estimated_clone_bytes(),
        |total, (_, document)| total.saturating_add(document.estimated_clone_bytes()),
    );
    meter.charge(BudgetKind::OwnedBytes, clone_bytes)
}

fn terminal_pattern_node_test(branch: &str) -> &str {
    let branch = branch.trim();
    let mut quote = None;
    let mut predicate_depth = 0usize;
    let mut parenthesis_depth = 0usize;
    let mut terminal_start = 0usize;
    let mut terminal_end = branch.len();
    for (index, character) in branch.char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '[' => {
                if predicate_depth == 0 && parenthesis_depth == 0 {
                    terminal_end = terminal_end.min(index);
                }
                predicate_depth += 1;
            }
            ']' => predicate_depth = predicate_depth.saturating_sub(1),
            '(' if predicate_depth == 0 => parenthesis_depth += 1,
            ')' if predicate_depth == 0 => parenthesis_depth = parenthesis_depth.saturating_sub(1),
            '/' if predicate_depth == 0 && parenthesis_depth == 0 => {
                terminal_start = index + 1;
                terminal_end = branch.len();
            }
            _ => {}
        }
    }
    branch[terminal_start..terminal_end].trim()
}

fn simple_absolute_element_pattern_path(pattern: &str) -> Option<&str> {
    let remainder = pattern.strip_prefix('/')?;
    if remainder.is_empty() || remainder.starts_with('/') {
        return None;
    }
    remainder
        .split('/')
        .map(|segment| segment.trim_matches(crate::lexical::is_xml_whitespace))
        .all(|segment| {
            !segment.is_empty()
                && !segment.contains(['[', ']', '(', ')', '|', '@', '*'])
                && !segment.contains("::")
        })
        .then_some(remainder)
}

fn project_semantic_document(source: &Document, meter: &mut Meter) -> Result<Package> {
    meter.charge(BudgetKind::OwnedBytes, semantic_projection_size(source))?;
    let package = Package::new();
    let document = package.as_document();
    let documents = document.create_element(QName::new(DOCUMENTS_ELEMENT));
    document.root().append_child(documents);

    for logical_root in source.logical_roots() {
        project_logical_root(source, *logical_root, document, documents)?;
    }
    Ok(package)
}

fn project_logical_root<'d>(
    source: &Document,
    logical_root: NodeId,
    document: SxdDocument<'d>,
    documents: SxdElement<'d>,
) -> Result<()> {
    let wrapper = document.create_element(QName::new(DOCUMENT_ELEMENT));
    documents.append_child(wrapper);
    let root = source
        .node(logical_root)
        .ok_or_else(|| Error::Dynamic("missing logical document root".into()))?;
    let mut pending = root
        .children
        .iter()
        .rev()
        .map(|child| (*child, wrapper))
        .collect::<Vec<_>>();
    while let Some((id, parent)) = pending.pop() {
        let node = source
            .node(id)
            .ok_or_else(|| Error::Dynamic(format!("stale semantic node {id:?}")))?;
        match &node.kind {
            NodeKind::Root => {
                pending.extend(node.children.iter().rev().map(|child| (*child, parent)));
            }
            NodeKind::Element {
                name,
                prefix,
                attributes,
                namespaces,
            } => {
                let element = document.create_element(QName::with_namespace_uri(
                    name.namespace.as_deref(),
                    &name.local,
                ));
                element.set_preferred_prefix(prefix.as_deref());
                for namespace in namespaces {
                    if let Some(prefix) = &namespace.prefix {
                        element.register_prefix(prefix, &namespace.uri);
                    } else {
                        element.set_default_namespace_uri(Some(&namespace.uri));
                        element.register_prefix("", &namespace.uri);
                    }
                }
                for attribute in attributes {
                    let projected = element.set_attribute_value(
                        QName::with_namespace_uri(
                            attribute.name.namespace.as_deref(),
                            &attribute.name.local,
                        ),
                        &attribute.value,
                    );
                    projected.set_preferred_prefix(attribute.prefix.as_deref());
                }
                parent.append_child(element);
                pending.extend(node.children.iter().rev().map(|child| (*child, element)));
            }
            NodeKind::Text { value, .. } => parent.append_child(document.create_text(value)),
            NodeKind::Comment(value) => parent.append_child(document.create_comment(value)),
            NodeKind::ProcessingInstruction { target, value } => parent
                .append_child(document.create_processing_instruction(target, value.as_deref())),
        }
    }
    Ok(())
}

fn semantic_projection_size(source: &Document) -> usize {
    source
        .nodes()
        .map(|(_, node)| match &node.kind {
            NodeKind::Root => 0,
            NodeKind::Text { value, .. } | NodeKind::Comment(value) => value.len(),
            NodeKind::ProcessingInstruction { target, value } => {
                target.len() + value.as_deref().map_or(0, str::len)
            }
            NodeKind::Element {
                name,
                prefix,
                attributes,
                namespaces,
            } => {
                name.local.len()
                    + name.namespace.as_deref().map_or(0, str::len)
                    + prefix.as_deref().map_or(0, str::len)
                    + attributes
                        .iter()
                        .map(|attribute| {
                            attribute.name.local.len()
                                + attribute.name.namespace.as_deref().map_or(0, str::len)
                                + attribute.prefix.as_deref().map_or(0, str::len)
                                + attribute.value.len()
                        })
                        .sum::<usize>()
                    + namespaces
                        .iter()
                        .map(|namespace| {
                            namespace.prefix.as_deref().map_or(0, str::len) + namespace.uri.len()
                        })
                        .sum::<usize>()
            }
        })
        .sum()
}

fn split_pattern_branches(source: &str) -> Vec<&str> {
    let mut branches = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut quote = None;
    for (index, character) in source.char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => {
                branches.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    branches.push(&source[start..]);
    branches
}

#[derive(Debug, Clone)]
pub(crate) enum XPathValue {
    NodeSet(Vec<SourceNode>),
    ResultTreeFragment(Arc<Document>),
    Boolean(bool),
    Number(f64),
    String(String),
    StoredExpression(String),
}
impl XPathValue {
    pub(crate) fn boolean(&self) -> bool {
        match self {
            Self::NodeSet(nodes) => !nodes.is_empty(),
            Self::ResultTreeFragment(_) => true,
            Self::Boolean(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(value) => !value.is_empty(),
            Self::StoredExpression(value) => !value.is_empty(),
        }
    }
    pub(crate) fn string(&self, evaluator: &Evaluator) -> String {
        match self {
            Self::NodeSet(nodes) => nodes
                .first()
                .map(|node| evaluator.string_value(node))
                .unwrap_or_default(),
            Self::ResultTreeFragment(document) => document.string_value(document.root()),
            Self::Boolean(true) => "true".into(),
            Self::Boolean(false) => "false".into(),
            Self::Number(value) => crate::value::format_xpath_number(*value),
            Self::String(value) => value.clone(),
            Self::StoredExpression(value) => value.clone(),
        }
    }
    pub(crate) fn into_string(self, evaluator: &Evaluator) -> String {
        match self {
            Self::String(value) | Self::StoredExpression(value) => value,
            value => value.string(evaluator),
        }
    }

    pub(crate) fn into_temporary_string(
        self,
        evaluator: &Evaluator,
        meter: &mut Meter,
    ) -> Result<(String, usize)> {
        match self {
            Self::String(value) | Self::StoredExpression(value) => Ok((value, 0)),
            Self::NodeSet(nodes) => {
                let Some(node) = nodes.first() else {
                    return Ok((String::new(), 0));
                };
                let length = evaluator.string_value_len(node);
                meter.charge(BudgetKind::OwnedBytes, length)?;
                Ok((evaluator.string_value_with_capacity(node, length), length))
            }
            Self::ResultTreeFragment(document) => {
                let length = document.string_value_len(document.root());
                meter.charge(BudgetKind::OwnedBytes, length)?;
                Ok((
                    document.string_value_with_capacity(document.root(), length),
                    length,
                ))
            }
            Self::Boolean(value) => {
                let value = if value { "true" } else { "false" };
                meter.charge(BudgetKind::OwnedBytes, value.len())?;
                Ok((value.into(), value.len()))
            }
            Self::Number(value) => {
                // XPath decimal expansion of a finite f64 needs at most 327 bytes (the negative
                // smallest subnormal is the longest). Reserve that bound before formatting.
                const MAX_XPATH_F64_BYTES: usize = 327;
                meter.charge(BudgetKind::OwnedBytes, MAX_XPATH_F64_BYTES)?;
                let value = crate::value::format_xpath_number(value);
                let retained = value.len();
                debug_assert!(retained <= MAX_XPATH_F64_BYTES);
                meter.release_owned_bytes(MAX_XPATH_F64_BYTES - retained);
                Ok((value, retained))
            }
        }
    }
    pub(crate) fn number(&self, evaluator: &Evaluator) -> f64 {
        match self {
            Self::Number(value) => *value,
            Self::Boolean(true) => 1.0,
            Self::Boolean(false) => 0.0,
            Self::String(value) => xpath_number(value),
            Self::StoredExpression(value) => xpath_number(value),
            Self::NodeSet(_) => xpath_number(&self.string(evaluator)),
            Self::ResultTreeFragment(document) => {
                xpath_number(&document.string_value(document.root()))
            }
        }
    }
}

pub(crate) fn xpath_number(value: &str) -> f64 {
    parse_xpath_number(value).unwrap_or(f64::NAN)
}

pub(crate) fn parse_xpath_number(value: &str) -> Option<f64> {
    // XPath 1.0 §§3.5 and 3.7 permit only decimal Number tokens, not host-language
    // spellings such as NaN or infinity: https://www.w3.org/TR/1999/REC-xpath-19991116/#numbers
    let trimmed = value.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    trimmed.strip_prefix('-').map_or_else(
        || parse_xpath_number_token(trimmed),
        |magnitude| parse_xpath_number_token(magnitude).map(|value| -value),
    )
}

pub(crate) fn parse_xpath_number_token(value: &str) -> Option<f64> {
    // XPath 1.0 section 3.7, productions 30-31, has no sign or exponent:
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    let valid = !value.is_empty()
        && value.split_once('.').map_or_else(
            || value.chars().all(|character| character.is_ascii_digit()),
            |(integer, fraction)| {
                (integer.is_empty() || integer.chars().all(|c| c.is_ascii_digit()))
                    && !(integer.is_empty() && fraction.is_empty())
                    && fraction.chars().all(|c| c.is_ascii_digit())
            },
        );
    valid.then(|| value.parse().ok()).flatten()
}

const XINCLUDE_NS: &str = "http://www.w3.org/2001/XInclude";

struct ExpandedXIncludeDocument {
    document: Document,
    principal_mapping: Option<HashMap<NodeId, NodeId>>,
    retained_owned_bytes: usize,
}

fn expand_xinclude_document(
    source: &Document,
    resolver: &dyn Resolver,
    meter: &mut Meter,
    identities: &mut HashMap<ResourceIdentity, ResolvedResource>,
    include_stack: &mut Vec<ResourceIdentity>,
    depth: usize,
) -> Result<ExpandedXIncludeDocument> {
    meter.recursion(depth)?;
    let source_nodes = source.node_count();
    let source_clone_bytes = source.estimated_clone_bytes();
    let mapping_bytes = xinclude_remap_bytes(source_nodes);
    let pending_bytes = xinclude_pending_bytes(source_nodes);
    meter.charge(
        BudgetKind::OwnedBytes,
        source_clone_bytes
            .saturating_add(mapping_bytes)
            .saturating_add(pending_bytes),
    )?;
    let mut retained_owned_bytes = source_clone_bytes.saturating_add(mapping_bytes);
    let base_uri = source
        .node(source.root())
        .and_then(|node| node.base_uri.clone());
    let mut output = Document::empty(base_uri);
    let mut principal_mapping = HashMap::with_capacity(source_nodes);
    principal_mapping.insert(source.root(), output.root());
    let mut pending = Vec::with_capacity(source_nodes.saturating_sub(1));
    pending.extend(
        source
            .node(source.root())
            .into_iter()
            .flat_map(|root| root.children.iter().rev())
            .map(|child| (*child, output.root())),
    );
    while let Some((source_id, target_parent)) = pending.pop() {
        let node = source
            .node(source_id)
            .ok_or_else(|| Error::Xml("XInclude source node is stale".into()))?;
        let is_include = matches!(
            &node.kind,
            NodeKind::Element { name, .. }
                if name.namespace.as_deref() == Some(XINCLUDE_NS) && name.local == "include"
        );
        if matches!(
            &node.kind,
            NodeKind::Element { name, .. }
                if name.namespace.as_deref() == Some(XINCLUDE_NS) && name.local == "fallback"
        ) {
            // XInclude 1.0 section 3.1 permits xi:fallback only as a direct xi:include child.
            // https://www.w3.org/TR/xinclude/#syntax
            return Err(Error::Xml(
                "xi:fallback must be a direct child of xi:include".into(),
            ));
        }
        if !is_include {
            let Some(target) = output.append_node_from(target_parent, node) else {
                continue;
            };
            principal_mapping.insert(source_id, target);
            pending.extend(node.children.iter().rev().map(|child| (*child, target)));
            continue;
        }

        let fallback = validate_xinclude_children(source, node)?;
        let result = resolve_xinclude(
            source,
            source_id,
            resolver,
            meter,
            identities,
            include_stack,
            depth,
        );
        match result {
            Ok(XIncludeContent::Xml(included)) => {
                let included_nodes = included.document.node_count();
                let copied_bytes = included.document.estimated_clone_bytes();
                let remap_bytes = xinclude_remap_bytes(included_nodes);
                meter.charge(
                    BudgetKind::OwnedBytes,
                    copied_bytes.saturating_add(remap_bytes),
                )?;
                let mut included_mapping = HashMap::with_capacity(included_nodes);
                if let Some(root) = included.document.node(included.document.root()) {
                    for child in root.children.iter().copied() {
                        output.append_subtree_from(
                            target_parent,
                            &included.document,
                            child,
                            &mut included_mapping,
                        );
                    }
                }
                output.remap_ids_from(&included.document, &included_mapping)?;
                output.merge_unparsed_entities_from(&included.document, output.root())?;
                meter
                    .release_owned_bytes(remap_bytes.saturating_add(included.retained_owned_bytes));
                retained_owned_bytes = retained_owned_bytes.saturating_add(copied_bytes);
            }
            Ok(XIncludeContent::Text(value, base_uri)) => {
                output.push_coalesced(
                    target_parent,
                    NodeKind::Text {
                        value,
                        disable_output_escaping: false,
                    },
                    Some(base_uri),
                );
            }
            Err(XIncludeFailure::Fatal(error)) => return Err(error),
            Err(XIncludeFailure::Resource(error)) => {
                let Some(fallback) = fallback else {
                    return Err(error);
                };
                if let Some(fallback) = source.node(fallback) {
                    pending.extend(
                        fallback
                            .children
                            .iter()
                            .rev()
                            .map(|child| (*child, target_parent)),
                    );
                }
            }
        }
    }
    output.remap_ids_from(source, &principal_mapping)?;
    output.merge_unparsed_entities_from(source, output.root())?;
    meter.release_owned_bytes(pending_bytes);
    Ok(ExpandedXIncludeDocument {
        document: output,
        principal_mapping: Some(principal_mapping),
        retained_owned_bytes,
    })
}

fn validate_xinclude_children(source: &Document, include: &Node) -> Result<Option<NodeId>> {
    let mut fallback = None;
    for child in &include.children {
        let Some(Node {
            kind: NodeKind::Element { name, .. },
            ..
        }) = source.node(*child)
        else {
            continue;
        };
        if name.namespace.as_deref() != Some(XINCLUDE_NS) {
            continue;
        }
        // XInclude 1.0 section 3.1 permits local/foreign extension children (which are
        // ignored), but makes every XInclude-namespace child except one fallback fatal.
        // https://www.w3.org/TR/xinclude/#syntax
        if name.local != "fallback" {
            return Err(Error::Xml(format!(
                "XInclude namespace child xi:{} is not permitted in xi:include",
                name.local
            )));
        }
        if fallback.replace(*child).is_some() {
            return Err(Error::Xml(
                "XInclude xi:include permits at most one xi:fallback child".into(),
            ));
        }
    }
    Ok(fallback)
}

fn decode_document_fragment<'a>(
    fragment: &'a str,
    meter: &mut Meter,
) -> Result<(Cow<'a, str>, usize)> {
    if !fragment.as_bytes().contains(&b'%') {
        return Ok((Cow::Borrowed(fragment), 0));
    }

    let bytes = fragment.as_bytes();
    let mut cursor = 0usize;
    let mut decoded_len = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let encoded = bytes.get(cursor + 1..cursor + 3).ok_or_else(|| {
                Error::Unsupported("document fragment has a truncated percent escape".into())
            })?;
            if !encoded.iter().all(u8::is_ascii_hexdigit) {
                return Err(Error::Unsupported(
                    "document fragment has an invalid percent escape".into(),
                ));
            }
            cursor += 3;
        } else {
            cursor += 1;
        }
        decoded_len = decoded_len.checked_add(1).ok_or_else(|| {
            Error::Unsupported("document fragment decoded length overflow".into())
        })?;
    }

    meter.charge(BudgetKind::OwnedBytes, decoded_len)?;
    let mut decoded = Vec::with_capacity(decoded_len);
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let high = hex_value(bytes[cursor + 1]);
            let low = hex_value(bytes[cursor + 2]);
            decoded.push((high << 4) | low);
            cursor += 3;
        } else {
            decoded.push(bytes[cursor]);
            cursor += 1;
        }
    }
    // XPointer Framework appendix B encodes pointer characters as UTF-8 octets;
    // RFC 3986 section 2.1 defines each percent triplet as one encoded octet.
    // https://www.w3.org/TR/xptr-framework/#escaping
    // https://www.rfc-editor.org/rfc/rfc3986#section-2.1
    let decoded = String::from_utf8(decoded).map_err(|_| {
        meter.release_owned_bytes(decoded_len);
        Error::Unsupported("document fragment percent escapes are not valid UTF-8".into())
    })?;
    Ok((Cow::Owned(decoded), decoded_len))
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("percent escape was validated before decoding"),
    }
}

fn xinclude_pending_bytes(node_count: usize) -> usize {
    node_count.saturating_mul(std::mem::size_of::<(NodeId, NodeId)>())
}

fn xinclude_remap_bytes(node_count: usize) -> usize {
    node_count.saturating_mul(
        std::mem::size_of::<(NodeId, NodeId)>().saturating_add(std::mem::size_of::<usize>()),
    )
}

enum XIncludeContent {
    Xml(ExpandedXIncludeDocument),
    Text(String, String),
}

enum XIncludeFailure {
    Resource(Error),
    Fatal(Error),
}

fn resolve_xinclude(
    source: &Document,
    include: NodeId,
    resolver: &dyn Resolver,
    meter: &mut Meter,
    identities: &mut HashMap<ResourceIdentity, ResolvedResource>,
    include_stack: &mut Vec<ResourceIdentity>,
    depth: usize,
) -> std::result::Result<XIncludeContent, XIncludeFailure> {
    let node = source
        .node(include)
        .ok_or_else(|| XIncludeFailure::Fatal(Error::Xml("XInclude node is stale".into())))?;
    let attributes = match &node.kind {
        NodeKind::Element { attributes, .. } => attributes,
        _ => {
            return Err(XIncludeFailure::Fatal(Error::Xml(
                "XInclude node is not an element".into(),
            )));
        }
    };
    let attribute = |local: &str| {
        attributes
            .iter()
            .find(|attribute| attribute.name.namespace.is_none() && attribute.name.local == local)
            .map(|attribute| attribute.value.as_str())
    };
    let href = attribute("href").unwrap_or_default();
    let parse = attribute("parse").unwrap_or("xml");
    if !matches!(parse, "xml" | "text") {
        return Err(XIncludeFailure::Fatal(Error::Xml(format!(
            "unsupported XInclude parse mode {parse}"
        ))));
    }
    if attribute("xpointer").is_some() {
        return Err(XIncludeFailure::Fatal(Error::Unsupported(
            "XInclude xpointer selection is not implemented".into(),
        )));
    }
    // XInclude 1.0 section 3.1 forbids fragment identifiers in href, including an empty
    // fragment; subresources are selected through the separate xpointer attribute.
    // https://www.w3.org/TR/xinclude/#include_element
    if href.contains('#') {
        return Err(XIncludeFailure::Fatal(Error::Xml(
            "XInclude href must not contain a fragment identifier".into(),
        )));
    }
    // Denied operations must not cross the resolver boundary. Charging before resolution also
    // bounds repeated failed attempts that are handled by xi:fallback.
    meter
        .charge(BudgetKind::ExternalDocuments, 1)
        .map_err(XIncludeFailure::Fatal)?;
    let resource = resolver
        .resolve(href, node.base_uri.as_deref(), ResolvePurpose::XInclude)
        .map_err(|error| match error {
            Error::ResourceNotFound { .. } | Error::Resolver { .. } => {
                XIncludeFailure::Resource(error)
            }
            error => XIncludeFailure::Fatal(error),
        })?;
    if include_stack.contains(&resource.identity) {
        return Err(XIncludeFailure::Fatal(Error::Resolver {
            uri: resource.canonical_uri,
            message: "XInclude cycle detected".into(),
        }));
    }
    let identity_is_new = match identities.get(&resource.identity) {
        Some(previous) if previous != &resource => {
            return Err(XIncludeFailure::Fatal(Error::StaleResource {
                identity: resource.identity,
            }));
        }
        Some(_) => false,
        None => true,
    };
    if parse == "text" {
        let encoding = attribute("encoding").or(resource.encoding.as_deref());
        let value = decode_xinclude_resource(&resource.bytes, encoding, meter, false)?;
        // XInclude 1.0 section 4.3 makes every character forbidden in XML documents a fatal
        // error, even after successful decoding: https://www.w3.org/TR/xinclude/#text_included
        if let Some(character) = value
            .chars()
            .find(|character| !crate::lexical::is_xml10_character(*character))
        {
            return Err(XIncludeFailure::Fatal(Error::Xml(format!(
                "XInclude text resource contains forbidden XML character U+{:04X}",
                u32::from(character)
            ))));
        }
        let canonical_uri = resource.canonical_uri.clone();
        if identity_is_new {
            identities.insert(resource.identity.clone(), resource);
        } else {
            meter.release_owned_bytes(resource.bytes.len());
        }
        return Ok(XIncludeContent::Text(value, canonical_uri));
    }
    let xml = decode_xinclude_resource(&resource.bytes, resource.encoding.as_deref(), meter, true)?;
    let decoded_temporary_bytes = xml.len().saturating_mul(2);
    // XInclude 1.0 section 4.2 explicitly makes non-well-formed acquired XML a fatal error,
    // unlike resource acquisition/encoding failures that may activate xi:fallback.
    // https://www.w3.org/TR/xinclude/#xml
    let document =
        Document::parse(&xml, Some(&resource.canonical_uri)).map_err(XIncludeFailure::Fatal)?;
    let resource_identity = resource.identity.clone();
    if identity_is_new {
        identities.insert(resource_identity.clone(), resource);
    } else {
        meter.release_owned_bytes(resource.bytes.len());
    }
    include_stack.push(resource_identity);
    let expanded = expand_xinclude_document(
        &document,
        resolver,
        meter,
        identities,
        include_stack,
        depth.saturating_add(1),
    );
    include_stack.pop();
    meter.release_owned_bytes(decoded_temporary_bytes);
    expanded
        .map(XIncludeContent::Xml)
        .map_err(XIncludeFailure::Fatal)
}

fn decode_xinclude_resource(
    bytes: &[u8],
    encoding: Option<&str>,
    meter: &mut Meter,
    parsed_xml: bool,
) -> std::result::Result<String, XIncludeFailure> {
    let (bytes, encoding) = if !parsed_xml {
        let (bytes, encoding) = xinclude_text_payload(bytes, encoding.unwrap_or("UTF-8"));
        (bytes, Some(encoding))
    } else {
        (bytes, encoding)
    };
    decode_resource_metered_inner(bytes, encoding, meter, parsed_xml).map_err(|error| match error {
        MeteredDecodeError::Budget(error) => XIncludeFailure::Fatal(error),
        MeteredDecodeError::Decode(error) => {
            let recoverable = matches!(
                error,
                xml_sec_xml_input::Error::UnsupportedByteEncoding(_)
                    | xml_sec_xml_input::Error::UnsupportedEncoding(_)
            );
            let error = Error::Xml(error.to_string());
            if recoverable {
                XIncludeFailure::Resource(error)
            } else {
                XIncludeFailure::Fatal(error)
            }
        }
    })
}

fn xinclude_text_payload<'a>(bytes: &'a [u8], encoding: &'a str) -> (&'a [u8], &'a str) {
    // XInclude 1.0 section 4.3.3 says an encoding signature is not part of the acquired text.
    // Select generic UTF byte order from that signature, then borrow past it so neither decoding
    // nor post-decode buffer shifting performs work for a character that must be discarded.
    // https://www.w3.org/TR/xinclude/#text_included
    if (encoding.eq_ignore_ascii_case("UTF-8") || encoding.eq_ignore_ascii_case("UTF8"))
        && let Some(payload) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF])
    {
        return (payload, encoding);
    }
    if encoding.eq_ignore_ascii_case("UTF-16") || encoding.eq_ignore_ascii_case("UTF16") {
        if let Some(payload) = bytes.strip_prefix(&[0xFE, 0xFF]) {
            return (payload, "UTF-16BE");
        }
        if let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE]) {
            return (payload, "UTF-16LE");
        }
    }
    if (encoding.eq_ignore_ascii_case("UTF-16BE") || encoding.eq_ignore_ascii_case("UTF16BE"))
        && let Some(payload) = bytes.strip_prefix(&[0xFE, 0xFF])
    {
        return (payload, encoding);
    }
    if (encoding.eq_ignore_ascii_case("UTF-16LE") || encoding.eq_ignore_ascii_case("UTF16LE"))
        && let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE])
    {
        return (payload, encoding);
    }
    if encoding.eq_ignore_ascii_case("UTF-32") || encoding.eq_ignore_ascii_case("UTF32") {
        if let Some(payload) = bytes.strip_prefix(&[0x00, 0x00, 0xFE, 0xFF]) {
            return (payload, "UTF-32BE");
        }
        if let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE, 0x00, 0x00]) {
            return (payload, "UTF-32LE");
        }
    }
    if (encoding.eq_ignore_ascii_case("UTF-32BE") || encoding.eq_ignore_ascii_case("UTF32BE"))
        && let Some(payload) = bytes.strip_prefix(&[0x00, 0x00, 0xFE, 0xFF])
    {
        return (payload, encoding);
    }
    if (encoding.eq_ignore_ascii_case("UTF-32LE") || encoding.eq_ignore_ascii_case("UTF32LE"))
        && let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE, 0x00, 0x00])
    {
        return (payload, encoding);
    }
    (bytes, encoding)
}

fn decode_resource_for_xml_parse(
    bytes: &[u8],
    encoding: Option<&str>,
    meter: &mut Meter,
) -> Result<String> {
    decode_resource_metered(bytes, encoding, meter, true)
}

fn decode_resource_metered(
    bytes: &[u8],
    encoding: Option<&str>,
    meter: &mut Meter,
    parsed_xml: bool,
) -> Result<String> {
    decode_resource_metered_inner(bytes, encoding, meter, parsed_xml).map_err(|error| match error {
        MeteredDecodeError::Budget(error) => error,
        MeteredDecodeError::Decode(error) => Error::Xml(error.to_string()),
    })
}

enum MeteredDecodeError {
    Budget(Error),
    Decode(xml_sec_xml_input::Error),
}

fn decode_resource_metered_inner(
    bytes: &[u8],
    encoding: Option<&str>,
    meter: &mut Meter,
    parsed_xml: bool,
) -> std::result::Result<String, MeteredDecodeError> {
    // XML parsing retains one decoded source copy while the decoder's output is still live.
    let decoded_copies = if parsed_xml { 2 } else { 1 };
    let (used, limit) = meter
        .usage(BudgetKind::OwnedBytes)
        .map_err(MeteredDecodeError::Budget)?;
    let available = limit.saturating_sub(used).saturating_sub(bytes.len());
    let maximum_decoded = available / decoded_copies;
    let decoded = decode_resource(bytes, encoding, parsed_xml, maximum_decoded).map_err(
        |error| match error {
            xml_sec_xml_input::Error::DecodedLimit { actual, .. } => {
                MeteredDecodeError::Budget(Error::Budget {
                    kind: BudgetKind::OwnedBytes,
                    limit,
                    actual: used
                        .saturating_add(bytes.len())
                        .saturating_add(actual.saturating_mul(decoded_copies)),
                })
            }
            error => MeteredDecodeError::Decode(error),
        },
    )?;
    let retained = bytes
        .len()
        .saturating_add(decoded.len().saturating_mul(decoded_copies));
    meter
        .charge(BudgetKind::OwnedBytes, retained)
        .map_err(MeteredDecodeError::Budget)?;
    Ok(decoded)
}

struct NodeMaps {
    forward: HashMap<SourceNode, NodePath>,
    reverse: HashMap<NodePath, SourceNode>,
    order: HashMap<SourceNode, NodeOrder>,
    next_order: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NodeOrder(usize, u8, usize);

impl NodeMaps {
    fn new(source: &Document, meter: &mut Meter) -> Result<Self> {
        let mut maps = Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            order: HashMap::new(),
            next_order: 0,
        };
        maps.extend(source, 0, meter)?;
        Ok(maps)
    }

    fn extend(&mut self, source: &Document, first_node: usize, meter: &mut Meter) -> Result<()> {
        let paths = semantic_node_paths_from(source, first_node, meter)?;
        let order_base = self.next_order;
        self.next_order = self.next_order.saturating_add(paths.len());
        for (id, node) in source.nodes().skip(first_node) {
            let (path, rank) = paths.get(&id).cloned().ok_or_else(|| {
                Error::Dynamic(format!("semantic node {id:?} has no document path"))
            })?;
            let path = NodePath::Ordinary(path);
            let key = SourceNode::Node(id);
            meter_node_map_entry(&path, meter)?;
            self.forward.insert(key.clone(), path.clone());
            self.reverse.insert(path.clone(), key.clone());
            let rank = order_base.saturating_add(rank);
            self.order
                .insert(key.clone(), NodeOrder(rank.saturating_mul(3), 0, 0));
            if let NodeKind::Element {
                attributes,
                namespaces,
                ..
            } = &node.kind
            {
                for (index, source_attribute) in attributes.iter().enumerate() {
                    meter.check_additional(
                        BudgetKind::OwnedBytes,
                        path.ordinary()
                            .len()
                            .saturating_mul(std::mem::size_of::<usize>()),
                    )?;
                    let attribute_path = NodePath::Attribute {
                        parent: path.ordinary().to_vec(),
                        namespace: source_attribute.name.namespace.clone(),
                        local: source_attribute.name.local.clone(),
                    };
                    let key = SourceNode::Attribute { owner: id, index };
                    meter_node_map_entry(&attribute_path, meter)?;
                    self.forward.insert(key.clone(), attribute_path.clone());
                    self.reverse.insert(attribute_path, key.clone());
                    self.order
                        .insert(key.clone(), NodeOrder(rank.saturating_mul(3), 2, index));
                }
                for (index, namespace) in namespaces
                    .iter()
                    .enumerate()
                    .filter(|(_, namespace)| xpath_namespace_is_visible(namespace))
                {
                    meter.check_additional(
                        BudgetKind::OwnedBytes,
                        path.ordinary()
                            .len()
                            .saturating_mul(std::mem::size_of::<usize>()),
                    )?;
                    let namespace_path = NodePath::Namespace {
                        parent: path.ordinary().to_vec(),
                        prefix: namespace.prefix.clone().unwrap_or_default(),
                        uri: namespace.uri.clone(),
                    };
                    let key = SourceNode::Namespace { owner: id, index };
                    meter_node_map_entry(&namespace_path, meter)?;
                    self.forward.insert(key.clone(), namespace_path.clone());
                    self.reverse.insert(namespace_path, key.clone());
                    // XPath 1.0 leaves namespace-axis order implementation-defined.
                    // libxml2 exposes the implicit `xml` binding first and the
                    // remaining declarations newest-first.
                    let namespace_order = if namespace.prefix.as_deref() == Some("xml") {
                        0
                    } else {
                        namespaces.len().saturating_sub(index).saturating_add(1)
                    };
                    self.order.insert(
                        key.clone(),
                        NodeOrder(rank.saturating_mul(3), 1, namespace_order),
                    );
                }
            }
        }
        Ok(())
    }
    fn to_sxd<'d>(&self, root: nodeset::Node<'d>, node: &SourceNode) -> Option<nodeset::Node<'d>> {
        self.resolve(root, self.forward.get(node)?)
    }
    fn resolve<'d>(&self, root: nodeset::Node<'d>, path: &NodePath) -> Option<nodeset::Node<'d>> {
        let mut node = root;
        for index in path.ordinary() {
            node = node.children().get(*index)?.clone();
        }
        match path {
            NodePath::Ordinary(_) => Some(node),
            NodePath::Attribute {
                namespace, local, ..
            } => node
                .element()?
                .attributes()
                .into_iter()
                .find(|attribute| {
                    let name = attribute.name();
                    let name = name.get();
                    name.local_part() == local && name.namespace_uri() == namespace.as_deref()
                })
                .map(nodeset::Node::Attribute),
            NodePath::Namespace { prefix, uri, .. } => resolve_namespace_node(node, prefix, uri),
        }
    }
    fn project_value(&self, root: nodeset::Node<'_>, value: SxdValue<'_>) -> Result<XPathValue> {
        Ok(match value {
            SxdValue::Boolean(value) => XPathValue::Boolean(value),
            SxdValue::Number(value) => XPathValue::Number(value),
            SxdValue::String(value) => XPathValue::String(value),
            SxdValue::ResultTreeFragment(_, _) => {
                return Err(Error::Dynamic(
                    "result-tree fragment escaped without its owning document".into(),
                ));
            }
            SxdValue::Nodeset(nodes) => {
                let node_count = nodes.size();
                if node_count <= 64 {
                    let mut projected = nodes
                        .into_iter()
                        .filter_map(|node| self.reverse.get(&typed_path_to(&node)).cloned())
                        .collect::<Vec<_>>();
                    projected.sort_by_key(|node| self.order.get(node).copied());
                    return Ok(XPathValue::NodeSet(projected));
                }
                let mut requested = nodes
                    .into_iter()
                    .map(|node| typed_path_to(&node))
                    .collect::<HashSet<_>>();
                let mut projected = Vec::with_capacity(node_count);
                let mut pending = vec![(root, Vec::new())];

                // Resolve ordinary nodes and attributes while walking the SXD tree once.
                // Computing a path independently for every result repeatedly scans sibling
                // vectors and becomes quadratic for large key() result sets.
                while let Some((node, path)) = pending.pop() {
                    let ordinary_path = NodePath::Ordinary(path.clone());
                    if requested.remove(&ordinary_path)
                        && let Some(source) = self.reverse.get(&ordinary_path)
                    {
                        projected.push(source.clone());
                    }
                    if let Some(element) = node.element() {
                        for attribute in element.attributes() {
                            let name = attribute.name();
                            let name = name.get();
                            let attribute_path = NodePath::Attribute {
                                parent: path.clone(),
                                namespace: name.namespace_uri().map(str::to_owned),
                                local: name.local_part().to_owned(),
                            };
                            if !requested.remove(&attribute_path) {
                                continue;
                            }
                            if let Some(source) = self.reverse.get(&attribute_path) {
                                projected.push(source.clone());
                            }
                        }
                    }
                    let children = node.children();
                    for (index, child) in children.into_iter().enumerate().rev() {
                        let mut child_path = path.clone();
                        child_path.push(index);
                        pending.push((child, child_path));
                    }
                }

                // Namespace nodes are synthesized by the XPath engine and are not children in
                // the SXD DOM. They are uncommon, so only those remaining after the tree walk
                // need the path-based fallback.
                projected.extend(
                    requested
                        .into_iter()
                        .filter_map(|path| self.reverse.get(&path).cloned()),
                );
                projected.sort_by_key(|node| self.order.get(node).copied());
                XPathValue::NodeSet(projected)
            }
        })
    }
}

fn xpath_namespace_is_visible(namespace: &crate::Namespace) -> bool {
    !namespace.uri.is_empty()
}

fn semantic_node_paths_from(
    source: &Document,
    first_node: usize,
    meter: &mut Meter,
) -> Result<HashMap<NodeId, (Vec<usize>, usize)>> {
    let mut paths = HashMap::new();
    let mut rank = 0usize;
    for (document_index, logical_root) in source.logical_roots().iter().copied().enumerate() {
        if logical_root.0 < first_node {
            continue;
        }
        meter.charge(
            BudgetKind::OwnedBytes,
            2usize.saturating_mul(std::mem::size_of::<usize>()),
        )?;
        let root_path = vec![0, document_index];
        let mut pending = vec![(logical_root, root_path)];
        while let Some((parent, parent_path)) = pending.pop() {
            meter.charge(
                BudgetKind::OwnedBytes,
                std::mem::size_of::<(NodeId, Vec<usize>, usize)>(),
            )?;
            paths.insert(parent, (parent_path.clone(), rank));
            rank = rank.saturating_add(1);
            let node = source.node(parent).ok_or_else(|| {
                Error::Dynamic(format!("stale semantic node {parent:?} in document path"))
            })?;
            for (index, child) in node.children.iter().copied().enumerate().rev() {
                meter.charge(
                    BudgetKind::OwnedBytes,
                    parent_path
                        .len()
                        .saturating_add(1)
                        .saturating_mul(std::mem::size_of::<usize>()),
                )?;
                let mut child_path = parent_path.clone();
                child_path.push(index);
                pending.push((child, child_path));
            }
        }
    }
    Ok(paths)
}

fn meter_node_map_entry(path: &NodePath, meter: &mut Meter) -> Result<()> {
    let retained = path
        .owned_bytes()
        .saturating_mul(2)
        .saturating_add(std::mem::size_of::<SourceNode>().saturating_mul(3))
        .saturating_add(std::mem::size_of::<NodeOrder>());
    meter.charge(BudgetKind::OwnedBytes, retained)
}

fn meter_node_base_uri_entries<'a>(
    source: &Document,
    entries: impl Iterator<Item = (&'a NodePath, &'a SourceNode)>,
    meter: &mut Meter,
) -> Result<()> {
    for (path, node) in entries {
        let base_uri_bytes = source
            .node(source_node_owner(node))
            .and_then(|node| node.base_uri.as_deref())
            .map_or(0, str::len);
        meter.charge(
            BudgetKind::OwnedBytes,
            path.owned_bytes()
                .saturating_add(std::mem::size_of::<Option<String>>())
                .saturating_add(base_uri_bytes),
        )?;
    }
    Ok(())
}

fn element_pattern_name_matches(
    lexical: &str,
    name: &crate::ExpandedName,
    namespaces: &[(String, String)],
) -> Result<bool> {
    if let Some((prefix, local)) = lexical.split_once(':') {
        let namespace = namespaces
            .iter()
            .find_map(|(candidate, uri)| (candidate == prefix).then_some(uri))
            .ok_or_else(|| Error::Static(format!("unbound pattern namespace prefix {prefix}")))?;
        Ok(name.namespace.as_deref() == Some(namespace.as_str())
            && (local == "*" || name.local == local))
    } else {
        Ok(name.namespace.is_none() && name.local == lexical)
    }
}

fn quoted_pattern_literal(value: &str) -> Option<&str> {
    let quote = value.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || value.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let literal = &value[1..value.len().checked_sub(1)?];
    (!literal.as_bytes().contains(&quote)).then_some(literal)
}

fn path_to(node: &nodeset::Node<'_>) -> Vec<usize> {
    let mut current = node.clone();
    let mut path = vec![];
    while let Some(parent) = current.parent() {
        let index = parent
            .children()
            .iter()
            .position(|child| *child == current)
            .unwrap_or(0);
        path.push(index);
        current = parent;
    }
    path.reverse();
    path
}

fn rewrite_absolute_paths(source: &str, logical_root_index: usize) -> std::borrow::Cow<'_, str> {
    if !contains_absolute_path(source) {
        return std::borrow::Cow::Borrowed(source);
    }
    let logical_root = format!(
        "/{DOCUMENTS_ELEMENT}/{DOCUMENT_ELEMENT}[{}]",
        logical_root_index + 1
    );
    if source.trim_matches(crate::lexical::is_xml_whitespace) == "/" {
        return std::borrow::Cow::Owned(logical_root);
    }
    let mut output = String::with_capacity(source.len());
    let mut quote = None;
    let mut previous_non_whitespace = None;
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if let Some(active) = quote {
            output.push(character);
            if character == active {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            output.push(character);
            previous_non_whitespace = Some(character);
            continue;
        }
        if character == '/' && absolute_path_can_start(&output, previous_non_whitespace) {
            output.push_str(&logical_root);
            if characters
                .clone()
                .find(|candidate| !crate::lexical::is_xml_whitespace(*candidate))
                .is_none_or(|next| {
                    matches!(next, ')' | ']' | ',' | '|' | '=' | '<' | '>' | '+' | '-')
                })
            {
                previous_non_whitespace = Some(']');
                continue;
            }
        }
        output.push(character);
        if !crate::lexical::is_xml_whitespace(character) {
            previous_non_whitespace = Some(character);
        }
    }
    if output == source {
        std::borrow::Cow::Borrowed(source)
    } else {
        std::borrow::Cow::Owned(output)
    }
}

fn contains_absolute_path(source: &str) -> bool {
    let mut quote = None;
    let mut previous_non_whitespace = None;
    for (offset, character) in source.char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            previous_non_whitespace = Some(character);
            continue;
        }
        if character == '/' && absolute_path_can_start(&source[..offset], previous_non_whitespace) {
            return true;
        }
        if !crate::lexical::is_xml_whitespace(character) {
            previous_non_whitespace = Some(character);
        }
    }
    false
}

fn absolute_path_can_start(output: &str, previous: Option<char>) -> bool {
    if previous.is_none_or(|previous| {
        matches!(
            previous,
            '(' | '[' | ',' | '|' | '=' | '<' | '>' | '+' | '-'
        )
    }) {
        return true;
    }
    if previous == Some('*') && multiplication_operator_ends(output) {
        return true;
    }
    let trimmed = output.trim_end_matches(crate::lexical::is_xml_whitespace);
    ["and", "or", "div", "mod"].iter().any(|operator| {
        trimmed.strip_suffix(operator).is_some_and(|prefix| {
            let Some(boundary) = prefix.chars().next_back() else {
                return false;
            };
            if crate::lexical::is_xml_whitespace(boundary) {
                return !prefix
                    .trim_end_matches(crate::lexical::is_xml_whitespace)
                    .is_empty();
            }
            boundary.is_ascii_digit() || matches!(boundary, ')' | ']' | '\'' | '"')
        })
    })
}

fn multiplication_operator_ends(output: &str) -> bool {
    let Some(prefix) = output
        .trim_end_matches(crate::lexical::is_xml_whitespace)
        .strip_suffix('*')
    else {
        return false;
    };
    let Some(previous) = prefix
        .trim_end_matches(crate::lexical::is_xml_whitespace)
        .chars()
        .next_back()
    else {
        return false;
    };
    !matches!(
        previous,
        '/' | ':' | '@' | '(' | '[' | ',' | '|' | '=' | '<' | '>' | '+' | '-' | '*'
    )
}

pub(crate) fn rewrite_absolute_paths_for_validation(source: &str) -> String {
    rewrite_absolute_paths(source, 0).into_owned()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtensionCallKind {
    NodeSet,
    ObjectType,
    Replace,
    Split,
    Tokenize,
    DynamicEvaluate,
    DynamicMap,
    SaxonExpression,
    SaxonEval,
    SaxonEvaluate,
    SaxonLineNumber,
}

fn variable_reference_name(source: &str, namespaces: &[(String, String)]) -> Option<ExpandedName> {
    let lexical = source.trim().strip_prefix('$')?;
    if let Some((prefix, local)) = lexical.split_once(':') {
        let namespace = namespaces
            .iter()
            .find_map(|(candidate, namespace)| (candidate == prefix).then(|| namespace.clone()))?;
        Some(ExpandedName::new(Some(namespace), local))
    } else {
        Some(ExpandedName::new(None::<String>, lexical))
    }
}

fn validate_dynamic_expression(source: &str, namespaces: &[(String, String)]) -> Result<()> {
    let normalized = normalize_xpath_for_sxd(source);
    Factory::new()
        .build(&normalized)
        .map_err(|error| Error::Dynamic(format!("invalid dynamic XPath `{source}`: {error}")))?;

    let bytes = source.as_bytes();
    let mut quote = None;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let character = bytes[cursor] as char;
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            cursor += 1;
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            cursor += 1;
            continue;
        }
        if !is_xpath_name_start(character) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < bytes.len()
            && ((bytes[cursor] as char).is_ascii_alphanumeric()
                || matches!(bytes[cursor], b'_' | b'-' | b'.'))
        {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b':' || bytes.get(cursor + 1) == Some(&b':') {
            continue;
        }
        let prefix = &source[start..cursor];
        if prefix != "xml" && !namespaces.iter().any(|(candidate, _)| candidate == prefix) {
            return Err(Error::Dynamic(format!(
                "dynamic XPath `{source}` uses undeclared namespace prefix `{prefix}`"
            )));
        }
        cursor += 1;
    }
    Ok(())
}

fn is_xpath_name_start(character: char) -> bool {
    character == '_' || character.is_ascii_alphabetic()
}

fn xpath_value_to_public(value: XPathValue) -> Value {
    match value {
        XPathValue::NodeSet(nodes) => Value::NodeSet(nodes),
        XPathValue::ResultTreeFragment(document) => Value::ResultTreeFragment(document),
        XPathValue::Boolean(value) => Value::Boolean(value),
        XPathValue::Number(value) => Value::Number(value),
        XPathValue::String(value) => Value::String(value),
        XPathValue::StoredExpression(value) => Value::StoredExpression(value),
    }
}

fn token_document(
    input: &str,
    delimiters: &str,
    kind: ExtensionCallKind,
    meter: &mut Meter,
) -> Result<Document> {
    let mut document = Document::empty(None);
    meter.charge(
        BudgetKind::OwnedBytes,
        document.retained_tree_container_bytes(),
    )?;
    visit_exslt_tokens(input, delimiters, kind, |token| {
        meter.charge(BudgetKind::ResultNodes, 2)?;
        meter.charge(BudgetKind::OwnedBytes, "token".len() + token.len())?;
        document.reserve_metered_push_containers(document.root(), meter)?;
        let element = document.push(
            document.root(),
            NodeKind::Element {
                name: ExpandedName::new(None::<String>, "token"),
                prefix: None,
                attributes: Vec::new(),
                namespaces: Vec::new(),
            },
            None,
        );
        document.reserve_metered_push_containers(element, meter)?;
        document.push(
            element,
            NodeKind::Text {
                value: token.to_owned(),
                disable_output_escaping: false,
            },
            None,
        );
        Ok(())
    })?;
    Ok(document)
}

fn visit_exslt_tokens(
    input: &str,
    delimiters: &str,
    kind: ExtensionCallKind,
    mut visit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    if delimiters.is_empty() {
        for (offset, character) in input.char_indices() {
            visit(&input[offset..offset + character.len_utf8()])?;
        }
        return Ok(());
    }
    match kind {
        ExtensionCallKind::Split => {
            for token in input.split(delimiters).filter(|token| !token.is_empty()) {
                visit(token)?;
            }
        }
        ExtensionCallKind::Tokenize => {
            for token in input
                .split(|character| delimiters.contains(character))
                .filter(|token| !token.is_empty())
            {
                visit(token)?;
            }
        }
        _ => unreachable!("token documents are produced only by split and tokenize"),
    }
    Ok(())
}

fn dynamic_map_document(values: &[(&str, String)], meter: &mut Meter) -> Result<Document> {
    let mut document = Document::empty(None);
    meter.charge(
        BudgetKind::OwnedBytes,
        document.retained_tree_container_bytes(),
    )?;
    for (local, value) in values {
        meter.charge(BudgetKind::ResultNodes, 2)?;
        meter.charge(
            BudgetKind::OwnedBytes,
            local.len() + EXSLT_COMMON_NS.len() + value.len(),
        )?;
        document.reserve_metered_push_containers(document.root(), meter)?;
        let element = document.push(
            document.root(),
            NodeKind::Element {
                name: ExpandedName::new(Some(EXSLT_COMMON_NS), *local),
                prefix: Some("exsl".into()),
                attributes: Vec::new(),
                namespaces: vec![crate::Namespace {
                    prefix: Some("exsl".into()),
                    uri: EXSLT_COMMON_NS.into(),
                }],
            },
            None,
        );
        document.reserve_metered_push_containers(element, meter)?;
        document.push(
            element,
            NodeKind::Text {
                value: value.clone(),
                disable_output_escaping: false,
            },
            None,
        );
    }
    Ok(document)
}

fn text_document(value: &str, meter: &mut Meter) -> Result<Document> {
    let mut document = Document::empty(None);
    meter.charge(BudgetKind::ResultNodes, 1)?;
    meter.charge(
        BudgetKind::OwnedBytes,
        document
            .retained_tree_container_bytes()
            .saturating_add(value.len()),
    )?;
    document.reserve_metered_push_containers(document.root(), meter)?;
    document.push(
        document.root(),
        NodeKind::Text {
            value: value.to_owned(),
            disable_output_escaping: false,
        },
        None,
    );
    Ok(document)
}

fn replace_exslt_string(
    input: &str,
    searches: &[String],
    replacements: &[String],
    meter: &mut Meter,
) -> Result<String> {
    let mut output_bytes = 0usize;
    for_each_exslt_replacement_segment(input, searches, replacements, |segment| {
        output_bytes = output_bytes.saturating_add(segment.len());
    });
    meter.charge(BudgetKind::OwnedBytes, output_bytes)?;
    let mut output = String::with_capacity(output_bytes);
    for_each_exslt_replacement_segment(input, searches, replacements, |segment| {
        output.push_str(segment);
    });
    Ok(output)
}

fn for_each_exslt_replacement_segment(
    input: &str,
    searches: &[String],
    replacements: &[String],
    mut emit: impl FnMut(&str),
) {
    let mut cursor = 0;
    let empty_search = searches.iter().position(String::is_empty);
    while cursor < input.len() {
        let remaining = &input[cursor..];
        let matched = searches
            .iter()
            .enumerate()
            .filter(|(_, search)| !search.is_empty() && remaining.starts_with(search.as_str()))
            .max_by_key(|(index, search)| (search.len(), usize::MAX - *index));
        if let Some((index, search)) = matched {
            emit(replacements.get(index).map_or("", String::as_str));
            cursor += search.len();
            continue;
        }
        let character = remaining
            .chars()
            .next()
            .expect("cursor remains inside the input");
        emit(&remaining[..character.len_utf8()]);
        cursor += character.len_utf8();
        if let Some(index) = empty_search
            && cursor < input.len()
        {
            emit(replacements.get(index).map_or("", String::as_str));
        }
    }
}

fn unused_internal_namespace<'a>(
    namespaces: &[(String, String)],
    preferred_prefix: &'a str,
    preferred_namespace: &'a str,
) -> (Cow<'a, str>, Cow<'a, str>) {
    (
        unused_internal_name(
            namespaces.iter().map(|(prefix, _)| prefix.as_str()),
            preferred_prefix,
            '_',
        ),
        unused_internal_name(
            namespaces.iter().map(|(_, namespace)| namespace.as_str()),
            preferred_namespace,
            ':',
        ),
    )
}

fn unused_internal_name<'existing, 'preferred>(
    existing: impl Iterator<Item = &'existing str> + Clone,
    preferred: &'preferred str,
    padding: char,
) -> Cow<'preferred, str> {
    if existing.clone().all(|value| value != preferred) {
        return Cow::Borrowed(preferred);
    }
    let longest = existing.map(str::len).max().unwrap_or(0);
    let mut unique = String::with_capacity(longest + padding.len_utf8());
    unique.push_str(preferred);
    while unique.len() <= longest {
        unique.push(padding);
    }
    Cow::Owned(unique)
}

fn rewrite_outer_context_functions<'a>(source: &'a str, prefix: &str) -> Cow<'a, str> {
    if !source.contains("position") && !source.contains("last") {
        return std::borrow::Cow::Borrowed(source);
    }
    // XSLT supplies the outer position and size, while predicates must retain XPath's
    // native dynamic context. Only calls outside predicates become private variables.
    let mut output = String::with_capacity(source.len());
    let mut quote = None;
    let mut predicate_depth = 0usize;
    let mut cursor = 0;
    while cursor < source.len() {
        let tail = &source[cursor..];
        let character = tail
            .chars()
            .next()
            .expect("cursor is at a character boundary");
        if let Some(active) = quote {
            output.push(character);
            cursor += character.len_utf8();
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '[' => predicate_depth += 1,
            ']' => predicate_depth = predicate_depth.saturating_sub(1),
            _ => {}
        }
        if predicate_depth == 0 {
            let replacement = [("position", "position"), ("last", "last")]
                .into_iter()
                .find_map(|(function, local)| {
                    outer_context_call_len(tail, function).and_then(|length| {
                        source[..cursor]
                            .chars()
                            .next_back()
                            .is_none_or(|before| !is_xpath_name_character(before))
                            .then_some((length, local))
                    })
                });
            if let Some((length, local)) = replacement {
                output.push('$');
                output.push_str(prefix);
                output.push(':');
                output.push_str(local);
                cursor += length;
                continue;
            }
        }
        output.push(character);
        cursor += character.len_utf8();
    }
    if output == source {
        std::borrow::Cow::Borrowed(source)
    } else {
        std::borrow::Cow::Owned(output)
    }
}

fn outer_context_call_len(source: &str, function: &str) -> Option<usize> {
    let mut cursor = function.len();
    if !source.starts_with(function)
        || source[cursor..]
            .chars()
            .next()
            .is_some_and(is_xpath_name_character)
    {
        return None;
    }
    cursor += source[cursor..]
        .find(|character: char| !is_xpath_whitespace(character))
        .unwrap_or(source.len() - cursor);
    if source.as_bytes().get(cursor) != Some(&b'(') {
        return None;
    }
    cursor += 1;
    cursor += source[cursor..]
        .find(|character: char| !is_xpath_whitespace(character))
        .unwrap_or(source.len() - cursor);
    (source.as_bytes().get(cursor) == Some(&b')')).then_some(cursor + 1)
}

fn is_xpath_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn is_xpath_name_character(character: char) -> bool {
    character == ':' || is_ncname_char(character)
}

fn is_lexical_qname(value: &str) -> bool {
    let mut parts = value.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    is_ncname(first) && parts.next().is_none_or(is_ncname) && parts.next().is_none()
}

#[derive(Default)]
struct GeneratedIdCache {
    assigned: HashMap<NodePath, usize>,
    owned_bytes: usize,
}

struct GenerateId {
    assigned: Rc<RefCell<GeneratedIdCache>>,
}
impl function::Function for GenerateId {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 1 {
            return Err(function::Error::Other {
                what: "generate-id() requires one argument".into(),
            });
        }
        let SxdValue::Nodeset(nodes) = &args[0] else {
            return Err(function::Error::Other {
                what: "generate-id() requires a node-set".into(),
            });
        };
        let Some(node) = nodes.document_order().first().cloned() else {
            return Ok(SxdValue::String(String::new()));
        };
        let id = assign_generated_id(context, &self.assigned, typed_path_to(&node))?;
        Ok(SxdValue::String(format!("id{id}")))
    }
}

fn assign_generated_id(
    context: &sxd_xpath_no_unsafe::context::Evaluation<'_, '_>,
    assigned: &RefCell<GeneratedIdCache>,
    path: NodePath,
) -> std::result::Result<usize, function::Error> {
    let mut cache = assigned.borrow_mut();
    if let Some(id) = cache.assigned.get(&path) {
        return Ok(*id);
    }
    let entry_bytes = path
        .owned_bytes()
        .saturating_add(std::mem::size_of::<(NodePath, usize)>());
    context.reserve_string_allocation(entry_bytes)?;
    let id = cache.assigned.len() + 1;
    cache.assigned.insert(path, id);
    cache.owned_bytes = cache.owned_bytes.saturating_add(entry_bytes);
    Ok(id)
}

enum NodeNameFunction {
    Qualified,
    Local,
    NamespaceUri,
}

fn is_projection_document_wrapper(node: &nodeset::Node<'_>) -> bool {
    let Some(name) = node.expanded_name() else {
        return false;
    };
    if name.namespace_uri().is_some() || name.local_part() != DOCUMENT_ELEMENT {
        return false;
    }
    let Some(container) = node.parent().and_then(|parent| parent.element()) else {
        return false;
    };
    let container_node = nodeset::Node::Element(container);
    container_node.expanded_name().is_some_and(|name| {
        name.namespace_uri().is_none() && name.local_part() == DOCUMENTS_ELEMENT
    }) && container
        .parent()
        .is_some_and(|parent| parent.root().is_some())
}

fn projected_document_root<'d>(node: nodeset::Node<'d>) -> nodeset::Node<'d> {
    let mut current = node;
    loop {
        if is_projection_document_wrapper(&current) {
            return current;
        }
        let Some(parent) = current.parent() else {
            return current.document().root().into();
        };
        current = parent;
    }
}

impl function::Function for NodeNameFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        let node = match args.as_slice() {
            [] => Some(context.node.clone()),
            [SxdValue::Nodeset(nodes)] => nodes.document_order().first().cloned(),
            [_] => {
                return Err(function::Error::Other {
                    what: "node name functions require a node-set argument".into(),
                });
            }
            _ => {
                return Err(function::Error::Other {
                    what: "node name functions accept at most one argument".into(),
                });
            }
        };
        let Some(node) = node else {
            return Ok(SxdValue::String(String::new()));
        };
        if is_projection_document_wrapper(&node) {
            // Projection wrappers represent XPath document nodes. Their implementation
            // QName must never leak through the XSLT node-name functions.
            return Ok(SxdValue::String(String::new()));
        }
        let value = match self {
            Self::Qualified => qualified_node_name(context, &node)?,
            Self::Local => node.expanded_name().map_or_else(
                || Ok(String::new()),
                |name| {
                    let value = name.local_part();
                    context.reserve_string_allocation(value.len())?;
                    Ok(value.to_owned())
                },
            )?,
            Self::NamespaceUri => node.expanded_name().map_or_else(
                || Ok(String::new()),
                |name| {
                    let value = name.namespace_uri().unwrap_or_default();
                    context.reserve_string_allocation(value.len())?;
                    Ok(value.to_owned())
                },
            )?,
        };
        Ok(SxdValue::String(value))
    }
}

fn qualified_node_name(
    context: &sxd_xpath_no_unsafe::context::Evaluation<'_, '_>,
    node: &nodeset::Node<'_>,
) -> std::result::Result<String, function::Error> {
    match node {
        nodeset::Node::Element(element) => {
            let prefix = element.preferred_prefix();
            let name = element.name();
            materialize_qualified_node_name(context, prefix.as_deref(), name.get().local_part())
        }
        nodeset::Node::Attribute(attribute) => {
            let prefix = attribute.preferred_prefix();
            let name = attribute.name();
            materialize_qualified_node_name(context, prefix.as_deref(), name.get().local_part())
        }
        nodeset::Node::ProcessingInstruction(instruction) => {
            let value = instruction.target();
            context.reserve_string_allocation(value.len())?;
            Ok(value.to_string())
        }
        nodeset::Node::Namespace(namespace) => {
            let value = namespace.prefix();
            context.reserve_string_allocation(value.len())?;
            Ok(value.to_owned())
        }
        _ => Ok(String::new()),
    }
}

fn materialize_qualified_node_name(
    context: &sxd_xpath_no_unsafe::context::Evaluation<'_, '_>,
    prefix: Option<&str>,
    local: &str,
) -> std::result::Result<String, function::Error> {
    let prefix = prefix.filter(|prefix| !prefix.is_empty());
    let output_len = prefix.map_or(local.len(), |prefix| prefix.len() + 1 + local.len());
    context.reserve_string_allocation(output_len)?;
    let Some(prefix) = prefix else {
        return Ok(local.to_owned());
    };
    let mut output = String::with_capacity(output_len);
    output.push_str(prefix);
    output.push(':');
    output.push_str(local);
    Ok(output)
}

struct LangFunction;

impl function::Function for LangFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 1 {
            return Err(function::Error::Other {
                what: "lang() requires one argument".into(),
            });
        }
        let requested = args[0].string().to_ascii_lowercase();
        let mut current = context
            .node
            .element()
            .or_else(|| context.node.parent().and_then(|node| node.element()));
        while let Some(element) = current {
            let language = element.attributes().into_iter().find_map(|attribute| {
                let name = attribute.name();
                let name = name.get();
                (name.namespace_uri() == Some("http://www.w3.org/XML/1998/namespace")
                    && name.local_part() == "lang")
                    .then(|| attribute.value())
            });
            if let Some(language) = language {
                let language = language.to_ascii_lowercase();
                return Ok(SxdValue::Boolean(
                    language == requested
                        || language
                            .strip_prefix(&requested)
                            .is_some_and(|suffix| suffix.starts_with('-')),
                ));
            }
            current = element.parent().and_then(|node| node.element());
        }
        Ok(SxdValue::Boolean(false))
    }
}

type IdIndex = Vec<HashMap<String, NodePath>>;

struct IdFunction {
    nodes_by_document: Rc<RefCell<IdIndex>>,
}

impl function::Function for IdFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 1 {
            return Err(function::Error::Other {
                what: "id() requires one argument".into(),
            });
        }
        // XPath 1.0 section 4.1 binds id() to the document containing the dynamic context node.
        // Every projected logical document occupies root/containers/document[index].
        // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-id
        let context_path = typed_path_to(&context.node);
        let nodes_by_document = self.nodes_by_document.borrow();
        let Some(nodes) = context_path
            .ordinary()
            .get(1)
            .and_then(|index| nodes_by_document.get(*index))
        else {
            return Ok(SxdValue::Nodeset(nodeset::Nodeset::new()));
        };
        let mut result = nodeset::Nodeset::new();
        let mut add_tokens = |value: &str| {
            // XPath 1.0 id() splits on XML's four S characters, not the host language's wider
            // ASCII whitespace class: https://www.w3.org/TR/1999/REC-xpath-19991116/#function-id
            for token in value
                .split(crate::lexical::is_xml_whitespace)
                .filter(|token| !token.is_empty())
            {
                if let Some(path) = nodes.get(token)
                    && let Some(node) =
                        resolve_node_path(context.node.document().root().into(), path)
                {
                    result.add(node);
                }
            }
        };
        match &args[0] {
            SxdValue::Nodeset(nodes) => {
                for node in nodes.iter() {
                    let value = node.string_value_with_context(context)?;
                    add_tokens(&value);
                }
            }
            SxdValue::String(value) | SxdValue::ResultTreeFragment(_, value) => add_tokens(value),
            value => {
                context.reserve_string_allocation(value.string_len())?;
                add_tokens(&value.string());
            }
        }
        Ok(SxdValue::Nodeset(result))
    }
}

fn extend_id_index(
    source: &Document,
    maps: &NodeMaps,
    first_node: usize,
    index: &mut IdIndex,
    meter: &mut Meter,
) -> Result<()> {
    index.resize_with(source.logical_roots().len(), HashMap::new);
    for (value, root, owner) in source.ids().filter(|(_, _, owner)| owner.0 >= first_node) {
        let Some(root_index) = source.logical_roots().binary_search(&root).ok() else {
            continue;
        };
        let Some(path) = maps.forward.get(&SourceNode::Node(owner)).cloned() else {
            continue;
        };
        let retained_bytes = value
            .len()
            .saturating_add(path.owned_bytes())
            .saturating_add(std::mem::size_of::<(String, NodePath)>().saturating_mul(2));
        meter.charge(BudgetKind::OwnedBytes, retained_bytes)?;
        index[root_index].insert(value.to_owned(), path);
    }
    Ok(())
}

fn build_unparsed_entity_index(
    source: &Document,
    meter: &mut Meter,
) -> Result<Vec<HashMap<String, String>>> {
    let mut index = Vec::with_capacity(source.logical_roots().len());
    for &root in source.logical_roots() {
        append_unparsed_entity_document(source, root, &mut index, meter)?;
    }
    Ok(index)
}

fn append_unparsed_entity_document(
    source: &Document,
    root: NodeId,
    index: &mut Vec<HashMap<String, String>>,
    meter: &mut Meter,
) -> Result<()> {
    let mut entities = HashMap::new();
    for (name, uri, _) in source
        .unparsed_entities()
        .filter(|(_, _, candidate)| *candidate == root)
    {
        meter.charge(
            BudgetKind::OwnedBytes,
            name.len()
                .saturating_add(uri.len())
                .saturating_add(std::mem::size_of::<(String, String)>()),
        )?;
        entities.insert(name.to_owned(), uri.to_owned());
    }
    index.push(entities);
    Ok(())
}

struct UnparsedEntityUriFunction {
    documents: Rc<RefCell<Vec<HashMap<String, String>>>>,
}

impl function::Function for UnparsedEntityUriFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 1 {
            return Err(function::Error::Other {
                what: "unparsed-entity-uri() requires one argument".into(),
            });
        }
        let document_index =
            path_to(&context.node)
                .get(1)
                .copied()
                .ok_or_else(|| function::Error::Other {
                    what: "unparsed-entity-uri() context has no logical document".into(),
                })?;
        let name = args[0].string();
        Ok(SxdValue::String(
            self.documents
                .borrow()
                .get(document_index)
                .and_then(|entities| entities.get(&name))
                .cloned()
                .unwrap_or_default(),
        ))
    }
}

struct DocumentFunction {
    roots: Rc<RefCell<HashMap<DocumentRequest, Vec<NodePath>>>>,
    pending: Rc<RefCell<HashSet<DocumentRequest>>>,
    node_base_uris: Rc<RefCell<HashMap<NodePath, Option<String>>>>,
    static_base_uri: Option<String>,
}

enum DocumentBaseSelection {
    Omitted,
    Explicit {
        base_uri: Option<String>,
        logical_document: Option<usize>,
    },
}

fn register_exslt_functions(
    context: &mut Context<'_>,
    clock: Arc<dyn Clock>,
    extension_policy: ExtensionPolicy,
) {
    macro_rules! register {
        ($namespace:expr, $name:expr, $function:expr) => {{
            context.set_function(($namespace, $name), $function);
        }};
    }
    crate::exslt_date::register(context, clock, extension_policy);
    register!(EXSLT_MATH_NS, "max", ExsltMathFunction::Max);
    register!(EXSLT_MATH_NS, "min", ExsltMathFunction::Min);
    register!(EXSLT_MATH_NS, "highest", ExsltMathFunction::Highest);
    register!(EXSLT_MATH_NS, "lowest", ExsltMathFunction::Lowest);
    register!(EXSLT_MATH_NS, "power", ExsltMathFunction::Power);
    register!(EXSLT_SETS_NS, "difference", ExsltSetFunction::Difference);
    register!(
        EXSLT_SETS_NS,
        "intersection",
        ExsltSetFunction::Intersection
    );
    register!(EXSLT_SETS_NS, "distinct", ExsltSetFunction::Distinct);
    register!(
        EXSLT_SETS_NS,
        "has-same-node",
        ExsltSetFunction::HasSameNode
    );
    register!(EXSLT_SETS_NS, "leading", ExsltSetFunction::Leading);
    register!(EXSLT_SETS_NS, "trailing", ExsltSetFunction::Trailing);
    register!(EXSLT_STRINGS_NS, "align", ExsltStringFunction::Align);
    register!(EXSLT_STRINGS_NS, "padding", ExsltStringFunction::Padding);
    register!(
        EXSLT_STRINGS_NS,
        "encode-uri",
        ExsltStringFunction::EncodeUri
    );
    register!(
        EXSLT_STRINGS_NS,
        "decode-uri",
        ExsltStringFunction::DecodeUri
    );
    register!(EXSLT_CRYPTO_NS, "md5", ExsltCryptoFunction::Md5);
    register!(EXSLT_CRYPTO_NS, "sha1", ExsltCryptoFunction::Sha1);
    register!(
        EXSLT_CRYPTO_NS,
        "rc4_encrypt",
        ExsltCryptoFunction::Rc4Encrypt
    );
    register!(
        EXSLT_CRYPTO_NS,
        "rc4_decrypt",
        ExsltCryptoFunction::Rc4Decrypt
    );
    register!(LIBXSLT_TEST_NS, "test", IdentityStringFunction);
    register!(LIBXSLT_TEST_PLUGIN_NS, "testplugin", IdentityStringFunction);
}

struct IdentityStringFunction;

impl function::Function for IdentityStringFunction {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 1 {
            return Err(function::Error::Other {
                what: "libxslt test function requires one argument".into(),
            });
        }
        Ok(SxdValue::String(args[0].string()))
    }
}

enum ExsltCryptoFunction {
    Md5,
    Sha1,
    Rc4Encrypt,
    Rc4Decrypt,
}

impl function::Function for ExsltCryptoFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        use sha1::Digest as _;

        match self {
            Self::Md5 | Self::Sha1 => {
                let Ok([value]) = <[SxdValue<'d>; 1]>::try_from(args) else {
                    return Err(function::Error::Other {
                        what: "EXSLT hash function requires one argument".into(),
                    });
                };
                if value.string_len() == 0 {
                    return Ok(SxdValue::String(String::new()));
                }
                let output_len = match self {
                    Self::Md5 => 32,
                    Self::Sha1 => 40,
                    _ => unreachable!(),
                };
                let workspace_bytes = sxd_string_materialization_bytes(&value)
                    .checked_add(output_len)
                    .ok_or_else(|| function::Error::Other {
                        what: "EXSLT hash allocation length overflow".into(),
                    })?;
                context.reserve_string_allocation(workspace_bytes)?;
                let value = value.into_string();
                let output = match self {
                    Self::Md5 => hex_encode(&md5::Md5::digest(value.as_bytes())),
                    Self::Sha1 => hex_encode(&sha1::Sha1::digest(value.as_bytes())),
                    _ => unreachable!(),
                };
                Ok(SxdValue::String(output))
            }
            Self::Rc4Encrypt | Self::Rc4Decrypt => {
                let Ok([key, input]) = <[SxdValue<'d>; 2]>::try_from(args) else {
                    return Err(function::Error::Other {
                        what: "EXSLT RC4 function requires key and data".into(),
                    });
                };
                let key_len = key.string_len();
                if key_len == 0 {
                    return Ok(SxdValue::String(String::new()));
                }
                let input_len = input.string_len();
                let coercion_bytes = sxd_string_materialization_bytes(&key)
                    .checked_add(sxd_string_materialization_bytes(&input))
                    .ok_or_else(|| function::Error::Other {
                        what: "EXSLT RC4 allocation length overflow".into(),
                    })?;
                let workspace_bytes = if matches!(self, Self::Rc4Decrypt) {
                    if !input_len.is_multiple_of(2) {
                        return Err(function::Error::Other {
                            what: "EXSLT RC4 ciphertext must contain complete hex octets".into(),
                        });
                    }
                    coercion_bytes
                        .checked_add(input_len)
                        .ok_or_else(|| function::Error::Other {
                            what: "EXSLT RC4 allocation length overflow".into(),
                        })?
                } else {
                    coercion_bytes
                        .checked_add(input_len.checked_mul(3).ok_or_else(|| {
                            function::Error::Other {
                                what: "EXSLT RC4 allocation length overflow".into(),
                            }
                        })?)
                        .ok_or_else(|| function::Error::Other {
                            what: "EXSLT RC4 allocation length overflow".into(),
                        })?
                };
                context.reserve_string_allocation(workspace_bytes)?;
                let key = key.into_string();
                let input = input.into_string();
                let input = if matches!(self, Self::Rc4Decrypt) {
                    hex_decode(&input)?
                } else {
                    input.into_bytes()
                };
                let mut padded_key = [0_u8; 128];
                let key_bytes = key.as_bytes();
                let copied = key_bytes.len().min(padded_key.len());
                padded_key[..copied].copy_from_slice(&key_bytes[..copied]);
                let output = rc4(&padded_key, &input);
                if matches!(self, Self::Rc4Encrypt) {
                    Ok(SxdValue::String(hex_encode(&output)))
                } else {
                    String::from_utf8(output)
                        .map(SxdValue::String)
                        .map_err(|_| function::Error::Other {
                            what: "EXSLT RC4 plaintext is not UTF-8".into(),
                        })
                }
            }
        }
    }
}

fn sxd_string_materialization_bytes(value: &SxdValue<'_>) -> usize {
    match value {
        SxdValue::String(_) | SxdValue::ResultTreeFragment(..) => 0,
        value => value.string_len(),
    }
}

fn rc4(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut state = [0_u8; 256];
    for (index, value) in state.iter_mut().enumerate() {
        *value = index as u8;
    }
    let mut j = 0_u8;
    for index in 0..256 {
        j = j
            .wrapping_add(state[index])
            .wrapping_add(key[index % key.len()]);
        state.swap(index, usize::from(j));
    }
    let (mut i, mut j) = (0_u8, 0_u8);
    input
        .iter()
        .map(|byte| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(state[usize::from(i)]);
            state.swap(usize::from(i), usize::from(j));
            let stream =
                state[usize::from(state[usize::from(i)].wrapping_add(state[usize::from(j)]))];
            byte ^ stream
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode(value: &str) -> std::result::Result<Vec<u8>, function::Error> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(function::Error::Other {
            what: "EXSLT RC4 ciphertext must contain complete hex octets".into(),
        });
    }
    pairs
        .iter()
        .map(|pair| {
            let [high, low] = pair.map(hex_nibble);
            high.zip(low)
                .map(|(high, low)| high << 4 | low)
                .ok_or_else(|| function::Error::Other {
                    what: "EXSLT RC4 ciphertext contains invalid hex".into(),
                })
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

enum ExsltMathFunction {
    Max,
    Min,
    Highest,
    Lowest,
    Power,
}

impl function::Function for ExsltMathFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if matches!(self, Self::Power) {
            if args.len() != 2 {
                return extension_argument_error("math:power() requires two arguments");
            }
            return Ok(SxdValue::Number(
                args[0].number(context)?.powf(args[1].number(context)?),
            ));
        }
        let [SxdValue::Nodeset(nodes)] = args.as_slice() else {
            return extension_argument_error("EXSLT math node functions require one node-set");
        };
        let node_count = nodes.size();
        let vector_bytes = node_count.saturating_mul(
            std::mem::size_of::<nodeset::Node<'_>>().saturating_add(std::mem::size_of::<f64>()),
        );
        let value_bytes = nodes.iter().fold(0usize, |total, node| {
            total.saturating_add(node.string_value_len())
        });
        let selection_bytes = node_count.saturating_mul(2).saturating_mul(
            std::mem::size_of::<nodeset::Node<'_>>().saturating_add(std::mem::size_of::<u64>()),
        );
        context.reserve_string_allocation(
            vector_bytes
                .saturating_add(value_bytes)
                .saturating_add(selection_bytes),
        )?;
        let ordered = nodes.document_order();
        let numbers = ordered
            .iter()
            .map(|node| SxdValue::String(node.string_value()).number(context))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if numbers.is_empty() || numbers.iter().any(|value| value.is_nan()) {
            return Ok(match self {
                Self::Max | Self::Min => SxdValue::Number(f64::NAN),
                Self::Highest | Self::Lowest => SxdValue::Nodeset(nodeset::Nodeset::new()),
                Self::Power => unreachable!(),
            });
        }
        let target = match self {
            Self::Max | Self::Highest => numbers.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            Self::Min | Self::Lowest => numbers.iter().copied().fold(f64::INFINITY, f64::min),
            Self::Power => unreachable!(),
        };
        Ok(match self {
            Self::Max | Self::Min => SxdValue::Number(target),
            Self::Highest | Self::Lowest => {
                let mut selected = nodeset::Nodeset::new();
                for (node, value) in ordered.into_iter().zip(numbers) {
                    if value == target {
                        selected.add(node);
                    }
                }
                SxdValue::Nodeset(selected)
            }
            Self::Power => unreachable!(),
        })
    }
}

enum ExsltSetFunction {
    Difference,
    Intersection,
    Distinct,
    HasSameNode,
    Leading,
    Trailing,
}

impl function::Function for ExsltSetFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if matches!(self, Self::Distinct) {
            let [SxdValue::Nodeset(nodes)] = args.as_slice() else {
                return extension_argument_error("set:distinct() requires one node-set");
            };
            let ordered = nodes.document_order();
            let value_bytes = ordered.iter().fold(0usize, |total, node| {
                total.saturating_add(node.string_value_len())
            });
            // Reserve conservatively for the strings plus hash buckets at the standard maximum
            // load. This keeps both allocations behind the same XPath owned-byte gate.
            let bucket_bytes = ordered.len().saturating_mul(2).saturating_mul(
                std::mem::size_of::<String>().saturating_add(std::mem::size_of::<usize>()),
            );
            context.reserve_string_allocation(value_bytes.saturating_add(bucket_bytes))?;
            let mut seen = std::collections::HashSet::with_capacity(ordered.len());
            let mut result = nodeset::Nodeset::new();
            for node in ordered {
                if seen.insert(node.string_value()) {
                    result.add(node);
                }
            }
            return Ok(SxdValue::Nodeset(result));
        }
        let [SxdValue::Nodeset(left), SxdValue::Nodeset(right)] = args.as_slice() else {
            return extension_argument_error("EXSLT set function requires two node-sets");
        };
        if matches!(self, Self::HasSameNode) {
            return Ok(SxdValue::Boolean(
                left.iter().any(|node| right.contains(node)),
            ));
        }
        let mut result = nodeset::Nodeset::new();
        match self {
            Self::Difference => {
                for node in left.document_order() {
                    if !right.contains(node.clone()) {
                        result.add(node);
                    }
                }
            }
            Self::Intersection => {
                for node in left.document_order() {
                    if right.contains(node.clone()) {
                        result.add(node);
                    }
                }
            }
            Self::Leading | Self::Trailing => {
                let Some(boundary) = right.document_order_first() else {
                    return Ok(SxdValue::Nodeset(left.clone()));
                };
                // EXSLT Sets defines a non-member boundary as an empty result, even when nodes
                // from the first set precede it in document order. This membership condition is
                // intentionally stricter than a plain document-order partition.
                if !left.contains(boundary.clone()) {
                    return Ok(SxdValue::Nodeset(nodeset::Nodeset::new()));
                }
                let mut combined = nodeset::Nodeset::new();
                combined.extend(left.iter());
                combined.extend(right.iter());
                let order = combined.document_order();
                let boundary = order
                    .iter()
                    .position(|node| node == &boundary)
                    .unwrap_or(usize::MAX);
                for (candidate, node) in order.into_iter().enumerate() {
                    if left.contains(node.clone())
                        && ((matches!(self, Self::Leading) && candidate < boundary)
                            || (matches!(self, Self::Trailing) && candidate > boundary))
                    {
                        result.add(node);
                    }
                }
            }
            Self::Distinct | Self::HasSameNode => unreachable!(),
        }
        Ok(SxdValue::Nodeset(result))
    }
}

fn utf8_prefix_bytes(value: &str, characters: usize) -> usize {
    value
        .char_indices()
        .nth(characters)
        .map_or(value.len(), |(offset, _)| offset)
}

enum ExsltStringFunction {
    Align,
    Padding,
    EncodeUri,
    DecodeUri,
}

impl function::Function for ExsltStringFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        match self {
            Self::Align => {
                if !(2..=3).contains(&args.len()) {
                    return extension_argument_error("str:align() requires two or three arguments");
                }
                let value = args[0].string();
                let padding = args[1].string();
                let alignment = args.get(2).map(SxdValue::string).unwrap_or_default();
                let width = padding.chars().count();
                let value_width = value.chars().count();
                if value_width >= width {
                    let output_bytes = utf8_prefix_bytes(&value, width);
                    context.reserve_string_allocation(output_bytes)?;
                    return Ok(SxdValue::String(value[..output_bytes].to_owned()));
                }
                let missing = width - value_width;
                let left = match alignment.as_str() {
                    "right" => missing,
                    "center" => missing / 2,
                    _ => 0,
                };
                let right = missing - left;
                // EXSLT overlays the value on the padding string by character position. Retain
                // borrowed UTF-8 slices and meter the exact output before its sole allocation:
                // https://exslt.github.io/str/functions/align/index.html
                let left_end = utf8_prefix_bytes(&padding, left);
                let right_start = utf8_prefix_bytes(&padding, left + value_width);
                let output_bytes = left_end
                    .checked_add(value.len())
                    .and_then(|bytes| bytes.checked_add(padding.len() - right_start))
                    .unwrap_or(usize::MAX);
                context.reserve_string_allocation(output_bytes)?;
                let mut result = String::with_capacity(output_bytes);
                result.push_str(&padding[..left_end]);
                result.push_str(&value);
                debug_assert_eq!(padding[right_start..].chars().count(), right);
                result.push_str(&padding[right_start..]);
                Ok(SxdValue::String(result))
            }
            Self::Padding => {
                if !(1..=2).contains(&args.len()) {
                    return extension_argument_error("str:padding() requires one or two arguments");
                }
                let requested = args[0].number(context)?.floor().max(0.0);
                let length = if requested.is_finite() && requested <= usize::MAX as f64 {
                    requested as usize
                } else {
                    usize::MAX
                };
                let pattern = args
                    .get(1)
                    .map(SxdValue::string)
                    .unwrap_or_else(|| " ".into());
                let pattern_characters = pattern.chars().count();
                if pattern_characters == 0 || length == 0 {
                    return Ok(SxdValue::String(String::new()));
                }
                let complete = length / pattern_characters;
                let remainder = length % pattern_characters;
                let bytes = pattern
                    .len()
                    .checked_mul(complete)
                    .and_then(|bytes| {
                        pattern
                            .chars()
                            .take(remainder)
                            .try_fold(bytes, |total, character| {
                                total.checked_add(character.len_utf8())
                            })
                    })
                    .unwrap_or(usize::MAX);
                context.reserve_string_allocation(bytes)?;
                let mut output = pattern.repeat(complete);
                output.extend(pattern.chars().take(remainder));
                Ok(SxdValue::String(output))
            }
            Self::EncodeUri => {
                if !(2..=3).contains(&args.len()) {
                    return extension_argument_error(
                        "str:encode-uri() requires two or three arguments",
                    );
                }
                let value = args[0].string();
                let escape_reserved = args[1].boolean();
                let encoding_label = args.get(2).map(SxdValue::string);
                let encoding = uri_encoding(encoding_label.as_deref(), "str:encode-uri()")?;
                let encoded_len = percent_encoded_uri_len(&value, escape_reserved, encoding)?;
                context.reserve_string_allocation(encoded_len)?;
                Ok(SxdValue::String(percent_encode_uri(
                    &value,
                    escape_reserved,
                    encoded_len,
                    encoding,
                )?))
            }
            Self::DecodeUri => {
                if !(1..=2).contains(&args.len()) {
                    return extension_argument_error(
                        "str:decode-uri() requires one or two arguments",
                    );
                }
                let encoding_label = args.get(1).map(SxdValue::string);
                let encoding = uri_encoding(encoding_label.as_deref(), "str:decode-uri()")?;
                let value = args[0].string();
                let decoded_len = percent_decoded_uri_len(&value)?;
                let (transcoded_len, workspace_len) = match encoding {
                    UriEncoding::Standard(encoding) => {
                        let transcoded_len = encoding
                            .new_decoder()
                            .max_utf8_buffer_length_without_replacement(decoded_len)
                            .ok_or_else(|| function::Error::Other {
                                what: "str:decode-uri() result length overflow".into(),
                            })?;
                        let workspace_len =
                            decoded_len.checked_add(transcoded_len).ok_or_else(|| {
                                function::Error::Other {
                                    what: "str:decode-uri() allocation length overflow".into(),
                                }
                            })?;
                        (transcoded_len, workspace_len)
                    }
                    UriEncoding::Registered(encoding) => {
                        let transcoded_len = registered_uri_decoded_len(&value, encoding)?;
                        // Registered single-byte repertoires stream directly into UTF-8 and do
                        // not require the intermediate decoded-octet vector used by encoding_rs.
                        (transcoded_len, transcoded_len)
                    }
                };
                context.reserve_string_allocation(workspace_len)?;
                Ok(SxdValue::String(percent_decode_uri(
                    &value,
                    encoding,
                    decoded_len,
                    transcoded_len,
                )?))
            }
        }
    }
}

fn extension_argument_error<T>(message: &str) -> std::result::Result<T, function::Error> {
    Err(function::Error::Other {
        what: message.into(),
    })
}

fn dynamic_expression_error_is_recoverable(error: &Error) -> bool {
    !matches!(
        error.kind(),
        ErrorKind::Budget | ErrorKind::Resource | ErrorKind::Resolver
    )
}

fn percent_encode_uri(
    value: &str,
    escape_reserved: bool,
    encoded_len: usize,
    encoding: UriEncoding,
) -> std::result::Result<String, function::Error> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(encoded_len);
    visit_uri_encoded_bytes(value, encoding, |byte| {
        let character = char::from(byte);
        if uri_byte_is_unescaped(character, escape_reserved) {
            output.push(character);
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(())
    })?;
    Ok(output)
}

fn percent_encoded_uri_len(
    value: &str,
    escape_reserved: bool,
    encoding: UriEncoding,
) -> std::result::Result<usize, function::Error> {
    let mut length = 0usize;
    visit_uri_encoded_bytes(value, encoding, |byte| {
        let character = char::from(byte);
        let encoded = !uri_byte_is_unescaped(character, escape_reserved);
        length = length
            .checked_add(if encoded { 3 } else { 1 })
            .ok_or_else(|| function::Error::Other {
                what: "str:encode-uri() result length overflow".into(),
            })?;
        Ok(())
    })?;
    Ok(length)
}

fn visit_uri_encoded_bytes(
    value: &str,
    encoding: UriEncoding,
    mut visit: impl FnMut(u8) -> std::result::Result<(), function::Error>,
) -> std::result::Result<(), function::Error> {
    match encoding {
        UriEncoding::Registered(encoding) => {
            for character in value.chars() {
                let byte = encoding.encode_char(character).ok_or_else(|| {
                    function::Error::Other {
                        what: format!(
                            "str:encode-uri() character `{character}` is not representable in {}",
                            encoding.name()
                        ),
                    }
                })?;
                visit(byte)?;
            }
        }
        UriEncoding::Standard(encoding) if encoding == encoding_rs::UTF_8 => {
            for &byte in value.as_bytes() {
                visit(byte)?;
            }
        }
        UriEncoding::Standard(encoding) => {
            let mut encoder = encoding.new_encoder();
            let mut source = value;
            let mut buffer = [0_u8; 1024];
            loop {
                let (result, read, written) =
                    encoder.encode_from_utf8_without_replacement(source, &mut buffer, true);
                for &byte in &buffer[..written] {
                    visit(byte)?;
                }
                source = &source[read..];
                match result {
                    encoding_rs::EncoderResult::InputEmpty => break,
                    encoding_rs::EncoderResult::OutputFull => {}
                    encoding_rs::EncoderResult::Unmappable(character) => {
                        return Err(function::Error::Other {
                            what: format!(
                                "str:encode-uri() character `{character}` is not representable in {}",
                                encoding.name()
                            ),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

fn uri_byte_is_unescaped(character: char, escape_reserved: bool) -> bool {
    // EXSLT inherits the reserved delimiters from RFC 2396 section 2.2. `#` is outside that
    // production and must remain encoded even when reserved delimiters are preserved.
    // https://www.rfc-editor.org/rfc/rfc2396#section-2.2
    const RESERVED: &str = ";/?:@&=+$,";
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')'
        )
        || (!escape_reserved && RESERVED.contains(character))
}

fn percent_decode_uri(
    value: &str,
    encoding: UriEncoding,
    decoded_len: usize,
    transcoded_len: usize,
) -> std::result::Result<String, function::Error> {
    if let UriEncoding::Registered(encoding) = encoding {
        let mut output = String::with_capacity(transcoded_len);
        visit_percent_decoded_bytes(value, |byte| {
            let character = encoding
                .decode_byte(byte)
                .ok_or_else(|| function::Error::Other {
                    what: format!("str:decode-uri() input is not valid {}", encoding.name()),
                })?;
            output.push(character);
            Ok(())
        })?;
        return Ok(output);
    }
    let UriEncoding::Standard(encoding) = encoding else {
        unreachable!("registered encodings return above")
    };
    let mut decoded = Vec::with_capacity(decoded_len);
    visit_percent_decoded_bytes(value, |byte| {
        decoded.push(byte);
        Ok(())
    })?;
    let (value, _, had_errors) = encoding.decode(&decoded);
    if had_errors {
        return extension_argument_error(&format!(
            "str:decode-uri() input is not valid {}",
            encoding.name()
        ));
    }
    Ok(value.into_owned())
}

#[derive(Clone, Copy)]
enum UriEncoding {
    Standard(&'static encoding_rs::Encoding),
    Registered(xml_sec_xml_input::IanaSingleByteEncoding),
}

fn uri_encoding(
    label: Option<&str>,
    function_name: &str,
) -> std::result::Result<UriEncoding, function::Error> {
    label.map_or(Ok(UriEncoding::Standard(encoding_rs::UTF_8)), |label| {
        if let Some(encoding) = xml_sec_xml_input::registered_single_byte_encoding(label) {
            return Ok(UriEncoding::Registered(encoding));
        }
        encoding_rs::Encoding::for_label(label.as_bytes())
            .filter(|encoding| xml_sec_xml_input::legacy_label_matches_encoding(label, encoding))
            .map(UriEncoding::Standard)
            .ok_or_else(|| function::Error::Other {
                what: format!("{function_name} has unknown encoding `{label}`"),
            })
    })
}

fn registered_uri_decoded_len(
    value: &str,
    encoding: xml_sec_xml_input::IanaSingleByteEncoding,
) -> std::result::Result<usize, function::Error> {
    let mut length = 0usize;
    visit_percent_decoded_bytes(value, |byte| {
        let character = encoding
            .decode_byte(byte)
            .ok_or_else(|| function::Error::Other {
                what: format!("str:decode-uri() input is not valid {}", encoding.name()),
            })?;
        length =
            length
                .checked_add(character.len_utf8())
                .ok_or_else(|| function::Error::Other {
                    what: "str:decode-uri() result length overflow".into(),
                })?;
        Ok(())
    })?;
    Ok(length)
}

fn visit_percent_decoded_bytes(
    value: &str,
    mut visit: impl FnMut(u8) -> std::result::Result<(), function::Error>,
) -> std::result::Result<(), function::Error> {
    let bytes = value.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%'
            && let Some(encoded) = bytes.get(cursor + 1..cursor + 3)
            && let Ok(encoded) = std::str::from_utf8(encoded)
            && let Ok(byte) = u8::from_str_radix(encoded, 16)
        {
            visit(byte)?;
            cursor += 3;
        } else {
            visit(bytes[cursor])?;
            cursor += 1;
        }
    }
    Ok(())
}

fn percent_decoded_uri_len(value: &str) -> std::result::Result<usize, function::Error> {
    let mut decoded_len = 0usize;
    visit_percent_decoded_bytes(value, |_| {
        decoded_len = decoded_len
            .checked_add(1)
            .ok_or_else(|| function::Error::Other {
                what: "str:decode-uri() result length overflow".into(),
            })?;
        Ok(())
    })?;
    Ok(decoded_len)
}

impl function::Function for DocumentFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if !(1..=2).contains(&args.len()) {
            return Err(function::Error::Other {
                what: "document() requires one or two arguments".into(),
            });
        }
        let base_selection = if let Some(base) = args.get(1) {
            let SxdValue::Nodeset(nodes) = base else {
                return Err(function::Error::Other {
                    what: "document() second argument must be a node-set".into(),
                });
            };
            let Some(node) = nodes.document_order().into_iter().next() else {
                return Ok(SxdValue::Nodeset(nodeset::Nodeset::new()));
            };
            let path = typed_path_to(&node);
            DocumentBaseSelection::Explicit {
                base_uri: self.node_base_uris.borrow().get(&path).cloned().flatten(),
                logical_document: path.ordinary().get(1).copied(),
            }
        } else {
            DocumentBaseSelection::Omitted
        };
        let root: nodeset::Node<'d> = context.node.document().root().into();
        let mut result = nodeset::Nodeset::new();
        let roots = self.roots.borrow();
        let mut process = |request: DocumentRequest| -> std::result::Result<(), function::Error> {
            let Some(paths) = roots.get(&request) else {
                let mut pending = self.pending.borrow_mut();
                if !pending.contains(&request) {
                    pending.insert(request);
                }
                return Ok(());
            };
            for path in paths {
                let node = resolve_node_path(root.clone(), path).ok_or_else(|| {
                    function::Error::Other {
                        what: format!("document resource `{}` is stale", request.href),
                    }
                })?;
                result.add_metered(context, node)?;
            }
            Ok(())
        };
        match &args[0] {
            SxdValue::Nodeset(nodes) => {
                for node in nodes.iter() {
                    let path = typed_path_to(&node);
                    context.reserve_temporary_allocation(path.owned_bytes())?;
                    let (base_uri, logical_document) = match &base_selection {
                        DocumentBaseSelection::Explicit {
                            base_uri,
                            logical_document,
                        } => (base_uri.clone(), *logical_document),
                        DocumentBaseSelection::Omitted => (
                            self.node_base_uris.borrow().get(&path).cloned().flatten(),
                            path.ordinary().get(1).copied(),
                        ),
                    };
                    let href = node.string_value_with_context(context)?;
                    context.reserve_temporary_allocation(
                        std::mem::size_of::<DocumentRequest>()
                            .saturating_add(base_uri.as_deref().map_or(0, str::len)),
                    )?;
                    process(DocumentRequest::relative_to(
                        href,
                        base_uri,
                        logical_document,
                    ))?;
                }
            }
            value => {
                let (base_uri, logical_document) = match &base_selection {
                    DocumentBaseSelection::Explicit {
                        base_uri,
                        logical_document,
                    } => (base_uri.clone(), *logical_document),
                    DocumentBaseSelection::Omitted => (self.static_base_uri.clone(), None),
                };
                context.reserve_temporary_allocation(value.string_len())?;
                let href = value.string();
                context.reserve_temporary_allocation(
                    std::mem::size_of::<DocumentRequest>()
                        .saturating_add(base_uri.as_deref().map_or(0, str::len)),
                )?;
                process(DocumentRequest::relative_to(
                    href,
                    base_uri,
                    logical_document,
                ))?;
            }
        }
        Ok(SxdValue::Nodeset(result))
    }
}

struct SystemProperty {
    namespaces: Arc<Vec<(String, String)>>,
}
impl function::Function for SystemProperty {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        let name = one_qname_argument(args, &self.namespaces, "system-property")?;
        if name.namespace.as_deref() == Some(crate::compiler::XSLT_NS) && name.local == "version" {
            // XSLT 1.0 section 12.4 defines xsl:version as the number 1.0.
            return Ok(SxdValue::Number(1.0));
        }
        let value = if name.namespace.as_deref() == Some(crate::compiler::XSLT_NS) {
            match name.local.as_str() {
                "vendor" => "structured-world xml-sec-xslt",
                "vendor-url" => "https://github.com/structured-world/xml-sec",
                _ => "",
            }
        } else {
            ""
        };
        Ok(SxdValue::String(value.into()))
    }
}

struct ElementAvailable {
    namespaces: Arc<Vec<(String, String)>>,
}
impl function::Function for ElementAvailable {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        let name = one_qname_argument(args, &self.namespaces, "element-available")?;
        let available = (name.namespace.as_deref() == Some(crate::compiler::XSLT_NS)
            && matches!(
                name.local.as_str(),
                "apply-imports"
                    | "apply-templates"
                    | "attribute"
                    | "call-template"
                    | "choose"
                    | "comment"
                    | "copy"
                    | "copy-of"
                    | "element"
                    | "for-each"
                    | "fallback"
                    | "if"
                    | "message"
                    | "number"
                    | "processing-instruction"
                    // XSLT 1.0 section 15 limits this function to instructions, but libxslt
                    // deliberately advertises these executable structural children as well.
                    // https://www.w3.org/TR/1999/REC-xslt-19991116#element-available
                    | "sort"
                    | "text"
                    | "value-of"
                    | "variable"
                    | "param"
                    | "with-param"
                    | "when"
                    | "otherwise"
            ))
            || (name.namespace.as_deref() == Some(crate::compiler::EXSLT_FUNCTIONS_NS)
                && name.local == "result")
            || matches!(
                (name.namespace.as_deref(), name.local.as_str()),
                (Some(SAXON_NS), "output")
                    | (Some(XALAN_REDIRECT_NS), "write")
                    | (Some(XT_NS), "document")
            );
        Ok(SxdValue::Boolean(available))
    }
}

fn hide_projection_elements_from_axes(source: &str) -> std::borrow::Cow<'_, str> {
    const AXES: &[&str] = &[
        "ancestor-or-self",
        "ancestor",
        "following",
        "following-sibling",
        "preceding",
        "preceding-sibling",
        "parent",
        "self",
    ];
    if !source.contains("..")
        && !AXES
            .iter()
            .any(|axis| source.split("::").any(|prefix| prefix.ends_with(axis)))
    {
        return std::borrow::Cow::Borrowed(source);
    }
    let mut output = String::with_capacity(source.len());
    let mut quote = None;
    let mut cursor = 0;
    while cursor < source.len() {
        let character = source[cursor..]
            .chars()
            .next()
            .expect("cursor is in bounds");
        if let Some(active) = quote {
            output.push(character);
            cursor += character.len_utf8();
            if character == active {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            output.push(character);
            cursor += character.len_utf8();
            continue;
        }
        if source[cursor..].starts_with("..")
            && source[..cursor]
                .chars()
                .next_back()
                .is_none_or(|previous| previous != '.' && !is_xpath_name_character(previous))
            && source[cursor + 2..]
                .chars()
                .next()
                .is_none_or(|next| next != '.' && !next.is_ascii_digit())
        {
            output
                .push_str("..[parent::node()][not(self::__xml_sec_documents and not(parent::*))]");
            cursor += 2;
            continue;
        }
        let axis = AXES.iter().find(|axis| {
            source[cursor..].starts_with(**axis) && source[cursor + axis.len()..].starts_with("::")
        });
        if let Some(axis) = axis
            && let Some(end) = xpath_axis_node_test_end(source, cursor + axis.len() + 2)
        {
            let node_test = source[cursor + axis.len() + 2..end].trim();
            output.push_str(&source[cursor..end]);
            // The package root and its `documents` container are implementation nodes.
            // A per-document wrapper represents the XPath root node and remains visible only
            // to node(), never to element principal-node tests.
            output.push_str("[not(self::__xml_sec_documents and not(parent::*))]");
            if matches!(*axis, "following-sibling" | "preceding-sibling") {
                output.push_str("[not(self::__xml_sec_document and parent::__xml_sec_documents[not(parent::*)])]");
            } else if xpath_test_matches_root(node_test) {
                output.push_str("[parent::node()]");
            } else {
                output.push_str("[not(self::__xml_sec_document and parent::__xml_sec_documents[not(parent::*)])]");
            }
            cursor = end;
            continue;
        }
        output.push(character);
        cursor += character.len_utf8();
    }
    if output == source {
        std::borrow::Cow::Borrowed(source)
    } else {
        std::borrow::Cow::Owned(output)
    }
}

fn xpath_axis_node_test_end(source: &str, mut cursor: usize) -> Option<usize> {
    while source[cursor..]
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
    {
        cursor += source[cursor..].chars().next()?.len_utf8();
    }
    if source[cursor..].starts_with('*') {
        return Some(cursor + 1);
    }
    let start = cursor;
    while let Some(character) = source[cursor..].chars().next() {
        if !is_xpath_name_character(character) && character != ':' && character != '*' {
            break;
        }
        cursor += character.len_utf8();
    }
    if cursor == start {
        return None;
    }
    while source[cursor..]
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
    {
        cursor += source[cursor..].chars().next()?.len_utf8();
    }
    if !source[cursor..].starts_with('(') {
        return Some(cursor);
    }
    let mut depth = 0usize;
    let mut quote = None;
    for (offset, character) in source[cursor..].char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == '(' {
            depth += 1;
        } else if character == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(cursor + offset + 1);
            }
        }
    }
    None
}

fn xpath_test_matches_root(node_test: &str) -> bool {
    let Some(arguments) = node_test
        .strip_prefix("node")
        .map(str::trim_start)
        .and_then(|value| value.strip_prefix('('))
        .and_then(|value| value.strip_suffix(')'))
    else {
        return false;
    };
    arguments.trim().is_empty()
}

struct FunctionAvailable {
    namespaces: Arc<Vec<(String, String)>>,
    stylesheet_functions: Arc<HashSet<ExpandedName>>,
}
impl function::Function for FunctionAvailable {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        let name = one_qname_argument(args, &self.namespaces, "function-available")?;
        let available = if name.namespace.is_some() {
            self.stylesheet_functions.contains(&name) || is_builtin_extension_function(&name)
        } else {
            matches!(
                name.local.as_str(),
                "boolean"
                    | "ceiling"
                    | "concat"
                    | "contains"
                    | "count"
                    | "current"
                    | "document"
                    | "false"
                    | "floor"
                    | "format-number"
                    | "generate-id"
                    | "id"
                    | "key"
                    | "lang"
                    | "last"
                    | "local-name"
                    | "name"
                    | "namespace-uri"
                    | "normalize-space"
                    | "not"
                    | "number"
                    | "position"
                    | "round"
                    | "starts-with"
                    | "string"
                    | "string-length"
                    | "substring"
                    | "substring-after"
                    | "substring-before"
                    | "sum"
                    | "system-property"
                    | "translate"
                    | "true"
                    | "unparsed-entity-uri"
                    | "element-available"
                    | "function-available"
            )
        };
        Ok(SxdValue::Boolean(available))
    }
}

fn is_builtin_extension_function(name: &ExpandedName) -> bool {
    match name.namespace.as_deref() {
        Some(EXSLT_COMMON_NS) => matches!(name.local.as_str(), "node-set" | "object-type"),
        Some(EXSLT_STRINGS_NS) => matches!(
            name.local.as_str(),
            "split" | "tokenize" | "replace" | "align" | "padding" | "encode-uri" | "decode-uri"
        ),
        Some(EXSLT_DYNAMIC_NS) => matches!(name.local.as_str(), "evaluate" | "map"),
        Some(EXSLT_MATH_NS) => matches!(
            name.local.as_str(),
            "max" | "min" | "highest" | "lowest" | "power"
        ),
        Some(EXSLT_SETS_NS) => matches!(
            name.local.as_str(),
            "difference" | "intersection" | "distinct" | "has-same-node" | "leading" | "trailing"
        ),
        Some(EXSLT_CRYPTO_NS) => {
            matches!(
                name.local.as_str(),
                "md5" | "sha1" | "rc4_encrypt" | "rc4_decrypt"
            )
        }
        Some(crate::exslt_date::NAMESPACE) => {
            crate::exslt_date::function_names().any(|candidate| candidate == name.local)
        }
        Some(SAXON_NS) => matches!(
            name.local.as_str(),
            "expression" | "eval" | "evaluate" | "line-number" | "node-set"
        ),
        Some(XT_NS | LIBXSLT_NS) => name.local == "node-set",
        Some(LIBXSLT_TEST_NS) => name.local == "test",
        Some(LIBXSLT_TEST_PLUGIN_NS) => name.local == "testplugin",
        _ => false,
    }
}

fn one_qname_argument(
    args: Vec<SxdValue<'_>>,
    namespaces: &[(String, String)],
    function: &str,
) -> std::result::Result<ExpandedName, function::Error> {
    if args.len() != 1 {
        return Err(function::Error::Other {
            what: format!("{function}() requires one argument"),
        });
    }
    resolve_lexical_name(&args[0].string(), namespaces)
}
struct CurrentNode {
    path: NodePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NodePath {
    Ordinary(Vec<usize>),
    Attribute {
        parent: Vec<usize>,
        namespace: Option<String>,
        local: String,
    },
    Namespace {
        parent: Vec<usize>,
        prefix: String,
        uri: String,
    },
}

impl NodePath {
    fn ordinary(&self) -> &[usize] {
        match self {
            Self::Ordinary(path)
            | Self::Attribute { parent: path, .. }
            | Self::Namespace { parent: path, .. } => path,
        }
    }

    fn owned_bytes(&self) -> usize {
        let payload = self
            .ordinary()
            .len()
            .saturating_mul(std::mem::size_of::<usize>());
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::Ordinary(_) => payload,
            Self::Attribute {
                namespace, local, ..
            } => payload
                .saturating_add(namespace.as_deref().map_or(0, str::len))
                .saturating_add(local.len()),
            Self::Namespace { prefix, uri, .. } => payload
                .saturating_add(prefix.len())
                .saturating_add(uri.len()),
        })
    }
}

fn typed_path_to(node: &nodeset::Node<'_>) -> NodePath {
    match node {
        nodeset::Node::Attribute(attribute) => {
            let parent = attribute.parent();
            let name = attribute.name();
            let name = name.get();
            NodePath::Attribute {
                parent: parent
                    .map(|parent| path_to(&nodeset::Node::Element(parent)))
                    .unwrap_or_default(),
                namespace: name.namespace_uri().map(str::to_owned),
                local: name.local_part().to_owned(),
            }
        }
        nodeset::Node::Namespace(namespace) => {
            let parent = namespace.parent;
            NodePath::Namespace {
                parent: path_to(&nodeset::Node::Element(parent)),
                prefix: namespace.prefix().to_owned(),
                uri: namespace.uri().to_owned(),
            }
        }
        _ => NodePath::Ordinary(path_to(node)),
    }
}

type KeyIndex = HashMap<(ExpandedName, String, usize), Vec<NodePath>>;

struct KeyFunction {
    index: Rc<RefCell<KeyIndex>>,
    namespaces: Arc<Vec<(String, String)>>,
}
impl function::Function for KeyFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 2 {
            return Err(function::Error::Other {
                what: "key() requires exactly two arguments".into(),
            });
        }
        context.reserve_temporary_allocation(args[0].string_len())?;
        let name = resolve_lexical_name(&args[0].string(), &self.namespaces)?;
        let document_index =
            path_to(&context.node)
                .get(1)
                .copied()
                .ok_or_else(|| function::Error::Other {
                    what: "key() context has no logical document".into(),
                })?;
        let mut result = nodeset::Nodeset::new();
        let index = self.index.borrow();
        let mut lookup = |value: String| -> std::result::Result<(), function::Error> {
            if let Some(paths) = index.get(&(name.clone(), value, document_index)) {
                for path in paths {
                    if let Some(node) =
                        resolve_node_path(context.node.document().root().into(), path)
                    {
                        result.add_metered(context, node)?;
                    }
                }
            }
            Ok(())
        };
        match &args[1] {
            SxdValue::Nodeset(nodes) => {
                for node in nodes.iter() {
                    lookup(node.string_value_with_context(context)?)?;
                }
            }
            value => {
                context.reserve_temporary_allocation(value.string_len())?;
                lookup(value.string())?;
            }
        }
        Ok(SxdValue::Nodeset(result))
    }
}

struct FormatNumberFunction {
    formats: Rc<Vec<DecimalFormat>>,
    namespaces: Arc<Vec<(String, String)>>,
}
impl function::Function for FormatNumberFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if !(2..=3).contains(&args.len()) {
            return Err(function::Error::Other {
                what: "format-number() requires two or three arguments".into(),
            });
        }
        let name = if args.len() == 3 {
            Some(resolve_lexical_name(&args[2].string(), &self.namespaces)?)
        } else {
            None
        };
        let format = self
            .formats
            .iter()
            .rev()
            .find(|format| format.name == name)
            .cloned()
            .or_else(|| name.is_none().then(default_decimal_format))
            .ok_or_else(|| function::Error::Other {
                what: "unknown decimal-format".into(),
            })?;
        let pattern = args[1].string();
        context.reserve_string_allocation(decimal_render_workspace_bytes(&pattern))?;
        Ok(SxdValue::String(render_decimal(
            args[0].number(context)?,
            &pattern,
            &format,
        )?))
    }
}

fn decimal_render_workspace_bytes(pattern: &str) -> usize {
    let characters = pattern.chars().count();
    let token_storage = characters.saturating_mul(
        std::mem::size_of::<DecimalPatternToken>()
            .saturating_add(std::mem::size_of::<Vec<DecimalPatternToken>>()),
    );
    // Rendering can retain formatted, localized, grouped, and final strings concurrently.
    token_storage
        .saturating_add(pattern.len().saturating_mul(8))
        .saturating_add(2_048)
}

fn resolve_lexical_name(
    lexical: &str,
    namespaces: &[(String, String)],
) -> std::result::Result<ExpandedName, function::Error> {
    if let Some((prefix, local)) = lexical.split_once(':') {
        if !is_ncname(prefix) || !is_ncname(local) || local.contains(':') {
            return Err(function::Error::Other {
                what: format!("invalid QName {lexical}"),
            });
        }
        let namespace = namespaces
            .iter()
            .find(|(candidate, _)| candidate == prefix)
            .map(|(_, uri)| uri.clone())
            .ok_or_else(|| function::Error::Other {
                what: format!("unbound QName prefix {prefix}"),
            })?;
        Ok(ExpandedName::new(Some(namespace), local))
    } else if is_ncname(lexical) {
        Ok(ExpandedName::new(None::<String>, lexical))
    } else {
        Err(function::Error::Other {
            what: format!("invalid QName {lexical}"),
        })
    }
}

fn follow_path<'d>(mut node: nodeset::Node<'d>, path: &[usize]) -> Option<nodeset::Node<'d>> {
    for index in path {
        node = node.children().get(*index).cloned()?;
    }
    Some(node)
}

fn resolve_node_path<'d>(root: nodeset::Node<'d>, path: &NodePath) -> Option<nodeset::Node<'d>> {
    let node = follow_path(root, path.ordinary())?;
    match path {
        NodePath::Ordinary(_) => Some(node),
        NodePath::Attribute {
            namespace, local, ..
        } => node
            .element()?
            .attributes()
            .into_iter()
            .find(|attribute| {
                let name = attribute.name();
                let name = name.get();
                name.local_part() == local && name.namespace_uri() == namespace.as_deref()
            })
            .map(nodeset::Node::Attribute),
        NodePath::Namespace { prefix, uri, .. } => resolve_namespace_node(node, prefix, uri),
    }
}

fn resolve_namespace_node<'d>(
    node: nodeset::Node<'d>,
    prefix: &str,
    uri: &str,
) -> Option<nodeset::Node<'d>> {
    let element = node.element()?;
    if prefix.is_empty()
        && element
            .recursive_default_namespace_uri()
            .as_deref()
            .is_some_and(|namespace| namespace == uri)
    {
        return Some(nodeset::Node::Namespace(nodeset::Namespace {
            parent: element,
            prefix: sxd_document_no_unsafe::to_ns_str!(prefix),
            uri: sxd_document_no_unsafe::to_ns_str!(uri),
        }));
    }
    element
        .namespaces_in_scope()
        .into_iter()
        .find(|namespace| namespace.prefix() == prefix && namespace.uri() == uri)
        .map(|namespace| {
            nodeset::Node::Namespace(nodeset::Namespace {
                parent: element,
                prefix: sxd_document_no_unsafe::to_ns_str!(namespace.prefix()),
                uri: sxd_document_no_unsafe::to_ns_str!(namespace.uri()),
            })
        })
}

fn default_decimal_format() -> DecimalFormat {
    DecimalFormat {
        name: None,
        precedence: 0,
        decimal_separator: '.',
        grouping_separator: ',',
        infinity: "Infinity".into(),
        minus_sign: '-',
        nan: "NaN".into(),
        percent: '%',
        per_mille: '‰',
        zero_digit: '0',
        digit: '#',
        pattern_separator: ';',
        specified: 0,
    }
}

fn render_decimal(
    value: f64,
    pattern: &str,
    format: &DecimalFormat,
) -> std::result::Result<String, function::Error> {
    if value.is_nan() {
        return Ok(format.nan.clone());
    }
    let alternatives = tokenize_decimal_pattern(pattern, format)?;
    let negative = value.is_sign_negative();
    // java.text.DecimalFormat defines the negative subpattern as an affix override only;
    // digit counts, grouping, and all other numeric shape come from the positive subpattern.
    // https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/text/DecimalFormat.html
    let negative_subpattern = negative && alternatives.len() > 1;
    let affix_pattern = if negative_subpattern {
        &alternatives[1]
    } else {
        &alternatives[0]
    };
    let number_pattern = &alternatives[0];
    let multiplier = if number_pattern
        .iter()
        .any(|token| token.syntax && token.value == format.percent)
    {
        100.0
    } else if number_pattern
        .iter()
        .any(|token| token.syntax && token.value == format.per_mille)
    {
        1000.0
    } else {
        1.0
    };
    let (number_first, number_last) = decimal_pattern_bounds(number_pattern, format)?;
    let (affix_first, affix_last) = decimal_pattern_bounds(affix_pattern, format)?;
    let scaled = value.abs() * multiplier;
    if scaled.is_infinite() {
        let mut output = String::new();
        if negative && !negative_subpattern {
            output.push(format.minus_sign);
        }
        output.extend(affix_pattern[..affix_first].iter().map(|token| token.value));
        output.push_str(&format.infinity);
        output.extend(affix_pattern[affix_last..].iter().map(|token| token.value));
        return Ok(output);
    }
    let number = &number_pattern[number_first..number_last];
    let decimal = number
        .iter()
        .position(|token| token.syntax && token.value == format.decimal_separator);
    let (integer_pattern, fraction_pattern) = decimal.map_or((number, &[][..]), |index| {
        (&number[..index], &number[index + 1..])
    });
    let minimum_integer = integer_pattern
        .iter()
        .filter(|token| token.syntax && token.value == format.zero_digit)
        .count();
    let minimum_fraction = fraction_pattern
        .iter()
        .filter(|token| token.syntax && token.value == format.zero_digit)
        .count();
    let mut maximum_fraction = fraction_pattern
        .iter()
        .filter(|token| {
            token.syntax && matches!(token.value, value if value == format.zero_digit || value == format.digit)
        })
        .count();
    let mut minimum_fraction = minimum_fraction;
    if integer_pattern.is_empty()
        && number
            .first()
            .is_some_and(|token| token.syntax && token.value == format.decimal_separator)
        && maximum_fraction > 0
    {
        minimum_fraction = minimum_fraction.max(1);
        maximum_fraction = maximum_fraction.max(1);
    }
    let factor = 10_f64.powi(i32::try_from(maximum_fraction).unwrap_or(i32::MAX));
    let shifted = scaled * factor;
    let rounded = if factor.is_finite() && shifted.is_finite() {
        // XSLT 1.0 section 12.3 adopts the JDK 1.1 picture syntax but does not mandate a
        // rounding mode. Match libxslt 1.1.45's `floor(scale * fraction + 0.5)` behavior so
        // midpoint formatting remains interoperable with the pinned oracle.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
        (shifted + 0.5).floor() / factor
    } else {
        // XSLT 1.0 section 12.3 delegates picture precision to DecimalFormat. Once the decimal
        // scale exceeds finite f64 powers, fixed-precision rendering performs the remaining
        // rounding without turning a finite input into NaN through `infinity / infinity`.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
        scaled
    };
    let mut rendered = format!("{rounded:.maximum_fraction$}");
    if maximum_fraction > minimum_fraction && rendered.contains('.') {
        while rendered.ends_with('0')
            && rendered.split('.').nth(1).map_or(0, str::len) > minimum_fraction
        {
            rendered.pop();
        }
        if rendered.ends_with('.') {
            rendered.pop();
        }
    }
    let (integer, fraction) = rendered.split_once('.').unwrap_or((&rendered, ""));
    let mut integer = format!("{integer:0>minimum_integer$}");
    if minimum_integer == 0 && minimum_fraction > 0 && integer == "0" {
        integer.clear();
    }
    if format.zero_digit != '0' {
        integer = localize_generated_decimal_digits(&integer, format.zero_digit);
    }
    let localized_fraction = (format.zero_digit != '0')
        .then(|| localize_generated_decimal_digits(fraction, format.zero_digit));
    let fraction = localized_fraction.as_deref().unwrap_or(fraction);
    if let Some(group) = integer_pattern
        .iter()
        .rposition(|token| token.syntax && token.value == format.grouping_separator)
    {
        let size = integer_pattern[group + 1..]
            .iter()
            .filter(|token| {
                token.syntax
                    && matches!(token.value, value if value == format.zero_digit || value == format.digit)
            })
            .count();
        if size > 0 {
            let chars = integer.chars().rev().collect::<Vec<_>>();
            integer = chars
                .chunks(size)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(&format.grouping_separator.to_string())
                .chars()
                .rev()
                .collect();
        }
    }
    let mut output = String::new();
    if negative && !negative_subpattern {
        output.push(format.minus_sign);
    }
    output.extend(affix_pattern[..affix_first].iter().map(|token| token.value));
    output.push_str(&integer);
    if !fraction.is_empty()
        || number
            .last()
            .is_some_and(|token| token.syntax && token.value == format.decimal_separator)
    {
        output.push(format.decimal_separator);
        if !fraction.is_empty() {
            output.push_str(fraction);
        }
    }
    output.extend(affix_pattern[affix_last..].iter().map(|token| token.value));
    Ok(output)
}

fn localize_generated_decimal_digits(value: &str, zero_digit: char) -> String {
    value
        .chars()
        .map(|character| {
            character
                .to_digit(10)
                .filter(|_| character.is_ascii_digit())
                .and_then(|digit| char::from_u32(u32::from(zero_digit) + digit))
                .unwrap_or(character)
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecimalPatternToken {
    value: char,
    syntax: bool,
}

fn tokenize_decimal_pattern(
    pattern: &str,
    format: &DecimalFormat,
) -> std::result::Result<Vec<Vec<DecimalPatternToken>>, function::Error> {
    let mut alternatives = vec![Vec::new()];
    let mut quoted = false;
    let mut characters = pattern.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\'' {
            if characters.peek() == Some(&'\'') {
                characters.next();
                alternatives
                    .last_mut()
                    .expect("decimal pattern has one subpattern")
                    .push(DecimalPatternToken {
                        value: '\'',
                        syntax: false,
                    });
            } else {
                quoted = !quoted;
            }
            continue;
        }
        if !quoted && character == format.pattern_separator {
            alternatives.push(Vec::new());
            continue;
        }
        alternatives
            .last_mut()
            .expect("decimal pattern has one subpattern")
            .push(DecimalPatternToken {
                value: character,
                syntax: !quoted,
            });
    }
    if quoted {
        return Err(function::Error::Other {
            what: "format-number pattern has an unterminated quoted literal".into(),
        });
    }
    if alternatives.len() > 2 {
        return Err(invalid_decimal_pattern("more than two subpatterns"));
    }
    for alternative in &alternatives {
        validate_decimal_subpattern(alternative, format)?;
    }
    Ok(alternatives)
}

fn validate_decimal_subpattern(
    pattern: &[DecimalPatternToken],
    format: &DecimalFormat,
) -> std::result::Result<(), function::Error> {
    let mut first = None;
    let mut last = None;
    let mut scaling_symbols = 0usize;
    for (index, token) in pattern.iter().enumerate().filter(|(_, token)| token.syntax) {
        if is_decimal_number_marker(token.value, format) {
            first.get_or_insert(index);
            last = Some(index);
        }
        if token.value == format.percent || token.value == format.per_mille {
            scaling_symbols = scaling_symbols.saturating_add(1);
        }
    }
    if scaling_symbols > 1 {
        return Err(invalid_decimal_pattern(
            "subpattern has more than one percent or per-mille symbol",
        ));
    }
    let (first, last) = first
        .zip(last)
        .ok_or_else(|| invalid_decimal_pattern("subpattern has no digit"))?;
    let number = &pattern[first..=last];
    let mut has_digit = false;
    let mut saw_decimal = false;
    let mut saw_required_integer = false;
    let mut saw_optional_fraction = false;
    for token in number {
        if !token.syntax {
            return Err(invalid_decimal_pattern(
                "numeric portion contains a quoted literal",
            ));
        }
        if token.value == format.zero_digit {
            has_digit = true;
            if saw_decimal {
                if saw_optional_fraction {
                    return Err(invalid_decimal_pattern(
                        "required fractional digit follows an optional digit",
                    ));
                }
            } else {
                saw_required_integer = true;
            }
        } else if token.value == format.digit {
            has_digit = true;
            if saw_decimal {
                saw_optional_fraction = true;
            } else if saw_required_integer {
                return Err(invalid_decimal_pattern(
                    "optional integer digit follows a required digit",
                ));
            }
        } else if token.value == format.decimal_separator {
            if saw_decimal {
                return Err(invalid_decimal_pattern(
                    "subpattern has more than one decimal separator",
                ));
            }
            saw_decimal = true;
        } else if token.value == format.grouping_separator {
            if saw_decimal {
                return Err(invalid_decimal_pattern(
                    "grouping separator appears in the fractional portion",
                ));
            }
        } else {
            return Err(invalid_decimal_pattern(
                "numeric portion contains an affix symbol",
            ));
        }
    }
    if !has_digit && !(number.len() == 1 && saw_decimal) {
        return Err(invalid_decimal_pattern("subpattern has no digit"));
    }
    Ok(())
}

fn is_decimal_digit_symbol(value: char, format: &DecimalFormat) -> bool {
    value == format.zero_digit || value == format.digit
}

fn is_decimal_number_marker(value: char, format: &DecimalFormat) -> bool {
    is_decimal_digit_symbol(value, format) || value == format.decimal_separator
}

fn invalid_decimal_pattern(reason: &str) -> function::Error {
    function::Error::Other {
        what: format!("invalid format-number pattern: {reason}"),
    }
}

fn decimal_pattern_bounds(
    pattern: &[DecimalPatternToken],
    format: &DecimalFormat,
) -> std::result::Result<(usize, usize), function::Error> {
    let first = pattern.iter().position(|token| {
        token.syntax
            && matches!(token.value, value if value == format.digit || value == format.zero_digit || value == format.decimal_separator)
    });
    let last = pattern.iter().rposition(|token| {
        token.syntax
            && matches!(token.value, value if value == format.digit || value == format.zero_digit || value == format.decimal_separator)
    });
    first
        .zip(last)
        .map(|(first, last)| (first, last + 1))
        .ok_or_else(|| invalid_decimal_pattern("subpattern has no digit"))
}
impl function::Function for CurrentNode {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if !args.is_empty() {
            return Err(function::Error::TooManyArguments {
                expected: 0,
                actual: args.len(),
            });
        }
        let path = self.path.ordinary();
        let mut node = nodeset::Node::Root(context.node.document().root());
        for index in path {
            node = node
                .children()
                .get(*index)
                .cloned()
                .ok_or_else(|| function::Error::Other {
                    what: "current() context is stale".into(),
                })?;
        }
        match &self.path {
            NodePath::Ordinary(_) => {}
            NodePath::Attribute {
                namespace, local, ..
            } => {
                let element = node.element().ok_or_else(|| function::Error::Other {
                    what: "current() owner is stale".into(),
                })?;
                let attribute = element
                    .attributes()
                    .into_iter()
                    .find(|attribute| {
                        let name = attribute.name();
                        let name = name.get();
                        name.local_part() == local && name.namespace_uri() == namespace.as_deref()
                    })
                    .ok_or_else(|| function::Error::Other {
                        what: "current() attribute is stale".into(),
                    })?;
                node = nodeset::Node::Attribute(attribute);
            }
            NodePath::Namespace { prefix, uri, .. } => {
                node = resolve_namespace_node(node, prefix, uri).ok_or_else(|| {
                    function::Error::Other {
                        what: "current() owner is stale".into(),
                    }
                })?;
            }
        }
        let mut set = nodeset::Nodeset::new();
        set.add(node);
        Ok(SxdValue::Nodeset(set))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExecutionBudget;
    use sxd_xpath_no_unsafe::function::Function;

    #[test]
    fn absolute_path_rewrite_distinguishes_div_name_tests_from_operators() {
        for path in ["div/span", "root/div/span"] {
            assert_eq!(rewrite_absolute_paths_for_validation(path), path);
        }
        assert_ne!(
            rewrite_absolute_paths_for_validation("1 div /root"),
            "1 div /root"
        );
    }

    #[test]
    fn variable_overlay_borrows_existing_payloads() {
        let name = ExpandedName::new(None::<String>, "payload");
        let mut base = HashMap::new();
        base.insert(name.clone(), Value::String("retained payload".into()));
        let overlay = VariableOverlay::new(&base);
        let Some(Value::String(original)) = base.get(&name) else {
            panic!("base payload is missing");
        };
        let Some(Value::String(borrowed)) = overlay.get(&name) else {
            panic!("overlay payload is missing");
        };
        assert!(std::ptr::eq(original, borrowed));
    }

    #[test]
    fn function_available_shares_the_stylesheet_catalog() {
        let catalog = Arc::new(HashSet::from([ExpandedName::new(
            Some("urn:extension"),
            "function",
        )]));
        let function = FunctionAvailable {
            namespaces: Arc::new(vec![]),
            stylesheet_functions: Arc::clone(&catalog),
        };

        assert!(Arc::ptr_eq(&function.stylesheet_functions, &catalog));
    }

    #[test]
    fn outer_context_functions_accept_xpath_whitespace() {
        // XPath allows whitespace between a function name and its empty
        // argument list; rewriting must not depend on one lexical spelling.
        assert_eq!(
            rewrite_outer_context_functions("position \t( ) + last\n(\r)", "__xml_sec_ctx",),
            "$__xml_sec_ctx:position + $__xml_sec_ctx:last"
        );
    }

    #[test]
    fn outer_context_rewrite_respects_unicode_ncname_boundaries() {
        // XML Names permits combining marks after the first NCName character. A built-in-looking
        // suffix inside such a QName must remain a call to that QName, not become an outer-context
        // variable reference.
        let source = "f:a\u{0301}position() + position()";
        assert_eq!(
            rewrite_outer_context_functions(source, "__xml_sec_ctx"),
            "f:a\u{0301}position() + $__xml_sec_ctx:position"
        );
    }

    #[test]
    fn rc4_extensions_reserve_workspace_before_allocating() {
        // The extension must preflight all key, input, cipher, and hexadecimal buffers against
        // the evaluator's allocation budget before materializing attacker-controlled data.
        let package = Package::new();
        let document = package.as_document();
        let mut context = Context::new();
        context.set_string_allocation_limit(1024);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        for (function, input) in [
            (ExsltCryptoFunction::Rc4Encrypt, "x".repeat(2048)),
            (ExsltCryptoFunction::Rc4Decrypt, "00".repeat(2048)),
        ] {
            let error = function
                .evaluate(
                    &evaluation,
                    vec![SxdValue::String("key".into()), SxdValue::String(input)],
                )
                .expect_err("workspace exceeds the evaluator budget");
            assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
        }
    }

    #[test]
    fn rc4_decrypt_rejects_non_ascii_hex_without_panicking() {
        // Ciphertext is attacker-controlled XPath string data. Invalid UTF-8 byte pairs must
        // reach the typed hexadecimal error instead of an infallible conversion assertion.
        let package = Package::new();
        let document = package.as_document();
        let context = Context::new();
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        let error = ExsltCryptoFunction::Rc4Decrypt
            .evaluate(
                &evaluation,
                vec![
                    SxdValue::String("key".into()),
                    SxdValue::String("😀".into()),
                ],
            )
            .expect_err("non-ASCII ciphertext is not hexadecimal");
        assert!(matches!(
            error,
            function::Error::Other { what } if what.contains("invalid hex")
        ));
    }

    #[test]
    fn hash_extensions_reserve_materialization_and_output_before_allocating() {
        // Node string-value coercion and fixed-size hexadecimal output must both cross the
        // evaluator allocation gate before the extension materializes either buffer.
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        root.append_child(document.create_text(&"x".repeat(2048)));
        document.root().append_child(root);
        let mut nodes = nodeset::Nodeset::new();
        nodes.add(root);

        for function in [ExsltCryptoFunction::Md5, ExsltCryptoFunction::Sha1] {
            let mut context = Context::new();
            context.set_string_allocation_limit(1024);
            let evaluation =
                sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
            let error = function
                .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes.clone())])
                .expect_err("hash workspace exceeds the evaluator budget");
            assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
        }

        for (function, output_len) in [
            (ExsltCryptoFunction::Md5, 32),
            (ExsltCryptoFunction::Sha1, 40),
        ] {
            let mut context = Context::new();
            context.set_string_allocation_limit(output_len - 1);
            let evaluation =
                sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
            let error = function
                .evaluate(&evaluation, vec![SxdValue::String("x".into())])
                .expect_err("hexadecimal output exceeds the evaluator budget");
            assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
        }
    }

    #[test]
    fn node_name_functions_reserve_qualified_name_before_materializing_it() {
        // General XPath evaluation can reduce name() to a scalar immediately, but the temporary
        // QName must still cross the evaluator's owned-memory gate before allocation.
        let package = Package::new();
        let document = package.as_document();
        let local = "n".repeat(2048);
        let element = document.create_element(("urn:test", local.as_str()));
        element.set_preferred_prefix(Some("prefix"));
        document.root().append_child(element);
        let mut nodes = nodeset::Nodeset::new();
        nodes.add(element);
        let mut context = Context::new();
        context.set_string_allocation_limit(1024);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

        let error = NodeNameFunction::Qualified
            .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
            .expect_err("qualified name exceeds the evaluator allocation budget");
        assert!(matches!(error, function::Error::Other { what } if what.contains("budget")));
    }

    #[test]
    fn key_and_document_nodeset_arguments_obey_the_allocation_budget() {
        // XSLT node-set arguments can contain many large string-values. key() and document()
        // must not retain an unmetered batch before performing their lookups.
        let package = Package::new();
        let document = package.as_document();
        let documents = document.create_element("documents");
        let logical = document.create_element("logical");
        document.root().append_child(documents);
        documents.append_child(logical);
        let mut nodes = nodeset::Nodeset::new();
        for _ in 0..8 {
            let item = document.create_element("item");
            item.append_child(document.create_text(&"x".repeat(1_024)));
            logical.append_child(item);
            nodes.add(item);
        }
        let mut xpath_context = Context::new();
        xpath_context.set_string_allocation_limit(128);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&xpath_context, logical.into());

        let key = KeyFunction {
            index: Rc::new(RefCell::new(HashMap::new())),
            namespaces: Arc::new(Vec::new()),
        };
        assert!(matches!(
            key.evaluate(
                &evaluation,
                vec![SxdValue::String("missing".into()), SxdValue::Nodeset(nodes.clone())],
            ),
            Err(function::Error::Other { what }) if what.contains("budget")
        ));

        let document_function = DocumentFunction {
            roots: Rc::new(RefCell::new(HashMap::new())),
            pending: Rc::new(RefCell::new(HashSet::new())),
            node_base_uris: Rc::new(RefCell::new(HashMap::new())),
            static_base_uri: None,
        };
        assert!(matches!(
            document_function
                .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)]),
            Err(function::Error::Other { what }) if what.contains("budget")
        ));
    }

    #[test]
    fn ordinary_xpath_rewrite_pipeline_keeps_borrowed_storage() {
        // Repeated evaluation of a cached relative XPath must not allocate intermediate
        // normalization strings when none of the internal rewrites apply.
        let source = "item/@name";
        let normalized = normalize_xpath_for_sxd(source);
        assert!(matches!(&normalized, std::borrow::Cow::Borrowed(_)));
        let isolated = hide_projection_elements_from_axes(&normalized);
        assert!(matches!(&isolated, std::borrow::Cow::Borrowed(_)));
        let context = rewrite_outer_context_functions(&isolated, "__xml_sec_ctx");
        assert!(matches!(context, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn document_fragment_decode_reserves_owned_output_before_allocation() {
        // Percent decoding must cross the same operation-owned-memory gate as every other
        // attacker-controlled temporary buffer, before capacity is allocated.
        let mut meter = Meter::new(
            ExecutionBudget {
                source_bytes: 0,
                external_documents: 0,
                recursion_depth: 0,
                xpath_evaluations: 0,
                template_applications: 0,
                sort_comparisons: 0,
                key_entries: 0,
                result_nodes: 0,
                serialized_bytes: 0,
                messages: 0,
                owned_bytes: 1,
            },
            0,
        )
        .expect("empty source fits the test budget");
        assert!(matches!(
            decode_document_fragment("%C3%A9", &mut meter),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn token_documents_charge_tree_containers_in_addition_to_payloads() {
        // Two one-byte token payloads consume twelve bytes including their element names. A
        // budget of exactly that size must still reject the arena and child-vector allocations.
        let mut meter = Meter::new(
            ExecutionBudget {
                source_bytes: 0,
                external_documents: 0,
                recursion_depth: 0,
                xpath_evaluations: 0,
                template_applications: 0,
                sort_comparisons: 0,
                key_entries: 0,
                result_nodes: 4,
                serialized_bytes: 0,
                messages: 0,
                owned_bytes: 12,
            },
            0,
        )
        .expect("empty source fits the payload-only budget");
        assert!(matches!(
            token_document("a b", " ", ExtensionCallKind::Split, &mut meter),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
    }

    #[test]
    fn clear_pattern_cache_releases_owned_bytes() {
        // Cache invalidation must return the exact reservation charged for keys and node sets;
        // otherwise repeated key-index construction eventually exhausts a bounded operation.
        let key: PatternCacheKey = (
            "item[@kind='retained']".into(),
            vec![("p".into(), "urn:retained".into())],
            NodeId::test(0),
        );
        let nodes = HashSet::from([
            SourceNode::Node(NodeId::test(1)),
            SourceNode::Node(NodeId::test(2)),
        ]);
        let reserved = pattern_cache_entry_owned_bytes(&key, nodes.len());
        let mut cache = HashMap::from([(key, nodes)]);
        let mut meter = Meter::new(
            ExecutionBudget {
                source_bytes: usize::MAX,
                external_documents: usize::MAX,
                recursion_depth: usize::MAX,
                xpath_evaluations: usize::MAX,
                template_applications: usize::MAX,
                sort_comparisons: usize::MAX,
                key_entries: usize::MAX,
                result_nodes: usize::MAX,
                serialized_bytes: usize::MAX,
                messages: usize::MAX,
                owned_bytes: usize::MAX,
            },
            0,
        )
        .expect("empty source fits the test budget");
        meter
            .charge(BudgetKind::OwnedBytes, reserved)
            .expect("cache reservation fits");

        clear_pattern_cache(&mut cache, &mut meter);

        assert!(cache.is_empty());
        assert_eq!(cache.capacity(), 0);
        assert_eq!(
            meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
            0
        );
    }

    #[test]
    fn document_cache_keys_reserve_both_owned_requests() {
        // The request is cloned into document_roots and moved into documents, so both retained
        // keys and both copies of their attacker-controlled strings must cross the same gate.
        let request = DocumentRequest {
            href: "relative/retained/document.xml".repeat(8),
            base_uri: Some("memory:retained/base/".repeat(8)),
            empty_document: None,
        };
        let reserved = document_cache_key_owned_bytes(&request);
        let limits = |owned_bytes| ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: usize::MAX,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes,
        };
        let mut insufficient =
            Meter::new(limits(reserved - 1), 0).expect("empty source fits the test budget");
        assert!(matches!(
            charge_document_cache_keys(&request, &mut insufficient),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                actual,
                ..
            }) if actual == reserved
        ));

        let mut exact =
            Meter::new(limits(reserved), 0).expect("empty source fits the exact budget");
        charge_document_cache_keys(&request, &mut exact).expect("exact reservation fits");
        assert_eq!(
            exact.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
            reserved
        );
    }

    #[test]
    fn source_clone_is_reserved_even_without_retained_source_xml() {
        // Result-like documents have no lexical source bytes, but cloning their semantic arena
        // must still cross the same owned-memory gate before allocation.
        let source = Document::empty(None);
        let limits = ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: usize::MAX,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes: 0,
        };
        let mut meter = Meter::new(limits, 0).expect("zero lexical bytes fit");
        let options = EvaluatorSourceOptions {
            processing: SourceProcessing::Xml,
            whitespace: Arc::from([]),
            clock: Arc::new(crate::SystemClock),
            extension_policy: ExtensionPolicy::Compatible,
        };

        assert!(matches!(
            prepare_evaluator_source(&source, &crate::NoResolver, &mut meter, &options),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
    }

    #[test]
    fn stylesheet_imports_are_reserved_as_one_batch_before_copying() {
        // Principal and module arenas are imported into one execution document. The complete
        // clone footprint must cross OwnedBytes before the first import can allocate anything.
        let principal = Document::parse("<stylesheet/>", None).expect("principal parses");
        let module =
            Document::parse("<stylesheet><node/></stylesheet>", None).expect("module parses");
        let modules = [("memory:module.xsl".to_owned(), module)];
        let required = principal
            .estimated_clone_bytes()
            .saturating_add(modules[0].1.estimated_clone_bytes());
        let limits = ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: usize::MAX,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes: required - 1,
        };
        let mut meter = Meter::new(limits, 0).expect("empty source fits");

        assert!(matches!(
            reserve_stylesheet_imports(&principal, &modules, &mut meter),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                actual,
                ..
            }) if actual == required
        ));
        assert_eq!(
            meter.usage(BudgetKind::OwnedBytes).expect("valid kind").0,
            0
        );
    }

    #[test]
    fn set_distinct_reserves_string_values_before_allocating_them() {
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        document.root().append_child(root);
        let mut nodes = nodeset::Nodeset::new();
        for value in ["first retained value", "second retained value"] {
            let child = document.create_element("item");
            child.append_child(document.create_text(value));
            root.append_child(child);
            nodes.add(child);
        }
        let mut context = Context::new();
        context.set_string_allocation_limit(1);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

        let error = ExsltSetFunction::Distinct
            .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
            .expect_err("distinct storage must cross the allocation gate");
        assert!(error.to_string().contains("allocation budget"));
    }

    #[test]
    fn id_nodeset_arguments_stream_through_the_allocation_gate() {
        // id() needs every node's string-value but does not retain those values. It must meter
        // each temporary while avoiding simultaneous retention in an unbounded Vec<String>.
        let package = Package::new();
        let document = package.as_document();
        let container = document.create_element("container");
        let logical_document = document.create_element("document");
        let target = document.create_element("target");
        let argument = document.create_element("ids");
        argument.append_child(document.create_text("target"));
        logical_document.append_child(target);
        logical_document.append_child(argument);
        container.append_child(logical_document);
        document.root().append_child(container);

        let mut indexed = HashMap::new();
        indexed.insert(
            "target".into(),
            typed_path_to(&nodeset::Node::Element(target)),
        );
        let function = IdFunction {
            nodes_by_document: Rc::new(RefCell::new(vec![indexed])),
        };
        let mut nodes = nodeset::Nodeset::new();
        nodes.add(argument);
        let mut context = Context::new();
        context.set_string_allocation_limit("target".len() - 1);
        let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(
            &context,
            nodeset::Node::Element(logical_document),
        );

        let error = function
            .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
            .expect_err("id node string-value must cross the allocation gate");
        assert!(error.to_string().contains("allocation budget"));
    }

    #[test]
    fn unparsed_entity_uri_uses_the_dynamic_context_document() {
        // XSLT 1.0 section 12.4 resolves the entity in the document containing the context node,
        // not in the principal document captured when the expression was compiled.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#misc-func
        let package = Package::new();
        let document = package.as_document();
        let documents = document.create_element("documents");
        document.root().append_child(documents);
        let first = document.create_element("document");
        let second = document.create_element("document");
        documents.append_child(first);
        documents.append_child(second);
        let context_node = document.create_element("external");
        second.append_child(context_node);
        let context = Context::new();
        let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(
            &context,
            nodeset::Node::Element(context_node),
        );
        let function = UnparsedEntityUriFunction {
            documents: Rc::new(RefCell::new(vec![
                HashMap::from([("logo".into(), "principal.png".into())]),
                HashMap::from([("logo".into(), "external.png".into())]),
            ])),
        };

        assert_eq!(
            function
                .evaluate(&evaluation, vec![SxdValue::String("logo".into())])
                .expect("entity URI resolves"),
            SxdValue::String("external.png".into())
        );
    }

    #[test]
    fn math_node_functions_reserve_workspace_before_allocating_it() {
        // All four node-set math functions share ordered-node, numeric, and string-value
        // workspace, which must be rejected before allocation when the budget is exhausted.
        for function in [
            ExsltMathFunction::Max,
            ExsltMathFunction::Min,
            ExsltMathFunction::Highest,
            ExsltMathFunction::Lowest,
        ] {
            let package = Package::new();
            let document = package.as_document();
            let root = document.create_element("root");
            document.root().append_child(root);
            let child = document.create_element("item");
            child.append_child(document.create_text("123456789"));
            root.append_child(child);
            let mut nodes = nodeset::Nodeset::new();
            nodes.add(child);
            let mut context = Context::new();
            context.set_string_allocation_limit(1);
            let evaluation =
                sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

            let error = function
                .evaluate(&evaluation, vec![SxdValue::Nodeset(nodes)])
                .expect_err("math workspace must cross the allocation gate");
            assert!(error.to_string().contains("allocation budget"));
        }
    }

    #[test]
    fn string_align_reserves_output_before_constructing_it() {
        let package = Package::new();
        let document = package.as_document();
        let mut context = Context::new();
        context.set_string_allocation_limit(1);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());

        let error = ExsltStringFunction::Align
            .evaluate(
                &evaluation,
                vec![
                    SxdValue::String("λ".into()),
                    SxdValue::String("........".into()),
                    SxdValue::String("center".into()),
                ],
            )
            .expect_err("aligned output must cross the allocation gate");
        assert!(error.to_string().contains("allocation budget"));
    }

    #[test]
    fn format_number_reserves_dynamic_pattern_workspace_before_rendering() {
        // The decimal pattern may come from untrusted XPath data. Token and precision buffers
        // must cross the operation allocation gate before the renderer materializes them.
        let package = Package::new();
        let document = package.as_document();
        let mut context = Context::new();
        context.set_string_allocation_limit(1);
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        let function = FormatNumberFunction {
            formats: Rc::new(Vec::new()),
            namespaces: Arc::new(Vec::new()),
        };

        let error = function
            .evaluate(
                &evaluation,
                vec![SxdValue::Number(1.25), SxdValue::String("0.0000".into())],
            )
            .expect_err("decimal rendering workspace must cross the allocation gate");
        assert!(error.to_string().contains("allocation budget"));
    }

    #[test]
    fn encode_uri_uses_the_rfc_2396_reserved_set() {
        // RFC 2396 section 2.2 does not classify square brackets as reserved, so EXSLT encodes
        // them even when reserved delimiters are preserved.
        // https://www.rfc-editor.org/rfc/rfc2396#section-2.2
        assert_eq!(
            percent_encode_uri("[]", false, 6, UriEncoding::Standard(encoding_rs::UTF_8))
                .expect("UTF-8 encoding succeeds"),
            "%5B%5D"
        );
    }
}
