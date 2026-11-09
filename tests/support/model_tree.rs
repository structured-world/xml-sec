//! An application-owned document tree for tests of tree-backed documents.
//!
//! Nodes live in one arena and are never reused, so a node's reference stays
//! the same across edits the way a libxml2 node pointer does; a test can tell
//! which nodes an operation kept and which it replaced.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use xml_sec::document::external::{
    ExternalNode, ExternalTree, Fragment, FragmentEvent, TreeEdit, TreeEditError, TreeSink,
};
use xml_sec::{Document, Node, NodeType, ParseError};

#[derive(Clone, Debug)]
enum Kind {
    Document,
    Element {
        local: String,
        prefix: Option<String>,
        namespace: Option<String>,
        declarations: Vec<(Option<String>, String)>,
        attributes: Vec<Attribute>,
    },
    Text(String),
    Comment(String),
    Pi(String, Option<String>),
}

#[derive(Clone, Debug)]
struct Attribute {
    local: String,
    prefix: Option<String>,
    namespace: Option<String>,
    value: String,
}

#[derive(Clone, Debug)]
struct Slot {
    kind: Kind,
    children: Vec<usize>,
}

/// One undo step: the children a node had before an edit.
#[derive(Clone, Debug)]
struct Undo {
    node: usize,
    children: Vec<usize>,
}

#[derive(Debug, Default)]
struct State {
    slots: Vec<Slot>,
    journal: Vec<Undo>,
}

/// A shared handle: the document owns one, the test keeps another to read
/// the tree after operations.
#[derive(Clone, Debug, Default)]
pub struct ModelTree(Arc<Mutex<State>>);

const DOCUMENT: usize = 0;

impl ModelTree {
    /// The tree of `xml`, built node by node.
    pub fn parse(xml: &str) -> Self {
        let document = Document::parse(xml).expect("test XML parses");
        let mut state = State::default();
        state.slots.push(Slot {
            kind: Kind::Document,
            children: Vec::new(),
        });
        for child in document.root().children() {
            let node = copy(&mut state, child);
            state.slots[DOCUMENT].children.push(node);
        }
        Self(Arc::new(Mutex::new(state)))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().expect("the model tree is not poisoned")
    }

    /// The tree serialized, every element with its own declarations.
    pub fn to_xml(&self) -> String {
        let state = self.state();
        let mut output = String::new();
        for &child in &state.slots[DOCUMENT].children {
            write_node(&state, child, &mut output);
        }
        output
    }

    /// References of every node reachable from the document, in document order.
    pub fn nodes(&self) -> Vec<ExternalNode> {
        let state = self.state();
        let mut nodes = Vec::new();
        collect(&state, DOCUMENT, &mut nodes);
        nodes
    }

    /// The reference of the first element named `local`.
    pub fn element(&self, local: &str) -> ExternalNode {
        let state = self.state();
        let mut nodes = Vec::new();
        collect(&state, DOCUMENT, &mut nodes);
        nodes
            .into_iter()
            .find(|node| {
                matches!(&state.slots[reference_index(*node)].kind,
                    Kind::Element { local: name, .. } if name == local)
            })
            .expect("the tree has the element")
    }

    /// Undo records the tree still holds.
    pub fn pending_undo(&self) -> usize {
        self.state().journal.len()
    }
}

fn reference(index: usize) -> ExternalNode {
    ExternalNode(index as u64 + 1)
}

fn reference_index(node: ExternalNode) -> usize {
    usize::try_from(node.0 - 1).expect("references fit")
}

fn copy(state: &mut State, node: Node<'_, '_>) -> usize {
    let kind = match node.node_type() {
        NodeType::Element => {
            let name = node.tag_name();
            let parent = node.parent_element();
            let declarations = node
                .namespaces()
                .filter(|namespace| {
                    parent
                        .and_then(|parent| parent.lookup_namespace_uri(namespace.name()))
                        .unwrap_or_default()
                        != namespace.uri()
                })
                .map(|namespace| (namespace.name().map(String::from), namespace.uri().into()))
                .collect();
            let attributes = node
                .attributes()
                .map(|attribute| Attribute {
                    local: attribute.name().into(),
                    prefix: attribute.prefix().map(String::from),
                    namespace: attribute.namespace().map(String::from),
                    value: attribute.value().into(),
                })
                .collect();
            Kind::Element {
                local: name.name().into(),
                prefix: node.prefix().map(String::from),
                namespace: name.namespace().map(String::from),
                declarations,
                attributes,
            }
        }
        NodeType::Text => Kind::Text(node.text().unwrap_or_default().into()),
        NodeType::Comment => Kind::Comment(node.text().unwrap_or_default().into()),
        NodeType::PI => {
            let pi = node.pi().expect("a processing instruction");
            Kind::Pi(pi.target.into(), pi.value.map(String::from))
        }
        NodeType::Root => unreachable!("the root is the document slot"),
    };
    let index = state.slots.len();
    state.slots.push(Slot {
        kind,
        children: Vec::new(),
    });
    for child in node.children() {
        let child = copy(state, child);
        state.slots[index].children.push(child);
    }
    index
}

fn collect(state: &State, index: usize, nodes: &mut Vec<ExternalNode>) {
    nodes.push(reference(index));
    for &child in &state.slots[index].children {
        collect(state, child, nodes);
    }
}

fn escape(value: &str, attribute: bool, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' if attribute => output.push_str("&quot;"),
            '\r' => output.push_str("&#xD;"),
            character => output.push(character),
        }
    }
}

fn qualified(prefix: Option<&str>, local: &str) -> String {
    prefix.map_or_else(|| local.to_owned(), |prefix| format!("{prefix}:{local}"))
}

fn write_node(state: &State, index: usize, output: &mut String) {
    match &state.slots[index].kind {
        Kind::Document => {}
        Kind::Element {
            local,
            prefix,
            declarations,
            attributes,
            ..
        } => {
            let name = qualified(prefix.as_deref(), local);
            write!(output, "<{name}").expect("writing to a String");
            for (prefix, uri) in declarations {
                match prefix {
                    Some(prefix) => write!(output, " xmlns:{prefix}=\"").expect("writing"),
                    None => output.push_str(" xmlns=\""),
                }
                escape(uri, true, output);
                output.push('"');
            }
            for attribute in attributes {
                write!(
                    output,
                    " {}=\"",
                    qualified(attribute.prefix.as_deref(), &attribute.local)
                )
                .expect("writing");
                escape(&attribute.value, true, output);
                output.push('"');
            }
            output.push('>');
            for &child in &state.slots[index].children {
                write_node(state, child, output);
            }
            write!(output, "</{name}>").expect("writing");
        }
        Kind::Text(text) => escape(text, false, output),
        Kind::Comment(text) => write!(output, "<!--{text}-->").expect("writing"),
        Kind::Pi(target, value) => match value {
            Some(value) => write!(output, "<?{target} {value}?>").expect("writing"),
            None => write!(output, "<?{target}?>").expect("writing"),
        },
    }
}

fn report(state: &State, index: usize, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
    let node = reference(index);
    match &state.slots[index].kind {
        Kind::Document => Ok(()),
        Kind::Element {
            local,
            prefix,
            namespace,
            declarations,
            attributes,
        } => {
            sink.begin_element(node, local, prefix.as_deref(), namespace.as_deref())?;
            for (prefix, uri) in declarations {
                sink.declare_namespace(prefix.as_deref(), uri)?;
            }
            for attribute in attributes {
                sink.attribute(
                    &attribute.local,
                    attribute.prefix.as_deref(),
                    attribute.namespace.as_deref(),
                    &attribute.value,
                    false,
                )?;
            }
            sink.open_element()?;
            for &child in &state.slots[index].children {
                report(state, child, sink)?;
            }
            sink.end_element()
        }
        Kind::Text(text) => sink.text(node, text),
        Kind::Comment(text) => sink.comment(node, text),
        Kind::Pi(target, value) => sink.processing_instruction(node, target, value.as_deref()),
    }
}

/// The nodes of `fragment`, created in the arena, as a sibling sequence.
fn build(state: &mut State, fragment: &Fragment<'_>) -> Vec<usize> {
    let mut top = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    let push = |state: &mut State, open: &[usize], top: &mut Vec<usize>, kind: Kind| {
        let index = state.slots.len();
        state.slots.push(Slot {
            kind,
            children: Vec::new(),
        });
        match open.last() {
            Some(&parent) => state.slots[parent].children.push(index),
            None => top.push(index),
        }
        index
    };
    fragment
        .walk(&mut |event| {
            match event {
                FragmentEvent::StartElement {
                    local_name,
                    prefix,
                    namespace,
                } => {
                    let index = push(
                        state,
                        &open,
                        &mut top,
                        Kind::Element {
                            local: local_name.into(),
                            prefix: prefix.map(String::from),
                            namespace: namespace.map(String::from),
                            declarations: Vec::new(),
                            attributes: Vec::new(),
                        },
                    );
                    open.push(index);
                }
                FragmentEvent::Namespace { prefix, uri } => {
                    let index = *open.last().expect("inside a start tag");
                    if let Kind::Element { declarations, .. } = &mut state.slots[index].kind {
                        declarations.push((prefix.map(String::from), uri.into()));
                    }
                }
                FragmentEvent::Attribute {
                    local_name,
                    prefix,
                    namespace,
                    value,
                } => {
                    let index = *open.last().expect("inside a start tag");
                    if let Kind::Element { attributes, .. } = &mut state.slots[index].kind {
                        attributes.push(Attribute {
                            local: local_name.into(),
                            prefix: prefix.map(String::from),
                            namespace: namespace.map(String::from),
                            value: value.into(),
                        });
                    }
                }
                FragmentEvent::OpenElement => {}
                FragmentEvent::EndElement => {
                    open.pop();
                }
                FragmentEvent::Text(text) => {
                    push(state, &open, &mut top, Kind::Text(text.into()));
                }
                FragmentEvent::Comment(text) => {
                    push(state, &open, &mut top, Kind::Comment(text.into()));
                }
                FragmentEvent::ProcessingInstruction { target, value } => {
                    push(
                        state,
                        &open,
                        &mut top,
                        Kind::Pi(target.into(), value.map(String::from)),
                    );
                }
            }
            Ok::<(), ()>(())
        })
        .expect("building cannot fail");
    top
}

fn parent_of(state: &State, index: usize) -> Option<usize> {
    state
        .slots
        .iter()
        .position(|slot| slot.children.contains(&index))
}

fn set_children(state: &mut State, node: usize, children: Vec<usize>) {
    let before = std::mem::replace(&mut state.slots[node].children, children);
    state.journal.push(Undo {
        node,
        children: before,
    });
}

impl ExternalTree for ModelTree {
    fn document(&self) -> ExternalNode {
        reference(DOCUMENT)
    }

    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        let state = self.state();
        for &child in &state.slots[DOCUMENT].children {
            report(&state, child, sink)?;
        }
        Ok(())
    }

    fn apply(&mut self, edits: &[TreeEdit<'_>]) -> Result<(), TreeEditError> {
        let mut state = self.state();
        for edit in edits {
            match *edit {
                TreeEdit::SetText { target, text } => {
                    let target = reference_index(target);
                    let index = state.slots.len();
                    state.slots.push(Slot {
                        kind: Kind::Text(text.into()),
                        children: Vec::new(),
                    });
                    let children = if text.is_empty() {
                        Vec::new()
                    } else {
                        vec![index]
                    };
                    set_children(&mut state, target, children);
                }
                TreeEdit::ReplaceContent { target, fragment } => {
                    let nodes = build(&mut state, &fragment);
                    set_children(&mut state, reference_index(target), nodes);
                }
                TreeEdit::AppendChild { target, fragment } => {
                    let target = reference_index(target);
                    let nodes = build(&mut state, &fragment);
                    let mut children = state.slots[target].children.clone();
                    children.extend(nodes);
                    set_children(&mut state, target, children);
                }
                TreeEdit::ReplaceNode { target, fragment }
                | TreeEdit::InsertBefore { target, fragment } => {
                    let target = reference_index(target);
                    let parent = parent_of(&state, target)
                        .ok_or_else(|| TreeEditError("the target has no parent".into()))?;
                    let nodes = build(&mut state, &fragment);
                    let mut children = state.slots[parent].children.clone();
                    let position = children
                        .iter()
                        .position(|&child| child == target)
                        .expect("a parent lists its child");
                    let removed = usize::from(matches!(edit, TreeEdit::ReplaceNode { .. }));
                    children.splice(position..position + removed, nodes);
                    set_children(&mut state, parent, children);
                }
            }
        }
        Ok(())
    }

    fn checkpoint(&mut self) -> usize {
        self.state().journal.len()
    }

    fn rollback(&mut self, mark: usize) {
        let mut state = self.state();
        while state.journal.len() > mark {
            let undo = state.journal.pop().expect("a record above the mark");
            state.slots[undo.node].children = undo.children;
        }
    }

    fn release(&mut self, mark: usize) {
        self.state().journal.truncate(mark);
    }
}
