//! Execution-owned workspaces for the single evaluator.

#[cfg(feature = "embedded")]
use crate::sxd_document as sxd_document_no_unsafe;
use crate::{Value, context, function};
use std::{fmt, ops::DerefMut};

pub(crate) trait List<T>: std::ops::Deref<Target = [T]> + DerefMut {
    fn reserve(&mut self, additional: usize) -> Result<(), function::Error>;
    fn push(&mut self, value: T) -> Result<(), function::Error>;
    fn capacity(&self) -> usize;
    fn pop(&mut self) -> Option<T>;
    fn truncate(&mut self, length: usize);
}

pub(crate) trait NamespaceSet {
    fn insert<'d>(
        &mut self,
        context: &context::Evaluation<'_, 'd>,
        prefix: crate::nodeset::DeclarationText<'_, 'd>,
    ) -> Result<bool, function::Error>;
}

pub(crate) trait Set<'d> {
    fn insert(
        &mut self,
        context: &context::Evaluation<'_, 'd>,
        node: crate::nodeset::Node<'d>,
    ) -> Result<(), function::Error>;
    fn finish(self) -> crate::nodeset::Nodeset<'d>;
}

impl<'d> Set<'d> for crate::nodeset::Nodeset<'d> {
    fn insert(
        &mut self,
        context: &context::Evaluation<'_, 'd>,
        node: crate::nodeset::Node<'d>,
    ) -> Result<(), function::Error> {
        self.add_metered(context, node)
    }
    fn finish(self) -> Self {
        self
    }
}

pub(crate) enum TextView<'a, T> {
    Borrowed(&'a str),
    Owned(T),
}

impl<T: std::ops::Deref<Target = str>> std::ops::Deref for TextView<'_, T> {
    type Target = str;
    fn deref(&self) -> &str {
        match self {
            Self::Borrowed(text) => text,
            Self::Owned(text) => text,
        }
    }
}

impl NamespaceSet for std::collections::HashSet<String> {
    fn insert<'d>(
        &mut self,
        context: &context::Evaluation<'_, 'd>,
        prefix: crate::nodeset::DeclarationText<'_, 'd>,
    ) -> Result<bool, function::Error> {
        #[cfg(feature = "embedded")]
        let prefix = prefix.as_str();
        if self.contains(prefix) {
            return Ok(false);
        }
        crate::nodeset::reserve_hashset_slot(self, context)?;
        context.reserve_temporary_allocation(prefix.len())?;
        Ok(std::collections::HashSet::insert(self, prefix.to_owned()))
    }
}

pub(crate) trait Runtime: Copy + fmt::Debug {
    const ACCOUNTED: bool;
    type List<T>: List<T>;
    type Text: std::ops::Deref<Target = str>;
    type Namespaces: NamespaceSet;
    type Set<'d>: Set<'d>;
    fn set<'d>(self) -> Self::Set<'d>;
    fn open_set<'d>(
        self,
        context: &context::Evaluation<'_, 'd>,
        nodes: crate::nodeset::Nodeset<'d>,
    ) -> Result<Self::Set<'d>, function::Error>;
    fn nodes<'a, 'd: 'a>(
        self,
        nodes: &'a crate::nodeset::Nodeset<'d>,
    ) -> Result<impl Iterator<Item = &'a crate::nodeset::Node<'d>> + 'a, function::Error>;
    fn merge<'d>(
        self,
        context: &context::Evaluation<'_, 'd>,
        output: &mut Self::Set<'d>,
        nodes: crate::nodeset::Nodeset<'d>,
    ) -> Result<(), function::Error> {
        for node in self.nodes(&nodes)? {
            output.insert(context, self.clone_node(context, node)?)?;
        }
        Ok(())
    }
    fn name_error(
        self,
        kind: crate::expression::NameKind,
        name: sxd_document_no_unsafe::PrefixedName<'_>,
    ) -> Result<crate::expression::Error, function::Error> {
        use crate::expression::{Error, NameKind};
        Ok(match kind {
            NameKind::Function => Error::UnknownFunction { name: name.into() },
            NameKind::Variable => Error::UnknownVariable { name: name.into() },
            NameKind::Namespace => Error::UnknownNamespace {
                prefix: name.local_part().into(),
            },
        })
    }
    fn empty_text(self) -> Result<Self::Text, function::Error>;
    fn append_text(
        self,
        context: &context::Evaluation<'_, '_>,
        target: &mut Self::Text,
        text: &str,
    ) -> Result<(), function::Error>;
    fn finish_text<'d>(self, text: Self::Text) -> Value<'d>;
    fn clone_value<'d>(
        self,
        context: &context::Evaluation<'_, 'd>,
        value: &Value<'d>,
    ) -> Result<Value<'d>, function::Error> {
        Ok(match value {
            Value::Boolean(value) => Value::Boolean(*value),
            Value::Number(value) => Value::Number(*value),
            Value::Nodeset(nodes) => Value::Nodeset(self.clone_nodes(context, nodes)?),
            Value::ResultTreeFragment(identity, text) => {
                Value::ResultTreeFragment(*identity, std::sync::Arc::clone(text))
            }
            Value::String(text) => return self.literal(context, text),
            #[cfg(feature = "embedded")]
            Value::AccountedString(text) => return self.literal(context, text.as_str()),
        })
    }
    fn clone_nodes<'d>(
        self,
        context: &context::Evaluation<'_, 'd>,
        nodes: &crate::nodeset::Nodeset<'d>,
    ) -> Result<crate::nodeset::Nodeset<'d>, function::Error> {
        let mut output = self.set();
        for node in self.nodes(nodes)? {
            output.insert(context, self.clone_node(context, node)?)?;
        }
        Ok(output.finish())
    }
    fn visit_node_text(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'_>,
        visit: impl FnMut(&str) -> Result<bool, function::Error>,
    ) -> Result<(), function::Error>;
    fn literal<'d>(
        self,
        context: &context::Evaluation<'_, '_>,
        text: &str,
    ) -> Result<Value<'d>, function::Error> {
        let mut output = self.empty_text()?;
        self.append_text(context, &mut output, text)?;
        Ok(self.finish_text(output))
    }
    fn append_number(
        self,
        context: &context::Evaluation<'_, '_>,
        target: &mut Self::Text,
        number: f64,
    ) -> Result<(), function::Error> {
        struct Writer<'a, 'c, 'd, R: Runtime> {
            runtime: R,
            context: &'a context::Evaluation<'c, 'd>,
            text: &'a mut R::Text,
            failure: Option<function::Error>,
        }
        impl<R: Runtime> fmt::Write for Writer<'_, '_, '_, R> {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                match self.runtime.append_text(self.context, self.text, text) {
                    Ok(()) => Ok(()),
                    Err(cause) => {
                        self.failure = Some(cause);
                        Err(fmt::Error)
                    }
                }
            }
        }
        let mut writer = Writer {
            runtime: self,
            context,
            text: target,
            failure: None,
        };
        let result = super::write_xpath_number(&mut writer, number);
        if let Some(cause) = writer.failure {
            return Err(cause);
        }
        result.expect("number formatting only fails on a refused write");
        Ok(())
    }
    fn value_text<'a>(
        self,
        context: &context::Evaluation<'_, '_>,
        value: &'a Value<'_>,
    ) -> Result<TextView<'a, Self::Text>, function::Error> {
        if let Some(text) = value.scalar_text() {
            return Ok(TextView::Borrowed(text));
        }
        match value {
            Value::Boolean(value) => Ok(TextView::Borrowed(if *value { "true" } else { "false" })),
            Value::Nodeset(nodes) => match nodes.document_order_first_in(context, self)? {
                Some(node) => self.node_text(context, &node).map(TextView::Owned),
                None => Ok(TextView::Borrowed("")),
            },
            Value::Number(number) => {
                let mut text = self.empty_text()?;
                self.append_number(context, &mut text, *number)?;
                Ok(TextView::Owned(text))
            }
            _ => unreachable!("string values were borrowed above"),
        }
    }
    fn namespaces(self) -> Self::Namespaces;
    fn namespace_declarations<'d, E>(
        self,
        element: sxd_document_no_unsafe::dom::Element<'d>,
        context: &context::Evaluation<'_, 'd>,
        visit: impl FnMut(
            crate::nodeset::DeclarationText<'_, 'd>,
            crate::nodeset::DeclarationText<'_, 'd>,
        ) -> Result<(), E>,
    ) -> Result<Result<(), E>, function::Error> {
        context.charge_work(1)?;
        context.reserve_temporary_allocation(element.namespace_declaration_workspace_bytes())?;
        #[cfg(feature = "embedded")]
        {
            let mut visit = visit;
            Ok(element
                .try_visit_namespace_declarations(|prefix, uri| visit(prefix.into(), uri.into())))
        }
        #[cfg(not(feature = "embedded"))]
        {
            Ok(element.try_visit_namespace_declarations(visit))
        }
    }
    fn list<T>(self) -> Self::List<T>;
    fn reserve<T>(
        self,
        context: &context::Evaluation<'_, '_>,
        values: &mut Self::List<T>,
        additional: usize,
    ) -> Result<(), function::Error> {
        if !Self::ACCOUNTED {
            context.reserve_temporary_allocation(
                additional.saturating_mul(std::mem::size_of::<T>()),
            )?;
        }
        values.reserve(additional)
    }
    fn clone_node<'d>(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'d>,
    ) -> Result<crate::nodeset::Node<'d>, function::Error> {
        node.clone_with_context(context)
    }
    fn namespace_text<'d>(
        self,
        text: crate::nodeset::DeclarationText<'_, 'd>,
    ) -> Result<sxd_document_no_unsafe::NsStr<'d>, function::Error>;
    fn push<T>(
        self,
        context: &context::Evaluation<'_, '_>,
        values: &mut Self::List<T>,
        value: T,
    ) -> Result<(), function::Error> {
        if !Self::ACCOUNTED && values.len() == values.capacity() {
            let additional = values.capacity().max(4);
            context.reserve_temporary_allocation(
                additional.saturating_mul(std::mem::size_of::<T>()),
            )?;
            values.reserve(additional)?;
        }
        values.push(value)
    }
    fn node_text(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'_>,
    ) -> Result<Self::Text, function::Error>;
    fn node_equals(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'_>,
        expected: &str,
    ) -> Result<bool, function::Error>;
    fn node_number(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'_>,
    ) -> Result<f64, function::Error>;
    fn invoke<'d>(
        self,
        function: function::Resolved<'_>,
        context: &context::Evaluation<'_, 'd>,
        arguments: Self::List<Value<'d>>,
    ) -> Result<Value<'d>, function::Error>;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Native;

impl<T> List<T> for Vec<T> {
    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }
    fn pop(&mut self) -> Option<T> {
        Vec::pop(self)
    }
    fn truncate(&mut self, length: usize) {
        Vec::truncate(self, length);
    }
    fn reserve(&mut self, additional: usize) -> Result<(), function::Error> {
        self.try_reserve_exact(additional)
            .map_err(|_| function::Error::Other {
                what: "XPath argument allocation failed".into(),
            })
    }
    fn push(&mut self, value: T) -> Result<(), function::Error> {
        Vec::push(self, value);
        Ok(())
    }
}

impl Runtime for Native {
    fn merge<'d>(
        self,
        context: &context::Evaluation<'_, 'd>,
        output: &mut Self::Set<'d>,
        nodes: crate::nodeset::Nodeset<'d>,
    ) -> Result<(), function::Error> {
        for node in nodes {
            output.insert(context, node)?;
        }
        Ok(())
    }
    type Set<'d> = crate::nodeset::Nodeset<'d>;
    fn set<'d>(self) -> Self::Set<'d> {
        crate::nodeset::Nodeset::new()
    }
    fn open_set<'d>(
        self,
        _: &context::Evaluation<'_, 'd>,
        nodes: crate::nodeset::Nodeset<'d>,
    ) -> Result<Self::Set<'d>, function::Error> {
        Ok(nodes)
    }
    fn nodes<'a, 'd: 'a>(
        self,
        nodes: &'a crate::nodeset::Nodeset<'d>,
    ) -> Result<impl Iterator<Item = &'a crate::nodeset::Node<'d>> + 'a, function::Error> {
        Ok(nodes.iter_ref())
    }
    const ACCOUNTED: bool = false;
    type List<T> = Vec<T>;
    type Text = String;
    type Namespaces = std::collections::HashSet<String>;
    fn empty_text(self) -> Result<String, function::Error> {
        Ok(String::new())
    }
    fn append_text(
        self,
        context: &context::Evaluation<'_, '_>,
        target: &mut String,
        text: &str,
    ) -> Result<(), function::Error> {
        function::append_metered_string(target, text, context)
    }
    fn finish_text<'d>(self, text: String) -> Value<'d> {
        Value::String(text)
    }
    fn visit_node_text(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'_>,
        visit: impl FnMut(&str) -> Result<bool, function::Error>,
    ) -> Result<(), function::Error> {
        node.visit_string_value_with_context(context, visit)
    }
    fn namespaces(self) -> Self::Namespaces {
        Self::Namespaces::new()
    }
    fn list<T>(self) -> Vec<T> {
        Vec::new()
    }
    fn namespace_text<'d>(
        self,
        text: crate::nodeset::DeclarationText<'_, 'd>,
    ) -> Result<sxd_document_no_unsafe::NsStr<'d>, function::Error> {
        #[cfg(feature = "embedded")]
        {
            Ok(sxd_document_no_unsafe::NamespaceText::Native(
                text.as_str().to_owned(),
            ))
        }
        #[cfg(not(feature = "embedded"))]
        {
            Ok(sxd_document_no_unsafe::to_ns_str!(text))
        }
    }
    fn node_text(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'_>,
    ) -> Result<Self::Text, function::Error> {
        node.string_value_with_context(context)
    }
    fn node_equals(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'_>,
        expected: &str,
    ) -> Result<bool, function::Error> {
        node.string_value_eq_with_context(context, expected)
    }
    fn node_number(
        self,
        context: &context::Evaluation<'_, '_>,
        node: &crate::nodeset::Node<'_>,
    ) -> Result<f64, function::Error> {
        crate::node_to_num_with_context(context, node)
    }
    fn invoke<'d>(
        self,
        function: function::Resolved<'_>,
        context: &context::Evaluation<'_, 'd>,
        mut arguments: Vec<Value<'d>>,
    ) -> Result<Value<'d>, function::Error> {
        match function {
            function::Resolved::Core(core) => core.evaluate_in(context, &mut arguments, self),
            function::Resolved::Extension(function) => function.evaluate(context, arguments),
        }
    }
}

#[cfg(feature = "embedded")]
mod paid {
    use super::{
        DerefMut, List, NamespaceSet, Runtime, Set, Value, context, fmt, function,
        sxd_document_no_unsafe,
    };
    use std::{cell::Cell, ops::Deref};
    use structured_asn1::memory::{MemoryError, OwnedMap, OwnedText, OwnedVec, SharedString, Work};

    #[derive(Clone)]
    pub(crate) struct Accounted<'w, W: Work> {
        pub work: &'w W,
        pub failure: &'w Cell<Option<MemoryError>>,
    }
    impl<W: Work> Copy for Accounted<'_, W> {}
    impl<W: Work> fmt::Debug for Accounted<'_, W> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("CurrentArguments")
        }
    }
    impl<W: Work> Accounted<'_, W> {
        fn refuse(self, cause: MemoryError) -> function::Error {
            if self.failure.get().is_none() {
                self.failure.set(Some(cause));
            }
            function::Error::ProcessingStopped
        }
    }

    pub(crate) struct Values<'w, T, W: Work> {
        values: OwnedVec<T, W>,
        runtime: Accounted<'w, W>,
    }
    impl<T, W: Work> Values<'_, T, W> {
        pub(crate) fn into_values(self) -> OwnedVec<T, W> {
            self.values
        }
    }
    pub(crate) struct NamespaceKeys<'w, W: Work> {
        keys: Option<OwnedMap<sxd_document_no_unsafe::NamespaceText, (), W>>,
        runtime: Accounted<'w, W>,
    }

    pub(crate) struct NodeKeys<'w, 'd, W: Work> {
        nodes: OwnedMap<crate::nodeset::Node<'d>, (), W>,
        runtime: Accounted<'w, W>,
    }
    impl<'d, W: Work> Set<'d> for NodeKeys<'_, 'd, W> {
        fn insert(
            &mut self,
            context: &context::Evaluation<'_, 'd>,
            node: crate::nodeset::Node<'d>,
        ) -> Result<(), function::Error> {
            context.charge_work(1)?;
            self.nodes
                .try_insert(node, ())
                .map_err(|cause| self.runtime.refuse(cause))?;
            Ok(())
        }
        fn finish(self) -> crate::nodeset::Nodeset<'d> {
            crate::nodeset::Nodeset::current(self.nodes.into_owned())
        }
    }
    impl<W: Work> NamespaceSet for NamespaceKeys<'_, W> {
        fn insert<'d>(
            &mut self,
            _: &context::Evaluation<'_, 'd>,
            prefix: crate::nodeset::DeclarationText<'_, 'd>,
        ) -> Result<bool, function::Error> {
            let keys = self.keys.get_or_insert_with(|| self.runtime.work.map());
            if keys
                .get_key_value_borrowed(prefix.as_str(), self.runtime.work)
                .map_err(|cause| self.runtime.refuse(cause))?
                .is_some()
            {
                return Ok(false);
            }
            let prefix = self.runtime.namespace_text(prefix)?;
            keys.try_insert(prefix, ())
                .map_err(|cause| self.runtime.refuse(cause))?;
            Ok(true)
        }
    }
    impl<T, W: Work> Deref for Values<'_, T, W> {
        type Target = [T];
        fn deref(&self) -> &[T] {
            &self.values
        }
    }
    impl<T, W: Work> DerefMut for Values<'_, T, W> {
        fn deref_mut(&mut self) -> &mut [T] {
            &mut self.values
        }
    }
    impl<T, W: Work> List<T> for Values<'_, T, W> {
        fn capacity(&self) -> usize {
            self.values.capacity()
        }
        fn pop(&mut self) -> Option<T> {
            self.values.pop()
        }
        fn truncate(&mut self, length: usize) {
            while self.values.len() > length {
                self.values.pop();
            }
        }
        fn reserve(&mut self, additional: usize) -> Result<(), function::Error> {
            self.values
                .try_reserve_exact(additional)
                .map_err(|cause| self.runtime.refuse(cause))
        }
        fn push(&mut self, value: T) -> Result<(), function::Error> {
            self.values
                .try_push(value)
                .map_err(|cause| self.runtime.refuse(cause))
        }
    }
    impl<'d, W: Work> crate::nodeset::TextStack<'d>
        for Values<'_, (crate::nodeset::Node<'d>, usize), W>
    {
        fn push(
            &mut self,
            frame: (crate::nodeset::Node<'d>, usize),
            _: &context::Evaluation<'_, '_>,
        ) -> Result<(), function::Error> {
            List::push(self, frame)
        }
        fn pop(&mut self) -> Option<(crate::nodeset::Node<'d>, usize)> {
            self.values.pop()
        }
    }
    impl<'w, W: Work> Runtime for Accounted<'w, W> {
        type Set<'d> = NodeKeys<'w, 'd, W>;
        fn set<'d>(self) -> Self::Set<'d> {
            NodeKeys {
                nodes: self.work.map(),
                runtime: self,
            }
        }
        fn open_set<'d>(
            self,
            context: &context::Evaluation<'_, 'd>,
            nodes: crate::nodeset::Nodeset<'d>,
        ) -> Result<Self::Set<'d>, function::Error> {
            use crate::nodeset::storage::Storage;
            match nodes.into_storage() {
                Storage::Current(nodes) => nodes
                    .with_execution(self.work)
                    .map(|nodes| NodeKeys {
                        nodes,
                        runtime: self,
                    })
                    .map_err(|_| self.refuse(MemoryError::WorkExceeded)),
                Storage::Native(nodes) => {
                    self.work
                        .charge_work(nodes.capacity() as u64)
                        .map_err(|cause| self.refuse(cause))?;
                    let mut result = self.set();
                    for node in nodes {
                        result.insert(context, self.clone_node(context, &node)?)?;
                    }
                    Ok(result)
                }
            }
        }
        fn nodes<'a, 'd: 'a>(
            self,
            nodes: &'a crate::nodeset::Nodeset<'d>,
        ) -> Result<impl Iterator<Item = &'a crate::nodeset::Node<'d>> + 'a, function::Error>
        {
            nodes
                .iter_current(self.work)
                .map_err(|cause| self.refuse(cause))
        }
        const ACCOUNTED: bool = true;
        type List<T> = Values<'w, T, W>;
        type Text = OwnedText<W>;
        type Namespaces = NamespaceKeys<'w, W>;
        fn name_error(
            self,
            kind: crate::expression::NameKind,
            name: sxd_document_no_unsafe::PrefixedName<'_>,
        ) -> Result<crate::expression::Error, function::Error> {
            let prefix = name
                .prefix()
                .map(|prefix| SharedString::try_from_str(prefix, self.work))
                .transpose()
                .map_err(|cause| self.refuse(cause))?;
            let local = SharedString::try_from_str(name.local_part(), self.work)
                .map_err(|cause| self.refuse(cause))?;
            Ok(crate::expression::Error::CurrentName {
                kind,
                name: crate::expression::NameText { prefix, local },
            })
        }
        fn empty_text(self) -> Result<Self::Text, function::Error> {
            OwnedText::try_from_str("", self.work).map_err(|cause| self.refuse(cause))
        }
        fn append_text(
            self,
            _: &context::Evaluation<'_, '_>,
            target: &mut Self::Text,
            text: &str,
        ) -> Result<(), function::Error> {
            target
                .try_push_str(text)
                .map_err(|cause| self.refuse(cause))
        }
        fn finish_text<'d>(self, text: Self::Text) -> Value<'d> {
            Value::AccountedString(text.into_owned())
        }
        fn visit_node_text(
            self,
            context: &context::Evaluation<'_, '_>,
            node: &crate::nodeset::Node<'_>,
            visit: impl FnMut(&str) -> Result<bool, function::Error>,
        ) -> Result<(), function::Error> {
            node.visit_string_value_with_stack(context, &mut self.list(), visit)
        }
        fn namespaces(self) -> Self::Namespaces {
            NamespaceKeys {
                keys: None,
                runtime: self,
            }
        }
        fn namespace_declarations<'d, E>(
            self,
            element: sxd_document_no_unsafe::dom::Element<'d>,
            context: &context::Evaluation<'_, 'd>,
            visit: impl FnMut(
                crate::nodeset::DeclarationText<'_, 'd>,
                crate::nodeset::DeclarationText<'_, 'd>,
            ) -> Result<(), E>,
        ) -> Result<Result<(), E>, function::Error> {
            context.charge_work(1)?;
            element
                .try_visit_namespace_labels(self.work, visit)
                .map_err(|cause| self.refuse(cause))
        }
        fn list<T>(self) -> Self::List<T> {
            Values {
                values: self.work.vector(),
                runtime: self,
            }
        }
        fn namespace_text<'d>(
            self,
            text: crate::nodeset::DeclarationText<'_, 'd>,
        ) -> Result<sxd_document_no_unsafe::NsStr<'d>, function::Error> {
            use sxd_document_no_unsafe::{NamespaceText, string_pool::Label};
            match text {
                Label::Current(text) => Ok(NamespaceText::Current(text.clone())),
                Label::Static(text) => Ok(NamespaceText::Static(text)),
                Label::Borrowed(text) => SharedString::try_from_str(text, self.work)
                    .map(NamespaceText::Current)
                    .map_err(|cause| self.refuse(cause)),
            }
        }
        fn clone_node<'d>(
            self,
            _: &context::Evaluation<'_, '_>,
            node: &crate::nodeset::Node<'d>,
        ) -> Result<crate::nodeset::Node<'d>, function::Error> {
            if let crate::nodeset::Node::Namespace(namespace) = node {
                let label = |text: &sxd_document_no_unsafe::NamespaceText| match text {
                    sxd_document_no_unsafe::NamespaceText::Current(_)
                    | sxd_document_no_unsafe::NamespaceText::Static(_) => Ok(text.clone()),
                    sxd_document_no_unsafe::NamespaceText::Native(text) => {
                        self.namespace_text(text.as_str().into())
                    }
                };
                return Ok(crate::nodeset::Node::Namespace(crate::nodeset::Namespace {
                    parent: namespace.parent,
                    prefix: label(&namespace.prefix)?,
                    uri: label(&namespace.uri)?,
                }));
            }
            Ok(node.clone())
        }
        fn node_text(
            self,
            context: &context::Evaluation<'_, '_>,
            node: &crate::nodeset::Node<'_>,
        ) -> Result<Self::Text, function::Error> {
            let mut text =
                OwnedText::try_from_str("", self.work).map_err(|cause| self.refuse(cause))?;
            let mut stack = self.list();
            node.visit_string_value_with_stack(context, &mut stack, |chunk| {
                text.try_push_str(chunk)
                    .map_err(|cause| self.refuse(cause))?;
                Ok(true)
            })?;
            Ok(text)
        }
        fn node_equals(
            self,
            context: &context::Evaluation<'_, '_>,
            node: &crate::nodeset::Node<'_>,
            expected: &str,
        ) -> Result<bool, function::Error> {
            node.string_value_eq_with_stack(context, expected, &mut self.list())
        }
        fn node_number(
            self,
            context: &context::Evaluation<'_, '_>,
            node: &crate::nodeset::Node<'_>,
        ) -> Result<f64, function::Error> {
            let text = self.node_text(context, node)?;
            // XPath 1.0 §4.4 number(): the same lexical conversion applies to
            // the element's complete string-value, never each chunk alone.
            // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-number
            self.work
                .charge_work(text.len() as u64)
                .map_err(|cause| self.refuse(cause))?;
            Ok(crate::str_to_num(&text))
        }
        fn invoke<'d>(
            self,
            function: function::Resolved<'_>,
            context: &context::Evaluation<'_, 'd>,
            mut arguments: Self::List<Value<'d>>,
        ) -> Result<Value<'d>, function::Error> {
            // The current owner remains live for the entire call. The callee
            // may move values out, but cannot grow or retain the argument list.
            match function {
                function::Resolved::Core(core) => core.evaluate_in(context, &mut arguments, self),
                function::Resolved::Extension(function) => {
                    function.evaluate_borrowed(context, &mut arguments)
                }
            }
        }
    }
}

#[cfg(feature = "embedded")]
pub(crate) use paid::Accounted;

#[cfg(all(test, feature = "embedded"))]
mod tests {
    use super::*;
    use std::{cell::Cell, sync::Arc};
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

    #[test]
    fn node_set_table_survives_producer_and_uses_each_current_execution() {
        // Freezing and reopening move the same buckets. A finished producer
        // cannot finance later iteration, and refusing local work allocates nothing.
        use structured_asn1::memory::Work as _;
        use structured_asn1::{Encoding, Limits, Parser};
        let package = crate::sxd_document::Package::new();
        let document = package.as_document();
        let first = document.create_element("first");
        let second = document.create_element("second");
        let context = crate::Context::new();
        let evaluation = context::Evaluation::new(&context, document.root().into());
        let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 1 << 20)));
        let retained;
        {
            let before = memory.work_used();
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: 10000,
                    ..Default::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 0).unwrap();
            let work = reader.execution();
            let failure = Cell::new(None);
            let runtime = Accounted {
                work: &work,
                failure: &failure,
            };
            let mut nodes = runtime.set();
            nodes.insert(&evaluation, first.into()).unwrap();
            nodes.insert(&evaluation, second.into()).unwrap();
            let used = memory.used();
            retained = nodes.finish();
            assert_eq!(retained.size(), 2);
            assert_eq!(memory.used(), used);
            work.charge_work((10000 - (memory.work_used() - before)) as u64)
                .unwrap();
            assert_eq!(work.charge_work(1), Err(MemoryError::WorkExceeded));
        }
        let retained_capacity = memory.used();
        assert!(retained_capacity > 0);
        for limit in [0, 10000] {
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: limit,
                    ..Default::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 0).unwrap();
            let work = reader.execution();
            let failure = Cell::new(None);
            let runtime = Accounted {
                work: &work,
                failure: &failure,
            };
            let before = memory.work_used();
            match runtime.nodes(&retained) {
                Ok(nodes) => {
                    assert_ne!(limit, 0);
                    assert_eq!(nodes.count(), 2);
                    assert!(memory.work_used() > before);
                }
                Err(cause) => {
                    assert_eq!(limit, 0);
                    assert_eq!(cause, function::Error::ProcessingStopped);
                    assert_eq!(failure.get(), Some(MemoryError::WorkExceeded));
                    assert_eq!(memory.work_used(), before);
                }
            }
            assert_eq!(memory.used(), retained_capacity);
        }
        let failure = Cell::new(None);
        let runtime = Accounted {
            work: &memory,
            failure: &failure,
        };
        let before = memory.work_used();
        let mut nodes = runtime.open_set(&evaluation, retained).unwrap();
        assert_eq!(memory.work_used(), before);
        assert_eq!(memory.used(), retained_capacity);
        nodes.insert(&evaluation, first.into()).unwrap();
        let before_finish = memory.work_used();
        let retained = nodes.finish();
        assert_eq!(memory.work_used(), before_finish);
        assert_eq!(retained.size(), 2);
        assert_eq!(memory.used(), retained_capacity);
        drop(retained);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn node_set_growth_refuses_current_work_or_actual_capacity() {
        // A singleton is a real table allocation too; there is no native set
        // fallback when either admission axis refuses its first bucket block.
        let package = crate::sxd_document::Package::new();
        let document = package.as_document();
        let context = crate::Context::new();
        let evaluation = context::Evaluation::new(&context, document.root().into());
        for (bytes, units, expected) in [
            (0, 10000, MemoryError::LimitExceeded),
            (10000, 0, MemoryError::WorkExceeded),
        ] {
            let memory = Memory::new(Arc::new(MemoryAccount::new(bytes, units)));
            let failure = Cell::new(None);
            let runtime = Accounted {
                work: &memory,
                failure: &failure,
            };
            let mut nodes = runtime.set();
            assert_eq!(
                nodes.insert(&evaluation, document.root().into()),
                Err(function::Error::ProcessingStopped)
            );
            assert_eq!(failure.get(), Some(expected));
            drop(nodes);
            assert_eq!(memory.used(), 0);
        }
    }

    #[test]
    fn implicit_xml_namespace_needs_no_shadow_table_or_owned_label() {
        // The mandatory constant binding may terminate name/namespace lookup
        // without constructing a set or copying either static label.
        let package = crate::sxd_document::Package::new();
        let document = package.as_document();
        let element = document.create_element("element");
        document.root().append_child(element);
        let current = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
        let failure = Cell::new(None);
        let runtime = Accounted {
            work: &current,
            failure: &failure,
        };
        let admit = |units| {
            current.charge_work(units as u64).map_err(|cause| {
                failure.set(Some(cause));
                function::Error::ProcessingStopped
            })
        };
        let mut context = crate::Context::new();
        context.set_work_admission(&admit);
        let evaluation = context::Evaluation::new(&context, element.into());
        let mut visits = 0;
        crate::nodeset::visit_namespace_bindings_in(
            element,
            &evaluation,
            runtime,
            |prefix, uri| {
                assert_eq!(prefix.as_str(), "xml");
                assert_eq!(uri.as_str(), "http://www.w3.org/XML/1998/namespace");
                visits += 1;
                Ok::<_, function::Error>(std::ops::ControlFlow::Break(()))
            },
        )
        .unwrap();
        assert_eq!(visits, 1);
        assert_eq!(current.used(), 0);
        assert!(current.work_remaining() < 4096);
        assert_eq!(failure.get(), None);
    }

    #[test]
    fn namespace_labels_retain_existing_owners_without_copying() {
        // Reading an immutable paid label needs no new capacity, and the
        // returned namespace handle retains its real producer allocation.
        use crate::sxd_document::{NamespaceText, string_pool::Label};
        use structured_asn1::memory::SharedString;
        let producer = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
        let label = SharedString::try_from_str("urn:retained", &producer).unwrap();
        let retained_bytes = producer.used();
        let current = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
        let failure = Cell::new(None);
        let runtime = Accounted {
            work: &current,
            failure: &failure,
        };
        let result = runtime.namespace_text(Label::Current(&label)).unwrap();
        let NamespaceText::Current(retained) = &result else {
            panic!("paid namespace owner")
        };
        assert!(SharedString::ptr_eq(&label, retained));
        assert!(matches!(
            runtime.namespace_text(Label::Static("xml")).unwrap(),
            NamespaceText::Static("xml")
        ));
        assert_eq!(producer.used(), retained_bytes);
        assert_eq!(current.used(), 0);
        assert_eq!(failure.get(), None);
        drop(label);
        assert_eq!(producer.used(), retained_bytes);
        drop(result);
        assert_eq!(producer.used(), 0);
    }

    #[test]
    fn unknown_names_do_not_allocate_native_diagnostics() {
        // Errors inspect attacker-provided names too. Retained AST storage
        // does not pay for a later owned diagnostic or hide allocator refusal.
        let producer = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
        let package = crate::sxd_document::Package::new();
        let context = crate::Context::new();
        for source in ["missing-function()", "$missing-variable", "missing:local()"] {
            let program = super::super::arena::Program::parse(source, &producer).unwrap();
            let current = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
            let failure = Cell::new(None);
            assert!(
                program
                    .evaluate_in(
                        &context,
                        package.as_document().root(),
                        Accounted {
                            work: &current,
                            failure: &failure,
                        }
                    )
                    .is_err()
            );
            assert_eq!(failure.get(), Some(MemoryError::LimitExceeded), "{source}");
            assert_eq!(current.used(), 0);
        }
    }

    #[test]
    fn variable_string_uses_current_capacity_and_retains_its_owner() {
        // Parsing and binding a variable cannot finance its later evaluated
        // copy. Successful output retains actual capacity until Value drops.
        let owner = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
        let program = super::super::arena::Program::parse("$value", &owner).unwrap();
        let package = crate::sxd_document::Package::new();
        let document = package.as_document();
        let mut context = crate::Context::new();
        context.set_variable("value", "retained variable text");
        for capacity in [0, 4096] {
            let current = Memory::new(Arc::new(MemoryAccount::new(capacity, 65536)));
            let failure = Cell::new(None);
            let result = program.evaluate_in(
                &context,
                document.root(),
                Accounted {
                    work: &current,
                    failure: &failure,
                },
            );
            if capacity == 0 {
                assert!(result.is_err());
                assert_eq!(failure.get(), Some(MemoryError::LimitExceeded));
            } else {
                let result = result.unwrap();
                assert_eq!(result, Value::from("retained variable text"));
                assert!(matches!(result, Value::AccountedString(_)));
                assert!(current.used() >= "retained variable text".len());
                drop(result);
            }
            assert_eq!(current.used(), 0);
        }
    }

    #[test]
    fn fragmented_text_materialization_has_linear_copy_work() {
        // A node with many short text children must not repeatedly relocate
        // its accumulated prefix. This allowance covers two walks and one copy,
        // but not the quadratic sum of exact one-byte capacity increases.
        let package = crate::sxd_document::Package::new();
        let document = package.as_document();
        let outer = document.create_element("outer");
        for _ in 0..256 {
            outer.append_child(document.create_text("x"));
        }
        let context = crate::Context::new();
        let evaluation = context::Evaluation::new(&context, outer.into());
        let work = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
        let failure = Cell::new(None);
        let text = Accounted {
            work: &work,
            failure: &failure,
        }
        .node_text(&evaluation, &outer.into())
        .expect("linear work allowance must cover fragmented text");
        assert_eq!(text.len(), 256);
        assert!(text.bytes().all(|byte| byte == b'x'));
        assert_eq!(failure.get(), None);
        assert!(work.used() >= text.len());
        drop(text);
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn numeric_text_and_descent_use_current_storage_and_release_it() {
        // Numeric coercion joins descendant text in document order and must
        // refuse before allocating either its text or traversal frames.
        let package = crate::sxd_document::Package::new();
        let document = package.as_document();
        let outer = document.create_element("outer");
        outer.append_child(document.create_text("1"));
        let inner = document.create_element("inner");
        inner.append_child(document.create_text("2"));
        outer.append_child(inner);
        let context = crate::Context::new();
        let evaluation = context::Evaluation::new(&context, outer.into());
        for (bytes, units, expected) in [
            (0, 4096, Some(MemoryError::LimitExceeded)),
            (1, 4096, Some(MemoryError::LimitExceeded)),
            (4096, 0, Some(MemoryError::WorkExceeded)),
            (4096, 4096, None),
        ] {
            let work = Memory::new(Arc::new(MemoryAccount::new(bytes, units)));
            let failure = Cell::new(None);
            let result = Accounted {
                work: &work,
                failure: &failure,
            }
            .node_number(&evaluation, &outer.into());
            assert_eq!(failure.get(), expected);
            if expected.is_some() {
                assert_eq!(result, Err(function::Error::ProcessingStopped));
            } else {
                assert_eq!(result, Ok(12.0));
                assert!(work.work_remaining() < units);
            }
            assert_eq!(work.used(), 0);
        }
    }
}
