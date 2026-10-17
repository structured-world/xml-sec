//! Storage-specialized XPath 1.0 core library.
use super::{Args, Error};
use crate::{
    Value, context,
    nodeset::{NamePart, Node},
    runtime::{List, Runtime},
};

macro_rules! names {
    ($($kind:ident => $name:literal),* $(,)?) => {
        #[derive(Clone, Copy, Debug)]
        pub(crate) enum Core { $($kind),* }
        impl Core {
            pub(crate) fn lookup(name: &str) -> Option<Self> { match name { $($name => Some(Self::$kind),)* _ => None } }
            pub(crate) fn native(self) -> &'static dyn super::Function {
                match self { $(Self::$kind => &Self::$kind,)* }
            }
        }
        pub(crate) const CORE_NAMES: &[&str] = &[$($name),*];
        /// Register the XPath 1.0 core library, replacing same-name overrides.
        pub fn register_core_functions(context: &mut context::ScopedContext<'_, '_>) {
            $(context.set_function($name, Core::$kind);)*
        }
    };
}
names! {
    Last => "last", Position => "position", Count => "count",
    LocalName => "local-name", NamespaceUri => "namespace-uri", Name => "name",
    String => "string", Concat => "concat", StartsWith => "starts-with",
    Contains => "contains", Before => "substring-before", After => "substring-after",
    Substring => "substring", StringLength => "string-length",
    Normalize => "normalize-space", Translate => "translate",
    Boolean => "boolean", Not => "not", True => "true", False => "false",
    Number => "number", Sum => "sum", Floor => "floor", Ceiling => "ceiling", Round => "round",
}

fn first_node<'d, R: Runtime>(
    context: &context::Evaluation<'_, 'd>,
    args: &[Value<'d>],
    runtime: R,
) -> Result<Option<Node<'d>>, Error> {
    match args.first() {
        None => runtime.clone_node(context, &context.node).map(Some),
        Some(Value::Nodeset(nodes)) => nodes.document_order_first_in(context, runtime),
        Some(value) => Err(Error::not_a_nodeset(value)),
    }
}
fn append_char<R: Runtime>(
    runtime: R,
    context: &context::Evaluation<'_, '_>,
    output: &mut R::Text,
    character: char,
) -> Result<(), Error> {
    runtime.append_text(context, output, character.encode_utf8(&mut [0; 4]))
}

impl Core {
    pub(crate) fn evaluate_in<'d, R: Runtime>(
        self,
        context: &context::Evaluation<'_, 'd>,
        values: &mut [Value<'d>],
        runtime: R,
    ) -> Result<Value<'d>, Error> {
        let args = Args::new(&mut *values);
        match self {
            Self::Last | Self::Position => {
                args.exactly(0)?;
                Ok(Value::Number(if matches!(self, Self::Last) {
                    context.size
                } else {
                    context.position
                } as f64))
            }
            Self::Count => {
                args.exactly(1)?;
                match &values[0] {
                    Value::Nodeset(nodes) => Ok(Value::Number(nodes.size() as f64)),
                    value => Err(Error::not_a_nodeset(value)),
                }
            }
            Self::LocalName | Self::NamespaceUri | Self::Name => {
                args.at_most(1)?;
                let part = match self {
                    Self::LocalName => NamePart::Local,
                    Self::NamespaceUri => NamePart::Namespace,
                    _ => NamePart::Qualified,
                };
                let text = match first_node(context, values, runtime)? {
                    Some(node) => node.name_in(part, context, runtime)?,
                    None => runtime.empty_text()?,
                };
                Ok(runtime.finish_text(text))
            }
            Self::String => {
                args.at_most(1)?;
                if let Some(value) = values.first_mut() {
                    if value.string_text().is_some() {
                        return Ok(std::mem::replace(value, Value::Boolean(false)));
                    }
                    match runtime.value_text(context, value)? {
                        crate::runtime::TextView::Borrowed(text) => runtime.literal(context, text),
                        crate::runtime::TextView::Owned(text) => Ok(runtime.finish_text(text)),
                    }
                } else {
                    runtime
                        .node_text(context, &context.node)
                        .map(|text| runtime.finish_text(text))
                }
            }
            Self::Concat => {
                args.at_least(2)?;
                let mut output = runtime.empty_text()?;
                for value in values {
                    match value {
                        Value::Number(number) => {
                            runtime.append_number(context, &mut output, *number)?
                        }
                        Value::Nodeset(nodes) => {
                            if let Some(node) = nodes.document_order_first_in(context, runtime)? {
                                runtime.visit_node_text(context, &node, |chunk| {
                                    runtime.append_text(context, &mut output, chunk)?;
                                    Ok(true)
                                })?;
                            }
                        }
                        value => {
                            let text = runtime.value_text(context, value)?;
                            runtime.append_text(context, &mut output, &text)?;
                        }
                    }
                }
                Ok(runtime.finish_text(output))
            }
            Self::StartsWith | Self::Contains | Self::Before | Self::After => {
                args.exactly(2)?;
                let first = runtime.value_text(context, &values[0])?;
                let second = runtime.value_text(context, &values[1])?;
                context.charge_work(first.len().saturating_mul(2).saturating_add(second.len()))?;
                match self {
                    Self::StartsWith => Ok(Value::Boolean(first.starts_with(&*second))),
                    Self::Contains => Ok(Value::Boolean(first.contains(&*second))),
                    Self::Before => runtime.literal(
                        context,
                        first.find(&*second).map_or("", |offset| &first[..offset]),
                    ),
                    _ => runtime.literal(
                        context,
                        first
                            .find(&*second)
                            .map_or("", |offset| &first[offset + second.len()..]),
                    ),
                }
            }
            Self::Substring => {
                args.at_least(2)?;
                args.at_most(3)?;
                let length = if values.len() == 3 {
                    Some(super::round_ties_to_positive_infinity(
                        values[2].number_in(context, runtime)?,
                    ))
                } else {
                    None
                };
                let start =
                    super::round_ties_to_positive_infinity(values[1].number_in(context, runtime)?);
                let source = runtime.value_text(context, &values[0])?;
                context.charge_work(source.len().saturating_mul(2))?;
                let mut output = runtime.empty_text()?;
                for (position, character) in source.chars().enumerate() {
                    let position = (position + 1) as f64;
                    if position >= start && length.is_none_or(|length| position < start + length) {
                        append_char(runtime, context, &mut output, character)?;
                    }
                }
                Ok(runtime.finish_text(output))
            }
            Self::StringLength | Self::Normalize => {
                args.at_most(1)?;
                let mut length = 0usize;
                let mut output = runtime.empty_text()?;
                let mut pending_space = false;
                let mut consume = |chunk: &str| {
                    context.charge_work(chunk.len())?;
                    for character in chunk.chars() {
                        if matches!(self, Self::StringLength) {
                            length += 1;
                        } else if matches!(character, ' ' | '\t' | '\r' | '\n') {
                            pending_space = !output.is_empty();
                        } else {
                            if pending_space {
                                runtime.append_text(context, &mut output, " ")?;
                                pending_space = false;
                            }
                            append_char(runtime, context, &mut output, character)?;
                        }
                    }
                    Ok(true)
                };
                match values.first() {
                    None => runtime.visit_node_text(context, &context.node, &mut consume)?,
                    Some(Value::Nodeset(nodes)) => {
                        if let Some(node) = nodes.document_order_first_in(context, runtime)? {
                            runtime.visit_node_text(context, &node, &mut consume)?;
                        }
                    }
                    Some(value) => {
                        consume(&runtime.value_text(context, value)?)?;
                    }
                }
                if matches!(self, Self::StringLength) {
                    Ok(Value::Number(length as f64))
                } else {
                    Ok(runtime.finish_text(output))
                }
            }
            Self::Translate => {
                args.exactly(3)?;
                let source = runtime.value_text(context, &values[0])?;
                let from = runtime.value_text(context, &values[1])?;
                let to = runtime.value_text(context, &values[2])?;
                let levels = (usize::BITS - from.len().leading_zeros()) as usize + 1;
                context.charge_work(
                    from.len()
                        .saturating_add(source.len())
                        .saturating_mul(levels.saturating_mul(2))
                        .saturating_add(to.len()),
                )?;
                let mut replacements = runtime.list();
                runtime.reserve(context, &mut replacements, from.chars().count())?;
                let mut to = to.chars();
                for (index, character) in from.chars().enumerate() {
                    replacements.push((character, index, to.next()))?;
                }
                replacements.sort_unstable_by_key(|&(character, index, _)| (character, index));
                let mut retained = 0;
                for index in 0..replacements.len() {
                    if retained == 0 || replacements[index].0 != replacements[retained - 1].0 {
                        replacements[retained] = replacements[index];
                        retained += 1;
                    }
                }
                replacements.truncate(retained);
                let mut output = runtime.empty_text()?;
                for character in source.chars() {
                    let mapped =
                        match replacements.binary_search_by_key(&character, |entry| entry.0) {
                            Ok(index) => replacements[index].2,
                            Err(_) => Some(character),
                        };
                    if let Some(character) = mapped {
                        append_char(runtime, context, &mut output, character)?;
                    }
                }
                Ok(runtime.finish_text(output))
            }
            Self::Boolean | Self::Not => {
                args.exactly(1)?;
                let value = values[0].boolean();
                Ok(Value::Boolean(if matches!(self, Self::Not) {
                    !value
                } else {
                    value
                }))
            }
            Self::True | Self::False => {
                args.exactly(0)?;
                Ok(Value::Boolean(matches!(self, Self::True)))
            }
            Self::Number => {
                args.at_most(1)?;
                let value = match values.first() {
                    Some(value) => value.number_in(context, runtime)?,
                    None => runtime.node_number(context, &context.node)?,
                };
                Ok(Value::Number(value))
            }
            Self::Sum => {
                args.exactly(1)?;
                let Value::Nodeset(nodes) = &values[0] else {
                    return Err(Error::not_a_nodeset(&values[0]));
                };
                let mut sum = 0.0;
                nodes.visit_document_order_in(context, runtime, |node| {
                    sum += runtime.node_number(context, node)?;
                    Ok(())
                })?;
                Ok(Value::Number(sum))
            }
            Self::Floor | Self::Ceiling | Self::Round => {
                args.exactly(1)?;
                let value = values[0].number_in(context, runtime)?;
                Ok(Value::Number(match self {
                    Self::Floor => value.floor(),
                    Self::Ceiling => value.ceil(),
                    _ => super::round_ties_to_positive_infinity(value),
                }))
            }
        }
    }
}
