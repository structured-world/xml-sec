//! Original-source XPath nodes with current-execution construction.

use std::cell::RefCell;

use structured_asn1::memory::{OwnedVec, Work};

use super::grammar::{Binary, Builder, Failure, Fault, Grammar, Node, Test};
use super::token::BorrowedToken;
use super::tokenizer::{BorrowedTokenizer, TokenDeabbreviator};
use crate::axis::Axis;
use crate::sxd_document::PrefixedName;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Handle {
    pub index: usize,
    pub depth: usize,
}

pub(super) struct Step<'s> {
    pub axis: Axis,
    pub test: Test<&'s str>,
    pub predicates: OwnedVec<Handle>,
    pub depth: usize,
}

pub(super) enum Entry<'s> {
    Context,
    Root,
    Number(f64),
    String(&'s str),
    Variable(PrefixedName<'s>),
    Function(PrefixedName<'s>, OwnedVec<Handle>),
    Negate(Handle),
    Binary(Binary, Handle, Handle),
    Filter(Handle, Handle),
    Path(Handle, OwnedVec<Step<'s>>),
}

pub(crate) struct Program<'s> {
    pub(super) nodes: OwnedVec<Entry<'s>>,
    pub(super) root: Handle,
}

struct Arena<'s, 'w, W: Work> {
    work: &'w W,
    nodes: RefCell<OwnedVec<Entry<'s>, W>>,
}

impl<'s, W: Work> Builder for Arena<'s, '_, W> {
    type Name = PrefixedName<'s>;
    type Text = &'s str;
    type Expression = Handle;
    type Predicate = Handle;
    type Step = Step<'s>;
    type List<T> = OwnedVec<T, W>;

    fn list<T>(&self) -> Self::List<T> {
        self.work.vector()
    }

    fn inspect(&self) -> Result<(), Failure<Self>> {
        self.work.charge_work(1).map_err(Fault::Resource)
    }

    fn push<T>(&self, list: &mut Self::List<T>, value: T) -> Result<(), Failure<Self>> {
        list.try_push(value).map_err(Fault::Resource)
    }

    fn node(&self, node: Node<Self>, depth: usize) -> Result<Handle, Failure<Self>> {
        let entry = match node {
            Node::Context => Entry::Context,
            Node::Root => Entry::Root,
            Node::Number(value) => Entry::Number(value),
            Node::String(value) => Entry::String(value),
            Node::Variable(name) => Entry::Variable(name),
            Node::Function(name, arguments) => Entry::Function(name, arguments.into_owned()),
            Node::Negate(child) => Entry::Negate(child),
            Node::Binary(operation, left, right) => Entry::Binary(operation, left, right),
            Node::Filter(selector, predicate) => Entry::Filter(selector, predicate),
            Node::Path(start, steps) => Entry::Path(start, steps.into_owned()),
        };
        let mut nodes = self.nodes.borrow_mut();
        let handle = Handle {
            index: nodes.len(),
            depth,
        };
        nodes.try_push(entry).map_err(Fault::Resource)?;
        Ok(handle)
    }

    fn depth(&self, expression: &Handle) -> usize {
        expression.depth
    }

    fn predicate(&self, expression: Handle) -> Handle {
        expression
    }

    fn step(
        &self,
        axis: Axis,
        test: Test<&'s str>,
        predicates: OwnedVec<Handle, W>,
        depth: usize,
    ) -> Step<'s> {
        Step {
            axis,
            test,
            predicates: predicates.into_owned(),
            depth,
        }
    }

    fn step_depth(&self, step: &Step<'s>) -> usize {
        step.depth
    }
}

impl<'s> Program<'s> {
    pub(crate) fn evaluate<'d, N: Into<crate::nodeset::Node<'d>>>(
        &self,
        context: &crate::context::ScopedContext<'_, 'd>,
        node: N,
    ) -> Result<crate::Value<'d>, super::ExecutionError> {
        self.evaluate_in(context, node, crate::runtime::Native)
    }

    pub(crate) fn evaluate_in<'d, N: Into<crate::nodeset::Node<'d>>, R: crate::runtime::Runtime>(
        &self,
        context: &crate::context::ScopedContext<'_, 'd>,
        node: N,
        runtime: R,
    ) -> Result<crate::Value<'d>, super::ExecutionError> {
        use crate::expression::Expression;
        let context = crate::context::Evaluation::new(context, node.into());
        super::expression::ArenaExpression {
            program: self,
            handle: self.root,
            runtime,
        }
        .evaluate(&context)
        .map_err(super::ExecutionError)
    }

    pub(crate) fn parse<W: Work>(
        source: &'s str,
        work: &W,
    ) -> Result<Self, Fault<BorrowedToken<'s>>> {
        // This pass is separate from normalization/complexity inspection. Both
        // the lexer and all arena growth use this execution, not retained credit.
        work.charge_work(source.len() as u64)
            .map_err(Fault::Resource)?;
        let arena = Arena {
            work,
            nodes: RefCell::new(work.vector()),
        };
        let tokens = TokenDeabbreviator::new(BorrowedTokenizer::new(source));
        let root = Grammar::new(&arena).parse(tokens)?;
        Ok(Self {
            nodes: arena.nodes.into_inner().into_owned(),
            root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

    fn memory(bytes: usize, work: usize) -> Memory {
        Memory::new(Arc::new(MemoryAccount::new(bytes, work)))
    }

    #[test]
    fn first_ast_allocation_is_refusable_and_releases_all_owners() {
        // A short expression must not build even one native Box before the
        // actual arena allocator has admitted its storage.
        let work = memory(0, 4096);
        assert!(matches!(
            Program::parse("1 + 2", &work),
            Err(Fault::Resource(MemoryError::LimitExceeded))
        ));
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn lexer_work_is_admitted_before_even_a_scalar() {
        // Current CPU exhaustion is terminal; a tiny AST is not an exemption.
        let work = memory(4096, 0);
        assert!(matches!(
            Program::parse("1", &work),
            Err(Fault::Resource(MemoryError::WorkExceeded))
        ));
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn function_argument_slots_belong_to_current_work_until_borrowed_call_returns() {
        // A retained program cannot pay for a later call's argument slots.
        // The callee observes their actual allocation, and cannot be entered
        // after either current capacity or current work has refused them.
        use std::cell::Cell;
        struct Probe<'a> {
            memory: &'a Memory,
            calls: &'a Cell<usize>,
        }
        impl crate::function::Function for Probe<'_> {
            fn evaluate_borrowed<'c, 'd>(
                &self,
                _: &crate::context::Evaluation<'c, 'd>,
                values: &mut [crate::Value<'d>],
            ) -> Result<crate::Value<'d>, crate::function::Error> {
                assert_eq!(
                    values,
                    &[
                        crate::Value::Number(1.0),
                        crate::Value::Number(2.0),
                        crate::Value::Number(3.0)
                    ]
                );
                assert!(self.memory.used() >= std::mem::size_of_val(values));
                self.calls.set(self.calls.get() + 1);
                let mut args = crate::function::Args::new(values);
                assert_eq!(args.pop_value()?, crate::Value::Number(3.0));
                assert_eq!(args.pop_value()?, crate::Value::Number(2.0));
                assert_eq!(args.pop_value()?, crate::Value::Number(1.0));
                assert_eq!(
                    args.pop_value(),
                    Err(crate::function::Error::ArgumentMissing)
                );
                Ok(crate::Value::Boolean(true))
            }
        }
        let producer = memory(65536, 65536);
        let program = Program::parse("probe(1, 2, 3)", &producer).expect("valid retained program");
        producer
            .charge_work(producer.work_remaining() as u64)
            .expect("exhaust the producer after retaining the AST");
        let package = crate::sxd_document::Package::new();
        for (bytes, units, expected) in [
            (0, 4096, Some(MemoryError::LimitExceeded)),
            (4096, 0, Some(MemoryError::WorkExceeded)),
            (4096, 4096, None),
        ] {
            let current = memory(bytes, units);
            let failure = Cell::new(None);
            let calls = Cell::new(0);
            let probe = Probe {
                memory: &current,
                calls: &calls,
            };
            let functions: [(
                crate::sxd_document::QName<'_>,
                &dyn crate::function::Function,
            ); 1] = [(crate::sxd_document::QName::new("probe"), &probe)];
            let mut context = crate::context::ScopedContext::new();
            context.set_function_view(&functions);
            let result = program.evaluate_in(
                &context,
                package.as_document().root(),
                crate::runtime::Accounted {
                    work: &current,
                    failure: &failure,
                },
            );
            assert_eq!(failure.get(), expected);
            if expected.is_some() {
                assert!(result.is_err());
                assert_eq!(calls.get(), 0);
            } else {
                assert_eq!(result, Ok(crate::Value::Boolean(true)));
                assert_eq!(calls.get(), 1);
            }
            assert_eq!(current.used(), 0);
            assert!(producer.used() > 0);
        }
    }

    #[test]
    fn all_variadic_nodes_retain_current_capacity_without_copying_source() {
        // Function arguments, path steps and predicates all belong to the
        // account, while names/literals still point into the input expression.
        let source = "p:fun('text', $v)/child::p:item[@id='x'][2]";
        let work = memory(1 << 20, 1 << 20);
        let program = Program::parse(source, &work).unwrap();
        let Entry::Path(start, steps) = &program.nodes[program.root.index] else {
            panic!("path")
        };
        let Entry::Function(name, arguments) = &program.nodes[start.index] else {
            panic!("function")
        };
        assert_eq!(name.local_part().as_ptr(), source[2..].as_ptr());
        assert_eq!(arguments.len(), 2);
        let Entry::String(literal) = program.nodes[arguments[0].index] else {
            panic!("literal")
        };
        assert_eq!(literal.as_ptr(), source[7..].as_ptr());
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].predicates.len(), 2);
        assert!(work.used() >= program.nodes.capacity() * std::mem::size_of::<Entry<'_>>());
        drop(program);
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn errors_and_deep_trees_do_not_leave_partial_arenas_alive() {
        // All errors unwind owned allocations; depth is cached per node and
        // final destruction follows a flat arena, not recursive Box children.
        let work = memory(1 << 20, 1 << 20);
        for invalid in ["f(1,)", "a[ ]", "a/", "(1", "1 2"] {
            assert!(Program::parse(invalid, &work).is_err(), "{invalid}");
            assert_eq!(work.used(), 0);
        }
        let deep = "-".repeat(super::super::grammar::MAX_DEPTH + 1) + "1";
        assert!(matches!(
            Program::parse(&deep, &work),
            Err(Fault::NestingLimit)
        ));
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn union_binds_inside_unary_minus_and_multiplication() {
        // XPath 1.0 §3.5 productions [24]–[27], not conventional arithmetic
        // intuition, determine the relative unary/union precedence.
        let work = memory(1 << 20, 1 << 20);
        let program = Program::parse("-a | b * 2", &work).unwrap();
        let Entry::Binary(Binary::Multiply, left, _) = program.nodes[program.root.index] else {
            panic!("multiply")
        };
        let Entry::Negate(union) = program.nodes[left.index] else {
            panic!("negate")
        };
        assert!(matches!(
            program.nodes[union.index],
            Entry::Binary(Binary::Union, _, _)
        ));
    }

    #[test]
    fn arena_and_native_evaluate_the_same_semantic_operations() {
        // Both representations use the same operators, node tests, axis and
        // predicate implementation. Exercise every arena dispatch family on
        // one document, including reverse axes and namespace/attribute nodes.
        let package = crate::sxd_document::parser::parse(
            "<root xmlns:p='urn:p'><p:item id='a'>3</p:item><p:item id='b'>7</p:item><?flag yes?><!--note--></root>",
        ).unwrap();
        let document = package.as_document();
        let mut context = crate::Context::new();
        context.set_namespace("p", "urn:p");
        context.set_variable("limit", 3.0);
        let memory = memory(1 << 20, 1 << 24);
        for source in [
            "/",
            "//p:item",
            "//p:item/@id",
            "//namespace::*",
            "//comment()",
            "//processing-instruction('flag')",
            "//text()",
            "count(//p:item)",
            "sum(//p:item)",
            "string((//p:item)[2])",
            "//p:item[. > $limit]",
            "//p:item[1]/following-sibling::*",
            "//p:item[2]/preceding-sibling::*",
            "//p:item/ancestor::*[1]",
            "//p:item/parent::node()",
            "//p:item | //p:item/@id",
            "false() and missing()",
            "true() or missing()",
            "(1 + 2) * 3 - 4 div 2",
            "8 mod 3",
            "-(2 + 3)",
            "3 < 4",
            "3 <= 3",
            "4 > 3",
            "4 >= 4",
            "//p:item = 7",
            "//p:item != 3",
            "'x' = 'x'",
            "concat('a', 'b')",
            "count(//p:item[@id='b'][position()=last()])",
            "boolean(//missing)",
        ] {
            let native = super::super::Factory::new().build(source).unwrap();
            let program = Program::parse(source, &memory).unwrap();
            assert_eq!(
                program.evaluate(&context, document.root()),
                native.evaluate(&context, document.root()),
                "{source}"
            );
            assert_eq!(program.root.depth, native.ast_depth(), "depth: {source}");
            drop(program);
            assert_eq!(memory.used(), 0, "{source}");
        }
    }

    #[test]
    fn arena_and_native_preserve_dynamic_errors() {
        // Missing names and namespaces are execution faults even when an axis
        // has no candidates; arena dispatch must not turn them into false.
        let package = crate::sxd_document::parser::parse("<root/>").unwrap();
        let context = crate::Context::new();
        let work = memory(1 << 20, 1 << 20);
        for source in [
            "unknown()",
            "$missing",
            "//p:missing",
            "p:f()",
            "$p:v",
            "1 | 2",
        ] {
            let native = super::super::Factory::new().build(source).unwrap();
            let program = Program::parse(source, &work).unwrap();
            let root = package.as_document().root();
            let expected = native.evaluate(&context, root);
            assert!(expected.is_err(), "{source}");
            assert_eq!(program.evaluate(&context, root), expected, "{source}");
        }
    }
}
