//! Tree, attribute and scalar access over the original verified document.

use crate::{Document, Error, Snapshot};
use core::convert::Infallible;
use structured_asn1::memory::Work;
use structured_xades::attributes::AttributeXml;
use structured_xades::properties::{DateTimeFact, DateTimeXml};
use structured_xades::reference::{LexicalSource, VisitError};
use structured_xades::scalar::{
    Datatype, Fact, QNameFact, QNameReading, QNameValue, QNameXml, ScalarXml, UriValue, UriXml,
};
use structured_xades::xml::{Name, Node, Xml};
use xml_sec::document::{DocumentIdentity, NodeIdentity};
use xml_sec::xmldsig::extension::{
    self, InspectionError, NodeView, ScalarFact, ScalarInspection, ScalarType, ScalarValue,
};

impl<W: Work> Xml for Document<'_, '_, '_, '_, W> {
    type Id = NodeIdentity;
    type Document = DocumentIdentity;
    type Generation = u64;
    type Error = Error;

    fn snapshot(&self) -> Snapshot {
        let view = self.session.view();
        Snapshot {
            document: view.identity(),
            generation: view.generation(),
        }
    }

    fn inspect<R, Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        execution: &Q,
        visitor: impl for<'view> FnOnce(Node<'view>) -> R,
    ) -> Result<R, Error> {
        self.check(snapshot)?;
        Ok(extension::inspect_node(
            self.session.view(),
            node,
            execution,
            |value| {
                visitor(match value {
                    NodeView::Element {
                        namespace,
                        local_name,
                    } => Node::Element(Name {
                        namespace: namespace.unwrap_or(""),
                        local: local_name,
                    }),
                    NodeView::Text(text) => Node::Text(text),
                    NodeView::Other => Node::Other,
                })
            },
        )?)
    }

    fn attribute<R, Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        name: Name<'_>,
        execution: &Q,
        visitor: impl for<'view> FnOnce(Option<&'view str>) -> R,
    ) -> Result<R, Error> {
        self.check(snapshot)?;
        self.with_attribute(node, name, execution, visitor)
    }

    fn first_child<Q: Work>(
        &self,
        snapshot: Snapshot,
        parent: NodeIdentity,
        execution: &Q,
    ) -> Result<Option<NodeIdentity>, Error> {
        self.check(snapshot)?;
        Ok(extension::first_child(
            self.session.view(),
            parent,
            execution,
        )?)
    }

    fn next_sibling<Q: Work>(
        &self,
        snapshot: Snapshot,
        parent: NodeIdentity,
        node: NodeIdentity,
        execution: &Q,
    ) -> Result<Option<NodeIdentity>, Error> {
        self.check(snapshot)?;
        Ok(extension::next_sibling(
            self.session.view(),
            parent,
            node,
            execution,
        )?)
    }
}

impl<W: Work> Document<'_, '_, '_, '_, W> {
    /// Find one direct attribute by expanded name; the empty namespace name
    /// selects an unqualified attribute (Namespaces in XML 1.0 §6.2).
    pub(crate) fn with_attribute<R, Q: Work>(
        &self,
        node: NodeIdentity,
        name: Name<'_>,
        execution: &Q,
        visitor: impl for<'view> FnOnce(Option<&'view str>) -> R,
    ) -> Result<R, Error> {
        let mut visitor = Some(visitor);
        let mut found = None;
        let visited =
            extension::visit_direct_attributes(self.session.view(), node, execution, |attribute| {
                if attribute.local_name == name.local
                    && attribute.namespace.unwrap_or("") == name.namespace
                {
                    let visitor = visitor.take().expect("an attribute is selected once");
                    found = Some(visitor(Some(attribute.value)));
                    // Expanded attribute names are unique on an element, so
                    // the first match ends the scan.
                    return Err(());
                }
                Ok(())
            });
        match visited {
            Ok(()) | Err(InspectionError::Visitor(())) => {}
            Err(InspectionError::Processing(error)) => return Err(error.into()),
        }
        Ok(match found {
            Some(value) => value,
            None => visitor.take().expect("no attribute was selected")(None),
        })
    }

    fn with_scalar<R, VE>(
        &self,
        node: NodeIdentity,
        source: LexicalSource<'_>,
        datatype: ScalarType<'_>,
        execution: &impl Work,
        consume: impl for<'a> FnOnce(ScalarInspection<'a>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Error, VE>> {
        extension::with_scalar(
            self.session.view(),
            node,
            crate::source(source),
            datatype,
            execution,
            consume,
        )
        .map_err(|error| match error {
            InspectionError::Processing(error) => VisitError::Processing(error.into()),
            InspectionError::Visitor(error) => VisitError::Visitor(error),
        })
    }
}

fn processing<T>(result: Result<T, VisitError<Error, Infallible>>) -> Result<T, Error> {
    result.map_err(|error| match error {
        VisitError::Processing(error) => error,
        VisitError::Visitor(never) => match never {},
    })
}

impl<W: Work> AttributeXml for Document<'_, '_, '_, '_, W> {
    fn visit_attributes<VE, Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        execution: &Q,
        mut visitor: impl for<'view> FnMut(Name<'view>) -> Result<(), VE>,
    ) -> Result<(), VisitError<Error, VE>> {
        self.check(snapshot).map_err(VisitError::Processing)?;
        extension::visit_direct_attributes(self.session.view(), node, execution, |attribute| {
            visitor(Name {
                namespace: attribute.namespace.unwrap_or(""),
                local: attribute.local_name,
            })
        })
        .map_err(|error| match error {
            InspectionError::Processing(error) => VisitError::Processing(error.into()),
            InspectionError::Visitor(error) => VisitError::Visitor(error),
        })
    }
}

impl<W: Work> QNameXml for Document<'_, '_, '_, '_, W> {
    fn with_qname<R, VE, Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        source: LexicalSource<'_>,
        execution: &Q,
        visitor: impl for<'view> FnOnce(QNameReading<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Error, VE>> {
        self.check(snapshot).map_err(VisitError::Processing)?;
        self.with_scalar(node, source, ScalarType::QName, execution, |inspection| {
            visitor(QNameReading {
                lexical: inspection.lexical,
                fact: match inspection.fact {
                    ScalarFact::Absent => QNameFact::Absent,
                    ScalarFact::ComplexContent => QNameFact::ComplexContent,
                    ScalarFact::Malformed => QNameFact::Malformed,
                    ScalarFact::UnboundPrefix(prefix) => QNameFact::UnboundPrefix(prefix),
                    ScalarFact::Value(ScalarValue::QName(value)) => QNameFact::Value(QNameValue {
                        namespace: value.namespace,
                        local_name: value.local_name,
                    }),
                    ScalarFact::Unsupported | ScalarFact::Value(_) => QNameFact::Unsupported,
                },
            })
        })
    }
}

impl<W: Work> UriXml for Document<'_, '_, '_, '_, W> {
    fn with_uri<R, VE, Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        source: LexicalSource<'_>,
        execution: &Q,
        visitor: impl for<'view> FnOnce(UriValue<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Error, VE>> {
        self.check(snapshot).map_err(VisitError::Processing)?;
        self.with_scalar(node, source, ScalarType::AnyUri, execution, |inspection| {
            visitor(match inspection.fact {
                ScalarFact::Absent => UriValue::Absent,
                ScalarFact::ComplexContent => UriValue::ComplexContent,
                ScalarFact::Malformed | ScalarFact::UnboundPrefix(_) => UriValue::Malformed,
                ScalarFact::Value(ScalarValue::AnyUri(value)) => UriValue::Valid(value),
                ScalarFact::Unsupported | ScalarFact::Value(_) => UriValue::Unsupported,
            })
        })
    }
}

impl<W: Work> ScalarXml for Document<'_, '_, '_, '_, W> {
    fn scalar<Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        source: LexicalSource<'_>,
        datatype: Datatype,
        execution: &Q,
    ) -> Result<Fact, Error> {
        self.check(snapshot)?;
        let requested = match datatype {
            Datatype::Id => ScalarType::Id,
            Datatype::AnyUri => ScalarType::AnyUri,
            Datatype::Integer => ScalarType::Integer,
        };
        processing(
            self.with_scalar(node, source, requested, execution, |inspection| {
                Ok(match inspection.fact {
                    ScalarFact::Absent => Fact::Absent,
                    ScalarFact::ComplexContent => Fact::ComplexContent,
                    ScalarFact::Malformed | ScalarFact::UnboundPrefix(_) => Fact::Malformed,
                    ScalarFact::Unsupported => Fact::Unsupported,
                    ScalarFact::Value(_) => Fact::Valid,
                })
            }),
        )
    }
}

impl<W: Work> DateTimeXml for Document<'_, '_, '_, '_, W> {
    fn date_time<Q: Work>(
        &self,
        snapshot: Snapshot,
        node: NodeIdentity,
        execution: &Q,
    ) -> Result<DateTimeFact, Error> {
        self.check(snapshot)?;
        processing(self.with_scalar(
            node,
            LexicalSource::SimpleContent,
            ScalarType::DateTime,
            execution,
            |inspection| {
                Ok(match inspection.fact {
                    ScalarFact::Value(ScalarValue::DateTime(value)) => DateTimeFact::Valid {
                        timezone_minutes: value.timezone_minutes,
                    },
                    ScalarFact::Absent
                    | ScalarFact::ComplexContent
                    | ScalarFact::Malformed
                    | ScalarFact::UnboundPrefix(_) => DateTimeFact::Malformed,
                    ScalarFact::Unsupported | ScalarFact::Value(_) => DateTimeFact::Unsupported,
                })
            },
        ))
    }
}
