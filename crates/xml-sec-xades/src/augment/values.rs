//! Values that join the `CertificateValues` and `RevocationValues` a
//! signature already holds.
//!
//! ETSI TS 101 903 V1.4.2 §§7.6.1-7.6.2 (and V1.1.1 §7.6) allow one of each,
//! `RevocationValues` holding `CRLValues`, `OCSPValues` and `OtherValues` in
//! turn, and the readers refuse a second one. While no archive timestamp
//! protects them, new values go inside the held containers, and a container
//! is created only where none is held.

use super::{AugmentError, StagingError, ValidationData};
use crate::draft::Draft;
use crate::placement::{self, PlacementError, Unsigned, XADES_141};
use alloc::{string::String, vec::Vec};
use structured_asn1::memory::Work;
use structured_xades::produce::{Event, Writer};
use xml_sec::document::{DocumentView, XmlDocument};

/// Whether the signature's unsigned properties already hold an archive
/// timestamp, which then covers its values: their entries stay as they are.
pub(super) fn archived<W: Work>(
    view: DocumentView<'_>,
    unsigned: Unsigned,
    namespace: &str,
    work: &W,
) -> Result<bool, PlacementError> {
    let Some(properties) = unsigned.signature_properties() else {
        return Ok(false);
    };
    for node in placement::children(view, properties, work)? {
        if placement::is_element(view, node, XADES_141, "ArchiveTimeStamp", work)?
            || placement::is_element(view, node, namespace, "ArchiveTimeStamp", work)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The values containers a signature already holds, while no archive
/// timestamp protects them.
#[derive(Clone, Copy, Default)]
pub(super) struct Held {
    certificates: bool,
    revocation: Option<HeldRevocation>,
}

/// The containers a held `RevocationValues` holds.
#[derive(Clone, Copy)]
struct HeldRevocation {
    crls: bool,
    ocsps: bool,
}

impl Held {
    /// The containers in `namespace` the `unsigned` properties hold, none
    /// once an archive timestamp covers them.
    pub(super) fn of<W: Work>(
        view: DocumentView<'_>,
        unsigned: Unsigned,
        namespace: &str,
        work: &W,
    ) -> Result<Self, PlacementError> {
        let Some(properties) = unsigned.signature_properties() else {
            return Ok(Self::default());
        };
        if archived(view, unsigned, namespace, work)? {
            return Ok(Self::default());
        }
        let held = |parent, local| {
            Ok::<_, PlacementError>(
                placement::child(view, parent, namespace, local, work)?.is_some(),
            )
        };
        let revocation =
            match placement::child(view, properties, namespace, "RevocationValues", work)? {
                Some(revocation) => Some(HeldRevocation {
                    crls: held(revocation, "CRLValues")?,
                    ocsps: held(revocation, "OCSPValues")?,
                }),
                None => None,
            };
        Ok(Self {
            certificates: held(properties, "CertificateValues")?,
            revocation,
        })
    }
}

/// Where a drafted piece of values joins the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Join {
    /// A new property after the unsigned signature properties.
    Property,
    /// A new `CertificateValues` before the held `RevocationValues`.
    BeforeRevocation,
    /// Into the held `CertificateValues`.
    Certificates,
    /// A new `CRLValues`, the first child of the held `RevocationValues`.
    FirstInRevocation,
    /// A new `OCSPValues`, before the held `OtherValues` or last.
    AfterCrls,
    /// Into the held `CRLValues`.
    Crls,
    /// Into the held `OCSPValues`.
    Ocsps,
}

/// One output of [`Split`]: the elements at least `skip` levels below the
/// values containers, as siblings.
struct Part {
    draft: Draft,
    skip: usize,
    join: Join,
    used: bool,
}

impl Part {
    fn new(skip: usize, join: Join) -> Self {
        Self {
            draft: Draft::siblings(),
            skip,
            join,
            used: false,
        }
    }

    fn finish(self) -> Result<Option<(String, Join)>, AugmentError> {
        if !self.used {
            return Ok(None);
        }
        Ok(Some((self.draft.finish_siblings()?.concat(), self.join)))
    }
}

/// The values written once, routed to the containers the signature holds:
/// a held container receives only the elements below it, a missing one is
/// written whole.
pub(super) struct Split {
    path: Vec<&'static str>,
    certificates: Part,
    revocation: Revocation,
}

/// Where the revocation values go.
enum Revocation {
    /// A new `RevocationValues`.
    Whole(Part),
    /// Into the held one: its CRLs and its OCSP responses.
    Held { crls: Part, ocsps: Part },
}

impl Split {
    pub(super) fn new(held: Held) -> Self {
        let certificates = match (held.certificates, held.revocation.is_some()) {
            (true, _) => Part::new(1, Join::Certificates),
            (false, true) => Part::new(0, Join::BeforeRevocation),
            (false, false) => Part::new(0, Join::Property),
        };
        let nested = |held, into, new| {
            if held {
                Part::new(2, into)
            } else {
                Part::new(1, new)
            }
        };
        let revocation = match held.revocation {
            None => Revocation::Whole(Part::new(0, Join::Property)),
            Some(revocation) => Revocation::Held {
                crls: nested(revocation.crls, Join::Crls, Join::FirstInRevocation),
                ocsps: nested(revocation.ocsps, Join::Ocsps, Join::AfterCrls),
            },
        };
        Self {
            path: Vec::new(),
            certificates,
            revocation,
        }
    }

    /// The part the current element belongs to, if it is written at all.
    fn part(&mut self) -> Option<&mut Part> {
        let part = match (self.path.first().copied(), self.path.get(1).copied()) {
            (Some("CertificateValues" | "AttrAuthoritiesCertValues"), _) => &mut self.certificates,
            (Some(_), second) => match (&mut self.revocation, second) {
                (Revocation::Whole(whole), _) => whole,
                (Revocation::Held { crls, .. }, Some("CRLValues")) => crls,
                (Revocation::Held { ocsps, .. }, Some("OCSPValues")) => ocsps,
                (Revocation::Held { .. }, _) => return None,
            },
            (None, _) => return None,
        };
        (self.path.len() > part.skip).then_some(part)
    }

    fn forward<Q: Work>(&mut self, event: Event<'_>, work: &Q) -> Result<(), StagingError> {
        if let Some(part) = self.part() {
            part.used = true;
            part.draft.write(event, work).map_err(StagingError::Draft)?;
        }
        Ok(())
    }

    /// The pieces in insertion order.
    pub(super) fn finish(self) -> Result<Vec<(String, Join)>, AugmentError> {
        let mut pieces = Vec::new();
        pieces.extend(self.certificates.finish()?);
        match self.revocation {
            Revocation::Whole(whole) => pieces.extend(whole.finish()?),
            Revocation::Held { crls, ocsps } => {
                pieces.extend(crls.finish()?);
                pieces.extend(ocsps.finish()?);
            }
        }
        Ok(pieces)
    }
}

impl Writer for Split {
    type Error = StagingError;

    fn write<Q: Work>(&mut self, event: Event<'_>, work: &Q) -> Result<(), StagingError> {
        match event {
            Event::Begin(name) => {
                self.path.push(name.local);
                self.forward(event, work)
            }
            Event::End => {
                self.forward(event, work)?;
                self.path.pop();
                Ok(())
            }
            Event::Attribute(..) | Event::Text(_) | Event::Binary(_) => self.forward(event, work),
        }
    }
}

/// Insert `pieces` into `data.signature`, each where its [`Join`] says; the
/// new properties go in one insertion after the existing ones.
pub(super) fn insert_values<W: Work>(
    document: &mut XmlDocument,
    data: &ValidationData<'_, '_>,
    namespace: &str,
    pieces: &[(String, Join)],
    work: &W,
) -> Result<(), AugmentError> {
    let mut properties = String::new();
    for (markup, join) in pieces {
        if *join == Join::Property {
            properties.push_str(markup);
            continue;
        }
        // One insertion per generation: each target is located afresh.
        let (node, before) = document.with_view(|view| {
            let located =
                placement::locate_in(view, data.signature, data.id_attributes, namespace, work)?;
            let held = || AugmentError::Construction(structured_xades::produce::Error::Foreign);
            let properties = located.unsigned.signature_properties().ok_or_else(held)?;
            let child = |parent, local| {
                placement::child(view, parent, namespace, local, work)?.ok_or_else(held)
            };
            Ok::<_, AugmentError>(match join {
                Join::Certificates => (child(properties, "CertificateValues")?, false),
                Join::BeforeRevocation => (child(properties, "RevocationValues")?, true),
                Join::Crls => (
                    child(child(properties, "RevocationValues")?, "CRLValues")?,
                    false,
                ),
                Join::Ocsps => (
                    child(child(properties, "RevocationValues")?, "OCSPValues")?,
                    false,
                ),
                Join::FirstInRevocation => {
                    let revocation = child(properties, "RevocationValues")?;
                    let mut first = None;
                    for node in placement::children(view, revocation, work)? {
                        if placement::is_element_node(view, node, work)? {
                            first = Some(node);
                            break;
                        }
                    }
                    first.map_or((revocation, false), |first| (first, true))
                }
                Join::AfterCrls => {
                    let revocation = child(properties, "RevocationValues")?;
                    placement::child(view, revocation, namespace, "OtherValues", work)?
                        .map_or((revocation, false), |other| (other, true))
                }
                Join::Property => unreachable!("new properties are inserted together"),
            })
        })?;
        if before {
            document.insert_before(node, markup)?;
        } else {
            document.append_child(node, markup)?;
        }
    }
    if !properties.is_empty() {
        let unsigned = document.with_view(|view| {
            placement::locate_in(view, data.signature, data.id_attributes, namespace, work)
                .map(|located| located.unsigned)
        })?;
        unsigned.insert_in(document, &properties, namespace)?;
    }
    Ok(())
}
