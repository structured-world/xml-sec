//! The ETSI TS 101 903 levels beyond T of one B-T signature, over the content
//! fixtures: `XAdES-C`, then `-X`, `-XL` and `-A`, each through the public
//! augmentation API, in the EN 319 132 property names.

use std::path::Path;

use structured_asn1::memory::Memory;
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::xmldsig::DigestAlgorithm;
use xml_sec_xades::properties::Profile;
use xml_sec_xades::{
    Assessment, CompleteReferences, Completion, ExtendedKind, Inputs, PendingTimestamp,
    ReferenceSyntax, Requirements, TimestampRequest, ValidationData, add_complete_references,
    add_extended_values, add_historical_references, add_historical_values, complete_timestamp,
    request_extended_timestamp, request_historical_extended_timestamp,
    request_historical_timestamp,
};

/// The nonce of every extended and historical request.
pub(crate) const NONCE: &[u8] = &[0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x03];

/// Writes one named output file.
type Write<'w> = dyn Fn(&str, &[u8]) -> Result<(), String> + 'w;

/// The file names of `profile`'s signature timestamp request and response,
/// and the suffix of its documents.
pub(crate) fn historical_names(profile: Profile) -> (&'static str, &'static str, &'static str) {
    match profile {
        Profile::PreEn => ("historical.tsq", "historical.tsr", "pre-en"),
        Profile::V111 => ("historical-v111.tsq", "historical-v111.tsr", "v111"),
        Profile::V122 => ("historical-v122.tsq", "historical-v122.tsr", "v122"),
    }
}

/// Request the signature timestamp of `document`, a signature in the
/// vocabulary of `profile`, and write it for `historical-request`, or
/// complete it with the TSA's response and write `t-<profile>.xml` for
/// `historical`, then for `historical-lt` add the validation values with the
/// first generation of CRLs and write `lt-<profile>.xml`.
pub(crate) fn historical(
    mut document: XmlDocument,
    (profile, action): (Profile, &str),
    assessment: &Assessment<'_, '_>,
    fixtures: &Path,
    [root, intermediate]: [&[u8]; 2],
    write: &Write<'_>,
    work: &Memory,
) -> Result<(), String> {
    let (query, answer, suffix) = historical_names(profile);
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let pending = request_historical_timestamp(&document, &request, profile, assessment, work)
        .map_err(|error| format!("historical request: {error}"))?;
    if action == "historical-request" {
        return write(query, pending.request());
    }
    let response =
        std::fs::read(fixtures.join(answer)).map_err(|error| format!("read {answer}: {error}"))?;
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))?;
    let (anchors, certificates) = ([root], [intermediate]);
    let inputs = Inputs {
        requirements: Requirements::Timestamped,
        anchors: &anchors,
        certificates: &certificates,
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &[],
        responses: &[],
    };
    complete_timestamp(
        &mut document,
        &pending,
        &response,
        &Completion {
            assessment,
            inputs: &inputs,
            window: None,
            id_attributes: &[],
        },
        work,
    )
    .map_err(|error| format!("historical: {error}"))?;
    write(&format!("t-{suffix}.xml"), document.as_xml().as_bytes())?;
    if action != "historical-lt" {
        return Ok(());
    }
    let read = |name: &str| {
        std::fs::read(fixtures.join(name)).map_err(|error| format!("read {name}: {error}"))
    };
    let lists = [read("root.crl")?, read("intermediate.crl")?];
    let crls: [&[u8]; 2] = [&lists[0], &lists[1]];
    let inputs = Inputs {
        requirements: Requirements::LongTerm,
        crls: &crls,
        ..inputs
    };
    add_historical_values(
        &mut document,
        &ValidationData {
            signature: "sig",
            assessment,
            inputs: &inputs,
            id_attributes: &[],
        },
        profile,
        work,
    )
    .map_err(|error| format!("historical values: {error}"))?;
    write(&format!("lt-{suffix}.xml"), document.as_xml().as_bytes())
}

/// The TS 101 903 levels of the B-B `document`, a signature in the TS 103 171
/// profile of V1.3.2, in the names of V1.3.2 as `action` says, after its
/// signature timestamp from `historical.tsr`: `pre-en-x-request` adds the
/// complete references and writes the X timestamp request `x-pre-en.tsq`,
/// `pre-en-a-request` completes it with `x-pre-en.tsr`, adds the values and
/// writes the archive timestamp request `a-pre-en.tsq`, `pre-en-lta-request`
/// writes the archive timestamp request `lta-pre-en.tsq` of the signature
/// with only its values, `pre-en-a2-request` writes the second archive
/// timestamp request `a2-pre-en.tsq` of the renewal branch (`PreEn::renewed`),
/// and `pre-en-levels` completes everything and writes `c-pre-en.xml`,
/// `x-pre-en.xml`, `xl-pre-en.xml`, `a-pre-en.xml`, `lta-pre-en.xml` and
/// `a-renewed-pre-en.xml`.
pub(crate) fn pre_en_levels(
    document: XmlDocument,
    action: &str,
    assessment: &Assessment<'_, '_>,
    fixtures: &Path,
    [root, intermediate]: [&[u8]; 2],
    write: &Write<'_>,
    work: &Memory,
) -> Result<(), String> {
    let read = |name: &str| {
        std::fs::read(fixtures.join(name)).map_err(|error| format!("read {name}: {error}"))
    };
    let lists = [read("root.crl")?, read("intermediate.crl")?];
    let crls: [&[u8]; 2] = [&lists[0], &lists[1]];
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))?;
    let (anchors, certificates) = ([root], [intermediate]);
    let inputs = Inputs {
        requirements: Requirements::LongTerm,
        anchors: &anchors,
        certificates: &certificates,
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &crls,
        responses: &[],
    };
    let completion = Completion {
        assessment,
        inputs: &inputs,
        window: None,
        id_attributes: &[],
    };
    // The archive TSA's own CA and its CRL, which only the renewal branch's
    // first archive timestamp needs.
    let (archive_ca, archive_crl) = (read("archive-ca.der")?, read("archive-ca.crl")?);
    let (renewal_certificates, renewal_crls): ([&[u8]; 2], [&[u8]; 3]) = (
        [intermediate, &archive_ca],
        [&lists[0], &lists[1], &archive_crl],
    );
    let renewal_inputs = Inputs {
        certificates: &renewal_certificates,
        crls: &renewal_crls,
        ..inputs
    };
    let renewal = Completion {
        inputs: &renewal_inputs,
        ..completion
    };
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let step = PreEn {
        action,
        assessment,
        request: &request,
        completion: &completion,
        renewal: &renewal,
        fixtures,
        write,
        work,
    };
    let mut document = document;
    let pending =
        request_historical_timestamp(&document, &request, Profile::PreEn, assessment, work)
            .map_err(|error| format!("historical request: {error}"))?;
    step.complete(&mut document, &pending, "historical.tsr")?;
    // The X and A requests need nothing of the B-LT branch.
    if matches!(action, "pre-en-x-request" | "pre-en-a-request") {
        return step.extended(&mut document);
    }
    // The B-LT branch: the values alone, then an archive timestamp.
    let mut long_term = XmlDocument::parse(document.as_xml())
        .map_err(|error| format!("reparse the B-T document: {error}"))?;
    step.values(&mut long_term)?;
    if step.archive(&mut long_term, "lta")? {
        step.extended(&mut document)?;
    }
    Ok(())
}

/// One run of `pre_en_levels`: what it does, and with what.
struct PreEn<'a> {
    action: &'a str,
    assessment: &'a Assessment<'a, 'a>,
    request: &'a TimestampRequest<'a>,
    completion: &'a Completion<'a, 'a>,
    /// The completion that also reads the archive TSA's CA and CRL.
    renewal: &'a Completion<'a, 'a>,
    fixtures: &'a Path,
    write: &'a Write<'a>,
    work: &'a Memory,
}

impl PreEn<'_> {
    /// Complete `pending` with the fixture response `answer`.
    fn complete(
        &self,
        document: &mut XmlDocument,
        pending: &PendingTimestamp,
        answer: &str,
    ) -> Result<(), String> {
        self.complete_with(document, pending, answer, self.completion)
    }

    /// [`Self::complete`] under `completion`.
    fn complete_with(
        &self,
        document: &mut XmlDocument,
        pending: &PendingTimestamp,
        answer: &str,
        completion: &Completion<'_, '_>,
    ) -> Result<(), String> {
        let response = std::fs::read(self.fixtures.join(answer))
            .map_err(|error| format!("read {answer}: {error}"))?;
        complete_timestamp(document, pending, &response, completion, self.work)
            .map_err(|error| format!("{answer}: {error}"))
    }

    /// Add the values the signature's census finds missing.
    fn values(&self, document: &mut XmlDocument) -> Result<(), String> {
        self.values_with(document, self.completion)
    }

    /// [`Self::values`] from the inputs of `completion`.
    fn values_with(
        &self,
        document: &mut XmlDocument,
        completion: &Completion<'_, '_>,
    ) -> Result<(), String> {
        let values = ValidationData {
            signature: "sig",
            assessment: self.assessment,
            inputs: completion.inputs,
            id_attributes: &[],
        };
        add_historical_values(document, &values, Profile::PreEn, self.work)
            .map(|_| ())
            .map_err(|error| format!("values: {error}"))
    }

    /// The `XAdESDoubleATest` branch of the XAdES-XL `document`: its archive
    /// timestamp from the archive TSA (`a-pre-en-other.tsr`, the answer to
    /// `a-pre-en.tsq`), that TSA's validation data right after it, then a
    /// second archive timestamp: `pre-en-a2-request` writes its request
    /// `a2-pre-en.tsq`, `pre-en-levels` completes it with `a2-pre-en.tsr`
    /// and writes `a-renewed-pre-en.xml`.
    fn renewed(&self, mut document: XmlDocument) -> Result<(), String> {
        if !matches!(self.action, "pre-en-a2-request" | "pre-en-levels") {
            return Ok(());
        }
        let archive = |document: &XmlDocument| {
            request_historical_extended_timestamp(
                document,
                self.request,
                ExtendedKind::Archive141,
                Profile::PreEn,
                self.assessment,
                self.work,
            )
            .map_err(|error| format!("renewal archive request: {error}"))
        };
        let pending = archive(&document)?;
        self.complete_with(&mut document, &pending, "a-pre-en-other.tsr", self.renewal)?;
        self.values_with(&mut document, self.renewal)?;
        let pending = archive(&document)?;
        if self.action == "pre-en-a2-request" {
            return (self.write)("a2-pre-en.tsq", pending.request());
        }
        self.complete_with(&mut document, &pending, "a2-pre-en.tsr", self.renewal)?;
        self.save(&document, "a-renewed-pre-en.xml")
    }

    /// Write `document` as `name` when the run completes every level.
    fn save(&self, document: &XmlDocument, name: &str) -> Result<(), String> {
        if self.action == "pre-en-levels" {
            (self.write)(name, document.as_xml().as_bytes())?;
        }
        Ok(())
    }

    /// Request the archive timestamp `<level>-pre-en`: write the request
    /// when the action asks for it and stop, or complete it when the run
    /// completes every level. Whether the run goes on.
    fn archive(&self, document: &mut XmlDocument, level: &str) -> Result<bool, String> {
        let pending = request_historical_extended_timestamp(
            document,
            self.request,
            ExtendedKind::Archive141,
            Profile::PreEn,
            self.assessment,
            self.work,
        )
        .map_err(|error| format!("{level} request: {error}"))?;
        if self.action == format!("pre-en-{level}-request") {
            (self.write)(&format!("{level}-pre-en.tsq"), pending.request())?;
            return Ok(false);
        }
        if self.action == "pre-en-levels" {
            self.complete(document, &pending, &format!("{level}-pre-en.tsr"))?;
            self.save(document, &format!("{level}-pre-en.xml"))?;
        }
        Ok(true)
    }

    /// The XAdES-C, -X, -XL and -A branch of the B-T `document`.
    fn extended(&self, document: &mut XmlDocument) -> Result<(), String> {
        add_historical_references(
            document,
            &CompleteReferences {
                signature: "sig",
                syntax: ReferenceSyntax::Original,
                digest: DigestAlgorithm::Sha256,
                assessment: self.assessment,
                inputs: self.completion.inputs,
                id_attributes: &[],
            },
            Profile::PreEn,
            self.work,
        )
        .map_err(|error| format!("references: {error}"))?;
        self.save(document, "c-pre-en.xml")?;
        let pending = request_historical_extended_timestamp(
            document,
            self.request,
            ExtendedKind::SignatureAndReferences(ReferenceSyntax::Original),
            Profile::PreEn,
            self.assessment,
            self.work,
        )
        .map_err(|error| format!("X request: {error}"))?;
        match self.action {
            "pre-en-x-request" => return (self.write)("x-pre-en.tsq", pending.request()),
            "pre-en-lta-request" => return Ok(()),
            _ => {}
        }
        self.complete(document, &pending, "x-pre-en.tsr")?;
        self.save(document, "x-pre-en.xml")?;
        self.values(document)?;
        self.save(document, "xl-pre-en.xml")?;
        let xl = XmlDocument::parse(document.as_xml())
            .map_err(|error| format!("reparse the XL document: {error}"))?;
        self.archive(document, "a")?;
        self.renewed(xl)
    }
}

/// Augment the B-T `document` as `action` says: `x-request` writes the X
/// timestamp request `x.tsq`, `x` completes it with `x.tsr` and writes
/// `c.xml` and `x.xml`, `a-request` goes on to write the archive timestamp
/// request `a.tsq`, `a2-request` completes it and writes the request of its
/// renewal `a2.tsq`, and `extended` completes all three and also writes
/// `xl.xml`, `a.xml` and `a-renewed.xml`.
pub(crate) fn levels(
    document: &mut XmlDocument,
    assessment: &Assessment<'_, '_>,
    fixtures: &Path,
    [root, intermediate]: [&[u8]; 2],
    action: &str,
    write: &Write<'_>,
    work: &Memory,
) -> Result<(), String> {
    let read = |name: &str| {
        std::fs::read(fixtures.join(name)).map_err(|error| format!("read {name}: {error}"))
    };
    let lists = [read("root.crl")?, read("intermediate.crl")?];
    let crls: [&[u8]; 2] = [&lists[0], &lists[1]];
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))?;
    let (anchors, certificates) = ([root], [intermediate]);
    let inputs = Inputs {
        requirements: Requirements::Timestamped,
        anchors: &anchors,
        certificates: &certificates,
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &crls,
        responses: &[],
    };
    add_complete_references(
        document,
        &CompleteReferences {
            signature: "sig",
            syntax: ReferenceSyntax::V2,
            digest: DigestAlgorithm::Sha256,
            assessment,
            inputs: &inputs,
            id_attributes: &[],
        },
        work,
    )
    .map_err(|error| format!("references: {error}"))?;
    let save = |name: &str, document: &XmlDocument| {
        if matches!(action, "x" | "extended") {
            write(name, document.as_xml().as_bytes())?;
        }
        Ok::<_, String>(())
    };
    save("c.xml", document)?;
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let completion = Completion {
        assessment,
        inputs: &inputs,
        window: None,
        id_attributes: &[],
    };
    let x = ExtendedKind::SignatureAndReferences(ReferenceSyntax::V2);
    let pending = request_extended_timestamp(document, &request, x, assessment, &inputs, work)
        .map_err(|error| format!("X request: {error}"))?;
    if action == "x-request" {
        return write("x.tsq", pending.request());
    }
    complete_timestamp(document, &pending, &read("x.tsr")?, &completion, work)
        .map_err(|error| format!("X: {error}"))?;
    save("x.xml", document)?;
    if action == "x" {
        return Ok(());
    }
    add_extended_values(
        document,
        &ValidationData {
            signature: "sig",
            assessment,
            inputs: &inputs,
            id_attributes: &[],
        },
        work,
    )
    .map_err(|error| format!("XL: {error}"))?;
    save("xl.xml", document)?;
    // The archive timestamp, then its renewal, which covers the first.
    for (name, query, response, archived) in [
        ("A", "a.tsq", "a.tsr", "a.xml"),
        ("A renewal", "a2.tsq", "a2.tsr", "a-renewed.xml"),
    ] {
        let pending = request_extended_timestamp(
            document,
            &request,
            ExtendedKind::Archive141,
            assessment,
            &inputs,
            work,
        )
        .map_err(|error| format!("{name} request: {error}"))?;
        if action == format!("{}-request", query.trim_end_matches(".tsq")) {
            return write(query, pending.request());
        }
        complete_timestamp(document, &pending, &read(response)?, &completion, work)
            .map_err(|error| format!("{name}: {error}"))?;
        save(archived, document)?;
    }
    Ok(())
}
