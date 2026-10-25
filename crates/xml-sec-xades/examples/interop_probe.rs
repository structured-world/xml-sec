//! Local interoperability evidence, using only public verified-session APIs.
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};
use structured_asn1::memory::{Memory, MemoryAccount};
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, ReplayMode, ReplayOutcome, VerificationRequest,
    VerifyContext, VerifyResult, XPathHereSemantics, with_verified_request,
};
use xml_sec::{XmlDocument, policy::VerificationPolicy};
use xml_sec_xades::validate_basic;

/// Chain-validating policy at a fixed instant with the requested `here()` mode.
fn verification_policy(here: &str) -> Result<VerificationPolicy, Box<dyn std::error::Error>> {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time =
        Some(SystemTime::UNIX_EPOCH + Duration::from_hours(500_000));
    policy.transforms.xpath_here_semantics = match here {
        "spec" => XPathHereSemantics::Specification,
        "legacy" => XPathHereSemantics::XmlSecLegacy,
        _ => return Err("here mode must be spec or legacy".into()),
    };
    Ok(policy)
}

/// Record one signature's status and references and write its pre-digest bytes.
fn report_signature(report: &mut String, output: &Path, ordinal: usize, result: &VerifyResult) {
    write!(
        report,
        "signature.{ordinal}.status={:?}\nkey_trust={:?}\n",
        result.status, result.key_trust
    )
    .expect("String write");
    if let Some(bytes) = &result.canonicalized_signed_info {
        fs::write(output.join(format!("signature-{ordinal}.bin")), bytes).unwrap();
    }
    for (index, reference) in result.signed_info_references.iter().enumerate() {
        write!(
            report,
            "reference.{index}.status={:?}\nreference.{index}.coverage={:?}\n",
            reference.status, reference.coverage
        )
        .expect("String write");
        if let Some(bytes) = &reference.pre_digest_data {
            fs::write(output.join(format!("reference-{index}.bin")), bytes).unwrap();
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err(
            "usage: interop_probe XML ROOT_DER OUTPUT spec|legacy EXPECTED_ID_OR_DASH".into(),
        );
    }
    let output = PathBuf::from(&args[3]);
    fs::create_dir_all(&output)?;
    let root = fs::read(&args[2])?;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..Default::default()
    });
    let context = VerifyContext::new()
        .policy(verification_policy(&args[4])?)
        .key_resolver(&resolver)
        .store_pre_digest(true);
    let document = XmlDocument::parse(fs::read_to_string(&args[1])?)?;
    let targets = if args[5] == "-" {
        vec![]
    } else {
        vec![
            document
                .with_view(|view| view.node_for_id(&args[5], &[]))
                .ok_or("expected ID missing or ambiguous")?,
        ]
    };
    let request = VerificationRequest {
        expected_targets: &targets,
        ..Default::default()
    };
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)));
    // Writing into a String cannot fail; each expect states that invariant.
    let mut report = format!("here={}\n", args[4]);
    let run = with_verified_request(&document, &context, &request, &work, |session| {
        write!(
            report,
            "accepted={}\nall_valid={}\n",
            session.evidence().accepted(&document)?,
            session.evidence().all_valid()
        )
        .expect("String write");
        for (ordinal, entry) in session.evidence().signatures().iter().enumerate() {
            match entry.result() {
                Err(error) => {
                    writeln!(report, "signature.{ordinal}.error={error:?}").expect("String write");
                }
                Ok(result) => report_signature(&mut report, &output, ordinal, result),
            }
            // Selection and replay remain gated by original authentication;
            // failed signatures cannot be promoted into authenticated evidence.
            match session.select_signature(entry.identity()) {
                Err(error) => writeln!(report, "replay.refused={error:?}").expect("String write"),
                Ok(selected) => {
                    let mut index = 0;
                    let catalogue = selected.visit_authenticated_references(|reference| {
                        let mut bytes = Vec::new();
                        let outcome = selected.replay_reference(
                            reference.identity,
                            ReplayMode::ReferenceOutput,
                            &mut |chunk: &[u8]| {
                                bytes.extend_from_slice(chunk);
                                Ok::<_, ()>(())
                            },
                        );
                        writeln!(report, "replay.{index}={outcome:?}").expect("String write");
                        if matches!(outcome, Ok(ReplayOutcome::Complete)) {
                            fs::write(output.join(format!("replay-{index}.bin")), bytes).unwrap();
                        }
                        index += 1;
                        Ok::<_, ()>(())
                    });
                    writeln!(report, "catalogue={catalogue:?}").expect("String write");
                    let xades =
                        validate_basic(&session, entry.identity(), &[root.as_slice()], |report| {
                            (
                                report.all_root_requirements_met(),
                                report.inputs().certificate.is_bound(),
                            )
                        });
                    writeln!(report, "xades={xades:?}").expect("String write");
                }
            }
        }
        Ok(())
    });
    write!(report, "request={run:?}\nretained_bytes={}\n", work.used()).expect("String write");
    fs::write(output.join("result.txt"), report)?;
    Ok(())
}
