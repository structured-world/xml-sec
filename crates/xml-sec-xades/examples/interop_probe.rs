//! Local interoperability evidence, using only public verified-session APIs.
use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use structured_asn1::memory::{Memory, MemoryAccount};
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, ReplayMode, ReplayOutcome, VerificationRequest,
    VerifyContext, XPathHereSemantics, with_verified_request,
};
use xml_sec::{XmlDocument, policy::VerificationPolicy};
use xml_sec_xades::validate_basic;

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
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time =
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000));
    policy.transforms.xpath_here_semantics = match args[4].as_str() {
        "spec" => XPathHereSemantics::Specification,
        "legacy" => XPathHereSemantics::XmlSecLegacy,
        _ => return Err("here mode must be spec or legacy".into()),
    };
    let context = VerifyContext::new()
        .policy(policy)
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
    let mut report = format!("here={}\n", args[4]);
    let run = with_verified_request(&document, &context, &request, &work, |session| {
        report.push_str(&format!(
            "accepted={}\nall_valid={}\n",
            session.evidence().accepted(&document)?,
            session.evidence().all_valid()
        ));
        for (ordinal, entry) in session.evidence().signatures().iter().enumerate() {
            match entry.result() {
                Err(error) => report.push_str(&format!("signature.{ordinal}.error={error:?}\n")),
                Ok(result) => {
                    report.push_str(&format!(
                        "signature.{ordinal}.status={:?}\nkey_trust={:?}\n",
                        result.status, result.key_trust
                    ));
                    if let Some(bytes) = &result.canonicalized_signed_info {
                        fs::write(output.join(format!("signature-{ordinal}.bin")), bytes).unwrap();
                    }
                    for (index, reference) in result.signed_info_references.iter().enumerate() {
                        report.push_str(&format!(
                            "reference.{index}.status={:?}\nreference.{index}.coverage={:?}\n",
                            reference.status, reference.coverage
                        ));
                        if let Some(bytes) = &reference.pre_digest_data {
                            fs::write(output.join(format!("reference-{index}.bin")), bytes)
                                .unwrap();
                        }
                    }
                }
            }
            // Selection and replay remain gated by original authentication;
            // failed signatures cannot be promoted into authenticated evidence.
            match session.select_signature(entry.identity()) {
                Err(error) => report.push_str(&format!("replay.refused={error:?}\n")),
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
                        report.push_str(&format!("replay.{index}={outcome:?}\n"));
                        if matches!(outcome, Ok(ReplayOutcome::Complete)) {
                            fs::write(output.join(format!("replay-{index}.bin")), bytes).unwrap();
                        }
                        index += 1;
                        Ok::<_, ()>(())
                    });
                    report.push_str(&format!("catalogue={catalogue:?}\n"));
                    let xades =
                        validate_basic(&session, entry.identity(), &[root.as_slice()], |report| {
                            (
                                report.all_root_requirements_met(),
                                report.inputs().certificate.is_bound(),
                            )
                        });
                    report.push_str(&format!("xades={xades:?}\n"));
                }
            }
        }
        Ok(())
    });
    report.push_str(&format!(
        "request={run:?}\nretained_bytes={}\n",
        work.used()
    ));
    fs::write(output.join("result.txt"), report)?;
    Ok(())
}
