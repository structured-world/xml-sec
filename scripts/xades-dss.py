#!/usr/bin/env python3
"""Build a pinned local EU DSS probe and retain independent profile reports.

Maven downloads public dependencies. Validation processes only local corpus
inputs; no fixture is uploaded. Build dependencies stay outside the corpus.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("corpus", ROOT / "scripts/xades-interop.py")
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)
PACKAGE = ROOT / "interop/xades"
TOOLS = ROOT / ".tools/xades-dss"
MAVEN = "3.9.12"
CASES = ["enveloped-control", "filter2-subtract", "filter2-sequence", "c14n11-reference",
         "c14n11-signedinfo", "empty-result", "baseline-wrong-target",
         "baseline-untyped-signed-properties", "baseline-certificate-digest-mismatch"]


def profile_binding(name, row):
    # EN 319 102-1 V1.4.1 §§5.2.2, 5.2.3.4: base-format FC does not
    # attest XAdES profile conformance; ISC must match the actual signer.
    # https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf
    if name == "baseline-wrong-target":
        return dict(status="не запускалось или заблокировано",
                    reason="FC and format labels do not attest Target binding; see dss-investigation")
    if name == "baseline-certificate-digest-mismatch":
        expected_refusal = (row["conclusions"].get("ISC") == "INDETERMINATE"
                            and row["subindications"].get("ISC") == "NO_SIGNING_CERTIFICATE_FOUND")
        return dict(status="проверено" if expected_refusal else "не прошло",
                    reason="root-only CertDigest must not identify the leaf signing certificate")
    if name == "baseline-untyped-signed-properties":
        return dict(status="проверено" if row["reported_format"] == "XAdES-BES" else "не прошло",
                    reason="format classification only; not full profile validation")
    return None


def summarize(logs):
    summary = []
    for name in CASES:
        simple = ET.parse(logs / name / "simple.xml").getroot().find("{*}Signature")
        signature = ET.parse(logs / name / "diagnostic.xml").getroot().find(".//{*}Signatures/{*}Signature")
        blocks = ET.parse(logs / name / "detailed.xml").getroot().find('.//{*}BasicBuildingBlocks[@Type="SIGNATURE"]')
        row = dict(name=name, reported_format=simple.get("SignatureFormat"),
                   indication=simple.findtext("{*}Indication"), subindication=simple.findtext("{*}SubIndication"),
                   signature_intact=signature.findtext("{*}BasicSignature/{*}SignatureIntact"),
                   digest_matchers=[dict(uri=m.get("uri"), found=m.findtext("{*}DataFound"), intact=m.findtext("{*}DataIntact"))
                                    for m in signature.findall("{*}DigestMatchers/{*}DigestMatcher")],
                   conclusions={c.tag.split("}")[-1]: c.findtext("{*}Conclusion/{*}Indication")
                                for c in blocks if c.find("{*}Conclusion") is not None},
                   subindications={c.tag.split("}")[-1]: c.findtext("{*}Conclusion/{*}SubIndication")
                                   for c in blocks if c.find("{*}Conclusion") is not None})
        row["crypto_status"] = "проверено" if row["signature_intact"] == "true" and len(row["digest_matchers"]) == 2 and all(m["intact"] == "true" for m in row["digest_matchers"]) else "не прошло"
        observation = profile_binding(name, row)
        if observation is not None:
            row["profile_binding"] = observation
        summary.append(row)
    (logs / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    return summary


def run(args, log):
    result = corpus.command(args, log)
    if result.returncode:
        raise SystemExit(f"failed ({result.returncode}): inspect {log}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--results", type=Path, default=ROOT / "target/xades-dss-results")
    parser.add_argument("--summarize", action="store_true", help="reanalyze existing reports without running DSS")
    options = parser.parse_args()
    logs = options.results.resolve()
    if options.summarize:
        summarize(logs)
        raise SystemExit(0)
    if logs.exists():
        raise SystemExit("results already exist; select a fresh --results directory")
    TOOLS.mkdir(parents=True, exist_ok=True)
    mvn = TOOLS / f"apache-maven-{MAVEN}/bin/mvn"
    logs.mkdir(parents=True)
    if not mvn.exists():
        archive = TOOLS / "maven.tar.gz"
        url = f"https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/{MAVEN}/apache-maven-{MAVEN}-bin.tar.gz"
        run(["curl", "--fail", "--silent", "--show-error", "--output", archive, url], logs / "download")
        expected = run(["curl", "--fail", "--silent", "--show-error", url + ".sha512"], logs / "download-sha512").stdout.decode().split()[0]
        if hashlib.sha512(archive.read_bytes()).hexdigest() != expected:
            raise SystemExit("Maven distribution SHA-512 mismatch")
        with tarfile.open(archive) as bundle:
            bundle.extractall(TOOLS, filter="data")
    pom = PACKAGE / "dss/pom.xml"
    # Keep build output under target so the repository's cargo clean removes it.
    target = ROOT / "target/xades-dss"
    args = [mvn, "-B", "-f", pom, f"-Dmaven.repo.local={TOOLS / 'repository'}"]
    run(args + ["compile", "dependency:build-classpath", f"-Dmdep.outputFile={TOOLS / 'classpath.txt'}"], logs / "build")
    run([mvn, "-v"], logs / "versions")
    run(args + ["dependency:tree", "-DoutputType=json", f"-DoutputFile={logs / 'dependencies.json'}"], logs / "dependencies")
    # Never feed the deliberately external-URI fixtures to another validator.
    manifest = {case["name"]: case for case in json.loads((PACKAGE / "cases.json").read_text())}
    classpath = str(target / "classes") + ":" + (TOOLS / "classpath.txt").read_text().strip()
    for name in CASES:
        run(["java", "-cp", classpath, "Probe", PACKAGE / manifest[name]["file"],
             PACKAGE / "fixtures/baseline/root.der", logs / name], logs / (name + "-run"))
    summary = summarize(logs)
    if any(row["crypto_status"] != "проверено" for row in summary):
        raise SystemExit("DSS cryptographic control failed; inspect retained reports")
    print(f"EU DSS 6.5.1: {len(CASES)} local profile reports saved to {logs}")
