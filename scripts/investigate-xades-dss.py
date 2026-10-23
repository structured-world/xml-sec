#!/usr/bin/env python3
"""Reproduce two XAdES binding discrepancies without changing either engine."""
import base64
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "interop/xades"
OUT = PACKAGE / "dss-investigation"
spec = importlib.util.spec_from_file_location("corpus", ROOT / "scripts/xades-interop.py")
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)
DS, XADES, EXC = corpus.DS, corpus.SP, corpus.EXC


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, reason):
    if not condition:
        raise SystemExit(reason)


def run(args, path):
    result = corpus.command(args, path)
    if result.returncode:
        raise SystemExit(f"command failed: inspect {path}.stderr")
    return result


def template(target, certificate_names):
    # EN 319 132-1 V1.3.1 §§4.3.1, 4.4.2, 5.2.2; no XPath/Filter2 or
    # xml:base so the binding defect is independent of transform semantics.
    # https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    certs = {name: (PACKAGE / f"fixtures/baseline/{name}.der").read_bytes()
             for name in ["signer", "intermediate", "root"]}
    refs = []
    for name in certificate_names:
        digest = bytes(32) if name == "unmatched" else hashlib.sha256(certs[name]).digest()
        refs.append(f'<x:Cert><x:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{base64.b64encode(digest).decode()}</ds:DigestValue></x:CertDigest></x:Cert>')
    keyinfo = ''.join(f'<ds:X509Certificate>{base64.b64encode(certs[n]).decode()}</ds:X509Certificate>' for n in ["signer", "intermediate"])
    target_attribute = '' if target is None else f' Target="{target}"'
    return f'''<r><Data Id="payload">x</Data><ds:Signature xmlns:ds="{DS}" Id="sig"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC}"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference Id="sig-data" URI="#payload"><ds:Transforms><ds:Transform Algorithm="{EXC}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference><ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp"><ds:Transforms><ds:Transform Algorithm="{EXC}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data>{keyinfo}</ds:X509Data></ds:KeyInfo><ds:Object><x:QualifyingProperties xmlns:x="{XADES}"{target_attribute}><x:SignedProperties Id="sp"><x:SignedSignatureProperties><x:SigningTime>2026-10-18T12:00:00Z</x:SigningTime><x:SigningCertificateV2>{''.join(refs)}</x:SigningCertificateV2></x:SignedSignatureProperties><x:SignedDataObjectProperties><x:DataObjectFormat ObjectReference="#sig-data"><x:MimeType>text/xml</x:MimeType></x:DataObjectFormat></x:SignedDataObjectProperties></x:SignedProperties></x:QualifyingProperties></ds:Object></ds:Signature></r>'''


def capture_native_octets(directory):
    """Retain oracle output bytes independently of ignored stdout captures."""
    stdout = (directory / 'libxmlsec.stdout').read_bytes()
    blocks = stdout.split(b'= REFERENCE VERIFICATION CONTEXT\n')[1:]
    require(len(blocks) == 2, f'incomplete native Reference diagnostics: {directory.name}')
    for index, block in enumerate(blocks):
        expected = corpus.debug_buffer(block, b'PreDigest')
        require(expected is not None, f'missing native Reference octets: {directory.name}/{index}')
        (directory / f'expected-reference-{index}.bin').write_bytes(expected)
    signed_info = corpus.debug_buffer(stdout, b'PreSigned')
    require(signed_info is not None, f'missing native SignedInfo: {directory.name}')
    (directory / 'expected-signedinfo.bin').write_bytes(signed_info)


def analyze_octets():
    """Independent byte checks prevent a bad signature fixture masking binding behavior."""
    evidence = []
    for case in json.loads((OUT / 'summary.json').read_text())['cases']:
        directory = OUT / case['name']
        values = ET.parse(directory / 'signed.xml').findall(f'.//{{{DS}}}SignedInfo/{{{DS}}}Reference/{{{DS}}}DigestValue')
        require(len(values) == 2, f'incomplete Reference inputs: {case["name"]}')
        row = dict(name=case['name'], references=[])
        for index, value in enumerate(values):
            expected = (directory / f'expected-reference-{index}.bin').read_bytes()
            actual = (directory / f'rust/reference-{index}.bin').read_bytes()
            result = corpus.compare(expected, actual)
            written = base64.b64decode(value.text)
            result.update(digest_value_hex=written.hex(), digest_matches=hashlib.sha256(actual).digest() == written,
                          replay=corpus.compare(actual, (directory / f'rust/replay-{index}.bin').read_bytes()))
            require(result['status'] == result['replay']['status'] == 'проверено' and result['digest_matches'],
                    f'Reference/digest/replay mismatch: {case["name"]}/{index}')
            row['references'].append(result)
        expected_si = (directory / 'expected-signedinfo.bin').read_bytes()
        row['signed_info'] = corpus.compare(expected_si, (directory / 'rust/signature-0.bin').read_bytes())
        require(row['signed_info']['status'] == 'проверено', f'SignedInfo mismatch: {case["name"]}')
        evidence.append(row)
    (OUT / 'octet-comparison.json').write_text(json.dumps(evidence, indent=2, ensure_ascii=False)+'\n')
    print(f'проверено: {len(evidence)*2} Reference pairs, digests and replay; {len(evidence)} SignedInfo pairs')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--output", type=Path, default=OUT, help="new evidence directory, or existing evidence to analyze")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--analyze", action="store_true", help="check retained native/Rust octets without rerunning engines")
    mode.add_argument("--strict-policy", action="store_true", help="reuse the existing inputs and change only DSS StructuralValidation WARN to FAIL")
    args = parser.parse_args()
    OUT = args.output.resolve()
    if args.analyze:
        analyze_octets()
        raise SystemExit(0)
    if args.strict_policy:
        cases = json.loads((OUT / 'summary.json').read_text())['cases']
        tools = ROOT / '.tools/xades-dss'
        run([tools / 'apache-maven-3.9.12/bin/mvn', '-B', '-o', '-f', PACKAGE / 'dss/pom.xml',
             f'-Dmaven.repo.local={tools / "repository"}', 'compile'], OUT / 'dss-strict-build')
        classpath = str(ROOT / 'target/xades-dss/classes') + ':' + (tools / 'classpath.txt').read_text().strip()
        summary = []
        for case in cases:
            directory = OUT / case['name']
            result = directory / 'dss-structure-fail'
            if result.exists():
                raise SystemExit(f'policy experiment already exists: {result}')
            run(['java', '-cp', classpath, 'BindingProbe', directory / 'signed.xml',
                 PACKAGE / 'fixtures/baseline/root.der', result, 'structure-fail'], directory / 'dss-structure-fail-probe')
            simple = ET.parse(result / 'simple.xml').getroot().find('{*}Signature')
            blocks = ET.parse(result / 'detailed.xml').getroot().find('.//{*}BasicBuildingBlocks[@Type="SIGNATURE"]')
            summary.append(dict(name=case['name'], indication=simple.findtext('{*}Indication'),
                subindication=simple.findtext('{*}SubIndication'),
                blocks={c.tag.split('}')[-1]: c.findtext('{*}Conclusion/{*}Indication') for c in blocks if c.find('{*}Conclusion') is not None}))
        (OUT / 'strict-policy-summary.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n')
        print(json.dumps(summary,indent=2))
        raise SystemExit(0)
    if OUT.exists():
        raise SystemExit("investigation evidence already exists; preserve or archive it before rerunning")
    OUT.mkdir(parents=True)
    cases = [
        ("control", "#sig", ["signer"], True),
        ("target-payload", "#payload", ["signer"], False),
        ("target-unresolved", "#absent", ["signer"], False),
        ("target-absent", None, ["signer"], False),
        ("cert-root", "#sig", ["root"], False),
        ("cert-intermediate", "#sig", ["intermediate"], False),
        ("cert-unmatched", "#sig", ["unmatched"], False),
        ("cert-root-then-signer", "#sig", ["root", "signer"], False),
        ("cert-signer-then-root", "#sig", ["signer", "root"], True),
    ]
    run(["cargo", "build", "-p", "xml-sec-xades", "--example", "interop_probe"], OUT / "rust-build")
    tools = ROOT / ".tools/xades-dss"
    mvn = tools / "apache-maven-3.9.12/bin/mvn"
    if not mvn.exists():
        raise SystemExit("first bootstrap the pinned oracle with scripts/xades-dss.py")
    run([mvn, "-B", "-o", "-f", PACKAGE / "dss/pom.xml", f"-Dmaven.repo.local={tools / 'repository'}",
         "compile", "dependency:build-classpath", f"-Dmdep.outputFile={tools / 'classpath.txt'}"], OUT / "dss-build")
    classpath = str(ROOT / "target/xades-dss/classes") + ':' + (tools / "classpath.txt").read_text().strip()
    summary = []
    for name, target, cert_names, expected_bb in cases:
        directory = OUT / name
        directory.mkdir()
        source, signed = directory / "template.xml", directory / "signed.xml"
        source.write_text(template(target, cert_names))
        credentials = ','.join(str(PACKAGE / ("fixtures/" + n)) for n in ["signer.key", "signer.pem", "intermediate.pem"])
        run(corpus.oracle_args("--sign", source) + ["--lax-key-search", "--privkey-pem", credentials, "--output", signed, source], directory / "sign")
        run(corpus.oracle_args("--verify", signed) + [signed], directory / "libxmlsec")
        capture_native_octets(directory)
        run([ROOT / "target/debug/examples/interop_probe", signed, PACKAGE / "fixtures/baseline/root.der", directory / "rust", "spec", "-"], directory / "rust-probe")
        run(["java", "-cp", classpath, "BindingProbe", signed, PACKAGE / "fixtures/baseline/root.der", directory / "dss"], directory / "dss-probe")
        simple = ET.parse(directory / "dss/simple.xml").getroot().find("{*}Signature")
        diag = ET.parse(directory / "dss/diagnostic.xml").getroot().find(".//{*}Signatures/{*}Signature")
        blocks = ET.parse(directory / "dss/detailed.xml").getroot().find('.//{*}BasicBuildingBlocks[@Type="SIGNATURE"]')
        rust = (directory / "rust/result.txt").read_text()
        rust_bb = 'xades=Ok(Assessed((true, true)))' in rust
        require("all_valid=true\n" in rust, f"not a valid XMLDSig fixture: {name}")
        require(rust_bb == expected_bb, f"Rust disagrees with normative case: {name}")
        row = dict(name=name, target=target, cert_references=cert_names, expected_bb=expected_bb,
                   fixture_sha256=sha(signed.read_bytes()), rust_bb=rust_bb,
                   rust_xml_dsig_status="проверено", native_xml_dsig_status="проверено",
                   rust_finding=next(line for line in rust.splitlines() if line.startswith('xades=')),
                   dss_format=simple.get('SignatureFormat'), dss_indication=simple.findtext('{*}Indication'),
                   dss_subindication=simple.findtext('{*}SubIndication'),
                   dss_structure=diag.find('{*}StructuralValidation').get('valid'),
                   dss_blocks={c.tag.split('}')[-1]: c.findtext('{*}Conclusion/{*}Indication') for c in blocks if c.find('{*}Conclusion') is not None})
        summary.append(row)
    # Target is outside SignedProperties. Exactly the same SignatureValue and
    # reference digests survive each Target-only change; no broken-crypto fixture.
    signatures = [ET.parse(OUT / n / 'signed.xml').findtext(f'.//{{{DS}}}SignatureValue') for n in ['control','target-payload','target-unresolved','target-absent']]
    require(len(set(signatures)) == 1, 'Target-only mutations changed SignatureValue')
    cert_hashes = {n: sha((PACKAGE / f'fixtures/baseline/{n}.der').read_bytes()) for n in ['signer','intermediate','root']}
    (OUT / 'summary.json').write_text(json.dumps(dict(cases=summary, certificate_sha256=cert_hashes, target_only_signature_values_identical=True),indent=2,ensure_ascii=False)+'\n')
    analyze_octets()
    print(json.dumps(summary, indent=2, ensure_ascii=False))
