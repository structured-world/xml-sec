#!/usr/bin/env python3
"""Generate synthetic XAdES inputs and compare local independent XMLDSig engines.

No online validators. Generation is explicit; normal runs preserve signed inputs.
All subprocess commands, streams, versions, byte comparisons and hashes are saved.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "interop" / "xades"
DS = "http://www.w3.org/2000/09/xmldsig#"
F2 = "http://www.w3.org/2002/06/xmldsig-filter2"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
C11 = "http://www.w3.org/2006/12/xml-c14n11"
SP = "http://uri.etsi.org/01903/v1.3.2#"
XMLSEC = os.environ.get("XMLSEC1_BIN", "xmlsec1")


def _capture_streams(process, stdout, stderr, timeout):
    # Persist progress before an enclosing runner can cancel this process.
    # Pipes still keep the deadline active when a descendant outlives its parent.
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, stdout)
        selector.register(process.stderr, selectors.EVENT_READ, stderr)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout)
            for key, _ in selector.select(remaining):
                # This is a read chunk, not a total output limit.
                data = os.read(key.fd, 65536)
                if data:
                    key.data.write(data)
                    key.data.flush()
                else:
                    selector.unregister(key.fileobj)
    process.wait(timeout=max(0, deadline - time.monotonic()))


def command(args, log, env=None, *, timeout=900):
    arguments = [str(x) for x in args]
    log.parent.mkdir(parents=True, exist_ok=True)
    log.with_suffix(".command.json").write_text(json.dumps(arguments, indent=2))
    session = os.getsid(0)
    parent_session = os.environ.get("_XADES_INTEROP_PARENT_SESSION")
    shared_group = (parent_session is not None and parent_session != str(session)
                    and os.getpgrp() == session)
    child_env = dict(os.environ if env is None else env)
    if not shared_group:
        child_env["_XADES_INTEROP_PARENT_SESSION"] = str(session)
    else:
        child_env["_XADES_INTEROP_PARENT_SESSION"] = parent_session
    # setsid isolates the outer command from its controller. Nested wrappers
    # inherit that group: detaching again would escape the outer timeout.
    # https://docs.python.org/3/library/subprocess.html#popen-constructor
    with (log.with_suffix(".stdout").open("wb") as stdout_log,
          log.with_suffix(".stderr").open("wb") as stderr_log,
          subprocess.Popen(arguments, cwd=ROOT, env=child_env,
                           start_new_session=not shared_group,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process):
        group = os.getpgrp() if shared_group else process.pid

        def terminate_group():
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The group already exited before cancellation.

        try:
            _capture_streams(process, stdout_log, stderr_log, timeout)
        except subprocess.TimeoutExpired as error:
            message = (f"command timed out after {timeout}s; inspect {log}.command.json, "
                       f"{log}.stdout and {log}.stderr")
            try:
                if shared_group:
                    print(message, file=sys.stderr, flush=True)
            finally:
                terminate_group()
            stdout, stderr = process.communicate()
            stdout_log.write(stdout)
            stderr_log.write(stderr)
            raise SystemExit(message) from error
        except BaseException:
            # In particular, do not leave the isolated group behind on Ctrl-C.
            terminate_group()
            process.communicate()
            raise
    return subprocess.CompletedProcess(arguments, process.returncode,
        log.with_suffix(".stdout").read_bytes(), log.with_suffix(".stderr").read_bytes())


def build_probe(log):
    build = command(["cargo", "build", "-p", "xml-sec-xades", "--example", "interop_probe",
                     "--message-format=json-render-diagnostics"], log)
    if build.returncode:
        raise SystemExit(f"probe build failed; inspect {log}.stderr")
    # Cargo reports the executable for this build, including cache hits and
    # CARGO_TARGET_DIR; inferring target/debug can select an older executable.
    # https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages
    binary = None
    for line in build.stdout.splitlines():
        if not line.startswith(b"{"):
            continue  # build scripts may also write ordinary diagnostic lines
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact":
            continue
        if (message["target"]["name"] != "interop_probe"
                or "example" not in message["target"]["kind"] or message["executable"] is None):
            continue
        if binary is not None:
            raise SystemExit(f"probe build must report exactly one example executable; inspect {log}.stdout")
        binary = Path(message["executable"])
    if binary is None:
        raise SystemExit(f"probe build must report exactly one example executable; inspect {log}.stdout")
    return binary


def oracle_args(action, fixture):
    args = [XMLSEC, action, "--enabled-reference-uris", "empty,same-doc",
            "--enabled-retrieval-method-uris", "empty,same-doc",
            "--enabled-key-info-reference-uris", "empty,same-doc",
            "--id-attr:Id", f"{DS}:Signature",
            "--id-attr:Id", f"{SP}:SignedProperties", "--id-attr:Id", "Data",
            "--id-attr:Id", "Outside"]
    if action == "--verify":
        args += ["--trusted-der", PACKAGE / "fixtures/baseline/root.der",
                 "--verification-gmt-time", "2027-01-15 08:00:00",
                 "--store-references", "--store-signatures", "--print-debug", "--verbose"]
    return args


def generate():
    fixtures = PACKAGE / "fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xades-interop-") as directory:
        work = Path(directory)
        env = dict(os.environ, XADES_FIXTURE_WORK=directory,
                   XADES_FIXTURE_OUTPUT=str(fixtures / "baseline"), XMLSEC1_BIN=XMLSEC)
        if (fixtures / "enveloped-control.template.xml").exists():
            template = (fixtures / "enveloped-control.template.xml").read_text()
        else:
            run = command(["bash", ROOT / "scripts/generate-xades-fixtures.sh"],
                          PACKAGE / "generation/baseline", env)
            if run.returncode:
                raise SystemExit("baseline generator failed; inspect generation/baseline.stderr")
            for name in ["signer.key", "signer.pem", "intermediate.pem"]:
                shutil.copyfile(work / name, fixtures / name)
            template = (work / "enveloped.template.xml").read_text()
        payload = ('<Document xmlns:q="urn:test:attributes" xml:id="document" '
                   'xml:base="https://example.invalid/a/" xml:lang="en">'
                   '<Box xml:id="box" xml:base="b/"><Data Id="payload" xml:id="business" '
                   'b="2" a="1" q:flag="yes">Synthetic invoice 123<!--covered comment-->'
                   '<Keep>signed</Keep><Excluded>mutable</Excluded></Data></Box>'
                   '<Outside Id="wrong">unrelated object</Outside>')
        template = template.replace('<Document><Data Id="payload">Enveloped baseline payload</Data>', payload)
        enveloped = f'<ds:Transform Algorithm="{DS}enveloped-signature"/>'

        def filters(operations):
            return f'<ds:Transform Algorithm="{F2}">' + ''.join(
                f'<f:XPath xmlns:f="{F2}" Filter="{op}">{expr}</f:XPath>'
                for op, expr in operations) + '</ds:Transform>'

        subtract = filters([("subtract", "/descendant::ds:Signature")])
        sequence = [("intersect", "/Document/Box/Data"),
                    ("subtract", "/Document/Box/Data/Excluded"),
                    ("union", "/Document/Outside")]
        variants = {
            "enveloped-control": (enveloped, EXC, EXC, False),
            "id-reference": (enveloped, EXC, EXC, False),
            "wrong-properties-type": (enveloped, EXC, EXC, False),
            "filter2-subtract": (subtract, EXC, EXC, False),
            "filter2-sequence": (filters(sequence), EXC, EXC, False),
            "filter2-restored": (filters(sequence + [("union", "/Document/Box/Data/Excluded")]), EXC, EXC, False),
            "c14n11-reference": (filters([("intersect", "/Document/Box/Data")]), C11, EXC, False),
            "c14n11-signedinfo": (subtract, EXC, C11, False),
            "c14n11-comments": (filters([("intersect", "/Document/Box/Data")]), C11 + "#WithComments", C11, True),
            "empty-result": (filters([("intersect", "/no-such-element")]), EXC, EXC, False),
            "axis-subset": (filters([("intersect", "/Document/Box/Data/@b | /Document/Box/Data/namespace::q")]), EXC, EXC, False),
            "here-legacy": (f'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Signature) and count(here()/ds:XPath) = 1</ds:XPath></ds:Transform>', EXC, EXC, False),
        }
        manifest = []
        for name, (transform, ref_c14n, si_c14n, comments) in variants.items():
            xml = template.replace(enveloped, transform, 1)
            xml = xml.replace(f'<ds:CanonicalizationMethod Algorithm="{EXC}"/>',
                              f'<ds:CanonicalizationMethod Algorithm="{si_c14n}"/>', 1)
            xml = xml.replace(f'{transform}\n        <ds:Transform Algorithm="{EXC}"/>',
                              f'{transform}\n        <ds:Transform Algorithm="{ref_c14n}"/>', 1)
            if comments:
                xml = xml.replace('Id="sig-data" URI=""', 'Id="sig-data" URI="#xpointer(/)"', 1)
            if name == "id-reference":
                xml = xml.replace('Id="sig-data" URI=""', 'Id="sig-data" URI="#payload"', 1)
            if name == "wrong-properties-type":
                xml = xml.replace('Type="http://uri.etsi.org/01903#SignedProperties"', 'Type="urn:test:wrong-properties"', 1)
            source = fixtures / f"{name}.template.xml"
            source.write_text(xml)
            target = fixtures / f"{name}.xml"
            args = oracle_args("--sign", source) + ["--lax-key-search", "--privkey-pem",
                    f'{fixtures / "signer.key"},{fixtures / "signer.pem"},{fixtures / "intermediate.pem"}',
                    "--output", target, source]
            result = command(args, PACKAGE / "generation" / name)
            if result.returncode:
                raise SystemExit(f"independent signing failed: {name}")
            manifest.append(dict(name=name, file=str(target.relative_to(PACKAGE)), valid=True))

        def mutation(name, original, before, after, valid):
            xml = (fixtures / f"{original}.xml").read_text()
            if before not in xml:
                raise ValueError(f"mutation did not match: {name}")
            (fixtures / f"{name}.xml").write_text(xml.replace(before, after, 1))
            manifest.append(dict(name=name, file=f"fixtures/{name}.xml", valid=valid))

        mutation("tampered-content", "filter2-subtract", "Synthetic invoice 123", "Synthetic invoice 999", False)
        mutation("excluded-signature-object", "filter2-subtract", "</ds:Signature>",
                 "<ds:Object>unsigned note</ds:Object></ds:Signature>", True)
        mutation("excluded-subtree", "filter2-sequence", ">mutable<", ">changed<", True)
        mutation("comment-omitted", "filter2-subtract", "covered comment", "changed comment", True)
        mutation("comment-covered", "c14n11-comments", "covered comment", "changed comment", False)
        mutation("attribute-covered", "c14n11-reference", 'q:flag="yes"', 'q:flag="no"', False)
        mutation("namespace-covered", "c14n11-reference", 'urn:test:attributes', 'urn:test:changed', False)
        mutation("xmlbase-covered", "c14n11-reference", 'xml:base="b/"', 'xml:base="changed/"', False)
        mutation("xmlid-covered", "c14n11-reference", 'xml:id="business"', 'xml:id="changed"', False)
        signed = (fixtures / "filter2-subtract.xml").read_text()
        certificate = re.search(r'<ds:X509Certificate>([^<]+)', signed).group(1)
        substituted = base64.b64encode((fixtures / "baseline/root.der").read_bytes()).decode()
        (fixtures / "keyinfo-certificate-substituted.xml").write_text(signed.replace(certificate, substituted, 1))
        manifest.append(dict(name="keyinfo-certificate-substituted", file="fixtures/keyinfo-certificate-substituted.xml", valid=False))
        mutation("union-tampered", "filter2-sequence", ">unrelated object<", ">changed<", False)
        mutation("unknown-algorithm", "filter2-subtract", F2 + '"', 'urn:test:unsupported"', False)
        mutation("malformed-xpath", "filter2-subtract", "/descendant::ds:Signature", "[", False)
        mutation("external-http", "filter2-subtract", 'Id="sig-data" URI=""',
                 'Id="sig-data" URI="https://example.invalid/never-fetch"', False)
        mutation("external-file", "filter2-subtract", 'Id="sig-data" URI=""',
                 'Id="sig-data" URI="file:///never-read"', False)
        mutation("duplicate-id", "id-reference", '<Outside Id="wrong">', '<Outside Id="payload">', False)
        signed = (fixtures / "filter2-subtract.xml").read_text()
        value = re.search(r'<ds:SignatureValue[^>]*>([^<]+)', signed).group(1)
        changed = ("B" if value[0] == "A" else "A") + value[1:]
        (fixtures / "signature-value-tampered.xml").write_text(signed.replace(value, changed, 1))
        manifest.append(dict(name="signature-value-tampered", file="fixtures/signature-value-tampered.xml", valid=False))
        # XMLDSig 1.1 §8.1.1: valid crypto covers transformed data, not a
        # same-name replacement chosen by the application. Preserve the original
        # signed Data, but put another Data in its business position.
        signed = (fixtures / "id-reference.xml").read_text()
        data = re.search(r'<Data Id="payload".*?</Data>', signed).group()
        wrapped = signed.replace(data, '<Data Id="replacement">attacker invoice</Data><Wrapper>' + data + '</Wrapper>', 1)
        (fixtures / "wrapped-object.xml").write_text(wrapped)
        manifest.append(dict(name="wrapped-object", file="fixtures/wrapped-object.xml", valid=True))
        for name in ["enveloped", "wrong-target", "untyped-signed-properties", "certificate-digest-mismatch"]:
            manifest.append(dict(name="baseline-" + name, file=f"fixtures/baseline/{name}.xml", valid=True))
        (PACKAGE / "cases.json").write_text(json.dumps(manifest, indent=2) + "\n")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def resolved_versions(metadata):
    """Keep dependency versions/features without Cargo's absolute package IDs."""
    nodes = {node["id"]: node["features"] for node in metadata["resolve"]["nodes"]}
    return sorted([dict(name=package["name"], version=package["version"], features=nodes[package["id"]])
                   for package in metadata["packages"]], key=lambda item: (item["name"], item["version"]))


def debug_buffer(block, kind):
    """libxmlsec1 1.3.12 DebugHexDump, not a text XML serialization.

    xmlSecDSigReferenceCtxDebugDump omits a zero-allocation empty buffer.
    The caller must independently require a successful SHA-256(empty) check
    before interpreting an absent Reference buffer as empty.
    https://github.com/lsh123/xmlsec/blob/1.3.12/src/xmldsig.c
    """
    match = re.search(rb"== " + kind + rb" data - start buffer:\n(.*?)\n== " + kind + rb" data - end buffer", block, re.S)
    if match is None:
        return None
    return bytes.fromhex(match[1].decode("ascii"))


def compare(expected, actual):
    first = next((i for i, (a, b) in enumerate(zip(expected, actual)) if a != b), None)
    if first is None and len(expected) != len(actual):
        first = min(len(expected), len(actual))
    return dict(status="проверено" if first is None else "не прошло", first_different_byte=first,
                expected_length=len(expected), actual_length=len(actual),
                expected_sha256=digest(expected), actual_sha256=digest(actual),
                expected_context_hex=None if first is None else expected[max(0, first-24):first+25].hex(),
                actual_context_hex=None if first is None else actual[max(0, first-24):first+25].hex())


def run_all(results):
    if results.exists():
        raise SystemExit("results already exist; archive them or choose a fresh checkout before rerunning")
    results.mkdir(parents=True)
    oracle = command([XMLSEC, "--version"], results / "versions/xmlsec1")
    if oracle.returncode:
        raise SystemExit("oracle version query failed; inspect versions/xmlsec1.stderr")
    oracle_version = oracle.stdout.decode().strip()
    if oracle_version not in {"xmlsec1 1.3.12 (openssl)", "xmlsec1 1.3.13 (openssl)"}:
        raise SystemExit(f"byte-dump parser requires qualified native xmlsec1 1.3.12/1.3.13 (openssl), got: {oracle_version}")
    commit = command(["git", "rev-parse", "HEAD"], results / "versions/commit")
    if commit.returncode:
        raise SystemExit("commit query failed; inspect versions/commit.stderr")
    versions = {"commit": commit.stdout.decode().strip(), "xmlsec1": (oracle.stdout + oracle.stderr).decode()}
    executable = Path(shutil.which(XMLSEC)).resolve()
    versions["oracle_binary"] = dict(name=executable.name, sha256=digest(executable.read_bytes()))
    for name, args in {"rustc": ["rustc", "-Vv"], "cargo": ["cargo", "-V"],
                       "openssl": ["openssl", "version"],
                       "python": ["python3", "--version"]}.items():
        result = command(args, results / "versions" / name)
        versions[name] = (result.stdout + result.stderr).decode()
    if os.uname().sysname == "Darwin":
        command(["otool", "-L", executable], results / "versions/oracle-linkage")
    elif os.uname().sysname == "Linux":
        command(["ldd", executable], results / "versions/oracle-linkage")
    command(["cargo", "tree", "-p", "xml-sec-xades", "-e", "features"], results / "versions/features")
    metadata = command(["cargo", "metadata", "--format-version", "1"], results / "versions/metadata")
    if metadata.returncode:
        raise SystemExit("cargo metadata failed")
    versions["resolved_dependencies"] = resolved_versions(json.loads(metadata.stdout))
    binary = build_probe(results / "build")
    summary = []
    for case in json.loads((PACKAGE / "cases.json").read_text()):
        name = case["name"]
        fixture = PACKAGE / case["file"]
        folder = results / name
        folder.mkdir()
        oracle = command(oracle_args("--verify", fixture) + [fixture], folder / "oracle")
        # xmlsec1 --store-* wraps exact bytes in diagnostic markers. Remove
        # exactly its one framing LF, never strip canonical XML whitespace.
        stdout = oracle.stdout
        values = ET.parse(fixture).findall(f'.//{{{DS}}}SignedInfo/{{{DS}}}Reference/{{{DS}}}DigestValue')
        blocks = stdout.split(b"= REFERENCE VERIFICATION CONTEXT\n")[1:]
        references = []
        for index, block in enumerate(blocks):
            data = debug_buffer(block, b"PreDigest")
            if data is None:
                if (oracle.returncode == 0 and b"== Status: OK\n" in block
                        and base64.b64decode(values[index].text) == hashlib.sha256(b"").digest()):
                    data = b""
                else:
                    break  # fail-fast processing never produced these bytes
            references.append(data)
        si_bytes = debug_buffer(stdout, b"PreSigned")
        signed_info = [] if si_bytes is None else [si_bytes]
        if oracle.returncode == 0 and (len(references) != 2 or len(signed_info) != 1):
            raise SystemExit(f"oracle byte extraction incomplete: {name}; inspect raw diagnostics")
        for index, data in enumerate(references):
            (folder / f"expected-reference-{index}.bin").write_bytes(data)
        if signed_info:
            (folder / "expected-signedinfo.bin").write_bytes(signed_info[0])
        row = dict(name=name, fixture_sha256=digest(fixture.read_bytes()),
                   expected_xml_dsig_valid=case["valid"], oracle_exit=oracle.returncode,
                   oracle_status="проверено" if (oracle.returncode == 0) == case["valid"] else "не прошло", modes={})
        for mode in ["spec", "legacy"]:
            out = folder / mode
            probe = command([binary, fixture, PACKAGE / "fixtures/baseline/root.der", out, mode, "-"], folder / f"probe-{mode}")
            if probe.returncode:
                raise SystemExit(f"probe crashed: {name}/{mode}")
            text = (out / "result.txt").read_text()
            actual_valid = "all_valid=true\n" in text
            # The here fixture was signed under the independent engine's
            # documented legacy interpretation; no automatic mode retry.
            expected_valid = case["valid"] and not (name == "here-legacy" and mode == "spec")
            facts = dict(xml_dsig="проверено" if actual_valid == expected_valid else "не прошло", actual_valid=actual_valid,
                         expected_valid=expected_valid, references=[], signed_info={"status": "не запускалось или заблокировано"},
                         diagnostics=[line for line in text.splitlines() if ".error=" in line or ".status=" in line or line.startswith("replay.refused=")])
            for index, expected in enumerate(references):
                actual_path = out / f"reference-{index}.bin"
                if not actual_path.exists():
                    facts["references"].append(dict(status="не запускалось или заблокировано", reason="fail-fast or processing error"))
                    continue
                actual = actual_path.read_bytes()
                result = compare(expected, actual)
                written = base64.b64decode(values[index].text)
                result.update(digest_value_hex=written.hex(), oracle_digest_hex=digest(expected), rust_digest_hex=digest(actual),
                              digest_matches=(hashlib.sha256(actual).digest() == written))
                replay = out / f"replay-{index}.bin"
                result["replay"] = compare(actual, replay.read_bytes()) if replay.exists() else {"status": "не запускалось или заблокировано", "reason": "signature not authenticated"}
                facts["references"].append(result)
            si = out / "signature-0.bin"
            if signed_info and si.exists():
                facts["signed_info"] = compare(signed_info[0], si.read_bytes())
            facts["xades"] = next((line[6:] for line in text.splitlines() if line.startswith("xades=")), "не запускалось или заблокировано")
            xades = facts["xades"]
            # EN 319 132-1 V1.3.1 §§4.3.1 (Target), 4.4.2 (Type),
            # 5.2.2 (first certificate reference identifies the signer).
            # These expectations are normative, not copied from DSS labels:
            # https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
            if not expected_valid:
                xades_ok = xades == "не запускалось или заблокировано"
            elif name == "baseline-wrong-target":
                xades_ok = "Binding(Target" in xades
            elif name in ["baseline-untyped-signed-properties", "wrong-properties-type"]:
                xades_ok = "Binding(Missing" in xades
            elif name == "baseline-certificate-digest-mismatch":
                xades_ok = xades == "Ok(Assessed((false, false)))"
            else:
                xades_ok = xades == "Ok(Assessed((true, true)))"
            facts["xades_expected_outcome"] = "проверено" if xades_ok else "не прошло"
            failures_by_level = {
                "unknown-algorithm": "ParseSignedInfo(Transform(UnsupportedTransform(",
                "malformed-xpath": "ParseSignedInfo(Transform(XPath(",
                "external-http": "Policy(Uri {", "external-file": "Policy(Uri {",
                "duplicate-id": 'Reference(UriDereference(ElementNotFound("payload")))',
                "keyinfo-certificate-substituted": "KeyResolution(",
                "signature-value-tampered": "Invalid(SignatureMismatch)",
            }
            if not expected_valid:
                marker = failures_by_level.get(name, "Invalid(ReferenceDigestMismatch {")
                facts["failure_level_status"] = "проверено" if any(marker in line for line in facts["diagnostics"]) else "не прошло"
            # A valid result requires every byte artifact and replay. In
            # particular a missing artifact must never be counted as a pass.
            facts["complete_valid_evidence"] = not expected_valid or (
                len(facts["references"]) == 2 and facts["signed_info"]["status"] == "проверено"
                and all(ref["status"] == "проверено" and ref["digest_matches"]
                        and ref["replay"]["status"] == "проверено" for ref in facts["references"]))
            row["modes"][mode] = facts
        # Explicit application-target requirements use identities from this
        # same immutable document. Arbitrary Filter2 coverage stays conservative.
        if name in ["enveloped-control", "filter2-subtract", "empty-result", "filter2-sequence", "id-reference", "wrapped-object"]:
            for target in (["payload", "replacement"] if name == "wrapped-object" else ["payload", "wrong"]):
                probe = command([binary, fixture, PACKAGE / "fixtures/baseline/root.der", folder / f"expected-{target}", "spec", target], folder / f"target-{target}")
                if probe.returncode:
                    raise SystemExit(f"target probe crashed: {name}/{target}")
                actual = "accepted=true\n" in (folder / f"expected-{target}/result.txt").read_text()
                expected = name == "enveloped-control" or (name in ["id-reference", "wrapped-object"] and target == "payload")
                row.setdefault("expected_targets", {})[target] = dict(actual_accepted=actual, expected_accepted=expected,
                    status="проверено" if actual == expected else "не прошло")
        summary.append(row)
    (results / "versions.json").write_text(json.dumps(versions, indent=2) + "\n")
    (results / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    failures = [r["name"] + "/" + mode for r in summary for mode, fact in r["modes"].items()
                if fact["xml_dsig"] == "не прошло" or fact["signed_info"]["status"] == "не прошло"
                or fact["xades_expected_outcome"] == "не прошло" or r["oracle_status"] == "не прошло"
                or fact.get("failure_level_status") == "не прошло"
                or not fact["complete_valid_evidence"]
                or (any(ref["status"] == "не прошло" for ref in fact["references"])
                    and not (r["name"] == "here-legacy" and mode == "spec"))
                or any(t["status"] == "не прошло" for t in r.get("expected_targets", {}).values())]
    print(json.dumps(dict(cases=len(summary), unexpected_failures=failures), ensure_ascii=False))
    return bool(failures)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--generate", action="store_true", help="create new test credentials and signed inputs")
    parser.add_argument("--results", type=Path, default=ROOT / "target/xades-interop-results", help="new run directory; existing evidence is never overwritten")
    args = parser.parse_args()
    if args.generate:
        generate()
    else:
        raise SystemExit(run_all(args.results.resolve()))
