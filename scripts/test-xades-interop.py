#!/usr/bin/env python3
"""Guard the evidence parser against false positive interoperability reports."""
import importlib.util
import base64
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("interop", Path(__file__).with_name("xades-interop.py"))
interop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interop)
spec_dss = importlib.util.spec_from_file_location("dss", Path(__file__).with_name("xades-dss.py"))
dss = importlib.util.module_from_spec(spec_dss)
spec_dss.loader.exec_module(dss)
spec_package = importlib.util.spec_from_file_location("package", Path(__file__).with_name("package-xades-interop.py"))
package = importlib.util.module_from_spec(spec_package)
spec_package.loader.exec_module(package)
spec_binding = importlib.util.spec_from_file_location("binding", Path(__file__).with_name("investigate-xades-dss.py"))
binding = importlib.util.module_from_spec(spec_binding)
spec_binding.loader.exec_module(binding)
spec_check = importlib.util.spec_from_file_location("check", Path(__file__).with_name("check-xades-interop.py"))
check = importlib.util.module_from_spec(spec_check)
spec_check.loader.exec_module(check)


class EvidenceTests(unittest.TestCase):
    def run_isolated_command(self, arguments, log, timeout=2):
        # Give the test controller its own scope even inside the CI runner.
        environment = dict(os.environ)
        environment.pop('_XADES_INTEROP_PARENT_SESSION', None)
        driver = ("import json,runpy,sys; from pathlib import Path; "
                  "result=runpy.run_path(sys.argv[1])['command'](json.loads(sys.argv[2]), "
                  "Path(sys.argv[3]), timeout=float(sys.argv[4])); "
                  "sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr); "
                  "sys.exit(result.returncode)")
        return subprocess.run([sys.executable, '-c', driver,
            str(Path(__file__).with_name('xades-interop.py').resolve()),
            json.dumps([str(a) for a in arguments]), str(log), str(timeout)],
            env=environment, capture_output=True, timeout=timeout + 10, start_new_session=True)

    def test_timeout_terminates_descendants_across_nested_wrappers(self):
        # A descendant holds a lock until it exits: unlike kill(pid, 0), this
        # does not mistake a killed but not-yet-reaped process for a live one.
        # The stop file cleans up the deliberately failing pre-fix reproduction.
        child = ("import fcntl,sys,time; from pathlib import Path; "
                 "lock=open(sys.argv[1], 'w'); fcntl.flock(lock, fcntl.LOCK_EX); "
                 "Path(sys.argv[2]).write_text('ready'); deadline=time.monotonic()+20\n"
                 "while not Path(sys.argv[3]).exists() and time.monotonic()<deadline: time.sleep(.01)\n")
        parent = ("import subprocess,sys,time; from pathlib import Path; "
                  "process=subprocess.Popen([sys.executable, '-c', sys.argv[1], *sys.argv[2:]])\n"
                  "while not Path(sys.argv[3]).exists(): time.sleep(.01)\n"
                  "print('ready', flush=True); print('waiting', file=sys.stderr, flush=True); process.wait()\n")
        with tempfile.TemporaryDirectory() as directory:
            for owner, inner_timeout, timeout in [
                    ('direct', None, 2), ('exited-parent', None, 2), ('outer', 30, 2), ('inner', 2, 5)]:
                with self.subTest(timeout_owner=owner):
                    output = Path(directory) / owner
                    output.mkdir()
                    lock, ready, stop = [output / name for name in ['lock', 'ready', 'stop']]
                    arguments = [sys.executable, '-c', parent, child, lock, ready, stop]
                    if owner == 'exited-parent':
                        # An exited parent does not end the descendant's output
                        # lifetime or release its held lock.
                        arguments[2] = parent.removesuffix('process.wait()\n')
                    if inner_timeout is not None:
                        wrapper = ("import json,runpy,sys; from pathlib import Path; "
                                   "runpy.run_path(sys.argv[1])['command'](json.loads(sys.argv[2]), "
                                   "Path(sys.argv[3]), timeout=float(sys.argv[4]))")
                        arguments = [sys.executable, '-c', wrapper,
                            Path(__file__).with_name('xades-interop.py').resolve(),
                            json.dumps([str(a) for a in arguments]), output / 'inner', inner_timeout]
                    try:
                        result = self.run_isolated_command(arguments, output / 'outer', timeout)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(b'timed out', result.stderr)
                        self.assertTrue(ready.exists(), 'descendant did not reach the reproduction')
                        if inner_timeout is not None:
                            self.assertEqual((output / 'inner.stdout').read_bytes(), b'ready\n')
                            self.assertEqual((output / 'inner.stderr').read_bytes(), b'waiting\n')
                        with lock.open() as held:
                            try:
                                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            except BlockingIOError:
                                self.fail('descendant survived command timeout')
                    finally:
                        stop.touch()
                        if ready.exists():
                            with lock.open() as held:
                                deadline = time.monotonic() + 5
                                while True:
                                    try:
                                        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                        break
                                    except BlockingIOError:
                                        if time.monotonic() >= deadline:
                                            raise RuntimeError('synthetic descendant did not stop')
                                        time.sleep(.01)

    def test_corpus_uses_cargo_reported_probe_instead_of_stale_default(self):
        # CARGO_TARGET_DIR must select the just-built probe even when the
        # default target directory contains an older executable.
        class Probed(Exception):
            pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / 'interop/xades'
            (assets / 'fixtures').mkdir(parents=True)
            (assets / 'fixtures/case.xml').write_text(f'<Signature xmlns="{interop.DS}"><SignedInfo/></Signature>')
            (assets / 'cases.json').write_text(json.dumps([
                dict(name='tampered-content', file='fixtures/case.xml', valid=False)]))
            stale = root / 'target/debug/examples/interop_probe'
            expected = root / 'custom-target/debug/examples/interop_probe'
            for path, data in [(stale, b'stale probe'), (expected, b'just-built probe')]:
                path.parent.mkdir(parents=True)
                path.write_bytes(data)
            native = root / 'native-xmlsec1'
            native.write_bytes(b'synthetic oracle identity')
            selected = []

            def capture(arguments, log, env=None):
                args = [str(a) for a in arguments]
                output = b''
                status = 0
                if args[:2] == ['cargo', 'build']:
                    output = json.dumps(dict(reason='compiler-artifact', fresh=True,
                        target=dict(name='interop_probe', kind=['example']), executable=str(expected))).encode()
                elif args[:2] == ['cargo', 'metadata']:
                    output = b'{"packages":[],"resolve":{"nodes":[]}}'
                elif args[1:] == ['--version'] and args[0] == interop.XMLSEC:
                    output = b'xmlsec1 1.3.13 (openssl)\n'
                elif '--verify' in args:
                    status = 1
                elif Path(args[0]).name == 'interop_probe':
                    selected.append(args[0])
                    raise Probed
                return subprocess.CompletedProcess(args, status, output, b'')

            with patch.object(interop, 'ROOT', root), patch.object(interop, 'PACKAGE', assets), \
                 patch.object(interop, 'command', side_effect=capture), \
                 patch.object(interop.shutil, 'which', return_value=str(native)), \
                 patch.dict(interop.os.environ, CARGO_TARGET_DIR=str(root / 'custom-target')):
                with self.assertRaises(Probed):
                    interop.run_all(root / 'output')
            self.assertEqual(selected, [str(expected)])

    def test_probe_build_requires_one_matching_example_artifact(self):
        # Do not guess a default binary when Cargo reports no unique executable;
        # unrelated library artifacts and ordinary build-script output are allowed.
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'build'
            executable = str(Path(directory) / 'custom-target/interop_probe')
            artifact = json.dumps(dict(reason='compiler-artifact', executable=executable,
                                       target=dict(name='interop_probe', kind=['example']))).encode() + b'\n'
            library = json.dumps(dict(reason='compiler-artifact', executable=None,
                                      target=dict(name='xml_sec_xades', kind=['lib']))).encode() + b'\n'
            with patch.object(interop, 'command', return_value=subprocess.CompletedProcess(
                    ['cargo'], 0, b'build-script diagnostic\n' + library + artifact, b'')) as build:
                self.assertEqual(interop.build_probe(log), Path(executable))
                self.assertIn('--message-format=json-render-diagnostics', build.call_args.args[0])
            for output in [library, artifact + artifact]:
                with self.subTest(output=output), patch.object(interop, 'command', return_value=
                        subprocess.CompletedProcess(['cargo'], 0, output, b'')):
                    with self.assertRaisesRegex(SystemExit, 'exactly one.*build.stdout'):
                        interop.build_probe(log)

    def test_commands_bound_execution_and_retain_timeout_diagnostics(self):
        # A stuck compiler/validator must fail with its argv and partial streams,
        # rather than waiting for the CI job timeout or losing its diagnostics.
        with tempfile.TemporaryDirectory() as directory:
            for runner, core in [(interop.command, interop), (dss.run, dss.corpus)]:
                with self.subTest(runner=runner.__module__):
                    log = Path(directory) / runner.__module__ / 'hung'

                    process = MagicMock()
                    process.__enter__.return_value = process

                    def launch(arguments, **options):
                        self.assertEqual(json.loads(log.with_suffix('.command.json').read_text()), arguments)
                        return process

                    def expired(child, stdout, stderr, timeout):
                        self.assertGreater(timeout, 0)
                        stdout.write(b'partial stdout\n'); stdout.flush()
                        stderr.write(b'partial stderr\n'); stderr.flush()
                        raise subprocess.TimeoutExpired(['synthetic-never-run'], timeout)

                    process.communicate.return_value = (b'', b'')
                    with (patch('subprocess.Popen', side_effect=launch), patch('os.killpg') as killed,
                          patch.object(core, '_capture_streams', side_effect=expired)):
                        with self.assertRaisesRegex(SystemExit, 'timed out.*hung'):
                            runner(['synthetic-never-run'], log)
                    killed.assert_called_once()
                    self.assertEqual(log.with_suffix('.stdout').read_bytes(), b'partial stdout\n')
                    self.assertEqual(log.with_suffix('.stderr').read_bytes(), b'partial stderr\n')

    def test_command_terminates_a_real_stuck_child(self):
        # Exercise the actual subprocess deadline, including flushed diagnostics.
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'child'
            result = self.run_isolated_command([sys.executable, '-u', '-c',
                    "import sys,time; print('ready'); print('waiting', file=sys.stderr); time.sleep(30)"],
                    log)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'timed out', result.stderr)
            self.assertIn(str(log.with_suffix('.command.json')).encode(), result.stderr)
            self.assertEqual(log.with_suffix('.stdout').read_bytes(), b'ready\n')
            self.assertEqual(log.with_suffix('.stderr').read_bytes(), b'waiting\n')

    def test_timeout_before_first_output_retains_empty_streams(self):
        # Timing out before the first byte still leaves inspectable stream files.
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'silent'
            process = MagicMock()
            process.__enter__.return_value = process
            process.communicate.return_value = (b'', b'')
            with (patch('subprocess.Popen', return_value=process), patch('os.killpg'),
                  patch.object(interop, '_capture_streams', side_effect=subprocess.TimeoutExpired(['silent'], 900))):
                with self.assertRaisesRegex(SystemExit, 'timed out.*silent'):
                    interop.command(['silent'], log)
            self.assertEqual(log.with_suffix('.stdout').read_bytes(), b'')
            self.assertEqual(log.with_suffix('.stderr').read_bytes(), b'')

    def test_nested_capture_failure_is_reported_before_group_cancellation(self):
        # Group cancellation also kills a nested wrapper; an I/O/capture error
        # must reach its controller before that signal, rather than disappear.
        with tempfile.TemporaryDirectory() as directory:
            process = MagicMock()
            process.__enter__.return_value = process
            diagnostics = io.StringIO()
            session = os.getsid(0)

            def cancel(group, sig):
                self.assertIn('synthetic capture failure', diagnostics.getvalue())

            with (patch.dict(os.environ, {'_XADES_INTEROP_PARENT_SESSION': str(session + 1)}),
                  patch('os.getpgrp', return_value=session), patch('os.killpg', side_effect=cancel) as cancelled,
                  patch('subprocess.Popen', return_value=process),
                  patch.object(interop, '_capture_streams', side_effect=OSError('synthetic capture failure')),
                  contextlib.redirect_stderr(diagnostics)):
                with self.assertRaisesRegex(OSError, 'synthetic capture failure'):
                    interop.command(['synthetic-never-run'], Path(directory) / 'capture')
            cancelled.assert_called_once()

    def test_inventory_rejects_changed_assets_and_tracked_run_outputs(self):
        # CI must catch stale reference data and accidental commits of actual outputs.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root/'interop/xades'
            fixture = corpus/'fixtures/enveloped-control.xml'
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(b'<synthetic/>')
            (corpus/'SHA256SUMS').write_text(hashlib.sha256(fixture.read_bytes()).hexdigest() +
                '  interop/xades/fixtures/enveloped-control.xml\n')
            tracked = b'interop/xades/fixtures/enveloped-control.xml\0interop/xades/SHA256SUMS\0'
            with patch.object(check, 'ROOT', root), patch.object(check, 'PACKAGE', corpus), \
                 patch.object(check, 'load', return_value=package), patch.object(package, 'PACKAGE', corpus), \
                 patch('subprocess.check_output', return_value=tracked) as listing:
                check.check_inventory()
                fixture.write_bytes(b'<changed/>')
                with self.assertRaisesRegex(SystemExit, 'corpus checksum mismatch'):
                    check.check_inventory()
                listing.return_value = tracked + b'interop/xades/results/enveloped-control/spec/reference-0.bin\0'
                with self.assertRaisesRegex(SystemExit, 'run artifact or undeclared corpus file tracked'):
                    check.check_inventory()

    def test_goldens_reject_changed_and_missing_live_octets(self):
        # Fresh oracle results must match the reference corpus, including empty vectors.
        with tempfile.TemporaryDirectory() as directory:
            expected, actual = Path(directory)/'expected', Path(directory)/'actual'
            expected.mkdir(); actual.mkdir()
            (expected/'expected-reference-0.bin').write_bytes(b'')
            (actual/'expected-reference-0.bin').write_bytes(b'')
            self.assertEqual(check.check_goldens(expected, actual), 1)
            (actual/'expected-reference-0.bin').write_bytes(b'x')
            with self.assertRaisesRegex(SystemExit, 'golden mismatch:.*first_different_byte'):
                check.check_goldens(expected, actual)
            self.assertEqual(json.loads((actual/'golden-comparison.json').read_text())[0]['first_different_byte'], 0)
            (actual/'expected-reference-0.bin').unlink()
            with self.assertRaisesRegex(SystemExit, 'golden inventory mismatch'):
                check.check_goldens(expected, actual)

    def test_dss_expectations_reject_changed_live_conclusions(self):
        # A passing XMLDSig cannot hide a changed DSS profile or certificate finding.
        with tempfile.TemporaryDirectory() as directory:
            expected, actual = Path(directory)/'expected.json', Path(directory)/'actual.json'
            expected.write_text('{"ISC":"PASSED"}')
            actual.write_text('{"ISC":"INDETERMINATE"}')
            with self.assertRaisesRegex(SystemExit, 'DSS expectation mismatch'):
                check.check_expectations(expected, actual)

    def test_binding_summary_preserves_selected_signer_and_digest(self):
        # Keep the evidence for the root-versus-signer discrepancy without raw reports.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binding-facts.txt"
            path.write_text("structural_policy=WARN\nselected_certificate=leaf\n"
                            "selected_certificate_reference_null=true\nreference.0.match=true\n"
                            "reference.0.digest=YWJjZA==\n")
            self.assertEqual(binding.binding_facts(path), {
                "selected_certificate": "leaf", "selected_certificate_reference_null": "true",
                "reference.0.match": "true", "reference.0.digest": "YWJjZA=="})

    def test_bundle_excludes_execution_logs(self):
        # A distributable corpus contains signature evidence, not workstation logs.
        for name in ["checks/pr-validation.json", "checks/build.log", "generation/sign.command.json",
                     "results/build.stdout", "results/versions/metadata.stdout", "case/run.stderr",
                     "case/probe.command.json", "case/rust/result.txt"]:
            self.assertFalse(package.include_evidence(package.PACKAGE / name), name)
        for name in ["case/diagnostic.xml", "case/detailed.xml", "case/simple.xml", "case/binding-facts.txt"]:
            self.assertFalse(package.include_evidence(package.PACKAGE / name), name)
        for name in ["results/control/spec/reference-0.bin", "results/control/spec/replay-0.bin",
                     "dss-investigation/control/rust/signature-0.bin", "results/summary.json",
                     "results/versions.json", "dss-evidence/dependencies.json", "surprise.tmp"]:
            self.assertFalse(package.include_evidence(package.PACKAGE / name), name)
        for name in ["fixtures/enveloped-control.xml", "fixtures/signer.key", "results/enveloped-control/expected-reference-0.bin",
                     "dss-evidence/expectations.json"]:
            self.assertTrue(package.include_evidence(package.PACKAGE / name), name)

    def test_dependency_versions_do_not_export_local_package_ids(self):
        # Cargo metadata includes absolute package IDs; the public manifest must not.
        identity = "path+file:///Users/example/private#sample@1.0.0"
        metadata = dict(packages=[dict(id=identity, name="sample", version="1.0.0")],
                        resolve=dict(nodes=[dict(id=identity, features=["std"])]))
        self.assertEqual(interop.resolved_versions(metadata),
                         [dict(name="sample", version="1.0.0", features=["std"])])

    def test_analyze_uses_retained_octets_without_raw_process_logs(self):
        # Reanalysis of a run needs its octets, not raw process captures.
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            case = output / "case"
            rust = case / "rust"
            rust.mkdir(parents=True)
            references = [b"first", b"second"]
            values = []
            for index, data in enumerate(references):
                (case / f"expected-reference-{index}.bin").write_bytes(data)
                (rust / f"reference-{index}.bin").write_bytes(data)
                (rust / f"replay-{index}.bin").write_bytes(data)
                values.append(base64.b64encode(hashlib.sha256(data).digest()).decode())
            (case / "expected-signedinfo.bin").write_bytes(b"signedinfo")
            (rust / "signature-0.bin").write_bytes(b"signedinfo")
            (case / "signed.xml").write_text(f'<Signature xmlns="{interop.DS}"><SignedInfo>' +
                ''.join(f'<Reference><DigestValue>{value}</DigestValue></Reference>' for value in values) +
                '</SignedInfo></Signature>')
            (output / "summary.json").write_text(json.dumps(dict(cases=[dict(name="case")])))
            with patch.object(binding, "OUT", output), contextlib.redirect_stdout(io.StringIO()):
                binding.analyze_octets()
            self.assertFalse((case / "libxmlsec.stdout").exists())
            self.assertEqual(json.loads((output / "octet-comparison.json").read_text())[0]
                             ["signed_info"]["status"], "проверено")

    def test_evidence_refusal_survives_python_optimization(self):
        # Python -O must not remove the signed-octet or normative outcome gates.
        script = Path(__file__).with_name("investigate-xades-dss.py").resolve()
        result = subprocess.run([sys.executable, "-O", "-c",
            "import runpy,sys; runpy.run_path(sys.argv[1])['require'](False, 'octet-check-failed')",
            str(script)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), "octet-check-failed")

    def test_corpus_output_creates_missing_parents(self):
        # Explicit results must work after cargo clean, before any oracle call.
        class SetupComplete(Exception):
            pass

        script = Path(__file__).with_name("xades-interop.py").resolve()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "missing-parent" / "evidence"
            with patch.object(sys, "argv", [str(script), "--results", str(output)]):
                with patch("subprocess.Popen", side_effect=SetupComplete):
                    with self.assertRaises(SetupComplete):
                        runpy.run_path(str(script), run_name="__main__")
            self.assertTrue(output.is_dir())

    def test_dss_fc_does_not_attest_target_binding(self):
        # EN 319 102-1 §5.2.2 excludes profile conformance from base-format FC.
        # Neither FC=PASSED nor a format label proves semantic Target checking.
        row = dict(conclusions=dict(FC="PASSED"), reported_format="XAdES-BASELINE-B")
        result = dss.profile_binding("baseline-wrong-target", row)
        self.assertEqual(result["status"], "не запускалось или заблокировано")

    def test_dss_root_digest_requires_signer_identification_failure(self):
        # EN 319 102-1 §5.2.3.4 requires matching the actual signing certificate.
        self.assertEqual(dss.profile_binding("baseline-certificate-digest-mismatch",
            dict(conclusions=dict(ISC="PASSED")))["status"], "не прошло")
        self.assertEqual(dss.profile_binding("baseline-certificate-digest-mismatch",
            dict(conclusions=dict(ISC="INDETERMINATE"),
                 subindications=dict(ISC="NO_SIGNING_CERTIFICATE_FOUND")))["status"], "проверено")
        self.assertEqual(dss.profile_binding("baseline-certificate-digest-mismatch",
            dict(conclusions=dict(ISC="INDETERMINATE"),
                 subindications=dict(ISC="CRYPTO_CONSTRAINTS_FAILURE")))["status"], "не прошло")

    def test_investigation_output_creates_missing_parents(self):
        # A clean checkout has no target directory. Explicit output must create
        # its parents before launching any compiler or validator.
        class SetupComplete(Exception):
            pass

        script = Path(__file__).with_name("investigate-xades-dss.py").resolve()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "missing-parent" / "evidence"
            with patch.object(sys, "argv", [str(script), "--output", str(output)]):
                with patch("subprocess.Popen", side_effect=SetupComplete):
                    with self.assertRaises(SetupComplete):
                        runpy.run_path(str(script), run_name="__main__")
            self.assertTrue(output.is_dir())

    def test_hex_dump_preserves_canonical_whitespace(self):
        # DebugHexDump is hex, not XML text. Final LF and spaces are signed.
        block = b"== PreDigest data - start buffer:\n3c612f3e20\n0a\n== PreDigest data - end buffer"
        self.assertEqual(interop.debug_buffer(block, b"PreDigest"), b"<a/> \n")

    def test_absent_buffer_is_not_implicitly_empty(self):
        # Missing debug output cannot pass byte comparison as empty content.
        self.assertIsNone(interop.debug_buffer(b"== Status: OK\n", b"PreDigest"))

    def test_malformed_hex_fails(self):
        # A tool-output format change must stop extraction, never corrupt bytes.
        with self.assertRaises(ValueError):
            interop.debug_buffer(b"== PreDigest data - start buffer:\n<XML/>\n== PreDigest data - end buffer", b"PreDigest")

    def test_first_difference_and_prefix_length(self):
        # Distinguish a changed byte from a truncated but matching prefix.
        difference = interop.compare(b"abcd", b"abXd")
        self.assertEqual(difference["first_different_byte"], 2)
        self.assertEqual(difference["status"], "не прошло")
        self.assertEqual(interop.compare(b"abcd", b"abc")["first_different_byte"], 3)
        self.assertIsNone(interop.compare(b"", b"")["first_different_byte"])


if __name__ == "__main__":
    unittest.main()
