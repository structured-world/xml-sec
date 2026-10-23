#!/usr/bin/env python3
"""Guard the evidence parser against false positive interoperability reports."""
import importlib.util
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("interop", Path(__file__).with_name("xades-interop.py"))
interop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interop)
spec_dss = importlib.util.spec_from_file_location("dss", Path(__file__).with_name("xades-dss.py"))
dss = importlib.util.module_from_spec(spec_dss)
spec_dss.loader.exec_module(dss)


class EvidenceTests(unittest.TestCase):
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
                with patch("subprocess.run", side_effect=SetupComplete):
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
                with patch("subprocess.run", side_effect=SetupComplete):
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
