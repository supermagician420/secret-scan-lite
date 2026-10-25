import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from secret_scan_lite import main, scan_path, scan_text, shannon_entropy


class RuleTests(unittest.TestCase):
    def test_private_key(self) -> None:
        findings = scan_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n", "key.pem", entropy=False)
        self.assertTrue(any(finding.kind == "private-key" for finding in findings))

    def test_aws_access_key(self) -> None:
        findings = scan_text("aws_key = AKIAIOSFODNN7REALKEY", "app.py", entropy=False)
        self.assertTrue(any(finding.kind == "aws-access-key" for finding in findings))

    def test_github_token(self) -> None:
        token = "ghp_" + "a" * 36
        findings = scan_text("token: %s" % token, "app.py", entropy=False)
        self.assertTrue(any(finding.kind == "github-token" for finding in findings))

    def test_generic_assignment_masks_secret(self) -> None:
        secret = "Zx9Qw2Er4Ty6Ui8Op0"
        findings = scan_text('api_key = "%s"' % secret, "config.py", entropy=False)
        self.assertTrue(any(finding.kind == "generic-secret" for finding in findings))
        for finding in findings:
            self.assertNotIn(secret, finding.preview)

    def test_connection_string(self) -> None:
        findings = scan_text("postgres://admin:supersecret@db.internal/app", "settings.py", entropy=False)
        self.assertTrue(any(finding.kind == "connection-string" for finding in findings))

    def test_placeholder_is_ignored(self) -> None:
        findings = scan_text('api_key = "your-example-key-here"', "config.py", entropy=False)
        self.assertEqual(findings, ())

    def test_allowlist_pragma(self) -> None:
        findings = scan_text('api_key = "Zx9Qw2Er4Ty6Ui8Op0"  # pragma: allowlist secret', "config.py", entropy=False)
        self.assertEqual(findings, ())


class EntropyTests(unittest.TestCase):
    def test_entropy_math(self) -> None:
        self.assertAlmostEqual(shannon_entropy("aaaa"), 0.0)
        self.assertGreater(shannon_entropy("aB3xK9qP2mL7zR5t"), 3.0)

    def test_high_entropy_candidate_is_flagged(self) -> None:
        candidate = "aB3xK9qP2mL7zR5tY8uI0oP1"
        findings = scan_text("value = %s" % candidate, "app.py", entropy=True)
        self.assertTrue(any(finding.kind == "high-entropy-string" for finding in findings))

    def test_low_entropy_candidate_is_not_flagged(self) -> None:
        findings = scan_text("value = aaaaaaaaaaaaaaaaaaaaaaaa", "app.py", entropy=True)
        self.assertFalse(any(finding.kind == "high-entropy-string" for finding in findings))

    def test_entropy_can_be_disabled(self) -> None:
        candidate = "aB3xK9qP2mL7zR5tY8uI0oP1"
        findings = scan_text("value = %s" % candidate, "app.py", entropy=False)
        self.assertFalse(any(finding.kind == "high-entropy-string" for finding in findings))


class PathTests(unittest.TestCase):
    def test_scan_directory_skips_git_and_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('api_key = "Zx9Qw2Er4Ty6Ui8Op0"\n', encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text('api_key = "Zx9Qw2Er4Ty6Ui8Op0"\n', encoding="utf-8")
            (root / "image.png").write_bytes(b"\x89PNG\x00\x00")
            result = scan_path(str(root), entropy=False)
        self.assertEqual(result.files_scanned, 1)
        self.assertTrue(any(finding.path == "app.py" for finding in result.findings))

    def test_scan_exclude_glob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('api_key = "Zx9Qw2Er4Ty6Ui8Op0"\n', encoding="utf-8")
            (root / "generated.py").write_text('api_key = "Zx9Qw2Er4Ty6Ui8Op0"\n', encoding="utf-8")
            result = scan_path(str(root), excludes=["generated.py"], entropy=False)
        self.assertEqual(result.files_scanned, 1)
        self.assertTrue(all(finding.path == "app.py" for finding in result.findings))

    def test_missing_path_raises(self) -> None:
        with self.assertRaises(Exception):
            scan_path("definitely-missing")


class CliTests(unittest.TestCase):
    def test_cli_json_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text('api_key = "Zx9Qw2Er4Ty6Ui8Op0"\n', encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main([str(path), "--json", "--no-entropy"])
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["files_scanned"], 1)
        self.assertGreaterEqual(len(data["findings"]), 1)

    def test_cli_clean_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.py"
            path.write_text("print('hello')\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main([str(path), "--no-entropy"])
        self.assertEqual(code, 0)
        self.assertIn("No potential secrets", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
