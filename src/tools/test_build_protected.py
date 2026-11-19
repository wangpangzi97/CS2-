import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("build_protected", Path(__file__).with_name("build_protected.py"))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class ReleaseTests(unittest.TestCase):
    def args(self, *extra):
        return b.parser().parse_args(["--out", "never-created-by-plan", *extra])

    def test_unsigned_flags_and_annotation(self):
        p = b.plan(self.args("--unsigned"))
        self.assertEqual(p["environment"][b.CONTROLFLOW], "1")
        self.assertEqual(len(p["commands"]), 2)
        for c in p["commands"]:
            for f in ("-literals", "-tiny", "-seed=random", "-mod=vendor", "-trimpath"):
                self.assertIn(f, c)
        self.assertIn("-H=windowsgui -X main.defaultGUIMode=true", p["commands"][1][7])

    def test_sign_verify_before_packaging(self):
        p = b.plan(self.args("--certificate-thumbprint", "AB" * 20, "--machine-store"))
        self.assertEqual([c[1] for c in p["commands"]], ["-literals", "-literals", "sign", "verify", "sign", "verify"])
        for c in p["commands"][2::2]:
            self.assertIn("/sm", c)
            self.assertEqual(c[c.index("/fd") + 1], "SHA256")
            self.assertEqual(c[c.index("/td") + 1], "SHA256")
        for c in p["commands"][3::2]:
            self.assertIn("/pa", c)
            self.assertIn("/tw", c)

    def test_bad_thumbprint_fails(self):
        with self.assertRaises(ValueError):
            b.plan(self.args("--certificate-thumbprint", "invalid"))

    def test_signing_has_no_password_parameter(self):
        p = b.plan(self.args("--certificate-thumbprint", "AB" * 20))
        self.assertNotIn("/p", [s for c in p["commands"] for s in c])

    def test_existing_output_fails(self):
        with tempfile.TemporaryDirectory() as d:
            a = self.args("--unsigned")
            a.out = Path(d)
            with self.assertRaises(ValueError):
                b.build(a)

    def test_native_failure_is_fail_closed_and_logged(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "log.jsonl"
            with patch.object(b.subprocess, "run", return_value=subprocess.CompletedProcess([], 7, b"out\n", b"err\n")):
                with self.assertRaises(RuntimeError):
                    b.run(["signtool", "verify"], {}, log)
            record = b.json.loads(log.read_text(encoding="utf-8"))
            self.assertEqual(record["exit_status"], 7)
            self.assertEqual(record["stderr"], "err\n")

    def configuration(self, directory, uplink="https://example.invalid/api/v1/ingest"):
        p = Path(directory)
        (p / "capture.json").write_text(b.json.dumps({"uplink": uplink, "proc": "cs2.exe"}), encoding="utf-8")
        (p / "license.json").write_text(b.json.dumps({"endpoint": "https://example.invalid/api/verify.php",
                    "app_key": "ab" * 32, "app_id": 1}), encoding="utf-8")

    def test_public_configs_are_included_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            self.configuration(d)
            files = b.public_configuration_files(d)
            self.assertEqual(set(files), {"capture.json", "license.json"})
            self.assertEqual(files["capture.json"], (Path(d) / "capture.json").read_bytes())

    def test_missing_config_fails_before_build(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileNotFoundError):
                b.public_configuration_files(d)

    def test_insecure_or_wrong_uplink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for url in ("", "http://example.invalid/api/v1/ingest", "https://u:p@example.invalid/api/v1/ingest",
                        "https://example.invalid/api/v1/ingest?token=x", "https://example.invalid/apiv1/ingest"):
                self.configuration(d, url)
                with self.assertRaises(ValueError):
                    b.public_configuration_files(d)

    def test_application_secret_is_not_packaged(self):
        with tempfile.TemporaryDirectory() as d:
            self.configuration(d)
            p = Path(d) / "license.json"
            obj = b.json.loads(p.read_text(encoding="utf-8"))
            obj["api_secret"] = "synthetic-not-a-real-secret"
            p.write_text(b.json.dumps(obj), encoding="utf-8")
            with self.assertRaises(ValueError):
                b.public_configuration_files(d)


if __name__ == "__main__":
    unittest.main()
