import os
import shutil
import subprocess
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON = sys.executable
MAIN = os.path.join(PROJECT_ROOT, "main.py")


def run_command(args, cwd=PROJECT_ROOT):
    result = subprocess.run([PYTHON, MAIN] + args, cwd=cwd, capture_output=True, text=True)
    return result


class SentinelCliTest(unittest.TestCase):
    def test_startup_panel(self):
        result = run_command([])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Analyze. Detect. Secure.", result.stdout)
        self.assertIn("Disclaimer", result.stdout)

    def test_scan_command(self):
        result = run_command(["scan", "example.com"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Security Score", result.stdout)

    def test_ssl_command(self):
        result = run_command(["ssl", "example.com"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("SSL Certificate Details", result.stdout)

    def test_dns_command(self):
        result = run_command(["dns", "example.com"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("DNS Records", result.stdout)

    def test_whois_command(self):
        result = run_command(["whois", "example.com"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("WHOIS Data", result.stdout)

    def test_headers_command(self):
        result = run_command(["headers", "example.com"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Security Headers", result.stdout)

    def test_ports_command(self):
        result = run_command(["ports", "example.com"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Port Scan", result.stdout)

    def test_ip_command_with_argument(self):
        result = run_command(["ip", "8.8.8.8"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("IP:", result.stdout)

    def test_ip_command_no_argument(self):
        result = run_command(["ip"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("IP", result.stdout)

    def test_password_command(self):
        result = run_command(["password", "--length", "16"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Generated Password", result.stdout)

    def test_hash_command(self):
        result = run_command(["hash", "--algo", "sha256", "test"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Digest:", result.stdout)

    def test_report_command(self):
        report_md = os.path.join(PROJECT_ROOT, "sentinel_report_example_com.md")
        report_pdf = os.path.join(PROJECT_ROOT, "sentinel_report_example_com.pdf")
        for path in (report_md, report_pdf):
            if os.path.exists(path):
                os.remove(path)

        result = run_command(["report", "example.com"])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(report_md))
        self.assertTrue(os.path.exists(report_pdf))

        for path in (report_md, report_pdf):
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main()
