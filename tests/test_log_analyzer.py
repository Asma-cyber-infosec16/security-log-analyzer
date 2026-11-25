import tempfile
import unittest
from pathlib import Path

from log_analyzer import analyze_log


class AnalyzeLogTests(unittest.TestCase):
    def analyze_text(self, text, threshold=4):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(text, encoding="utf-8")
            return analyze_log(log_path, threshold)

    def test_counts_failed_attempts_by_ip(self):
        text = (
            "2025-03-01 09:00:12 FAILED_LOGIN ip=203.0.113.10 user=alice\n"
            "2025-03-01 09:01:06 FAILED_LOGIN ip=203.0.113.10 user=alice\n"
            "2025-03-01 09:02:44 FAILED_LOGIN ip=198.51.100.23 user=bob\n"
        )

        results = self.analyze_text(text)

        self.assertEqual(
            results["failed_attempts"],
            {"198.51.100.23": 1, "203.0.113.10": 2},
        )

    def test_flags_only_ips_at_the_threshold(self):
        text = (
            "2025-03-01 09:00:12 FAILED_LOGIN ip=203.0.113.10 user=alice\n"
            "2025-03-01 09:01:06 FAILED_LOGIN ip=203.0.113.10 user=alice\n"
            "2025-03-01 09:02:44 FAILED_LOGIN ip=203.0.113.10 user=alice\n"
            "2025-03-01 09:03:18 FAILED_LOGIN ip=198.51.100.23 user=bob\n"
            "2025-03-01 09:04:01 FAILED_LOGIN ip=198.51.100.23 user=bob\n"
            "2025-03-01 09:05:01 FAILED_LOGIN ip=198.51.100.23 user=bob\n"
            "2025-03-01 09:06:01 FAILED_LOGIN ip=198.51.100.23 user=bob\n"
        )

        results = self.analyze_text(text)

        self.assertEqual(
            results["suspicious_ips"],
            {"198.51.100.23": 4},
        )

    def test_counts_successful_logins_and_ignores_invalid_lines(self):
        text = (
            "2025-03-01 09:00:12 SUCCESS_LOGIN ip=203.0.113.10 user=alice\n"
            "this is not a valid log line\n"
            "2025-03-01 09:02:44 FAILED_LOGIN ip=999.0.0.1 user=bob\n"
        )

        results = self.analyze_text(text)

        self.assertEqual(results["successful_logins"], 1)
        self.assertEqual(results["invalid_lines"], 2)

    def test_rejects_zero_threshold(self):
        with self.assertRaises(ValueError):
            analyze_log("file-that-does-not-need-to-exist.log", threshold=0)


if __name__ == "__main__":
    unittest.main()