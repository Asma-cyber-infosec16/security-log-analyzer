import argparse
import ipaddress
import re
from collections import Counter
from pathlib import Path


LOG_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} "
    r"(?P<event>FAILED_LOGIN|SUCCESS_LOGIN) "
    r"ip=(?P<ip>\S+) user=\S+$"
)


def analyze_log(log_path, threshold=4):
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    failed_attempts = Counter()
    successful_logins = 0
    invalid_lines = 0

    with Path(log_path).open("r", encoding="utf-8") as log_file:
        for line in log_file:
            line = line.strip()

            if not line:
                continue

            match = LOG_PATTERN.fullmatch(line)
            if match is None:
                invalid_lines += 1
                continue

            ip = match.group("ip")

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                invalid_lines += 1
                continue

            if match.group("event") == "FAILED_LOGIN":
                failed_attempts[ip] += 1
            else:
                successful_logins += 1

    suspicious_ips = {
        ip: count
        for ip, count in failed_attempts.items()
        if count >= threshold
    }

    return {
        "failed_attempts": dict(sorted(failed_attempts.items())),
        "suspicious_ips": dict(sorted(suspicious_ips.items())),
        "successful_logins": successful_logins,
        "invalid_lines": invalid_lines,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze sample authentication logs for repeated failed logins."
    )

    parser.add_argument(
        "log_file",
        nargs="?",
        default="logs/auth.log",
        help="Path to a log file (default: logs/auth.log).",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=4,
        help="Failed attempts needed to flag an IP (default: 4).",
    )

    args = parser.parse_args()

    try:
        results = analyze_log(args.log_file, args.threshold)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log file: {args.log_file}")
    print(f"Successful logins: {results['successful_logins']}")
    print(f"Invalid lines ignored: {results['invalid_lines']}")
    print()

    print("Failed login attempts by IP:")
    if results["failed_attempts"]:
        for ip, count in results["failed_attempts"].items():
            print(f"  {ip}: {count}")
    else:
        print("  None")

    print()
    print(f"Suspicious IPs (at least {args.threshold} failed attempts):")
    if results["suspicious_ips"]:
        for ip, count in results["suspicious_ips"].items():
            print(f"  {ip}: {count} failed attempts")
    else:
        print("  None")


if __name__ == "__main__":
    main()