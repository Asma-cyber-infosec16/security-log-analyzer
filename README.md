# Security Log Analyzer

A beginner-friendly Python command-line tool that analyzes authentication logs and summarizes login activity.

## Features

- Counts failed login attempts by IP address
- Counts successful logins
- Skips invalid or malformed log lines
- Flags IP addresses that reach the failed-login threshold (4 attempts in the included sample)

## Requirements

- Python 3
- No external packages required

## Run

From the project folder, run:

```powershell
python log_analyzer.py
```

## Run the tests

```powershell
python -B -m unittest discover -v
```

## Included sample

The sample file `logs/auth.log` contains fictional test data. It produces these results:

- Successful logins: 1
- Invalid lines: 0
- Failed logins from `192.0.2.44`: 1
- Failed logins from `198.51.100.23`: 2
- Failed logins from `203.0.113.10`: 4
- Suspicious IP at the sample threshold: `203.0.113.10`

These IP addresses are reserved for documentation and testing; the sample logs do not contain real login data.

## Project structure

```text
logs/
├── auth.log
└── simple.log
tests/
├── __init__.py
└── test_log_analyzer.py
.gitignore
.gitattributes
log_analyzer.py
README.md
```

> This is an educational project for analyzing sample logs, not a production security-monitoring system.
