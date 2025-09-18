# WebScan3r

> **Advanced Web Security Scanner** — a multi-threaded Python tool for automated security testing of web applications. Use only on targets you own or are explicitly authorized to test.

---

## Table of contents

* [Overview](#overview)
* [Features](#features)
* [Vulnerability detection capabilities](#vulnerability-detection-capabilities)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)
* [Wordlists and setup](#wordlists-and-setup)
* [Configuration](#configuration)
* [Important notes & legal](#important-notes--legal)

---

## Overview

WebScan3r is a performant, extensible web application security scanner written in Python. It combines intelligent crawling, active tests, and optional WFuzz integration to find common web vulnerabilities and misconfigurations.

## Features

* **Multi-threaded scanning** with configurable thread count for high throughput.
* **Comprehensive vulnerability tests** for many common web issues.
* **Intelligent crawling** to discover endpoints and parameters automatically.
* **WFuzz integration** (optional) for directory brute-forcing and pattern-based fuzzing.
* **JSON reporting** for machine-readable results.

## Vulnerability detection capabilities

WebScan3r includes tests or checks for (non-exhaustive):

* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Security header analysis (missing/misconfigured headers)
* CSRF protection checks (forms without tokens)
* CORS misconfigurations
* Local & Remote File Inclusion (LFI/RFI)
* Command injection
* XXE (XML External Entity) issues
* SSRF (Server-Side Request Forgery)
* Open redirects
* Common API issues (BOLA, sensitive data exposure, etc.)
* Information disclosure (sensitive data in responses)
* Dangerous HTTP methods (TRACE, PUT, DELETE)

## Prerequisites

### System

* Python **3.7+**
* Linux, macOS, or Windows
* Internet connection (for external tests or WFuzz)
* Sufficient RAM/CPU for multi-threaded scanning

### Python packages

Install runtime dependencies:

```bash
pip install requests beautifulsoup4 aiohttp colorama
```

### Optional (WFuzz)

WFuzz improves directory/parameter fuzzing when available.

```bash
# Kali / Debian-based
sudo apt install wfuzz

# Alternative (limited):
pip install wfuzz
```

## Installation

1. Save the scanner script as `web_scanner.py` in a working directory.
2. Make the script executable (Linux/macOS):

```bash
chmod +x web_scanner.py
```

## Usage

Basic scan:

```bash
python web_scanner.py https://example.com
```

Verbose output:

```bash
python web_scanner.py https://example.com -v
```

Aggressive (more tests):

```bash
python web_scanner.py https://example.com -a
```

Verbose + Aggressive:

```bash
python web_scanner.py https://example.com -v -a
```

WFuzz pattern support — if your target URL contains `/FUZZ/` the scanner will use WFuzz when available:

```bash
python web_scanner.py https://example.com/FUZZ/
```

Display help:

```bash
python web_scanner.py --help
```

## Wordlists and setup

Place the following wordlists in the same directory as the script (or update configuration paths):

* `raft-small-directories-lowercase.txt` — directory wordlist (common directories)
* `hugeSQL.txt` — SQL injection payloads
* `xss-payload-list.txt` — XSS payloads
* `common-params.txt` — common parameter names (e.g. `id,page,view,file,search`)

Sources: SecLists ([https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)) or your preferred collections.

## Configuration

* Default thread count: **500** (may be high for some systems). Reduce in the `CONFIG` section of the script if needed.
* Reporting: JSON output stored to `reports/` by default (adjustable).
* Timeouts, user-agent, and rate limits can be configured in the script config block.

## Important notes & legal

* **Authorization:** Only scan web applications you own or have explicit written permission to test. Unauthorized scanning can be illegal.
* **Performance:** High thread counts may consume large CPU/RAM and generate significant network traffic. Tune settings for your environment and the target.
* **False positives/negatives:** Automated scanners can be noisy and incomplete — manually validate findings before taking action.

---
