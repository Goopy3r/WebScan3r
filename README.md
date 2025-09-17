# WebScan3r

Advanced Web Security Scanner is a comprehensive, multi-threaded web application security scanner written in Python. It performs automated security testing against web applications to identify common vulnerabilities and security misconfigurations.

## Features
1. **Multi-threaded Scanning**: High-performance scanning with configurable thread counts

2. **Comprehensive Vulnerability Detection**: Tests for numerous web application vulnerabilities

3. **Intelligent Crawling**: Discovers and tests application endpoints automatically

4. **WFuzz Integration**: Leverages the popular wfuzz tool for directory brute-forcing when available

5. **Detailed Reporting**: Generates JSON reports with vulnerability findings

## Vulnerability Detection Capabilities
**The scanner tests for a wide range of security issues including**

SQL Injection (SQLi): Tests for various SQL injection vectors

Cross-Site Scripting (XSS): Detects reflected XSS vulnerabilities

Security Header Analysis: Checks for missing or misconfigured security headers

CSRF Protection: Identifies forms without proper CSRF protection

CORS Misconfigurations: Tests for insecure CORS configurations

File Inclusion: Local and remote file inclusion vulnerabilities

Command Injection: OS command injection vulnerabilities

XXE Injection: XML External Entity processing vulnerabilities

SSRF: Server-Side Request Forgery vulnerabilities

Open Redirects: Unsafe redirects that could facilitate phishing

API Security: Tests for common API vulnerabilities (BOLA, data exposure, etc.)

Information Disclosure: Sensitive data exposure in responses

HTTP Method Testing: Dangerous HTTP methods (TRACE, PUT, DELETE)
