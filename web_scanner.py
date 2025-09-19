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
import signal

# Initialize colorama
init(autoreset=True)

# Configuration
CONFIG = {
    "WORDLIST": {
        "DIRECTORY": "directories.txt",
        "SQLI": "hugeSQL.txt",
        "XSS": "xss-payload-list.txt",
        "PARAMS": "params.txt"
    },
    "THREADS": 20,
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
    def __init__(self, verbose=False, aggressive=False, debug=False):
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
        self.debug = debug
        self.color = CONFIG["COLORS"]
        self.vulnerabilities = []
        self.discovered_paths = []
        self.checked_urls = set()
        self.semaphore = asyncio.Semaphore(CONFIG["THREADS"])
        self.aiohttp_session = None
        self.strict_verification = True
        self.shutdown = False

    def get_wordlist_path(self, wordlist_name):
        """Get the correct path for a wordlist file"""
        filename = CONFIG["WORDLIST"][wordlist_name]
        
        # Check multiple possible locations
        possible_paths = [
            filename,  # Current directory
            os.path.join("txt", filename),  # txt/ subdirectory
            os.path.join(os.path.dirname(__file__), filename),  # Script directory
            os.path.join(os.path.dirname(__file__), "txt", filename)  # Script dir/txt/
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
                
        # If not found, return None
        self.print_status(f"Wordlist {filename} not found in any location", "warning")
        return None

    def print_status(self, message, level="info"):
        color = self.color.get(level, Fore.WHITE)
        print(f"{color}[{level.upper()}] {message}{Style.RESET_ALL}")

    def random_user_agent(self):
        return random.choice(CONFIG["USER_AGENTS"])

    async def async_request(self, method, url, **kwargs):
        if self.shutdown:
            return None

        if not self.aiohttp_session:
            connector = aiohttp.TCPConnector(
                limit=CONFIG["THREADS"],
                limit_per_host=10,
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
        except asyncio.CancelledError:
            return None
        except Exception as e:
            if self.verbose:
                self.print_status(f"Request error: {e}", "error")
            return None

    def scan(self, url):
        """
        Main scanning function that coordinates the security scan.

        Args:
            url: The target URL to scan for vulnerabilities
        """
        print(CONFIG["BANNER"])

        # Normalize the URL - add https:// if no scheme is provided
        normalized_url = self.normalize_url(url)
        self.print_status(f"Starting scan for: {normalized_url}", "info")

        if not self.validate_url(normalized_url):
            self.print_status("Invalid URL format", "error")
            return

        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Set up signal handling for graceful shutdown
        def signal_handler():
            self.print_status("Shutting down gracefully...", "warning")
            self.shutdown = True
            # Cancel all running tasks
            for task in asyncio.all_tasks(loop):
                task.cancel()

        try:
            # Add signal handlers for graceful shutdown
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, signal_handler)

            # Check if URL contains /FUZZ/ and only run WFuzz if it does
            if "/FUZZ/" in normalized_url.upper():
                self.print_status(
                    "FUZZ pattern detected, running WFuzz only", "info")
                loop.run_until_complete(self.run_wfuzz_only(normalized_url))
            else:
                # Run the full async scan
                loop.run_until_complete(self.async_scan(normalized_url))

        except KeyboardInterrupt:
            self.print_status("Scan interrupted by user", "warning")
        except asyncio.CancelledError:
            self.print_status("Scan cancelled", "warning")
        except Exception as e:
            self.print_status(
                f"Unexpected error during scan: {str(e)}", "error")
            if self.debug:
                import traceback
                traceback.print_exc()
        finally:
            # Cleanup resources
            try:
                if hasattr(self, 'aiohttp_session') and self.aiohttp_session:
                    loop.run_until_complete(self.aiohttp_session.close())
            except Exception as e:
                if self.debug:
                    self.print_status(
                        f"Error closing session: {str(e)}", "debug")
            finally:
                loop.close()

    def normalize_url(self, url):
        """Add https:// scheme if no scheme is provided"""
        if not url.startswith(('http://', 'https://')):
            # Try https first, fall back to http if https fails
            https_url = f"https://{url}"
            http_url = f"http://{url}"

            # Test which protocol works
            try:
                response = requests.head(
                    https_url, timeout=5, allow_redirects=True)
                return https_url
            except:
                try:
                    response = requests.head(
                        http_url, timeout=5, allow_redirects=True)
                    return http_url
                except:
                    # If both fail, default to https
                    return https_url
        return url

    async def async_scan(self, url):
        await self.crawl(url, max_depth=1)  # Reduced depth for speed

        tests = [
            ("Basic Security Checks", self.run_basic_checks),
            ("Directory Bruteforce", self.run_bruteforce),
            ("Parameter Discovery", self.find_parameters),
            ("Advanced SQLi Scan", self.advanced_sqli_scan),
            ("Advanced XSS Scan", self.advanced_xss_scan),
        ]

        for name, test in tests:
            if self.shutdown:
                break
            try:
                self.print_status(f"Starting {name}...", "info")
                if asyncio.iscoroutinefunction(test):
                    await test(url)
                else:
                    # Handle synchronous functions
                    result = test(url)
                    if asyncio.iscoroutine(result):
                        await result
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.print_status(f"{name} failed: {str(e)}", "error")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

        if not self.shutdown:
            self.generate_report(url)
            self.print_status("Scan completed!", "success")

    def validate_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    async def crawl(self, url, max_depth=1):
        self.print_status(f"Crawling {url} (max depth: {max_depth})", "info")
        await self._crawl(url, max_depth, current_depth=0)

    async def _crawl(self, url, max_depth, current_depth):
        if self.shutdown or current_depth > max_depth or url in self.checked_urls:
            return

        self.checked_urls.add(url)

        try:
            await asyncio.sleep(0.1)  # Reduced sleep time
            headers = {"User-Agent": self.random_user_agent()}
            response = await self.async_request('GET', url, headers=headers, timeout=CONFIG["TIMEOUT"])

            if not response or 'text/html' not in response['headers'].get('Content-Type', ''):
                return

            soup = BeautifulSoup(response['text'], 'html.parser')

            tasks = []
            for link in soup.find_all('a', href=True):
                if self.shutdown:
                    break

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
                    if self.verbose:
                        self.print_status(f"Discovered: {normalized_url}", "debug")

                # Create task for each URL to crawl
                task = asyncio.create_task(self._crawl(
                    normalized_url, max_depth, current_depth + 1))
                tasks.append(task)

            for form in soup.find_all('form'):
                if self.shutdown:
                    break

                form_action = form.get('action', '')
                if form_action:
                    absolute_url = urljoin(url, form_action)
                    if absolute_url not in self.discovered_paths:
                        self.discovered_paths.append(absolute_url)
                        if self.verbose:
                            self.print_status(
                                f"Discovered form action: {absolute_url}", "debug")

            # Wait for all tasks to complete
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        except asyncio.CancelledError:
            pass
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
            if self.shutdown:
                break
            try:
                self.print_status(f"Testing {name}...", "info")
                if asyncio.iscoroutinefunction(check):
                    await check(url)
                else:
                    result = check(url)
                    if asyncio.iscoroutine(result):
                        await result
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.print_status(f"{name} check failed: {str(e)}", "error")

    async def run_wfuzz_only(self, url):
        """Run only WFuzz when FUZZ pattern is detected in URL"""
        # Extract base URL without the FUZZ part
        base_url = url.replace('/FUZZ', '').replace('/FUZZ/', '')
        
        wordlist_path = self.get_wordlist_path("DIRECTORY")
        if not wordlist_path:
            self.print_status("No directory wordlist found, cannot run WFuzz", "error")
            return

        command = [
            "wfuzz",
            "-w", wordlist_path,
            "--hc", "404,403",
            url
        ]

        try:
            self.print_status(f"Running command: {' '.join(command)}", "info")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Print WFuzz output in real-time
            while True:
                if self.shutdown:
                    process.terminate()
                    break
                line = await process.stdout.readline()
                if not line:
                    break
                print(line.decode().strip())

            await process.wait()
            self.print_status("WFuzz scan completed", "success")
        except Exception as e:
            self.print_status(f"WFuzz error: {str(e)}", "error")
            self.print_status("Falling back to Python brute forcer...", "info")
            await self.run_python_bruteforce(base_url, wordlist_path)

    async def run_bruteforce(self, url):
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        wordlist_path = self.get_wordlist_path("DIRECTORY")
        
        if self.check_wfuzz() and wordlist_path:
            await self.run_wfuzz_scan(base_url, wordlist_path)
        else:
            await self.run_python_bruteforce(base_url, wordlist_path)

    async def run_wfuzz_scan(self, base_url, wordlist_path):
        """Run WFuzz as part of the full scan process"""
        target_url = f"{base_url}/FUZZ"

        command = [
            "wfuzz",
            "-w", wordlist_path,
            "--hc", "404,403",
            target_url
        ]

        try:
            self.print_status(
                f"Running WFuzz scan: {' '.join(command)}", "info")
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
            await self.run_python_bruteforce(base_url, wordlist_path)

    async def run_python_bruteforce(self, base_url, wordlist_path=None):
        self.print_status("Running directory bruteforce with Python", "info")

        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r', errors='ignore') as f:
                    dirs = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.print_status(f"Error reading wordlist: {e}", "error")
                dirs = self.get_default_directories()
        else:
            dirs = self.get_default_directories()
            self.print_status("Using built-in common directories", "info")

        print("\n" + "="*100)
        print(f"{'URL':<60}{'Response':<12}{'Size':<10}{'Title':<30}")
        print("="*100)

        found_results = False

        async def check_dir(directory):
            nonlocal found_results
            try:
                if self.shutdown:
                    return

                test_url = f"{base_url}/{directory}"
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
            except asyncio.CancelledError:
                pass
            except Exception as e:
                if self.verbose:
                    self.print_status(
                        f"Directory check error for {directory}: {e}", "error")

        # Process directories in batches to avoid overwhelming the server
        batch_size = CONFIG["THREADS"]
        for i in range(0, len(dirs), batch_size):
            if self.shutdown:
                break
                
            batch = dirs[i:i+batch_size]
            tasks = [check_dir(directory) for directory in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

        if not found_results:
            self.print_status("No accessible directories found", "warning")

        print("="*100)

    def get_default_directories(self):
        """Return a list of common directories to test"""
        return [
            "", "admin", "login", "wp-admin", "wp-login", "administrator",
            "backend", "secure", "private", "test", "api", "console",
            "admin.php", "login.php", "admin.asp", "login.asp",
            "admin.aspx", "login.aspx", "admin.cgi", "login.cgi",
            "admin.html", "login.html", "admin.htm", "login.htm",
            "config", "backup", "backups", "db", "database", "sql",
            "include", "includes", "inc", "lib", "library", "src",
            "source", "uploads", "upload", "download", "downloads",
            "images", "img", "css", "js", "assets", "static", "media",
            "cgi-bin", "cgi", "bin", "scripts", "script", "tools",
            "tool", "web", "webapp", "app", "apps", "application",
            "tmp", "temp", "cache", "logs", "log", "error", "errors",
            "debug", "test", "testing", "demo", "example", "samples",
            "doc", "docs", "documentation", "help", "support",
            "phpmyadmin", "myadmin", "pma", "mysql", "phpinfo",
            "info", "status", "server-status", "server-info"
        ]

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

        wordlist_path = self.get_wordlist_path("PARAMS")
        if wordlist_path:
            with open(wordlist_path, 'r') as f:
                params = [line.strip() for line in f if line.strip()]
        else:
            params = ["id", "page", "view", "file",
                      "search", "query", "user", "name"]
            self.print_status("Using built-in common parameters", "info")

        vulnerable_params = []

        async def check_param(param):
            try:
                if self.shutdown:
                    return

                test_url = f"{url}?{param}=test"
                response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])

                if response and response['status'] == 200 and "test" in response['text']:
                    vulnerable_params.append(param)
                    self.print_status(f"Parameter found: {param}", "success")
            except asyncio.CancelledError:
                pass
            except Exception as e:
                if self.verbose:
                    self.print_status(
                        f"Parameter check error for {param}: {e}", "error")

        # Process parameters in batches
        batch_size = CONFIG["THREADS"]
        for i in range(0, len(params), batch_size):
            if self.shutdown:
                break
                
            batch = params[i:i+batch_size]
            tasks = [check_param(param) for param in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

        if vulnerable_params:
            self.print_status(
                f"Discovered parameters: {', '.join(vulnerable_params)}", "success")
        else:
            self.print_status("No parameters discovered", "warning")

        return vulnerable_params

    async def advanced_sqli_scan(self, url):
        self.print_status("Running advanced SQL injection tests...", "info")

        wordlist_path = self.get_wordlist_path("SQLI")
        if wordlist_path:
            with open(wordlist_path, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        else:
            payloads = [
                "'", "\"", "`", "'--", "\"--", "`--", "' OR '1'='1", "\" OR \"1\"=\"1",
                "' OR 1=1--", "\" OR 1=1--", "' OR 1=1#", "\" OR 1=1#", "' OR 1=1/*"
            ]
            self.print_status("Using built-in SQLi payloads", "info")

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                if self.shutdown:
                    return

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
            except asyncio.CancelledError:
                pass
            except Exception as e:
                if self.verbose:
                    self.print_status(f"SQLi test error: {e}", "error")

        # Limit payloads unless aggressive mode
        test_payloads = payloads[:50] if not self.aggressive else payloads

        # Run tests with limited concurrency
        batch_size = min(CONFIG["THREADS"], 10)  # Further limit SQLi tests
        for i in range(0, len(test_payloads), batch_size):
            if self.shutdown:
                break
                
            batch = test_payloads[i:i+batch_size]
            tasks = [test_payload(payload) for payload in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

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

        wordlist_path = self.get_wordlist_path("XSS")
        if wordlist_path:
            with open(wordlist_path, 'r') as f:
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
            self.print_status("Using built-in XSS payloads", "info")

        vulnerable = False

        async def test_payload(payload):
            nonlocal vulnerable
            try:
                if self.shutdown:
                    return

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
            except asyncio.CancelledError:
                pass
            except Exception as e:
                if self.verbose:
                    self.print_status(f"XSS test error: {e}", "error")

        # Process payloads in batches
        batch_size = CONFIG["THREADS"]
        for i in range(0, len(payloads), batch_size):
            if self.shutdown:
                break
                
            batch = payloads[i:i+batch_size]
            tasks = [test_payload(payload) for payload in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

        if not vulnerable:
            self.print_status("No XSS vulnerabilities detected", "success")

    async def test_headers(self, url):
        try:
            if self.shutdown:
                return

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
                    if header == 'X-Frame-Options' and value != 'deny' and 'sameorigin' not in value:
                        insecure.append(
                            f"{header}: {headers[header]} (should be 'DENY' or 'SAMEORIGIN')")
                    elif header == 'X-Content-Type-Options' and value != 'nosniff':
                        insecure.append(
                            f"{header}: {headers[header]} (should be 'nosniff')")

            if missing:
                self.print_status(
                    f"Missing security headers: {', '.join(missing)}", "warning")
                self.vulnerabilities.append({
                    "type": "Missing Security Headers",
                    "url": url,
                    "payload": None,
                    "evidence": f"Missing: {', '.join(missing)}"
                })

            if insecure:
                for issue in insecure:
                    self.print_status(
                        f"Insecure header configuration: {issue}", "warning")
                    self.vulnerabilities.append({
                        "type": "Insecure Security Header",
                        "url": url,
                        "payload": None,
                        "evidence": issue
                    })

            if not missing and not insecure:
                self.print_status(
                    "All security headers properly configured", "success")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print_status(f"Header test error: {e}", "error")

    async def test_csrf(self, url):
        try:
            if self.shutdown:
                return

            response = await self.async_request('GET', url, timeout=CONFIG["TIMEOUT"])
            if not response:
                return

            soup = BeautifulSoup(response['text'], 'html.parser')
            vulnerable_forms = []

            for form in soup.find_all('form'):
                if self.shutdown:
                    break

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
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print_status(f"CSRF test error: {e}", "error")

    async def test_cors(self, url):
        try:
            if self.shutdown:
                return

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
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print_status(f"CORS test error: {e}", "error")

    async def test_clickjacking(self, url):
        try:
            if self.shutdown:
                return

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
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print_status(f"Clickjacking test error: {e}", "error")

    async def test_cookies(self, url):
        try:
            if self.shutdown:
                return

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
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print_status(f"Cookie test error: {e}", "error")

    async def test_http_methods(self, url):
        try:
            if self.shutdown:
                return

            methods = ['GET', 'POST', 'PUT', 'DELETE', 'TRACE', 'OPTIONS']
            allowed_methods = []

            for method in methods:
                try:
                    if self.shutdown:
                        break
                    response = await self.async_request(method, url, timeout=CONFIG["TIMEOUT"])
                    if response and response['status'] != 405:
                        allowed_methods.append(method)
                except asyncio.CancelledError:
                    break
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
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print_status(f"HTTP methods test error: {e}", "error")

    async def test_info_disclosure(self, url):
        try:
            if self.shutdown:
                return

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
                if self.shutdown:
                    return
                test_url = urljoin(url, file)
                try:
                    file_response = await self.async_request('GET', test_url, timeout=CONFIG["TIMEOUT"])
                    if file_response and file_response['status'] == 200:
                        disclosures.append(f"Exposed file: {test_url}")
                except asyncio.CancelledError:
                    pass
                except:
                    pass

            tasks = [check_file(file) for file in common_files]
            await asyncio.gather(*tasks, return_exceptions=True)

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
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print_status(
                f"Information disclosure test error: {e}", "error")

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
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug output")
    args = parser.parse_args()

    if args.url:
        url = args.url
    else:
        try:
            url = input(
                "Enter target URL (with or without http/https): ").strip()
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            sys.exit(0)

    scanner = WebScanner(verbose=args.verbose,
                         aggressive=args.aggressive, debug=args.debug)
    scanner.scan(url)


if __name__ == "__main__":
    main()
