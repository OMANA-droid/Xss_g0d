# Xss_g0d Scanner Tool

A Python-based automated scanner for detecting Cross-Site Scripting (XSS) vulnerabilities, including reflected, DOM-based, and stored XSS. Designed for penetration testers, bug bounty hunters, and security researchers to efficiently find XSS issues across URLs and their parameters.

---

## Features

- **Reflection-based XSS Detection:** Tests common URL parameters with various XSS payloads.
- **DOM-based XSS Detection:** Searches for dangerous DOM sinks like `innerHTML`, `document.write`, `eval`, etc.
- **Stored XSS Detection:** Sends POST requests with payloads to common form parameters to find stored vulnerabilities.
- **Optional Link Crawling:** Automatically crawls internal links for deeper scanning.
- **Subdomain Enumeration (planned):** Placeholder for integrating subdomain enumeration.
- Outputs findings with detailed parameter and payload info.
- Save results to JSON file for later review.

---

## Requirements

- Python 3.7+
- `requests`
- `beautifulsoup4`

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Xss_g0d.git
   cd Xss_g0d

2. (Recommended) Create a virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows

3. install dependencies:
   ```bash
   pip install -r requirements.txt

4. Command 
   ```bash
   python3 Xss_g0d.py --url https://example.com

5. Available command line options:

   
    --url (required) : Target URL to scan

    --subdomains : Include subdomain enumeration (currently placeholder)
  
    --crawl : Enable crawling for additional internal links to scan

    --depth : Depth of crawling (default: 1)

    --output : Save findings to specified JSON output file

   

 ## Examples

   
  Scan a single URL:
    
   ```bash
    python3 Xss_g0d.py --url https://example.com   
 ```



Scan URL and crawl internal links to depth 2:
   
  ```bash
         python3 Xss_g0d.py --url https://example.com --crawl --depth 2
 ```

  ## Notes
  
    Make sure to run with permission on authorized targets only.

    Crawling depth may increase scan time significantly.

    Subdomain enumeration is a placeholder and requires implementation.

  ## Acknowledgments
  
  Created by OMANA-droid. Inspired by open-source XSS scanning tools.
