# HackTheBox: Bug Bounty Methodology

This document outlines a practical methodology for bug bounty hunting, focusing on common techniques and tools used to discover vulnerabilities in web applications. This is designed to be a comprehensive guide for beginners and intermediate hunters.

## 1. Reconnaissance Phase (Information Gathering)

Reconnaissance is the most crucial phase in bug bounty hunting. The more information you gather, the higher your chances of finding vulnerabilities.

### 1.1. Subdomain Enumeration
Discovering subdomains helps expand the attack surface. Many vulnerabilities reside in forgotten or less-maintained subdomains.

- **Passive Subdomain Enumeration**: Using public sources like Certificate Transparency logs, DNS records, and third-party services.
  - *Tools*: `assetfinder`, `subfinder`, `crt.sh`, `VirusTotal`.
  ```bash
  # Discover subdomains and check for live hosts
  assetfinder --subs-only example.com | httprobe -c 50 -t 3000 | tee live_subdomains.txt
  subfinder -d example.com -o subdomains.txt
  ```
- **Brute-force Subdomain Enumeration**: Using wordlists to guess subdomains.
  - *Tools*: `ffuf`, `gobuster`, `dnsenum`.
  ```bash
  # FFUF for subdomain brute-forcing
  ffuf -w /path/to/wordlist.txt -u https://FUZZ.example.com -mc 200 -ac
  ```

### 1.2. Port Scanning & Service Discovery
Identify open ports and services on discovered IP addresses and subdomains.

- *Tools*: `nmap`
  ```bash
  # Nmap scan for common web ports on a list of hosts
  nmap -iL live_subdomains.txt -p 80,443,8000,8080,8443 -sC -sV -oA web_ports_scan
  ```

### 1.3. Technology Stack Identification
Understanding the technologies used (web servers, frameworks, programming languages, CMS) helps in identifying known vulnerabilities.

- *Tools*: `Wappalyzer` (browser extension), `whatweb`, `builtwith`.
  ```bash
  # Identify technologies used on a target URL
  whatweb example.com
  ```

### 1.4. Content Discovery
Find hidden directories, files, backup files, and sensitive endpoints.

- *Tools*: `gobuster`, `dirsearch`, `ffuf`.
  ```bash
  # Dirsearch for directory brute-forcing
  dirsearch -u http://example.com -e php,html,js,bak,old,zip -t 50 -w /path/to/wordlist.txt
  ```

## 2. Vulnerability Scanning (Automated)

Automated scanners can quickly identify low-hanging fruit and common misconfigurations. They are a good starting point but should always be followed by manual testing.

- **Web Vulnerability Scanners**:
  - **Burp Suite Professional (Scanner)**: An industry-standard tool with an integrated scanner for passive and active scanning. Highly recommended for web application testing.
  - **OWASP ZAP**: Free and open-source web application security scanner. Good for beginners.
  - **Nuclei**: A fast and customizable vulnerability scanner based on simple YAML-based templates. Excellent for identifying known vulnerabilities and misconfigurations.
  ```bash
  # Scan with Nuclei for common web vulnerabilities
  nuclei -u http://example.com -t /path/to/nuclei-templates/http/exposed-panels/
  ```
- **API Scanners**: Tools like Postman (with Newman for automation) can be used for API testing, or specialized API security scanners.

## 3. Manual Testing (Deep Dive)

Manual testing is where the real skill of a bug bounty hunter shines. It involves understanding application logic and creatively identifying vulnerabilities that automated tools might miss.

### 3.1. Common Web Vulnerabilities & Techniques

1.  **SQL Injection (SQLi)**: Manipulating database queries to extract or modify data.
    - *Techniques*: Union-based, Error-based, Time-based Blind, Boolean-based Blind, Out-of-band.
    - *Payload Examples*:
      ```sql
      ' OR 1=1-- -
      " OR 1=1-- -
      ' UNION SELECT NULL,database(),NULL-- -
      ```
    - *Tools*: `sqlmap` (for automation), Burp Suite (manual testing).

2.  **Cross-Site Scripting (XSS)**: Injecting malicious client-side scripts into web pages viewed by other users.
    - *Types*: Reflected, Stored, DOM-based.
    - *Payload Examples*:
      ```html
      <script>alert(document.domain)</script>
      <img src=x onerror=alert(1)>
      ```
    - *Techniques*: Context analysis, bypassing filters, HTML entity encoding.

3.  **Server-Side Request Forgery (SSRF)**: A web security vulnerability that allows an attacker to cause the server-side application to make an HTTP request to an arbitrary domain of the attacker's choosing.
    - *Payload Examples*:
      ```http
      http://localhost/admin
      file:///etc/passwd
      http://169.254.169.254/latest/meta-data/ # AWS metadata
      ```
    - *Techniques*: URL parsing tricks, bypassing blacklists, open redirects.

4.  **Insecure Direct Object References (IDOR)**: Accessing resources (e.g., user accounts, files) by manipulating parameters that directly reference objects.
    - *Techniques*: Changing numerical IDs, UUIDs, or file names in URLs/requests.
    - *Example*: Changing `?id=123` to `?id=124` to access another user's data.

5.  **Broken Access Control**: Flaws in the enforcement of authorization. Users can perform actions they are not authorized for.
    - *Techniques*: Horizontal privilege escalation (user A accesses user B's data), Vertical privilege escalation (low-privileged user accesses admin functions).
    - *Example*: Accessing `/admin` endpoint as a regular user.

6.  **Cross-Site Request Forgery (CSRF)**: Forcing an authenticated user to submit a request to a web application against their will.
    - *Techniques*: Crafting malicious HTML/JS, checking for anti-CSRF tokens.

7.  **XML External Entity (XXE) Injection**: Vulnerabilities arising from insecure parsing of XML input.
    - *Techniques*: Retrieving local files, performing SSRF, port scanning internal networks.

8.  **File Inclusion (LFI/RFI)**: Including local or remote files on the server.
    - *Techniques*: Path traversal (`../../etc/passwd`), null byte injection, wrapper usage.

## 4. Reporting (Critical Phase)

A well-written report is essential for a bug bounty submission to be accepted and rewarded. Clarity, reproducibility, and impact are key.

### 4.1. Essential Elements of a Good Report

-   **Vulnerability Title**: Clear, concise, and descriptive (e.g., "Reflected XSS on Search Function").
-   **Vulnerability Type**: Categorize the vulnerability (e.g., XSS, SQLi, IDOR).
-   **Severity/Impact**: Explain the potential damage if the vulnerability is exploited. Use CVSS scoring if applicable.
    -   *Example*: "High - Allows an attacker to execute arbitrary JavaScript in the victim's browser, leading to session hijacking or defacement."
-   **Affected URL(s)**: Provide the exact URLs where the vulnerability was found.
-   **Steps to Reproduce**: A clear, step-by-step guide that allows the program to replicate the vulnerability easily.
    -   Include HTTP requests (from Burp Suite), parameters, and any necessary preconditions.
    -   Use code blocks for clarity.
-   **Proof of Concept (PoC)**: Screenshots, videos, or code snippets demonstrating the vulnerability.
-   **Remediation/Recommendation**: Suggest how the vulnerability can be fixed. This shows your understanding of security best practices.
    -   *Example*: "Implement proper input validation and output encoding for all user-supplied data to prevent XSS."
-   **Tools Used**: List the tools you used to find and verify the vulnerability.

## 5. Tools Cheatsheet

| Tool | Purpose | Key Features |
|------|---------|--------------|
| **Burp Suite** | Web application penetration testing suite | Intercepting Proxy, Repeater, Intruder, Scanner, Decoder, Comparer. Essential for manual testing. |
| **SQLmap** | Automated SQL injection and database takeover tool | Detects and exploits various SQLi types, database enumeration, file read/write. |
| **FFUF** | Fast web fuzzer | Directory/file brute-forcing, virtual host discovery, parameter fuzzing, content discovery. |
| **Subfinder/Assetfinder** | Subdomain discovery tools | Passive subdomain enumeration from various sources. |
| **Nmap** | Network scanner | Port scanning, service version detection, OS detection, vulnerability scripting. |
| **Dirsearch** | Web path scanner | Brute-forces directories and files on web servers. |
| **Nuclei** | Fast and customizable vulnerability scanner | Template-based scanning for known vulnerabilities and misconfigurations. |
| **Postman** | API development and testing | Used for sending custom HTTP requests, testing REST APIs. |
| **Dnsenum** | DNS enumeration tool | Gathers DNS information, including host addresses, mail servers, and name servers. |
| **Wappalyzer** | Technology profiler | Browser extension to identify web technologies used on websites. |

## 6. Continuous Learning & Practice

Bug bounty hunting is an ever-evolving field. Continuous learning is key to success.

-   **Practice Platforms**: Hack The Box, TryHackMe, PortSwigger Web Security Academy.
-   **Read Writeups**: Learn from other hunters' successful reports.
-   **Stay Updated**: Follow security blogs, news, and researchers on Twitter.
-   **Build Your Own Labs**: Set up vulnerable applications to practice on.

Good luck and happy hunting!
