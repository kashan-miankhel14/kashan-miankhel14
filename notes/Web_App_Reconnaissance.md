# Web Application Reconnaissance Techniques

Web application reconnaissance is a critical first step in bug bounty hunting and web penetration testing. It involves gathering as much information as possible about the target web application to identify potential attack vectors.

## 1. Scope Definition

Clearly understand the target scope provided by the bug bounty program or client. This includes:
-   Allowed domains/subdomains
-   Out-of-scope assets
-   Specific types of vulnerabilities allowed/disallowed

## 2. Passive Reconnaissance

Gathering information without directly interacting with the target web server. This minimizes the risk of detection.

### 2.1. DNS Enumeration

-   **WHOIS**: Check domain registration details.
-   **DNS Records**: Look for A, AAAA, CNAME, MX, NS, TXT records.
    -   *Tools*: `dig`, `nslookup`, `host`, online DNS lookup tools.
-   **Subdomain Enumeration**: Identify all subdomains associated with the target.
    -   *Techniques*: Certificate Transparency logs (`crt.sh`), public DNS records, search engines, brute-forcing.
    -   *Tools*: `assetfinder`, `subfinder`, `findomain`, `amass`, `gobuster` (with `-mode dns`).
    ```bash
    assetfinder --subs-only example.com | tee subdomains_passive.txt
    subfinder -d example.com -o subdomains_subfinder.txt
    ```

### 2.2. OSINT (Open Source Intelligence)

Leveraging publicly available information.

-   **Search Engines (Google Dorking)**: Use advanced search operators to find sensitive files, error messages, login pages, etc.
    -   *Examples*: `site:example.com intitle:"index of"`, `site:example.com filetype:pdf confidential`.
-   **Social Media**: Look for employee profiles, company announcements, leaked information.
-   **Code Repositories**: GitHub, GitLab, Bitbucket for leaked credentials, API keys, sensitive configuration files.
    -   *Tools*: `trufflehog`, `git-dumper`.
-   **Wayback Machine / Archive.org**: View historical versions of websites to find old pages, forgotten endpoints, or sensitive information that was later removed.
    -   *Tools*: `waybackurls`.
    ```bash
    waybackurls example.com | tee wayback_urls.txt
    ```
-   **Shodan / Censys**: Search for internet-connected devices, open ports, banners, and vulnerabilities.
    -   *Examples*: `http.title:"example.com"`, `port:8080 country:US`.

### 2.3. Technology Stack Identification

Identify web servers, frameworks, programming languages, CMS, and other technologies.

-   *Tools*: `Wappalyzer` (browser extension), `BuiltWith` (browser extension), `whatweb`.
    ```bash
    whatweb example.com
    ```

## 3. Active Reconnaissance

Interacting directly with the target web server. This carries a higher risk of detection but provides more accurate and real-time data.

### 3.1. Port Scanning

Identify open ports and services on the target web server.

-   *Tools*: `nmap`
    ```bash
    # Scan common web ports
    nmap -p 80,443,8000,8080,8443 -sC -sV -oA web_scan example.com
    ```

### 3.2. Directory and File Enumeration (Content Discovery)

Discover hidden directories, files, backup files, and sensitive endpoints that are not linked from the main website.

-   *Tools*: `gobuster`, `dirsearch`, `ffuf`.
    ```bash
    # Gobuster for directory brute-forcing
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -x php,html,js,bak,old,zip,txt,json --no-error

    # FFUF for advanced content discovery (e.g., virtual hosts, parameter fuzzing)
    ffuf -w /path/to/wordlist.txt -u http://example.com/FUZZ -mc 200,301,302,403 -ac
    ```
-   **VHost Enumeration**: Identify virtual hosts hosted on the same IP address.
    -   *Tools*: `ffuf` (with `Host` header fuzzing).
-   **Parameter Discovery**: Identify hidden or undocumented parameters.
    -   *Tools*: `Arjun`, `ParamMiner` (Burp Suite extension).

### 3.3. Web Application Crawling

Automatically traverse the web application to discover all accessible pages and links.

-   *Tools*: `Burp Suite (Spider)`, `OWASP ZAP (Spider)`, `wget` (recursive download).

### 3.4. Manual Exploration

Manually browse the web application, clicking on every link, testing every input field, and observing responses. Pay attention to:

-   **URL Structure**: Look for predictable patterns, parameters.
-   **HTTP Headers**: Security headers, cookies, server information.
-   **Error Messages**: Detailed error messages can leak sensitive information.
-   **Comments in Source Code**: Developers often leave comments with useful information.
-   **JavaScript Files**: Analyze JS files for API endpoints, sensitive data, or hidden functionalities.
-   **Forms**: Test all input fields for various injection types.

## 4. API Reconnaissance

If the application uses APIs, dedicate time to understanding and enumerating them.

-   **API Endpoints**: Look for `/api/v1/`, `/rest/`, etc.
-   **API Documentation**: Swagger/OpenAPI docs can reveal all endpoints and parameters.
-   **Tools**: `Postman`, `Insomnia`, `Burp Suite`.

## 5. Advanced Techniques

-   **Cloud Recon**: Identify if the target uses cloud services (AWS, Azure, GCP) and look for misconfigurations (e.g., exposed S3 buckets).
-   **Mobile Application Analysis**: If a mobile app exists, decompile the APK/IPA to find hardcoded credentials, API keys, or hidden endpoints.
-   **WebSockets**: Analyze WebSocket communication for vulnerabilities.
-   **Deserialization**: Look for insecure deserialization vulnerabilities if the application uses Java, .NET, Python, etc.

## 6. Documentation

Keep detailed notes of all findings, tools used, and potential attack vectors. This helps in organizing your thoughts and preparing for exploitation and reporting.
