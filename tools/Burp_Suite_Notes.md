# Burp Suite: The Complete Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation & Setup](#installation--setup)
3. [Core Tools](#core-tools)
   - [Proxy](#1-proxy)
   - [Target](#2-target)
   - [Scanner](#3-scanner-professional)
   - [Intruder](#4-intruder)
   - [Repeater](#5-repeater)
   - [Sequencer](#6-sequencer)
   - [Decoder](#7-decoder)
   - [Comparer](#8-comparer)
   - [Extender](#9-extender)
4. [Advanced Features](#advanced-features)
5. [Burp Suite Extensions (BApps)](#burp-suite-extensions-bapps)
6. [Workflows & Methodologies](#workflows--methodologies)
7. [Troubleshooting & Optimization](#troubleshooting--optimization)
8. [Pro Tips & Best Practices](#pro-tips--best-practices)
9. [Real-World Examples](#real-world-examples)
10. [Resources & References](#resources--references)

## Introduction

Burp Suite is an integrated platform for performing security testing of web applications. Developed by PortSwigger, it has become the industry standard for web application security testing, used by security professionals worldwide for manual and automated testing.

### Key Features
- **Intercepting Proxy**: View and modify all HTTP/S traffic
- **Web Vulnerability Scanner**: Automated detection of security issues (Pro version)
- **Advanced Manual Testing Tools**: For in-depth analysis
- **Extensibility**: Support for custom extensions (BApps)
- **Collaboration**: Project files for team-based testing
- **Session Handling**: Advanced session management capabilities

## Installation & Setup

### System Requirements
- **OS**: Windows, macOS, Linux
- **Java**: JRE 11 or later
- **RAM**: Minimum 8GB (16GB+ recommended for large applications)
- **Disk Space**: 1GB free space

### Installation Steps
1. **Download** the appropriate version from [PortSwigger](https://portswigger.net/burp/releases)
2. **Install** following the wizard (Windows/macOS) or extract the JAR (Linux)
3. **Launch** using the desktop shortcut or via command line:
   ```bash
   java -jar burpsuite_community.jar
   ```
4. **Configure** your browser to use Burp's proxy (default: 127.0.0.1:8080)
5. **Install** Burp's CA certificate to intercept HTTPS traffic

### Initial Configuration
1. **Project Options**: Set up project-specific settings
2. **User Options**: Configure global preferences
3. **Proxy Listeners**: Manage proxy interfaces/ports
4. **Sessions**: Configure session handling rules
5. **Scope**: Define target scope for testing

## Core Tools

### 1. Proxy

#### Intercepting Requests/Responses
- **Intercept On/Off**: Toggle request interception
- **Forward/Back**: Navigate through intercepted items
- **Action**: Access context menu for additional options
- **Intercept Client Requests/Responses**: Fine-tune what gets intercepted

#### Proxy Options
- **Intercept**: Configure interception rules
- **HTTP History**: View all captured traffic
- **WebSockets**: Monitor WebSocket connections
- **Options**: Configure proxy listeners, response modification, etc.

#### Practical Example: Modifying Requests
1. Intercept a login request
2. Change credentials or parameters
3. Forward to server and observe response

### 2. Target

#### Site Map
- **Contents**: Tree view of discovered content
- **Issues**: Automatically identified vulnerabilities
- **Filter**: Narrow down results by various criteria

#### Scope
- **Target Scope**: Define what's in/out of scope
- **Exclude from Scope**: Items to explicitly exclude
- **Advanced Scope Control**: Fine-grained scope rules

### 3. Scanner (Professional)

#### Scan Configuration
- **Crawl Strategy**: Control how the scanner navigates
- **Audit Checks**: Select which vulnerability checks to run
- **Resource Pools**: Manage system resource allocation

#### Scan Types
- **Active Scanning**: Actively probe for vulnerabilities
- **Passive Scanning**: Analyze traffic without sending test cases
- **Crawl-Only**: Just map the application without testing

### 4. Intruder

#### Attack Types
- **Sniper**: Single parameter fuzzing
- **Battering Ram**: Same payload to multiple positions
- **Pitchfork**: Multiple parameter sets in parallel
- **Cluster Bomb**: All combinations of multiple payload sets

#### Payloads
- **Simple List**: Basic wordlist
- **Runtime File**: Load from external file
- **Custom Iterator**: Build complex payloads
- **Character Substitution**: Automatic case variations
- **Recursive Grep**: Extract data from responses

#### Practical Example: Brute-Forcing Login
1. Capture login request with Burp Proxy
2. Send to Intruder
3. Set attack type to "Pitchfork"
4. Set username and password as parameters
5. Load username and password wordlists
6. Start attack and analyze results

### 5. Repeater

#### Features
- **Request/Response Views**: Multiple formats (Raw, Params, Headers, etc.)
- **History**: Track request modifications
- **Compare**: Side-by-side response comparison
- **Match/Replace**: Automatic request modifications

#### Practical Example: Testing for SQLi
1. Capture request with vulnerable parameter
2. Send to Repeater
3. Add single quote (') to parameter
4. Send request and analyze response for errors
5. Try Boolean-based tests: `' AND 1=1--` / `' AND 1=2--`

### 6. Sequencer

#### Analysis Types
- **Live Capture**: Real-time token analysis
- **Manual Load**: Analyze saved tokens
- **Token Location**: Where to find tokens (Cookies, Headers, etc.)

#### Statistical Tests
- **Character-Level Analysis**: Per-character randomness
- **Bit-Level Analysis**: Bit-level entropy
- **FIPS 140-2**: Compliance testing

### 7. Decoder

#### Encoding/Decoding
- **URL**: URL encoding/decoding
- **HTML**: HTML entity encoding
- **Base64**: Encode/decode Base64
- **Hex**: Hexadecimal conversion
- **Hashing**: Multiple hash algorithms
- **Smart Decode**: Automatic detection

### 8. Comparer

#### Comparison Types
- **Words**: Word-level diff
- **Bytes**: Byte-level diff
- **Response Comparison**: Side-by-side HTTP responses

### 9. Extender

#### BApp Store
- **Vulnerability Scanners**: Additional security checks
- **Utilities**: Helper tools
- **Integration**: Connect with other tools

#### Java/Python Extensions
- **API Documentation**: Available on PortSwigger website
- **Example Extensions**: Custom scanners, UI modifications

## Advanced Features

### 1. Macros
- **Recording**: Capture login sequences
- **Configuration**: Set parameters and extraction rules
- **Session Handling**: Use macros for session-dependent testing

### 2. Session Handling Rules
- **Scope**: Define when rules apply
- **Actions**: What to do with matching requests
- **Cookie Jar**: Automatic cookie management

### 3. Project Files
- **Save/Load**: Save your work
- **Collaboration**: Share with team members
- **Versioning**: Track changes over time

### 4. Command Line Options
```bash
java -jar burpsuite_pro.jar --project-file=project.burp --config-file=config.json
```

## Burp Suite Extensions (BApps)

### Must-Have Extensions
1. **Param Miner**: Find hidden parameters
2. **Authz**: Test authorization issues
3. **ActiveScan++**: Enhanced scanning capabilities
4. **Turbo Intruder**: High-speed fuzzing
5. **Logger++**: Enhanced logging
6. **J2EEScan**: Java EE specific tests
7. **Retire.js**: Detect vulnerable JavaScript libraries

### Installing Extensions
1. Go to Extender > BApp Store
2. Find desired extension
3. Click "Install"
4. Configure if needed

## Workflows & Methodologies

### 1. Initial Reconnaissance
1. Configure scope
2. Spider the application
3. Review site map
4. Identify key functionality

### 2. Automated Scanning
1. Run passive scan
2. Review results
3. Run active scan on key areas
4. Verify findings manually

### 3. Manual Testing
1. Map all functionality
2. Test each input vector
3. Verify automated findings
4. Look for logic flaws

### 4. Authentication Testing
1. Test account creation
2. Test login/logout
3. Test password reset
4. Test session management

## Troubleshooting & Optimization

### Common Issues
1. **HTTPS not working**: Install Burp's CA certificate
2. **Slow performance**: Adjust proxy settings, increase memory
3. **Scanner stuck**: Check for infinite redirects, adjust scope

### Performance Optimization
- Increase JVM heap size:
  ```bash
  java -Xmx4G -jar burpsuite_pro.jar
  ```
- Use fewer threads in active scanner
- Configure scope precisely
- Use filters to reduce noise

## Pro Tips & Best Practices

1. **Always work with a methodology**
2. **Document everything**
3. **Use project files**
4. **Create custom wordlists**
5. **Master keyboard shortcuts**
6. **Use macros for complex workflows**
7. **Regularly update Burp and extensions**
8. **Understand false positives/negatives**
9. **Combine automated and manual testing**
10. **Keep learning new features**

## Real-World Examples

### Example 1: Finding IDOR
1. Map application functionality
2. Identify object references in URLs/parameters
3. Test for unauthorized access
4. Document the finding with proof

### Example 2: XSS Discovery
1. Find all input vectors
2. Test with basic XSS payloads
3. Bypass filters if needed
4. Document impact and reproduction steps

## Resources & References

### Official Documentation
- [PortSwigger Documentation](https://portswigger.net/burp/documentation)
- [Web Security Academy](https://portswigger.net/web-security)

### Training
- [PortSwigger Training](https://portswigger.net/training)
- [Web Security Academy Labs](https://portswigger.net/web-security/all-labs)

### Community
- [PortSwigger Community Edition](https://portswigger.net/burp/communitydownload)
- [GitHub Repositories](https://github.com/portswigger)
- [Burp Suite Forum](https://forum.portswigger.net/)

### Books
- "The Web Application Hacker's Handbook"
- "Black Hat Python"
- "Web Application Security"

### Blogs
- [PortSwigger Blog](https://portswigger.net/blog)
- [HackTricks](https://book.hacktricks.xyz/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
