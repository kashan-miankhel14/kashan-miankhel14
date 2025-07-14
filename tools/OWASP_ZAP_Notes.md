# OWASP ZAP: The Complete Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation & Setup](#installation--setup)
3. [Core Components](#core-components)
   - [Heads Up Display (HUD)](#1-heads-up-display-hud)
   - [Manual Request Editor](#2-manual-request-editor)
   - [Automated Scanner](#3-automated-scanner)
   - [Passive Scanner](#4-passive-scanner)
   - [Spider](#5-spider)
   - [AJAX Spider](#6-ajax-spider)
   - [Fuzzer](#7-fuzzer)
   - [Forced Browse](#8-forced-browse)
   - [Port Scanner](#9-port-scanner)
   - [Sequence](#10-sequence)
   - [WebSocket](#11-websocket)
   - [Breakpoints](#12-breakpoints)
   - [Scripting](#13-scripting)
4. [Advanced Features](#advanced-features)
5. [Add-ons & Extensions](#add-ons--extensions)
6. [Automation & API](#automation--api)
7. [Best Practices](#best-practices)
8. [Real-World Scenarios](#real-world-scenarios)
9. [Troubleshooting](#troubleshooting)
10. [Resources & References](#resources--references)

## Introduction

OWASP Zed Attack Proxy (ZAP) is one of the world's most popular free security tools and is actively maintained by hundreds of international volunteers. It's designed specifically for testing web applications and is ideal for both beginners and experienced penetration testers.

### Key Features
- **Completely Free and Open Source**
- **Cross-Platform** (Windows, Linux, macOS)
- **Easy to Install** (No runtime dependencies)
- **Comprehensive** (All major web security testing features)
- **Internationalization Support** (20+ languages)
- **Extensible** (Numerous add-ons available)
- **Scriptable** (Multiple scripting languages supported)
- **Headless Support** (For CI/CD integration)

## Installation & Setup

### System Requirements
- **OS**: Windows, macOS, Linux, or Docker
- **Java**: Java 8 or later (included in Windows installer)
- **RAM**: 2GB minimum (4GB+ recommended)
- **Disk Space**: 500MB free space

### Installation Methods

#### Windows/macOS
1. Download the installer from [OWASP ZAP Downloads](https://www.zaproxy.org/download/)
2. Run the installer and follow the wizard
3. Launch ZAP from the desktop shortcut or Start Menu/Applications

#### Linux (Debian/Ubuntu)
```bash
# Add the ZAP repository
sudo apt update && sudo apt install -y software-properties-common
sudo add-apt-repository ppa:zaproxy/stable

# Install ZAP
sudo apt update
sudo apt install -y zaproxy
```

#### Docker
```bash
docker pull owasp/zap2docker-stable
docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable zap-webswing
```

### Initial Configuration
1. **First Run Wizard**: Configure proxy settings and create a new session
2. **HTTPS Support**: Install the ZAP Root CA certificate in your browser
3. **Update Add-ons**: Go to `Help` > `Check for Updates`
4. **Configure Browser Proxy**: Set to `127.0.0.1:8080` (default ZAP proxy)
5. **Set Up Contexts**: Define your target scope in `Sites` > `Right-click` > `Add to Context`

## Core Components

### 1. Heads Up Display (HUD)
A revolutionary interface that provides guidance and enables you to do security testing in your browser.

**Key Features**:
- **Learn as you test**: Contextual help and guidance
- **Quick Start**: One-click access to common tasks
- **Heads Up Display**: Shows security information directly in the browser
- **Training Mode**: Step-by-step guidance for beginners

**Example Workflow**:
1. Enable HUD mode from the ZAP desktop
2. Configure your browser to use ZAP's proxy
3. Browse your target application
4. Use the HUD interface to perform security tests

### 2. Manual Request Editor
Allows you to manually craft and send HTTP/HTTPS requests.

**Features**:
- Raw request editing
- Support for all HTTP methods
- Request history
- Tabbed interface for multiple requests

**Example: Manual SQL Injection Test**
```http
GET /products.php?id=1' OR '1'='1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
Connection: close
```

### 3. Automated Scanner
Performs active vulnerability scanning against web applications.

**Scan Types**:
- **Active Scan**: Actively probes for vulnerabilities
- **Spider Scan**: Discovers URLs and content
- **AJAX Spider**: Handles JavaScript-heavy applications
- **User-Defined Scans**: Customize scan policies

**Best Practices**:
1. Always run a spider first to discover content
2. Review the site structure before active scanning
3. Use appropriate scan policies
4. Be mindful of scan impact on production systems

### 4. Passive Scanner
Automatically analyzes all requests and responses for potential vulnerabilities.

**Detects**:
- Insecure cookies
- Missing security headers
- Information disclosure
- Cross-domain policy issues
- Mixed content
- And many more...

### 5. Spider
Traditional web crawler that discovers URLs by following links in HTML responses.

**Usage**:
- Right-click on a site in the Sites tree
- Select `Attack` > `Spider...`
- Configure options (recursion, max children, etc.)
- Click `Start Scan`

### 6. AJAX Spider
Specialized crawler for JavaScript-heavy applications using a real browser.

**Features**:
- Based on Selenium
- Handles dynamic content
- Supports multiple browsers
- Configurable click depth and timeouts

### 7. Fuzzer
Tests for vulnerabilities by sending large numbers of malicious requests.

**Payload Types**:
- File fuzzing
- Number fuzzing
- Character fuzzing
- Regex fuzzing
- Script-based payloads

**Example: XSS Fuzzing**
1. Right-click on a parameter in the request
2. Select `Fuzz...`
3. Choose or create a payload source
4. Configure fuzzing options
5. Click `Start Fuzzer`

### 8. Forced Browse
Discovers hidden files and directories using wordlists.

**Built-in Wordlists**:
- Directory and file names
- Common backup extensions
- Common configuration files

**Custom Wordlists**:
- Add your own wordlists
- Combine multiple wordlists
- Filter results by response codes

### 9. Port Scanner
Basic port scanning functionality for target discovery.

**Features**:
- Common ports
- Custom port ranges
- Service detection
- Fast scan options

### 10. Sequence
Tests for business logic vulnerabilities by automating sequences of requests.

**Use Cases**:
- Multi-step processes
- Shopping carts
- Registration flows
- Authentication bypass testing

### 11. WebSocket
Inspect and manipulate WebSocket traffic.

**Features**:
- Message interception
- Manual message editing
- Connection management
- Message filtering

### 12. Breakpoints
Pause and modify requests/responses.

**Types**:
- Global breakpoints
- URL-specific breakpoints
- Request/Response breakpoints
- Break on all
- Break on scope

### 13. Scripting
Automate tasks using various scripting languages.

**Supported Languages**:
- JavaScript (Nashorn)
- Python (Jython)
- Ruby (JRuby)
- Zest (ZAP's own scripting language)

**Example: Authentication Script**
```javascript
// ZAP JavaScript Authentication Script
function authenticate(helper, paramsValues, credentials) {
    // Make a login request
    var loginUrl = 'https://example.com/login';
    var loginData = 'username=' + encodeURIComponent(credentials.getParam('username')) +
                   '&password=' + encodeURIComponent(credentials.getParam('password'));
    
    helper.prepareMessage();
    helper.getHttpSender().sendAndReceive(
        helper.prepareMessage(),
        helper.prepareMessage()
            .setUri(loginUrl)
            .setHeader('Content-Type', 'application/x-www-form-urlencoded')
            .setBody(loginData)
            .setMethod(HttpRequestHeader.POST)
    );
    
    // Check if login was successful
    if (helper.getHttpSender().getLastResponseHeader().getStatusCode() == 302) {
        // Extract session cookie
        var cookie = helper.getHttpSender().getCookieValue(helper.getHttpSender().getLastResponseHeader(), 'sessionid');
        return cookie;
    }
    return null;
}
```

## Advanced Features

### 1. Authentication Handling
- Form-based authentication
- HTTP/NTLM authentication
- Script-based authentication
- Session management
- Multi-step authentication flows

### 2. Session Management
- Multiple sessions support
- Session tokens handling
- Anti-CSRF tokens
- Session fixation testing

### 3. Scan Policies
- Customize attack strength
- Configure alert thresholds
- Enable/disable specific rules
- Import/export policies

### 4. Contexts
- Define application scope
- Authentication methods
- Session management
- Technology detection
- Custom parameter handling

### 5. API Scanning
- Import OpenAPI/Swagger definitions
- SOAP web services testing
- REST API testing
- GraphQL endpoint testing

## Add-ons & Extensions

### Essential Add-ons
1. **HUD**: Modern web interface for security testing
2. **GraphQL**: Support for GraphQL testing
3. **OpenAPI**: Import and test OpenAPI/Swagger definitions
4. **SOAP**: SOAP web services support
5. **Custom Payloads**: Advanced fuzzing capabilities
6. **Retire.js**: Detect vulnerable JavaScript libraries
7. **Wappalyzer**: Technology detection

### Installing Add-ons
1. Go to `Tools` > `Add-ons`
2. Click on the `Marketplace` tab
3. Search for the desired add-on
4. Click `Install`
5. Restart ZAP when prompted

## Automation & API

### Command Line Options
```bash
# Basic headless scan
zap.sh -cmd -quickurl http://example.com -quickout /path/to/report.html

# Full scan with authentication
zap.sh -cmd -quickurl http://example.com -quickout /path/to/report.html \
  -config api.key=your-api-key \
  -config connection.timeoutInSecs=60 \
  -quickprogress

# Run a ZAP script
zap.sh -cmd -script /path/to/script.js
```

### REST API
ZAP provides a comprehensive REST API for automation:

**Example: Start a spider scan via API**
```bash
curl "http://zap-server:8080/JSON/spider/action/scan/?apikey=your-api-key&url=http://example.com&recurse=true"
```

**Example: Get scan progress**
```bash
curl "http://zap-server:8080/JSON/pscan/view/recordsToScan/?apikey=your-api-key"
```

## Best Practices

1. **Always Get Permission**
   - Only test systems you own or have explicit permission to test
   - Be aware of legal implications

2. **Use Contexts**
   - Define the scope of your testing
   - Configure authentication properly
   - Set up session management

3. **Start with Passive Scanning**
   - Less intrusive
   - Identifies low-hanging fruit
   - Helps understand the application

4. **Be Selective with Active Scanning**
   - Target specific components
   - Use appropriate scan policies
   - Be mindful of application impact

5. **Manual Testing**
   - Automated tools miss logic flaws
   - Test business logic manually
   - Verify all findings

6. **Documentation**
   - Keep detailed notes
   - Document false positives
   - Provide remediation advice

## Real-World Scenarios

### Scenario 1: E-commerce Checkout Testing
1. **Reconnaissance**: Spider the application
2. **Authentication Testing**: Test registration and login
3. **Product Browsing**: Check for IDOR in product IDs
4. **Shopping Cart**: Test price manipulation
5. **Checkout Process**: Test payment flow
6. **Order History**: Test access control

### Scenario 2: API Security Testing
1. **Documentation Review**: Check for exposed API docs
2. **Endpoint Discovery**: Find all API endpoints
3. **Authentication Testing**: Test API keys, JWT, OAuth
4. **Input Validation**: Test for injection flaws
5. **Rate Limiting**: Test for DoS vulnerabilities
6. **Data Exposure**: Check for information leakage

## Troubleshooting

### Common Issues
1. **ZAP not intercepting traffic**
   - Verify browser proxy settings
   - Check if any other tool is using port 8080
   - Ensure ZAP's proxy is enabled

2. **HTTPS connections not working**
   - Install ZAP's Root CA certificate
   - Check certificate warnings in the browser
   - Verify system time is correct

3. **Slow performance**
   - Increase JVM heap size
   - Use scan policies to limit test scope
   - Use the API for automated scans

4. **AJAX Spider not working**
   - Ensure the correct browser is installed
   - Check browser driver compatibility
   - Increase timeouts if needed

### Debugging
- Check the Output window in ZAP
- Enable debug logging in `Tools` > `Options` > `UI`
- Review the ZAP log file (Help > Show Log File)

## Resources & References

### Official Resources
- [OWASP ZAP Website](https://www.zaproxy.org/)
- [ZAP User Guide](https://www.zaproxy.org/docs/desktop/)
- [ZAP API Documentation](https://www.zaproxy.org/docs/api/)
- [GitHub Repository](https://github.com/zaproxy/zaproxy/)

### Learning Resources
- [ZAP Getting Started Guide](https://www.zaproxy.org/getting-started/)
- [ZAP in Ten](https://www.zaproxy.org/zap-in-ten/)
- [ZAP HUD Tutorial](https://www.zaproxy.org/docs/desktop/start/features/hud/)

### Community
- [OWASP ZAP User Group](https://groups.google.com/group/zaproxy-users)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/zap)
- [OWASP Slack](https://owasp.slack.com/) (#zaproxy channel)

### Books
- "The Web Application Hacker's Handbook"
- "Web Application Security: A Beginner's Guide"
- "Hacking APIs: Breaking Web Application Programming Interfaces"

### Training
- [OWASP ZAP Training](https://www.zaproxy.org/training/)
- [Web Security Academy (PortSwigger)](https://portswigger.net/web-security)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)
