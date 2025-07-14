# Gobuster Notes

Gobuster is a tool used to brute-force URIs (directories and files) in web sites, DNS subdomains, Virtual Host names on target web servers, and Open Amazon S3 buckets. It's a popular choice for content discovery due to its speed and simplicity.

## Key Modes & Use Cases

Gobuster operates in different modes, each designed for a specific type of brute-forcing:

1.  **`dir` mode (Directory/File Brute-forcing)**: The most commonly used mode for discovering hidden directories and files.
    ```bash
    # Basic directory scan
    gobuster dir -u http://example.com -w /path/to/wordlist.txt

    # Scan with common file extensions
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -x php,html,txt,bak

    # Exclude specific status codes (e.g., 404 Not Found)
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -b 404

    # Include specific status codes (e.g., 200 OK, 301 Moved Permanently)
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -s 200,301

    # Add a custom User-Agent header
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -H "User-Agent: Mozilla/5.0"

    # Use a proxy
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -p http://127.0.0.1:8080
    ```

2.  **`dns` mode (DNS Subdomain Brute-forcing)**: Discover subdomains for a given domain.
    ```bash
    gobuster dns -d example.com -w /path/to/subdomains_wordlist.txt
    ```

3.  **`vhost` mode (Virtual Host Brute-forcing)**: Discover virtual hosts on a web server.
    ```bash
    gobuster vhost -u http://example.com -w /path/to/vhosts_wordlist.txt
    ```

4.  **`s3` mode (Open Amazon S3 Bucket Brute-forcing)**: Discover open S3 buckets.
    ```bash
    gobuster s3 -w /path/to/s3_wordlist.txt
    ```

5.  **`fuzz` mode (Fuzzing)**: A more generic fuzzing mode (less common than `dir` for basic use).
    ```bash
    gobuster fuzz -u http://example.com/FUZZ -w /path/to/wordlist.txt
    ```

## Common Options

-   `-u <url>`: Target URL (for `dir`, `vhost`, `fuzz` modes).
-   `-d <domain>`: Target domain (for `dns` mode).
-   `-w <wordlist>`: Path to the wordlist file.
-   `-x <extensions>`: Comma-separated list of file extensions to search for (e.g., `php,html,txt`).
-   `-t <threads>`: Number of concurrent threads (default: 10).
-   `-k`: Skip SSL certificate verification.
-   `-P <proxy>`: Use a proxy (e.g., `http://127.0.0.1:8080`).
-   `-b <status_codes>`: Blacklist status codes (e.g., `404,500`).
-   `-s <status_codes>`: Whitelist status codes (e.g., `200,301`).
-   `-H <header>`: Add custom HTTP headers (e.g., `"User-Agent: MyAgent"`).

## Tips for Penetration Testing

-   **Wordlist Selection**: Choose appropriate wordlists for the target. `SecLists` is a great resource.
-   **Combine with other tools**: Use Gobuster to find directories/files, then use `curl` or Burp Suite to investigate further.
-   **Error Handling**: Pay attention to status codes. Filtering out 404s is crucial, but sometimes 200 OK responses can be false positives (e.g., custom 404 pages).
-   **Recursion**: While Gobuster has a `-r` (recursive) option, for deep recursive scans, tools like `ffuf` might offer more flexibility.
