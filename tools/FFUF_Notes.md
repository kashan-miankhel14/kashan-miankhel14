# FFUF: The Complete Guide for Web Fuzzing

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Directory/File Discovery](#directoryfile-discovery)
5. [Virtual Host Discovery](#virtual-host-discovery)
6. [Parameter Fuzzing](#parameter-fuzzing)
7. [Filtering & Matching](#filtering--matching)
8. [Performance Tuning](#performance-tuning)
9. [Output Formats](#output-formats)
10. [Authentication & Headers](#authentication--headers)
11. [Proxies & Debugging](#proxies--debugging)
12. [Advanced Techniques](#advanced-techniques)
13. [Wordlists](#wordlists)
14. [Real-World Examples](#real-world-examples)
15. [Troubleshooting](#troubleshooting)
16. [Resources](#resources)

## Introduction

FFUF (Fuzz Faster U Fool) is a blazing fast web fuzzer written in Go. It's designed for directory and file discovery, parameter fuzzing, and web application security testing. FFUF is known for its speed, flexibility, and extensive feature set.

### Key Features
- **High Performance**: Multi-threaded and written in Go
- **Flexible**: Supports multiple fuzzing points in a single run
- **Customizable**: Extensive filtering and matching options
- **Output Formats**: Multiple output formats including JSON, HTML, and CSV
- **Recursive Fuzzing**: Automatic directory recursion
- **Pipelining**: Can chain multiple fuzzing operations

## Installation

### Pre-built Binaries
Download the latest release from the [official GitHub repository](https://github.com/ffuf/ffuf/releases).

### From Source
```bash
go install github.com/ffuf/ffuf/v2@latest
```

### Package Managers
#### Kali Linux
```bash
sudo apt install ffuf
```

#### macOS (Homebrew)
```bash
brew install ffuf
```

#### Windows (Scoop)
```bash
scoop install ffuf
```

### Verify Installation
```bash
ffuf --help
```

## Basic Usage

### Basic Directory Discovery
```bash
ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ
```

## Tips & Tricks

-   **Wordlists**: The quality of your wordlists directly impacts FFUF's effectiveness. Use specialized wordlists for different tasks (e.g., `dirb`, `SecLists`).
-   **Calibration**: Use `-ac` (auto-calibrate) or `-acc` (auto-calibrate with content-length) to automatically filter out common error pages or default responses.
-   **Concurrency**: Adjust `-t` (threads) for optimal performance based on your network and the target's capacity.
-   **Proxy**: Use `-x` to route traffic through a proxy (e.g., Burp Suite) for further analysis.
    ```bash
    ffuf -w wordlist.txt -u http://example.com/FUZZ -x http://127.0.0.1:8080
    ```
-   **Output**: Use `-o` to save results in various formats (csv, json, html, md, etc.).
