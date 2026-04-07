# TCP Port Scanner with Service Detection

**Project #21 — Custom Port Scanner with Service Detection**  
Implement a scanner to detect open ports and services using concurrent scanning, timeout & retry logic, banner grabbing, and scan efficiency evaluation.

**Languages:** C, C++, Python  
**Protocol:** TCP  

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Parameters](#parameters)
- [Requirements](#requirements)
- [Setup & Installation](#setup--installation)
- [Running the Scanner](#running-the-scanner)
- [Running the Web UI](#running-the-web-ui)
- [How It Works](#how-it-works)
- [Sample Output](#sample-output)
- [Future Enhancements](#future-enhancements)

---

## Overview

A multi-layered TCP port scanner built from scratch in three languages. Given a target IP address, it:

- Scans a range of ports concurrently using a thread pool
- Identifies which ports are open, closed, or filtered
- Grabs the service banner from each open port
- Identifies what software is running (Apache, OpenSSH, Pure-FTPd, etc.)
- Measures and reports scan efficiency (ports/second)
- Displays results in a clean web UI

---

## Architecture
Browser (React UI)
↓  HTTP POST /api/scan
Flask Server (Python)
↓  subprocess.run()
scanner_main binary (C++)
↓  function calls
Raw Socket Engine (C)
↓  TCP packets
Target Host

The three layers are:

- **C** — raw socket creation, manual TCP/IP packet construction, checksum calculation
- **C++** — thread pool, concurrent TCP connect scanning, banner grabbing, JSON output
- **Python** — Flask REST API, React web UI, result reporting

---

## Tech Stack

| Layer | Language | Key Concepts |
|---|---|---|
| Socket engine | C | Raw sockets, IP/TCP headers, checksums, `IPPROTO_TCP` |
| Scanner | C++ | Thread pool, `std::mutex`, `std::condition_variable`, `std::atomic`, non-blocking sockets, `select()` |
| Interface | Python + React | Flask, `subprocess`, REST API, React hooks (`useState`, `useEffect`) |
| Test targets | Docker | Containerization, bridge networking, port mapping |

---

## Project Structure
tcp-port-scanner/
├── core/
│   ├── raw_socket.h        # C header with extern "C" guards
│   └── raw_socket.c        # Raw socket creation, SYN packets, checksum
├── scanner/
│   ├── Scanner.h           # Scanner class declaration
│   ├── Scanner.cpp         # TCP connect scan, thread pool, JSON output
│   ├── ThreadPool.h        # ThreadPool class declaration
│   ├── ThreadPool.cpp      # Worker threads, mutex, condition variable
│   ├── BannerGrabber.h     # BannerGrabber class declaration
│   └── BannerGrabber.cpp   # Banner grabbing, service identification
├── python/
│   ├── server.py           # Flask backend, REST API
│   └── ui.html             # React frontend (no build step)
├── signatures/
│   └── services.json       # Service signature database
├── main.cpp                # Entry point, argument parsing, JSON writing
├── Makefile                # Build system
├── .gitignore
└── README.md

---

## Parameters

### Runtime Parameters (passed as flags)

| Flag | Default | Description |
|---|---|---|
| `--target` | required | Target IP address or hostname |
| `--source` | required | Your machine's IP address |
| `--ports` | required | Port range e.g. `1-1024` or `22,80,443` |
| `--threads` | 100 | Number of concurrent threads |
| `--timeout` | 2 | Seconds to wait per port |
| `--retries` | 2 | Retry attempts for filtered ports |
| `--output` | `/tmp/scan_out.json` | Output file path |

### Hardcoded Parameters

| Parameter | Value | Location |
|---|---|---|
| IP TTL | 64 hops | `raw_socket.c` |
| TCP window size | 5840 bytes | `raw_socket.c` |
| Banner read buffer | 1024 bytes | `BannerGrabber.cpp` |
| Banner grab timeout | 3 seconds | `main.cpp` |
| HTTP probe ports | 80, 8080, 443, 8443 | `BannerGrabber.cpp` |
| Flask port | 5000 | `server.py` |
| Server scan timeout | 300 seconds | `server.py` |

---

## Requirements

- Ubuntu 22.04+ or WSL2 (Ubuntu)
- gcc, g++ (GCC 11+)
- Python 3.10+
- make
- Docker

---

## Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/tcp-port-scanner.git
cd tcp-port-scanner
```

### 2. Install system dependencies
```bash
sudo apt install -y gcc g++ python3 python3-pip make docker.io
```

### 3. Install Python dependencies
```bash
sudo pip3 install flask --break-system-packages
```

### 4. Build the scanner
```bash
make
```

Expected output:
gcc -Wall -O2 -c core/raw_socket.c -o core/raw_socket.o
g++ -Wall -O2 -std=c++17 -c scanner/Scanner.cpp -o scanner/Scanner.o
...
Build complete! Binary: ./scanner_main

### 5. Start Docker test targets
```bash
sudo systemctl start docker

sudo docker run -d -p 8080:80  --name test_http httpd:alpine
sudo docker run -d -p 2222:22 --name test_ssh  rastasheep/ubuntu-sshd:18.04
sudo docker run -d -p 2121:21 --name test_ftp  stilliard/pure-ftpd
```

### 6. Get container IP addresses
```bash
sudo docker inspect test_http | grep '"IPAddress"'
sudo docker inspect test_ssh  | grep '"IPAddress"'
sudo docker inspect test_ftp  | grep '"IPAddress"'
```

Typical output:
"IPAddress": "172.17.0.2"   ← HTTP (Apache)
"IPAddress": "172.17.0.3"   ← SSH (OpenSSH)
"IPAddress": "172.17.0.4"   ← FTP (Pure-FTPd)

---

## Running the Scanner

### Basic scan (single port)
```bash
sudo ./scanner_main \
  --target 172.17.0.2 \
  --source 172.22.49.86 \
  --ports 80 \
  --threads 10 \
  --timeout 3 \
  --retries 1 \
  --output results.json
```

### Range scan
```bash
sudo ./scanner_main \
  --target 172.17.0.2 \
  --source 172.22.49.86 \
  --ports 1-1024 \
  --threads 200 \
  --timeout 2 \
  --retries 1 \
  --output results.json
```

### Scan specific ports
```bash
sudo ./scanner_main \
  --target 172.17.0.3 \
  --source 172.22.49.86 \
  --ports 22,80,443,8080 \
  --threads 50 \
  --timeout 2 \
  --retries 1 \
  --output results.json
```

---

## Running the Web UI

### Start the server
```bash
sudo python3 python/server.py
```

### Open in browser
http://localhost:5000

The UI will:
- Auto-detect running Docker containers and display them as clickable targets
- Let you configure target, port range, threads, timeout, and retries via sliders
- Run the scan and display open ports with service names and banners

---

## How It Works

### 1. TCP Connect Scan

For each port, the scanner:
1. Creates a non-blocking TCP socket
2. Calls `connect()` — returns immediately with `EINPROGRESS`
3. Uses `select()` to wait up to `timeout` seconds
4. Checks `SO_ERROR` — 0 means open, `ECONNREFUSED` means closed, timeout means filtered

### 2. Thread Pool

- N worker threads are created at startup and wait on a condition variable
- The main thread enqueues one scan task per port
- Workers wake up, grab a task, scan the port, store the result, go back to sleep
- A mutex protects the shared results vector from race conditions

### 3. Banner Grabbing

For each open port:
1. Opens a full TCP connection
2. Sends an HTTP probe (`HEAD / HTTP/1.0`) for web ports
3. Reads the first bytes the service sends (the banner)
4. Matches against a signature database to identify the service

### 4. Python-C++ Bridge

Python calls the compiled C++ binary via `subprocess.run()`, passing all parameters as command-line flags. The C++ binary writes results to a temporary JSON file. Python reads and parses that file, then returns it to the browser as an HTTP response.

---

## Sample Output
[] Target: 172.17.0.2
[] Source: 172.22.49.86
[+] Scanner initialized (TCP connect mode)
[*] Total ports to scan: 1024
[+] Thread pool created with 200 threads
[OPEN] Port 80 (0.23 ms)
[] Scan complete!
[] Grabbing banner from port 80...
Banner: HTTP/1.1 200 OK  Server: Apache/2.4.66 (Unix)
Service: HTTP-Apache
PORT      STATUS    RESP(ms)             SERVICE

  80        OPEN        0.23         HTTP-Apache
--- Summary ---
Open:     1
Closed:   1023
Filtered: 0
Speed:    28224.4 ports/sec
Time:     0.036 sec

---

## Future Enhancements

- **UDP scanning** — add support for DNS, DHCP, SNMP and other UDP services
- **OS fingerprinting** — identify the target OS from TTL, TCP window size, and response characteristics
- **CVE lookup** — query the NVD API to flag known vulnerabilities for detected service versions
- **CIDR range scanning** — scan entire subnets e.g. `192.168.1.0/24` with a ping sweep first
- **Scheduled monitoring** — run scans on a schedule and alert on changes (new open ports, version changes)
- **Export formats** — PDF reports, CSV export, nmap-compatible XML output
- **Distributed scanning** — distribute port ranges across multiple machines for large-scale network audits
- **ML-based service detection** — train a classifier on banner data to identify obfuscated services