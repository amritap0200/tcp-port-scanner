# TCP Port Scanner with Service Detection

## Overview

This project implements a high-performance TCP port scanner with service detection using a multi-layered architecture:

* **C (core layer):** Raw socket implementation for SYN-based port scanning
* **C++ (scanner layer):** Thread pool, concurrency, and scan orchestration
* **Python (interface layer):** CLI, UI server, and result visualization
* **Docker (test environment):** Containerized services to simulate real-world networks

The scanner performs half-open TCP SYN scans, detects open ports, and uses banner grabbing to identify services running on those ports.

---

## Architecture

```
User (CLI/UI)
      ↓
Python (server.py / CLI)
      ↓
C++ Scanner (threading, orchestration)
      ↓
C Raw Socket Engine (SYN packets)
      ↓
Network (Dockerized services)
```

### Key Concepts

**TCP SYN Scan**

* Sends SYN packet
* Receives SYN-ACK for open ports
* Receives RST for closed ports
* Does not complete handshake

**Raw Sockets**

* Full control over packet construction
* Requires root privileges
* Enables stealth scanning

**Thread Pool**

* Concurrent scanning of multiple ports
* Uses mutexes and condition variables
* Improves performance significantly

**Banner Grabbing**

* Connects to open ports
* Reads service response
* Matches against signature database

---

## Project Structure

```
tcp-port-scanner/
├── core/               # C raw socket implementation
├── scanner/            # C++ threading and scan logic
├── python/             # UI and CLI interface
│   ├── server.py
│   └── ui.html
├── signatures/         # Service detection database
│   └── services.json
├── services/           # Docker-based test environment
│   ├── docker-compose.yml
│   └── generate_services.py (optional)
├── logs/
├── main.cpp
├── scanner_main        # compiled binary
├── Makefile
└── README.md
```

---

## Requirements

* Ubuntu or WSL2
* gcc, g++
* python3, pip
* make
* Docker (with WSL integration enabled)

---

## Setup Instructions

### 1. Install dependencies

```bash
sudo apt update
sudo apt install -y gcc g++ python3 python3-pip make docker.io
sudo pip3 install flask pyyaml --break-system-packages
```

### 2. Enable Docker (WSL users)

Ensure Docker Desktop WSL integration is enabled.

Verify:

```bash
docker --version
docker compose version
```

### 3. Build the scanner

```bash
make
```

This compiles:

* C raw socket module
* C++ scanner
* Produces `scanner_main`

---

## Running the UI

```bash
sudo python3 python/server.py
```

Open:

```
http://localhost:5000
```

---

## Test Environment Evolution

### Initial Approach

Previously, test services were created manually:

```bash
docker run -d -p 8080:80  httpd
docker run -d -p 2222:22  ssh
docker run -d -p 2121:21  ftp
```

Issues:

* Manual setup required for each service
* Not scalable
* Not reproducible
* Hard to extend

---

### Improved Approach using Docker Compose

We replaced manual container management with a configuration-driven system.

All services are now defined in:

```
services/docker-compose.yml
```

### Benefits

* Single command startup
* Scalable to many services
* Reproducible environment
* No need to manually create containers

---

## Starting Test Services

### Step 1

```bash
cd services
```

### Step 2

```bash
docker compose up -d
```

This automatically:

* Pulls images
* Creates containers
* Configures networking
* Maps ports

---

## Services Included

| Service  | Port  |
| -------- | ----- |
| nginx    | 8080  |
| apache   | 8081  |
| ftp      | 2121  |
| ssh      | 2222  |
| mysql    | 3306  |
| postgres | 5432  |
| mongo    | 27017 |
| redis    | 6379  |
| smtp     | 2525  |
| node app | 3000  |

---

## Important Note on Networking

Containers run in an isolated Docker network.

The scanner should target:

```
127.0.0.1
```

and use exposed host ports instead of container IPs.

Example:

```bash
--target 127.0.0.1 --ports 8080,2121,2222
```

---

## Running the Scanner

### Using UI

1. Open UI at localhost:5000
2. Set target to 127.0.0.1
3. Enter ports
4. Run scan

---

### Using CLI

```bash
sudo ./scanner_main \
--target 127.0.0.1 \
--source <your-ip> \
--ports 8080,8081,2121,2222,3306,5432,27017,6379,2525,3000 \
--threads 200 \
--timeout 2 \
--retries 1 \
--output results.json
```

---

## Optional: Dynamic Service Generation

To further improve scalability, a generator script is included.

### Run:

```bash
cd services
python3 generate_services.py
docker compose -f docker-compose.generated.yml up -d
```

### Purpose

* Automatically generate service configurations
* Add new services programmatically
* Reduce manual YAML editing

---

## Iterations and Improvements

### Phase 1

* Basic scanner with manual test containers

### Phase 2

* Introduced Docker Compose
* Centralized service definitions

### Phase 3

* Added multiple real-world services
* Expanded banner detection coverage

### Phase 4

* Introduced generator script
* Enabled dynamic scaling

---

## Key Improvements

**Automation**

* Single command replaces multiple docker run commands

**Scalability**

* Easily add new services without changing scanner code

**Decoupling**

* Scanner logic independent of environment

**Reproducibility**

* Same setup across machines

**Realistic Testing**

* Simulates multi-service network environment

---

## Troubleshooting

### No open ports detected

* Ensure correct target IP
* Use 127.0.0.1 instead of container IP
* Verify containers are running:

```bash
docker ps
```

---

### Permission errors

Run scanner with sudo:

```bash
sudo ./scanner_main
```

---

### Ports not available

Stop existing containers:

```bash
docker compose down
```

---

## Summary

This project evolved from a manually managed testing setup to a scalable, automated, and reproducible system using Docker Compose.

The scanner remains unchanged while the testing infrastructure has been significantly improved, allowing efficient evaluation across multiple services and realistic network scenarios.

This separation of concerns ensures maintainability and extensibility for future enhancements.
