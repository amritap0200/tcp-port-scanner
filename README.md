# Custom Port Scanner with Service Detection

A TCP port scanner built from scratch in C, C++, and Python.

## Features
- TCP connect scanning with configurable port ranges
- Concurrent scanning via thread pool
- Timeout and retry logic for filtered port detection
- Banner grabbing for service identification
- Port-to-service name mapping (`/etc/services`)
- Scan efficiency benchmarking across thread counts

## Project Structure
```
port-scanner/
├── src-c/        # C implementation (raw sockets, pthreads)
├── src-cpp/      # C++ implementation (OOP refactor with classes)
├── python/       # Python implementation (argparse CLI)
├── benchmarks/   # Performance results and analysis
└── docs/         # Notes and references
```

## Usage
_To be updated as implementation progresses._

## Build
_To be updated._
