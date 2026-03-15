# Snifed: Multithreaded Linux Network Traffic Analyzer

Snifed is a high-performance network analysis tool built for Linux using C++. It captures raw packets at the Ethernet layer and provides deep inspection across the networking stack, covering ARP, IPv4, IPv6, TCP, UDP, and application-layer protocols such as HTTPS, DNS, and FTP.

The project features a Qt-based interface that handles live data streams, offering real-time protocol classification, MAC/IP extraction, and customizable filtering.

---

## Key Features

* **Parallel Processing:** Uses POSIX threads to decouple packet capture from the UI, ensuring the application remains responsive under high traffic loads.
* **Low-Level Capture:** Utilizes a raw socket interface to intercept traffic directly from the link layer.
* **Full-Stack Inspection:** Decodes data from Ethernet headers through to the application layer.
* **Dual-Stack Support:** Native parsing for both IPv4 and IPv6 traffic.
* **Protocol Identification:** Automatically identifies common services like SSH, HTTP, and DNS based on port signatures.
* **Qt Interface:** A dedicated GUI for visualizing packet metadata and filtering specific traffic streams.

---

## Technical Stack

* **Language:** C++
* **Framework:** Qt 5/6
* **Networking:** Raw sockets (`AF_PACKET`)
* **Concurrency:** POSIX Threads
* **Platform:** Linux (Relies on `ether_header` structs and Linux-specific socket APIs)

---

## System Requirements

* **Operating System:** Any modern Linux distribution (Ubuntu, Debian, Fedora, etc.)
* **Dependencies:** Qt 5 or 6 development libraries (`qtbase5-dev` or equivalent)
* **Compiler:** g++
* **Permissions:** Root privileges are required to open raw sockets.

---

## Installation and Setup

```bash
git clone https://github.com/yourusername/snifed.git
cd snifed
mkdir build && cd build
cmake ..
make
sudo ./snifed
