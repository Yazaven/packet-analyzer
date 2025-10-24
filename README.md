# 🕵️‍♂️ Snifed - Multithreaded Linux Network Traffic Analyzer in C++

Snifed is a **real-time, multithreaded network traffic analyzer** built in **C++** for **Linux**. It captures raw packets at the Ethernet layer and dissects them across the full stack — including ARP, IPv4/IPv6, TCP/UDP, and common application protocols like **HTTPS, DNS, FTP, and more**.

The tool also includes a responsive **Qt-based GUI** that displays parsed packet data live, with features like MAC/IP address extraction, protocol classification, and advanced filtering.

---

## ✨ Features
 
- 🧵 **Multithreaded packet capture** using POSIX threads for responsive and efficient traffic processing.
- 📡 **Raw socket interface** to capture traffic from the link layer.
- 🧠 **Deep packet inspection** from Ethernet headers to application layer protocols.
- 🌐 **IPv4 and IPv6 support**, including ICMP, TCP, UDP parsing.
- 📦 **Application protocol identification** by port (e.g., HTTP, HTTPS, DNS, SSH, FTP, etc.).
- 🖥️ **Qt GUI** with real-time packet visualization and protocol-aware filtering.
- 🔍 **Displays key metadata**: MAC addresses, IPs, port numbers, protocol names, and protocol-specific info.

---

## 🧱 Built With

- **C++**
- **Qt 5/6**
- **Raw sockets (AF_PACKET)**
- **POSIX Threads**
- **Linux-only** (due to raw socket use and `ether_header` structs)

---

## 🛠️ Requirements

- Linux OS (Ubuntu, Debian, etc.)
- Qt 5 or Qt 6 (`libqt5widgets`, `qtbase5-dev`, etc.)
- g++ compiler
- Root privileges (to access raw sockets)

---

## 🔧 Build Instructions

```bash
git clone https://github.com/yourusername/snifed.git
cd snifed
mkdir build
cd build
cmake ..
make
sudo ./snifed
