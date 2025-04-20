
# 🕵️ Network Packet Analyzer (Python)

A lightweight network packet sniffer built in Python that captures and displays IP, TCP, UDP, and ICMP traffic — with optional filtering by **protocol**, **port**, and **IP address**.

## 🚀 Features

- 🧠 Raw socket-based packet capture
- 🔍 Filters:
  - By **protocol**: TCP, UDP, ICMP
  - By **port number**
  - By **IP address** (source or destination)
- 💡 Supports Windows & Linux
- 📦 Self-contained, single `.py` file
- 🧪 Great for learning or basic network traffic analysis

---

## 🛠 Requirements

- Python 3.6+
- **Administrator/root privileges** (raw sockets require elevated permissions)

---

## 🖥 How to Run

> ⚠️ Run as Administrator or with sudo!

```bash
python network_packet_analyzer.py
