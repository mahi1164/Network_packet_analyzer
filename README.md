# 📡 Network Packet Analyzer

A real-time TCP/IP network packet analyzer with a live web dashboard,
built with Python and Flask. Captures, filters, and visualizes live
network traffic directly in your browser.

Built by **Mahi Panjwani** as part of a systems networking project,
demonstrating core concepts in TCP/IP, OOP design, socket programming,
and real-time data streaming.

---

## 🖥️ Dashboard Preview

> Live packet feed, protocol distribution, packets/second graph,
> top talkers, and filter controls — all updating in real time.

![Dashboard Preview](preview.png)

---

## ✨ Features

- 📊 **Live Charts** — Packets/second line graph + protocol distribution donut chart
- 🌐 **Protocol Analysis** — Captures and classifies TCP, UDP, ICMP, and other packets
- 🔍 **Smart Filters** — Filter by protocol, source IP, destination IP, or port number
- 🏆 **Top Talkers** — Real-time ranking of most active IP addresses
- 📋 **Live Packet Feed** — Scrollable, searchable, sortable packet table
- 💾 **CSV Export** — Download all captured packets with one click
- ⚡ **Real-time Streaming** — WebSocket-based live updates via Socket.IO

---

## 🏗️ Architecture & OOP Design

The project is structured around four core classes demonstrating
clean separation of concerns:
```
Packet          → Parses and represents a single captured network packet
Stats           → Tracks live session statistics (protocol counts, PPS, top talkers)
NetworkAnalyzer → Orchestrates capture, filtering, and real-time emission
Flask App       → Serves the dashboard and exposes REST control endpoints
```

**Data Flow:**
```
Network Interface → Scapy Sniffer → Packet Parser → Stats Engine
                                                   → WebSocket Emit → Browser Dashboard
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Packet Capture | Python, Scapy |
| Backend | Flask, Flask-SocketIO |
| Real-time Streaming | WebSockets (Socket.IO) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | Chart.js |
| Networking Concepts | TCP/IP, UDP, ICMP, Socket Programming |
| Design Pattern | Object-Oriented Programming (OOP) |

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.8+
- [Npcap](https://npcap.com) installed (Windows) — required for packet capture
- Run as **Administrator** (required for raw socket access)

### Installation
```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/network-packet-analyzer.git
cd network-packet-analyzer

# 2. Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Mac/Linux
source .venv/bin/activate

# 3. Install dependencies
pip install flask flask-socketio flask-cors scapy eventlet
```

### Run
```bash
# Must run as Administrator on Windows
python analyzer.py
```

Then open your browser at:
```
http://localhost:5000
```

---

## 🚀 Usage

| Action | How |
|---|---|
| Start capturing | Click **▶ Start** button |
| Stop capturing | Click **⬛ Stop** button |
| Filter by protocol | Select from dropdown → Apply |
| Filter by IP/Port | Enter value → Apply |
| Search packets | Type in search box (live filter) |
| Sort table | Click any column header |
| Export data | Click **⬇ Export CSV** |

---

## 📁 Project Structure
```
network-packet-analyzer/
├── analyzer.py          # Core backend — packet capture, Flask API, SocketIO
├── requirements.txt     # Python dependencies
└── templates/
    └── index.html       # Full dashboard UI (HTML + CSS + JS)
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Serves the dashboard |
| POST | `/start` | Begin packet capture |
| POST | `/stop` | Stop packet capture |
| POST | `/filter` | Apply capture filters |
| GET | `/export` | Download packets as CSV |

---

## 🧠 Concepts Demonstrated

- **TCP/IP Stack** — Live classification of Layer 3/4 protocols
- **Socket Programming** — Real-time bidirectional communication via WebSockets
- **OOP Design** — Clean class hierarchy with single responsibility per class
- **Multithreading** — Packet capture runs on a background daemon thread
- **REST API Design** — Flask endpoints for dashboard control
- **Real-time Data Streaming** — Server-sent events via Socket.IO

---

## 📌 Requirements File
```
flask
flask-socketio
flask-cors
scapy
eventlet
```

Generate with:
```bash
pip freeze > requirements.txt
```

---

## 👩‍💻 Author

**Mahi Panjwani**
B.Tech Computer Science & Engineering — Amity University Chhattisgarh
[LinkedIn](http://www.linkedin.com/in/mahi-panjwani-bbb6a7294/) · [GitHub](http://github.com/mahi1164)
