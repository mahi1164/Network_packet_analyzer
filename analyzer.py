

from flask import Flask, render_template, Response
from flask_socketio import SocketIO
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import csv
import io

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ─── Classes ──────────────────────────────────────────────────────

class Packet:
    def __init__(self, raw):
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.src_ip   = "N/A"
        self.dst_ip   = "N/A"
        self.protocol = "OTHER"
        self.src_port = "-"
        self.dst_port = "-"
        self.size     = len(raw)
        self.flags    = "-"
        self._parse(raw)

    def _parse(self, pkt):
        if IP not in pkt:
            return
        self.src_ip = pkt[IP].src
        self.dst_ip = pkt[IP].dst
        if TCP in pkt:
            self.protocol = "TCP"
            self.src_port = pkt[TCP].sport
            self.dst_port = pkt[TCP].dport
            self.flags    = str(pkt[TCP].flags)
        elif UDP in pkt:
            self.protocol = "UDP"
            self.src_port = pkt[UDP].sport
            self.dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            self.protocol = "ICMP"

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "protocol":  self.protocol,
            "src_ip":    self.src_ip,
            "src_port":  str(self.src_port),
            "dst_ip":    self.dst_ip,
            "dst_port":  str(self.dst_port),
            "size":      self.size,
            "flags":     self.flags,
        }


class Stats:
    def __init__(self):
        self.total     = 0
        self.protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.ip_counts = {}
        self.pps_history = []
        self._sec_count  = 0
        self._last_sec   = datetime.now().second

    def update(self, pkt: Packet):
        self.total += 1
        self.protocols[pkt.protocol] = self.protocols.get(pkt.protocol, 0) + 1
        self.ip_counts[pkt.src_ip]   = self.ip_counts.get(pkt.src_ip, 0) + 1
        now = datetime.now().second
        if now != self._last_sec:
            self.pps_history.append(self._sec_count)
            if len(self.pps_history) > 30:
                self.pps_history.pop(0)
            self._sec_count = 1
            self._last_sec  = now
        else:
            self._sec_count += 1

    def top_talkers(self, n=5):
        return sorted(
            [{"ip": k, "count": v} for k, v in self.ip_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:n]

    def to_dict(self):
        return {
            "total":       self.total,
            "protocols":   self.protocols,
            "pps_history": self.pps_history,
            "top_talkers": self.top_talkers(),
        }


class NetworkAnalyzer:
    def __init__(self):
        self.running = False
        self.stats   = Stats()
        self.packets = []
        self._filter = {}

    def set_filter(self, protocol=None, src_ip=None, dst_ip=None, port=None):
        self._filter = {
            "protocol": protocol or None,
            "src_ip":   src_ip   or None,
            "dst_ip":   dst_ip   or None,
            "port":     str(port) if port else None,
        }

    def _matches(self, pkt: Packet) -> bool:
        f = self._filter
        if f.get("protocol") and pkt.protocol != f["protocol"]:
            return False
        if f.get("src_ip") and pkt.src_ip != f["src_ip"]:
            return False
        if f.get("dst_ip") and pkt.dst_ip != f["dst_ip"]:
            return False
        if f.get("port"):
            if str(pkt.src_port) != f["port"] and str(pkt.dst_port) != f["port"]:
                return False
        return True

    def _handle(self, raw):
        if not self.running or IP not in raw:
            return
        pkt = Packet(raw)
        self.stats.update(pkt)
        if self._matches(pkt):
            d = pkt.to_dict()
            self.packets.append(d)
            if len(self.packets) > 500:
                self.packets.pop(0)
            socketio.emit("packet", {
                "packet": d,
                "stats":  self.stats.to_dict()
            })

    def start(self):
        if self.running:
            return
        self.running = True
        self.stats   = Stats()
        self.packets = []
        threading.Thread(
            target=lambda: sniff(prn=self._handle, store=False),
            daemon=True
        ).start()

    def stop(self):
        self.running = False

    def export_csv(self):
        if not self.packets:
            return ""
        out = io.StringIO()
        w   = csv.DictWriter(out, fieldnames=self.packets[0].keys())
        w.writeheader()
        w.writerows(self.packets)
        return out.getvalue()


# ─── App ──────────────────────────────────────────────────────────
analyzer = NetworkAnalyzer()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start():
    analyzer.start()
    return {"status": "started"}

@app.route("/stop", methods=["POST"])
def stop():
    analyzer.stop()
    return {"status": "stopped"}

@app.route("/filter", methods=["POST"])
def set_filter():
    from flask import request
    d = request.json
    analyzer.set_filter(
        protocol=d.get("protocol"),
        src_ip=d.get("src_ip"),
        dst_ip=d.get("dst_ip"),
        port=d.get("port"),
    )
    return {"status": "ok"}

@app.route("/export")
def export():
    return Response(
        analyzer.export_csv(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=packets.csv"}
    )

if __name__ == "__main__":
    print("\n🌐  Open your browser → http://localhost:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)