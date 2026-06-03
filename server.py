import os
import re
import time
import json
import threading
from datetime import datetime
from flask import Flask, jsonify, request
from flask_sock import Sock
from collections import defaultdict

app = Flask(__name__, static_folder=".", static_url_path="")
sock = Sock(app)

# ─── State ────────────────────────────────────────────────────────────────────
connected_clients = []
clients_lock = threading.Lock()
login_tracker = defaultdict(list)   # ip -> [timestamps]
all_events = []
all_alerts = []

# ─── Detection Rules ──────────────────────────────────────────────────────────
#stateful = TRUE (jb hmara rule past memory p dependent ho)
RULES = [
    {
        "id": "BRUTE_FORCE",
        "name": "Brute Force Attack",
        "severity": "CRITICAL",
        "check": lambda e, _: (
            e["type"] == "AUTH" and
            re.search(r"fail|invalid|wrong|denied", e["message"], re.I) is not None
        ),
        "stateful": True,   # needs IP tracking
        "threshold": 5, #if in 60 sec more than 5 times user give wrong pass
        "window_sec": 60,
    },
    {
        "id": "ROOT_LOGIN",
        "name": "Root Login Detected",
        "severity": "CRITICAL",
        "check": lambda e, _: bool(
            re.search(r"root", e["message"], re.I) and
            re.search(r"login|session open|accepted", e["message"], re.I)
        ),
        "stateful": False,
    },
    {
        "id": "PORT_SCAN",
        "name": "Port Scan Activity",
        "severity": "HIGH",
        "check": lambda e, _: bool(re.search(r"scan|sweep|nmap|masscan", e["message"], re.I)),
        "stateful": False,
    },
    {
        "id": "MALWARE",
        "name": "Malware / Ransomware Signature",
        "severity": "CRITICAL",
        "check": lambda e, _: bool(re.search(r"ransom|malware|trojan|rootkit|encrypt.*file|virus", e["message"], re.I)),
        "stateful": False,
    },
    {
        "id": "PRIV_ESC",
        "name": "Privilege Escalation",
        "severity": "HIGH",
        "check": lambda e, _: bool(re.search(r"sudo|su root|privilege|escalat|setuid", e["message"], re.I)),
        "stateful": False,
    },
    {
        "id": "OFF_HOURS",
        "name": "Off-Hours Login",
        "severity": "MEDIUM",
        "check": lambda e, _: (
            e["type"] == "AUTH" and
            re.search(r"login|accepted|session", e["message"], re.I) is not None and
            (datetime.now().hour < 6 or datetime.now().hour > 22)
        ),
        "stateful": False,
    },
    {
        "id": "DATA_EXFIL",
        "name": "Data Exfiltration Pattern",
        "severity": "HIGH",
        "check": lambda e, _: bool(re.search(r"exfil|large.*transfer|unusual.*upload|outbound.*data", e["message"], re.I)),
        "stateful": False,
    },
]

# ─── Parser ───────────────────────────────────────────────────────────────────
def parse_line(line):
    line = line.strip()
    print(line)
    if not line:
        return None

    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    time_match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", line)

    # Determine severity
    if re.search(r"crit|fatal|emerg|alert", line, re.I):
        severity = "CRITICAL"
    elif re.search(r"error|fail|denied|refused", line, re.I):
        severity = "HIGH"
    elif re.search(r"warn|suspect|unusual|anomal", line, re.I):
        severity = "MEDIUM"
    elif re.search(r"info|notice|success", line, re.I):
        severity = "LOW"
    else:
        severity = "INFO"

    # Determine type
    if re.search(r"auth|login|ssh|sudo|password|session|pam", line, re.I):
        event_type = "AUTH"
    elif re.search(r"tcp|udp|http|dns|port|net|connect|socket", line, re.I):
        event_type = "NETWORK"
    elif re.search(r"kern|cpu|mem|disk|proc|service|daemon", line, re.I):
        event_type = "SYSTEM"
    elif re.search(r"file|dir|path|read|write|chmod|chown", line, re.I):
        event_type = "FILE"
    else:
        event_type = "SYSTEM"

    return {
        "id": int(time.time() * 1000),
        "time": time_match.group(0) if time_match else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity,
        "type": event_type,
        "message": line[:120],
        "ip": ip_match.group(1) if ip_match else None,
        "raw": line,
    }

# ─── Rule Engine ──────────────────────────────────────────────────────────────
def check_rules(event):
    alerts_fired = []
    now = time.time()

    for rule in RULES:
        print(rule)
        try:
            if not rule["check"](event, None):
                continue

            # only applicable on BRUTE_FORCE
            if rule.get("stateful") and event.get("ip"):
                ip = event["ip"]
                login_tracker[ip].append(now)
                # keep only within window
                window = rule.get("window_sec", 60)
                login_tracker[ip] = [t for t in login_tracker[ip] if now - t < window]
                if len(login_tracker[ip]) < rule.get("threshold", 5): #default 5 time
                    continue

            alert = {
                "id": f"{rule['id']}_{int(now*1000)}",
                "rule_id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "detail": event["message"][:100],
                "ip": event.get("ip"),
                "time": event["time"],
                "event_id": event["id"],
            }
            alerts_fired.append(alert)
        except Exception:
            pass

    return alerts_fired

# ─── Broadcast ────────────────────────────────────────────────────────────────
def broadcast(payload):
    dead = []
    with clients_lock:
        for ws in connected_clients:
            try:
                ws.send(json.dumps(payload))
            except Exception:
                dead.append(ws)
        for ws in dead:
            connected_clients.remove(ws)

# ─── WebSocket endpoint ───────────────────────────────────────────────────────
@sock.route("/ws")
def websocket(ws):
    with clients_lock:
        connected_clients.append(ws)
    # Send existing events on connect
    try:
        ws.send(json.dumps({"type": "init", "events": all_events[-100:], "alerts": all_alerts}))
        while True:
            ws.receive(timeout=30)   # keep alive
    except Exception:
        pass
    finally:
        with clients_lock:
            if ws in connected_clients:
                connected_clients.remove(ws)

# ─── REST: analyze uploaded file ──────────────────────────────────────────────
@app.route("/analyze", methods=["POST"])
def analyze():
    
    global all_events, all_alerts
    all_events = []
    all_alerts = []
    login_tracker.clear()

    data = request.get_json()
    lines = data.get("lines", [])

    for line in lines:
        
        event = parse_line(line)
        print(event)
        if not event:
            continue
        all_events.append(event)
        alerts = check_rules(event)
        print(alerts)
        all_alerts.extend(alerts)
        broadcast({"type": "event", "event": event, "alerts": alerts})
        time.sleep(0.04)   # slight delay so frontend animates nicely

    return jsonify({"events": len(all_events), "alerts": len(all_alerts)})

# ─── REST: watch a local file path ────────────────────────────────────────────
@app.route("/watch", methods=["POST"])
def watch_file():
    data = request.get_json()
    path = data.get("path", "")
    if not os.path.exists(path):
        return jsonify({"error": f"File not found: {path}"}), 404

    def tail():
        with open(path, "r") as f:
            f.seek(0, 2)   # go to end
            while True:
                line = f.readline()
                if line:
                    event = parse_line(line)
                    if event:
                        all_events.append(event)
                        alerts = check_rules(event)
                        all_alerts.extend(alerts)
                        broadcast({"type": "event", "event": event, "alerts": alerts})
                else:
                    time.sleep(0.5)

    t = threading.Thread(target=tail, daemon=True)
    t.start()
    return jsonify({"status": "watching", "path": path})

@app.route("/")
def index():
    return app.send_static_file("index.html")

if __name__ == "__main__":
    print("SIEM Server running → http://localhost:5000")
    # app.run(debug=True, port=5000, threaded=True)
    app.run(
    debug=True,
    use_reloader=False,
    port=5000,
    threaded=True
    )
    