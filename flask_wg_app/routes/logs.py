from flask import Blueprint, render_template, request, flash, Response, jsonify, stream_with_context
import subprocess, shlex, time, re
import wg_manager
from datetime import datetime

bp = Blueprint("logs", __name__)

# -------- Helpers --------
def _common_context():
    running = wg_manager.is_wg_up("wg0")
    status = wg_manager.wg_show()
    peers = wg_manager.list_peers("wg0") if running else []
    server = wg_manager.get_server_info("wg0")
    return running, status, peers, server


# -------- Fonction d’exécution shell sécurisée --------
def _read_command(cmd: str) -> str:
    try:
        p = subprocess.run(shlex.split(cmd), text=True, capture_output=True, check=False)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return str(e)


# -------- Classification des logs --------
_PATTERNS = [
    (re.compile(r'(Started WireGuard|interface is up)', re.I), ('service.start','ok')),
    (re.compile(r'(Stopped WireGuard|Deactivated)', re.I), ('service.stop','warn')),
    (re.compile(r'(Failed|failure|exit-code|cannot|denied)', re.I), ('system.error','error')),
    (re.compile(r'wireguard:.*handshake', re.I), ('peer.handshake','ok')),
    (re.compile(r'keepalive', re.I), ('peer.keepalive','info')),
    (re.compile(r'(handshake.*failed|retrying in|no route|invalid|bad)', re.I), ('peer.fail','error')),
    (re.compile(r'peer .* endpoint', re.I), ('peer.endpoint_change','info')),
    (re.compile(r'(added peer|removed peer|AllowedIPs|ListenPort)', re.I), ('config.change','info')),
]

def _classify_line(line: str, src: str):
    cat, sev = 'other', 'info'
    for rx, (c, s) in _PATTERNS:
        if rx.search(line):
            cat, sev = c, s
            break

    peer, ip, ts = "", "", ""
    m = re.search(r'peer\s+([A-Za-z0-9+/=]{8,})', line)
    if m: peer = m.group(1)
    m = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b', line)
    if m: ip = m.group(0)
    m = re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line)
    if m: ts = m.group(0)

    return {
        "ts": ts, "src": src,
        "category": cat, "severity": sev,
        "peer": peer, "ip": ip,
        "message": line
    }


# -------- Page principale /logs --------
@bp.route("/")
def logs_page():
    running, status, peers, server = _common_context()
    wg_recent = _read_command("sudo wg show") or "wg show vide."
    j_recent = _read_command("journalctl -u wg-quick@wg0.service -n 200 --no-pager")

    return render_template(
        "logs.html",
        active_tab="logs",
        running=running,
        status=status,
        peers=peers,
        server=server,
        wg_recent=wg_recent,
        j_recent=j_recent
    )


# -------- API /logs/api --------
@bp.route("/api")
def logs_api():
    source = request.args.get("source", "systemd")
    lines = int(request.args.get("lines", "300"))
    q = (request.args.get("q", "") or "").strip()

    if source == "wg":
        text = _read_command("sudo wg show")
    elif source == "kernel":
        text = _read_command(f"dmesg --ctime | tail -n {lines}")
    else:
        text = _read_command(f"journalctl -u wg-quick@wg0.service -n {lines} --no-pager")

    if q:
        text = "\n".join([L for L in text.splitlines() if q.lower() in L.lower()])
    return Response(text, mimetype="text/plain")


# -------- Streaming des logs (Server-Sent Events) --------
@bp.route("/stream")
def logs_stream():
    source = request.args.get("source", "systemd")
    if source == "wg":
        cmd = None
    elif source == "kernel":
        cmd = "dmesg --follow --ctime"
    else:
        cmd = "journalctl -u wg-quick@wg0.service -f -n 0 --no-pager"

    @stream_with_context
    def gen():
        if not cmd:
            prev = ""
            while True:
                cur = _read_command("sudo wg show")
                if cur != prev:
                    for line in cur.splitlines():
                        yield f"data: {line}\n\n"
                    prev = cur
                time.sleep(2)
        else:
            with subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as p:
                for line in p.stdout:
                    yield f"data: {line.rstrip()}\n\n"

    return Response(gen(), mimetype="text/event-stream")


# -------- Logs parsés et classifiés --------
@bp.route("/parsed.json")
def logs_parsed():
    source = request.args.get("source", "systemd")
    lines = int(request.args.get("lines", "500"))
    q = (request.args.get("q", "") or "").strip()
    catf = (request.args.get("category", "") or "").strip()

    if source == "wg":
        text = _read_command("sudo wg show")
    elif source == "kernel":
        text = _read_command(f"dmesg --ctime | tail -n {lines}")
    else:
        text = _read_command(f"journalctl -u wg-quick@wg0.service -n {lines} --no-pager")

    items, counts = [], {}
    for L in text.splitlines():
        if q and q.lower() not in L.lower():
            continue
        item = _classify_line(L, source)
        if catf and item["category"] != catf:
            continue
        items.append(item)
        counts[item["category"]] = counts.get(item["category"], 0) + 1

    return jsonify({"items": items, "counts": counts})


# -------- Derniers peers actifs --------
@bp.route("/peers/last.json")
def peers_last():
    peers = wg_manager.list_peers("wg0")
    out = []
    for p in peers:
        out.append({
            "public_key": p.get("public_key"),
            "endpoint": p.get("endpoint"),
            "latest_handshake": p.get("latest_handshake", "Never"),
            "rx": p.get("transfer_rx"),
            "tx": p.get("transfer_tx"),
        })

    def _key(hs):
        if not hs or hs == "Never": return (1, 0)
        try: return (0, int(hs))
        except: return (0, 0)
    out.sort(key=lambda x: _key(x["latest_handshake"]))
    return jsonify({"items": out})


# -------- Métriques RX/TX globales --------
def _parse_bytes(s: str) -> int:
    s = s.strip()
    parts = s.split()
    if len(parts) < 2:
        return 0
    val, unit = float(parts[0]), parts[1]
    mult = {"B":1, "KiB":1024, "MiB":1024**2, "GiB":1024**3, "TiB":1024**4}.get(unit, 1)
    return int(val * mult)

@bp.route("/metrics.json")
def metrics():
    peers = wg_manager.list_peers("wg0")
    total_rx = sum(_parse_bytes(p.get("transfer_rx", "0 B")) for p in peers)
    total_tx = sum(_parse_bytes(p.get("transfer_tx", "0 B")) for p in peers)
    return jsonify({"ts": int(datetime.now().timestamp()), "rx": total_rx, "tx": total_tx})
