from flask import Flask, render_template, redirect, url_for, flash, request, send_file, Response, jsonify
import io, qrcode
from flask_socketio import SocketIO, emit, disconnect
import threading
import paramiko, io as _io
import wg_manager
from datetime import datetime

app = Flask(__name__)
app.secret_key = "dev-secret-key"

# Force le moteur de WebSocket en mode threading (pas d'eventlet)
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# ---- Console SSH : configuration basique ----
ALLOW_HOSTS = [
    "127.0.0.1",
    "10.200.0.1",
    "10.200.0.2",
    "192.168.64.9", "192.168.64.10"
]

# -------------------- Helpers --------------------
def _common_context():
    running = wg_manager.is_wg_up("wg0")
    status = wg_manager.wg_show()
    peers = wg_manager.list_peers("wg0") if running else []
    server = wg_manager.get_server_info("wg0")
    return running, status, peers, server

def _find_peer(pubkey: str):
    for p in wg_manager.list_peers("wg0"):
        if p.get("public_key") == pubkey:
            return p
    return None

# -------------------- Pages (nouveau layout) --------------------
@app.route("/")
def home():
    running, status, peers, server = _common_context()
    return render_template(
        "dashboard.html",
        active_tab="dashboard",
        running=running, status=status, peers=peers, server=server
    )

@app.route("/peers")
def peers_page():
    running, status, peers, server = _common_context()
    return render_template(
        "peers.html",
        active_tab="peers",
        running=running, status=status, peers=peers, server=server
    )

@app.route("/server/settings", methods=["GET", "POST"])
def server_settings_page():
    running, status, peers, server = _common_context()
    if request.method == "POST":
        if "port" in request.form:
            try:
                new_port = int(request.form.get("port", ""))
                if not (1 <= new_port <= 65535):
                    raise ValueError
            except Exception:
                flash("Port invalide", "error")
                return redirect(url_for("server_settings_page"))
            if hasattr(wg_manager, "change_server_port"):
                ok, msg = wg_manager.change_server_port(new_port)
                flash(msg, "success" if ok else "error")
            else:
                flash("Changement de port non implémenté côté manager", "error")
        elif "rotate_keys" in request.form:
            if hasattr(wg_manager, "change_server_keys"):
                ok, msg = wg_manager.change_server_keys()
                flash(msg, "success" if ok else "error")
            else:
                flash("Rotation de clés non implémentée côté manager", "error")
        return redirect(url_for("server_settings_page"))

    info = server or {"listen_port": "?", "public_key": "?"}
    return render_template(
        "server_settings.html",
        active_tab="server",
        running=running, peers=peers, info=info, server=server
    )

# ---- Audit: classification des logs (backend) ----
import re

# (catégorie, sévérité) ; adapte si besoin
_PATTERNS = [
    (re.compile(r'(Started WireGuard|interface is up)', re.I), ('service.start','ok')),
    (re.compile(r'(Stopped WireGuard|Deactivated)', re.I),       ('service.stop','warn')),
    (re.compile(r'(Failed|failure|exit-code|cannot|denied)', re.I), ('system.error','error')),

    (re.compile(r'wireguard:.*handshake', re.I),                 ('peer.handshake','ok')),
    (re.compile(r'keepalive', re.I),                              ('peer.keepalive','info')),
    (re.compile(r'(handshake.*failed|retrying in|no route|invalid|bad)', re.I),
                                                                ('peer.fail','error')),
    (re.compile(r'peer .* endpoint', re.I),                      ('peer.endpoint_change','info')),
    (re.compile(r'(added peer|removed peer|AllowedIPs|ListenPort)', re.I),
                                                                ('config.change','info')),
]

def _classify_line(line: str, src: str):
    cat, sev = 'other', 'info'
    for rx, (c, s) in _PATTERNS:
        if rx.search(line):
            cat, sev = c, s
            break

    # heuristiques légères
    peer = None
    m = re.search(r'peer\s+([A-Za-z0-9+/=]{8,})', line)
    if m: peer = m.group(1)

    ip = None
    m = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b', line)
    if m: ip = m.group(0)

    # timestamp style 'Aug 14 06:16:13' si présent en tête
    ts = ''
    m = re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line)
    if m: ts = m.group(0)

    return {
        "ts": ts,
        "src": src,                 # 'systemd' | 'kernel' | 'wg'
        "category": cat,            # ex: 'peer.handshake'
        "severity": sev,            # ok|info|warn|error
        "peer": peer or "",
        "ip": ip or "",
        "message": line,
    }


# -------------------- Contrôles wg0 --------------------
@app.route("/start")
def start():
    ok, msg = wg_manager.start_wg("wg0")
    flash(msg, "success" if ok else "error")
    # revenir sur la page appelante si possible
    return redirect(request.referrer or url_for("home"))

@app.route("/stop")
def stop():
    ok, msg = wg_manager.stop_wg("wg0")
    flash(msg, "success" if ok else "error")
    return redirect(request.referrer or url_for("home"))

@app.route("/restart")
def restart():
    ok, msg = wg_manager.restart_wg("wg0")
    flash(msg, "success" if ok else "error")
    return redirect(request.referrer or url_for("home"))

# -------------------- Peers --------------------
@app.route("/peers/new", methods=["GET", "POST"])
def peers_new():
    if request.method == "POST":
        allowed = request.form.get("allowed_ips", "").strip()   # ex: 10.200.0.10/32
        keepalive = request.form.get("keepalive", "").strip()   # ex: 25

        # Validation /32
        if not wg_manager.validate_allowed_ip(allowed):
            flash("Adresse client invalide. Utilise une IP /32 (ex: 10.200.0.10/32).", "error")
            return redirect(url_for("peers_new"))
        # Optionnel: refuser doublon d'IP si la fonction existe
        try:
            if hasattr(wg_manager, "peer_exists_with_ip") and wg_manager.peer_exists_with_ip(allowed):
                flash("Un peer utilise déjà cette adresse /32.", "error")
                return redirect(url_for("peers_new"))
        except Exception:
            pass

        keys = wg_manager.gen_keys()
        if not keys:
            flash("Échec génération des clés", "error")
            return redirect(url_for("peers_page"))

        client_priv = keys["private"]
        client_pub  = keys["public"]

        ok, out = wg_manager.add_peer_live(client_pub, allowed, endpoint=None, keepalive=keepalive or None)
        if not ok:
            flash("Échec ajout live: " + out, "error")
            return redirect(url_for("peers_page"))

        ok, _ = wg_manager.append_peer_to_conf(client_pub, allowed, endpoint=None, keepalive=keepalive or None)
        if not ok:
            flash("Attention: ajout live OK mais pas écrit dans wg0.conf", "error")

        server = wg_manager.get_server_info("wg0")
        if not server:
            flash("Impossible de lire la clé publique/port serveur", "error")
            return redirect(url_for("peers_page"))

        endpoint_server = f"{request.host.split(':')[0]}:{server['listen_port']}"

        # Génère la conf client (évite le double /32)
        client_cfg = wg_manager.gen_client_config(
            server_public=server["public_key"],
            server_endpoint=endpoint_server,
            client_private=client_priv,
            client_address_cidr=allowed,
            keepalive=int(keepalive or 25),
            dns="1.1.1.1"
        )

        return Response(
            client_cfg,
            headers={"Content-Disposition": "attachment; filename=wg-client.conf"},
            mimetype="text/plain"
        )

    # GET
    running, status, peers, server = _common_context()
    return render_template(
        "new_peer.html",
        active_tab="peers",
        running=running, status=status, peers=peers, server=server
    )

@app.route("/peers/delete", methods=["POST"])
def peers_delete():
    pubkey = request.form.get("public_key", "").strip()
    if not pubkey:
        flash("Clé publique manquante", "error")
        return redirect(url_for("peers_page"))
    wg_manager.remove_peer_live(pubkey)
    ok, msg = wg_manager.remove_peer_from_conf(pubkey)
    flash("Peer supprimé" if ok else msg, "success" if ok else "error")
    return redirect(url_for("peers_page"))

# Formulaire d’édition (UI)
@app.route("/peers/edit")
def peers_edit_form():
    pubkey = request.args.get("public_key", "").strip()
    peer = _find_peer(pubkey)
    if not peer:
        flash("Peer introuvable", "error")
        return redirect(url_for("peers_page"))
    running, status, peers, server = _common_context()
    return render_template(
        "edit_peer.html",
        active_tab="peers",
        peer=peer,
        running=running, status=status, peers=peers, server=server
    )

# Enregistrement des modifications
@app.route("/peers/update", methods=["POST"])
def peers_update():
    pubkey = request.form.get("public_key", "").strip()
    new_allowed = (request.form.get("allowed_ips", "") or "").strip() or None
    keepalive = (request.form.get("keepalive", "") or "").strip() or None
    endpoint  = (request.form.get("endpoint", "") or "").strip() or None

    if new_allowed and not wg_manager.validate_allowed_ip(new_allowed):
        flash("AllowedIPs invalide (attendu: 10.200.0.X/32).", "error")
        return redirect(url_for("peers_edit_form", public_key=pubkey))

    if hasattr(wg_manager, "edit_peer"):
        ok, msg = wg_manager.edit_peer(pubkey, new_allowed=new_allowed, keepalive=keepalive, endpoint=endpoint)
    else:
        ok, msg = (True, "Aucun changement")
        if new_allowed:
            ok, msg = wg_manager.update_peer_allowed_ips(pubkey, new_allowed)

    flash(msg, "success" if ok else "error")
    return redirect(url_for("peers_page"))

# QR Code (optionnel, si tu le gardes)
@app.route("/peers/qr", methods=["POST"])
def peers_qr():
    cfg = request.form.get("config", "").strip()
    if not cfg:
        flash("Configuration vide", "error")
        return redirect(url_for("peers_page"))
    img = qrcode.make(cfg)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png", download_name="wg-client-qr.png")

# -------------------- Metrics (graphe gauche) --------------------
def _parse_bytes(s: str) -> int:
    s = s.strip()
    parts = s.split()
    if len(parts) < 2:
        return 0
    val, unit = float(parts[0]), parts[1]
    mult = {"B":1, "KiB":1024, "MiB":1024**2, "GiB":1024**3, "TiB":1024**4}.get(unit, 1)
    return int(val * mult)

@app.route("/metrics.json")
def metrics():
    peers = wg_manager.list_peers("wg0")
    total_rx = sum(_parse_bytes(p.get("transfer_rx", "0 B")) for p in peers)
    total_tx = sum(_parse_bytes(p.get("transfer_tx", "0 B")) for p in peers)
    return jsonify({"ts": int(datetime.now().timestamp()), "rx": total_rx, "tx": total_tx})

# -------------------- Conf serveur (download / restore) --------------------
@app.route("/server/conf")
def server_conf_download():
    if hasattr(wg_manager, "download_conf"):
        ok, text = wg_manager.download_conf()
        if ok:
            return Response(text, headers={"Content-Disposition": "attachment; filename=wg0.conf"}, mimetype="text/plain")
        flash(text, "error")
        return redirect(url_for("server_settings_page"))
    # fallback si pas d’helper
    return Response(wg_manager.wg_show(), mimetype="text/plain")

@app.route("/server/restore", methods=["GET", "POST"])
def server_restore():
    running, status, peers, server = _common_context()
    if request.method == "POST":
        backup_path = (request.form.get("backup_path", "") or "").strip()
        if not backup_path:
            flash("Chemin de backup requis", "error")
            return redirect(url_for("server_restore"))
        if hasattr(wg_manager, "restore_conf"):
            ok, msg = wg_manager.restore_conf(backup_path)
            flash(msg, "success" if ok else "error")
            return redirect(url_for("server_settings_page"))
        flash("Restauration non implémentée côté manager", "error")
        return redirect(url_for("server_restore"))
    return render_template(
        "server_restore.html",
        active_tab="server",
        running=running, status=status, peers=peers, server=server
    )

# -------------------- Etat serveur (page + API JSON) --------------------
import os, time, socket, shutil

@app.route("/status")
def status_page():
    running, status, peers, server = _common_context()
    return render_template(
        "status.html",
        active_tab="status",
        running=running, status=status, peers=peers, server=server
    )

def _cpu_percent_sample(interval=0.2):
    # calcule %CPU en lisant /proc/stat deux fois
    def snap():
        with open("/proc/stat") as f:
            cpu = f.readline().split()
        vals = list(map(int, cpu[1:8]))  # user nice system idle iowait irq softirq
        idle = vals[3] + vals[4]
        total = sum(vals)
        return idle, total
    idle1, total1 = snap()
    time.sleep(interval)
    idle2, total2 = snap()
    didle = idle2 - idle1
    dtotal = total2 - total1
    if dtotal <= 0: 
        return 0.0
    return round(100.0 * (1.0 - (didle / dtotal)), 1)

def _mem_info():
    mt = ma = 0
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemTotal:"): mt = int(line.split()[1])  # kB
            if line.startswith("MemAvailable:"): ma = int(line.split()[1])
    used = max(0, mt - ma)
    return {
        "total_kb": mt,
        "used_kb": used,
        "percent": round(100.0 * used / mt, 1) if mt else 0.0
    }

def _uptime():
    with open("/proc/uptime") as f:
        secs = float(f.read().split()[0])
    secs = int(secs)
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    human = f"{days}j {hours}h {mins}m"
    return secs, human

@app.route("/system.json")
def system_json():
    cpu = _cpu_percent_sample(0.2)
    mem = _mem_info()
    du = shutil.disk_usage("/")
    disk_total = du.total
    disk_used = du.total - du.free
    disk_percent = round(100.0 * disk_used / disk_total, 1) if disk_total else 0.0
    up_secs, up_human = _uptime()

    data = {
        "ts": int(time.time()),
        "host": socket.gethostname(),
        "kernel": os.uname().release,
        "ips": os.popen("hostname -I 2>/dev/null").read().strip(),
        "uptime": {"seconds": up_secs, "human": up_human},
        "cpu": {"percent": cpu},
        "mem": {
            "percent": mem["percent"],
            "used_kb": mem["used_kb"],
            "total_kb": mem["total_kb"]
        },
        "disk": {
            "percent": disk_percent,
            "used": disk_used,
            "total": disk_total
        }
    }
    return jsonify(data)

# -------------------- Journal / Audit --------------------
import subprocess, shlex
from flask import stream_with_context

def _read_command(cmd: str) -> str:
    try:
        p = subprocess.run(shlex.split(cmd), text=True, capture_output=True, check=False)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return str(e)

@app.route("/logs")
def logs_page():
    running, status, peers, server = _common_context()
    # un extrait initial (dernieres lignes)
    wg_recent = _read_command("sudo wg show") or "wg show vide."
    j_recent  = _read_command("journalctl -u wg-quick@wg0.service -n 200 --no-pager")
    return render_template(
        "logs.html",
        active_tab="logs",
        running=running, status=status, peers=peers, server=server,
        wg_recent=wg_recent, j_recent=j_recent
    )

# API: récupérer un “snapshot” avec filtres simples
@app.route("/logs/api")
def logs_api():
    source = request.args.get("source","systemd")  # wg | systemd | kernel
    lines  = int(request.args.get("lines","300"))
    q      = (request.args.get("q","") or "").strip()

    if source == "wg":
        text = _read_command("sudo wg show")
    elif source == "kernel":
        text = _read_command(f"dmesg --ctime | tail -n {lines}")
    else:
        text = _read_command(f"journalctl -u wg-quick@wg0.service -n {lines} --no-pager")

    if q:
        text = "\n".join([L for L in text.splitlines() if q.lower() in L.lower()])
    return Response(text, mimetype="text/plain")

# API: streaming (tail -f) via Server-Sent Events
@app.route("/logs/stream")
def logs_stream():
    source = request.args.get("source","systemd")
    if source == "wg":
        # wg n’a pas de “tail -f” → on re-dump périodiquement
        cmd = None
    elif source == "kernel":
        cmd = "dmesg --follow --ctime"
    else:
        cmd = "journalctl -u wg-quick@wg0.service -f -n 0 --no-pager"

    @stream_with_context
    def gen():
        if not cmd:
            # fallback: rediffuse wg show toutes les 2s
            import time
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

@app.route("/logs/parsed.json")
def logs_parsed():
    source = request.args.get("source","systemd")  # wg | systemd | kernel
    lines  = int(request.args.get("lines","500"))
    q      = (request.args.get("q","") or "").strip()
    catf   = (request.args.get("category","") or "").strip()  # filtre cat optionnel

    if source == "wg":
        text = _read_command("sudo wg show")
    elif source == "kernel":
        text = _read_command(f"dmesg --ctime | tail -n {lines}")
    else:
        text = _read_command(f"journalctl -u wg-quick@wg0.service -n {lines} --no-pager")

    items = []
    for L in text.splitlines():
        if q and q.lower() not in L.lower():
            continue
        item = _classify_line(L, source)
        if catf and item["category"] != catf:
            continue
        items.append(item)

    # petits compteurs par catégorie
    counts = {}
    for it in items:
        counts[it["category"]] = counts.get(it["category"], 0) + 1

    return jsonify({"items": items, "counts": counts})

@app.route("/logs/peers/last.json")
def peers_last():
    peers = wg_manager.list_peers("wg0")
    out = []
    for p in peers:
        out.append({
            "public_key": p.get("public_key"),
            "endpoint": p.get("endpoint"),
            "latest_handshake": p.get("latest_handshake","Never"),
            "rx": p.get("transfer_rx"),
            "tx": p.get("transfer_tx"),
        })
    # tri: ceux avec handshake récent d'abord (met "Never" en bas)
    def _key(hs):
        if not hs or hs == "Never": return (1, 0)
        # wg dump renvoie souvent un epoch ; si c'est du texte "2 minutes ago", on garde l'ordre brut
        try: return (0, int(hs))
        except: return (0, 0)
    out.sort(key=lambda x: _key(x["latest_handshake"]))
    return jsonify({"items": out})

@app.route("/terminal")
def terminal_page():
    running, status, peers, server = _common_context()
    return render_template(
        "terminal.html",
        active_tab="terminal",
        running=running, status=status, peers=peers, server=server,
        allow_hosts=ALLOW_HOSTS
    )

# ---- WebSocket <-> SSH bridge ----
_SESS = {}  # sid -> {"client":paramiko.SSHClient, "chan":Channel, "thr":Thread, "readonly":bool}

def _reader_loop(sid):
    try:
        chan = _SESS[sid]["chan"]
        while True:
            if chan.recv_ready():
                data = chan.recv(4096)
                if not data:
                    break
                socketio.emit("stdout", data.decode("utf-8", "ignore"), to=sid, namespace="/tty")
            if chan.recv_stderr_ready():
                data = chan.recv_stderr(4096)
                if data:
                    socketio.emit("stdout", data.decode("utf-8", "ignore"), to=sid, namespace="/tty")
            time.sleep(0.02)  
    except Exception as e:
        socketio.emit("status", {"state":"closed", "msg": str(e)}, to=sid, namespace="/tty")
    finally:
        # fermeture propre
        try:
            _SESS[sid]["chan"].close()
        except: pass
        try:
            _SESS[sid]["client"].close()
        except: pass
        _SESS.pop(sid, None)
        socketio.emit("status", {"state":"closed"}, to=sid, namespace="/tty")

@socketio.on("connect", namespace="/tty")
def _ws_connect():
    emit("status", {"state":"connected"})

@socketio.on("disconnect", namespace="/tty")
def _ws_disconnect():
    s = _SESS.pop(request.sid, None)
    if s:
        try: s["chan"].close()
        except: pass
        try: s["client"].close()
        except: pass

@socketio.on("connect_ssh", namespace="/tty")
def _connect_ssh(payload):
    """
    payload: {
      host, port, user, password?, pkey?, passphrase?, cols?, rows?, readonly?
    }
    """
    sid = request.sid
    host = (payload.get("host") or "").strip()
    port = int(payload.get("port") or 22)
    user = (payload.get("user") or "").strip()
    password   = payload.get("password") or None
    pkey_text  = payload.get("pkey") or None
    passphrase = payload.get("passphrase") or None
    cols = int(payload.get("cols") or 100)
    rows = int(payload.get("rows") or 30)
    readonly = bool(payload.get("readonly") or False)

    if host not in ALLOW_HOSTS:
        emit("status", {"state":"error", "msg":"Hôte non autorisé"}); return
    if not user:
        emit("status", {"state":"error", "msg":"Utilisateur manquant"}); return
    if not (password or pkey_text):
        emit("status", {"state":"error", "msg":"Mot de passe ou clé privée requis"}); return

    try:
        key = None
        if pkey_text:
            # essaie Ed25519, RSA, ECDSA
            for K in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                try:
                    key = K.from_private_key(_io.StringIO(pkey_text), password=passphrase)
                    break
                except Exception:
                    key = None
            if key is None:
                emit("status", {"state":"error", "msg":"Clé privée invalide / passphrase incorrecte"})
                return

        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(
            hostname=host, port=port, username=user,
            password=password, pkey=key, look_for_keys=False, allow_agent=False,
            timeout=10
        )
        chan = cli.invoke_shell(term="xterm-256color", width=cols, height=rows)
        chan.settimeout(0.0)  # non bloquant

        _SESS[sid] = {"client":cli, "chan":chan, "thr":None, "readonly":readonly}
        t = threading.Thread(target=_reader_loop, args=(sid,), daemon=True)
        _SESS[sid]["thr"] = t
        t.start()

        emit("status", {"state":"ready"})
    except Exception as e:
        emit("status", {"state":"error", "msg": str(e)})

@socketio.on("stdin", namespace="/tty")
def _stdin(data):
    sid = request.sid
    s = _SESS.get(sid)
    if not s:
        return
    if s.get("readonly"):
        return
    try:
        s["chan"].send(data)
    except Exception as e:
        emit("status", {"state":"error", "msg": str(e)})

@socketio.on("resize", namespace="/tty")
def _resize(payload):
    sid = request.sid
    s = _SESS.get(sid)
    if not s: return
    try:
        cols = int(payload.get("cols") or 100)
        rows = int(payload.get("rows") or 30)
        s["chan"].resize_pty(width=cols, height=rows)
    except Exception:
        pass

@socketio.on("disconnect_ssh", namespace="/tty")
def _disconnect_ssh():
    sid = request.sid
    s = _SESS.pop(sid, None)
    if not s: return
    try: s["chan"].close()
    except: pass
    try: s["client"].close()
    except: pass
    emit("status", {"state":"closed"})



# -------------------- Lancement --------------------
# -------------------- Lancement --------------------
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
