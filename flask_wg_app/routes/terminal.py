# routes/terminal.py
from flask import Blueprint, render_template, request
import threading, time, paramiko, io as _io
import wg_manager

bp = Blueprint("terminal", __name__)

# Liste blanche des hôtes accessibles (déplace-la en config si tu veux)
ALLOW_HOSTS = {
    "127.0.0.1",
    "10.200.0.1",
    "10.200.0.2",
    "192.168.64.9",
    "192.168.64.10",
}

# --- helpers communs ---
def _common_context():
    running = wg_manager.is_wg_up("wg0")
    status  = wg_manager.wg_show()
    peers   = wg_manager.list_peers("wg0") if running else []
    server  = wg_manager.get_server_info("wg0")
    return running, status, peers, server

@bp.route("/")
def page():
    running, status, peers, server = _common_context()
    return render_template(
        "terminal.html",
        active_tab="terminal",
        running=running, status=status, peers=peers, server=server,
        allow_hosts=sorted(ALLOW_HOSTS)
    )

# ================== WebSocket (via Flask-SocketIO) ==================
# On évite l'import circulaire avec app.py :
# - on définit une fonction d'initialisation appelée depuis app.py
# - on stocke la référence socketio dans une variable locale

_SOCKETIO = None
_SESS = {}  # sid -> {"client":paramiko.SSHClient, "chan":Channel, "thr":Thread, "readonly":bool}

def init_socketio(socketio):
    """À appeler depuis app.py après avoir instancié SocketIO(app, ...)."""
    global _SOCKETIO
    _SOCKETIO = socketio

    # -------- Handlers --------
    @socketio.on("connect", namespace="/tty")
    def _ws_connect():
        socketio.emit("status", {"state": "connected"}, namespace="/tty")

    @socketio.on("disconnect", namespace="/tty")
    def _ws_disconnect():
        s = _SESS.pop(request.sid, None)
        if s:
            try: s["chan"].close()
            except: pass
            try: s["client"].close()
            except: pass

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
            try: _SESS[sid]["chan"].close()
            except: pass
            try: _SESS[sid]["client"].close()
            except: pass
            _SESS.pop(sid, None)
            socketio.emit("status", {"state":"closed"}, to=sid, namespace="/tty")

    @socketio.on("connect_ssh", namespace="/tty")
    def _connect_ssh(payload):
        """
        payload: {host, port, user, password?, pkey?, passphrase?, cols?, rows?, readonly?}
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
            socketio.emit("status", {"state":"error", "msg":"Hôte non autorisé"}, to=sid, namespace="/tty"); return
        if not user:
            socketio.emit("status", {"state":"error", "msg":"Utilisateur manquant"}, to=sid, namespace="/tty"); return
        if not (password or pkey_text):
            socketio.emit("status", {"state":"error", "msg":"Mot de passe ou clé privée requis"}, to=sid, namespace="/tty"); return

        try:
            key = None
            if pkey_text:
                for K in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
                    try:
                        key = K.from_private_key(_io.StringIO(pkey_text), password=passphrase)
                        break
                    except Exception:
                        key = None
                if key is None:
                    socketio.emit("status", {"state":"error", "msg":"Clé privée invalide / passphrase incorrecte"}, to=sid, namespace="/tty")
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

            _SESS[sid] = {"client": cli, "chan": chan, "thr": None, "readonly": readonly}
            t = threading.Thread(target=_reader_loop, args=(sid,), daemon=True)
            _SESS[sid]["thr"] = t
            t.start()

            socketio.emit("status", {"state":"ready"}, to=sid, namespace="/tty")
        except Exception as e:
            socketio.emit("status", {"state":"error", "msg": str(e)}, to=sid, namespace="/tty")

    @socketio.on("stdin", namespace="/tty")
    def _stdin(data):
        s = _SESS.get(request.sid)
        if not s or s.get("readonly"):
            return
        try:
            s["chan"].send(data)
        except Exception as e:
            _SOCKETIO.emit("status", {"state":"error", "msg": str(e)}, to=request.sid, namespace="/tty")

    @socketio.on("resize", namespace="/tty")
    def _resize(payload):
        s = _SESS.get(request.sid)
        if not s: return
        try:
            cols = int(payload.get("cols") or 100)
            rows = int(payload.get("rows") or 30)
            s["chan"].resize_pty(width=cols, height=rows)
        except Exception:
            pass

    @socketio.on("disconnect_ssh", namespace="/tty")
    def _disconnect_ssh():
        s = _SESS.pop(request.sid, None)
        if not s: return
        try: s["chan"].close()
        except: pass
        try: s["client"].close()
        except: pass
        _SOCKETIO.emit("status", {"state":"closed"}, to=request.sid, namespace="/tty")
