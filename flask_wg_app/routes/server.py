from flask import Blueprint, render_template, request, flash, redirect, url_for, Response, jsonify
import wg_manager, os, time, socket, shutil
from datetime import datetime

bp = Blueprint("server", __name__)

# -------- Helpers communs --------
def _common_context():
    running = wg_manager.is_wg_up("wg0")
    status = wg_manager.wg_show()
    peers = wg_manager.list_peers("wg0") if running else []
    server = wg_manager.get_server_info("wg0")
    return running, status, peers, server


# -------- Paramètres serveur --------
@bp.route("/settings", methods=["GET", "POST"])
def settings_page():
    running, status, peers, server = _common_context()

    if request.method == "POST":
        if "port" in request.form:
            try:
                new_port = int(request.form.get("port", ""))
                if not (1 <= new_port <= 65535):
                    raise ValueError
            except Exception:
                flash("Port invalide", "error")
                return redirect(url_for("server.settings_page"))

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

        return redirect(url_for("server.settings_page"))

    info = server or {"listen_port": "?", "public_key": "?"}
    return render_template(
        "server_settings.html",
        active_tab="server",
        running=running,
        peers=peers,
        info=info,
        server=server
    )


# -------- Télécharger la configuration serveur --------
@bp.route("/conf")
def conf_download():
    if hasattr(wg_manager, "download_conf"):
        ok, text = wg_manager.download_conf()
        if ok:
            return Response(
                text,
                headers={"Content-Disposition": "attachment; filename=wg0.conf"},
                mimetype="text/plain"
            )
        flash(text, "error")
        return redirect(url_for("server.settings_page"))

    # fallback
    return Response(wg_manager.wg_show(), mimetype="text/plain")


# -------- Restaurer une sauvegarde --------
@bp.route("/restore", methods=["GET", "POST"])
def restore():
    running, status, peers, server = _common_context()
    if request.method == "POST":
        backup_path = (request.form.get("backup_path", "") or "").strip()
        if not backup_path:
            flash("Chemin de backup requis", "error")
            return redirect(url_for("server.restore"))

        if hasattr(wg_manager, "restore_conf"):
            ok, msg = wg_manager.restore_conf(backup_path)
            flash(msg, "success" if ok else "error")
            return redirect(url_for("server.settings_page"))

        flash("Restauration non implémentée côté manager", "error")
        return redirect(url_for("server.restore"))

    return render_template(
        "server_restore.html",
        active_tab="server",
        running=running,
        status=status,
        peers=peers,
        server=server
    )


# -------- Page statut serveur --------
@bp.route("/status")
def status_page():
    running, status, peers, server = _common_context()
    return render_template(
        "status.html",
        active_tab="status",
        running=running,
        status=status,
        peers=peers,
        server=server
    )


# --------- API système (CPU, mémoire, disque, uptime) ---------
def _cpu_percent_sample(interval=0.2):
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
            if line.startswith("MemTotal:"):
                mt = int(line.split()[1])
            if line.startswith("MemAvailable:"):
                ma = int(line.split()[1])
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
    return secs, f"{days}j {hours}h {mins}m"

@bp.route("/system.json")
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
        "mem": mem,
        "disk": {
            "percent": disk_percent,
            "used": disk_used,
            "total": disk_total
        }
    }
    return jsonify(data)
