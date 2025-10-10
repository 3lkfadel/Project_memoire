# routes/status.py
from flask import Blueprint, render_template, jsonify
import os, time, shutil, socket
import wg_manager

bp = Blueprint("status", __name__)

def _common_context():
    running = wg_manager.is_wg_up("wg0")
    status  = wg_manager.wg_show()
    peers   = wg_manager.list_peers("wg0") if running else []
    server  = wg_manager.get_server_info("wg0")
    return running, status, peers, server

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
            if line.startswith("MemTotal:"): mt = int(line.split()[1])
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

@bp.route("/status")
def status_page():
    running, status, peers, server = _common_context()
    return render_template(
        "status.html",
        active_tab="status",
        running=running, status=status, peers=peers, server=server
    )

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
