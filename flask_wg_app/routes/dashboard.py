from flask import Blueprint, render_template, redirect, url_for, flash, request
import wg_manager

bp = Blueprint("dashboard", __name__)

def _common_context():
    running = wg_manager.is_wg_up("wg0")
    status = wg_manager.wg_show()
    peers = wg_manager.list_peers("wg0") if running else []
    server = wg_manager.get_server_info("wg0")
    return running, status, peers, server

@bp.route("/")
def home():
    running, status, peers, server = _common_context()
    return render_template(
        "dashboard.html",
        active_tab="dashboard",
        running=running,
        status=status,
        peers=peers,
        server=server
    )

@bp.route("/start")
def start():
    ok, msg = wg_manager.start_wg("wg0")
    flash(msg, "success" if ok else "error")
    return redirect(request.referrer or url_for("dashboard.home"))

@bp.route("/stop")
def stop():
    ok, msg = wg_manager.stop_wg("wg0")
    flash(msg, "success" if ok else "error")
    return redirect(request.referrer or url_for("dashboard.home"))

@bp.route("/restart")
def restart():
    ok, msg = wg_manager.restart_wg("wg0")
    flash(msg, "success" if ok else "error")
    return redirect(request.referrer or url_for("dashboard.home"))
