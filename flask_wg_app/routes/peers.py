from flask import Blueprint, render_template, request, flash, redirect, url_for, Response, send_file
import io, qrcode
import wg_manager
from datetime import datetime

bp = Blueprint("peers", __name__)

# --------- Helpers ---------
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


# --------- Pages principales ---------
@bp.route("/")
def list_peers_page():
    running, status, peers, server = _common_context()
    return render_template(
        "peers.html",
        active_tab="peers",
        running=running,
        status=status,
        peers=peers,
        server=server
    )


# --------- Ajouter un peer ---------
@bp.route("/new", methods=["GET", "POST"])
def peers_new():
    if request.method == "POST":
        allowed = request.form.get("allowed_ips", "").strip()
        keepalive = request.form.get("keepalive", "").strip()

        if not wg_manager.validate_allowed_ip(allowed):
            flash("Adresse client invalide. Utilise une IP /32 (ex: 10.200.0.10/32).", "error")
            return redirect(url_for("peers.peers_new"))

        try:
            if hasattr(wg_manager, "peer_exists_with_ip") and wg_manager.peer_exists_with_ip(allowed):
                flash("Un peer utilise déjà cette adresse /32.", "error")
                return redirect(url_for("peers.peers_new"))
        except Exception:
            pass

        keys = wg_manager.gen_keys()
        if not keys:
            flash("Échec de génération des clés.", "error")
            return redirect(url_for("peers.list_peers_page"))

        client_priv, client_pub = keys["private"], keys["public"]

        ok, out = wg_manager.add_peer_live(client_pub, allowed, endpoint=None, keepalive=keepalive or None)
        if not ok:
            flash("Échec ajout live: " + out, "error")
            return redirect(url_for("peers.list_peers_page"))

        ok, _ = wg_manager.append_peer_to_conf(client_pub, allowed, endpoint=None, keepalive=keepalive or None)
        if not ok:
            flash("Ajout live OK mais pas écrit dans wg0.conf", "warning")

        server = wg_manager.get_server_info("wg0")
        if not server:
            flash("Impossible de lire la clé publique/port serveur", "error")
            return redirect(url_for("peers.list_peers_page"))

        endpoint_server = f"{request.host.split(':')[0]}:{server['listen_port']}"

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

    running, status, peers, server = _common_context()
    return render_template(
        "new_peer.html",
        active_tab="peers",
        running=running,
        status=status,
        peers=peers,
        server=server
    )


# --------- Supprimer un peer ---------
@bp.route("/delete", methods=["POST"])
def peers_delete():
    pubkey = request.form.get("public_key", "").strip()
    if not pubkey:
        flash("Clé publique manquante", "error")
        return redirect(url_for("peers.list_peers_page"))

    wg_manager.remove_peer_live(pubkey)
    ok, msg = wg_manager.remove_peer_from_conf(pubkey)
    flash("Peer supprimé" if ok else msg, "success" if ok else "error")
    return redirect(url_for("peers.list_peers_page"))


# --------- Modifier un peer ---------
@bp.route("/edit")
def peers_edit_form():
    pubkey = request.args.get("public_key", "").strip()
    peer = _find_peer(pubkey)
    if not peer:
        flash("Peer introuvable", "error")
        return redirect(url_for("peers.list_peers_page"))

    running, status, peers, server = _common_context()
    return render_template(
        "edit_peer.html",
        active_tab="peers",
        peer=peer,
        running=running,
        status=status,
        peers=peers,
        server=server
    )

@bp.route("/update", methods=["POST"])
def peers_update():
    pubkey = request.form.get("public_key", "").strip()
    new_allowed = (request.form.get("allowed_ips", "") or "").strip() or None
    keepalive = (request.form.get("keepalive", "") or "").strip() or None
    endpoint = (request.form.get("endpoint", "") or "").strip() or None

    if new_allowed and not wg_manager.validate_allowed_ip(new_allowed):
        flash("AllowedIPs invalide (attendu: 10.200.0.X/32).", "error")
        return redirect(url_for("peers.peers_edit_form", public_key=pubkey))

    if hasattr(wg_manager, "edit_peer"):
        ok, msg = wg_manager.edit_peer(pubkey, new_allowed=new_allowed, keepalive=keepalive, endpoint=endpoint)
    else:
        ok, msg = (True, "Aucun changement")
        if new_allowed:
            ok, msg = wg_manager.update_peer_allowed_ips(pubkey, new_allowed)

    flash(msg, "success" if ok else "error")
    return redirect(url_for("peers.list_peers_page"))


# --------- QR Code pour le client ---------
@bp.route("/qr", methods=["POST"])
def peers_qr():
    cfg = request.form.get("config", "").strip()
    if not cfg:
        flash("Configuration vide", "error")
        return redirect(url_for("peers.list_peers_page"))

    img = qrcode.make(cfg)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png", download_name="wg-client-qr.png")
