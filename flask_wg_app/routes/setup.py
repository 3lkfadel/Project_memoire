from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from markupsafe import Markup
import os, subprocess, tempfile
import wg_manager

bp = Blueprint("setup", __name__)
UPLOAD_DIR = "/var/lib/novaguard/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -------- Helpers communs --------
def _common_context():
    running = wg_manager.is_wg_up("wg0")
    status  = wg_manager.wg_show()
    peers   = wg_manager.list_peers("wg0") if running else []
    server  = wg_manager.get_server_info("wg0")
    return running, status, peers, server


# -------- Page /setup --------
@bp.route("/", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        f = request.files.get("conf")
        iface = (request.form.get("iface") or "wg0").strip()

        if not f or not f.filename.endswith(".conf"):
            flash(("error", "Charge un fichier .conf valide (wg0.conf)."))
            return redirect(url_for("setup.setup"))

        tmp_path = os.path.join(UPLOAD_DIR, next(tempfile._get_candidate_names()) + ".conf")
        f.save(tmp_path)

        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()

        if "[Interface]" not in content or "PrivateKey" not in content:
            os.remove(tmp_path)
            flash(("error", "Fichier invalide : section [Interface]/PrivateKey manquante."))
            return redirect(url_for("setup.setup"))

        # Appel de l’application novaguard-apply
        proc = subprocess.run(
            ["sudo", "/usr/local/bin/novaguard-apply", "--iface", iface, "--conf", tmp_path],
            capture_output=True, text=True, timeout=600
        )
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")

        if proc.returncode == 0:
            flash(("success", f"Configuration terminée pour {iface}."))
            flash(("info", Markup(f"<pre class='panel-raw'>{out}</pre>")))
        else:
            flash(("error", f"Échec de l’installation ({proc.returncode})."))
            flash(("error", Markup(f"<pre class='panel-raw'>{out}</pre>")))

        return redirect(url_for("setup.setup"))

    running, status, peers, server = _common_context()
    return render_template(
        "setup.html",
        active_tab="setup",
        running=running, status=status, peers=peers, server=server
    )


# -------- Génération de clés --------
def _wg_genkeypair():
    """Retourne (priv, pub) avec wg genkey/pubkey."""
    p = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True)
    priv = p.stdout.strip()
    p2 = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True)
    pub = p2.stdout.strip()
    return priv, pub

@bp.route("/genkeys.json")
def genkeys_json():
    try:
        priv, pub = _wg_genkeypair()
        return jsonify({"ok": True, "private": priv, "public": pub})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# -------- Génération d’une nouvelle config WireGuard --------
def _build_server_conf(priv, address_cidr, listen_port, dns=None, peers_rows=None, add_basic_firewall=True):
    lines = []
    lines += ["[Interface]"]
    lines += [f"PrivateKey = {priv}", f"Address = {address_cidr}", f"ListenPort = {listen_port}"]
    if dns:
        lines += [f"DNS = {dns}"]
    if add_basic_firewall:
        lines += [
            "PostUp = sysctl -w net.ipv4.ip_forward=1",
            "PostDown = sysctl -w net.ipv4.ip_forward=0"
        ]
    lines += [""]

    peers_rows = peers_rows or []
    for row in peers_rows:
        pub = (row.get("pub") or "").strip()
        allowed = (row.get("allowed") or "").strip()
        ka = (row.get("keepalive") or "").strip()
        if not pub or not allowed:
            continue
        lines += ["[Peer]", f"PublicKey = {pub}", f"AllowedIPs = {allowed}"]
        if ka:
            lines += [f"PersistentKeepalive = {ka}"]
        lines += [""]

    return "\n".join(lines).strip() + "\n"


@bp.route("/generate", methods=["POST"])
def setup_generate():
    iface = (request.form.get("iface") or "wg0").strip()
    listen_port = (request.form.get("listen_port") or "51820").strip()
    addr = (request.form.get("address_cidr") or "").strip()
    dns = (request.form.get("dns") or "").strip()
    priv = (request.form.get("server_priv") or "").strip()
    add_fw = bool(request.form.get("add_fw"))

    peers_rows = []
    for i in range(1, 6):
        peers_rows.append({
            "pub": request.form.get(f"peer{i}_pub", "") or "",
            "allowed": request.form.get(f"peer{i}_allowed", "") or "",
            "keepalive": request.form.get(f"peer{i}_ka", "") or ""
        })

    if not priv:
        try:
            priv, _pub = _wg_genkeypair()
        except Exception as e:
            flash(("error", f"Impossible de générer les clés : {e}"))
            return redirect(url_for("setup.setup"))

    if not addr or "/" not in addr:
        flash(("error", "Adresse CIDR invalide (ex: 10.200.0.1/24)."))
        return redirect(url_for("setup.setup"))
    try:
        int(listen_port)
    except:
        flash(("error", "Port invalide."))
        return redirect(url_for("setup.setup"))

    conf_text = _build_server_conf(priv, addr, listen_port, dns=dns or None,
                                   peers_rows=peers_rows, add_basic_firewall=add_fw)

    tmp_path = os.path.join(UPLOAD_DIR, next(tempfile._get_candidate_names()) + ".conf")
    with open(tmp_path, "w") as f:
        f.write(conf_text)

    proc = subprocess.run(
        ["sudo", "/usr/local/bin/novaguard-apply", "--iface", iface, "--conf", tmp_path],
        capture_output=True, text=True
    )
    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")

    if proc.returncode == 0:
        flash(("success", f"{iface} généré et appliqué."))
        flash(("info", Markup(f"<pre class='panel-raw'>{out}</pre>")))
    else:
        flash(("error", f"Échec application ({proc.returncode})."))
        flash(("error", Markup(f"<pre class='panel-raw'>{out}</pre>")))

    return redirect(url_for("setup.setup"))
