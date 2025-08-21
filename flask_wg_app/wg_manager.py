# -*- coding: utf-8 -*-
import subprocess, shlex, re, os
from typing import Tuple, Dict, List, Optional

WG_IFACE = "wg0"
WG_CONF  = f"/etc/wireguard/{WG_IFACE}.conf"

def _run(cmd: List[str]) -> Tuple[bool, str]:
    """Exécute une commande et renvoie (ok, stdout|stderr). Toutes les
    commandes nécessitant des privilèges sont préfixées par sudo ici."""
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, check=False)
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
        return (p.returncode == 0, out.strip())
    except Exception as e:
        return (False, str(e))

# ---------- Infos / état ----------
def is_wg_up(iface: str = WG_IFACE) -> bool:
    ok, out = _run(["ip", "link", "show", iface])
    return ok and "state" in out

def wg_show() -> str:
    ok, out = _run(["sudo", "wg", "show"])
    return out if ok else out  # on renvoie même en cas d’erreur pour debug

def get_server_info(iface: str = WG_IFACE) -> Optional[Dict[str, str]]:
    # wg show wg0 dump => première ligne = interface
    ok, out = _run(["sudo", "wg", "show", iface, "dump"])
    if not ok or not out:
        return None
    lines = out.splitlines()
    if not lines:
        return None
    cols = lines[0].split("\t")
    # Format interface line:
    # privateKey  publicKey  listenPort  fwmark
    if len(cols) < 3:
        return None
    return {
        "public_key": cols[1],
        "listen_port": cols[2],
    }

# ---------- Peers ----------
def list_peers(iface: str = WG_IFACE) -> List[Dict[str, str]]:
    """Parse 'wg show wg0 dump' pour extraire les peers et stats."""
    ok, out = _run(["sudo", "wg", "show", iface, "dump"])
    if not ok or not out:
        return []
    peers = []
    lines = out.splitlines()[1:]  # skip interface line
    for line in lines:
        cols = line.split("\t")
        # Format peer line:
        # publicKey  presharedKey  endpoint  allowedIPs
        # latestHandshake  transferRx  transferTx  persistentKeepalive
        if len(cols) < 8:
            continue
        pub, psk, endpoint, allowed, hs, rx, tx, keep = cols[:8]
        # Normalisation des valeurs
        endpoint = endpoint if endpoint != "(none)" else ""
        keep     = keep if keep != "off" else ""
        # Conversion des octets bruts en libellé humain pour l’UI
        def _fmt_bytes(n: str) -> str:
            try:
                v = int(n)
            except:
                return "0 B"
            for unit, div in (("B",1),("KiB",1024),("MiB",1024**2),("GiB",1024**3),("TiB",1024**4)):
                if v < div*1024 or unit == "TiB":
                    return f"{v/div:.2f} {unit}" if div>1 else f"{v} {unit}"
            return f"{v} B"
        peer = {
            "public_key": pub,
            "endpoint": endpoint,
            "allowed_ips": allowed,
            "latest_handshake": hs if hs != "0" else "Never",
            "transfer_rx": _fmt_bytes(rx),
            "transfer_tx": _fmt_bytes(tx),
            "keepalive": keep,
        }
        peers.append(peer)
    return peers

def add_peer_live(pubkey: str, allowed_ips: str, endpoint: Optional[str]=None, keepalive: Optional[str]=None) -> Tuple[bool, str]:
    """Applique le peer en live via 'wg set'."""
    cmd = ["sudo", "wg", "set", WG_IFACE, "peer", pubkey, "allowed-ips", allowed_ips]
    if endpoint:
        cmd += ["endpoint", endpoint]
    if keepalive:
        cmd += ["persistent-keepalive", str(keepalive)]
    return _run(cmd)

def append_peer_to_conf(pubkey: str, allowed_ips: str, endpoint: Optional[str]=None, keepalive: Optional[str]=None) -> Tuple[bool, str]:
    """Ajoute un bloc [Peer] dans /etc/wireguard/wg0.conf (persistance)."""
    try:
        block = ["\n[Peer]", f"PublicKey = {pubkey}", f"AllowedIPs = {allowed_ips}"]
        if endpoint:
            block.append(f"Endpoint = {endpoint}")
        if keepalive:
            block.append(f"PersistentKeepalive = {keepalive}")
        block.append("")  # newline
        text = "\n".join(block)
        # backup rapide
        _run(["sudo", "cp", WG_CONF, f"{WG_CONF}.bak"])
        # append
        p = subprocess.run(["sudo", "tee", "-a", WG_CONF], input=text, text=True, capture_output=True)
        if p.returncode != 0:
            return (False, p.stderr.strip())
        # recharger la conf (wg-quick gère routes/addresses si besoin)
        _run(["sudo", "wg-quick", "save", WG_IFACE])  # sauvegarde l’état dans conf
        return (True, "Peer ajouté au fichier de conf")
    except Exception as e:
        return (False, str(e))

def remove_peer_live(pubkey: str) -> Tuple[bool, str]:
    return _run(["sudo", "wg", "set", WG_IFACE, "peer", pubkey, "remove"])

def remove_peer_from_conf(pubkey: str) -> Tuple[bool, str]:
    """Supprime le bloc [Peer] correspondant à PublicKey=pubkey dans wg0.conf."""
    ok, out = _run(["sudo", "cat", WG_CONF])
    if not ok:
        return (False, out)
    content = out
    # Regex qui capture un bloc [Peer] contenant PublicKey = <pubkey>
    pattern = re.compile(r"\n\[Peer\][^\[]*?PublicKey\s*=\s*"+re.escape(pubkey)+r"[^\[]*", re.MULTILINE|re.DOTALL)
    new_content = re.sub(pattern, "\n", content)
    if new_content == content:
        return (False, "Bloc peer non trouvé dans wg0.conf")
    # backup
    _run(["sudo", "cp", WG_CONF, f"{WG_CONF}.bak"])
    # écrire
    p = subprocess.run(["sudo", "tee", WG_CONF], input=new_content, text=True, capture_output=True)
    if p.returncode != 0:
        return (False, p.stderr.strip())
    _run(["sudo", "wg-quick", "save", WG_IFACE])
    return (True, "Bloc peer supprimé du fichier de conf")

# ---------- Clés ----------
def gen_keys() -> Optional[Dict[str,str]]:
    """Génère (private, public) via 'wg genkey'."""
    ok, priv = _run(["wg", "genkey"])
    if not ok:
        # Essaye via sudo si wg nécessite privilèges
        ok, priv = _run(["sudo", "wg", "genkey"])
        if not ok:
            return None
    priv = priv.strip()
    # pubkey = echo <priv> | wg pubkey
    p = subprocess.Popen(["wg", "pubkey"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(priv+"\n")
    if p.returncode != 0 or not out.strip():
        # retry avec sudo
        p = subprocess.Popen(["sudo", "wg", "pubkey"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(priv+"\n")
        if p.returncode != 0:
            return None
    pub = out.strip()
    return {"private": priv, "public": pub}

# ---------- Service ----------
def start_wg(iface: str = WG_IFACE) -> Tuple[bool, str]:
    return _run(["sudo", "systemctl", "start", f"wg-quick@{iface}"])

def stop_wg(iface: str = WG_IFACE) -> Tuple[bool, str]:
    return _run(["sudo", "systemctl", "stop", f"wg-quick@{iface}"])

def restart_wg(iface: str = WG_IFACE) -> Tuple[bool, str]:
    return _run(["sudo", "systemctl", "restart", f"wg-quick@{iface}"])


import ipaddress

def validate_allowed_ip(cidr: str) -> bool:
    """Vérifie que l’entrée est du type 10.200.0.X/32 (ou /128 en IPv6)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # on accepte /32 IPv4 ou /128 IPv6 pour une adresse client unique
        return (net.version == 4 and net.prefixlen == 32) or (net.version == 6 and net.prefixlen == 128)
    except Exception:
        return False

def gen_client_config(server_public: str, server_endpoint: str, client_private: str,
                      client_address_cidr: str, keepalive: int = 25, dns: str = "1.1.1.1") -> str:
    """Construit le fichier .conf du client."""
    return f"""[Interface]
Address = {client_address_cidr}
PrivateKey = {client_private}
DNS = {dns}

[Peer]
PublicKey = {server_public}
AllowedIPs = 0.0.0.0/0
Endpoint = {server_endpoint}
PersistentKeepalive = {keepalive}
"""

def update_peer_allowed_ips(pubkey: str, new_allowed: str) -> tuple[bool, str]:
    """Change en live les AllowedIPs d’un peer existant."""
    return _run(["sudo", "wg", "set", WG_IFACE, "peer", pubkey, "allowed-ips", new_allowed])

def reload_wg(iface: str = WG_IFACE) -> tuple[bool, str]:
    """Recharge la conf (utile après modifications fichier)."""
    return _run(["sudo", "systemctl", "restart", f"wg-quick@{iface}"])
