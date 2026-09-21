#!/usr/bin/env python3
"""sbx — консольный VPN-клиент поверх sing-box: подписки, выбор сервера, автозапуск.

Движок — системный sing-box (пакет extra/sing-box), sbx только собирает для него
конфиг и управляет systemd-юнитом. Из подписки берутся лишь сами серверы
(outbound'ы): панели часто отдают конфиг в устаревшем формате полей, который
свежий sing-box уже не принимает, поэтому DNS, TUN и маршрутизация свои.

Форматы подписок (определяются сами):
  * sing-box JSON (полный конфиг или список outbound'ов);
  * Clash / mihomo YAML (секция proxies);
  * base64 или просто список URI: vless, vmess, trojan, ss, hysteria2/hy2, tuic, socks.

Режимы: TUN (весь трафик системы) + mixed SOCKS5/HTTP на 127.0.0.1:2080,
либо только прокси. LAN, WireGuard (10.8.0.0/24), docker и прочие частные сети
в туннель не идут, ответы WireGuard-сервера (:51820) и Caddy (:443) тоже —
иначе удалённый доступ отвалится.

Примеры:
  sbx sub add myvpn 'https://sub.example/xyz'    # добавить подписку и скачать
  sbx update                                     # обновить все подписки
  sbx ls                                         # серверы, ● — текущий
  sbx test                                       # задержка до всех серверов
  sbx use 5 | sbx use германия | sbx use auto    # выбрать сервер
  sbx up | down | restart | status | log -f
  sbx enable | disable                           # автозапуск при загрузке
  sbx mode tun|proxy    sbx route ru|global
  sbx add 'vless://…'                            # одиночный сервер без подписки
  sbx probe [-a]                                 # проверка рядом с другим VPN, без перехвата
"""
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HOME = Path.home()
CONF_DIR = HOME / ".config/sbx"
STATE_FILE = CONF_DIR / "state.json"
SUBS_DIR = CONF_DIR / "subs"
RULESET_DIR = CONF_DIR / "rulesets"
CONFIG_FILE = CONF_DIR / "config.json"
WORK_DIR = HOME / ".local/state/sbx"
SING_BOX = shutil.which("sing-box") or "/usr/bin/sing-box"
UNIT = "sbx.service"
UNIT_DIR = Path("/etc/systemd/system")
PROBE_IF = "sbx-probe"
# gvisor, а не system/mixed: system-стек принимает TCP через input ядра с TUN-интерфейса,
# а nftables (policy drop, разрешены lo/wg0/LAN) такие пакеты режет — TCP не работает.
STACK = "gvisor"
PROBE_UNIT = "sbx-probe.service"

PROXY_TYPES = {"vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2",
               "tuic", "socks", "http", "ssh", "shadowtls", "anytls", "naive"}

RULESETS = {
    "geoip-ru": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
    "geosite-category-ru": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs",
}

DEFAULT_EXCLUDE = [
    "10.0.0.0/8",        # WireGuard 10.8.0.0/24, docker wg-net 10.8.1.0/24
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",     # docker
    "192.168.0.0/16",    # LAN
    "224.0.0.0/4",
    "255.255.255.255/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

DEFAULT_STATE = {
    "subs": [],             # [{name, url, ua, hwid: bool}]
    "manual": [],           # outbound'ы, добавленные через `sbx add`
    "selected": "auto",
    "settings": {
        "mode": "tun",              # tun | proxy
        "route": "ru",              # ru — российское напрямую, global — всё через VPN
        "mixed_port": 2080,
        "api_port": 9097,
        "api_secret": "",
        "tun_name": "sbx0",
        "exclude": DEFAULT_EXCLUDE,
        "bypass_sports": ["udp:51820", "tcp:443"],   # ответы своих серверов — мимо TUN
        "dns_remote": "https://1.1.1.1/dns-query",
        "dns_direct": "77.88.8.8",
        "auto_exclude": "",         # regex: какие серверы не брать в auto
        "test_url": "https://www.gstatic.com/generate_204",
        "ua": "SFA/1.13 (sbx; sing-box)",   # ^SFA — Remnawave/Marzban отдают sing-box JSON
        "log_level": "info",
    },
    "latency": {},          # tag -> ms (-1 = недоступен)
}


# ─── утилиты ──────────────────────────────────────────────────────────────────

def die(msg, code=1):
    print(f"sbx: {msg}", file=sys.stderr)
    sys.exit(code)


def warn(msg):
    print(f"⚠ {msg}", file=sys.stderr)


def load_state():
    st = json.loads(json.dumps(DEFAULT_STATE))
    if STATE_FILE.exists():
        saved = json.loads(STATE_FILE.read_text())
        settings = {**st["settings"], **saved.get("settings", {})}
        st.update(saved)
        st["settings"] = settings
    if not st["settings"]["api_secret"]:
        st["settings"]["api_secret"] = secrets.token_hex(16)
    return st


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def save_state(st):
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONF_DIR, 0o700)
    write_private(STATE_FILE, json.dumps(st, ensure_ascii=False, indent=2))


def hwid():
    """Как у Koala Clash / Happ-подобных клиентов: sha256(machine-id)[:16] — то же устройство в панели."""
    mid = Path("/etc/machine-id").read_text().strip()
    return hashlib.sha256(mid.encode()).hexdigest()[:16]


def os_version():
    try:
        rel = Path("/etc/os-release").read_text()
        name = re.search(r'^NAME="?([^"\n]+)', rel, re.M)
        return name.group(1) if name else "Linux"
    except OSError:
        return "Linux"


def b64decode(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_")).decode()
    except Exception:
        return None


def run(cmd, check=True, **kw):
    return subprocess.run(cmd, check=check, text=True, **kw)


def systemctl(*args, sudo=False, check=True, capture=False):
    cmd = (["sudo"] if sudo and os.geteuid() != 0 else []) + ["systemctl", *args]
    return run(cmd, check=check, capture_output=capture)


def unit_prop(prop):
    r = systemctl("show", "-p", prop, "--value", UNIT, check=False, capture=True)
    return r.stdout.strip()


def is_active():
    return unit_prop("ActiveState") == "active"


def human_bytes(n):
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ПиБ"


# ─── разбор серверов ──────────────────────────────────────────────────────────

class Unsupported(Exception):
    pass


def tls_block(security, sni=None, fp=None, alpn=None, insecure=False, pbk=None, sid=None):
    if security in (None, "", "none"):
        return None
    tls = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if insecure:
        tls["insecure"] = True
    if alpn:
        tls["alpn"] = [a for a in (alpn if isinstance(alpn, list) else alpn.split(",")) if a]
    if security == "reality":
        if not pbk:
            raise Unsupported("reality без public key")
        tls["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid or ""}
        fp = fp or "chrome"
    if fp and fp not in ("none", ""):
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls


def transport_block(net, path=None, host=None, service_name=None, header_type=None):
    net = (net or "tcp").lower()
    if net in ("tcp", "raw", ""):
        if header_type == "http":
            t = {"type": "http", "method": "GET"}
            if host:
                t["host"] = host.split(",")
            if path:
                t["path"] = path
            return t
        return None
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        m = re.search(r"[?&]ed=(\d+)", t["path"])
        if m:
            t["path"] = re.sub(r"[?&]ed=\d+", "", t["path"]) or "/"
            t["max_early_data"] = int(m.group(1))
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if host:
            t["headers"] = {"Host": host}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": service_name or path or ""}
    if net in ("http", "h2"):
        t = {"type": "http"}
        if host:
            t["host"] = host.split(",")
        if path:
            t["path"] = path
        return t
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path or "/"}
        if host:
            t["host"] = host
        return t
    raise Unsupported(f"транспорт {net} в sing-box не поддерживается")


def finish(out, tls=None, transport=None):
    if tls:
        out["tls"] = tls
    if transport:
        out["transport"] = transport
    return out


def split_hostport(netloc):
    """host:port с учётом [ipv6] и userinfo@."""
    hp = netloc.rsplit("@", 1)[-1]
    m = re.match(r"^\[([^\]]+)\]:(\d+)$", hp) or re.match(r"^([^:]+):(\d+)$", hp)
    if not m:
        raise Unsupported(f"не разобрать адрес {hp!r}")
    return m.group(1), int(m.group(2))


def parse_uri(uri):
    uri = uri.strip()
    scheme = uri.split("://", 1)[0].lower()
    if scheme == "vmess":
        return parse_vmess(uri)
    if scheme == "ss":
        return parse_ss(uri)
    u = urllib.parse.urlsplit(uri)
    q = {k: v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}
    name = urllib.parse.unquote(u.fragment) or None
    server, port = split_hostport(u.netloc)
    user = urllib.parse.unquote(u.netloc.rsplit("@", 1)[0]) if "@" in u.netloc else ""
    insecure = q.get("allowInsecure", q.get("insecure", "0")) in ("1", "true")

    if scheme in ("vless", "trojan"):
        out = {"type": scheme, "server": server, "server_port": port}
        if scheme == "vless":
            out["uuid"] = user
            if q.get("flow"):
                out["flow"] = q["flow"]
            out["packet_encoding"] = "xudp"
            default_sec = "none"
        else:
            out["password"] = user
            default_sec = "tls"
        sec = q.get("security", default_sec)
        tls = tls_block(sec, q.get("sni") or q.get("peer") or (server if sec == "tls" else None),
                        q.get("fp"), q.get("alpn"), insecure, q.get("pbk"), q.get("sid"))
        tr = transport_block(q.get("type"), q.get("path"), q.get("host"),
                             q.get("serviceName"), q.get("headerType"))
        return name, finish(out, tls, tr)

    if scheme in ("hysteria2", "hy2"):
        out = {"type": "hysteria2", "server": server, "server_port": port, "password": user}
        ports = q.get("mport") or q.get("ports")
        if ports:
            out["server_ports"] = [p.replace("-", ":") for p in ports.split(",")]
        if q.get("obfs") and q["obfs"] != "none":
            out["obfs"] = {"type": q["obfs"], "password": q.get("obfs-password", "")}
        out["tls"] = tls_block("tls", q.get("sni") or server, None, q.get("alpn") or "h3", insecure)
        return name, out

    if scheme == "tuic":
        uuid, _, password = user.partition(":")
        out = {"type": "tuic", "server": server, "server_port": port, "uuid": uuid,
               "password": password,
               "congestion_control": q.get("congestion_control", "bbr"),
               "udp_relay_mode": q.get("udp_relay_mode", "native")}
        out["tls"] = tls_block("tls", q.get("sni") or server, None, q.get("alpn") or "h3",
                               insecure or q.get("allow_insecure") == "1")
        return name, out

    if scheme in ("socks", "socks5"):
        out = {"type": "socks", "server": server, "server_port": port, "version": "5"}
        if user:
            decoded = user if ":" in user else (b64decode(user) or user)
            out["username"], _, out["password"] = decoded.partition(":")
        return name, out

    raise Unsupported(f"схема {scheme}:// не поддерживается")


def parse_vmess(uri):
    raw = b64decode(uri[len("vmess://"):])
    if not raw:
        raise Unsupported("vmess: не base64")
    j = json.loads(raw)
    out = {"type": "vmess", "server": j["add"], "server_port": int(j["port"]),
           "uuid": j["id"], "alter_id": int(j.get("aid") or 0),
           "security": j.get("scy") or "auto", "packet_encoding": "xudp"}
    tls = tls_block("tls" if j.get("tls") in ("tls", True) else None,
                    j.get("sni") or j.get("host") or None, j.get("fp"), j.get("alpn"),
                    str(j.get("allowInsecure", "")) in ("1", "true"))
    tr = transport_block(j.get("net"), j.get("path"), j.get("host"), j.get("path"), j.get("type"))
    return j.get("ps"), finish(out, tls, tr)


def parse_ss(uri):
    body = uri[len("ss://"):]
    body, _, frag = body.partition("#")
    name = urllib.parse.unquote(frag) or None
    body, _, query = body.partition("?")
    q = dict(urllib.parse.parse_qsl(query))
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo)
        dec = b64decode(userinfo) if ":" not in userinfo else None
        method, _, password = (dec or userinfo).partition(":")
    else:  # legacy: base64(method:pass@host:port)
        dec = b64decode(body) or ""
        cred, _, hostport = dec.rpartition("@")
        method, _, password = cred.partition(":")
    server, port = split_hostport(hostport.rstrip("/"))
    out = {"type": "shadowsocks", "server": server, "server_port": port,
           "method": method, "password": password}
    if q.get("plugin"):
        plugin, _, opts = urllib.parse.unquote(q["plugin"]).partition(";")
        out["plugin"] = "obfs-local" if plugin in ("obfs-local", "simple-obfs") else plugin
        out["plugin_opts"] = opts
    return name, out


def from_clash(p):
    t = p.get("type")
    server, port = p.get("server"), int(p.get("port", 0))
    insecure = bool(p.get("skip-cert-verify"))
    name = p.get("name")
    ws, grpc, h2 = p.get("ws-opts") or {}, p.get("grpc-opts") or {}, p.get("h2-opts") or {}
    net = p.get("network")

    def tr():
        if net == "ws":
            return transport_block("ws", ws.get("path"), (ws.get("headers") or {}).get("Host"))
        if net == "grpc":
            return transport_block("grpc", service_name=grpc.get("grpc-service-name"))
        if net in ("h2", "http"):
            hosts = h2.get("host") or []
            return transport_block("http", h2.get("path"), ",".join(hosts) if hosts else None)
        if net == "httpupgrade":
            hu = p.get("http-upgrade-opts") or ws
            return transport_block("httpupgrade", hu.get("path"), (hu.get("headers") or {}).get("Host"))
        return transport_block(net)

    def tls(default_on):
        ro = p.get("reality-opts")
        sec = "reality" if ro else ("tls" if p.get("tls", default_on) else None)
        return tls_block(sec, p.get("servername") or p.get("sni") or (server if sec == "tls" else None),
                         p.get("client-fingerprint"), p.get("alpn"), insecure,
                         (ro or {}).get("public-key"), (ro or {}).get("short-id"))

    if t == "vless":
        out = {"type": "vless", "server": server, "server_port": port, "uuid": p["uuid"],
               "packet_encoding": "xudp"}
        if p.get("flow"):
            out["flow"] = p["flow"]
        return name, finish(out, tls(False), tr())
    if t == "vmess":
        out = {"type": "vmess", "server": server, "server_port": port, "uuid": p["uuid"],
               "alter_id": int(p.get("alterId", 0)), "security": p.get("cipher", "auto"),
               "packet_encoding": "xudp"}
        return name, finish(out, tls(False), tr())
    if t == "trojan":
        out = {"type": "trojan", "server": server, "server_port": port, "password": p["password"]}
        return name, finish(out, tls(True), tr())
    if t == "ss":
        out = {"type": "shadowsocks", "server": server, "server_port": port,
               "method": p["cipher"], "password": p["password"]}
        if p.get("plugin") == "obfs":
            po = p.get("plugin-opts") or {}
            out["plugin"] = "obfs-local"
            out["plugin_opts"] = f"obfs={po.get('mode', 'http')};obfs-host={po.get('host', '')}"
        elif p.get("plugin"):
            raise Unsupported(f"ss-плагин {p['plugin']}")
        return name, out
    if t == "hysteria2":
        out = {"type": "hysteria2", "server": server, "server_port": port,
               "password": p.get("password", "")}
        if p.get("ports"):
            out["server_ports"] = [x.replace("-", ":") for x in str(p["ports"]).split(",")]
        if p.get("obfs"):
            out["obfs"] = {"type": p["obfs"], "password": p.get("obfs-password", "")}
        out["tls"] = tls_block("tls", p.get("sni") or server, None, p.get("alpn") or ["h3"], insecure)
        return name, out
    if t == "tuic":
        out = {"type": "tuic", "server": server, "server_port": port, "uuid": p["uuid"],
               "password": p.get("password", ""),
               "congestion_control": p.get("congestion-controller", "bbr"),
               "udp_relay_mode": p.get("udp-relay-mode", "native")}
        out["tls"] = tls_block("tls", p.get("sni") or server, None, p.get("alpn") or ["h3"], insecure)
        return name, out
    if t == "socks5":
        out = {"type": "socks", "server": server, "server_port": port, "version": "5"}
        if p.get("username"):
            out["username"], out["password"] = p["username"], p.get("password", "")
        return name, finish(out, tls(False) if p.get("tls") else None)
    raise Unsupported(f"clash-тип {t}")


def clean_outbound(o):
    o = {k: v for k, v in o.items() if k not in ("domain_strategy", "detour", "tag")}
    return o


def parse_subscription(text):
    """-> (список (имя, outbound), список ошибок, формат)"""
    items, errors = [], []
    s = text.strip()
    if s.startswith(("{", "[")):
        try:
            j = json.loads(s)
            obs = j.get("outbounds", []) if isinstance(j, dict) else j
            for o in obs:
                if o.get("type") in PROXY_TYPES:
                    items.append((o.get("tag"), clean_outbound(o)))
            return items, errors, "sing-box json"
        except json.JSONDecodeError:
            pass
    if re.search(r"^proxies\s*:", s, re.M):
        import yaml
        y = yaml.safe_load(s) or {}
        for p in y.get("proxies") or []:
            try:
                items.append(from_clash(p))
            except (Unsupported, KeyError, ValueError) as e:
                errors.append(f"{p.get('name')}: {e}")
        return items, errors, "clash yaml"
    fmt = "uri list"
    if "://" not in s:
        dec = b64decode(s)
        if dec and "://" in dec:
            s, fmt = dec, "base64"
    for line in s.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        try:
            items.append(parse_uri(line))
        except (Unsupported, KeyError, ValueError, json.JSONDecodeError) as e:
            label = urllib.parse.unquote(line.partition("#")[2]) or line.split("://")[0]
            errors.append(f"{label}: {e}")
    return items, errors, fmt


def is_stub(o):
    """Заглушки панелей (Remnawave без HWID и т.п.): 0.0.0.0:1."""
    return o.get("server") in ("0.0.0.0", "127.0.0.1", "") or o.get("server_port", 443) in (0, 1)


# ─── подписки ─────────────────────────────────────────────────────────────────

def sub_file(name):
    return SUBS_DIR / f"{name}.json"


def load_sub_cache(name):
    f = sub_file(name)
    return json.loads(f.read_text()) if f.exists() else {"servers": [], "meta": {}}


def fetch_sub(st, sub):
    headers = {"User-Agent": sub.get("ua") or st["settings"]["ua"], "Accept": "*/*"}
    if sub.get("hwid", True):
        headers.update({"x-hwid": hwid(), "x-device-os": "Linux",
                        "x-ver-os": os_version(), "x-device-model": socket.gethostname()})
    req = urllib.request.Request(sub["url"], headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode("utf-8", "replace")
        info = r.headers.get("subscription-userinfo", "")
        title = r.headers.get("profile-title", "")
    if title.startswith("base64:"):
        title = b64decode(title[7:]) or title
    meta = {"updated": int(time.time()), "title": title}
    for part in info.split(";"):
        k, _, v = part.strip().partition("=")
        if k and v.strip().isdigit():
            meta[k] = int(v)
    items, errors, fmt = parse_subscription(body)
    servers, stubs = [], 0
    for name, o in items:
        if is_stub(o):
            stubs += 1
            continue
        servers.append({"name": name or f"{o['type']} {o.get('server')}", "outbound": o})
    meta["format"] = fmt
    return servers, errors, stubs, meta


def update_subs(st, names=None, quiet=False):
    subs = [s for s in st["subs"] if not names or s["name"] in names]
    if names and not subs:
        die(f"нет подписки {', '.join(names)}")
    ok = True
    for sub in subs:
        try:
            servers, errors, stubs, meta = fetch_sub(st, sub)
        except (urllib.error.URLError, OSError, ValueError) as e:
            warn(f"{sub['name']}: не скачалась ({e}), остаётся прошлый список")
            ok = False
            continue
        if not servers:
            hint = " — похоже на заглушки: панель требует HWID?" if stubs else ""
            warn(f"{sub['name']}: серверов нет ({meta['format']}){hint}, остаётся прошлый список")
            ok = False
            continue
        SUBS_DIR.mkdir(parents=True, exist_ok=True)
        write_private(sub_file(sub["name"]), json.dumps({"servers": servers, "meta": meta},
                                                        ensure_ascii=False, indent=1))
        if not quiet:
            extra = f", пропущено {len(errors)}" if errors else ""
            print(f"✓ {sub['name']}: {len(servers)} серверов ({meta['format']}{extra})")
            for e in errors:
                print(f"    пропущен {e}")
    update_rulesets(quiet)
    return ok


def update_rulesets(quiet=False, force=False):
    RULESET_DIR.mkdir(parents=True, exist_ok=True)
    for tag, url in RULESETS.items():
        path = RULESET_DIR / f"{tag}.srs"
        if path.exists() and not force and time.time() - path.stat().st_mtime < 7 * 86400:
            continue
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
            path.write_bytes(data)
            if not quiet:
                print(f"✓ rule-set {tag} ({human_bytes(len(data))})")
        except (urllib.error.URLError, OSError) as e:
            warn(f"rule-set {tag} не скачался: {e}")


# ─── серверы и конфиг ─────────────────────────────────────────────────────────

def all_servers(st):
    """-> [{tag, outbound, source}] в стабильном порядке, теги уникальны."""
    out, seen = [], set()

    def add(name, o, source):
        tag = name.strip() or "server"
        if tag in seen or tag in ("proxy", "auto", "direct"):
            base, n = f"{tag} [{source}]", 2
            tag = base
            while tag in seen:
                tag, n = f"{base} #{n}", n + 1
        seen.add(tag)
        out.append({"tag": tag, "outbound": o, "source": source})

    for sub in st["subs"]:
        for s in load_sub_cache(sub["name"])["servers"]:
            add(s["name"], s["outbound"], sub["name"])
    for s in st["manual"]:
        add(s["name"], s["outbound"], "manual")
    return out


def build_config(st, servers, *, tun=None, api_port=None, mixed_port=None, probe=False):
    cfg_s = st["settings"]
    tun = cfg_s["mode"] == "tun" if tun is None else tun
    tags = [s["tag"] for s in servers]
    rx = cfg_s.get("auto_exclude")
    auto = [t for t in tags if not (rx and re.search(rx, t, re.I))] or tags
    selected = st["selected"] if st["selected"] in tags else "auto"

    have = {t: (RULESET_DIR / f"{t}.srs") for t in RULESETS}
    have = {t: p for t, p in have.items() if p.exists()}
    ru = cfg_s["route"] == "ru" and have

    dns_remote = urllib.parse.urlsplit(cfg_s["dns_remote"])
    dns = {
        "servers": [
            {"type": dns_remote.scheme or "udp", "tag": "dns-remote",
             "server": dns_remote.hostname or cfg_s["dns_remote"],
             **({"path": dns_remote.path} if dns_remote.path else {})},
            {"type": "udp", "tag": "dns-direct", "server": cfg_s["dns_direct"]},
        ],
        "rules": [],
        "final": "dns-remote",
        "strategy": "ipv4_only",
    }
    rules = [
        {"action": "sniff"},
        {"type": "logical", "mode": "or", "rules": [{"protocol": "dns"}, {"port": 53}],
         "action": "hijack-dns"},
        {"ip_cidr": [cfg_s["dns_direct"] + "/32"], "outbound": "direct"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    rule_sets = []
    if ru:
        rule_sets = [{"type": "local", "tag": t, "format": "binary", "path": str(p)}
                     for t, p in have.items()]
        if "geosite-category-ru" in have:
            dns["rules"].append({"rule_set": ["geosite-category-ru"], "server": "dns-direct"})
        rules.append({"domain_suffix": [".ru", ".su", ".xn--p1ai", ".рф"], "outbound": "direct"})
        rules.append({"rule_set": list(have), "outbound": "direct"})

    inbounds = []
    if probe:
        # TUN без auto_route: интерфейс есть, но ни маршрутов, ни ip rule — перехватывать нечего
        inbounds.append({"type": "tun", "tag": "tun-in", "interface_name": PROBE_IF,
                         "address": ["198.19.255.1/30"], "mtu": 9000,
                         "auto_route": False, "stack": STACK})
    elif tun:
        inbounds.append({
            "type": "tun", "tag": "tun-in", "interface_name": cfg_s["tun_name"],
            "address": ["198.18.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 9000,
            "auto_route": True, "strict_route": True, "stack": STACK,
            "route_exclude_address": cfg_s["exclude"],
        })
    inbounds.append({"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                     "listen_port": mixed_port or cfg_s["mixed_port"]})

    outbounds = [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto", *tags], "default": selected,
         "interrupt_exist_connections": True},
        {"type": "urltest", "tag": "auto", "outbounds": auto, "url": cfg_s["test_url"],
         "interval": "5m", "tolerance": 50},
        *({**s["outbound"], "tag": s["tag"]} for s in servers),
        {"type": "direct", "tag": "direct"},
    ]
    return {
        "log": {"level": cfg_s["log_level"], "timestamp": True},
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules, "rule_set": rule_sets, "final": "proxy",
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-direct"},
        },
        "experimental": {"clash_api": {
            "external_controller": f"127.0.0.1:{api_port or cfg_s['api_port']}",
            "secret": cfg_s["api_secret"], "default_mode": "rule"}},
    }


def check_config(path):
    r = run([SING_BOX, "check", "-c", str(path)], check=False, capture_output=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def apply(st, reload=True, quiet=False):
    """Собрать конфиг, проверить, записать; если движок работает — перечитать (SIGHUP)."""
    servers = all_servers(st)
    if not servers:
        die("серверов нет: добавьте подписку (sbx sub add) или сервер (sbx add)")
    text = json.dumps(build_config(st, servers), ensure_ascii=False, indent=2)
    old = CONFIG_FILE.read_text() if CONFIG_FILE.exists() else None
    if text == old:
        return False
    tmp = CONF_DIR / ".config.check.json"
    write_private(tmp, text)
    ok, err = check_config(tmp)
    if not ok:
        tmp.unlink()
        die(f"sing-box отверг конфиг:\n{err}")
    os.replace(tmp, CONFIG_FILE)
    if reload and is_active():
        pid = int(unit_prop("MainPID") or 0)
        if pid:
            os.kill(pid, signal.SIGHUP)
            if not quiet:
                print("↻ конфиг перечитан")
    return True


# ─── clash API ────────────────────────────────────────────────────────────────

def api(st, method, path, body=None, port=None, timeout=10):
    port = port or st["settings"]["api_port"]
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {st['settings']['api_secret']}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return json.loads(data) if data else None


def api_up(st, port=None):
    try:
        api(st, "GET", "/version", port=port, timeout=2)
        return True
    except (urllib.error.URLError, OSError):
        return False


def current_node(st):
    try:
        proxy = api(st, "GET", "/proxies/proxy")
        now = proxy.get("now")
        if now == "auto":
            return "auto → " + (api(st, "GET", "/proxies/auto").get("now") or "?")
        return now
    except (urllib.error.URLError, OSError, ValueError):
        return None


# ─── systemd ──────────────────────────────────────────────────────────────────

def unit_text(st):
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or HOME.name
    rules = []
    for spec in st["settings"]["bypass_sports"]:
        proto, _, port = spec.partition(":")
        for fam in ("-4", "-6"):
            rules.append(f"{fam} rule %s priority 8990 ipproto {proto} sport {port} lookup main")
    add = "\n".join(f"ExecStartPre=-+/usr/bin/ip {r % 'add'}" for r in rules)
    delete = "\n".join(f"ExecStopPost=-+/usr/bin/ip {r % 'del'}" for r in rules)
    return f"""# Сгенерировано sbx (~/scripts/sbx.py install). Правки затрёт следующий install.
[Unit]
Description=sbx — sing-box VPN client
Documentation=file://{Path(__file__).resolve()}
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User={user}
Group={user}
# TUN и маршруты без root: только нужные capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
# Ответы своих серверов (WireGuard, Caddy) уходят по main, мимо правил TUN (приоритет 9000+)
{add}
ExecStartPre={SING_BOX} check -c {CONFIG_FILE}
ExecStart={SING_BOX} run -c {CONFIG_FILE} -D {WORK_DIR}
ExecReload=/bin/kill -HUP $MAINPID
{delete}
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"""


def timer_units():
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or HOME.name
    exe = Path(__file__).resolve()
    svc = f"""[Unit]
Description=sbx — обновление подписок
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User={user}
ExecStart=/usr/bin/python3 {exe} update --quiet
"""
    tmr = """[Unit]
Description=sbx — обновление подписок по расписанию

[Timer]
OnBootSec=3min
OnUnitActiveSec=6h
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
"""
    return svc, tmr


def sudo_write(path, text):
    run(["sudo", "tee", str(path)], input=text, stdout=subprocess.DEVNULL)


def install_units(st, quiet=False):
    svc, tmr = timer_units()
    files = {UNIT_DIR / UNIT: unit_text(st), UNIT_DIR / "sbx-update.service": svc,
             UNIT_DIR / "sbx-update.timer": tmr}
    changed = False
    for path, text in files.items():
        if not path.exists() or path.read_text() != text:
            sudo_write(path, text)
            changed = True
    if changed:
        systemctl("daemon-reload", sudo=True)
        if not quiet:
            print("✓ юниты установлены: sbx.service, sbx-update.timer")
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    return changed


def foreign_tun():
    """Другой VPN с TUN (Koala Clash / mihomo и т.п.) — маршруты подерутся."""
    r = run(["pgrep", "-a", "-f", "mihomo|clash-meta|xray|hiddify|nekobox|throne"],
            check=False, capture_output=True)
    return [l for l in r.stdout.splitlines() if "sbx" not in l and "pgrep" not in l]


# ─── команды ──────────────────────────────────────────────────────────────────

def cmd_sub(st, a):
    if a.action == "add":
        if any(s["name"] == a.name for s in st["subs"]):
            die(f"подписка {a.name} уже есть (sbx sub rm {a.name})")
        sub = {"name": a.name, "url": a.url, "hwid": not a.no_hwid}
        if a.ua:
            sub["ua"] = a.ua
        st["subs"].append(sub)
        save_state(st)
        if not update_subs(st, [a.name]):
            warn("подписка сохранена, но пока пустая — повторите `sbx update`")
            return
        apply(st)
    elif a.action == "rm":
        before = len(st["subs"])
        st["subs"] = [s for s in st["subs"] if s["name"] != a.name]
        if len(st["subs"]) == before:
            die(f"нет подписки {a.name}")
        sub_file(a.name).unlink(missing_ok=True)
        save_state(st)
        if all_servers(st):
            apply(st)
        print(f"✓ подписка {a.name} удалена")
    else:
        if not st["subs"]:
            print("подписок нет: sbx sub add ИМЯ URL")
        for s in st["subs"]:
            c = load_sub_cache(s["name"])
            m = c["meta"]
            line = f"{s['name']}: {len(c['servers'])} серверов"
            if m.get("title"):
                line += f" · {m['title']}"
            if m.get("updated"):
                line += f" · обновлена {time.strftime('%d.%m %H:%M', time.localtime(m['updated']))}"
            print(line)
            used = m.get("upload", 0) + m.get("download", 0)
            if m.get("total"):
                print(f"    трафик {human_bytes(used)} из {human_bytes(m['total'])}")
            elif used:
                print(f"    трафик {human_bytes(used)}")
            if m.get("expire"):
                days = (m["expire"] - time.time()) / 86400
                print(f"    до {time.strftime('%d.%m.%Y', time.localtime(m['expire']))} "
                      f"(осталось {days:.0f} дн.)")
            if a.verbose:
                print(f"    {s['url']}")


def cmd_update(st, a):
    ok = update_subs(st, a.names or None, quiet=a.quiet)
    save_state(st)
    if all_servers(st):
        apply(st, quiet=a.quiet)
    if not ok:
        sys.exit(1)


def cmd_add(st, a):
    added = 0
    for uri in a.uris:
        try:
            name, o = parse_uri(uri)
        except (Unsupported, KeyError, ValueError, json.JSONDecodeError) as e:
            warn(f"не добавлен: {e}")
            continue
        name = a.name if a.name and len(a.uris) == 1 else (name or f"{o['type']} {o['server']}")
        st["manual"].append({"name": name, "outbound": o})
        print(f"✓ {name} ({o['type']} {o['server']}:{o['server_port']})")
        added += 1
    if added:
        save_state(st)
        apply(st)


def cmd_rm(st, a):
    tag = resolve(st, a.server, allow_auto=False)
    before = len(st["manual"])
    st["manual"] = [s for s in st["manual"] if s["name"] != tag]
    if len(st["manual"]) == before:
        die(f"{tag} пришёл из подписки — удаляется только вместе с ней (или auto_exclude)")
    save_state(st)
    apply(st)
    print(f"✓ удалён {tag}")


def resolve(st, query, allow_auto=True):
    servers = all_servers(st)
    if allow_auto and query.lower() == "auto":
        return "auto"
    if query.isdigit():
        i = int(query)
        if 1 <= i <= len(servers):
            return servers[i - 1]["tag"]
        die(f"номера {i} нет, всего {len(servers)}")
    exact = [s["tag"] for s in servers if s["tag"] == query]
    if exact:
        return exact[0]
    found = [s["tag"] for s in servers if query.lower() in s["tag"].lower()]
    if len(found) == 1:
        return found[0]
    if not found:
        die(f"не найден сервер «{query}» (sbx ls)")
    die("под «%s» подходят несколько:\n  %s" % (query, "\n  ".join(found)))


def cmd_ls(st, a):
    servers = all_servers(st)
    if not servers:
        print("серверов нет: sbx sub add ИМЯ URL")
        return
    now = current_node(st) if is_active() else None
    live = now.split(" → ")[-1] if now else None
    sel = st["selected"]
    print(f"{'●' if sel == 'auto' else ' '}   0  auto" + (f"  → {live}" if sel == "auto" and live else ""))
    rx = st["settings"].get("auto_exclude")
    for i, s in enumerate(servers, 1):
        if a.filter and a.filter.lower() not in s["tag"].lower():
            continue
        mark = "●" if s["tag"] == sel else ("›" if sel == "auto" and s["tag"] == live else " ")
        ms = st["latency"].get(s["tag"])
        lat = "" if ms is None else ("  —" if ms < 0 else f"{ms:>5} мс")
        o = s["outbound"]
        kind = o["type"] + ("+reality" if (o.get("tls") or {}).get("reality") else "")
        noauto = "  (не в auto)" if rx and re.search(rx, s["tag"], re.I) else ""
        print(f"{mark} {i:>3}  {s['tag']:<34} {kind:<16}{lat:>9}  [{s['source']}]{noauto}")


def cmd_use(st, a):
    tag = resolve(st, a.server)
    st["selected"] = tag
    save_state(st)
    apply(st, reload=False)
    if is_active() and api_up(st):
        api(st, "PUT", "/proxies/proxy", {"name": tag})
    print(f"✓ выбран {tag}")


def cmd_test(st, a):
    servers = all_servers(st)
    if a.filter:
        servers = [s for s in servers if a.filter.lower() in s["tag"].lower()]
    if not servers:
        die("нечего проверять")
    port, proc, tmpdir = None, None, None
    if not (is_active() and api_up(st)):
        # временный sing-box без TUN: прав не нужно, мешать работающему нечему
        tmpdir = Path(tempfile.mkdtemp(prefix="sbx-test-"))
        port = free_port()
        cfg = build_config(st, all_servers(st), tun=False, api_port=port, mixed_port=free_port())
        (tmpdir / "c.json").write_text(json.dumps(cfg))
        proc = subprocess.Popen([SING_BOX, "run", "-c", str(tmpdir / "c.json"), "-D", str(tmpdir)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if api_up(st, port):
                break
            time.sleep(0.1)
        else:
            proc.kill()
            die("временный sing-box не поднялся")
    url = urllib.parse.quote(st["settings"]["test_url"], safe="")
    timeout = int(a.timeout * 1000)

    def probe(s):
        path = f"/proxies/{urllib.parse.quote(s['tag'], safe='')}/delay?url={url}&timeout={timeout}"
        try:
            return s["tag"], api(st, "GET", path, port=port, timeout=a.timeout + 3)["delay"]
        except (urllib.error.URLError, OSError, KeyError, ValueError):
            return s["tag"], -1

    try:
        with ThreadPoolExecutor(8) as ex:
            results = dict(ex.map(probe, servers))
            # первая волна на холодную (DNS, TLS) даёт ложные отказы — упавшим второй шанс
            retry = [s for s in servers if results[s["tag"]] < 0]
            results.update(ex.map(probe, retry))
        results = list(results.items())
    finally:
        if proc:
            proc.terminate()
            proc.wait(5)
            shutil.rmtree(tmpdir, ignore_errors=True)
    st["latency"].update(dict(results))
    save_state(st)
    idx = {s["tag"]: i for i, s in enumerate(all_servers(st), 1)}
    for tag, ms in sorted(results, key=lambda r: (r[1] < 0, r[1])):
        print(f"{idx[tag]:>4}  {tag:<34} {'недоступен' if ms < 0 else f'{ms} мс':>10}")


def ip_snapshot():
    """Правила и маршруты всех таблиц — чтобы доказать, что проба ничего не перехватила."""
    lines = []
    for cmd in (["ip", "rule"], ["ip", "-6", "rule"], ["ip", "route", "show", "table", "all"]):
        lines += run(cmd, check=False, capture_output=True).stdout.splitlines()
    return {l.strip() for l in lines if PROBE_IF not in l}


def cmd_probe(st, a):
    """Проверка ядра, TUN и подписки рядом с работающим VPN (Koala и т.п.), без перехвата."""
    if is_active():
        die("sbx уже работает — проба не нужна, см. sbx status")
    servers = all_servers(st)
    if not servers:
        die("серверов нет: sbx sub add ИМЯ URL")
    api_port, mixed = free_port(), free_port()
    cfg = build_config(st, servers, probe=True, api_port=api_port, mixed_port=mixed)
    probe_dir = WORK_DIR / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = probe_dir / "config.json"
    write_private(cfg_path, json.dumps(cfg, ensure_ascii=False))
    ok, err = check_config(cfg_path)
    if not ok:
        die(f"sing-box отверг конфиг:\n{err}")

    before = ip_snapshot()
    user = os.environ.get("USER") or HOME.name
    caps = "CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE"
    run(["sudo", "systemctl", "reset-failed", PROBE_UNIT], check=False, capture_output=True)
    run(["sudo", "systemd-run", f"--unit={PROBE_UNIT}", f"--uid={user}", f"--gid={user}",
         "-p", f"AmbientCapabilities={caps}", "-p", f"CapabilityBoundingSet={caps}",
         "--quiet", "--collect", SING_BOX, "run", "-c", str(cfg_path), "-D", str(probe_dir)])
    results = []

    def step(name, good, detail=""):
        results.append(good)
        print(f"{'✓' if good else '✗'} {name}" + (f": {detail}" if detail else ""))

    try:
        for _ in range(50):
            if api_up(st, api_port):
                break
            time.sleep(0.1)
        try:
            ver = api(st, "GET", "/version", port=api_port)["version"]
            step("ядро sing-box запущено", True, ver)
        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
            step("ядро sing-box запущено", False, str(e))
            run(["journalctl", "-u", PROBE_UNIT, "-n", "20", "--no-pager", "-o", "cat"], check=False)
            return

        link = run(["ip", "-br", "link", "show", PROBE_IF], check=False, capture_output=True).stdout
        step(f"TUN {PROBE_IF} создан", bool(link.strip()), " ".join(link.split()[1:2]))

        url = urllib.parse.quote(st["settings"]["test_url"], safe="")
        targets = servers if a.all else [s for s in servers if s["tag"] == st["selected"]] or \
            [{"tag": "auto"}]
        for s in targets:
            path = f"/proxies/{urllib.parse.quote(s['tag'], safe='')}/delay?url={url}&timeout=5000"
            try:
                ms = api(st, "GET", path, port=api_port, timeout=8)["delay"]
                step(f"сервер {s['tag']}", True, f"{ms} мс")
            except (urllib.error.URLError, OSError, KeyError, ValueError):
                step(f"сервер {s['tag']}", False, "не отвечает")
        if not a.all:
            now = api(st, "GET", "/proxies/auto", port=api_port).get("now")
            if now:
                print(f"  auto выбрал: {now}")

        def curl(extra):
            r = run(["curl", "-sS", "-m", "15", *extra, "https://ipinfo.io/json"],
                    check=False, capture_output=True)
            try:
                j = json.loads(r.stdout)
                return True, f"{j.get('ip')} {j.get('country', '')} {j.get('org', '')}"
            except ValueError:
                return False, (r.stderr or r.stdout).strip()[:200]

        step("трафик через mixed-прокси", *curl(["-x", f"socks5h://127.0.0.1:{mixed}"]))
        # сокет, привязанный к интерфейсу, уходит в TUN и без маршрутов — только этот curl
        step("трафик через TUN", *curl(["--interface", PROBE_IF]))

        after = ip_snapshot()
        diff = (after - before) | (before - after)
        step("маршруты и ip rule не тронуты", not diff, "; ".join(sorted(diff))[:300])
    finally:
        run(["sudo", "systemctl", "stop", PROBE_UNIT], check=False, capture_output=True)
        gone = not run(["ip", "link", "show", PROBE_IF], check=False, capture_output=True).stdout
        print(f"{'✓' if gone else '✗'} проба остановлена, {PROBE_IF} {'удалён' if gone else 'остался!'}")
    if not all(results):
        sys.exit(1)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cmd_up(st, a):
    others = foreign_tun()
    if others and not a.force:
        die("работает другой VPN-клиент, маршруты подерутся:\n  " + "\n  ".join(others) +
            "\nзакройте его или запустите с --force")
    apply(st, reload=False)
    install_units(st)
    systemctl("restart" if is_active() else "start", UNIT, sudo=True)
    time.sleep(1.5)
    if not is_active():
        run(["journalctl", "-u", UNIT, "-n", "30", "--no-pager"], check=False)
        die("sing-box не запустился")
    print("✓ VPN включён")
    show_status(st)


def cmd_down(st, a):
    systemctl("stop", UNIT, sudo=True)
    print("✓ VPN выключен")


def cmd_restart(st, a):
    apply(st, reload=False)
    install_units(st)
    systemctl("restart", UNIT, sudo=True)
    print("✓ перезапущен")


def show_status(st):
    active = is_active()
    enabled = unit_prop("UnitFileState")
    s = st["settings"]
    print(f"состояние:   {'работает' if active else 'выключен'}"
          f"  (автозапуск: {'да' if enabled == 'enabled' else 'нет'})")
    print(f"режим:       {'TUN + ' if s['mode'] == 'tun' else ''}прокси 127.0.0.1:{s['mixed_port']}"
          f" · маршрут {s['route']}")
    print(f"выбран:      {st['selected']}")
    if active:
        node = current_node(st)
        if node:
            print(f"сейчас:      {node}")
        try:
            conns = api(st, "GET", "/connections")
            print(f"трафик:      ↑ {human_bytes(conns.get('uploadTotal', 0))}"
                  f"  ↓ {human_bytes(conns.get('downloadTotal', 0))}"
                  f"  · соединений {len(conns.get('connections') or [])}")
        except (urllib.error.URLError, OSError, ValueError):
            pass
    t = unit_prop_of("sbx-update.timer", "UnitFileState")
    print(f"обновление:  {'по таймеру раз в 6 ч' if t == 'enabled' else 'вручную (sbx update)'}")


def unit_prop_of(unit, prop):
    r = systemctl("show", "-p", prop, "--value", unit, check=False, capture=True)
    return r.stdout.strip()


def cmd_status(st, a):
    show_status(st)


def cmd_ip(st, a):
    proxy = urllib.request.ProxyHandler({p: f"http://127.0.0.1:{st['settings']['mixed_port']}"
                                         for p in ("http", "https")})
    opener = urllib.request.build_opener(proxy)
    try:
        with opener.open("https://ipinfo.io/json", timeout=10) as r:
            j = json.loads(r.read())
        print(f"{j.get('ip')}  {j.get('country', '')} {j.get('city', '')}  {j.get('org', '')}")
    except (urllib.error.URLError, OSError) as e:
        die(f"через прокси не получилось: {e}")


def cmd_log(st, a):
    cmd = ["journalctl", "-u", UNIT, "-n", str(a.lines), "--no-pager"] + (["-f"] if a.follow else [])
    os.execvp(cmd[0], cmd)


def cmd_enable(st, a):
    apply(st, reload=False)
    install_units(st)
    systemctl("enable", UNIT, "sbx-update.timer", sudo=True)
    print("✓ автозапуск включён (sbx.service + sbx-update.timer)")
    if a.now and not is_active():
        cmd_up(st, argparse.Namespace(force=False))


def cmd_disable(st, a):
    systemctl("disable", UNIT, sudo=True)
    if a.timer:
        systemctl("disable", "sbx-update.timer", sudo=True)
    print("✓ автозапуск выключен (работающий VPN не тронут)")


def cmd_mode(st, a):
    if a.mode:
        st["settings"]["mode"] = a.mode
        save_state(st)
        apply(st)
    print(st["settings"]["mode"])


def cmd_route(st, a):
    if a.route:
        st["settings"]["route"] = a.route
        save_state(st)
        if a.route == "ru":
            update_rulesets()
        apply(st)
    print(st["settings"]["route"])


def cmd_set(st, a):
    s = st["settings"]
    if not a.key:
        for k, v in s.items():
            if k != "api_secret":
                print(f"{k} = {json.dumps(v, ensure_ascii=False)}")
        return
    if a.key not in s:
        die(f"нет настройки {a.key}")
    if a.value is None:
        print(json.dumps(s[a.key], ensure_ascii=False))
        return
    cur = s[a.key]
    if isinstance(cur, list):
        val = [x for x in a.value.split(",") if x] if a.value != "default" else DEFAULT_STATE["settings"][a.key]
    elif isinstance(cur, int):
        val = int(a.value)
    else:
        val = a.value
    s[a.key] = val
    save_state(st)
    if a.key == "bypass_sports":
        install_units(st)
        print("  правила обхода применятся при следующем sbx restart")
    apply(st)
    print(f"{a.key} = {json.dumps(val, ensure_ascii=False)}")


def cmd_install(st, a):
    apply(st, reload=False)
    install_units(st)


def cmd_uninstall(st, a):
    systemctl("disable", "--now", UNIT, "sbx-update.timer", sudo=True, check=False)
    for f in (UNIT, "sbx-update.service", "sbx-update.timer"):
        run(["sudo", "rm", "-f", str(UNIT_DIR / f)], check=False)
    systemctl("daemon-reload", sudo=True)
    print(f"✓ юниты удалены; подписки и настройки остались в {CONF_DIR}")


def cmd_config(st, a):
    apply(st, reload=False)
    if a.show:
        print(CONFIG_FILE.read_text())
    else:
        ok, err = check_config(CONFIG_FILE)
        print(f"{CONFIG_FILE}: {'ok' if ok else err}")


def main():
    p = argparse.ArgumentParser(prog="sbx", description=__doc__.split("\n")[0],
                                epilog=__doc__.split("\n\n", 1)[1],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", metavar="команда")

    s = sp.add_parser("sub", help="подписки: ls | add ИМЯ URL | rm ИМЯ")
    ssp = s.add_subparsers(dest="action")
    x = ssp.add_parser("add", help="добавить подписку и скачать")
    x.add_argument("name")
    x.add_argument("url")
    x.add_argument("--ua", help="свой User-Agent (формат ответа панели зависит от него)")
    x.add_argument("--no-hwid", action="store_true", help="не слать x-hwid и данные устройства")
    x = ssp.add_parser("rm", help="удалить подписку")
    x.add_argument("name")
    x = ssp.add_parser("ls", help="список с трафиком и сроком")
    x.add_argument("-v", "--verbose", action="store_true", help="показать URL")
    s.set_defaults(func=cmd_sub, action="ls", verbose=False)

    x = sp.add_parser("update", help="обновить подписки (все или указанные)")
    x.add_argument("names", nargs="*")
    x.add_argument("-q", "--quiet", action="store_true")
    x.set_defaults(func=cmd_update)

    x = sp.add_parser("add", help="добавить сервер(ы) по URI без подписки")
    x.add_argument("uris", nargs="+")
    x.add_argument("-n", "--name", help="имя сервера")
    x.set_defaults(func=cmd_add)

    x = sp.add_parser("rm", help="удалить добавленный вручную сервер")
    x.add_argument("server")
    x.set_defaults(func=cmd_rm)

    x = sp.add_parser("ls", help="серверы (● выбран, › активный в auto)")
    x.add_argument("filter", nargs="?")
    x.set_defaults(func=cmd_ls)

    x = sp.add_parser("use", help="выбрать сервер: номер, часть имени или auto")
    x.add_argument("server")
    x.set_defaults(func=cmd_use)

    x = sp.add_parser("test", help="задержка до серверов")
    x.add_argument("filter", nargs="?")
    x.add_argument("-t", "--timeout", type=float, default=5, help="секунд на сервер (5)")
    x.set_defaults(func=cmd_test)

    x = sp.add_parser("up", help="включить VPN")
    x.add_argument("-f", "--force", action="store_true", help="даже если работает другой VPN")
    x.set_defaults(func=cmd_up)
    sp.add_parser("down", help="выключить VPN").set_defaults(func=cmd_down)
    sp.add_parser("restart", help="перезапустить").set_defaults(func=cmd_restart)
    sp.add_parser("status", help="состояние").set_defaults(func=cmd_status)
    sp.add_parser("ip", help="внешний IP через VPN").set_defaults(func=cmd_ip)
    x = sp.add_parser("probe", help="проверить ядро, TUN и подписку без перехвата трафика")
    x.add_argument("-a", "--all", action="store_true", help="проверить все серверы")
    x.set_defaults(func=cmd_probe)

    x = sp.add_parser("log", help="журнал sing-box")
    x.add_argument("-f", "--follow", action="store_true")
    x.add_argument("-n", "--lines", type=int, default=50)
    x.set_defaults(func=cmd_log)

    x = sp.add_parser("enable", help="автозапуск при загрузке")
    x.add_argument("--now", action="store_true", help="и сразу включить")
    x.set_defaults(func=cmd_enable)
    x = sp.add_parser("disable", help="снять с автозапуска")
    x.add_argument("--timer", action="store_true", help="и таймер обновления подписок")
    x.set_defaults(func=cmd_disable)

    x = sp.add_parser("mode", help="tun — весь трафик, proxy — только 127.0.0.1:порт")
    x.add_argument("mode", nargs="?", choices=["tun", "proxy"])
    x.set_defaults(func=cmd_mode)
    x = sp.add_parser("route", help="ru — российское напрямую, global — всё через VPN")
    x.add_argument("route", nargs="?", choices=["ru", "global"])
    x.set_defaults(func=cmd_route)
    x = sp.add_parser("set", help="настройки: sbx set [ключ [значение]]")
    x.add_argument("key", nargs="?")
    x.add_argument("value", nargs="?")
    x.set_defaults(func=cmd_set)

    x = sp.add_parser("config", help="проверить сгенерированный конфиг")
    x.add_argument("--show", action="store_true", help="напечатать (там ключи!)")
    x.set_defaults(func=cmd_config)
    sp.add_parser("install", help="(пере)установить systemd-юниты").set_defaults(func=cmd_install)
    sp.add_parser("uninstall", help="удалить юниты, данные оставить").set_defaults(func=cmd_uninstall)

    a = p.parse_args()
    if not a.cmd:
        a = p.parse_args(["status"])
    st = load_state()
    if not STATE_FILE.exists():
        save_state(st)
    try:
        a.func(st, a)
    except subprocess.CalledProcessError as e:
        die(f"команда завершилась с ошибкой: {' '.join(map(str, e.cmd))}")
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
