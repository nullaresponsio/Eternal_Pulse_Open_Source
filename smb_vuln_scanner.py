#!/usr/bin/env python3
"""
Async SMB v2/v3 vulnerability scanner + self-installer (rev 6, 2025-07-14)
Now flags non-default shares, suspicious files, and other tell-tale signs of
backdoor installation in addition to CVE checks.
"""

import argparse, asyncio, concurrent.futures, json, os, random, re, socket, struct, sys, time
import importlib, subprocess, ipaddress, logging, shutil, stat, platform
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------- dependency bootstrap ----------

def _ensure(pkgs: List[str]) -> None:
    for n in pkgs:
        try:
            importlib.import_module(n.split("[")[0].replace("-", "_"))
        except ImportError:
            subprocess.call(
                [sys.executable, "-m", "pip", "install", "--quiet", "--user", n],
                env=dict(os.environ, PIP_DISABLE_PIP_VERSION_CHECK="1"),
            )

_ensure(["impacket>=0.11.0", "scapy", "requests"])

from impacket.smbconnection import SMBConnection
from scapy.all import IP, IPv6, TCP, sr1, conf as _scapy_conf
_scapy_conf.verb = 0
import requests

# backdoor patterns (extend as needed)
_BKD_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"\\?nc(?:64)?\.exe$",
        r"mimikatz.*\.exe$",
        r"reverse.*shell",
        r"backdoor",
        r"svchosts?\.exe$",
        r"taskhost\.exe$",
        r"wmiexec.*\.py$",
        r"rdpwrap\.dll$",
    ]
]
_DEFAULT_SHARES = {"ADMIN$", "C$", "IPC$", "PRINT$", "SYSVOL", "NETLOGON"}

# ---------- low-level helpers ----------

def _sr1(pkt, timeout, dst):
    try:
        return sr1(pkt, timeout=timeout, iface_hint=dst)
    except TypeError:
        return sr1(pkt, timeout=timeout)

def _expand(targets: List[str]) -> List[str]:
    out = []
    for t in targets:
        try:
            out.extend(map(str, ipaddress.ip_network(t, strict=False).hosts()))
        except ValueError:
            out.append(t)
    return out

def _parse_ports(spec: str | None) -> List[int]:
    if not spec:
        return [445]
    r = []
    for part in spec.split(","):
        if "-" in part:
            a, b = map(int, part.split("-", 1))
            r.extend(range(a, b + 1))
        else:
            r.append(int(part))
    return sorted(set(r))

def _syn_probe(dst: str, dport: int, ttl: int | None, frag: bool, timeout: float) -> bool:
    fam = IPv6 if ":" in dst and not dst.endswith(".") else IP
    ip_layer = fam(dst=dst, ttl=ttl) if ttl else fam(dst=dst)
    tcp_layer = TCP(
        dport=dport,
        sport=random.randint(1024, 65535),
        flags="S",
        seq=random.randrange(2**32),
    )
    pkt = ip_layer / tcp_layer
    if frag and isinstance(ip_layer, IP):
        f1, f2 = pkt.copy(), pkt.copy()
        f1.frag, f1.flags = 0, "MF"
        f2.frag, f2.flags = 3, 0
        f1.payload = bytes(pkt.payload)[:8]
        f2.payload = bytes(pkt.payload)[8:]
        _sr1(f1, timeout, dst)
        _sr1(f2, timeout, dst)
    else:
        ans = _sr1(pkt, timeout, dst)
        if ans and ans.haslayer(TCP):
            return (ans[TCP].flags & 0x12) == 0x12
    return False

def _tcp_open(host: str, port: int, timeout: float, evasion: str, ttl: int | None) -> bool:
    try:
        fam = socket.AF_INET6 if ":" in host and not host.endswith(".") else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except Exception:
        if evasion in ("syn", "frag"):
            return _syn_probe(host, port, ttl, evasion == "frag", timeout)
    return False

def _cap_bits(flags: int) -> List[str]:
    m = {
        0x0001: "DF",
        0x0004: "EXT_SEC",
        0x0010: "SIGNING",
        0x0040: "LARGE_READ",
        0x0080: "LARGE_WRITE",
        0x0800: "COMPRESSION",
        0x1000: "ENC_AES128_GCM",
        0x2000: "ENC_AES256_GCM",
    }
    return [n for k, n in m.items() if flags & k]

# ---------- backdoor detection ----------

def _detect_backdoor(conn: SMBConnection) -> List[str]:
    ind: List[str] = []
    try:
        shares = [s["shi1_netname"][:-1] for s in conn.listShares()]
        for sh in shares:
            if sh.upper() not in _DEFAULT_SHARES:
                ind.append(f"non-default share: {sh}")
            try:
                entries = conn.listPath(sh, "*")
                for e in entries:
                    name = getattr(e, "get_longname", lambda: e.get("name", ""))()
                    if name in (".", ".."):
                        continue
                    if any(p.search(name) for p in _BKD_PATTERNS):
                        ind.append(f"suspicious file: {sh}\\{name}")
            except Exception:
                continue
    except Exception as e:
        ind.append(f"share enumeration failed: {e}")
    return ind

# ---------- vulnerability analysis ----------

def _analyze(host: str, port: int, conn: SMBConnection):
    ctx = conn._Connection
    d = conn.getDialect()
    caps = ctx.get("Capabilities", 0)
    comp = bool(ctx.get("CompressionCapabilities"))
    enc_caps = (ctx.get("EncryptionCapabilities") or {}).get("Ciphers", [])
    quic = "SMB2_QUIC_RESPONSE" in ctx.get("NegotiateContextList", {})
    os_str = conn.getServerOS()
    sig_ok = "SIGNING" in _cap_bits(caps)

    vulns: List[str] = []

    if d == 0x0311 and comp:
        vulns.append("SMB3 compression RCE (CVE-2024-43447)")
    if not sig_ok:
        vulns.append("NTLM hash leak (CVE-2024-43451)")
    if d >= 0x0300 and not enc_caps:
        vulns.append("Info disclosure (CVE-2025-29956)")
    if "ksmbd" in os_str.lower() and "linux" in os_str.lower():
        vulns.append("ksmbd LOGOFF UAF (CVE-2025-37899)")
    if "windows" in os_str.lower():
        vulns.extend(
            [
                "SMB DoS (CVE-2024-43642)",
                "SMB EoP (CVE-2025-32718)",
                "SMB EoP (CVE-2025-33073)",
            ]
        )

    backdoor_ind = _detect_backdoor(conn)

    return dict(
        host=host,
        port=port,
        dialect=hex(d),
        compression=comp,
        signing=sig_ok,
        encryption=bool(enc_caps),
        quic=quic,
        os=os_str,
        vulnerabilities=vulns,
        backdoor_indicators=backdoor_ind,
    )

# ---------- scanning coroutine ----------

async def _scan_host(
    host: str,
    ports: List[int],
    timeout: float,
    evasion: str,
    ttl: int | None,
    rate: int,
    jitter: float,
    sem: asyncio.Semaphore,
    creds_list: List[Tuple[str, str]],
    retries: int,
    retry_delay: float,
):
    loop = asyncio.get_running_loop()
    open_ports = [
        p
        for p in ports
        if await loop.run_in_executor(None, _tcp_open, host, p, timeout, evasion, ttl)
    ]
    for p in open_ports:
        async with sem:
            if jitter:
                await asyncio.sleep(random.uniform(0, jitter))
            for _ in range(max(1, retries)):
                for user, pw in creds_list:
                    try:
                        conn = SMBConnection(
                            remoteName=host,
                            remoteHost=host,
                            sess_port=p,
                            preferredDialect=0x0311,
                            timeout=timeout,
                        )
                        try:
                            conn.login(user, pw)
                        except Exception:
                            if (user, pw) != ("", ""):
                                continue
                            conn.login("", "")
                        info = _analyze(host, p, conn)
                        print(json.dumps(info, separators=(",", ":")))
                        conn.logoff()
                        break
                    except Exception as e:
                        print(json.dumps({"host": host, "port": p, "error": str(e)}))
                else:
                    await asyncio.sleep(retry_delay)
                    continue
                break

# ---------- installer ----------

def _install_self(target: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path(__file__).resolve(), target)
    target.chmod(target.stat().st_mode | stat.S_IEXEC)

    if platform.system() == "Linux":
        service = f"""[Unit]
Description=SMB Vuln Scanner
After=network-online.target
[Service]
ExecStart={target} --config /etc/smbscan.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
"""
        Path("/etc/systemd/system/smbscan.service").write_text(service)
        subprocess.call(["systemctl", "daemon-reload"])
        subprocess.call(["systemctl", "enable", "smbscan.service"])
        print("installed systemd unit smbscan.service")
    print(f"installed to {target}")

# ---------- main ----------

def _load_creds(path: Optional[str]) -> List[Tuple[str, str]]:
    if not path:
        return [("", "")]
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                user, pw = line.split(":", 1)
            else:
                user, pw = line, ""
            out.append((user, pw))
    return out or [("", "")]

async def main_async(args):
    targets = _expand(args.targets)
    ports = _parse_ports(args.ports)
    sem = asyncio.Semaphore(args.rate)
    creds_list = _load_creds(args.creds)
    await asyncio.gather(
        *[
            _scan_host(
                h,
                ports,
                args.timeout,
                args.evasion,
                args.ttl,
                args.rate,
                args.jitter,
                sem,
                creds_list,
                args.retries,
                args.retry_delay,
            )
            for h in targets
        ]
    )

def main():
    ap = argparse.ArgumentParser(description="Async SMB v2/v3 vulnerability scanner 2025")
    ap.add_argument("targets", nargs="*")
    ap.add_argument("--ports", default="445")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--rate", type=int, default=128)
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--evasion", choices=["none", "syn", "frag"], default="none")
    ap.add_argument("--ttl", type=int)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--log", help="log file path")
    ap.add_argument("--creds", help="credential list file (user:pass per line)")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--retry-delay", type=float, default=2.0)
    ap.add_argument("--install", metavar="PATH", help="install scanner to PATH")
    args = ap.parse_args()

    if args.install:
        _install_self(Path(args.install))
        return

    if not args.targets:
        args.targets = ["scanme.nmap.org"]
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        filename=args.log,
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
