#!/usr/bin/env python3
# smb_vuln_scanner.py  (rev 4, 2025-07-14)

import argparse, asyncio, concurrent.futures, json, math, os, random, re, socket
import struct, sys, time, importlib, subprocess, ipaddress, logging
from typing import Dict, List, Optional, Tuple

def _ensure(pkgs: List[str]) -> None:
    for n in pkgs:
        try:
            importlib.import_module(n.split("[")[0].replace("-", "_"))
            logging.debug(f"dependency {n} already installed")
        except ImportError:
            logging.info(f"installing {n}")
            rc = subprocess.call(
                [sys.executable, "-m", "pip", "install", "--quiet", "--user", n],
                env=dict(os.environ, PIP_DISABLE_PIP_VERSION_CHECK="1"),
            )
            logging.debug(f"pip exit code {rc}")

_ensure(["impacket", "scapy", "requests"])

from impacket.smbconnection import SMBConnection
from scapy.all import IP, IPv6, TCP, sr1, conf as _scapy_conf
_scapy_conf.verb = 0
import requests

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
        return [445, 10445]
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
        seq=random.randrange(2 ** 32),
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
            logging.debug(f"{host}:{port} connect OK")
            return True
    except Exception as e:
        logging.debug(f"{host}:{port} connect fail: {e}")
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

def _windows_build(os_str: str) -> int:
    m = re.search(r"\b(\d{4,6})\b", os_str)
    return int(m.group(1)) if m else 0

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

    # 2024-2025 CVEs
    if d == 0x0311 and comp:
        vulns.append("SMB3 compression RCE (CVE-2024-43447)")
        vulns.append("SMB3 compression priv-esc (CVE-2024-9142)")

    if not sig_ok:
        vulns.append("NTLM hash leak / pass-the-hash (CVE-2024-43451)")
    if d >= 0x0300 and not enc_caps:
        vulns.append("Information disclosure risk (CVE-2025-29956)")

    if "ksmbd" in os_str.lower() and "linux" in os_str.lower():
        vulns.append("ksmbd LOGOFF UAF (CVE-2025-37899)")

    if "windows" in os_str.lower():
        vulns.extend(
            [
                "Potential SMB DoS (CVE-2024-43642)",
                "Potential SMB EoP (CVE-2024-26245)",
                "Potential SMB EoP (CVE-2025-32718)",
                "Potential SMB EoP (CVE-2025-33073)",
            ]
        )

    return (
        dict(
            host=host,
            port=port,
            dialect=hex(d),
            compression=comp,
            signing=sig_ok,
            encryption=bool(enc_caps),
            quic=quic,
            os=os_str,
            vulnerabilities=vulns,
        ),
        vulns,
    )

async def _scan_host(
    host: str,
    ports: List[int],
    timeout: float,
    evasion: str,
    ttl: int | None,
    rate: int,
    jitter: float,
    sem: asyncio.Semaphore,
    creds: Tuple[str, str],
) -> None:
    loop = asyncio.get_running_loop()
    open_ports = [p for p in ports if await loop.run_in_executor(None, _tcp_open, host, p, timeout, evasion, ttl)]
    for p in open_ports:
        async with sem:
            if jitter:
                await asyncio.sleep(random.uniform(0, jitter))
            try:
                conn = SMBConnection(
                    remoteName=host,
                    remoteHost=host,
                    sess_port=p,
                    preferredDialect=0x0311,
                    timeout=timeout,
                )
                try:
                    conn.login(creds[0], creds[1])
                except Exception:
                    if creds != ("", ""):
                        raise
                    conn.login("", "")
                info, _ = _analyze(host, p, conn)
                print(json.dumps(info, separators=(",", ":")))
                logging.info(
                    f"{host}:{p} dialect {info['dialect']} vulns={len(info['vulnerabilities'])}"
                )
                conn.logoff()
            except Exception as e:
                err = {"host": host, "port": p, "error": str(e)}
                print(json.dumps(err))
                logging.error(err)

async def main_async(args):
    targets = _expand(args.targets)
    ports = _parse_ports(args.ports)
    sem = asyncio.Semaphore(args.rate)
    creds = (args.user, args.passw)
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
                creds,
            )
            for h in targets
        ]
    )

def main():
    ap = argparse.ArgumentParser(description="Async SMB v2/v3 vulnerability scanner")
    ap.add_argument("targets", nargs="*")
    ap.add_argument("--ports", default="445")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--rate", type=int, default=128)
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--evasion", choices=["none", "syn", "frag"], default="none")
    ap.add_argument("--ttl", type=int)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--log", help="log file path")
    ap.add_argument("--user", default="")
    ap.add_argument("--passw", default="")
    args = ap.parse_args()
    if not args.targets:
        args.targets = ["scanme.nmap.org"]
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        filename=args.log,
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.info("scanner start")
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        logging.info("cancelled by user")

if __name__ == "__main__":
    main()
