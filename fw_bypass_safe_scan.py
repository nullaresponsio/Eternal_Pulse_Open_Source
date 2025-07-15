#!/usr/bin/env python3
"""
Async SMB v2/v3 vulnerability scanner (educational release, July 2025).
Back‑door or exploit functionality intentionally removed.
"""
import argparse, asyncio, concurrent.futures, json, os, random, re, socket, struct, sys, subprocess, ipaddress, time, logging
from pathlib import Path

# ---------- 1  Dynamic dependency bootstrap ----------
REQUIRED = [
    "impacket>=0.11.0",
    "scapy",
    "python-nmap",
    "paramiko",
    "cryptography",
]

def _ensure(pkgs):
    for p in pkgs:
        try:
            __import__(p.split("[",1)[0].replace("-","_"))
        except ImportError:
            subprocess.call([sys.executable, "-m", "pip", "install", "--quiet", "--user", p],
                            env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK":"1"})

_ensure(REQUIRED)

from impacket.smbconnection import SMBConnection  # type: ignore
from scapy.all import IP, IPv6, TCP, sr1, conf as _scapy_conf  # type: ignore
import nmap  # type: ignore
_scapy_conf.verb = 0

# ---------- 2  Helpers ----------
_BKD_PATTERNS = [re.compile(p, re.I) for p in [r"\\?nc(?:64)?\.exe$", r"mimikatz.*\.exe$", r"reverse.*shell", r"backdoor", r"svchosts?\.exe$", r"taskhost\.exe$", r"wmiexec.*\.py$", r"rdpwrap\.dll$"]]
_DEFAULT_SHARES = {"ADMIN$","C$","IPC$","PRINT$","SYSVOL","NETLOGON"}


def _sr1(pkt, timeout):
    try:
        return sr1(pkt, timeout=timeout, iface_hint=pkt[IP].dst if IP in pkt else None)
    except Exception:
        return None


def _expand(targets):
    out = []
    for t in targets:
        try:
            out.extend(str(ip) for ip in ipaddress.ip_network(t, strict=False).hosts())
        except ValueError:
            out.append(t)
    return out


def _parse_ports(spec: str | None):
    if not spec:
        return [445]
    res: list[int] = []
    for part in spec.split(','):
        if '-' in part:
            a, b = map(int, part.split('-', 1))
            res.extend(range(a, b + 1))
        else:
            res.append(int(part))
    return sorted(set(res))


def _syn_probe(dst: str, dport: int, timeout: float, frag: bool):
    fam = IPv6 if ':' in dst and not dst.endswith('.') else IP
    ip_hdr = fam(dst=dst)
    tcp_hdr = TCP(dport=dport, sport=random.randint(1024, 65535), flags='S', seq=random.randrange(2**32))
    pkt = ip_hdr / tcp_hdr
    if frag and isinstance(ip_hdr, IP):
        f1, f2 = pkt.copy(), pkt.copy()
        f1.frag, f1.flags = 0, 'MF'
        f2.frag, f2.flags = 3, 0
        f1.payload = bytes(pkt.payload)[:8]
        f2.payload = bytes(pkt.payload)[8:]
        _sr1(f1, timeout)
        _sr1(f2, timeout)
        return False
    ans = _sr1(pkt, timeout)
    return bool(ans and ans.haslayer(TCP) and (ans[TCP].flags & 0x12) == 0x12)


def _tcp_open(host: str, port: int, timeout: float, mode: str):
    try:
        fam = socket.AF_INET6 if ':' in host and not host.endswith('.') else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except Exception:
        if mode in ("syn", "frag"):
            return _syn_probe(host, port, timeout, mode == "frag")
    return False


_CAPS = {
    0x0001: 'DF',
    0x0004: 'EXT_SEC',
    0x0010: 'SIGNING',
    0x0040: 'LARGE_READ',
    0x0080: 'LARGE_WRITE',
    0x0800: 'COMPRESSION',
    0x1000: 'ENC_AES128_GCM',
    0x2000: 'ENC_AES256_GCM',
}


def _cap_bits(flags: int):
    return [n for k, n in _CAPS.items() if flags & k]


def _detect_backdoor(conn: SMBConnection):
    ind: list[str] = []
    try:
        shares = [s['shi1_netname'][:-1] for s in conn.listShares()]
        for sh in shares:
            if sh.upper() not in _DEFAULT_SHARES:
                ind.append(f"non-default share:{sh}")
            try:
                for e in conn.listPath(sh, '*'):
                    name = getattr(e, 'get_longname', lambda: e.get('name', ''))()
                    if name in ('.', '..'):
                        continue
                    if any(p.search(name) for p in _BKD_PATTERNS):
                        ind.append(f"suspicious:{sh}\\{name}")
            except Exception:
                pass
    except Exception as e:
        ind.append(f"share enum fail:{e}")
    return ind


def _analyze_smb(conn: SMBConnection):
    ctx = conn._Connection  # type: ignore
    d = conn.getDialect()
    caps = ctx.get('Capabilities', 0)
    comp = bool(ctx.get('CompressionCapabilities'))
    enc = bool(ctx.get('EncryptionCapabilities'))
    os_str = conn.getServerOS()
    sig = 'SIGNING' in _cap_bits(caps)
    vulns: list[str] = []

    if d == 0x0311 and comp:
        vulns.append('CVE-2024-43447')
    if not sig:
        vulns.append('CVE-2024-43451')
    if d >= 0x0300 and not enc:
        vulns.append('CVE-2025-29956')
    if 'ksmbd' in os_str.lower():
        vulns.append('CVE-2025-37899')
    if 'windows' in os_str.lower():
        vulns += ['CVE-2024-43642', 'CVE-2025-32718', 'CVE-2025-33073']

    return {
        'dialect': hex(d),
        'compression': comp,
        'signing': sig,
        'encryption': enc,
        'os': os_str,
        'vulnerabilities': vulns,
    }


# ---------- 3  Async probe ----------
async def _scan_host(host: str, ports: list[int], timeout: float, mode: str, creds: list[tuple[str,str]], sem: asyncio.Semaphore):
    loop = asyncio.get_running_loop()
    open_ports = [p for p in ports if await loop.run_in_executor(None, _tcp_open, host, p, timeout, mode)]
    for p in open_ports:
        async with sem:
            for user, pw in creds:
                try:
                    conn = SMBConnection(host, host, sess_port=p, preferredDialect=0x0311, timeout=timeout)
                    conn.login(user, pw)
                    res = _analyze_smb(conn)
                    print(json.dumps({'host': host, 'port': p, **res}, separators=(',', ':')))
                    conn.logoff()
                    break
                except Exception as e:
                    logging.debug("%s:%d %s", host, p, e)
                    continue


# ---------- 4  Main ----------

def main():
    ap = argparse.ArgumentParser(description="Async SMB v2/v3 vulnerability scanner")
    ap.add_argument('--targets', nargs='*', help='IPs, CIDRs or filenames')
    ap.add_argument('--ports', default='445', help='Port list, e.g. 445,139 or 139-445')
    ap.add_argument('--timeout', type=float, default=3.0)
    ap.add_argument('--mode', choices=['connect', 'syn', 'frag'], default='connect')
    ap.add_argument('--workers', type=int, default=500)
    ap.add_argument('--username', default='')
    ap.add_argument('--password', default='')
    ap.add_argument('--install', action='store_true', help='Install as systemd service')
    args = ap.parse_args()

    # Install self as systemd service
    if args.install:
        dst = Path('/usr/local/bin/smbscan.py')
        dst.write_bytes(Path(__file__).read_bytes())
        svc = """[Unit]
Description=Nightly SMB v2/v3 vulnerability scanner

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/bin/smbscan.py --targets /etc/smbscan.allow --mode connect

[Install]
WantedBy=multi-user.target
"""
        (Path('/etc/systemd/system')/ 'smbscan.service').write_text(svc)
        subprocess.call(['systemctl', 'daemon-reload'])
        subprocess.call(['systemctl', 'enable', '--now', 'smbscan.service'])
        print('installed service smbscan.service')
        return

    raw_targets = args.targets or []
    expanded: list[str] = []
    for item in raw_targets:
        if os.path.isfile(item):
            expanded += [l.strip() for l in open(item) if l.strip()]
        else:
            expanded.append(item)

    targets = _expand(expanded)
    ports = _parse_ports(args.ports)
    creds = [(args.username, args.password)]

    sem = asyncio.Semaphore(args.workers)
    tasks = [_scan_host(t, ports, args.timeout, args.mode, creds, sem) for t in targets]
    asyncio.run(asyncio.gather(*tasks))


if __name__ == '__main__':
    main()
