#!/usr/bin/env python3
# fw_bypass_safe_scan.py  (rev 8 – package-check fix, 2025-07-14)

import argparse, sys, socket, subprocess, concurrent.futures, math, json, os, time, random, ipaddress, asyncio, struct, resource, ctypes, importlib
from typing import List, Dict, Optional

def _ensure_packages() -> None:
    pkgs = ("impacket", "requests", "scapy")
    for name in pkgs:
        try:
            __import__(name.split("[")[0].replace("-", "_"))
        except ImportError:
            subprocess.call(
                [sys.executable, "-m", "pip", "install", "--quiet", "--user", name],
                env=dict(os.environ, PIP_DISABLE_PIP_VERSION_CHECK="1"),
            )

_ensure_packages()

from impacket.smbconnection import SMBConnection
import requests
from scapy.all import IP, IPv6, TCP, sr1, conf as _scapy_conf
_scapy_conf.verb = 0


def _connect(host: str, port: int, timeout: float = 5.0) -> SMBConnection | None:
    try:
        c = SMBConnection(remoteName=host, remoteHost=host, sess_port=port,
                          preferredDialect=0x0311, compression=True, timeout=timeout)
        c.login("", "")
        return c
    except Exception:
        return None


def _cap_bits(flags: int) -> List[str]:
    m = {0x0001: "DF", 0x0004: "EXT_SEC", 0x0010: "SIGNING", 0x0040: "LARGE_READ",
         0x0080: "LARGE_WRITE", 0x0800: "COMPRESSION", 0x1000: "ENC_AES128_GCM",
         0x2000: "ENC_AES256_GCM"}
    return [n for k, n in m.items() if flags & k]


def _syn_probe(dst: str, dport: int, ttl: int | None, frag: bool, timeout: float) -> bool:
    fam = IPv6 if ":" in dst and not dst.endswith(".") else IP
    ip_layer = fam(dst=dst, ttl=ttl) if ttl else fam(dst=dst)
    tcp_layer = TCP(dport=dport, sport=random.randint(1024, 65535),
                    flags="S", seq=random.randrange(2**32))
    pkt = ip_layer / tcp_layer
    if frag and isinstance(ip_layer, IP):
        frags = [pkt.copy()]
        frags[0].frag = 0; frags[0].flags = "MF"; frags[0].payload = bytes(pkt.payload)[:8]
        frags.append(pkt.copy()); frags[1].frag = 3; frags[1].flags = 0
        frags[1].payload = bytes(pkt.payload)[8:]
        for p in frags:
            sr1(p, timeout=timeout, iface_hint=dst)
    else:
        ans = sr1(pkt, timeout=timeout, iface_hint=dst)
        if ans and ans.haslayer(TCP):
            return ans.getlayer(TCP).flags & 0x12 == 0x12
    return False


def _scan_port(host: str, port: int, timeout: float, src_ports: List[Optional[int]],
               evasion: str, ttl: int | None) -> bool:
    sps = list(src_ports); random.shuffle(sps)
    while sps:
        sp = sps.pop()
        try:
            fam = socket.AF_INET6 if ":" in host and not host.endswith(".") else socket.AF_INET
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                if sp is not None:
                    try: s.bind(("", sp))
                    except PermissionError: continue
                s.settimeout(timeout)
                s.connect((host, port))
                return True
        except Exception:
            if evasion == "syn":
                return _syn_probe(host, port, ttl, False, timeout)
            if evasion == "frag":
                return _syn_probe(host, port, ttl, True, timeout)
            continue
    return False


async def _scan_ports_async(host: str, ports: List[int], src_ports: List[Optional[int]],
                            tgt_rate: int, timeout: float, jitter: float,
                            global_sem: asyncio.Semaphore, evasion: str,
                            ttl: int | None) -> Dict[int, bool]:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(tgt_rate)
    res: Dict[int, bool] = {}
    async def w(p: int) -> None:
        async with global_sem, sem:
            if jitter: await asyncio.sleep(random.uniform(0, jitter))
            ok = await loop.run_in_executor(None, _scan_port, host, p, timeout,
                                            src_ports, evasion, ttl)
            res[p] = ok
            print(f"{host}:{p} -> {'open' if ok else 'closed'}", flush=True)
            _log({"type":"port","host":host,"port":p,"open":ok})
    await asyncio.gather(*(w(p) for p in ports))
    return res


def _risk_score(open_ports: List[int]) -> float:
    s = sum(PORT_WEIGHTS.get(p, 1) for p in open_ports)
    return round((1 - math.exp(-s / 10)) * 100, 2)


def _print_summary(host: str, open_ports: List[int]) -> None:
    r = _risk_score(open_ports)
    t = f"{host}: open {','.join(map(str,open_ports))}" if open_ports else f"{host}: no curated ports reachable"
    print(f"{t} -> risk={r}%", flush=True)
    _log({"type":"summary","host":host,"open_ports":open_ports,"risk":r})


_logfile_path = os.getenv("SCAN_RESULTS_PATH", "scan_results.jl")
_logfile = open(_logfile_path, "a", buffering=1)
def _log(e: Dict) -> None:
    e["ts"] = time.time()
    try: _logfile.write(json.dumps(e,separators=(",",":"))+"\n")
    except Exception: pass
    url, tok = os.getenv("LOG_SERVER_URL"), os.getenv("LOG_SERVER_TOKEN")
    if url and tok:
        try: requests.post(url, json=e, timeout=3, headers={"Authorization":f"Bearer {tok}"})
        except Exception: pass


WINDOWS_PORTS = [137, 138, 139, 445, 3389, 5985, 5986, 10445]
LINUX_PORTS = [22, 111, 2049, 3306, 5432, 6379]
MAC_PORTS = [22, 548, 3283, 5900]
IOS_PORTS = [62078]
ANDROID_PORTS = [5555, 5037, 2222]
UNIVERSAL_PORTS = [53, 80, 123, 443, 8080, 8443]
EXTRA_PORTS = [27017]

PORT_WEIGHTS: Dict[int, int] = {}
for p in WINDOWS_PORTS: PORT_WEIGHTS[p] = 3
for p in LINUX_PORTS + MAC_PORTS: PORT_WEIGHTS[p] = 2
for p in IOS_PORTS + ANDROID_PORTS: PORT_WEIGHTS[p] = 3
for p in UNIVERSAL_PORTS: PORT_WEIGHTS[p] = 1
for p in EXTRA_PORTS: PORT_WEIGHTS[p] = 2
ALL_PORTS = sorted(PORT_WEIGHTS)

TRUSTED_SRC_DEFAULT = [53, 443, 123, None]


def _parse_ports(spec: str | None) -> List[int]:
    if not spec: return []
    r: List[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = map(int, part.split("-", 1)); r.extend(range(a, b + 1))
        else: r.append(int(part))
    return sorted(set(r))


def _parse_src_ports(spec: str | None) -> List[Optional[int]]:
    if not spec: return TRUSTED_SRC_DEFAULT.copy()
    r: List[Optional[int]] = []
    for part in spec.split(","):
        part = part.strip()
        if part in ("", "-", "random"):
            r.append(None)
        elif "-" in part:
            a, b = map(int, part.split("-", 1)); r.extend(range(a, b + 1))
        else:
            r.append(int(part))
    return r


def _expand_targets(raw: List[str]) -> List[str]:
    out: List[str] = []
    for t in raw:
        try: out.extend(map(str, ipaddress.ip_network(t, strict=False).hosts()))
        except ValueError: out.append(t)
    return out


def _fd_soft_limit() -> int:
    try: return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except Exception: return 1024
def _fd_count() -> int:
    if os.name=="posix":
        try: return len(os.listdir("/proc/self/fd"))
        except Exception: pass
    return 0


async def _process_target(host: str, ports: List[int], src_ports: List[Optional[int]],
                          tgt_rate: int, timeout: float, jitter: float,
                          global_sem: asyncio.Semaphore, evasion: str,
                          ttl: int | None) -> None:
    res = await _scan_ports_async(host, ports, src_ports, tgt_rate, timeout,
                                  jitter, global_sem, evasion, ttl)
    open_ports = [p for p, ok in res.items() if ok]
    _print_summary(host, open_ports)
    smb_candidates = [p for p in open_ports if p in (445, 10445)]
    if smb_candidates:
        for p in smb_candidates:
            c = _connect(host, p)
            if c:
                try:
                    os_ver = c.getServerOS()
                    d = c.getDialect()
                    caps = c._Connection.get("Capabilities", 0)
                    comp = bool(c._Connection.get("CompressionCapabilities"))
                    signing = "SIGNING" in _cap_bits(caps)
                    enc_algs = (c._Connection.get("EncryptionCapabilities") or {}).get("Ciphers", [])
                    quic = "SMB2_QUIC_RESPONSE" in c._Connection.get("NegotiateContextList", {})
                    status = "VULNERABLE" if d == 0x0311 and comp and not signing else "Review"
                    print(f"{host}:{p}: dialect={hex(d)} os=\"{os_ver}\" cap={_cap_bits(caps)} "
                          f"comp={comp} enc={enc_algs} quic={quic} -> {status}", flush=True)
                    _log({"type":"smb","host":host,"port":p,"dialect":hex(d),"compression":comp,
                          "signing":signing,"enc_algs":enc_algs,"quic":quic,"status":status})
                finally:
                    c.logoff()
    _log({"type":"fd","open_fd":_fd_count()})


async def main_async(args) -> None:
    targets = _expand_targets(args.targets)
    ports = list(ALL_PORTS)
    if args.extra_ports:
        ports.extend(_parse_ports(args.extra_ports)); ports = sorted(set(ports))
    src_ports = _parse_src_ports(args.bypass_src)
    soft_limit = _fd_soft_limit(); reserved = 64; max_global = max(1, soft_limit - reserved)
    if args.global_rate<=0 or args.global_rate>max_global: args.global_rate=max_global
    if args.rate*len(targets)>args.global_rate: args.rate=max(1,args.global_rate//len(targets))
    global_sem = asyncio.Semaphore(args.global_rate)
    await asyncio.gather(*(_process_target(h,ports,src_ports,args.rate,args.timeout,
                                          args.jitter,global_sem,args.evasion,args.ttl)
                           for h in targets))


def main() -> None:
    ap = argparse.ArgumentParser(description="Firewall-bypass surface scanner (async evasion)")
    ap.add_argument("targets", nargs="*", help="targets or CIDRs")
    ap.add_argument("--targets-file")
    ap.add_argument("--extra-ports")
    ap.add_argument("--bypass-src")
    ap.add_argument("--rate", type=int, default=128)
    ap.add_argument("--global-rate", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--evasion", choices=["none","syn","frag"], default="none")
    ap.add_argument("--ttl", type=int, help="custom TTL")
    args = ap.parse_args()
    if args.targets_file:
        try:
            with open(args.targets_file) as fh:
                args.targets.extend(l.strip() for l in fh if l.strip())
        except Exception as e:
            sys.exit(f"targets-file: {e}")
    if not args.targets: args.targets=["nsa.gov"]
    try: asyncio.run(main_async(args))
    except KeyboardInterrupt: pass


if __name__=="__main__":
    main()
