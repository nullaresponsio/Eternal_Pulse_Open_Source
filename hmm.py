#!/usr/bin/env python3
# fw_bypass_safe_scan.py
#   Safe firewall-bypass surface scanner for desktop, server, and mobile OSes.
#   Includes SMBv3 compression vulnerability check from original script.

import argparse
import sys
import socket
import concurrent.futures
import math
from typing import List, Dict, Optional

from impacket.smbconnection import SMBConnection


# === original SMB compression check (unchanged) ===
def _connect(host: str, port: int) -> SMBConnection | None:
    try:
        conn = SMBConnection(
            remoteName=host,
            remoteHost=host,
            sess_port=port,
            preferredDialect=0x0311,
            compression=True,
            timeout=5,
        )
        conn.login("", "")
        return conn
    except Exception:
        return None


def _test_host(host: str, ports: List[int]) -> None:
    for port in ports:
        conn = _connect(host, port)
        if not conn:
            continue
        os_ver = conn.getServerOS()
        dialect = conn.getDialect()
        comp = bool(conn._Connection.get("CompressionCapabilities"))
        status = "VULNERABLE" if dialect == 0x0311 and comp else "Not vulnerable"
        print(
            f"{host}:{port}: dialect={hex(dialect)} os=\"{os_ver}\" "
            f"compression={comp} -> {status}"
        )
        conn.logoff()
        return
    print(f"{host}: no SMB service reachable on {','.join(map(str, ports))}")
# === end unchanged section ===


def _parse_ports(spec: str | None) -> List[int]:
    if not spec:
        return []
    res: List[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = map(int, part.split("-", 1))
            res.extend(range(a, b + 1))
        else:
            res.append(int(part))
    return sorted(set(res))


# curated port sets
WINDOWS_PORTS = [137, 138, 139, 445, 3389, 5985, 5986, 10445]
LINUX_PORTS = [22, 111, 2049, 3306, 5432, 6379]
MAC_PORTS = [22, 548, 3283, 5900]
IOS_PORTS = [62078]
ANDROID_PORTS = [5555, 5037, 2222]
UNIVERSAL_PORTS = [53, 80, 123, 443, 8080, 8443]
EXTRA_PORTS = [27017]

PORT_WEIGHTS: Dict[int, int] = {}
for p in WINDOWS_PORTS:
    PORT_WEIGHTS[p] = 3
for p in LINUX_PORTS + MAC_PORTS:
    PORT_WEIGHTS[p] = 2
for p in IOS_PORTS + ANDROID_PORTS:
    PORT_WEIGHTS[p] = 3
for p in UNIVERSAL_PORTS:
    PORT_WEIGHTS[p] = 1
for p in EXTRA_PORTS:
    PORT_WEIGHTS[p] = 2

ALL_PORTS = sorted(PORT_WEIGHTS)

TRUSTED_SRC_DEFAULT = [53, 443, 123, None]  # None = random OS-assigned port


def _scan_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    src_ports: Optional[List[Optional[int]]] = None,
) -> bool:
    src_ports = src_ports or TRUSTED_SRC_DEFAULT
    for sp in src_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if sp is not None:
                try:
                    s.bind(("", sp))
                except PermissionError:
                    pass
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            continue
    return False


def _scan_ports(
    host: str, ports: List[int], src_ports: Optional[List[Optional[int]]]
) -> Dict[int, bool]:
    open_ports: Dict[int, bool] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(64, len(ports))
    ) as exe:
        fut = {
            exe.submit(_scan_port, host, p, 2.0, src_ports): p for p in ports
        }
        for f in concurrent.futures.as_completed(fut):
            port = fut[f]
            open_ports[port] = f.result()
    return open_ports


def _risk_score(open_ports: List[int]) -> float:
    score = sum(PORT_WEIGHTS.get(p, 1) for p in open_ports)
    max_score = sum(PORT_WEIGHTS.values())
    return round((1 - math.exp(-score / 10)) * 100, 2)


def _print_summary(host: str, open_ports: List[int]) -> None:
    risk = _risk_score(open_ports)
    if open_ports:
        print(f"{host}: open {','.join(map(str, open_ports))} -> risk={risk}%")
    else:
        print(f"{host}: no curated ports reachable -> risk={risk}%")



def main() -> None:
    ap = argparse.ArgumentParser(
        description="Safe firewall-bypass surface scanner with SMB test"
    )
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--extra-ports", help="comma/range list to append to curated list")
    ap.add_argument(
        "--bypass-src",
        help="comma list of source ports used when connecting "
        "(use '-' or 'random' for OS-chosen)",
    )
    args = ap.parse_args()

    ports = list(ALL_PORTS)
    if args.extra_ports:
        ports.extend(_parse_ports(args.extra_ports))
        ports = sorted(set(ports))

    src_ports: Optional[List[Optional[int]]] = None
    if args.bypass_src:
        raw = args.bypass_src.split(",")
        src_ports = [
            None if x in ("-", "random", "") else int(x) for x in raw
        ]

    for host in args.targets:
        try:
            results = _scan_ports(host, ports, src_ports)
            open_ports = [p for p, ok in results.items() if ok]
            _print_summary(host, open_ports)
            smb_candidates = [p for p in open_ports if p in (445, 10445)]
            if smb_candidates:
                _test_host(host, smb_candidates)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"{host}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
