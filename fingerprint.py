# fingerprint.py
import argparse
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional

# --- original imports & fall‑backs (unchanged) ---
try:
    from scapy.all import IP, IPv6, TCP, sr1
    _SCAPY = True
except ImportError:
    _SCAPY = False

try:
    import nmap
    NM_AVAILABLE = True
except ImportError:
    NM_AVAILABLE = False

# --- original functions (unchanged) -----------------------------------------
def fingerprint_os_nmap(host: str):
    if not NM_AVAILABLE:
        return None
    try:
        scanner = nmap.PortScanner()
        scanner.scan(host, arguments='-O -Pn')
        if host in scanner.all_hosts() and 'osmatch' in scanner[host]:
            matches = scanner[host]['osmatch']
            if matches:
                return matches[0]['name']
    except Exception as e:
        print(f"[ERROR] Nmap OS fingerprint failed: {e}", file=sys.stderr)
    return None


def fingerprint_os_scapy(host: str):
    if not _SCAPY:
        return None
    try:
        version = ipaddress.ip_address(host).version
        if version == 6:
            pkt = IPv6(dst=host) / TCP(dport=445, flags="S")
        else:
            pkt = IP(dst=host) / TCP(dport=445, flags="S")

        response = sr1(pkt, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            ttl = response.ttl
            window = response[TCP].window

            if ttl <= 64:
                return "Linux/Android"
            elif ttl <= 128:
                return "Windows"
            else:
                return "macOS/iOS"
    except Exception as e:
        print(f"[ERROR] Scapy OS fingerprint failed: {e}", file=sys.stderr)
    return None


def detect_os(host: str):
    nmap_result = fingerprint_os_nmap(host)
    if nmap_result:
        return nmap_result
    return fingerprint_os_scapy(host)


def run_nse_vuln(host: str):
    if not NM_AVAILABLE:
        return None
    try:
        scanner = nmap.PortScanner()
        scanner.scan(host, arguments='-Pn -sV --script vuln')
        return scanner[host] if host in scanner.all_hosts() else None
    except Exception as e:
        print(f"[ERROR] NSE vulnerability scan failed: {e}", file=sys.stderr)
        return None


def run_smb_nse(host: str):
    if not NM_AVAILABLE:
        return None
    try:
        scanner = nmap.PortScanner()
        scanner.scan(
            host,
            arguments='-p 445 -Pn --script smb-os-discovery,smb-protocols,'
                      'smb-enum-shares,smb-vuln-ms17-010',
        )
        return scanner[host] if host in scanner.all_hosts() else None
    except Exception as e:
        print(f"[ERROR] SMB NSE scripts failed: {e}", file=sys.stderr)
        return None


def enumerate_samba_shares(host: str):
    if not NM_AVAILABLE:
        return []
    host_info = run_smb_nse(host)
    shares = []
    try:
        if host_info:
            tcp_info = host_info.get('tcp', {}).get(445, {})
            script_output = tcp_info.get('script', {})
            enum_shares = script_output.get('smb-enum-shares', "")

            for line in enum_shares.splitlines():
                if "Sharename:" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[1].strip()
                        shares.append(share_name)
    except Exception as e:
        print(f"[ERROR] Samba share enumeration failed: {e}", file=sys.stderr)
    return shares
# -----------------------------------------------------------------------------


# --- additions ---------------------------------------------------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 445, 443, 3389]


def quick_tcp_probe(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def banner_grab(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(1024).decode(errors='ignore').strip()
    except Exception:
        return None


def scan_ports(host: str, ports: List[int] = COMMON_PORTS) -> Dict[int, Dict[str, Optional[str]]]:
    results = {}
    for p in ports:
        if quick_tcp_probe(host, p):
            results[p] = {"open": True, "banner": banner_grab(host, p)}
        else:
            results[p] = {"open": False, "banner": None}
    return results


def advanced_os_detect(host: str) -> Optional[str]:
    result = detect_os(host)
    if result:
        return result
    # fallback: TTL from multiple ports
    ttls = []
    if _SCAPY:
        for p in (22, 80, 443):
            try:
                pkt = IP(dst=host) / TCP(dport=p, flags="S")
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp:
                    ttls.append(resp.ttl)
            except Exception:
                pass
    if ttls:
        avg_ttl = sum(ttls) / len(ttls)
        if avg_ttl <= 64:
            return "Linux/Android (heuristic)"
        elif avg_ttl <= 128:
            return "Windows (heuristic)"
        return "macOS/iOS (heuristic)"
    return None


def gather_host_info(host: str, run_vuln: bool, run_smb: bool) -> Dict:
    info = {
        "host": host,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "os": advanced_os_detect(host),
        "ports": scan_ports(host),
    }
    if run_vuln:
        info["nse_vuln"] = run_nse_vuln(host)
    if run_smb:
        info["smb_shares"] = enumerate_samba_shares(host)
    return info


def parse_args():
    ap = argparse.ArgumentParser(
        description="Comprehensive network fingerprinting and enumeration tool"
    )
    ap.add_argument("targets", nargs="*", help="Target hosts/IPs (comma‑separated)")
    ap.add_argument("-f", "--file", help="File containing one target per line")
    ap.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads")
    ap.add_argument("--vuln", action="store_true", help="Run NSE vuln scripts")
    ap.add_argument("--smb", action="store_true", help="Run SMB enumeration")
    ap.add_argument("-j", "--json", action="store_true", help="JSON output")
    return ap.parse_args()


def load_targets(args) -> List[str]:
    targets = set()
    for raw in args.targets:
        for t in raw.split(","):
            t = t.strip()
            if t:
                targets.add(t)
    if args.file:
        try:
            with open(args.file) as fh:
                for line in fh:
                    t = line.strip()
                    if t:
                        targets.add(t)
        except Exception as e:
            print(f"[ERROR] reading file {args.file}: {e}", file=sys.stderr)
    return sorted(targets)


def main():
    args = parse_args()
    targets = load_targets(args)
    if not targets:
        print("No targets specified.", file=sys.stderr)
        sys.exit(1)

    results: List[Dict] = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        fut_map = {
            executor.submit(gather_host_info, h, args.vuln, args.smb): h for h in targets
        }
        for fut in as_completed(fut_map):
            r = fut.result()
            results.append(r)
            if not args.json:
                print(f"\n=== {r['host']} ===")
                print(f"OS: {r['os']}")
                print("Open ports:")
                for p, d in r["ports"].items():
                    if d["open"]:
                        b = f" | {d['banner']}" if d["banner"] else ""
                        print(f"  {p}{b}")
                if args.smb:
                    print("SMB shares:", ", ".join(r.get("smb_shares", [])) or "none")
                if args.vuln:
                    print("Vuln scan: data collected")

    if args.json:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()