#!/usr/bin/env python3
"""
PublicIPFirewallSMB 2.0 – exhaustive SMB discovery, even through filtering.
Author: ChatGPT‑4o, 2025‑07‑25
Licence: MIT
"""
import asyncio
import concurrent.futures
import errno
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import time
import uuid
from contextlib import suppress
from datetime import datetime, timezone
from typing import Dict, List, Tuple

# ─── Optional dependencies ──────────────────────────────────────────────────
try:
    from smbprotocol.connection import Connection                   # explicit SMB check
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    from scapy.all import IP, IPv6, TCP, ICMP, sr1                  # stealth scans
    _SCAPY = True
except ImportError:
    _SCAPY = False

try:
    import nmap                                                     # wrapper for Nmap
    NM_AVAILABLE = True
except ImportError:
    NM_AVAILABLE = False

try:
    # RPC Endpoint‑mapper probe
    from impacket.dcerpc.v5 import transport, epm
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

try:
    from deap import base, creator, tools, algorithms               # genetic fuzz
    GA_AVAILABLE = True
except ImportError:
    GA_AVAILABLE = False
# ────────────────────────────────────────────────────────────────────────────

DEFAULT_ALLOWLIST = {"ips": [], "cidrs": []}


class PublicIPFirewallSMB:
    # ─── round‑robin helper ────────────────────────────────────────────────
    class RoundRobin:
        def __init__(self, targets):
            self._targets = list(targets)

        def __iter__(self):
            return iter(self._targets)

    # ─── constructor ───────────────────────────────────────────────────────
    def __init__(
        self,
        allowlist: str | Dict | None = None,
        strategy: str = "round",
        timeout: int = 2,
        workers: int = 100,
        verbose: bool = True,
        tcp_ports: List[int] | None = None,
        udp_ports: List[int] | None = None,
        use_nmap: bool = True,
        smb_verify: bool = True,
        smb_fuzz: bool = True,
        fuzz_gens: int = 20,
        fuzz_pop: int = 30,
        fuzz_len: int = 128,
    ):
        # allowlist / targets ------------------------------------------------
        self._nets, self._ips = self._load_allowlist(allowlist)
        # timeouts / threading ----------------------------------------------
        self._timeout = timeout
        self._workers = workers
        self._verbose = verbose
        # strategy -----------------------------------------------------------
        self._strategy_cls = {"round": self.RoundRobin}.get(strategy, self.RoundRobin)
        # core SMB & auxiliary ports ----------------------------------------
        self._tcp_ports = tcp_ports or [445, 139]
        self._udp_ports = udp_ports or [137, 138]
        # *** new auxiliary channels ***
        if 135 not in self._tcp_ports:
            self._tcp_ports.append(135)       # RPC EPM
        if 443 not in self._udp_ports:
            self._udp_ports.append(443)       # SMB‑over‑QUIC
        random.shuffle(self._tcp_ports)
        random.shuffle(self._udp_ports)
        # feature toggles ----------------------------------------------------
        self._use_nmap = use_nmap and NM_AVAILABLE
        self._smb_verify = smb_verify
        self._smb_fuzz = smb_fuzz and GA_AVAILABLE
        # genetic fuzz params -----------------------------------------------
        self._fuzz_gens = fuzz_gens
        self._fuzz_pop = fuzz_pop
        self._fuzz_len = fuzz_len
        # runtime state ------------------------------------------------------
        self._results: Dict[str, Dict] = {}
        self._skipped: List[str] = []

    # ─── logging ───────────────────────────────────────────────────────────
    def _log(self, *m):
        if self._verbose:
            print("[DBG]", *m, file=sys.stderr, flush=True)

    # ─── allowlist helpers ─────────────────────────────────────────────────
    @staticmethod
    def _load_allowlist(src):
        if src is None:
            d = DEFAULT_ALLOWLIST
        elif isinstance(src, dict):
            d = src.get("allow", src)
        else:
            with open(os.path.abspath(src)) as f:
                data = json.load(f)
                d = data.get("allow", data)
        nets, ips = [], set()
        for t in list(d.get("ips", [])) + list(d.get("cidrs", [])):
            with suppress(ValueError):
                if "/" in t:
                    nets.append(ipaddress.ip_network(t, strict=False))
                else:
                    ips.add(ipaddress.ip_address(t))
        return nets, ips

    @staticmethod
    def _allowed(ip, nets, ips):
        a = ipaddress.ip_address(ip)
        return a in ips or any(a in n for n in nets)

    @staticmethod
    def _fam(ip):
        return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    # ════════════════════════════════════════════════════════════════════════
    #  1)  TCP active & stealth probes (added Window + Maimon)               ║
    # ════════════════════════════════════════════════════════════════════════
    def _tcp_connect(self, host, port):  # plain three‑way handshake
        s = socket.socket(self._fam(host), socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((host, port))
            return "open"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                return "unreachable"
            return "error"
        finally:
            s.close()

    def _tcp_syn(self, host, port):
        return self._scapy_flag_scan(host, port, "S")

    def _tcp_fin(self, host, port):
        return self._scapy_flag_scan(host, port, "F")

    def _tcp_null(self, host, port):
        return self._scapy_flag_scan(host, port, 0)

    def _tcp_xmas(self, host, port):
        return self._scapy_flag_scan(host, port, "FPU")

    def _tcp_ack(self, host, port):
        return self._scapy_flag_scan(host, port, "A", ack_probe=True)

    # *** NEW stealth methods ***
    def _tcp_window(self, host, port):               # Nmap –sW
        return self._scapy_flag_scan(host, port, "A", inspect_window=True)

    def _tcp_maimon(self, host, port):               # FIN/ACK combo
        return self._scapy_flag_scan(host, port, "FA")

    # common helper for Scapy probes ----------------------------------------
    def _scapy_flag_scan(self, host, port, flags, ack_probe=False, inspect_window=False):
        if not _SCAPY:
            return "unavailable"
        try:
            layer = IPv6 if ipaddress.ip_address(host).version == 6 else IP
            pkt = layer(dst=host) / TCP(dport=port, flags=flags)
            ans = sr1(pkt, timeout=self._timeout, verbose=0)
            if not ans or not ans.haslayer(TCP):
                return "filtered"
            tcp = ans.getlayer(TCP)
            # SYN/ACK / RST handling ----------------------------------------
            if ack_probe:
                # Any RST means *unfiltered* (state unknown)
                return "unfiltered" if tcp.flags & 0x04 else "filtered"
            if inspect_window:
                # RFC793 window > 0 → open|filtered (heuristic)
                return "open" if tcp.window > 0 else "closed"
            # Generic scans --------------------------------------------------
            if tcp.flags & 0x12:      # SYN‑ACK
                return "open"
            if tcp.flags & 0x14:      # RST‑ACK
                return "closed"
            return "open"
        except PermissionError:
            return "unavailable"
        except Exception as e:
            self._log("scapy‑scan error:", host, port, e)
            return "error"

    # ════════════════════════════════════════════════════════════════════════
    #  2) UDP probes (for NBNS + QUIC)                                       ║
    # ════════════════════════════════════════════════════════════════════════
    def _udp_state(self, host, port):
        s = socket.socket(self._fam(host), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            s.sendto(b"", (host, port))
            try:
                s.recvfrom(1024)
                return "open"
            except socket.timeout:
                return "open|filtered"
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                return "closed"
            return "error"
        finally:
            s.close()

    # ════════════════════════════════════════════════════════════════════════
    #  3) Explicit SMB / NBNS / RPC / QUIC checks                            ║
    # ════════════════════════════════════════════════════════════════════════
    def _smb_check(self, host, port):
        """
        True  → positive SMB negotiation
        False → negotiation failed or not attempted
        """
        if not self._smb_verify or port not in (445, 139):
            return False

        # a) smbprotocol (SMB1/2 negotiate)
        if SMB_AVAILABLE:
            try:
                conn = Connection(uuid.uuid4().hex, host, port=port, timeout=self._timeout)
                conn.connect(); conn.negotiate(); conn.close()
                return True
            except Exception:
                pass

        # b) manual 4‑byte *session message* pre‑amble
        try:
            s = socket.socket(self._fam(host), socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, port))
            s.sendall(b"\x00\x00\x00\x00")
            data = s.recv(4)
            s.close()
            return data.startswith((b"\xffSMB", b"\xfeSMB"))
        except Exception:
            return False

    def _netbios_node_status(self, host):
        """UDP/137 node‑status query (“NBSTAT *”); single packet."""
        trn_id = random.randrange(0, 65536)
        hdr = struct.pack(">HHHHHH", trn_id, 0, 1, 0, 0, 0)
        nb_name = "*               \x00"
        enc = "".join(
            chr(((ord(c) >> 4) & 0x0F) + 0x41) + chr((ord(c) & 0x0F) + 0x41)
            for c in nb_name
        ).encode()
        qname = b"\x20" + enc + b"\x00"
        qtail = struct.pack(">HH", 0x0021, 0x0001)
        pkt = hdr + qname + qtail
        s = socket.socket(self._fam(host), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            s.sendto(pkt, (host, 137))
            resp, _ = s.recvfrom(256)
            return len(resp) > 12
        except Exception:
            return False
        finally:
            s.close()

    # *** NEW: RPC Endpoint Mapper /135 ‑‑> srvsvc UUID ***
    def _rpc_srvsvc_check(self, host):
        if not IMPACKET_AVAILABLE:
            return False
        try:
            stringbinding = f"ncacn_ip_tcp:{host}[135]"
            rpctrans = transport.DCERPCTransportFactory(stringbinding)
            rpctrans.set_connect_timeout(self._timeout * 1000)
            dce = rpctrans.get_dce_rpc()
            dce.connect()
            # srvsvc = 4b324fc8‑1670‑01d3‑1278‑5a47bf6ee188 (LanmanServer)
            srvsvc_uuid = uuid.UUID("4b324fc8-1670-01d3-1278-5a47bf6ee188")
            epm.hept_map(dce, srvsvc_uuid, protocol="ncacn_ip_tcp")
            dce.disconnect()
            return True
        except Exception:
            return False

    # *** NEW: SMB over QUIC / UDP‑443 ***
    def _quic_smb_check(self, host):
        """
        Send QUIC Initial (1200B) with random DCID and ALPN length → if any
        reply is seen we assume QUIC is enabled. We do *not* deeply parse TLS.
        """
        s = socket.socket(self._fam(host), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            # First byte: Long‑header, Initial packet, random version (Google's draft), DCID len 8
            data = b"\xc3\x00\x00\x00\x01\x08" + os.urandom(8)     # fake DCID
            # pad to 1200 bytes (minimum QUIC initial)
            data = data.ljust(1200, b"\x00")
            s.sendto(data, (host, 443))
            resp, _ = s.recvfrom(2048)
            return len(resp) > 0   # any response at all → QUIC supported
        except Exception:
            return False
        finally:
            s.close()

    # ════════════════════════════════════════════════════════════════════════
    #  4) Genetic SMB fuzz (unchanged)                                       ║
    # ════════════════════════════════════════════════════════════════════════
    def _smb_genetic_fuzz(self, host, port):
        creator.create("FitnessMax", base.Fitness, weights=(1.0,))
        creator.create("Individual", list, fitness=creator.FitnessMax)
        toolbox = base.Toolbox()
        toolbox.register("attr_byte", random.randrange, 0, 256)
        toolbox.register("individual", tools.initRepeat,
                         creator.Individual, toolbox.attr_byte, self._fuzz_len)
        toolbox.register("population", tools.initRepeat, list, toolbox.individual)

        def eval_payload(ind):
            data = bytes(ind)
            try:
                s = socket.socket(self._fam(host), socket.SOCK_STREAM)
                s.settimeout(self._timeout)
                s.connect((host, port))
                s.send(data)
                resp = s.recv(1024)
                s.close()
                return (len(resp),)
            except Exception:
                return (0,)
        toolbox.register("evaluate", eval_payload)
        toolbox.register("mate", tools.cxTwoPoint)
        toolbox.register("mutate", tools.mutFlipBit, indpb=0.05)
        toolbox.register("select", tools.selTournament, tournsize=3)

        pop = toolbox.population(n=self._fuzz_pop)
        hof = tools.HallOfFame(1)
        algorithms.eaSimple(pop, toolbox, cxpb=0.5, mutpb=0.2,
                            ngen=self._fuzz_gens, halloffame=hof, verbose=False)
        best = hof[0]
        return {"payload_hex": bytes(best).hex(), "response_len": len(best)}

    # ════════════════════════════════════════════════════════════════════════
    #  5) Nmap wrapper (unchanged)                                           ║
    # ════════════════════════════════════════════════════════════════════════
    def _nmap_scan(self, host):
        res = {}
        if not self._use_nmap:
            return res
        try:
            scanner = nmap.PortScanner()
            ports = ",".join(map(str, self._tcp_ports + self._udp_ports))
            args = f"-Pn -p {ports} --host-timeout {self._timeout}s -n"
            scanner.scan(hosts=host, arguments=args)
            if host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    for p, data in scanner[host][proto].items():
                        res[(proto, p)] = data.get("state", "unknown")
        except Exception as e:
            self._log("nmap error", host, e)
        return res

    # ════════════════════════════════════════════════════════════════════════
    #  6) Port‑state probe orchestrator                                      ║
    # ════════════════════════════════════════════════════════════════════════
    def _probe_port(self, host, port, proto):
        if proto == "tcp":
            methods = [
                self._tcp_connect,
                self._tcp_syn,
                self._tcp_null,
                self._tcp_fin,
                self._tcp_xmas,
                self._tcp_ack,
                self._tcp_window,   # NEW
                self._tcp_maimon,   # NEW
            ]
            for m in methods:
                s = m(host, port)
                if s == "open":
                    return "open"
                if s in ("closed", "unreachable", "error"):
                    return s
            return "filtered"
        return self._udp_state(host, port)

    # ════════════════════════════════════════════════════════════════════════
    #  7) Asynchronous orchestration (unchanged)                             ║
    # ════════════════════════════════════════════════════════════════════════
    async def _async_scan(self, order):
        loop = asyncio.get_running_loop()
        futures = [loop.run_in_executor(None, self._probe_host, h) for h in order]
        for host, r in zip(order, await asyncio.gather(*futures, return_exceptions=True)):
            if isinstance(r, Exception):
                self._results[host] = {"error": str(r)}
            else:
                self._results[host] = r
            self._log("RESULT", host, "success" if self._is_success(self._results[host]) else "fail")
        return self._results

    # ════════════════════════════════════════════════════════════════════════
    #  8) Host‑level probe (core logic)                                      ║
    # ════════════════════════════════════════════════════════════════════════
    def _probe_host(self, host):
        result = {"host": host, "ports": {}, "smb_inferred": False}
        nmap_data = self._nmap_scan(host)

        # ── NBNS pre‑check (single packet, cheap) ───────────────────────────
        nbns_presence = self._netbios_node_status(host)

        # ─────────────────────────────────────────────────────────────────────
        #  TCP ports (445,139,135)                                           
        # ─────────────────────────────────────────────────────────────────────
        for port in self._tcp_ports:
            state = nmap_data.get(("tcp", port)) or self._probe_port(host, port, "tcp")
            if port in (445, 139):
                smb_ok = self._smb_check(host, port) if state == "open" else False
                # inference if filtered but NBNS answered
                if state.startswith("filter") and nbns_presence:
                    result["smb_inferred"] = True
            elif port == 135:
                smb_ok = self._rpc_srvsvc_check(host) if state == "open" else False
                if smb_ok:
                    result["smb_inferred"] = True
            else:
                smb_ok = False

            entry = {"protocol": "tcp", "state": state, "smb": smb_ok}
            if smb_ok and self._smb_fuzz and port in (445, 139):
                entry["vuln"] = self._smb_genetic_fuzz(host, port)
            result["ports"][port] = entry

        # ─────────────────────────────────────────────────────────────────────
        #  UDP ports (137,138,443)                                            
        # ─────────────────────────────────────────────────────────────────────
        for port in self._udp_ports:
            state = nmap_data.get(("udp", port)) or self._probe_port(host, port, "udp")
            if port == 443:
                quic_ok = self._quic_smb_check(host) if state.startswith("open") else False
                if quic_ok:
                    result["smb_inferred"] = True
                result["ports"][port] = {"protocol": "udp", "state": state, "quic": quic_ok}
            else:
                result["ports"][port] = {"protocol": "udp", "state": state}

        # Final NBNS flag
        result["nbns"] = nbns_presence
        if nbns_presence:
            result["smb_inferred"] = True

        return result

    # ════════════════════════════════════════════════════════════════════════
    #  9) Public scan entry‑point (unchanged aside from class tweaks)        ║
    # ════════════════════════════════════════════════════════════════════════
    def scan(self, hosts=None, cidrs=None, async_mode=False):
        targets = list(self._iter_targets(hosts or [], cidrs or []))
        filtered = self._filter_targets(targets)
        if not filtered:
            self._log("No targets after filtering")
            return {}
        ordered = list(self._strategy_cls(filtered))

        if async_mode:
            asyncio.run(self._async_scan(ordered))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as ex:
                fut_to_host = {ex.submit(self._probe_host, h): h for h in ordered}
                for fut in concurrent.futures.as_completed(fut_to_host):
                    host = fut_to_host[fut]
                    try:
                        self._results[host] = fut.result()
                    except Exception as e:
                        self._results[host] = {"error": str(e)}
                    self._log(
                        "RESULT", host,
                        "success" if self._is_success(self._results[host]) else "fail"
                    )

        self._log(
            f"Scan finished: {len(self._results)} scanned, "
            f"{len(self._skipped)} skipped, "
            f"{len(self.successful_routes())} successful"
        )
        return self._results

    # ════════════════════════════════════════════════════════════════════════
    # 10) Misc helpers (filtering, route saving)                             ║
    # ════════════════════════════════════════════════════════════════════════
    @staticmethod
    def _iter_targets(hosts, cidrs):
        for h in hosts:
            yield h
        for c in cidrs:
            for ip in ipaddress.ip_network(c, strict=False):
                yield str(ip)

    def _filter_targets(self, targets):
        allowed, seen = [], set()
        for t in targets:
            if t in seen:
                continue
            seen.add(t)
            if self._allowed(t, self._nets, self._ips):
                allowed.append(t)
            else:
                self._skipped.append(t)
        return allowed

    # *** success now includes inferred SMB channels ***
    def _is_success(self, res):
        # explicit open 445/139
        for p in (445, 139):
            if res.get("ports", {}).get(p, {}).get("state") == "open":
                return True
        return res.get("smb_inferred", False)

    def successful_routes(self):
        s, ts = [], datetime.now(timezone.utc).isoformat()
        for host, r in self._results.items():
            if not self._is_success(r):
                continue
            # pick any port that is open *or* inferred
            chosen_port = 445
            for p in (445, 139):
                if r["ports"].get(p, {}).get("state") == "open":
                    chosen_port = p; break
            host_f = "0.0.0.0/0" if ipaddress.ip_address(host).version == 4 else "::/0"
            rid = f"{host_f}:{chosen_port}"
            s.append({"id": rid, "host": host_f, "port": chosen_port,
                      "details": r, "ts": ts})
        return s

    def save_routes(self, path):
        if not path:
            return
        path = os.path.abspath(path)
        new = self.successful_routes()
        if not new:
            return
        old = self.load_routes(path) or []
        mp = {r["id"]: r for r in old}
        for r in new:
            mp[r["id"]] = r
        with open(path, "w") as f:
            json.dump(list(mp.values()), f, indent=2)
        self._log(f"Saved {len(new)} routes to {path}")

    @staticmethod
    def load_routes(path):
        if not path:
            return None
        path = os.path.abspath(path)
        if os.path.isfile(path):
            with suppress(Exception):
                with open(path) as f:
                    return json.load(f)
        return None


# ─── CLI wrapper (unchanged) ────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", nargs="*", help="IP addresses")
    ap.add_argument("--cidrs", nargs="*", help="CIDRs")
    ap.add_argument("--allowlist", help="JSON file with allow rules")
    ap.add_argument("--output", help="Save successful routes")
    ap.add_argument("--timeout", type=int, default=2)
    ap.add_argument("--workers", type=int, default=100)
    ap.add_argument("--no-nmap", action="store_true")
    ap.add_argument("--no-smb-verify", action="store_true")
    ap.add_argument("--no-smb-fuzz", dest="no_smb_fuzz", action="store_true")
    ap.add_argument("--async", dest="async_mode", action="store_true")
    args = ap.parse_args()

    scanner = PublicIPFirewallSMB(
        allowlist=args.allowlist,
        timeout=args.timeout,
        workers=args.workers,
        use_nmap=not args.no_nmap,
        smb_verify=not args.no_smb_verify,
        smb_fuzz=not args.no_smb_fuzz,
    )
    res = scanner.scan(
        hosts=args.hosts,
        cidrs=args.cidrs,
        async_mode=args.async_mode,
    )
    if args.output:
        scanner.save_routes(args.output)
    print(json.dumps(res, indent=2))