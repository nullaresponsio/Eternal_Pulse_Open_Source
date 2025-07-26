#!/usr/bin/env python3
# __main__.py
"""
Concurrent DNS/URL metadata collector (safe).
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import socket
import sys
import threading
import time
from urllib.parse import urlparse

import http.client
import ssl


def parse_targets(path):
    t = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            t.append(s)
    return t


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_host(host, timeout):
    fams = [socket.AF_INET, socket.AF_INET6]
    out_ips, rdns = [], {}
    for fam in fams:
        try:
            infos = socket.getaddrinfo(host, None, family=fam)
        except Exception:
            continue
        for ai in infos:
            ip = ai[4][0]
            if ip not in out_ips:
                out_ips.append(ip)
    for ip in out_ips:
        try:
            socket.setdefaulttimeout(timeout)
            hn, aliases, _ = socket.gethostbyaddr(ip)
            rdns[ip] = {"hostname": hn, "aliases": aliases}
        except Exception:
            rdns[ip] = None
    return out_ips, rdns


def http_probe(url, timeout, allow_redirects=False):
    u = urlparse(url)
    scheme = (u.scheme or "").lower()
    host = u.hostname
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    res = {
        "url": url,
        "request": {"method": "HEAD", "host": host, "port": port, "path": path, "scheme": scheme},
        "timing_ms": {},
    }
    t0 = time.time()
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=ctx)
        elif scheme == "http":
            conn = http.client.HTTPConnection(host, port=port, timeout=timeout)
        else:
            res["error"] = "unsupported scheme"
            return res
        t1 = time.time()
        conn.request("HEAD", path, headers={"User-Agent": "safe-meta/1.0"})
        r = conn.getresponse()
        t2 = time.time()
        if r.status == 405:
            conn.close()
            if scheme == "https":
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port=port, timeout=timeout)
            conn.request("GET", path, headers={"Range": "bytes=0-0", "User-Agent": "safe-meta/1.0"})
            r = conn.getresponse()
            t2 = time.time()
            res["request"]["method"] = "GET(range)"
        res["status"] = int(r.status)
        res["reason"] = r.reason
        res["headers"] = {k: v for k, v in r.getheaders()}
        body_read = False
        if allow_redirects and r.status in (301, 302, 303, 307, 308) and "Location" in res["headers"]:
            res["redirect_to"] = res["headers"]["Location"]
        if scheme == "https":
            sock = conn.sock
            cert = sock.getpeercert()
            res["tls"] = {
                "version": sock.version(),
                "cipher": sock.cipher(),
                "peercert": cert,
            }
        if not body_read:
            try:
                r.read(0)
            except Exception:
                pass
        conn.close()
        t3 = time.time()
        res["timing_ms"] = {
            "connect": int((t1 - t0) * 1000),
            "first_byte": int((t2 - t1) * 1000),
            "total": int((t3 - t0) * 1000),
        }
        return res
    except Exception as e:
        res["error"] = str(e)
        res["timing_ms"]["total"] = int((time.time() - t0) * 1000)
        return res


def process_target(target, timeout, http_for_plain, debug):
    entry = {"target": target, "resolved": {}, "urls": []}
    parsed = urlparse(target)
    is_url = bool(parsed.scheme and parsed.hostname)
    host = parsed.hostname if is_url else target
    try:
        ips, rdns = resolve_host(host, timeout)
    except Exception as e:
        ips, rdns = [], {}
        if debug:
            print(f"[ERR] DNS {host}: {e}", file=sys.stderr, flush=True)
    entry["resolved"]["host"] = host
    entry["resolved"]["ips"] = ips
    entry["resolved"]["rdns"] = rdns
    for ip in ips:
        print(f"[RESOLVE] {host} -> {ip}{'' if rdns.get(ip) is None else f' (rdns={rdns[ip]['hostname']})'}", file=sys.stderr, flush=True)
    urls = []
    if is_url:
        urls = [target]
    elif http_for_plain:
        urls = [f"https://{host}/", f"http://{host}/"]
    for u in urls:
        r = http_probe(u, timeout=timeout)
        entry["urls"].append(r)
        if debug:
            st = r.get("status")
            tls = r.get("tls", {})
            v = (tls.get("version") or "", tls.get("cipher") or "")
            print(f"[HTTP] {u} status={st} tls={v}", file=sys.stderr, flush=True)
    return entry


def atomic_write_json(path, data):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--input", required=True)
    ap.add_argument("--save")
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--http-probe", action="store_true")
    ap.add_argument("--ndjson", action="store_true")
    args = ap.parse_args()

    targets = parse_targets(args.input)
    if not targets:
        print("[ERROR] no targets", file=sys.stderr)
        sys.exit(1)

    results = {}
    lock = threading.Lock()
    out_f = None
    if args.save and args.ndjson:
        out_f = open(args.save, "a", encoding="utf-8")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {
                ex.submit(process_target, t, args.timeout, args.http_probe, not args.quiet): t
                for t in targets
            }
            for fut in concurrent.futures.as_completed(futs):
                t = futs[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"target": t, "error": str(e)}
                if args.json:
                    print(json.dumps(res, separators=(",", ":")), flush=True)
                if args.save:
                    with lock:
                        if args.ndjson:
                            out_f.write(json.dumps(res) + "\n")
                            out_f.flush()
                        else:
                            results[t] = res
                            atomic_write_json(args.save, results)
    finally:
        if out_f:
            out_f.close()

    if args.save and not args.ndjson:
        atomic_write_json(args.save, results)


if __name__ == "__main__":
    main()