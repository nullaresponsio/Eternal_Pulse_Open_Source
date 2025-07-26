# Currently on 5.1

# I'm working to modularize this for schema reliability inside a module and modular improvements capability; it's coming soon!

# EternalPulse Scanner 5.1

> Enhanced network reconnaissance with evasion, fuzzing, DPI, vulnerability correlation, and simulated C2/backdoor activity.

```bash
# Quick demo (authorized lab host only)
sudo ./scanner_v5_1.py twitch.tv --stealth 4 --intensity 5 --fuzz

⚠️ Legal & Safety

Use only on systems you own or are explicitly authorized to test. You are responsible for complying with all laws, policies, and contracts. Prefer isolated lab ranges such as Twitch

⸻

Features
	•	Dynamic results saving with auto-naming
	•	Genetic protocol fuzzing with intensity scaling
	•	Evasion technique tracking and adaptive patterns
	•	Protocol-aware deep packet inspection and fingerprinting
	•	Vulnerability correlation (SMB/RDP/TLS/SSH/HTTP hints)
	•	DNS reconnaissance and (simulated) zone-transfer check
	•	Simulation of backdoor install + C2 beaconing (no real implant)
	•	Parallel scanning with progress/debug timer
	•	Reports: JSON, HTML, or text

⸻

Requirements
	•	Python 3.9+ (3.10+ recommended)
	•	Linux/macOS (root/sudo recommended when raw packets/evasion are used)

Optional dependencies (auto-enabled if available)
	•	scapy — packet crafting/evasion/DNS helpers
	•	smbprotocol — richer SMB handling
	•	nmap — auxiliary integration hook
	•	cryptography — crypto for stealth/C2 simulation
	•	dnspython — DNS queries

Install

python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install scapy smbprotocol cryptography dnspython python-nmap

Omit packages you don’t need. The scanner runs with stdlib only, but reduced capabilities.

⸻

Usage

python3 scanner_v5_1.py [-h] [-o OUTPUT] [-f {json,html,text}] [-t TIMEOUT]
                        [-w WORKERS] [-s {1,2,3,4}] [-i {1,2,3,4,5}]
                        [--no-evasion] [--no-vuln] [--backdoor] [--fuzz]
                        targets [targets ...]

Positional
	•	targets — Hosts, FQDNs, or CIDRs (e.g., 127.0.0.1, 192.0.2.0/28, lab.example)

Flags
	•	-o, --output Path to save report
	•	-f, --format Report format: json (default), html, text
	•	-t, --timeout Per-connection timeout (s), default 3.0
	•	-w, --workers Parallel workers, default 50
	•	-s, --stealth Stealth level 1..4 (1 = verbose, 4 = silent)
	•	-i, --intensity Scan/fuzz intensity 1..5 (1 = light, 5 = comprehensive)
	•	--no-evasion Disable evasion techniques
	•	--no-vuln Disable vulnerability correlation
	•	--backdoor Enable simulation of backdoor install+C2 beacons
	•	--fuzz Enable enhanced protocol fuzzing

Root privileges may be required for some evasion paths/packet crafting; otherwise the scanner uses standard sockets.

⸻

Examples (use authorized targets only)

1) Single host, comprehensive with fuzzing

sudo ./scanner_v5_1.py 192.0.2.10 --stealth 4 --intensity 5 --fuzz -o results.json -f json

2) CIDR range, default settings

sudo ./scanner_v5_1.py 192.0.2.0/28 -o report.html -f html

3) Multiple hosts, higher concurrency, HTML report

sudo ./scanner_v5_1.py 192.0.2.10 lab.example 198.51.100.5 -w 150 -o scan.html -f html

4) Disable evasion and vuln checks (quick probe)

python3 scanner_v5_1.py 127.0.0.1 --no-evasion --no-vuln -f text

5) Simulate backdoor + C2 beacons on open services (lab only)

sudo ./scanner_v5_1.py 192.0.2.10 --backdoor -o c2.json

The backdoor/C2 module is a simulation: it records synthetic install metadata and locally generated “beacon” events in the report; it does not plant a real implant.

⸻

How It Works (brief)
	•	Targeting: Expands CIDRs, randomizes order to reduce patterns.
	•	TCP/UDP Probes: Protocol-specific payloads; DPI for HTTP/SMB/RDP/TLS/SSH/DNS.
	•	Evasion: Traffic morphing, padding, fragmentation (when scapy present), TTL/source variations.
	•	Fuzzing: Genetic algorithm + grammar-aware generation; coverage/anomaly heuristics.
	•	Vuln Hints: Lightweight banner/signature checks for SMB (MS17-010/ZeroLogon indicators), RDP (BlueKeep heuristics), TLS (weak ciphers/versions), SSH, HTTP (known header/version flags).
	•	DNS Recon: Common record lookups; attempts AXFR where permitted.
	•	Reporting: Aggregates results, evasion metrics, fuzzing stats, simulated C2 activity.

⸻

Output

JSON

Machine-readable results, including:
	•	metadata (version, timings, evasion counters)
	•	results[host].ports with status+fingerprint
	•	vulnerabilities (heuristic indicators)
	•	fuzzing_results (counts, samples)
	•	backdoor_simulations (if enabled)

jq '.' results.json

HTML

Self-contained report with colorized risk cues and fuzz/C2 sections.

open scan.html  # macOS
xdg-open scan.html  # Linux

Text

Concise, greppable output.

⸻

Stealth & Intensity
	•	--stealth 1..4: Higher values add delays, increase obfuscation, and reduce verbosity.
	•	--intensity 1..5: Scales port lists, fuzz population, mutation rate, and generations.

Higher levels increase duration and network traffic. Tune for your lab’s limits.

⸻

Dependencies & Capabilities Matrix

Capability	Requires	Without It
Packet crafting/fragmentation	scapy	Falls back to socket-level probes
SMB session features	smbprotocol	Basic SMB signatures only
TLS crypto stealth/C2 GCM	cryptography	Crypto-based obfuscation disabled
DNS queries	dnspython	Minimal DNS payloads only
Nmap hooks	python-nmap	Not used


⸻

Troubleshooting
	•	PermissionError / raw sockets: Use sudo or reduce stealth features (--no-evasion).
	•	Timeouts: Increase -t, lower -w, or reduce --intensity.
	•	No results in HTML: Ensure you ran with -o <file> -f html.
	•	Overzealous IPS/IDS: Lower --intensity, use --stealth 3, or disable evasion in sensitive networks (with written permission).

⸻

Development
	•	Entry point: scanner_v5_1.py (EternalPulseScanner)
	•	Key modules: evasion engine, genetic fuzzer, vulnerability hints, DNS recon, report generators
	•	Version: 5.1

⸻

License

Specify an appropriate license before distribution.

