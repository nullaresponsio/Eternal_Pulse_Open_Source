
# Scapy is a Python packet toolkit that crafts/sends/receives packets at L2/L3/L4. With elevated privileges (e.g., sudo on Linux/macOS or capabilities like CAP_NET_RAW), it opens raw sockets and can inject/observe packets directly, enabling custom flags/options, unusual fragmentation, and protocol experiments. Without raw-socket privileges, Scapy cannot send/receive raw packets; in this scanner, fragmented SYN probes are automatically skipped in that case and normal TCP connect-scans are used instead.
⸻
Overview
This tool resolves hostnames to IPv4 addresses concurrently, then scans configurable TCP and UDP ports. TCP state is derived from a standard TCP connect scan (portable, no raw packets required). Optionally, when Scapy is available and raw sockets are permitted, the tool fires a best-effort fragmented SYN probe on selected SMB-adjacent ports (135/139/445) without affecting the authoritative connect-scan result. Output summarizes per-host states and a simple SMB inference.
Key guarantees: • No port result is ever reported as error. • Scapy presence/privilege issues never break scans; raw probes are skipped with a concise debug note. • DNS and scanning run concurrently with configurable worker count and timeouts.
⸻
Installation
python3 -m venv .venv && . .venv/bin/activate pip install --upgrade pip pip install scapy
Scapy is optional. Fragmented SYN probes require raw-socket privileges.
⸻
Usage
Basic connect scan (no raw packets)
python3 scanner.py mass.gov nsa.gov google.com
With 50 workers and optional fragmented probes if privileged
sudo -E python3 scanner.py -w 50 -p 80,135,139,443,445 -U 137,138 --fragmented mass.gov nsa.gov google.com
Targets from file (one per line)
python3 scanner.py -f targets.txt
Options: • -w/--workers number of threads (default: 50) • -p/--ports TCP ports (default: 80,135,139,443,445) • -U/--udp-ports UDP ports (default: 137,138) • -t/--timeout socket timeout seconds (default: 2.0) • --fragmented attempt fragmented SYN on 135,139,445 when Scapy+raw are available
⸻
Output • TCP states: open, closed, filtered • UDP states: conservative open|filtered • SMB Inferred: True if TCP/139 or TCP/445 is open • Fragmented probe notes appear only as debug lines; they do not change TCP results.
Example:
[DNS] Resolving 3 hostnames with 50 workers [DNS] mass.gov -> 13.248.160.110, 76.223.33.104 [DNS] nsa.gov -> 23.196.144.211 [DNS] google.com -> 142.250.81.238 [DNS] Total targets after resolution: 4 [DBG] fragmented probe skipped (no raw socket): 13.248.160.110:135 ... [SCAN] Completed: 4 hosts in 2.18s
⸻
Notes • IPv4 only; add IPv6 if needed later. • Fragmented probes are best-effort and informational only. • Use only on networks/hosts you are authorized to test.


