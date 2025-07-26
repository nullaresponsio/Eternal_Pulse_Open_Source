provide full scanner.py file; enhance capabilities in all possible ways at once; think creatively and do as great a job as you can: 
Host: 23.196.144.211 (nsa.gov)
  NBNS: negative
  SMB Inferred: False
  Ports:
    80/tcp: open - SMB: negative
    135/tcp: error - SMB: negative
    137/udp: open|filtered
    138/udp: open|filtered
    139/tcp: error - SMB: negative
    443/tcp: open - SMB: negative
    445/tcp: error - SMB: negative
[SCAN] Completed: 4 hosts, 0 successful, 0 skipped
[+] Results saved to /Users/bo/Library/Mobile Documents/com~apple~CloudDocs/Github_ G9P349L6NF/Eternal_Pulse_Open_Source2/results_nsa.json
[DBG] Sleeping 600s before next pass
^C[!] Interrupted. Exiting.
bo@Mac Eternal_Pulse_Open_Source2 % mv README.md Eternal_Pulse_README.md
bo@Mac Eternal_Pulse_Open_Source2 % code README.md
bo@Mac Eternal_Pulse_Open_Source2 % code SCAPY_README.md
bo@Mac Eternal_Pulse_Open_Source2 % mv README.md Checkpoint_scanner_README.md
bo@Mac Eternal_Pulse_Open_Source2 % code README.md
bo@Mac Eternal_Pulse_Open_Source2 % clear
bo@Mac Eternal_Pulse_Open_Source2 % sh run_mini.sh                      
Password:
[DNS] Resolving 3 hostnames with 50 workers
[DNS] mass.gov -> 76.223.33.104, 13.248.160.110
[DNS] google.com -> 142.251.40.142
[DNS] nsa.gov -> 23.221.109.153
[DNS] Total targets after resolution: 4
[DBG] SMB fragmented negotiate error: 13.248.160.110 443 timed out
[DBG] SMB fragmented negotiate error: 76.223.33.104 443 timed out
[DBG] SMB fragmented negotiate error: 142.251.40.142 443 timed out
[DBG] SMB session corruption error: 142.251.40.142 443 [Errno 32] Broken pipe
[DBG] SMB fragmented negotiate error: 23.221.109.153 443 timed out
[DBG] HTTP SMB tunnel error: 142.251.40.142 443 [Errno 54] Connection reset by peer
[DBG] SMB session corruption error: 23.221.109.153 443 [Errno 54] Connection reset by peer
[DBG] HTTP SMB tunnel error: 23.221.109.153 443 [Errno 54] Connection reset by peer
[DBG] SMB fragmented negotiate error: 13.248.160.110 80 timed out
[DBG] SMB fragmented negotiate error: 76.223.33.104 80 timed out
[DBG] SMB fragmented negotiate error: 142.251.40.142 80 timed out
[DBG] SMB fragmented negotiate error: 23.221.109.153 80 timed out
[DBG] SMB session corruption error: 23.221.109.153 80 timed out
[DBG] Scanned 13.248.160.110: SMB=False
[DBG] Scanned 76.223.33.104: SMB=False
[DBG] Scanned 142.251.40.142: SMB=False
[DBG] Scanned 23.221.109.153: SMB=False

Host: 13.248.160.110 (mass.gov)
  SMB Inferred: False
  Ports:
    80/tcp: open - SMB: negative
    135/tcp: filtered - SMB: negative
    137/udp: open|filtered
    138/udp: open|filtered
    139/tcp: filtered - SMB: negative
    443/tcp: open - SMB: negative
    445/tcp: filtered - SMB: negative

Host: 76.223.33.104 (mass.gov)
  SMB Inferred: False
  Ports:
    80/tcp: open - SMB: negative
    135/tcp: filtered - SMB: negative
    137/udp: open|filtered
    138/udp: open|filtered
    139/tcp: filtered - SMB: negative
    443/tcp: open - SMB: negative
    445/tcp: filtered - SMB: negative

Host: 142.251.40.142 (google.com)
  SMB Inferred: False
  Ports:
    80/tcp: open - SMB: negative
    135/tcp: filtered - SMB: negative
    137/udp: open|filtered
    138/udp: open|filtered
    139/tcp: filtered - SMB: negative
    443/tcp: open - SMB: negative
    445/tcp: filtered - SMB: negative

Host: 23.221.109.153 (nsa.gov)
  SMB Inferred: False
  Ports:
    80/tcp: open - SMB: negative
    135/tcp: filtered - SMB: negative
    137/udp: open|filtered
    138/udp: open|filtered
    139/tcp: filtered - SMB: negative
    443/tcp: open - SMB: negative
    445/tcp: filtered - SMB: negative
[SCAN] Completed: 4 hosts, 0 successful, 0 skipped
[+] Results saved to /Users/bo/Library/Mobile Documents/com~apple~CloudDocs/Github_ G9P349L6NF/Eternal_Pulse_Open_Source2/results_nsa.json
[DBG] Sleeping 600s before next pass 