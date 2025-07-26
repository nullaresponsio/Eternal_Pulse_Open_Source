provide the fully updated scanner.py file; fix all sample errors here in all ways: [DNS] Resolving 3 hostnames with 50 workers
[DNS] mass.gov -> 13.248.160.110, 76.223.33.104
[DNS] nsa.gov -> 23.196.144.211
[DNS] google.com -> 142.250.81.238
[DNS] Total targets after resolution: 4
[DBG] fragmented scan error: 23.196.144.211 135 name 'send' is not defined
[DBG] fragmented scan error: 76.223.33.104 135 name 'send' is not defined
[DBG] fragmented scan error: 13.248.160.110 135 name 'send' is not defined
[DBG] fragmented scan error: 142.250.81.238 135 name 'send' is not defined
[DBG] fragmented scan error: 13.248.160.110 445 name 'send' is not defined
[DBG] fragmented scan error: 76.223.33.104 445 name 'send' is not defined
[DBG] fragmented scan error: 142.250.81.238 445 name 'send' is not defined
[DBG] fragmented scan error: 23.196.144.211 445 name 'send' is not defined
[DBG] fragmented scan error: 76.223.33.104 139 name 'send' is not defined
[DBG] fragmented scan error: 13.248.160.110 139 name 'send' is not defined
[DBG] fragmented scan error: 142.250.81.238 139 name 'send' is not defined
[DBG] RESULT 13.248.160.110 fail
[DBG] RESULT 76.223.33.104 fail
[DBG] RESULT 142.250.81.238 fail
[DBG] fragmented scan error: 23.196.144.211 139 name 'send' is not defined
[DBG] RESULT 23.196.144.211 fail
[DBG] Scan finished: 4 scanned, 0 skipped, 0 successful

Host: 13.248.160.110 (mass.gov)
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

Host: 76.223.33.104 (mass.gov)
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

Host: 142.250.81.238 (google.com)
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
[SCAN] Completed: 4 hosts, 0 successful, 0 skipped: 