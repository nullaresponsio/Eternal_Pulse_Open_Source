Below is a deep‑dive reference on the Server Message Block (SMB) protocol and the many paths from an exposed TCP 445 port to full remote‑code execution (RCE).  Citations appear after each paragraph.

1. SMB in a nutshell
SMB is the file‑, printer‑ and named‑pipe‑sharing protocol built into every supported edition of Windows and implemented by Samba on Linux/macOS.  Modern Windows ships SMB 3.1.1, which extends the original 1980s dialect with encryption (AES‑GCM/CCM), pre‑authentication integrity (SHA‑512), and multichannel I/O, but it still begins every session with a dialect‑negotiation handshake, then NTLM or Kerberos authentication, followed by tree‑connects and individual file or pipe transactions. 
Because those first packets must be accepted before the server knows whether a client is trusted, logic errors in the parser, weak authentication settings, or simple misconfiguration can all lead to unauthenticated RCE.

2. Why attackers love SMB
Reachability: Shodan indexes ~100 k hosts that expose 445/TCP to the Internet every day.


Privileges: The service runs in kernel‑space (srv.sys) on Windows and often as root in Samba.


Functionality abuse: SMB lets a user write a file and immediately launch it (e.g., via the Service Control Manager), providing an easy write‑then‑exec primitive.


Legacy baggage: Many organisations keep SMB 1 enabled for legacy devices. That dialect has no signing, no encryption and multiple memory‑corruption bugs.



3. Classes of remote‑execution vulnerabilities
3.1 Memory‑corruption bugs in the Windows SMB kernel drivers
Vuln / CVE
Dialect
Bug class
Practical impact
EternalBlue – CVE‑2017‑0144 / MS17‑010
SMB 1
Pool‑overflow in Srv!SrvOs2FeaToNt
Unauthenticated kernel‑RCE, weaponised by WannaCry
SMBGhost – CVE‑2020‑0796
SMB 3.1.1 compression
Integer‑overflow → heap overflow
Wormable RCE on Win 10/Server 2019
SMBleed – CVE‑2020‑1206
SMB 3 compression
Info‑leak + heap corruption
Bypass ASLR / used with SMBGhost for reliable RCE

The common pattern is a packet‑length mis‑calculation that reaches kernel mode before authentication.  A single malformed TRANS2 or compressed read can corrupt adjacent structures and land the instruction pointer on attacker‑controlled data.
3.2 Logic‑layer flaws & downgrade risks
SMB signing disabled or “if client agrees”. Without mandatory signing, a man‑in‑the‑middle can flip payload bits or relay NTLM challenges.  Pen‑test reports still flag this as SMB Signing Not Required (CVE‑2016‑2115 for Samba). 


Protocol downgrade to SMB 1. Many IDS signatures only look for SMB 2/3.  Disabling SMB 1 entirely removes a whole class of memory‑safety bugs. 


3.3 NTLM Relay / SMB Relay
An adversary who intercepts a victim’s NTLM handshake can replay it to another host that has SMB signing disabled, gaining the victim’s privileges without ever cracking a password.  This “classic” SMB Relay still appears in real‑world incident reports. 
3.4 Writable‑share RCE in Samba
If an attacker can write and ask the server to load a shared library from that location, the result is root‑level RCE:
Vuln
Trigger
Notes
CVE‑2017‑7494 – “SambaCry”
Upload .so to writable share, call nttrans to load
Affects Samba 3.5.0‑4.6.4
CVE‑2021‑44142
Malicious extended attributes when vfs_fruit is enabled
Heap OOB ‑> root on NAS devices

3.5 Living‑off‑the‑land service creation
Tools like PsExec, sc.exe or wmic PROCESS CALL CREATE copy an EXE over an admin share (\\ADMIN$) and create a temporary Windows service—exactly MITRE ATT&CK T1021.002 + T1569.002.  No kernel bugs needed; only a stolen admin hash. 

4. “Eternal Pulse” framework in context
The paper you supplied describes a six‑phase tool chain that stitches all of the above into one workflow:
Phase
What it does
Security‑relevance
1. Discovery
50 k probes/s via raw SYN, UDP NetBIOS & mDNS
Detects SMB even behind load balancers
2. Enumeration
NSS, JARM, ATT&CK mapping
Quickly spots hosts missing MS17‑010 patch
3. Path modelling
Genetic / MCTS schedulers
Prioritises the easiest RCE (e.g., CVE‑2020‑0796)
4. Safety gates
Ed25519‑signed packets, dry‑run mode
Lets red‑teams stay legal & auditable
5. Implantation
Uses only SMB TRANS2 write calls for cross‑platform backdoor
Avoids noisy RPC or WinRM channels
6. Reporting
ND‑JSON + SARIF + Prometheus exporter
Blue teams get evidence & metrics

Technically the implant never exploits a memory bug; it relies on credentials or writable shares plus the legitimate SMB file‑write API to drop an AES‑encrypted agent, achieving persistence via startup folders, /etc/rc.local, or LaunchDaemons.

5. Detection & prevention checklist
Defence layer
Action
Patch management
Apply MS17‑010, KB4551762 (SMBGhost), KB4565511 (SMBleed), latest Samba 4.19+
Protocol hygiene
Remove SMB 1 (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol); require SMB signing on clients and servers via GPO
Network segmentation
Block inbound 445/TCP at the edge; limit lateral movement with host firewalls
Credential protection
Disable NTLM where possible; enforce channel‑binding; monitor for NTLM SSP events 4624/4625
Share hardening
No Everyone:Full Control on any share; for Samba set map to guest = never and smb encrypt = required
Intrusion detection
Signature for Trans2Secondary + large NTRename packet (EternalBlue) and compressed SMB2_WRITE with len < 4 (SMBGhost)
Audit & logging
Enable SMB client/server audit category; forward events 3000‑3015 and kernel ETW Microsoft-Windows-SMBServer


6. Safe demonstration snippet
Below is a non‑exploit Python example that enumerates shares and tests for mandatory signing.  All stock Impacket code is shown with minimal comments, per your formatting request.
#!/usr/bin/env python3
from impacket.smbconnection import SMBConnection
import sys

def enum_shares(target, user='', passwd='', domain='', lmhash='', nthash=''):
    conn = SMBConnection(target, target, sess_port=445)
    conn.login(user, passwd, domain, lmhash, nthash)
    for share in conn.listShares():
        flags = "SIGNED" if conn.isSigningRequired() else "UNSIGNED"
        print(f"[{flags}] {share['shi1_netname']}")
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: smb_enum.py <ip> [user] [pass]")
        sys.exit(1)
    enum_shares(*sys.argv[1:3])
Running it against a patched server should print [SIGNED] IPC$, [SIGNED] C$, etc.  An [UNSIGNED] line is your red‑flag for relay or tampering attacks.  (Impacket is BSD‑licensed; no lines were removed.)

7. Key take‑aways for defenders
Patch or perish: EternalBlue‑class bugs will remain wormable as long as SMB 1 exists on any segment.


Signing everywhere: Requiring SMB signing kills relay attacks and opportunistic tampering with minimal overhead on ≤1 Gb links.


Principle of least privilege: Guest/anonymous access and writable shares are still the #1 Samba RCE vector.


Monitor, then block: Telemetry from SMB audit logs plus ETW feeds is cheap and catches both exploit traffic and living‑off‑the‑land PsExec use.


Assume lateral movement: Even if 445 isn’t Internet‑facing, every workstation can still be a stepping stone; treat internal SMB the same way you treat RDP.


Applying those five points will neutralise both boutique frameworks like Eternal Pulse and the decade‑old exploits still roaming corporate networks today.

