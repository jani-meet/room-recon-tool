#!/usr/bin/env python3
"""
ROOM - Recon. Observe. Operate. Map.
AI-style guided network recon — 100% free, no API, works offline.
Only use on systems you own or have explicit permission to test.
"""

import subprocess
import sys
import socket
import argparse
import re
import os
from datetime import datetime

# ── Colors ────────────────────────────────────────────────────────────────────
R   = "\033[1;31m"
G   = "\033[1;32m"
Y   = "\033[1;33m"
B   = "\033[1;34m"
C   = "\033[1;36m"
M   = "\033[1;35m"
W   = "\033[1;37m"
DIM = "\033[2m"
RST = "\033[0m"

BANNER = f"""{C}
  ██████╗  ██████╗  ██████╗ ███╗   ███╗
  ██╔══██╗██╔═══██╗██╔═══██╗████╗ ████║
  ██████╔╝██║   ██║██║   ██║██╔████╔██║
  ██╔══██╗██║   ██║██║   ██║██║╚██╔╝██║
  ██║  ██║╚██████╔╝╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝
{RST}{W}  Recon. Observe. Operate. Map.{RST}
{DIM}  Guided Network Recon Tool v2.0 — 100% Free & Offline{RST}
{B}  ─────────────────────────────────────────────────────{RST}
"""

HELP_SCREEN = f"""
{BANNER}
{W}USAGE:{RST}
  python3 room.py <target> [options]
  python3 room.py --install
  python3 room.py --help

{W}TARGET:{RST}
  Any hostname or IP address you have permission to scan.
  {DIM}Examples:  192.168.1.1    10.0.0.5    scanme.nmap.org{RST}

{W}OPTIONS:{RST}
  {C}--mode {Y}<quick|full|all>{RST}   Scan depth  {DIM}(default: quick){RST}
  {C}--install{RST}               Check & install all tools
  {C}--help{RST}                  Show this screen

{W}SCAN MODES:{RST}
  {G}quick{RST}   Top 1000 ports + service detection + guided analysis   {DIM}~1 min{RST}
  {Y}full{RST}    All 65535 ports + guided analysis + HTTP headers        {DIM}~6 min{RST}
  {R}all{RST}     Full + OS detection + NSE vuln scripts + full report    {DIM}~12 min{RST}

{W}EXAMPLES:{RST}
  {DIM}# Quick scan — nmap's public legal test server{RST}
  {C}python3 room.py scanme.nmap.org{RST}

  {DIM}# Full port scan on your own machine{RST}
  {C}python3 room.py 192.168.1.1 --mode full{RST}

  {DIM}# Complete recon on a lab target{RST}
  {C}python3 room.py 10.0.0.5 --mode all{RST}

{W}WHAT ROOM DOES:{RST}
  {G}✓{RST} Scans all ports — no nmap flags to memorise
  {G}✓{RST} Rates every finding: {R}CRITICAL{RST} / {Y}HIGH{RST} / {C}MEDIUM{RST} / {G}LOW{RST}
  {G}✓{RST} Gives exact commands to investigate every open port
  {G}✓{RST} Explains what each service is and why it matters
  {G}✓{RST} Checks HTTP security headers automatically
  {G}✓{RST} Prioritises findings — tells you where to start
  {G}✓{RST} 100% free — no API keys, no internet needed for analysis
  {G}✓{RST} Works on Kali Linux, Parrot OS, Ubuntu, macOS

{W}INSTALL DEPENDENCIES:{RST}
  {C}python3 room.py --install{RST}

{B}  ─────────────────────────────────────────────────────{RST}
{DIM}  Legal: Only scan systems you own or have written permission to test.{RST}
"""

# ─────────────────────────────────────────────────────────────────────────────
#  BUILT-IN KNOWLEDGE BASE
#  Severity: 4=CRITICAL  3=HIGH  2=MEDIUM  1=LOW  0=INFO
# ─────────────────────────────────────────────────────────────────────────────
KB = {
    21: {
        "name": "FTP",
        "severity": 3,
        "what": "File Transfer Protocol — transfers files between client and server.",
        "why": "Often allows anonymous login. Credentials and data sent in plaintext. Outdated versions have known RCE vulnerabilities.",
        "cves": ["CVE-2011-2523 (vsftpd backdoor)", "CVE-2010-4221 (ProFTPD RCE)"],
        "commands": [
            "nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor {t}",
            "ftp {t}                         # try: anonymous / anonymous@",
            "nc {t} 21                        # grab banner manually",
            "nmap -p21 --script ftp-brute --script-args userdb=users.txt,passdb=pass.txt {t}",
        ],
        "look_for": [
            "Anonymous login allowed — means anyone can read/write files",
            "Banner reveals software version — search it for CVEs",
            "Writable directories — can be used to plant files",
            "vsftpd 2.3.4 specifically — has a known backdoor on port 6200",
        ],
    },
    22: {
        "name": "SSH",
        "severity": 2,
        "what": "Secure Shell — encrypted remote terminal access.",
        "why": "Weak passwords or old OpenSSH versions can be brute-forced or exploited. Key-based auth misconfiguration is common.",
        "cves": ["CVE-2023-38408 (OpenSSH agent RCE)", "CVE-2016-6515 (DoS)"],
        "commands": [
            "nmap -p22 --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey {t}",
            "ssh -v {t}                       # check version and supported auth",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{t}",
            "nmap -p22 --script ssh-brute --script-args userdb=users.txt {t}",
        ],
        "look_for": [
            "Password authentication enabled (vs keys-only) — brute-force risk",
            "OpenSSH version < 8.0 — check for known CVEs",
            "Weak ciphers: arcfour, 3des-cbc, blowfish-cbc",
            "Root login permitted — critical misconfiguration",
        ],
    },
    23: {
        "name": "Telnet",
        "severity": 4,
        "what": "Telnet — unencrypted remote terminal. Obsolete and dangerous.",
        "why": "Everything transmitted in cleartext — credentials, commands, data. Any attacker on the same network can intercept everything.",
        "cves": ["No specific CVE needed — the protocol itself is the vulnerability"],
        "commands": [
            "nc {t} 23                        # connect and grab banner",
            "nmap -p23 --script telnet-ntlm-info,telnet-encryption {t}",
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://{t}",
            "wireshark -i eth0 -f 'tcp port 23'  # capture cleartext session",
        ],
        "look_for": [
            "ANY open Telnet port — flag as CRITICAL immediately",
            "Login banner may reveal OS, hostname, or software version",
            "Default credentials: admin/admin, admin/password, root/root",
        ],
    },
    25: {
        "name": "SMTP",
        "severity": 2,
        "what": "Simple Mail Transfer Protocol — sends email between servers.",
        "why": "Open relays allow spam sending. User enumeration via VRFY/EXPN. Older versions have RCE vulnerabilities.",
        "cves": ["CVE-2020-7247 (OpenSMTPD RCE)", "CVE-2019-10149 (Exim RCE)"],
        "commands": [
            "nmap -p25 --script smtp-open-relay,smtp-enum-users,smtp-commands {t}",
            "nc {t} 25                        # connect: try EHLO, VRFY root, EXPN admin",
            "smtp-user-enum -M VRFY -U users.txt -t {t}",
            "nmap -p25 --script smtp-vuln-cve2010-4344 {t}",
        ],
        "look_for": [
            "Open relay — MAIL FROM / RCPT TO with external addresses accepted",
            "VRFY command enabled — can confirm valid usernames",
            "Server banner reveals Exim/Sendmail/Postfix version",
            "STARTTLS missing — credentials sent in plaintext",
        ],
    },
    53: {
        "name": "DNS",
        "severity": 2,
        "what": "Domain Name System — resolves hostnames to IP addresses.",
        "why": "Zone transfers can expose the entire internal hostname map. DNS amplification can be used for DDoS.",
        "cves": ["CVE-2020-1350 (Windows DNS SIGRed RCE)", "CVE-2008-1447 (Kaminsky)"],
        "commands": [
            "dig axfr @{t} <domain>           # attempt zone transfer",
            "nmap -p53 --script dns-zone-transfer,dns-recursion,dns-cache-snoop {t}",
            "dnsenum --dnsserver {t} <domain>",
            "dnsrecon -d <domain> -n {t} -t axfr",
        ],
        "look_for": [
            "Zone transfer succeeds — reveals all internal hostnames and IPs",
            "Recursive queries allowed from outside — DDoS amplification risk",
            "BIND version exposed in banner — search for CVEs",
            "Internal hostnames like dev., staging., vpn., admin. revealed",
        ],
    },
    80: {
        "name": "HTTP",
        "severity": 2,
        "what": "Hypertext Transfer Protocol — unencrypted web server.",
        "why": "Full web attack surface: SQLi, XSS, RFI, directory traversal, default creds, outdated CMS. No encryption means MITM is easy.",
        "cves": ["CVE-2021-41773 (Apache path traversal)", "CVE-2017-5638 (Struts RCE)"],
        "commands": [
            "nikto -h http://{t}              # automatic web vulnerability scan",
            "gobuster dir -u http://{t} -w /usr/share/wordlists/dirb/common.txt",
            "curl -I http://{t}               # check response headers",
            "nmap -p80 --script http-enum,http-headers,http-methods,http-title {t}",
            "whatweb http://{t}               # fingerprint CMS, frameworks, versions",
        ],
        "look_for": [
            "Server header reveals software + version (Apache 2.4.x, nginx 1.x)",
            "Missing security headers: X-Frame-Options, CSP, HSTS",
            "Admin panels: /admin /manager /phpmyadmin /wp-admin",
            "Directory listing enabled — can browse files directly",
            "Default credentials on login pages",
        ],
    },
    110: {
        "name": "POP3",
        "severity": 2,
        "what": "Post Office Protocol v3 — retrieves email from a mail server.",
        "why": "Transmits email and credentials in plaintext unless STARTTLS is used. Brute-force of email accounts possible.",
        "cves": ["CVE-2003-0028 (POP3 overflow)"],
        "commands": [
            "nc {t} 110                       # connect: USER admin  PASS password",
            "nmap -p110 --script pop3-capabilities,pop3-ntlm-info {t}",
            "hydra -l user@domain.com -P /usr/share/wordlists/rockyou.txt pop3://{t}",
        ],
        "look_for": [
            "STARTTLS not offered — credentials in cleartext",
            "Banner reveals server software and version",
            "Successful login with default or weak credentials",
        ],
    },
    111: {
        "name": "RPCBind",
        "severity": 3,
        "what": "RPC portmapper — maps RPC program numbers to network ports.",
        "why": "Exposes what RPC services are running (NFS, NIS, etc.). Often leads to NFS share enumeration and data theft.",
        "cves": ["CVE-2017-8779 (rpcbomb DoS)"],
        "commands": [
            "rpcinfo -p {t}                   # list all RPC services",
            "nmap -p111 --script rpcinfo {t}",
            "showmount -e {t}                 # check NFS exports",
            "nmap -p111 --script nfs-ls,nfs-showmount,nfs-statfs {t}",
        ],
        "look_for": [
            "NFS (port 2049) listed — check for world-readable exports",
            "NIS/YP services — can dump password hashes",
            "mountd listed — attempt to mount NFS shares",
        ],
    },
    135: {
        "name": "MSRPC",
        "severity": 3,
        "what": "Microsoft RPC endpoint mapper — Windows remote procedure calls.",
        "why": "Common Windows attack surface. Exposes WMI, DCOM, and other services. Several critical Windows RCE vulns use this.",
        "cves": ["CVE-2003-0352 (Blaster worm)", "MS03-026"],
        "commands": [
            "nmap -p135 --script msrpc-enum {t}",
            "rpcclient -U '' {t}              # null session attempt",
            "impacket-rpcdump @{t}            # dump RPC endpoints",
        ],
        "look_for": [
            "Null session accepted — anonymous enumeration possible",
            "DCOM enabled — potential lateral movement vector",
            "Windows version revealed in RPC response",
        ],
    },
    139: {
        "name": "NetBIOS",
        "severity": 3,
        "what": "NetBIOS session service — Windows file/print sharing over older protocol.",
        "why": "Null sessions can enumerate users, shares, and domains without credentials. Pairs with port 445 for SMB attacks.",
        "cves": ["MS08-067 (NetAPI RCE)"],
        "commands": [
            "nmap -p139 --script nbstat,smb-enum-shares,smb-enum-users {t}",
            "nmblookup -A {t}                 # NetBIOS name lookup",
            "enum4linux -a {t}                # full NetBIOS/SMB enumeration",
            "smbclient -L //{t} -N            # list shares anonymously",
        ],
        "look_for": [
            "Null session allowed — enumerate users, groups, shares, policies",
            "Workgroup / domain name revealed",
            "Computer name and OS version exposed",
        ],
    },
    143: {
        "name": "IMAP",
        "severity": 2,
        "what": "Internet Message Access Protocol — reads email directly on server.",
        "why": "Credentials often sent in plaintext. Brute-force of email accounts. May expose sensitive corporate email.",
        "cves": ["CVE-2021-38647 (Exchange RCE)"],
        "commands": [
            "nc {t} 143                       # connect: a1 LOGIN user pass",
            "nmap -p143 --script imap-capabilities,imap-ntlm-info {t}",
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://{t}",
        ],
        "look_for": [
            "STARTTLS not supported — plaintext credentials",
            "LOGIN capability enabled — direct username/password auth",
            "Server banner reveals Dovecot/Courier/Exchange version",
        ],
    },
    443: {
        "name": "HTTPS",
        "severity": 1,
        "what": "Encrypted web server over TLS/SSL.",
        "why": "Same web attack surface as HTTP but encrypted. Weak TLS configs (old ciphers, expired certs, Heartbleed) are common.",
        "cves": ["CVE-2014-0160 (Heartbleed)", "CVE-2014-3566 (POODLE)", "CVE-2021-41773"],
        "commands": [
            "nikto -h https://{t} -ssl       # web vulnerability scan",
            "nmap -p443 --script ssl-enum-ciphers,ssl-heartbleed,ssl-cert {t}",
            "openssl s_client -connect {t}:443  # check TLS version and cert",
            "gobuster dir -u https://{t} -w /usr/share/wordlists/dirb/common.txt",
            "testssl.sh {t}                  # full TLS security audit",
        ],
        "look_for": [
            "TLS 1.0 or 1.1 supported — outdated, vulnerable to POODLE/BEAST",
            "Self-signed or expired certificate",
            "Heartbleed vulnerable — leaks 64KB of server memory per request",
            "Weak ciphers: RC4, DES, NULL, EXPORT grade",
            "Missing HSTS header — allows SSL stripping",
        ],
    },
    445: {
        "name": "SMB",
        "severity": 4,
        "what": "Server Message Block — Windows file sharing and remote administration.",
        "why": "EternalBlue (WannaCry/NotPetya) exploits this port. Null sessions, pass-the-hash, and ransomware all target SMB.",
        "cves": ["CVE-2017-0144 (EternalBlue/WannaCry)", "CVE-2020-0796 (SMBGhost)", "CVE-2017-0145"],
        "commands": [
            "nmap -p445 --script smb-vuln-ms17-010,smb-vuln-ms10-054,smb-vuln-cve-2020-0796 {t}",
            "nmap -p445 --script smb-enum-shares,smb-enum-users,smb-security-mode {t}",
            "smbclient -L //{t} -N            # list shares (null session)",
            "enum4linux -a {t}                # full SMB enumeration",
            "crackmapexec smb {t}             # quick SMB fingerprint",
        ],
        "look_for": [
            "EternalBlue (MS17-010) vulnerable — immediate critical risk",
            "SMBGhost (CVE-2020-0796) vulnerable — Windows 10/2019",
            "Null session allowed — read shares without credentials",
            "SMBv1 enabled — insecure legacy protocol",
            "Readable shares: C$, ADMIN$, IPC$ accessible",
        ],
    },
    993: {
        "name": "IMAPS",
        "severity": 1,
        "what": "IMAP over SSL/TLS — encrypted email access.",
        "why": "Check TLS version and certificate validity. Brute-force still possible.",
        "cves": [],
        "commands": [
            "nmap -p993 --script ssl-enum-ciphers,imap-capabilities {t}",
            "openssl s_client -connect {t}:993",
            "hydra -l user -P /usr/share/wordlists/rockyou.txt imaps://{t}",
        ],
        "look_for": [
            "Weak TLS version or ciphers",
            "Certificate validity and expiry",
            "Dovecot/Exchange version in banner",
        ],
    },
    1433: {
        "name": "MSSQL",
        "severity": 4,
        "what": "Microsoft SQL Server — database server.",
        "why": "Internet-exposed MSSQL is almost always a critical risk. xp_cmdshell enables OS command execution from SQL queries.",
        "cves": ["CVE-2020-0618 (SSRS RCE)", "CVE-2019-1068"],
        "commands": [
            "nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config {t}",
            "nmap -p1433 --script ms-sql-brute --script-args userdb=users.txt {t}",
            "hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{t}",
            "impacket-mssqlclient sa@{t}      # connect with found credentials",
        ],
        "look_for": [
            "sa account with empty or default password — instant RCE via xp_cmdshell",
            "SQL Server version exposed — check for unpatched CVEs",
            "xp_cmdshell enabled — run OS commands directly from SQL",
            "Database names visible — look for sensitive data",
        ],
    },
    1521: {
        "name": "Oracle DB",
        "severity": 4,
        "what": "Oracle Database listener — enterprise database server.",
        "why": "Should never be internet-facing. TNS listener can be fingerprinted and abused. Default SIDs and creds are common.",
        "cves": ["CVE-2012-1675 (TNS Poison)", "CVE-2009-1979"],
        "commands": [
            "nmap -p1521 --script oracle-tns-version,oracle-sid-brute {t}",
            "tnscmd10g version -h {t}         # query TNS listener",
            "odat all -s {t} -p 1521         # full Oracle audit (odat tool)",
            "hydra -l system -P pass.txt oracle://{t}/ORCL",
        ],
        "look_for": [
            "Default SIDs: ORCL, XE, PROD, TEST — try each",
            "Default accounts: sys/change_on_install, system/manager, scott/tiger",
            "TNS listener version — older versions have known vulns",
        ],
    },
    2049: {
        "name": "NFS",
        "severity": 3,
        "what": "Network File System — remote file sharing (Linux/Unix).",
        "why": "World-readable NFS exports let anyone mount and read the filesystem. Misconfigured no_root_squash allows privilege escalation.",
        "cves": ["CVE-2019-3010"],
        "commands": [
            "showmount -e {t}                 # list exported shares",
            "nmap -p2049 --script nfs-showmount,nfs-ls,nfs-statfs {t}",
            "mkdir /tmp/nfsmount && mount -t nfs {t}:/ /tmp/nfsmount",
            "nmap -p2049 --script nfs-ls --script-args nfs-ls.time {t}",
        ],
        "look_for": [
            "Exports with * or 0.0.0.0 — world-accessible",
            "no_root_squash option — root on client = root on server",
            "Sensitive files in exported directories: /etc, /home, /root",
            "SSH keys readable — use to log in as that user",
        ],
    },
    3306: {
        "name": "MySQL",
        "severity": 4,
        "what": "MySQL database server.",
        "why": "Internet-exposed MySQL is a critical risk. Remote root login, empty passwords, and data dumping are common findings.",
        "cves": ["CVE-2012-2122 (auth bypass)", "CVE-2016-6662 (RCE)"],
        "commands": [
            "nmap -p3306 --script mysql-info,mysql-empty-password,mysql-enum {t}",
            "mysql -h {t} -u root             # try root with no password",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{t}",
            "nmap -p3306 --script mysql-databases --script-args mysqluser=root {t}",
        ],
        "look_for": [
            "Root login with empty password — instant full DB access",
            "Remote root login allowed in my.cnf",
            "MySQL version — 5.x has several critical CVEs",
            "Sensitive databases: wordpress, joomla, users, customers, passwords",
        ],
    },
    3389: {
        "name": "RDP",
        "severity": 3,
        "what": "Remote Desktop Protocol — graphical remote access to Windows.",
        "why": "BlueKeep allows unauthenticated RCE on unpatched Windows. Brute-force of credentials is extremely common.",
        "cves": ["CVE-2019-0708 (BlueKeep)", "CVE-2019-1182 (DejaBlue)", "CVE-2020-0609"],
        "commands": [
            "nmap -p3389 --script rdp-vuln-ms12-020,rdp-enum-encryption {t}",
            "nmap -p3389 --script rdp-vuln-cve-2019-0708 {t}    # BlueKeep check",
            "hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://{t}",
            "xfreerdp /v:{t} /u:administrator # connect with found credentials",
        ],
        "look_for": [
            "BlueKeep (CVE-2019-0708) — unauthenticated RCE on Win7/2008",
            "NLA (Network Level Auth) disabled — authentication happens after connection",
            "Default or weak admin credentials",
            "Multiple accounts to try: Administrator, admin, user, Guest",
        ],
    },
    5432: {
        "name": "PostgreSQL",
        "severity": 3,
        "what": "PostgreSQL database server.",
        "why": "Internet-exposed Postgres should never exist. COPY TO/FROM PROGRAM enables OS command execution if authenticated.",
        "cves": ["CVE-2019-9193 (COPY RCE)"],
        "commands": [
            "nmap -p5432 --script pgsql-brute {t}",
            "psql -h {t} -U postgres          # try default user",
            "hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://{t}",
        ],
        "look_for": [
            "Default user 'postgres' with no password",
            "trust authentication in pg_hba.conf — no password needed",
            "Once in: COPY TO PROGRAM 'command' — OS command execution",
        ],
    },
    5900: {
        "name": "VNC",
        "severity": 4,
        "what": "Virtual Network Computing — graphical remote desktop access.",
        "why": "Often configured with no password or weak password. No encryption by default. Direct desktop access if compromised.",
        "cves": ["CVE-2006-2369 (auth bypass)", "CVE-2008-4770"],
        "commands": [
            "nmap -p5900 --script vnc-info,vnc-brute,realvnc-auth-bypass {t}",
            "vncviewer {t}                    # try connecting with no password",
            "hydra -P /usr/share/wordlists/rockyou.txt vnc://{t}",
        ],
        "look_for": [
            "No authentication required — direct desktop access",
            "RealVNC auth bypass vulnerability",
            "VNC version in banner — older versions have known bypasses",
            "Weak 4-8 character password",
        ],
    },
    6379: {
        "name": "Redis",
        "severity": 4,
        "what": "Redis in-memory data store / cache server.",
        "why": "Redis almost never requires authentication by default. Unauthenticated access allows data theft, config write, and often RCE via cron or SSH key injection.",
        "cves": ["CVE-2022-0543 (Lua sandbox escape RCE)", "CVE-2015-8080"],
        "commands": [
            "redis-cli -h {t} ping            # if PONG — no auth, wide open",
            "redis-cli -h {t} info            # dump server info and config",
            "redis-cli -h {t} keys '*'        # list all stored keys",
            "redis-cli -h {t} config get dir  # check data directory",
            "nmap -p6379 --script redis-info {t}",
        ],
        "look_for": [
            "PONG response to ping — unauthenticated access confirmed",
            "config get dir / config get dbfilename — path for file write",
            "Write SSH key: CONFIG SET dir /root/.ssh → SET key → BGSAVE",
            "Write cron: CONFIG SET dir /var/spool/cron → plant reverse shell",
            "Sensitive keys: session:, user:, token:, password:",
        ],
    },
    8080: {
        "name": "HTTP-Alt",
        "severity": 2,
        "what": "Alternative HTTP port — often a dev server, proxy, or admin panel.",
        "why": "Dev servers often have debug mode on, weaker auth, or expose internal APIs. Admin panels with default creds are common.",
        "cves": ["CVE-2021-41773 (Apache)", "CVE-2020-1938 (Tomcat AJP Ghostcat)"],
        "commands": [
            "curl -I http://{t}:8080          # check what's running",
            "nikto -h http://{t}:8080",
            "gobuster dir -u http://{t}:8080 -w /usr/share/wordlists/dirb/common.txt",
            "nmap -p8080 --script http-title,http-headers,http-enum {t}",
        ],
        "look_for": [
            "Apache Tomcat manager at /manager/html — default: tomcat/tomcat",
            "Jenkins at / — often unauthenticated script console",
            "Jupyter Notebook — may allow unauthenticated code execution",
            "Spring Boot Actuator /actuator/env — exposes config and secrets",
        ],
    },
    8443: {
        "name": "HTTPS-Alt",
        "severity": 2,
        "what": "Alternative HTTPS port — often admin panels or application servers.",
        "why": "Admin panels on non-standard ports are often overlooked and under-secured.",
        "cves": [],
        "commands": [
            "curl -Ik https://{t}:8443        # check what's running",
            "nikto -h https://{t}:8443 -ssl",
            "nmap -p8443 --script ssl-cert,http-title,http-auth {t}",
            "gobuster dir -u https://{t}:8443 -w /usr/share/wordlists/dirb/common.txt",
        ],
        "look_for": [
            "SSL certificate reveals internal hostnames or org name",
            "Admin interfaces: Kubernetes, Rancher, VMware, Fortinet, pfSense",
            "Default credentials on any login page found",
        ],
    },
    27017: {
        "name": "MongoDB",
        "severity": 4,
        "what": "MongoDB NoSQL database server.",
        "why": "MongoDB has no authentication by default. Millions of databases have been wiped and held for ransom due to this.",
        "cves": ["CVE-2019-2386", "Countless data breaches from no-auth default"],
        "commands": [
            "mongo {t}:27017                  # connect with no credentials",
            "nmap -p27017 --script mongodb-info,mongodb-databases {t}",
            "mongodump --host {t}             # dump entire database",
        ],
        "look_for": [
            "Connection succeeds without credentials — critical",
            "show dbs — list all databases",
            "Sensitive collections: users, accounts, sessions, orders, emails",
            "bindIp not set to 127.0.0.1 — world-accessible",
        ],
    },
    9200: {
        "name": "Elasticsearch",
        "severity": 4,
        "what": "Elasticsearch — search and analytics engine.",
        "why": "No authentication by default. Direct HTTP API exposes all indexed data. Massive data breaches have resulted from exposed instances.",
        "cves": ["CVE-2015-1427 (Groovy sandbox RCE)", "CVE-2014-3120"],
        "commands": [
            "curl http://{t}:9200/            # check if accessible",
            "curl http://{t}:9200/_cat/indices  # list all indices",
            "curl http://{t}:9200/_cluster/health",
            "nmap -p9200 --script http-title {t}",
        ],
        "look_for": [
            "Accessible without auth — all data is exposed",
            "_cat/indices — look for: users, logs, sessions, orders, emails",
            "Version info — older versions have RCE via dynamic scripting",
        ],
    },
    11211: {
        "name": "Memcached",
        "severity": 3,
        "what": "Memcached — distributed memory caching system.",
        "why": "No authentication. Cache can contain session tokens, user data, database query results. Also used for UDP DDoS amplification.",
        "cves": ["CVE-2018-1000115 (DDoS amplification)"],
        "commands": [
            "nc {t} 11211                     # connect: stats, stats items",
            "echo 'stats' | nc {t} 11211",
            "nmap -p11211 --script memcached-info {t}",
        ],
        "look_for": [
            "stats command works — no auth confirmed",
            "stats items — shows what's cached (sessions, tokens, data)",
            "Dump cache: stats cachedump <slab> <limit>",
        ],
    },
}

# Severity labels and colors
SEV = {4: (R,  "CRITICAL"), 3: (Y,  "HIGH"), 2: (C,  "MEDIUM"), 1: (G,  "LOW"), 0: (DIM, "INFO")}


# ── Installer ─────────────────────────────────────────────────────────────────
def run_install():
    print(BANNER)
    print(f"{W}  ROOM — Dependency Checker & Installer{RST}")
    print(f"{B}  ─────────────────────────────────────────────────────{RST}\n")

    tools = [
        ("nmap",       "nmap",            "sudo apt install -y nmap",          "Core port scanner — required"),
        ("curl",       "curl",            "sudo apt install -y curl",          "HTTP header analysis"),
        ("hydra",      "hydra",           "sudo apt install -y hydra",         "Credential brute-forcing"),
        ("nikto",      "nikto",           "sudo apt install -y nikto",         "Web vulnerability scanner"),
        ("gobuster",   "gobuster",        "sudo apt install -y gobuster",      "Directory & file enumeration"),
        ("dig",        "dnsutils",        "sudo apt install -y dnsutils",      "DNS zone transfer testing"),
        ("enum4linux", "enum4linux",      "sudo apt install -y enum4linux",    "SMB/NetBIOS enumeration"),
        ("smbclient",  "smbclient",       "sudo apt install -y smbclient",     "SMB share access"),
        ("redis-cli",  "redis-tools",     "sudo apt install -y redis-tools",   "Redis testing"),
        ("whatweb",    "whatweb",         "sudo apt install -y whatweb",       "Web technology fingerprinting"),
    ]

    missing = []
    print(f"  {W}{'Tool':<14} {'Status':<16} Purpose{RST}")
    print(f"  {'─'*14} {'─'*16} {'─'*30}")

    for tool, pkg, cmd, purpose in tools:
        found = subprocess.run(["which", tool], capture_output=True).returncode == 0
        if found:
            print(f"  {W}{tool:<14}{RST} {G}✓ installed   {RST} {DIM}{purpose}{RST}")
        else:
            print(f"  {W}{tool:<14}{RST} {R}✗ missing     {RST} {DIM}{purpose}{RST}")
            missing.append((tool, pkg, cmd))

    print()

    if not missing:
        print(f"  {G}✓ All tools installed — ROOM is ready!{RST}")
        print(f"\n  {DIM}Try: python3 room.py scanme.nmap.org{RST}\n")
        return

    print(f"  {Y}Missing {len(missing)} tool(s).{RST}")
    confirm = input(f"  {C}Install them now? (yes/no): {RST}").strip().lower()

    if confirm not in ("yes", "y"):
        print(f"\n  {DIM}Manual install commands:{RST}")
        for _, _, cmd, _ in missing:
            print(f"    {Y}{cmd}{RST}")
        print()
        return

    for tool, pkg, cmd, _ in missing:
        print(f"\n  {DIM}▸ {cmd}{RST}")
        res = subprocess.run(cmd.split(), capture_output=False)
        if res.returncode == 0:
            print(f"  {G}✓ {tool} installed{RST}")
        else:
            print(f"  {R}✗ Failed — try manually: {cmd}{RST}")

    print(f"\n  {G}Done! Try: python3 room.py scanme.nmap.org{RST}\n")


# ── Nmap wrappers ─────────────────────────────────────────────────────────────
def run_nmap(target: str, flags: str, label: str) -> str:
    print(f"  {DIM}▸ nmap {flags} {target}{RST}")
    try:
        r = subprocess.run(
            ["nmap"] + flags.split() + [target],
            capture_output=True, text=True, timeout=600
        )
        return r.stdout
    except FileNotFoundError:
        print(f"  {R}[!] nmap not found — run: python3 room.py --install{RST}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"  {Y}[!] Timed out: {label}{RST}")
        return ""


def parse_open_ports(nmap_output: str) -> list:
    ports = []
    for line in nmap_output.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            ports.append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip(),
            })
    return ports


# ── Analysis engine ───────────────────────────────────────────────────────────
def analyze_ports(ports: list, target: str):
    """Print full guided analysis for all open ports."""

    print(f"\n  {G}Found {len(ports)} open port(s):{RST}\n")

    # Severity order: highest first
    sorted_ports = sorted(ports, key=lambda p: KB.get(p["port"], {}).get("severity", 0), reverse=True)

    analyzed = []
    unknown  = []

    for p in sorted_ports:
        info = KB.get(p["port"])
        if info:
            analyzed.append((p, info))
        else:
            unknown.append(p)

    # Print each known port
    for p, info in analyzed:
        sev_num = info["severity"]
        sev_col, sev_label = SEV[sev_num]

        print(f"  {B}{'─'*55}{RST}")
        print(f"  {W}PORT {p['port']}/{p['proto']}  —  {info['name']}{RST}  {sev_col}[{sev_label}]{RST}")
        if p.get("version"):
            print(f"  {DIM}  Version detected: {p['version']}{RST}")
        print(f"\n  {W}What it is:{RST}")
        print(f"    {info['what']}")
        print(f"\n  {W}Why it matters:{RST}")
        print(f"    {Y}{info['why']}{RST}")

        if info.get("cves"):
            print(f"\n  {W}Known CVEs to check:{RST}")
            for cve in info["cves"]:
                print(f"    {R}• {cve}{RST}")

        print(f"\n  {W}Commands to run:{RST}")
        for i, cmd in enumerate(info["commands"], 1):
            formatted = cmd.replace("{t}", target)
            print(f"    {Y}{i}.{RST} {formatted}")

        print(f"\n  {W}What to look for:{RST}")
        for item in info["look_for"]:
            print(f"    {C}▸{RST} {item}")
        print()

    # Unknown ports
    if unknown:
        print(f"  {B}{'─'*55}{RST}")
        print(f"  {W}UNKNOWN / UNUSUAL PORTS{RST}  {DIM}(not in common port list — investigate manually){RST}\n")
        for p in unknown:
            print(f"  {G}[+]{RST} Port {W}{p['port']}/{p['proto']}{RST}  ({p['service']}  {DIM}{p['version']}{RST})")
            print(f"    {Y}1.{RST} nmap -p{p['port']} --script banner,version {target}")
            print(f"    {Y}2.{RST} nc {target} {p['port']}   # manual banner grab")
            print(f"    {Y}3.{RST} searchsploit {p['service']}   # search for known exploits")
            print()

    # Priority + quick win
    if analyzed:
        print(f"  {B}{'─'*55}{RST}")
        print(f"  {G}{W}PRIORITY ORDER — start here:{RST}\n")
        for i, (p, info) in enumerate(analyzed, 1):
            sev_col, sev_label = SEV[info["severity"]]
            print(f"  {Y}{i}.{RST} Port {p['port']} ({info['name']})  {sev_col}[{sev_label}]{RST}")

        # Quick win = highest severity port
        top_p, top_info = analyzed[0]
        print(f"\n  {G}{W}QUICK WIN:{RST}")
        print(f"  Start with port {top_p['port']} ({top_info['name']}) — {top_info['why'].split('.')[0]}.")
        first_cmd = top_info["commands"][0].replace("{t}", target)
        print(f"  {Y}▸ {first_cmd}{RST}\n")


def check_http_headers(target: str, ports: list):
    """Check HTTP headers on web ports and flag issues."""
    SECURITY_HEADERS = {
        "strict-transport-security": ("HSTS missing", "Allows SSL stripping attacks"),
        "content-security-policy":   ("CSP missing",  "Allows XSS and data injection"),
        "x-frame-options":           ("X-Frame-Options missing", "Allows clickjacking"),
        "x-content-type-options":    ("X-Content-Type-Options missing", "Allows MIME sniffing"),
        "referrer-policy":           ("Referrer-Policy missing", "May leak sensitive URLs"),
        "permissions-policy":        ("Permissions-Policy missing", "No browser feature control"),
    }
    INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]

    for p in ports:
        scheme = "https" if p["port"] in (443, 8443) else "http"
        url = f"{scheme}://{target}:{p['port']}"
        print(f"\n  {C}● {url}{RST}")

        try:
            r = subprocess.run(
                ["curl", "-sI", "--max-time", "10", "--insecure", url],
                capture_output=True, text=True
            )
            raw = r.stdout
        except FileNotFoundError:
            print(f"  {Y}  curl not installed — run: python3 room.py --install{RST}")
            continue

        header_map = {}
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                header_map[k.strip().lower()] = v.strip()

        found_issues = False

        # Info leaks
        for h in INFO_LEAK_HEADERS:
            if h in header_map:
                print(f"  {Y}INFO LEAK  {W}{h}:{RST} {header_map[h]}")
                found_issues = True

        # Missing security headers
        for h, (label, risk) in SECURITY_HEADERS.items():
            if h not in header_map:
                print(f"  {R}MISSING    {W}{label}:{RST} {DIM}{risk}{RST}")
                found_issues = True

        if not found_issues:
            print(f"  {G}  Headers look good — no obvious issues found{RST}")

        print(f"  {DIM}  Raw headers:{RST}")
        for line in raw.splitlines()[:12]:
            print(f"  {DIM}    {line}{RST}")


# ── Section helper ────────────────────────────────────────────────────────────
def section(title: str):
    print(f"\n{B}{'─'*58}{RST}")
    print(f"{W}  {title}{RST}")
    print(f"{B}{'─'*58}{RST}\n")


# ── Main scan ─────────────────────────────────────────────────────────────────
def scan(target: str, mode: str):
    print(BANNER)

    section("1 / Target Resolution")
    try:
        ip = socket.gethostbyname(target)
        print(f"  {G}[+]{RST} {target} → {W}{ip}{RST}")
    except socket.gaierror:
        print(f"  {R}[!] Cannot resolve: {target}{RST}")
        sys.exit(1)
    print(f"  {DIM}Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    print(f"  {DIM}Mode    : {mode}{RST}")

    all_raw   = ""
    all_ports = []

    section("2 / Service Scan (Top 1000 Ports)")
    out = run_nmap(target, "-sV --open -T4", "service scan")
    print(out)
    all_raw  += out
    all_ports += parse_open_ports(out)

    if mode in ("full", "all"):
        section("3 / Full Port Scan (1–65535)")
        print(f"  {DIM}Scanning all ports — this may take a few minutes...{RST}\n")
        out = run_nmap(target, "-p- --open -T4", "full range")
        print(out)
        all_raw  += out
        all_ports += parse_open_ports(out)

    if mode == "all":
        section("4 / OS & Deep Service Detection")
        out = run_nmap(target, "-O -sV --version-intensity 7", "OS detect")
        print(out)
        all_raw += out

    if mode == "all":
        section("5 / NSE Vulnerability Scripts")
        out = run_nmap(target, "--script vuln -T4", "vuln scripts")
        print(out)
        all_raw  += out
        all_ports += parse_open_ports(out)

    # Deduplicate
    seen = set()
    unique = []
    for p in all_ports:
        if p["port"] not in seen:
            seen.add(p["port"])
            unique.append(p)

    if not unique:
        print(f"\n{Y}  No open ports found.{RST}")
        print(f"  {DIM}Try --mode full to scan all 65535 ports, or check firewall rules.{RST}\n")
        return

    # HTTP header check
    web = [p for p in unique if p["port"] in (80, 443, 8080, 8443, 8000, 8888)]
    if web and mode in ("full", "all"):
        section("6 / HTTP Security Header Review")
        check_http_headers(target, web)

    # Main analysis
    section("✦ Guided Vulnerability Analysis")
    analyze_ports(unique, target)

    # Summary
    section("✦ Scan Complete")
    print(f"  {W}Target     :{RST} {target}  ({ip})")
    print(f"  {W}Mode       :{RST} {mode}")
    print(f"  {W}Open ports :{RST} {G}{len(unique)}{RST}  →  {Y}{', '.join(str(p['port']) for p in unique)}{RST}")
    print(f"\n  {DIM}Tip: run with --mode all for the deepest scan including OS and vuln scripts{RST}")
    print(f"  {R}  Legal: only scan systems you own or have permission to test{RST}\n")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) == 1 or "--help" in sys.argv or "-h" in sys.argv:
        print(HELP_SCREEN)
        sys.exit(0)

    if "--install" in sys.argv:
        run_install()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target")
    parser.add_argument("--mode", choices=["quick", "full", "all"], default="quick")
    parser.add_argument("--help", "-h", action="store_true")
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()

    print(f"\n{R}[!] LEGAL NOTICE:{RST} Only scan systems you own or have explicit permission to test.")
    confirm = input(f"{Y}    Confirm permission to scan {args.target}? (yes/no): {RST}").strip().lower()
    if confirm not in ("yes", "y"):
        print(f"{R}  Aborted.{RST}\n")
        sys.exit(0)

    scan(args.target, args.mode)


if __name__ == "__main__":
    main()
