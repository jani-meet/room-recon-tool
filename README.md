# ⚔️ ROOM — Recon. Observe. Operate. Map.

> *"Room."* — Trafalgar D. Water Law

Inspired by the Devil Fruit ability of Trafalgar Law from One Piece — ROOM creates a space where you have full control. Give it a target, and it maps everything, tells you what's vulnerable, and walks you through exactly how to exploit it — step by step.

**100% free. No API keys. No internet needed for analysis. Works offline.**

---

## 🏴‍☠️ What is ROOM?

ROOM is a guided network reconnaissance and exploitation tool for ethical hackers, security researchers, and CTF players. 

Most beginners know they should "run nmap" but don't know what the results mean or what to do next. ROOM solves that — it scans, analyses, explains, and then walks you through the full exploitation process with exact commands and vulnerability chains.

---

## ⚡ Features

### 🔍 Scanning
- Scans all ports automatically — no nmap flags to memorise
- Detects service name and exact version on every open port
- 3 scan depths: quick, full, complete
- OS detection and NSE vulnerability scripts
- HTTP security header analysis on web ports

### 📊 Analysis
- Rates every finding: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`
- Covers **16 ports** with detailed knowledge
- Shows known CVEs for each service
- Priority order — tells you where to start
- Quick Win — the single most likely vulnerability

### 📖 Step-by-Step Exploit Guides
Full exploitation guides for **7 services** — each with multiple phases, exact commands, explanations, and what to look for:

| Port | Service | Phases | Steps |
|------|---------|--------|-------|
| 21 | FTP | 5 | 14 |
| 22 | SSH | 5 | 14 |
| 80 | HTTP | 5 | 16 |
| 445 | SMB | 5 | 14 |
| 6379 | Redis | 4 | 11 |
| 3306 | MySQL | 4 | 11 |
| 27017 | MongoDB | 3 | 9 |

### 🔗 Vulnerability Chains
Shows how one vulnerability leads to the next:
```
FTP anonymous login → read wp-config.php → DB password
→ MySQL access → write web shell → RCE → reverse shell → root
```

### 🖥️ Interactive Menu
After every scan, pick any open port and get its full exploitation guide instantly.

---

## 🖥️ Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Kali Linux | ✅ Full | Recommended |
| Parrot OS | ✅ Full | All tools supported |
| Ubuntu / Debian | ✅ Full | All tools supported |
| macOS | ✅ Partial | Most tools via Homebrew |
| Windows | ⚠️ Basic | nmap only — use WSL for full support |

**Windows users:** For the full toolkit use WSL:
```powershell
wsl --install -d kali-linux
```

---

## 📦 Installation

```bash
# Clone the repo
git clone https://github.com/jani-meet/room-recon-tool.git
cd room-recon-tool

# Check & install all dependencies automatically
python3 room.py --install
```

**Requirements:** Python 3.6+, nmap

**Optional tools (auto-installed):** hydra, nikto, gobuster, curl, enum4linux, smbclient, redis-cli, whatweb, sqlmap, wpscan

---

## 🚀 Usage

```bash
python3 room.py <target> [options]
```

### Scan Modes

| Mode | What it does | Time |
|------|-------------|------|
| `quick` | Top 1000 ports + service detection + analysis | ~1 min |
| `full` | All 65535 ports + analysis + HTTP headers | ~6 min |
| `all` | Full + OS detection + NSE vuln scripts | ~12 min |

### Examples

```bash
# Quick scan — try this first (legal public test server)
python3 room.py scanme.nmap.org

# Full port scan
python3 room.py 192.168.1.1 --mode full

# Complete recon
python3 room.py 10.0.0.5 --mode all

# Jump straight to exploit guide for a specific port
python3 room.py --exploit 21 --target 10.0.0.5
python3 room.py --exploit 80 --target 192.168.1.1

# Check & install all tools
python3 room.py --install

# Help
python3 room.py --help
```

---

## 📸 Preview

```
  ██████╗  ██████╗  ██████╗ ███╗   ███╗
  ██╔══██╗██╔═══██╗██╔═══██╗████╗ ████║
  ██████╔╝██║   ██║██║   ██║██╔████╔██║
  ██╔══██╗██║   ██║██║   ██║██║╚██╔╝██║
  ██║  ██║╚██████╔╝╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝
  Recon. Observe. Operate. Map.
  Guided Network Recon + Exploit Guide v3.0
  Inspired by Trafalgar D. Water Law — Surgeon of Death

PORT 21/tcp — FTP  [HIGH]
  Version: vsftpd 2.3.4
  What it is:   File Transfer Protocol
  Risk:         Often allows anonymous login. Known RCE backdoor.
  CVEs:         CVE-2011-2523 (vsftpd backdoor)

  [Full exploit guide available]

VULNERABILITY CHAINS:
  vsftpd 2.3.4 backdoor  →  Root shell on port 6200  →  Full system compromise
  FTP anonymous login  →  Read config files  →  DB password  →  MySQL access
```

---

## 📖 Exploit Guide Preview

```
══════════════════════════════════════════════════════
FTP — Full Exploitation Guide
══════════════════════════════════════════════════════

"Room." — Law (activating his Devil Fruit ability)

PHASE 1 — Reconnaissance
  ▶ Banner grab
    $ nc 10.0.0.5 21
    Connect raw and read the first line. It tells you the FTP
    server software and version. Search for CVEs based on this.

  ▶ Nmap deep scan
    $ nmap -p21 --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor 10.0.0.5
    Checks anonymous login, gets OS info, checks vsftpd backdoor.

PHASE 2 — Anonymous Login Attempt
PHASE 3 — Version Exploit Check
PHASE 4 — Brute Force
PHASE 5 — Post Access

VULNERABILITY CHAINS:
  FTP anonymous login  →  Read wp-config.php  →  Find DB password  →  MySQL access
  FTP write access  →  Upload PHP web shell  →  RCE  →  Reverse shell  →  Root
```

---

## 🛠️ Tools Used

ROOM uses and guides you through these industry-standard tools:

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and NSE scripts |
| hydra | Credential brute-forcing |
| nikto | Web vulnerability scanning |
| gobuster | Directory and file enumeration |
| sqlmap | SQL injection testing |
| metasploit | Exploit framework |
| enum4linux | SMB/NetBIOS enumeration |
| redis-cli | Redis testing |
| wpscan | WordPress scanning |
| curl | HTTP header analysis |

---

## ⚠️ Legal Disclaimer

> **Only scan systems you own or have explicit written permission to test.**
>
> Unauthorised scanning and exploitation is illegal in most countries and can result in criminal charges. The tool asks for confirmation before every scan.
>
> The author is not responsible for any misuse of this tool. ROOM is built for ethical hacking, CTF challenges, and authorised penetration testing only.

---

## 🗺️ Roadmap

- [ ] Save scan results to file (PDF / TXT report)
- [ ] Exploit guides for: Telnet, SMB, RDP, VNC, MSSQL, Elasticsearch
- [ ] CVE lookup integration
- [ ] Auto privilege escalation checklist post-shell
- [ ] HackTheBox / TryHackMe mode

---

## 👤 Author

**jani-meet**
- GitHub: [@jani-meet](https://github.com/jani-meet)

---

## ⭐ Support

If ROOM helped you — drop a ⭐ on GitHub!

---

*Built for ethical hackers, CTF players, and security students.*

*"I've already decided... I will never bow to anyone again." — Trafalgar D. Water Law*
