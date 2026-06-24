# 🔍 ROOM — Recon. Observe. Operate. Map.

> A guided network reconnaissance tool. Give it an IP or hostname — it scans all ports, finds what's open, explains every finding, and tells you exactly what to do next.

**No need to memorise nmap flags. No API keys. No cost. 100% free & offline.**

---

## 📸 Preview

```
PORT 22/tcp  —  SSH  [MEDIUM]
  What it is:   Secure Shell — encrypted remote terminal access.
  Why it matters: Old OpenSSH versions can be brute-forced or exploited.

  Commands to run:
    1. nmap -p22 --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey <target>
    2. ssh -v <target>
    3. hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>

  What to look for:
    ▸ Password authentication enabled — brute-force risk
    ▸ OpenSSH version < 8.0 — check for known CVEs
    ▸ Root login permitted — critical misconfiguration

QUICK WIN:
  Start with port 6379 (Redis) — if PONG comes back, it's wide open.
  ▸ redis-cli -h <target> ping
```

---

## ⚡ Features

- 🔎 **Scans all ports automatically** — no nmap flags to memorise
- 🎯 **Severity rating** for every finding — `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`
- 📋 **Exact commands** to investigate every open port (nmap NSE, hydra, nikto, gobuster, etc.)
- 💡 **Explains** what each service is and why it's a risk
- 🌐 **HTTP header analysis** — flags missing security headers and info leaks
- 🏆 **Priority order** — tells you which port to attack first
- ⚡ **Quick Win** — the single most likely vulnerability to check immediately
- 🖥️ **Cross-platform** — works on Kali Linux, Parrot OS, Ubuntu, macOS, Windows
- 💸 **100% free** — no API keys, no internet needed for analysis

---

## 🛠️ Requirements

- Python 3.6+
- nmap

Optional (recommended for full functionality):
- hydra, nikto, gobuster, curl, enum4linux, smbclient

---

## 📦 Installation

**Clone the repo:**
```bash
git clone https://github.com/jani-meet/room-recon-tool.git
cd room-recon-tool
```

**Check & install all dependencies:**
```bash
python3 room.py --install
```

---

## 🚀 Usage

```bash
python3 room.py <target> --mode <quick|full|all>
```

### Scan Modes

| Mode    | What it does                                               | Time     |
|---------|------------------------------------------------------------|----------|
| `quick` | Top 1000 ports + service detection + guided analysis       | ~1 min   |
| `full`  | All 65535 ports + guided analysis + HTTP header review     | ~6 min   |
| `all`   | Full + OS detection + NSE vuln scripts + complete report   | ~12 min  |

### Examples

```bash
# Quick scan — try this first (legal public test server)
python3 room.py scanme.nmap.org

# Full port scan on your own machine
python3 room.py 192.168.1.1 --mode full

# Complete recon on a lab target
python3 room.py 10.0.0.5 --mode all

# See all options
python3 room.py --help
```

---

## 📊 Ports Covered

ROOM has a built-in knowledge base covering **27 ports** including:

| Port  | Service       | Severity |
|-------|--------------|----------|
| 23    | Telnet        | 🔴 CRITICAL |
| 445   | SMB           | 🔴 CRITICAL |
| 6379  | Redis         | 🔴 CRITICAL |
| 27017 | MongoDB       | 🔴 CRITICAL |
| 3306  | MySQL         | 🔴 CRITICAL |
| 1433  | MSSQL         | 🔴 CRITICAL |
| 9200  | Elasticsearch | 🔴 CRITICAL |
| 5900  | VNC           | 🔴 CRITICAL |
| 3389  | RDP           | 🟠 HIGH |
| 21    | FTP           | 🟠 HIGH |
| 111   | RPCBind       | 🟠 HIGH |
| 22    | SSH           | 🟡 MEDIUM |
| 80    | HTTP          | 🟡 MEDIUM |
| 443   | HTTPS         | 🟢 LOW |
| ...   | and more      | |

---

## 🖥️ Platform Support

| Platform         | Status | Notes |
|-----------------|--------|-------|
| Kali Linux       | ✅ Full | All tools supported |
| Parrot OS        | ✅ Full | All tools supported |
| Ubuntu / Debian  | ✅ Full | All tools supported |
| macOS            | ✅ Partial | Most tools via Homebrew |
| Windows          | ⚠️ Basic | nmap only — use WSL for full support |

**Windows users:** For the full toolkit, use WSL with Kali:
```powershell
wsl --install -d kali-linux
```

---

## ⚠️ Legal Disclaimer

> **Only scan systems you own or have explicit written permission to test.**
> Unauthorised scanning is illegal in most countries and can result in criminal charges.
> The tool asks for confirmation before every scan.
> The author is not responsible for any misuse of this tool.

---

## 👤 Author

**jani-meet**
- GitHub: [@jani-meet](https://github.com/jani-meet)

---

## ⭐ Support

If ROOM helped you — give it a star ⭐ on GitHub!

---

*Built for ethical hackers, security researchers, and CTF players.*
