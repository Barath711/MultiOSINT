# 🔎 MultiOSINT v10

**A desktop threat intelligence platform for SOC analysts.**

Query **14+ OSINT sources** simultaneously — IPs, Domains, URLs, Hashes, and Emails — from a single interface. Triage phishing emails, analyze IOCs, and generate AI-powered summaries without switching tabs.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## ⚡ Why This Exists

During incident response, analysts constantly copy-paste IOCs between browser tabs. It's slow, error-prone, and breaks focus.

**MultiOSINT** eliminates that friction:
- Enter an IP, domain, URL, hash, or email **once**
- Get results from **14+ sources** in parallel
- Triage phishing `.eml`/`.msg` files with a single drag-and-drop
- Browse **160+ OSINT tools** from a built-in navigator

---

## 🖥️ Feature Overview

### 🔍 OSINT Lookup
| Source | IP | Domain | Hash | Email | Free |
|--------|:--:|:------:|:----:|:-----:|:----:|
| VirusTotal | ✅ | ✅ | ✅ | ✅ | Free tier |
| AbuseIPDB | ✅ | — | — | — | Free tier |
| GreyNoise | ✅ | — | — | — | Free tier |
| Shodan | ✅ | — | — | — | API key |
| CriminalIP | ✅ | — | — | — | API key |
| IPQualityScore | ✅ | ✅ | — | ✅ | API key |
| OTX AlienVault | ✅ | ✅ | ✅ | — | Free |
| Pulsedive | ✅ | ✅ | — | — | API key |
| URLhaus | ✅ | ✅ | — | — | Free |
| ThreatFox | ✅ | ✅ | ✅ | — | Free |
| MalwareBazaar | — | — | ✅ | — | Free |
| CIRCL HashLookup | — | — | ✅ | — | Free |
| XposedOrNot | — | — | — | ✅ | Free |
| Breach.VIP | — | — | — | ✅ | Free |
| Geolocation / rDNS / WHOIS / DNS | ✅ | ✅ | — | — | Free |

### 📧 Phishing Analyzer
- Drag-and-drop `.eml` / `.msg` file triage
- Auto-extracts sender, reply-to, IPs, domains, URLs, and attachments
- Enriches all extracted IOCs automatically via the same API stack
- Header analysis with hop-by-hop SPF/DKIM/DMARC visualization
- Joe Sandbox detonation for attachments
- Export full report to HTML

### 🌐 OSINT Navigator
- 160+ curated OSINT tools across 14 categories:
  Search, IP Info, Threat Intel, Hash Lookup, Email & Breach, Email Headers, Attack Surface, Vulnerabilities, Malware Analysis, Malware Feeds, Phishing, Social Media & People, Utilities, AI Tools
- Live search filter across all tools
- One-click open — syncs IOC from the Lookup tab automatically
- Collapsible categories, expand/collapse all

### 🤖 AI Summary (Gemini)
- Paste results → get a structured analyst summary in seconds
- Supports `gemini-2.0-flash`, `gemini-1.5-pro`, and more
- Auto-summarize after every lookup (optional)

### 📊 Reporting
- Export results to **CSV** or **HTML** report
- Clean results view — errors and "not found" responses are suppressed automatically

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install customtkinter pillow requests urllib3 python-whois dnspython xposedornot
```

### 2. Run
```bash
pythonw MultiOSINT.pyw
```
> On Windows, use `pythonw` (not `python`) to avoid a console window.  
> Or: right-click → Open with → `pythonw.exe` → tick *Always use this app*

### 3. Configure API keys
Open **Settings** tab inside the app. Keys are saved to `config.json` in the same folder.

**Free-tier keys (recommended to get):**
| Service | Link |
|---------|------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | https://www.abuseipdb.com/account/api |
| OTX AlienVault | https://otx.alienvault.com/api |
| IPQualityScore | https://www.ipqualityscore.com/user/api-keys |
| Pulsedive | https://pulsedive.com/account/ |
| Google Gemini | https://aistudio.google.com/app/apikey |

---

## 📦 Distribution (EXE Build)

To build a standalone `.exe` for sharing with your team (no Python install required):

```powershell
.\build.ps1
```

- Output: `dist\MultiOSINT_v10\MultiOSINT_v10.exe`
- `config.json` and `myicon.ico` stay **external** — each team member keeps their own API keys
- Gemini/HTTPS works correctly (SSL cert bundle included automatically)

Share the entire `dist\MultiOSINT_v10\` folder as a zip.

---

## 🗂️ File Structure

```
MultiOSINT/
├── MultiOSINTv10.pyw   # Main application (single file)
├── config.json         # API keys (edit per user, never commit)
├── myicon.ico          # App icon
└── build.ps1           # EXE build script
```

---

## ✅ What's New in v10

- **Breach.VIP** integration (free, no key — breach search by email/domain/IP/username)
- **XposedOrNot** breach lookup confirmed working
- **OSINT Navigator tab** — 160+ tools, live filter, IOC sync
- **Splash screen** on startup
- **Clean results** — errors and empty "not found" blocks are hidden automatically
- **AI Summary** tab with Gemini model selector
- IPQualityScore, CriminalIP, Pulsedive added
- EXE build support with `build.ps1`

---

## 🤝 Contributing

PRs welcome. If you're a SOC analyst with feature ideas, open an issue.

---

## 📜 License

MIT — use it, modify it, make your SOC faster.

---

## 👤 Author

**Barath A C**  
SOC Analyst II @ Deloitte USI  
[LinkedIn](https://linkedin.com/in/barath07) · [GitHub](https://github.com/Barath711)
