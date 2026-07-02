# 🔎 MultiOSINT v12

**A desktop threat intelligence platform for SOC analysts.**

Query **18+ OSINT sources** simultaneously — IPs, Domains, URLs, Hashes, and Emails — from a single interface. Triage phishing emails, analyze browser history, investigate IOCs, and generate AI-powered summaries without switching tabs.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/UI-PyQt6-41CD52?style=flat&logo=qt&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## ⚡ Why This Exists

During incident response, analysts constantly copy-paste IOCs between browser tabs. It's slow, error-prone, and breaks focus.

**MultiOSINT** eliminates that friction:
- Enter an IP, domain, URL, hash, or email **once**
- Get results from **18+ sources** in parallel
- Triage phishing `.eml`/`.msg` files with a single drag-and-drop
- Parse Edge/Chrome **browser history & downloads** into a forensic timeline
- Browse **160+ OSINT tools** from a built-in navigator
- Generate a full analyst report with one Gemini AI click

---

## 🖥️ Feature Overview

### 🔍 OSINT Lookup
| Source | IP | Domain | URL | Hash | Email | Free |
|--------|:--:|:------:|:---:|:----:|:-----:|:----:|
| VirusTotal | ✅ | ✅ | ✅ | ✅ | ✅ | Free tier |
| AbuseIPDB | ✅ | — | — | — | — | Free tier |
| GreyNoise | ✅ | — | — | — | — | Free tier |
| Shodan | ✅ | — | — | — | — | API key |
| CriminalIP | ✅ | — | — | — | — | API key |
| IPQualityScore | ✅ | ✅ | ✅ | — | ✅ | API key |
| OTX AlienVault | ✅ | ✅ | — | ✅ | — | Free |
| Pulsedive | ✅ | ✅ | — | — | — | API key |
| URLScan.io | ✅ | ✅ | ✅ | — | — | Free (key optional) |
| PhishTank | — | ✅ | ✅ | — | — | Free |
| URLhaus | ✅ | ✅ | — | — | — | Free |
| ThreatFox | ✅ | ✅ | ✅ | ✅ | — | Free |
| MalwareBazaar | — | — | — | ✅ | — | Free |
| CIRCL HashLookup | — | — | — | ✅ | — | Free |
| XposedOrNot | — | — | — | — | ✅ | Free |
| Breach.VIP | — | — | — | — | ✅ | Free |
| EmailRep.io | — | — | — | — | ✅ | Free |
| LeakCheck.io | — | — | — | — | ✅ | Free |
| Geolocation / rDNS / WHOIS / DNS | ✅ | ✅ | — | — | — | Free |

### 📧 Phishing Analyzer
- Drag-and-drop `.eml` / `.msg` file triage
- Auto-extracts sender, reply-to, IPs, domains, URLs, and attachments
- Enriches all extracted IOCs automatically via the same API stack
- Header analysis with hop-by-hop SPF/DKIM/DMARC visualization
- Joe Sandbox detonation for attachments with screenshot preview
- URLScan.io screenshot capture for suspicious links
- Export full report to HTML

### 🌐 Browser History Analyzer *(new in v12)*
- Load one or more **Edge / Chrome `History`** SQLite databases
- **Preview browsing history** — URL, title, visit time (UTC), and correlated downloads
- **Downloads tab** — file name, start/end time, state, size, source & final URL
- **Downloads-only filter** — surface just the history rows that produced a download
- Correlates downloads to history entries by exact URL **and by hostname**
- Live search filter across URLs, titles, and file names
- **Export to XLSX** — separate History and Downloads sheets, with optional case/subject label prefix
- Batch export across multiple History files in one run
- All timestamps normalized to **UTC** (WebKit epoch conversion)

### 🧭 OSINT Navigator
- 160+ curated OSINT tools across 14 categories:
  Search, IP Info, Threat Intel, Hash Lookup, Email & Breach, Email Headers, Attack Surface, Vulnerabilities, Malware Analysis, Malware Feeds, Phishing, Social Media & People, Utilities, AI Tools
- Live search filter across all tools
- **▲ ▼ IOC navigation** — cycle through all entered IOCs one by one without retyping
- Collapsible categories with expand/collapse all
- Color-coded section headers for quick visual scanning

### 🤖 AI Summary (Gemini)
- One click → structured SOC analyst report covering all IOCs
- Uses `gemini-flash-latest` via REST API
- Non-blocking — runs in background thread, UI stays responsive
- Button disabled while generating to prevent duplicate requests

### 🔐 Settings & API Keys
- All API keys hidden by default (password masking)
- **👁 Show Keys / 🔒 Hide Keys** toggle to reveal/hide all at once
- Keys saved locally to `config.json` — never sent anywhere except the respective APIs

### 📊 Reporting
- Export OSINT results to **TXT** or **CSV**
- Export browser history & downloads to **XLSX**
- Export phishing report to **HTML**
- Clean results view — errors and "not found" responses suppressed automatically

---

## 🎨 UI Highlights

- **Three top-level modes** — 🔍 OSINT Lookup · 🎣 Phishing Analyzer · 🌐 Browser History — switch via header pills
- **PyQt6** — iOS-style design with smooth animated tab transitions, pill buttons, and frosted cards
- **Light / Dark mode toggle** — seamless color transitions, light is default; theme propagates to the Browser History panel
- **Animated circular splash screen** on startup — spinning arc progress indicator
- **Fullscreen by default** — maximized on launch
- Custom `.ico` icon support — just drop `myicon.ico` next to the `.pyw`

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install PyQt6 pillow requests urllib3 python-whois dnspython extract-msg openpyxl
```

### 2. Run
```bash
pythonw MultiOSINT.pyw
```
> On Windows, use `pythonw` (not `python`) to suppress the console window.  
> Or: right-click → Open with → `pythonw.exe` → tick *Always use this app*

### 3. Configure API keys
Open the **⚙️ Settings** tab inside the app. Keys are saved to `config.json` in the same folder. Click **👁 Show Keys** to reveal entries.

**Free-tier keys (recommended to get):**
| Service | Link |
|---------|------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | https://www.abuseipdb.com/account/api |
| OTX AlienVault | https://otx.alienvault.com/api |
| IPQualityScore | https://www.ipqualityscore.com/user/api-keys |
| Pulsedive | https://pulsedive.com/account/ |
| URLScan.io | https://urlscan.io/user/profile/ |
| Google Gemini | https://aistudio.google.com/app/apikey |

> URLScan.io, PhishTank, EmailRep.io, and LeakCheck.io work with no key (rate-limited). Adding a URLScan key enables live screenshot scans.

---

## 🗂️ File Structure

```
MultiOSINT/
├── MultiOSINT.pyw      # Main application (single file)
├── config.json         # API keys (edit per user, never commit)
└── myicon.ico          # App icon (optional, external)
```

---

## ✅ What's New in v12

- **🌐 Browser History Analyzer** — brand-new mode: parse Edge/Chrome History DBs into browsing + download timelines, correlate downloads by URL and hostname, filter, and export to XLSX (UTC timestamps)
- **4 new OSINT sources** — URLScan.io, PhishTank, EmailRep.io, and LeakCheck.io added to the lookup engine
- **Expanded email enrichment** — EmailRep.io reputation + LeakCheck.io breach lookups alongside XposedOrNot and Breach.VIP
- **URL coverage** — URLScan.io and PhishTank verdicts for URL/domain IOCs
- **URLScan screenshots** — live scan + screenshot preview in the Sandbox/Phishing flow
- **Restructured header** — three top-level mode pills (OSINT Lookup · Phishing Analyzer · Browser History)
- **Batch XLSX export** — process multiple History files in a single run with case/subject labels

---

## 📦 From v11

Everything from the v11 PyQt6 rewrite carries forward: iOS-style UI, light/dark toggle, animated splash screen, IOC navigation (▲ ▼), API key masking, non-blocking Gemini threading, animated tab transitions, fullscreen default, and custom icon support.

---

## 🤝 Contributing

PRs welcome. If you're a SOC analyst with feature ideas, open an issue.

---

## 📜 License

MIT — use it, modify it, make your SOC faster.

---

## 👤 Author

**Barath A C**  
SOC Analyst II
[LinkedIn](https://linkedin.com/in/barath07) · [GitHub](https://github.com/Barath711)
