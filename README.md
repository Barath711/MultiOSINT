Updated todo list

Here's the updated README for v11:

---

# 🔎 MultiOSINT v11

**A desktop threat intelligence platform for SOC analysts.**

Query **14+ OSINT sources** simultaneously — IPs, Domains, URLs, Hashes, and Emails — from a single interface. Triage phishing emails, analyze IOCs, and generate AI-powered summaries without switching tabs.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/UI-PyQt6-41CD52?style=flat&logo=qt&logoColor=white)
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
- Generate a full analyst report with one Gemini AI click

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
- Joe Sandbox detonation for attachments with screenshot preview
- Export full report to HTML

### 🌐 OSINT Navigator
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
- Export results to **TXT** or **CSV**
- Clean results view — errors and "not found" responses suppressed automatically

---

## 🎨 UI Highlights (v11)

- **PyQt6** — replaced CustomTkinter entirely
- **iOS-style design** — smooth animated tab transitions, pill buttons, frosted cards
- **Light / Dark mode toggle** — bottom-right corner, seamless color transitions, light is default
- **Animated circular splash screen** on startup — spinning arc progress indicator
- **Fullscreen by default** — maximized on launch
- Custom `.ico` icon support — just drop `myicon.ico` next to the `.pyw`

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install PyQt6 pillow requests urllib3 python-whois dnspython extract-msg
```

### 2. Run
```bash
pythonw MultiOSINTv11.pyw
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
| Google Gemini | https://aistudio.google.com/app/apikey |

---


## 🗂️ File Structure

```
MultiOSINT/
├── MultiOSINTv11.pyw   # Main application (single file)
├── config.json         # API keys (edit per user, never commit)
└── myicon.ico          # App icon (optional, external)
```

---

## ✅ What's New in v11

- **PyQt6 rewrite** — full iOS-style UI, replaces CustomTkinter
- **Light / Dark mode** with seamless toggle (light default)
- **Animated splash screen** — circular spinning arc on startup
- **IOC navigation (▲ ▼)** in the Navigator tab — step through multiple IOCs without copy-paste
- **API key masking** — all keys hidden by default; Show/Hide toggle
- **Gemini threading** — AI summary runs non-blocking; button locks during generation
- **Animated tab transitions** across all panels
- **Fullscreen default** — maximized on launch
- **Color-coded Navigator headers** — section headings visually distinct from tool buttons
- **Custom icon support** — external `myicon.ico` loaded at runtime

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
