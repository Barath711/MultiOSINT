# 🔎 MultiOSINT

**A desktop threat intelligence aggregator for SOC analysts.**

Query **VirusTotal**, **AbuseIPDB**, and **URLSCAN.io** simultaneously from a single interface. No more tab-switching during active investigations.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## ⚡ Why This Exists

During incident response, analysts constantly copy-paste IOCs between browser tabs—VirusTotal, AbuseIPDB, URLSCAN. It's slow, error-prone, and breaks focus.

**MultiOSINT** eliminates that friction:
- Enter an IP, domain, URL, or hash **once**
- Get results from **all three sources** in parallel
- Results cached to avoid rate limits during high-volume investigations

**Result:** 40% faster IOC lookups. Now adopted as a standard utility across my SOC shift.

---

## 🖥️ Features

| Feature | Description |
|---------|-------------|
| 🔄 **Parallel Queries** | Async API calls to all three services simultaneously |
| 💾 **Result Caching** | Avoid duplicate lookups and rate limit issues |
| 📋 **Quick Copy** | One-click copy of verdicts for ticket documentation |
| 🎨 **Clean GUI** | Built with tkinter—lightweight, no browser needed |
| 🔑 **API Key Config** | Securely store your API keys locally |

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/Barath711/MultiOSINT.git
cd MultiOSINT
```

### 2. Install dependencies
```bash
pip install customtkinter pillow requests urllib3 python-whois dnspython xposedornot
```

### 3. Get your API keys (free tiers work fine)
- [VirusTotal API](https://www.virustotal.com/gui/my-apikey)
- [AbuseIPDB API](https://www.abuseipdb.com/account/api)
- [URLSCAN.io API](https://urlscan.io/user/profile/)

### 4. Run it
```bash
python MultiOSINT.pyw
```

On first run, you'll be prompted to enter your API keys. They're stored locally in `config.json`.

---

## 📸 Screenshot

*Coming soon*

---

## 🔧 Supported IOC Types

| Type | VirusTotal | AbuseIPDB | URLSCAN |
|------|:----------:|:---------:|:-------:|
| IPv4/IPv6 | ✅ | ✅ | ✅ |
| Domain | ✅ | ❌ | ✅ |
| URL | ✅ | ❌ | ✅ |
| File Hash (MD5/SHA1/SHA256) | ✅ | ❌ | ❌ |

---

## 🛣️ Roadmap

- [ ] Add Shodan integration
- [ ] Export results to CSV/JSON
- [ ] Dark mode theme
- [ ] Bulk IOC import from file
- [ ] Integration with MISP/OpenCTI

---

## 🤝 Contributing

PRs welcome! If you're a fellow SOC analyst with feature ideas, open an issue.

---

## 📜 License

MIT License - use it, modify it, make your SOC faster.

---

## 👤 Author

**Barath A C**  
SOC Analyst II @ Deloitte USI  
[LinkedIn](https://linkedin.com/in/barath07) · [GitHub](https://github.com/Barath711)
