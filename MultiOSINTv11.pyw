# -*- coding: utf-8 -*-
"""
OSINT MultiSearch v11
======================
Multi-mode security tool â€” iOS-style PyQt6 UI
  â€¢ OSINT Lookup  â€” IPs, Domains, Hashes, Email addresses
  â€¢ Phishing Analyzer â€” .eml / .msg triage with full enrichment
  â€¢ OSINT Navigator â€” navigate IOCs with â†‘ â†“ arrows

APIs: VirusTotal, AbuseIPDB, URLScan.io, GreyNoise, OTX AlienVault,
      Shodan, abuse.ch, HaveIBeenPwned, Joe Sandbox,
      IPQualityScore, CriminalIP, Pulsedive, Google Gemini AI

Free (no key): ip-api.com, DNS/rDNS, WHOIS, CIRCL.lu HashLookup, PhishTank
"""

# â”€â”€ Splash screen â€” shown immediately using stdlib tkinter only â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# ── Circular animated splash screen (PyQt6) ─────────────────────────────────
import sys as _sys, os as _os

from PyQt6.QtWidgets import QApplication as _QApp, QWidget as _QW
from PyQt6.QtCore    import Qt as _Qt, QTimer as _QTimer, QRect as _QRect
from PyQt6.QtGui     import (QPainter as _QP, QColor as _QCol, QPen as _QPen,
                              QFont as _QFont, QBrush as _QBrush)

_app_qt = _QApp.instance() or _QApp(_sys.argv)
_app_qt.setApplicationName("MultiOSINT v11")


class _CircularSplash(_QW):
    """Animated circular loading splash (GeisielMelo-style)."""
    def __init__(self):
        super().__init__()
        self.setWindowFlags(
            _Qt.WindowType.FramelessWindowHint |
            _Qt.WindowType.WindowStaysOnTopHint |
            _Qt.WindowType.Tool)
        self.setAttribute(_Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(340, 340)
        sg = _app_qt.primaryScreen().availableGeometry()
        self.move((sg.width() - 340) // 2, (sg.height() - 340) // 2)
        self._angle  = 0
        self._pct    = 0
        self._status = "Initializing..."
        self._timer  = _QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)

    def set_status(self, msg: str, bump: int = 15):
        self._status = msg
        self._pct = min(self._pct + bump, 95)
        _app_qt.processEvents()

    def _tick(self):
        self._angle = (self._angle + 3) % 360
        self.update()

    def paintEvent(self, _e):
        p = _QP(self)
        p.setRenderHint(_QP.RenderHint.Antialiasing)
        W, H = self.width(), self.height()
        cx, cy = W // 2, H // 2
        R = 140
        # Dark background circle
        p.setBrush(_QBrush(_QCol("#1C1C1E")))
        p.setPen(_Qt.PenStyle.NoPen)
        p.drawEllipse(cx - R, cy - R, R * 2, R * 2)
        # Outer track ring
        m = 10
        trk = _QPen(_QCol("#3A3A3C"), 9, _Qt.PenStyle.SolidLine, _Qt.PenCapStyle.RoundCap)
        p.setPen(trk); p.setBrush(_Qt.BrushStyle.NoBrush)
        p.drawArc(cx-R+m, cy-R+m, (R-m)*2, (R-m)*2, 0, 360*16)
        # Animated blue arc
        arc = _QPen(_QCol("#0A84FF"), 9, _Qt.PenStyle.SolidLine, _Qt.PenCapStyle.RoundCap)
        p.setPen(arc)
        p.drawArc(cx-R+m, cy-R+m, (R-m)*2, (R-m)*2, (90 - self._angle)*16, -130*16)
        # App title
        p.setPen(_QCol("#F2F2F7"))
        p.setFont(_QFont("Segoe UI", 14, _QFont.Weight.Bold))
        p.drawText(_QRect(0, cy-62, W, 30), _Qt.AlignmentFlag.AlignHCenter, "MultiOSINT")
        # Subtitle
        p.setPen(_QCol("#636366"))
        p.setFont(_QFont("Segoe UI", 9))
        p.drawText(_QRect(0, cy-30, W, 22), _Qt.AlignmentFlag.AlignHCenter, "OSINT Multi-Search")
        # Version badge
        vr = _QRect(cx - 35, cy - 5, 70, 22)
        p.setBrush(_QBrush(_QCol("#2C2C2E"))); p.setPen(_Qt.PenStyle.NoPen)
        p.drawRoundedRect(vr, 11, 11)
        p.setPen(_QCol("#5AC8FA")); p.setFont(_QFont("Segoe UI", 8))
        p.drawText(vr, _Qt.AlignmentFlag.AlignCenter, "v 11.0")
        # Percent
        p.setPen(_QCol("#5AC8FA"))
        p.setFont(_QFont("Segoe UI", 22, _QFont.Weight.Bold))
        p.drawText(_QRect(0, cy+22, W, 44), _Qt.AlignmentFlag.AlignHCenter, f"{self._pct}%")
        # Status text
        p.setPen(_QCol("#8E8E93")); p.setFont(_QFont("Segoe UI", 9))
        p.drawText(_QRect(0, cy+68, W, 22), _Qt.AlignmentFlag.AlignHCenter, self._status)
        p.end()


_splash_win = _CircularSplash()
_splash_win.show()
_app_qt.processEvents()


def _splash_status(msg: str, bump: int = 15):
    _splash_win.set_status(msg, bump)


_splash_status("Loading libraries...", 10)

import re, os, sys, json, csv, socket, threading, time, base64, hashlib
import quopri, traceback, webbrowser, email
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from io import BytesIO
from urllib.parse import urlparse, parse_qs, unquote
from email import policy as _epolicy
from email.parser import BytesParser
from email.header import decode_header, make_header

_splash_status("Loading GUI framework...", 15)
import requests, urllib3
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QPlainTextEdit, QLineEdit,
    QScrollArea, QFrame, QProgressBar, QComboBox, QStackedWidget,
    QGridLayout, QFileDialog, QMessageBox, QSizePolicy, QSplitter,
    QCheckBox, QScrollBar, QGraphicsOpacityEffect)
from PyQt6.QtCore import (
    Qt, QPropertyAnimation, QEasingCurve, QTimer, pyqtSignal,
    QObject, QSize, QPoint, QRect, QByteArray)
from PyQt6.QtGui import (
    QFont, QColor, QPixmap, QTextCursor, QTextCharFormat,
    QIcon, QCursor, QImage, QPainter, QPainterPath, QPen, QBrush)
from PIL import Image

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_splash_status("Loading optional modules...", 10)
try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from xposedornot import XposedOrNot as _XON
    _XON_AVAILABLE = True
except ImportError:
    _XON_AVAILABLE = False

GEMINI_AVAILABLE = True  # uses REST API, no package needed

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import extract_msg as _xmsg
    HAS_MSG = True
except ImportError:
    HAS_MSG = False


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE  = os.path.join(_SCRIPT_DIR, "config.json")

DEFAULT_CONFIG = {
    "virustotal": "", "abuseipdb": "", "urlscan": "",
    "greynoise": "",  "otx": "",       "shodan": "",
    "abusech": "",    "hibp": "",      "joe_key": "",
    "joe_server": "https://jbxcloud.joesecurity.org",
    "gemini_key": "",
    "ipqs": "",        "criminalip": "", "pulsedive": "",
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def save_config(data):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        return str(e)

# ──────────────────────────────────────────────────────
# OSINT MODULE
# ──────────────────────────────────────────────────────
class OSINTModule:
    OSINT_URLS = {
        "virustotal":       "https://www.virustotal.com/gui/search/",
        "talosintelligence":"https://talosintelligence.com/reputation_center/lookup?search=",
        "ibmxforce":        "https://exchange.xforce.ibmcloud.com/search/",
        "shodan":           "https://www.shodan.io/search?query=",
        "ipinfo":           "https://ipinfo.io/",
        "abuseipdb":        "https://www.abuseipdb.com/check/",
        "greynoise":        "https://www.greynoise.io/viz/ip/",
        "hybridanalysis":   "https://www.hybrid-analysis.com/search?query=",
        "urlscan":          "https://urlscan.io/search/#",
        "threatfox":        "https://threatfox.abuse.ch/browse.php?search=ioc%3A",
        "mxtoolbox":        "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a",
        "censys":           "https://search.censys.io/hosts/",
        "otx":              "https://otx.alienvault.com/indicator/",
        "malwarebazaar":    "https://bazaar.abuse.ch/browse.php?search=",
        "pulsedive":        "https://pulsedive.com/indicator/?ioc=",
        "criminalip":       "https://www.criminalip.io/asset/report?ip=",
        "phishtank":        "https://www.phishtank.com/search.php?valid=y&active=y&Search=Search&url=",
        "hashlookup":       "https://hashlookup.circl.lu/lookup/sha256/",
        "ipqs":             "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/",
        "breachvip":        "https://breach.vip/",
        "xposedornot":      "https://xposedornot.com/xposed/#",
    }
    DEFAULT_SOURCES = {
        "domain": ["virustotal","talosintelligence","ibmxforce","urlscan","mxtoolbox","threatfox","pulsedive","phishtank"],
        "ip":     ["virustotal","talosintelligence","abuseipdb","greynoise","shodan","censys","ipinfo","criminalip","pulsedive","ipqs"],
        "hash":   ["virustotal","talosintelligence","ibmxforce","hybridanalysis","threatfox","malwarebazaar","hashlookup","pulsedive"],
        "email":  ["ipqs","breachvip","xposedornot"],
    }

    def __init__(self, config): self.config = config

    @property
    def vt_api_key(self):       return self.config.get("virustotal", "")
    @property
    def abuseipdb_api_key(self): return self.config.get("abuseipdb", "")
    @property
    def urlscan_api_key(self):  return self.config.get("urlscan", "")
    @property
    def greynoise_api_key(self):return self.config.get("greynoise", "")
    @property
    def otx_api_key(self):      return self.config.get("otx", "")
    @property
    def shodan_api_key(self):   return self.config.get("shodan", "")
    @property
    def abusech_api_key(self):  return self.config.get("abusech", "")
    @property
    def hibp_api_key(self):     return self.config.get("hibp", "")
    @property
    def joe_api_key(self):      return self.config.get("joe_key", "")
    @property
    def joe_server(self):       return self.config.get("joe_server", "https://jbxcloud.joesecurity.org")
    @property
    def gemini_key(self):       return self.config.get("gemini_key", "")
    @property
    def ipqs_api_key(self):     return self.config.get("ipqs", "")
    @property
    def criminalip_api_key(self): return self.config.get("criminalip", "")
    @property
    def pulsedive_api_key(self):  return self.config.get("pulsedive", "")


    def check_gemini_summary(self, results_text: str,
                             model: str = "gemini-flash-latest") -> str:
        """Call Gemini via REST API with a comprehensive multi-IOC prompt."""
        key = self.gemini_key
        if not key:
            return "No Gemini API key configured. Add it in Settings."
        prompt = (
            "You are a senior SOC/threat-intelligence analyst.\n"
            "Below is raw OSINT data for one or more indicators (IPs, domains, hashes, emails).\n"
            "Write a COMPREHENSIVE analyst report covering ALL indicators.\n\n"
            "=== RAW OSINT DATA ===\n"
            f"{results_text[:8000]}\n"
            "=== END DATA ===\n\n"
            "Format your response in plain text (no markdown asterisks/bold). "
            "Use these sections:\n\n"
            "OVERALL RISK VERDICT\n"
            "One-line risk score for the entire submission "
            "(e.g. HIGH / MEDIUM / LOW) with a 1-sentence reason.\n\n"
            "INDICATOR BREAKDOWN\n"
            "For EACH indicator, one short paragraph:\n"
            "  - What it is (IP in Russia, domain registered 3 days ago, leaked email, etc.)\n"
            "  - Key threat signals (VT detections, abuse reports, breach count, geo, ISP, etc.)\n"
            "  - Any known campaign / malware family / breach source if identifiable\n\n"
            "KEY FINDINGS (5 bullets)\n"
            "The 5 most important threat indicators across all IOCs.\n\n"
            "RECOMMENDED ACTIONS\n"
            "3-5 specific SOC actions (block, investigate, escalate, notify, etc.).\n\n"
            "ANALYST NOTES\n"
            "Caveats, conflicting signals, data gaps, or further investigation suggestions."
        )
        try:
            url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
                   f"{model}:generateContent")
            resp = requests.post(url,
                headers={"Content-Type": "application/json", "X-goog-api-key": key},
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=90)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            return f"Gemini error: {e}"

    @staticmethod
    def clean_ioc(ioc):
        ioc = ioc.replace("[dot]",".").replace("[.]",".").replace("hxxp","http").replace("hxxps","https")
        ioc = re.sub(r'["\'\[\] ]', '', ioc)
        return ioc.strip().rstrip("/")

    @staticmethod
    def is_hash(ioc):   return bool(re.fullmatch(r"[A-Fa-f0-9]{32,64}", ioc))
    @staticmethod
    def is_ip(ioc):
        return bool(re.fullmatch(
            r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
            r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)", ioc))
    @staticmethod
    def is_email(ioc):  return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", ioc))

    @staticmethod
    def get_ioc_type(ioc):
        if OSINTModule.is_hash(ioc):  return "hash"
        if OSINTModule.is_ip(ioc):    return "ip"
        if OSINTModule.is_email(ioc): return "email"
        return "domain"

    def get_sources(self, ioc_type):
        return self.DEFAULT_SOURCES.get(ioc_type, [])

    def build_url_pairs(self, ioc, sources):
        pairs = []
        for src in sources:
            base = self.OSINT_URLS.get(src, "")
            if not base: continue
            if src == "otx":
                t = {"ip":"ip","domain":"domain","hash":"file"}.get(self.get_ioc_type(ioc),"domain")
                pairs.append((src, f"{base}{t}/{ioc}"))
            else:
                pairs.append((src, base + ioc))
        return pairs

    def open_in_browser(self, iocs):
        for ioc in iocs:
            cleaned  = self.clean_ioc(ioc)
            ioc_type = self.get_ioc_type(cleaned)
            for _, url in self.build_url_pairs(cleaned, self.get_sources(ioc_type)):
                webbrowser.open_new_tab(url)

    # ── VirusTotal ──
    def check_virustotal(self, ioc, ioc_type):
        if not self.vt_api_key: return None
        headers = {"x-apikey": self.vt_api_key}
        api = "https://www.virustotal.com/api/v3"
        r = {k: "" for k in ["malicious","suspicious","harmless","undetected",
            "vt_verdict","vt_error","creation_date","last_analysis_date","registrar","vt_score",
            "threat_label","as_owner","asn","country","network",
            "total_votes_mal","total_votes_ok","reputation",
            "file_type","file_size","file_names","first_seen","categories","last_http_code"]}
        try:
            if ioc_type == "domain":
                url = f"{api}/urls/{base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')}"
            elif ioc_type == "ip":   url = f"{api}/ip_addresses/{ioc}"
            elif ioc_type == "hash": url = f"{api}/files/{ioc}"
            else: r["vt_error"] = "Unknown IOC type."; return r
            resp = requests.get(url, headers=headers, timeout=30, verify=False)
            if resp.status_code == 200:
                attr  = resp.json()["data"]["attributes"]
                stats = attr.get("last_analysis_stats", {})
                mal   = stats.get("malicious", 0); sus = stats.get("suspicious", 0)
                votes = attr.get("total_votes", {})
                r.update({"malicious":mal,"suspicious":sus,"harmless":stats.get("harmless",0),
                    "undetected":stats.get("undetected",0),"vt_score":mal+sus,
                    "vt_verdict":"🔴 MALICIOUS" if mal>0 else "🟡 SUSPICIOUS" if sus>0 else "🟢 Clean",
                    "reputation":attr.get("reputation",""),
                    "total_votes_mal":votes.get("malicious",""),"total_votes_ok":votes.get("harmless","")})
                for field, akey in [("creation_date","creation_date"),
                                    ("last_analysis_date","last_analysis_date"),
                                    ("first_seen","first_submission_date")]:
                    ts = attr.get(akey, "")
                    if ts:
                        try:    r[field] = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC")
                        except: r[field] = str(ts)
                if ioc_type == "ip":
                    r.update({"as_owner":attr.get("as_owner",""),"asn":str(attr.get("asn","")),
                              "country":attr.get("country",""),"network":attr.get("network","")})
                elif ioc_type == "domain":
                    r["registrar"] = attr.get("registrar","")
                    cats = attr.get("categories",{})
                    if cats: r["categories"] = ", ".join(list(set(cats.values()))[:4])
                    r["last_http_code"] = str(attr.get("last_http_response_code",""))
                elif ioc_type == "hash":
                    ptc = attr.get("popular_threat_classification",{})
                    r["threat_label"] = ptc.get("suggested_threat_label","")
                    r["file_type"]    = attr.get("type_description","") or attr.get("magic","")
                    size = attr.get("size","")
                    r["file_size"]    = f"{size:,} bytes" if isinstance(size,int) and size else ""
                    names = attr.get("meaningful_name","") or ""
                    if not names:
                        nl = attr.get("names",[]); names = nl[0] if nl else ""
                    r["file_names"] = names
            elif resp.status_code == 404: r["vt_error"] = "Not found in VT database."
            elif resp.status_code == 401: r["vt_error"] = "VT API key invalid."
            elif resp.status_code == 429: r["vt_error"] = "VT rate limit exceeded."
            else: r["vt_error"] = f"VT API error: HTTP {resp.status_code}"
        except Exception as e: r["vt_error"] = f"VT error: {e}"
        return r

    # ── AbuseIPDB ──
    def check_abuseipdb(self, ioc):
        if not self.abuseipdb_api_key: return None
        r = {k:"" for k in ["abuse_score","total_reports","country","isp",
                             "usage_type","domain","abuse_verdict","abuse_error"]}
        try:
            resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key":self.abuseipdb_api_key,"Accept":"application/json"},
                params={"ipAddress":ioc,"maxAgeInDays":90,"verbose":True},
                timeout=15, verify=False)
            if resp.status_code == 200:
                d = resp.json().get("data",{})
                score = int(d.get("abuseConfidenceScore",0))
                r.update({"abuse_score":score,"total_reports":d.get("totalReports",0),
                    "country":d.get("countryCode",""),"isp":d.get("isp",""),
                    "usage_type":d.get("usageType",""),"domain":d.get("domain",""),
                    "abuse_verdict":"🔴 MALICIOUS" if score>=75 else "🟡 SUSPICIOUS" if score>=25 else "🟢 Clean"})
            elif resp.status_code == 429: r["abuse_error"] = "AbuseIPDB: Rate limit exceeded."
            elif resp.status_code == 401: r["abuse_error"] = "AbuseIPDB: Invalid API key."
            else: r["abuse_error"] = f"AbuseIPDB error: HTTP {resp.status_code}"
        except Exception as e: r["abuse_error"] = f"AbuseIPDB error: {e}"
        return r

    # ── GreyNoise ──
    def check_greynoise(self, ioc):
        if not self.greynoise_api_key: return None
        r = {k:"" for k in ["classification","noise","riot","name","last_seen","gn_verdict","gn_error"]}
        try:
            resp = requests.get(f"https://api.greynoise.io/v3/community/{ioc}",
                headers={"key":self.greynoise_api_key}, timeout=15, verify=False)
            if resp.status_code == 200:
                d = resp.json(); cls = d.get("classification","unknown")
                riot = d.get("riot",False); noise = d.get("noise",False)
                r.update({"classification":cls,"noise":noise,"riot":riot,
                    "name":d.get("name",""),"last_seen":d.get("last_seen",""),
                    "gn_verdict":"🔴 MALICIOUS" if cls=="malicious"
                        else "🟢 RIOT (benign service)" if riot
                        else "🟡 Noise/Unknown" if noise else f"ℹ️ {cls}"})
            elif resp.status_code == 404: r["gn_verdict"] = "🟢 Not seen by GreyNoise"
            elif resp.status_code == 401: r["gn_error"] = "GreyNoise: Invalid API key."
            elif resp.status_code == 429: r["gn_error"] = "GreyNoise: Rate limit exceeded."
            else: r["gn_error"] = f"GreyNoise error: HTTP {resp.status_code}"
        except Exception as e: r["gn_error"] = f"GreyNoise error: {e}"
        return r

    # ── OTX AlienVault ──
    def check_otx(self, ioc, ioc_type):
        if not self.otx_api_key: return None
        r = {k:"" for k in ["pulse_count","malware_families","tags","reputation","otx_verdict","otx_error"]}
        otx_type = {"ip":"IPv4","domain":"domain","hash":"file"}.get(ioc_type,"domain")
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general",
                headers={"X-OTX-API-KEY":self.otx_api_key}, timeout=15, verify=False)
            if resp.status_code == 200:
                d = resp.json()
                pulses = d.get("pulse_info",{}).get("pulses",[])
                cnt = d.get("pulse_info",{}).get("count",len(pulses))
                families = list(set(f.get("name","") for p in pulses
                    for f in (p.get("malware_families") or []) if f.get("name")))[:5]
                tags = list(set(t for p in pulses for t in (p.get("tags") or []) if t))[:5]
                r.update({"pulse_count":cnt,
                    "malware_families":", ".join(families) if families else "None",
                    "tags":", ".join(tags) if tags else "None",
                    "reputation":d.get("reputation",0),
                    "otx_verdict":"🔴 MALICIOUS" if cnt>=5 else "🟡 SUSPICIOUS" if cnt>=1 else "🟢 Clean"})
            elif resp.status_code == 404: r["otx_verdict"] = "🟢 Not found in OTX"
            elif resp.status_code == 403: r["otx_error"] = "OTX: Invalid API key."
            else: r["otx_error"] = f"OTX error: HTTP {resp.status_code}"
        except Exception as e: r["otx_error"] = f"OTX error: {e}"
        return r

    # ── Shodan ──
    def check_shodan(self, ioc):
        if not self.shodan_api_key: return None
        r = {k:"" for k in ["org","country","ports","vulns","os","hostnames","tags","shodan_error"]}
        try:
            resp = requests.get(f"https://api.shodan.io/shodan/host/{ioc}",
                params={"key":self.shodan_api_key}, timeout=15, verify=False)
            if resp.status_code == 200:
                d = resp.json()
                r.update({"org":d.get("org",""),"country":d.get("country_name",""),
                    "ports":", ".join(str(p) for p in sorted(d.get("ports",[]))[:20]),
                    "vulns":", ".join(list(d.get("vulns",{}).keys())[:5]) or "None",
                    "os":d.get("os","") or "Unknown",
                    "hostnames":", ".join(d.get("hostnames",[])[:5]),
                    "tags":", ".join(d.get("tags",[])[:5])})
            elif resp.status_code == 404: r["shodan_error"] = "Shodan: No data for this IP."
            elif resp.status_code == 401: r["shodan_error"] = "Shodan: Invalid API key."
            elif resp.status_code == 429: r["shodan_error"] = "Shodan: Rate limit exceeded."
            else: r["shodan_error"] = f"Shodan error: HTTP {resp.status_code}"
        except Exception as e: r["shodan_error"] = f"Shodan error: {e}"
        return r

    # ── XposedOrNot (free breach check — no API key required) ──
    def check_hibp(self, email_addr):
        r = {"breaches": [], "breach_count": 0, "xon_verdict": "", "xon_error": ""}
        try:
            if _XON_AVAILABLE:
                xon = _XON()
                # check_email returns breaches as list-of-lists, flatten
                chk = xon.check_email(email_addr)
                breach_names = []
                for item in (chk.breaches or []):
                    if isinstance(item, list):  breach_names.extend(item)
                    else:                       breach_names.append(str(item))
                # get details via breach_analytics
                details_map = {}
                try:
                    analytics = xon.breach_analytics(email_addr)
                    for bd in (analytics.breaches_details or []):
                        details_map[bd.breach] = bd
                except Exception:
                    pass
                r["breach_count"] = len(breach_names)
                breaches_out = []
                for name in breach_names[:20]:
                    bd = details_map.get(name)
                    breaches_out.append({
                        "name":        name,
                        "domain":      getattr(bd, "domain", ""),
                        "date":        getattr(bd, "xposed_date", ""),
                        "records":     getattr(bd, "xposed_records", 0),
                        "data_classes":getattr(bd, "xposed_data", "").replace(";", ", "),
                        "industry":    getattr(bd, "industry", ""),
                        "password_risk": getattr(bd, "password_risk", ""),
                    })
                r["breaches"] = breaches_out
                r["xon_verdict"] = (
                    f"🔴 EXPOSED — found in {r['breach_count']} breach(es)"
                    if r["breach_count"] > 0
                    else "🟢 Not found in any known breaches (XposedOrNot)")
            else:
                # fallback REST
                from urllib.parse import quote
                resp = requests.get(
                    f"https://api.xposedornot.com/v1/check-email/{quote(email_addr)}",
                    headers={"User-Agent": "OSINTMultiSearch-v8"}, timeout=15)
                if resp.status_code == 404:
                    r["xon_verdict"] = "🟢 Not found in any known breaches (XposedOrNot)"
                    return r
                if resp.status_code != 200:
                    r["xon_error"] = f"XposedOrNot HTTP {resp.status_code}"; return r
                d = resp.json()
                breach_str = d.get("Breaches") or d.get("breaches") or ""
                if isinstance(breach_str, str) and breach_str:
                    names = [b.strip() for b in breach_str.split(";") if b.strip()]
                    r["breach_count"] = len(names)
                    r["breaches"] = [{"name": n} for n in names[:20]]
                    r["xon_verdict"] = f"🔴 EXPOSED — found in {r['breach_count']} breach(es)"
                else:
                    r["xon_verdict"] = "🟢 Not found in any known breaches (XposedOrNot)"
        except Exception as e:
            r["xon_error"] = f"XposedOrNot error: {e}"
        return r

    # ── Breach.VIP (free — no API key required, 15 req/min) ──
    def check_breachvip(self, ioc, field_type="email"):
        """Search breach.vip for an email, domain, IP, or username in breach databases."""
        r = {"bvip_results": [], "bvip_count": 0, "bvip_verdict": "", "bvip_error": ""}
        try:
            resp = requests.post(
                "https://breach.vip/api/search",
                json={"term": ioc, "fields": [field_type]},
                timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                r["bvip_count"] = len(results)
                r["bvip_results"] = [
                    {"source": item.get("source","?"),
                     "categories": item.get("categories",""),
                     "extra": {k: v for k, v in item.items() if k not in ("source","categories")}}
                    for item in results[:30]
                ]
                if results:
                    r["bvip_verdict"] = f"🔴 EXPOSED — found in {len(results)} breach source(s)"
                else:
                    r["bvip_verdict"] = "🟢 Not found in breach.vip database"
            elif resp.status_code == 429:
                r["bvip_error"] = "breach.vip: Rate limited (15 req/min)"
            else:
                r["bvip_error"] = f"breach.vip HTTP {resp.status_code}"
        except Exception as e:
            r["bvip_error"] = f"breach.vip error: {e}"
        return r
    def check_ipapi(self, ioc):
        r = {k:"" for k in ["country","region","city","isp","org","asn","timezone","proxy","hosting","ipapi_error"]}
        try:
            resp = requests.get(f"http://ip-api.com/json/{ioc}",
                params={"fields":"status,message,country,regionName,city,isp,org,as,timezone,proxy,hosting"},
                timeout=10)
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    r.update({"country":d.get("country",""),"region":d.get("regionName",""),
                        "city":d.get("city",""),"isp":d.get("isp",""),"org":d.get("org",""),
                        "asn":d.get("as",""),"timezone":d.get("timezone",""),
                        "proxy":"⚠️ Yes" if d.get("proxy") else "No",
                        "hosting":"☁️ Yes" if d.get("hosting") else "No"})
                else: r["ipapi_error"] = d.get("message","ip-api.com query failed")
            else: r["ipapi_error"] = f"ip-api.com error: HTTP {resp.status_code}"
        except Exception as e: r["ipapi_error"] = f"ip-api.com error: {e}"
        return r

    # ── Free: DNS ──
    def check_dns(self, domain):
        r = {"a_records":[],"aaaa_records":[],"ptr":"","mx":[],"ns":[],"txt":[],"cname":[],"dns_error":""}
        try:
            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET)
                r["a_records"] = list(set(i[4][0] for i in infos))
            except Exception: pass
            try:
                infos6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
                r["aaaa_records"] = list(set(i[4][0] for i in infos6))
            except Exception: pass
            if DNS_AVAILABLE:
                for rtype, key, fmt in [
                    ("MX","mx", lambda a:[str(x.exchange).rstrip(".") for x in a]),
                    ("NS","ns", lambda a:[str(x).rstrip(".") for x in a]),
                    ("CNAME","cname",lambda a:[str(x.target).rstrip(".") for x in a]),
                    ("TXT","txt", lambda a:[" ".join(b.decode() if isinstance(b,bytes) else str(b)
                                             for b in x.strings) for x in a]),
                ]:
                    try:
                        r[key] = fmt(dns.resolver.resolve(domain, rtype, lifetime=5))
                    except Exception: pass
        except Exception as e: r["dns_error"] = str(e)
        return r

    @staticmethod
    def check_reverse_dns(ip):
        try: return socket.gethostbyaddr(ip)[0]
        except: return ""

    # ── Free: WHOIS ──
    def check_whois(self, ioc):
        r = {"whois_data":"","whois_error":""}
        if not WHOIS_AVAILABLE:
            r["whois_error"] = "python-whois not installed.  pip install python-whois"; return r
        try:
            w = whois_lib.whois(ioc)
            lines = []
            for k in ["domain_name","registrar","creation_date","expiration_date","updated_date",
                      "name_servers","emails","country","org","address","city","state"]:
                v = w.get(k)
                if v:
                    if isinstance(v,list): v = ", ".join(str(i) for i in v[:3])
                    lines.append(f"  {k:<28} {v}")
            r["whois_data"] = "\n".join(lines) if lines else "  No WHOIS data returned."
        except Exception as e: r["whois_error"] = f"WHOIS error: {e}"
        return r

    # ── abuse.ch: URLhaus ──
    def check_urlhaus(self, ioc, ioc_type):
        r = {"uh_status":"","uh_threat":"","uh_tags":"","uh_urls":0,"uh_error":""}
        auth = {"Auth-Key": self.abusech_api_key} if self.abusech_api_key else {}
        try:
            if ioc_type == "hash":
                pl = {"sha256_hash":ioc} if len(ioc)==64 else {"md5_hash":ioc}
                resp = requests.post("https://urlhaus-api.abuse.ch/v1/payload/",
                    headers=auth, data=pl, timeout=10, verify=False)
            else:
                resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                    headers=auth, data={"host":ioc}, timeout=10, verify=False)
            if resp.status_code == 200:
                d = resp.json(); status = d.get("query_status","")
                r["uh_status"] = status
                if status == "no_results": r["uh_threat"] = "🟢 Not found in URLhaus"
                elif status in ("is_host","ok","is_payload"):
                    urls = d.get("urls", d.get("url_list",[]))
                    r["uh_urls"] = len(urls)
                    threats = list(set(u.get("threat","") for u in urls if u.get("threat")))
                    all_tags = list(set(t for u in urls for t in (u.get("tags") or []) if t))
                    r["uh_threat"] = ("🔴 "+" ,".join(threats)) if threats else "🟡 Listed in URLhaus"
                    r["uh_tags"]   = ", ".join(all_tags[:6])
                else: r["uh_threat"] = f"ℹ️ URLhaus: {status}"
            elif resp.status_code in (401, 403):
                r["uh_error"] = "URLhaus: Register for a free API key at auth.abuse.ch"
            else: r["uh_error"] = f"URLhaus error: HTTP {resp.status_code}"
        except Exception as e: r["uh_error"] = f"URLhaus error: {e}"
        return r

    # ── abuse.ch: MalwareBazaar ──
    def check_malwarebazaar(self, hash_val):
        r = {k:"" for k in ["mb_file_name","mb_file_type","mb_signature","mb_tags","mb_first_seen","mb_verdict","mb_error"]}
        auth = {"Auth-Key": self.abusech_api_key} if self.abusech_api_key else {}
        try:
            resp = requests.post("https://mb-api.abuse.ch/api/v1/",
                headers=auth,
                data={"query":"get_info","hash":hash_val}, timeout=10, verify=False)
            if resp.status_code == 200:
                d = resp.json(); status = d.get("query_status","")
                if status == "hash_not_found": r["mb_verdict"] = "🟢 Not found in MalwareBazaar"
                elif status == "ok":
                    info = (d.get("data") or [{}])[0]; sig = info.get("signature") or ""
                    r.update({"mb_file_name":info.get("file_name",""),"mb_file_type":info.get("file_type",""),
                        "mb_signature":sig,"mb_tags":", ".join(info.get("tags") or []),
                        "mb_first_seen":info.get("first_seen",""),
                        "mb_verdict":f"🔴 MALWARE: {sig}" if sig else "🔴 Found in MalwareBazaar"})
                else: r["mb_error"] = f"MalwareBazaar: {status}"
            elif resp.status_code in (401, 403):
                r["mb_error"] = "MalwareBazaar: Register for a free API key at auth.abuse.ch"
            else: r["mb_error"] = f"MalwareBazaar error: HTTP {resp.status_code}"
        except Exception as e: r["mb_error"] = f"MalwareBazaar error: {e}"
        return r

    # ── abuse.ch: ThreatFox ──
    def check_threatfox(self, ioc):
        r = {k:"" for k in ["tf_ioc_type","tf_threat_type","tf_malware","tf_confidence","tf_tags","tf_verdict","tf_error"]}
        auth = {"Auth-Key": self.abusech_api_key} if self.abusech_api_key else {}
        try:
            resp = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                headers=auth,
                json={"query":"search_ioc","search_term":ioc}, timeout=10, verify=False)
            if resp.status_code == 200:
                d = resp.json(); status = d.get("query_status","")
                if status == "no_result": r["tf_verdict"] = "🟢 Not found in ThreatFox"
                elif status == "ok":
                    items = d.get("data") or []
                    if items:
                        item = items[0]; malware = item.get("malware_printable") or item.get("malware","")
                        conf = item.get("confidence_level",0) or 0
                        r.update({"tf_ioc_type":item.get("ioc_type",""),"tf_threat_type":item.get("threat_type",""),
                            "tf_malware":malware,"tf_confidence":f"{conf}%",
                            "tf_tags":", ".join(item.get("tags") or []),
                            "tf_verdict":(f"🔴 {malware} ({conf}% confidence)" if conf>=50
                                          else f"🟡 {malware or 'Listed in ThreatFox'}")})
                    else: r["tf_verdict"] = "🟢 Not found in ThreatFox"
                else: r["tf_error"] = f"ThreatFox: {status}"
            elif resp.status_code in (401, 403):
                r["tf_error"] = "ThreatFox: Register for a free API key at auth.abuse.ch"
            else: r["tf_error"] = f"ThreatFox error: HTTP {resp.status_code}"
        except Exception as e: r["tf_error"] = f"ThreatFox error: {e}"
        return r

    # ── IPQualityScore ──
    def check_ipqs(self, ioc, ioc_type):
        if not self.ipqs_api_key: return None
        r = {k:"" for k in ["ipqs_score","ipqs_vpn","ipqs_proxy","ipqs_tor","ipqs_bot",
                             "ipqs_disposable","ipqs_fraud_score","ipqs_verdict","ipqs_error"]}
        try:
            from urllib.parse import quote as _q
            if ioc_type == "ip":
                url = f"https://ipqualityscore.com/api/json/ip/{self.ipqs_api_key}/{ioc}"
                params = {"strictness": 1}
            elif ioc_type == "email":
                url = f"https://ipqualityscore.com/api/json/email/{self.ipqs_api_key}/{_q(ioc)}"
                params = {"strictness": 1, "fast": "true"}
            elif ioc_type in ("domain", "url"):
                url = f"https://ipqualityscore.com/api/json/url/{self.ipqs_api_key}/{_q(ioc)}"
                params = {"strictness": 1}
            else:
                r["ipqs_error"] = "IPQS: unsupported IOC type"; return r
            resp = requests.get(url, params=params, timeout=15, verify=False)
            if resp.status_code == 200:
                d = resp.json()
                if not d.get("success", True):
                    r["ipqs_error"] = d.get("message", "IPQS request failed"); return r
                score = d.get("fraud_score", d.get("overall_score", 0))
                r["ipqs_fraud_score"] = score
                if ioc_type == "ip":
                    r.update({"ipqs_vpn": "⚠️ Yes" if d.get("vpn") else "No",
                               "ipqs_proxy": "⚠️ Yes" if d.get("proxy") else "No",
                               "ipqs_tor": "🔴 Yes" if d.get("tor") else "No",
                               "ipqs_bot": "🔴 Yes" if d.get("bot_status") else "No"})
                elif ioc_type == "email":
                    r.update({"ipqs_disposable": "🔴 Yes" if d.get("disposable") else "No",
                               "ipqs_score": d.get("fraud_score", "")})
                r["ipqs_verdict"] = ("🔴 HIGH RISK" if score >= 85
                                     else "🟡 SUSPICIOUS" if score >= 50
                                     else "🟢 Clean")
            elif resp.status_code == 401: r["ipqs_error"] = "IPQS: Invalid API key."
            elif resp.status_code == 429: r["ipqs_error"] = "IPQS: Rate limit exceeded."
            else: r["ipqs_error"] = f"IPQS error: HTTP {resp.status_code}"
        except Exception as e: r["ipqs_error"] = f"IPQS error: {e}"
        return r

    # ── CriminalIP ──
    def check_criminalip(self, ioc):
        if not self.criminalip_api_key: return None
        r = {k:"" for k in ["cip_score","cip_type","cip_country","cip_org","cip_open_ports",
                             "cip_cves","cip_tags","cip_verdict","cip_error"]}
        try:
            resp = requests.get("https://api.criminalip.io/v1/asset/ip/report",
                headers={"x-api-key": self.criminalip_api_key},
                params={"ip": ioc}, timeout=20, verify=False)
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == 200:
                    score = d.get("score", {}).get("inbound", 0) or 0
                    ip_data = d.get("ip", {}) or {}
                    issues = d.get("issues", {}) or {}
                    port_data = d.get("port", {}).get("data", []) or []
                    ports = ", ".join(str(p.get("open_port_no","")) for p in port_data[:10] if p.get("open_port_no"))
                    cves_raw = []
                    for p in port_data[:5]:
                        for cv in (p.get("vulnerability_info") or [])[:2]:
                            cves_raw.append(cv.get("cve_id",""))
                    tags = [k for k, v in issues.items() if v]
                    r.update({"cip_score": score,
                               "cip_type": ip_data.get("type",""),
                               "cip_country": ip_data.get("country",""),
                               "cip_org": ip_data.get("org",""),
                               "cip_open_ports": ports,
                               "cip_cves": ", ".join(cves_raw[:5]) or "None",
                               "cip_tags": ", ".join(tags[:5]),
                               "cip_verdict": ("🔴 CRITICAL" if score >= 80
                                               else "🟡 SUSPICIOUS" if score >= 40
                                               else "🟢 Clean")})
                else:
                    r["cip_error"] = d.get("message", f"CriminalIP error: {d.get('status')}")
            elif resp.status_code == 401: r["cip_error"] = "CriminalIP: Invalid API key."
            elif resp.status_code == 429: r["cip_error"] = "CriminalIP: Rate limit exceeded."
            else: r["cip_error"] = f"CriminalIP error: HTTP {resp.status_code}"
        except Exception as e: r["cip_error"] = f"CriminalIP error: {e}"
        return r

    # ── CIRCL.lu HashLookup (free, no key) ──
    def check_hashlookup(self, hash_val):
        r = {k:"" for k in ["hl_filename","hl_filetype","hl_known","hl_parents",
                             "hl_verdict","hl_error"]}
        try:
            hlen = len(hash_val)
            if hlen == 32:   endpoint = f"https://hashlookup.circl.lu/lookup/md5/{hash_val}"
            elif hlen == 40: endpoint = f"https://hashlookup.circl.lu/lookup/sha1/{hash_val}"
            elif hlen == 64: endpoint = f"https://hashlookup.circl.lu/lookup/sha256/{hash_val}"
            else:
                r["hl_error"] = "HashLookup: unsupported hash length"; return r
            resp = requests.get(endpoint, timeout=10, verify=False,
                                headers={"Accept": "application/json"})
            if resp.status_code == 200:
                d = resp.json()
                r.update({"hl_filename": (d.get("FileName") or d.get("name",""))[:60],
                           "hl_filetype": d.get("FileType","") or d.get("mime-type",""),
                           "hl_known": "✅ Known-Good (NSRL)",
                           "hl_verdict": "🟢 Known-Good file (NSRL HashLookup)"})
                parents = d.get("parents", [])
                r["hl_parents"] = str(len(parents)) if parents else ""
            elif resp.status_code == 404:
                r["hl_verdict"] = "⬜ Not in HashLookup DB (unknown hash)"
                r["hl_known"] = "Unknown"
            else:
                r["hl_error"] = f"HashLookup HTTP {resp.status_code}"
        except Exception as e: r["hl_error"] = f"HashLookup error: {e}"
        return r

    # ── Pulsedive ──
    def check_pulsedive(self, ioc, ioc_type):
        r = {k:"" for k in ["pd_risk","pd_type","pd_threats","pd_feeds","pd_tags",
                             "pd_lastseen","pd_verdict","pd_error"]}
        try:
            params = {"ioc": ioc, "pretty": "1"}
            if self.pulsedive_api_key:
                params["key"] = self.pulsedive_api_key
            resp = requests.get("https://pulsedive.com/api/info.php",
                params=params, timeout=15, verify=False)
            if resp.status_code == 200:
                d = resp.json()
                if d.get("error"):
                    r["pd_verdict"] = "🟢 Not found in Pulsedive"; return r
                risk = d.get("risk", "unknown") or "unknown"
                threats = [t.get("name","") for t in (d.get("threats") or [])[:5] if t.get("name")]
                feeds   = [f.get("name","") for f in (d.get("feeds")   or [])[:5] if f.get("name")]
                tags    = [t.get("tag","")  for t in (d.get("tags")    or [])[:5] if t.get("tag")]
                r.update({"pd_risk": risk,
                           "pd_type": d.get("type",""),
                           "pd_threats": ", ".join(threats) or "None",
                           "pd_feeds":   ", ".join(feeds)   or "None",
                           "pd_tags":    ", ".join(tags)    or "None",
                           "pd_lastseen": d.get("stamp_updated",""),
                           "pd_verdict": ("🔴 HIGH" if risk in ("high","critical","very high")
                                          else "🟡 MEDIUM" if risk in ("medium","suspicious","unknown","none")
                                          else "🟢 Low")})
            elif resp.status_code == 404:
                r["pd_verdict"] = "🟢 Not found in Pulsedive"
            elif resp.status_code == 429:
                r["pd_error"] = "Pulsedive: Rate limit exceeded."
            else:
                r["pd_error"] = f"Pulsedive error: HTTP {resp.status_code}"
        except Exception as e: r["pd_error"] = f"Pulsedive error: {e}"
        return r

    # ── PhishTank (free, no key required) ──
    def check_phishtank(self, url_or_domain):
        r = {k:"" for k in ["pt_in_database","pt_verified","pt_phish_detail_url","pt_verdict","pt_error"]}
        try:
            target = url_or_domain if url_or_domain.startswith("http") else f"http://{url_or_domain}"
            resp = requests.post("https://checkurl.phishtank.com/checkurl/",
                data={"url": target, "format": "json", "app_key": ""},
                headers={"User-Agent": "OSINTMultiSearch-v10"},
                timeout=15, verify=False)
            if resp.status_code == 200:
                d = resp.json().get("results", {})
                in_db    = d.get("in_database", False)
                verified = d.get("verified", False)
                detail   = d.get("phish_detail_url", "")
                r.update({"pt_in_database": "Yes" if in_db else "No",
                           "pt_verified":   "Yes" if verified else "No",
                           "pt_phish_detail_url": detail,
                           "pt_verdict": ("🔴 PHISHING (verified)" if (in_db and verified)
                                          else "🟡 In PhishTank DB (unverified)" if in_db
                                          else "🟢 Not in PhishTank")})
            else:
                r["pt_error"] = f"PhishTank error: HTTP {resp.status_code}"
        except Exception as e: r["pt_error"] = f"PhishTank error: {e}"
        return r

    # ── URLScan.io Screenshot ──
    def urlscan_screenshot(self, domain, callback):
        if not self.urlscan_api_key:
            callback(None, "No URLScan API key — add one in Settings.", None, None); return
        headers = {"API-Key":self.urlscan_api_key,"Content-Type":"application/json"}
        target  = domain if domain.startswith("http") else f"https://{domain}"
        try:
            resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers,
                json={"url":target,"visibility":"public"}, timeout=15, verify=False)
            if resp.status_code not in (200,201):
                try:    msg = resp.json().get("message",f"HTTP {resp.status_code}")
                except: msg = f"HTTP {resp.status_code}"
                callback(None, f"URLScan submit failed: {msg}", None, None); return
            uuid = resp.json().get("uuid")
            if not uuid: callback(None,"URLScan did not return a scan UUID.",None,None); return
            result_api = f"https://urlscan.io/api/v1/result/{uuid}/"
            result_hdrs = {"API-Key": self.urlscan_api_key}
            for _ in range(25):
                time.sleep(3)
                r = requests.get(result_api, headers=result_hdrs, timeout=15, verify=False)
                if r.status_code == 200: break
                if r.status_code != 404:
                    callback(None, f"URLScan result error: HTTP {r.status_code}", None, None); return
            else:
                callback(None, "URLScan result not ready after 75 s.", None, None); return
            data = r.json()
            ss_url     = data.get("task",{}).get("screenshotURL")
            doc_url    = data.get("page",{}).get("url","")
            report_url = data.get("task",{}).get("reportURL","")
            if not ss_url:
                callback(None, "No screenshot URL in URLScan result.", doc_url, report_url); return
            img_resp = requests.get(ss_url, timeout=15, verify=False)
            if img_resp.status_code == 200:
                callback(img_resp.content, None, doc_url, report_url)
            else:
                callback(None, f"Screenshot download failed: HTTP {img_resp.status_code}", doc_url, report_url)
        except Exception as e: callback(None, f"URLScan error: {e}", None, None)

# ══════════════════════════════════════════════════════════════════
# PHISHING ENGINE  (EML/MSG parsing, URL deobfuscation, enrichment)
# ══════════════════════════════════════════════════════════════════

_IP_RE  = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_URL_RE = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.I)
_SL_DOMAINS = {
    "safelinks.protection.outlook.com","nam01.safelinks.protection.outlook.com",
    "nam02.safelinks.protection.outlook.com","nam04.safelinks.protection.outlook.com",
    "eur01.safelinks.protection.outlook.com","eur02.safelinks.protection.outlook.com",
    "apac01.safelinks.protection.outlook.com",
}
PHISH_KW = [
    "verify your account","confirm your account","update your information",
    "click here","click below","click the link","your account will be",
    "account suspended","account compromised","unusual activity",
    "unauthorized access","suspicious activity","verify now","act now",
    "action required","immediate action","your password","reset your password",
    "won a prize","you have been selected","invoice attached","payment overdue",
    "expir","expire","expiring","wire transfer","urgent",
]

def _ph_private(ip):
    try:
        p = list(map(int, ip.split(".")))
        return (p[0]==10 or p[0]==127 or (p[0]==172 and 16<=p[1]<=31)
                or (p[0]==192 and p[1]==168) or (p[0]==169 and p[1]==254))
    except: return False

def _ph_email_addr(v):
    if not v: return None
    m = re.search(r'[\w.+-]+@[\w.-]+', v)
    return m.group(0).lower() if m else None

def _ph_domain_of(addr):
    return addr.split("@",1)[1].lower() if addr and "@" in addr else None

def _ph_h(msg, name):
    val = msg.get(name)
    if val is None: return None
    try:    return str(make_header(decode_header(val))).strip()
    except: return str(val).strip()

def _ph_hall(msg, name):
    vals = msg.get_all(name) or []; out = []
    for v in vals:
        try:    out.append(str(make_header(decode_header(v))).strip())
        except: out.append(str(v).strip())
    return out

def _ph_auth(direct, auth_raw, proto):
    for src in [direct, auth_raw]:
        if not src: continue
        lv = src.lower()
        for kw in ("pass","fail","softfail","none","neutral","temperror","permerror"):
            if proto in lv and kw in lv:
                m = re.search(rf'(?:^|[\s;]){re.escape(proto)}[^\s]*\s*=\s*(\w+)', src, re.I)
                if m: return m.group(1).lower()
                if kw in lv: return kw
    return None

def _ph_scan_keywords(text):
    if not text: return []
    tl = text.lower(); seen = set(); out = []
    for kw in PHISH_KW:
        if kw in tl and kw not in seen: seen.add(kw); out.append(kw)
    return out

def _ph_valid_url(url):
    if not url or len(url) < 10: return False
    try:
        h = urlparse(url).hostname or ""
        return bool(h) and "=" not in h and "." in h and re.match(r'^[a-zA-Z0-9.\-]+$', h)
    except: return False

def _ph_extract_urls(text):
    if not text: return []
    clean = re.sub(r'=\r?\n', '', text); seen = set(); out = []
    for url in _URL_RE.findall(clean):
        url = re.sub(r'[.,;:)\]}>\'\"]+$','',url).replace("&amp;","&").replace("&#61;","=")
        if _ph_valid_url(url) and url not in seen:
            seen.add(url); out.append(url)
    return out

def _ph_sender_ip(received):
    if not received: return None
    for hdr in reversed(received):
        for ip in _IP_RE.findall(hdr):
            if not _ph_private(ip): return ip
    return None

def _ph_part_bytes(part):
    try:
        d = part.get_payload(decode=True)
        if d is not None: return d
        d = part.get_payload(decode=False)
        return d.encode("utf-8","replace") if isinstance(d,str) else None
    except: return None

def _ph_part_text(part):
    try:
        raw = part.get_payload(decode=True)
        if raw is None:
            s = part.get_payload(decode=False)
            if isinstance(s,str):
                if "=\r\n" in s or "=\n" in s:
                    try: return quopri.decodestring(s.encode("ascii","replace")).decode("ascii","replace")
                    except: pass
                return re.sub(r'=\r?\n','',s)
            return None
        cs = part.get_content_charset() or "utf-8"
        try:    return raw.decode(cs, errors="replace")
        except: return raw.decode("utf-8", errors="replace")
    except: return None

def _ph_extract_body(msg):
    body_text = ""; body_html = ""; attachments = []
    for part in msg.walk():
        ct   = part.get_content_type()
        disp = str(part.get("Content-Disposition") or "")
        fname = part.get_filename() or ""
        if "attachment" in disp.lower() or fname:
            data = _ph_part_bytes(part)
            if data:
                attachments.append({"filename":fname,"content_type":ct,"size":len(data),
                    "md5":hashlib.md5(data).hexdigest(),"sha256":hashlib.sha256(data).hexdigest()})
            continue
        if ct == "text/plain":
            t = _ph_part_text(part);  body_text += (t+"\n") if t else ""
        elif ct == "text/html":
            t = _ph_part_text(part);  body_html += (t+"\n") if t else ""
    return body_text.strip(), body_html.strip(), attachments

def _ph_extract_all(msg):
    auth_raw = _ph_h(msg,"Authentication-Results") or _ph_h(msg,"ARC-Authentication-Results")
    received = _ph_hall(msg,"Received")
    dkim_sig = _ph_h(msg,"DKIM-Signature") or ""
    dkim_dom = None
    m = re.search(r'd=([^\s;]+)', dkim_sig)
    if m: dkim_dom = m.group(1).strip().rstrip(";")
    body_text, body_html, attachments = _ph_extract_body(msg)
    combined = (body_html or "") + "\n" + (body_text or "")
    urls     = _ph_extract_urls(combined)
    keywords = _ph_scan_keywords((body_text or "") + (body_html or ""))
    from_addr = _ph_email_addr(_ph_h(msg,"From") or "")
    rp_addr   = _ph_email_addr(_ph_h(msg,"Reply-To") or "")
    rt_addr   = _ph_email_addr(_ph_h(msg,"Return-Path") or "")
    ff = _ph_h(msg,"X-Forefront-Antispam-Report"); scl = None
    for src in [ff, _ph_h(msg,"X-Microsoft-Antispam")]:
        if src:
            m2 = re.search(r'SCL:(\d+)', src)
            if m2: scl = m2.group(1); break
    mismatches = []
    fd = _ph_domain_of(from_addr)
    if fd:
        for label, addr in [("Reply-To",rp_addr),("Return-Path",rt_addr)]:
            d = _ph_domain_of(addr)
            if d and d != fd: mismatches.append({"type":label,"from":fd,"other":d})
    return {"subject":_ph_h(msg,"Subject"),"from":_ph_h(msg,"From"),"to":_ph_h(msg,"To"),
        "cc":_ph_h(msg,"CC"),"reply_to":_ph_h(msg,"Reply-To"),"return_path":_ph_h(msg,"Return-Path"),
        "sender":_ph_h(msg,"Sender"),"date":_ph_h(msg,"Date"),
        "message_id":_ph_h(msg,"Message-ID"),"delivered_to":_ph_h(msg,"Delivered-To"),
        "spf":_ph_auth(_ph_h(msg,"Received-SPF"),auth_raw,"spf"),
        "dkim":_ph_auth(None,auth_raw,"dkim"),"dmarc":_ph_auth(None,auth_raw,"dmarc"),
        "arc":_ph_auth(None,_ph_h(msg,"ARC-Authentication-Results"),"arc"),
        "auth_results_raw":auth_raw,"received_spf":_ph_h(msg,"Received-SPF"),
        "sender_ip":_ph_sender_ip(received),"x_originating_ip":_ph_h(msg,"X-Originating-IP"),
        "x_mailer":_ph_h(msg,"X-Mailer") or _ph_h(msg,"User-Agent"),
        "dkim_domain":dkim_dom,"scl":scl,"forefront_antispam":ff,
        "ms_antispam":_ph_h(msg,"X-Microsoft-Antispam"),
        "body_text":body_text,"body_html":body_html,"urls":urls,"keywords":keywords,
        "attachments":attachments,"received_headers":received,"domain_mismatches":mismatches}

def parse_eml(filepath):
    with open(filepath, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"): raw = raw[3:]
    nl = raw.find(b"\n")
    if nl > 0 and raw[:nl].startswith(b"From ") and b"@" not in raw[:nl][:50]:
        raw = raw[nl+1:]
    for strategy in [
        lambda r: _ph_extract_all(BytesParser(policy=_epolicy.compat32).parsebytes(r)),
        lambda r: _ph_extract_all(BytesParser(policy=_epolicy.default).parsebytes(r)),
        lambda r: _ph_extract_all(email.message_from_string(r.decode("utf-8","replace"))),
    ]:
        try:
            result = strategy(raw)
            if result and (result.get("from") or result.get("subject")): return result
        except Exception: pass
    return {}

def parse_msg(filepath):
    if not HAS_MSG:
        return {"_error": "extract-msg not installed. Run: pip install extract-msg"}
    try:
        msg = _xmsg.openMsg(filepath)
        body_text = msg.body or ""; body_html = msg.htmlBody or (msg.body or "")
        if isinstance(body_html, bytes): body_html = body_html.decode("utf-8","replace")
        if isinstance(body_text, bytes): body_text = body_text.decode("utf-8","replace")
        combined = body_html + "\n" + body_text
        attachments = []
        for att in (msg.attachments or []):
            fn   = getattr(att,"longFilename",None) or getattr(att,"shortFilename","")
            data = getattr(att,"data",b"") or b""
            if data: attachments.append({"filename":fn,"content_type":"application/octet-stream",
                "size":len(data),"md5":hashlib.md5(data).hexdigest(),"sha256":hashlib.sha256(data).hexdigest()})
        return {"subject":msg.subject,"from":msg.sender,"to":msg.to,"cc":msg.cc,
            "date":str(msg.date) if msg.date else None,"reply_to":None,"return_path":None,
            "sender":msg.sender,"message_id":None,"delivered_to":None,
            "spf":None,"dkim":None,"dmarc":None,"arc":None,
            "auth_results_raw":None,"received_spf":None,"sender_ip":None,"x_originating_ip":None,
            "x_mailer":None,"dkim_domain":None,"scl":None,"forefront_antispam":None,"ms_antispam":None,
            "body_text":body_text,"body_html":body_html,"urls":_ph_extract_urls(combined),
            "keywords":_ph_scan_keywords(combined),"attachments":attachments,
            "received_headers":[],"domain_mismatches":[]}
    except Exception as e: return {"_error": str(e)}

# ── URL Deobfuscation ──
def _ph_qp_url(url):
    if '=' not in url: return url
    cleaned = re.sub(r'=\r?\n','',url)
    if re.search(r'=[0-9A-Fa-f]{2}',cleaned):
        try:
            dec = quopri.decodestring(cleaned.encode("ascii","replace")).decode("ascii","replace")
            if "http" in dec: cleaned = dec
        except:
            cleaned = re.sub(r'=([0-9A-Fa-f]{2})',
                lambda m: bytes.fromhex(m.group(1)).decode("ascii","replace"), cleaned)
    return cleaned.strip()

def _ph_sl_extract(raw_url, parsed):
    try:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for c in (qs.get("url",[]) + qs.get("URL",[])):
            inner = c
            if inner.startswith("="): inner = inner[1:]
            if re.match(r'^3[Dd]',inner): inner = inner[2:]
            inner = unquote(inner).strip()
            if '=' in inner and not inner.startswith("http"):
                try: inner = quopri.decodestring(inner.encode("ascii","replace")).decode("ascii","replace")
                except: pass
            if inner.startswith("http"): return inner
    except: pass
    return None

def _ph_static_unwrap(url):
    try:
        p = urlparse(url); host = (p.hostname or "").lower()
        if any(host==d or host.endswith("."+d) for d in _SL_DOMAINS):
            inner = _ph_sl_extract(url, p)
            if inner: return inner, "Microsoft SafeLinks"
        if "urldefense.proofpoint.com" in host:
            qs = parse_qs(p.query); u = (qs.get("u") or [None])[0]
            if u:
                dec = unquote(u).replace("-",".").replace("_","-")
                if dec.startswith("http"): return dec, "ProofPoint URL Defense"
        if "urldefense.com" in host and "__" in url:
            m = re.search(r'/__(.+?)__/',url)
            if m:
                inner = unquote(m.group(1)).replace("_","-").replace("*",".")
                return ("https://"+inner if not inner.startswith("http") else inner), "ProofPoint v3"
        if "mimecastprotect.com" in host:
            qs = parse_qs(p.query)
            for param in ("url","u","redirect"):
                v = (qs.get(param) or [None])[0]
                if v:
                    inner = unquote(v)
                    if inner.startswith("http"): return inner, "Mimecast"
    except: pass
    return url, None

def ph_unwrap_url(url):
    result = {"original_url":url,"unwrapped_url":url,"final_url":url,"wrapper_type":None,"hops":[],"error":None}
    working = _ph_qp_url(url)
    unwrapped, wtype = _ph_static_unwrap(working)
    result.update({"unwrapped_url":unwrapped,"wrapper_type":wtype})
    if not _ph_valid_url(unwrapped):
        result["error"] = f"Malformed after unwrap: {unwrapped[:60]}"; result["final_url"] = unwrapped; return result
    try:
        hdrs = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}
        s = requests.Session(); s.max_redirects = 15
        try:    r = s.head(unwrapped, allow_redirects=True, timeout=10, headers=hdrs, verify=False)
        except: r = s.get(unwrapped, allow_redirects=True, timeout=10, headers=hdrs, verify=False, stream=True); r.close()
        hops = [{"url":rr.url,"status":rr.status_code} for rr in r.history]
        hops.append({"url":r.url,"status":r.status_code})
        result.update({"final_url":r.url,"hops":hops})
    except requests.exceptions.TooManyRedirects: result["error"] = "Too many redirects"
    except requests.exceptions.SSLError as e:    result["error"] = f"SSL error: {str(e)[:60]}"
    except requests.exceptions.Timeout:          result["error"] = "Timed out"
    except Exception as e:                        result["error"] = str(e)[:60]
    return result

# ── Hop table parsing ──
_TS_RE      = re.compile(r';\s*((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s*\d{1,2}\s+\w+\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*[+-]\d{4})',re.I)
_FROM_IP_RE = re.compile(r'\((?:[^\)]*?\s)?\[?(\d{1,3}(?:\.\d{1,3}){3})\]?[^\)]*\)')
_BY_RE      = re.compile(r'\bby\s+([^\s(;\[]+)',re.I)

def ph_parse_hop_table(received_headers):
    if not received_headers: return []
    from email.utils import parsedate_to_datetime
    hops = []
    for hdr in reversed(received_headers):
        hop = {}
        m = _FROM_IP_RE.search(hdr)
        if m: hop["ip"] = m.group(1)
        if "ip" not in hop:
            ips = _IP_RE.findall(hdr)
            if ips: hop["ip"] = ips[0]
        m = re.match(r'from\s+(\S+)', hdr.strip(), re.I)
        if m: hop["from"] = m.group(1).strip(";")
        m = _BY_RE.search(hdr)
        if m: hop["by"] = m.group(1).strip(";")
        m = _TS_RE.search(hdr)
        if m:
            hop["ts_str"] = m.group(1).strip()
            try: hop["ts"] = parsedate_to_datetime(hop["ts_str"])
            except: pass
        if hop.get("ip") or hop.get("from") or hop.get("by"):
            hop["raw"] = hdr; hops.append(hop)
    for i in range(1, len(hops)):
        if hops[i].get("ts") and hops[i-1].get("ts"):
            try: hops[i]["delay_s"] = int((hops[i]["ts"]-hops[i-1]["ts"]).total_seconds())
            except: pass
    return hops

def ph_compute_verdict(email_data, url_results, ip_results):
    score = 0; flags = []; ed = email_data
    for proto, val in [("SPF",ed.get("spf")),("DKIM",ed.get("dkim")),("DMARC",ed.get("dmarc"))]:
        if val in ("fail","softfail"): score+=15; flags.append(f"❌ {proto} {val.upper()}")
        elif val in ("none",None) and proto=="DMARC": score+=5
    for mm in ed.get("domain_mismatches",[]):
        score+=20; flags.append(f"⚠️ {mm['type']} mismatch: {mm['from']} vs {mm['other']}")
    for raw_url, data in url_results.items():
        vt   = data.get("virustotal",{}) or {}
        us   = data.get("urlscan",{}) or {}
        deob = data.get("deobfuscation",{}) or {}
        disp = deob.get("final_url") or raw_url
        mal  = vt.get("malicious",0) or 0; sus = vt.get("suspicious",0) or 0
        if   mal>=5: score+=55; flags.append(f"🚨 VT MALICIOUS ({mal} engines): {disp[:60]}")
        elif mal>=2: score+=40; flags.append(f"🚨 VT flagged ({mal} malicious): {disp[:60]}")
        elif mal==1: score+=25; flags.append(f"⚠️ VT suspicious (1 engine): {disp[:60]}")
        elif sus>=3: score+=20; flags.append(f"⚠️ VT suspicious ({sus}): {disp[:60]}")
        elif sus>=1: score+=10; flags.append(f"ℹ️ VT low suspicion: {disp[:60]}")
        if us.get("verdict")=="MALICIOUS": score+=40; flags.append(f"🚨 URLScan MALICIOUS: {disp[:60]}")
        elif us.get("verdict")=="SUSPICIOUS": score+=20; flags.append(f"⚠️ URLScan suspicious: {disp[:60]}")
        final = deob.get("final_url","")
        if final and final != raw_url:
            oh=(urlparse(raw_url).hostname or ""); fh=(urlparse(final).hostname or "")
            if oh and fh and oh!=fh: score+=8; flags.append(f"🔀 Redirects: {oh} → {fh}")
    for ip, data in ip_results.items():
        ab = data.get("abuseipdb",{}) or {}; vt = data.get("virustotal",{}) or {}
        if ab.get("verdict")=="MALICIOUS": score+=35; flags.append(f"🚨 AbuseIPDB malicious IP: {ip}")
        elif ab.get("verdict")=="SUSPICIOUS": score+=15; flags.append(f"⚠️ AbuseIPDB suspicious IP: {ip}")
        if vt.get("malicious",0)>=1: score+=25; flags.append(f"🚨 VT malicious IP: {ip}")
    kw = ed.get("keywords",[])
    if kw: score+=min(len(kw)*3,15); flags.append(f"⚠️ Suspicious keywords: {', '.join(kw[:5])}")
    for att in ed.get("attachments",[]):
        ext = os.path.splitext(att.get("filename",""))[1].lower()
        if ext in {".exe",".js",".vbs",".ps1",".bat",".cmd",".hta",".scr",".doc",".docm",".xlsm",".jar"}:
            score+=30; flags.append(f"🚨 Suspicious attachment: {att['filename']}")
    score = min(score, 200)
    return {"level":"MALICIOUS" if score>=55 else "SUSPICIOUS" if score>=15 else "CLEAN",
            "score":score,"flags":flags}

def ph_generate_worknote(email_data, url_results, ip_results, verdict):
    ed = email_data; ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    lines = ["="*70, f"PHISHING TRIAGE REPORT — {ts}", "="*70,
        f"VERDICT : {verdict['level']}  (Score: {verdict['score']}/200)", "",
        "── EMAIL IDENTITY ──────────────────────────────────────────────",
        f"Subject     : {ed.get('subject') or 'N/A'}",
        f"From        : {ed.get('from') or 'N/A'}",
        f"To          : {ed.get('to') or 'N/A'}",
        f"Reply-To    : {ed.get('reply_to') or 'N/A'}",
        f"Return-Path : {ed.get('return_path') or 'N/A'}",
        f"Date        : {ed.get('date') or 'N/A'}",
        f"Message-ID  : {ed.get('message_id') or 'N/A'}", "",
        "── AUTHENTICATION ──────────────────────────────────────────────",
        f"SPF   : {(ed.get('spf') or 'N/A').upper()}",
        f"DKIM  : {(ed.get('dkim') or 'N/A').upper()}",
        f"DMARC : {(ed.get('dmarc') or 'N/A').upper()}", "",
        "── INFRASTRUCTURE ──────────────────────────────────────────────",
        f"Sender IP       : {ed.get('sender_ip') or 'N/A'}",
        f"X-Originating-IP: {ed.get('x_originating_ip') or 'N/A'}",
        f"DKIM Domain     : {ed.get('dkim_domain') or 'N/A'}",
        f"X-Mailer        : {ed.get('x_mailer') or 'N/A'}", ""]
    if ed.get("domain_mismatches"):
        lines.append("── DOMAIN MISMATCHES ───────────────────────────────────────────")
        for mm in ed["domain_mismatches"]:
            lines.append(f"  {mm['type']}: From={mm['from']}  Other={mm['other']}")
        lines.append("")
    lines.append("── URLs ANALYZED ───────────────────────────────────────────────")
    for raw_url, data in url_results.items():
        deob = data.get("deobfuscation",{}) or {}; vt = data.get("virustotal",{}) or {}
        us   = data.get("urlscan",{}) or {}
        final = deob.get("final_url") or raw_url; wrap = deob.get("wrapper_type","")
        lines.append(f"  URL     : {raw_url}")
        if wrap:             lines.append(f"  Wrapper : {wrap}")
        if final != raw_url: lines.append(f"  Final   : {final}")
        hops = deob.get("hops",[])
        if len(hops)>1: lines.append(f"  Hops    : {' → '.join(str(h.get('status','?'))+' '+h.get('url','') for h in hops[:5])}")
        lines.append(f"  VT      : Mal={vt.get('malicious',0)} Sus={vt.get('suspicious',0)} Verdict={vt.get('verdict','N/A')}")
        if us.get("ip"): lines.append(f"  URLScan : IP={us['ip']}  Score={us.get('score',0)}")
        lines.append("")
    if ip_results:
        lines.append("── IP REPUTATION ───────────────────────────────────────────────")
        for ip, data in ip_results.items():
            ab = data.get("abuseipdb",{}) or {}
            lines += [f"  IP      : {ip}",
                      f"  Abuse   : Score={ab.get('score',0)}  Country={ab.get('country','?')}  ISP={ab.get('isp','?')}", ""]
    if ed.get("keywords"):
        lines += ["── SUSPICIOUS KEYWORDS ─────────────────────────────────────────",
                  f"  {', '.join(ed['keywords'])}", ""]
    lines += ["── THREAT INDICATORS ───────────────────────────────────────────",
              *[f"  {f}" for f in verdict["flags"]], "",
              "── ANALYST NOTES ───────────────────────────────────────────────",
              "  [ Add notes here ]", "", "="*70]
    return "\n".join(lines)

def ph_geolocate_ip(ip):
    if not ip or _ph_private(ip): return {}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}",
            params={"fields":"status,country,countryCode,city,isp,org,as,query"}, timeout=6)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return {"country":d.get("country"),"country_code":d.get("countryCode"),
                        "city":d.get("city"),"isp":d.get("isp"),"org":d.get("org"),"asn":d.get("as")}
    except: pass
    return {}

def ph_vt_check_url(url, api_key):
    if not api_key: return {}
    try:
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
            headers={"x-apikey":api_key}, timeout=20)
        if r.status_code == 404:
            s = requests.post("https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey":api_key}, data={"url":url}, timeout=20)
            if s.status_code not in (200,202): return {"error":f"VT submit {s.status_code}"}
            time.sleep(15)
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers={"x-apikey":api_key}, timeout=20)
        if r.status_code != 200: return {"error":f"VT HTTP {r.status_code}"}
        stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        mal = stats.get("malicious",0); sus = stats.get("suspicious",0)
        return {"malicious":mal,"suspicious":sus,"harmless":stats.get("harmless",0),
                "verdict":"MALICIOUS" if mal>=1 else "SUSPICIOUS" if sus>=2 else "CLEAN",
                "link":f"https://www.virustotal.com/gui/url/{uid}"}
    except Exception as e: return {"error":str(e)[:80]}

def ph_urlscan_submit(url, api_key):
    if not api_key: return {}
    try:
        r = requests.post("https://urlscan.io/api/v1/scan/",
            headers={"API-Key":api_key,"Content-Type":"application/json"},
            json={"url":url,"visibility":"private"}, timeout=15)
        if r.status_code not in (200,202): return {"error":f"URLScan submit HTTP {r.status_code}"}
        uuid = r.json().get("uuid")
        if not uuid: return {"error":"No UUID returned from URLScan"}
        return {"uuid":uuid,"status":"pending","link":f"https://urlscan.io/result/{uuid}/"}
    except Exception as e: return {"error":str(e)[:80]}

def ph_urlscan_fetch(uuid, api_key=""):
    try:
        hdrs = {"API-Key": api_key} if api_key else {}
        r = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", headers=hdrs, timeout=10)
        if r.status_code == 404:
            return {"uuid":uuid,"status":"pending","link":f"https://urlscan.io/result/{uuid}/"}
        if r.status_code != 200: return {"error":f"URLScan HTTP {r.status_code}","uuid":uuid}
        d = r.json(); v = d.get("verdicts",{}).get("overall",{}); p = d.get("page",{})
        return {"uuid":uuid,"status":"done",
            "verdict":"MALICIOUS" if v.get("malicious") else "SUSPICIOUS" if v.get("score",0)>=50 else "CLEAN",
            "score":v.get("score",0),"ip":p.get("ip"),"country":p.get("country"),
            "screenshot":d.get("task",{}).get("screenshotURL"),
            "link":f"https://urlscan.io/result/{uuid}/"}
    except Exception as e: return {"error":str(e)[:80]}

def ph_abuseipdb_check(ip, api_key):
    if not api_key: return {}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
            headers={"Key":api_key,"Accept":"application/json"},
            params={"ipAddress":ip,"maxAgeInDays":90}, timeout=15)
        if r.status_code != 200: return {"error":f"AbuseIPDB HTTP {r.status_code}"}
        d = r.json().get("data",{})
        score = d.get("abuseConfidenceScore",0)
        return {"score":score,"country":d.get("countryCode"),"isp":d.get("isp"),
                "total_reports":d.get("totalReports",0),
                "verdict":"MALICIOUS" if score>=75 else "SUSPICIOUS" if score>=25 else "CLEAN"}
    except Exception as e: return {"error":str(e)[:80]}

def ph_joe_submit(url: str, api_key: str, server: str) -> dict:
    if not api_key: return {}
    try:
        base = server.rstrip("/")
        r = requests.post(f"{base}/api/v2/analysis/submit/url",
            data={"apikey": api_key, "url": url, "type": "url", "accept-tac": 1},
            timeout=30)
        if r.status_code not in (200, 201): return {"error": f"Joe submit HTTP {r.status_code}"}
        d = r.json(); data = d.get("data", {})
        webid = data.get("webid", "")
        return {"webid": webid, "status": "submitted",
                "link": f"{base}/analysis/{webid}/" if webid else ""}
    except Exception as e: return {"error": str(e)[:80]}

def ph_joe_fetch(webid: str, api_key: str, server: str) -> dict:
    if not api_key or not webid: return {}
    try:
        base = server.rstrip("/")
        r = requests.post(f"{base}/api/v2/analysis/info",
            data={"apikey": api_key, "webid": webid}, timeout=20)
        if r.status_code != 200: return {"webid": webid, "status": "pending"}
        d = r.json(); info = d.get("data", {})
        status = info.get("status", "pending")
        score = info.get("score", 0)
        return {"webid": webid, "status": status, "score": score,
                "classification": info.get("classification", ""),
                "link": f"{base}/analysis/{webid}/"}
    except Exception as e: return {"webid": webid, "status": "error", "error": str(e)[:80]}

# ══════════════════════════════════════════════════════════════════
# OSINT NAVIGATOR — 140+ tool index (inspired by ekky19/osint)
# ══════════════════════════════════════════════════════════════════
_NAV_SKIP = True  # shorthand
NAV_TOOLS = {
    "🔍 Search Tools": [
        {"name": "VirusTotal",       "url": "https://www.virustotal.com/gui/search/",                           "desc": "Analyse IPs, domains, URLs & hashes",                  "tags": ["ip","url","hash","malware"]},
        {"name": "URL Scan",         "url": "https://urlscan.io/search/#",                                      "desc": "Search domains, IPs, filenames, hashes, ASNs",         "tags": ["ip","url","hash"]},
        {"name": "Hybrid Analysis",  "url": "https://www.hybrid-analysis.com/search?query=",                    "desc": "Malware analysis & threat intel",                       "tags": ["url","hash","ip","malware"]},
        {"name": "Pulsedive",        "url": "https://pulsedive.com/ioc/",                                      "desc": "Search any domain, IP, or URL",                         "tags": ["ip","url","ioc"]},
        {"name": "Abuse IP DB",      "url": "https://www.abuseipdb.com/check/",                                 "desc": "Check report history of any IP address",               "tags": ["ip"]},
        {"name": "URLhaus",          "url": "https://urlhaus.abuse.ch/browse.php?search=",                      "desc": "Malicious URL tracker",                                "tags": ["url","hash"]},
        {"name": "WhoisXML",         "url": "https://whois.whoisxmlapi.com/lookup?q=",                         "desc": "Domain/IP WHOIS records",                              "tags": ["url","ip","whois"]},
        {"name": "URL Void",         "url": "https://www.urlvoid.com/scan/",                                    "desc": "Check online reputation of a website",                 "tags": ["url"]},
        {"name": "Sucuri SiteCheck", "url": "https://sitecheck.sucuri.net/results/",                            "desc": "Malware / blacklist / software check",                 "tags": ["url"]},
        {"name": "Talos Intelligence","url": "https://talosintelligence.com/reputation_center/lookup?search=",  "desc": "Cisco Talos threat intelligence",                      "tags": ["ip","url","email","hash"]},
        {"name": "Rapid DNS",        "url": "https://rapiddns.io/s/",                                          "desc": "Discover subdomains for a target domain",              "tags": ["subdomain","dns","url"]},
        {"name": "Google SafeBrowse","url": "https://transparencyreport.google.com/safe-browsing/search?url=",  "desc": "Google Safe Browsing check",                           "tags": ["url"]},
        {"name": "Threat Yeti",      "url": "https://threatyeti.com/search?q=",                                "desc": "Full security analysis for domains/URLs",              "tags": ["url","ip"]},
        {"name": "crt.sh",           "url": "https://crt.sh/?q=",                                              "desc": "Certificate transparency records",                     "tags": ["url","hash","cert"]},
        {"name": "SecurityTrails",   "url": "https://securitytrails.com/domain/",                               "desc": "Domain & DNS historical data",                        "tags": ["url","hostname"]},
        {"name": "DNS Propagation",  "url": "https://dnschecker.org/#A/",                                      "desc": "Global DNS propagation check",                        "tags": ["dns","url"]},
        {"name": "IntelX",           "url": "https://intelx.io/?s=",                                           "desc": "Domain, URL, email, IP, CIDR search",                  "tags": ["ip","url","email","cidr"]},
        {"name": "ThreatIntel Plat.", "url": "https://threatintelligenceplatform.com/report/",                  "desc": "Threat intel reports for domains/IPs",                "tags": ["url","ip"]},
        {"name": "SocRadar IOC",     "url": "https://socradar.io/labs/app/ioc-radar/",                         "desc": "Advanced IOC threat intelligence search",              "tags": ["ip","hash","hostname"], "skipSearch": _NAV_SKIP},
        {"name": "Have I Been Squatted","url": "https://haveibeensquatted.com/",                                "desc": "Check if a domain has been typosquatted",             "tags": ["url","domain"], "skipSearch": _NAV_SKIP},
    ],
    "🖥️ IP Info": [
        {"name": "Criminal IP",      "url": "https://www.criminalip.io/asset/report?ip=",                       "desc": "IP attack surface & threat hunting",                   "tags": ["ip"]},
        {"name": "IPinfo",           "url": "https://ipinfo.io/",                                               "desc": "IP geolocation, ASN, org",                            "tags": ["ip","asn"]},
        {"name": "IP Void",          "url": "https://www.ipvoid.com/scan/",                                     "desc": "IP address reputation information",                   "tags": ["ip"]},
        {"name": "IPQS Proxy Lookup","url": "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/", "desc": "IP lookup & proxy/VPN/Tor detection",              "tags": ["ip","proxy","vpn"]},
        {"name": "Spur",             "url": "https://spur.us/context/",                                        "desc": "Detect VPNs, residential proxies, and bots",          "tags": ["proxy","vpn","bot"]},
        {"name": "GreyNoise",        "url": "https://viz.greynoise.io/query/",                                  "desc": "Internet background noise analysis",                  "tags": ["ip"]},
        {"name": "ARIN RDAP",        "url": "https://search.arin.net/rdap/?query=",                             "desc": "ARIN WHOIS / RDAP lookup",                            "tags": ["ip","whois"]},
        {"name": "DomainTools",      "url": "https://whois.domaintools.com/",                                   "desc": "WHOIS for domains and IPs",                           "tags": ["url","ip","whois"]},
        {"name": "Feodo Tracker",    "url": "https://feodotracker.abuse.ch/browse.php?search=",                 "desc": "C2 IPs — Dridex, TrickBot, QakBot, Emotet",          "tags": ["ip","c2","botnet"]},
        {"name": "SANS ISC",         "url": "https://isc.sans.edu/ipinfo.html?ip=",                             "desc": "SANS Internet Storm Center IP lookup",                "tags": ["ip","port"]},
        {"name": "IP Hub",           "url": "https://iphub.info/?ip=",                                         "desc": "IP Hub proxy/VPN detection",                         "tags": ["ip","proxy","vpn"]},
        {"name": "GeoIP HackerTarget","url": "https://api.hackertarget.com/geoip/?q=",                         "desc": "Geo IP lookup via HackerTarget",                      "tags": ["ip","geolocation"]},
        {"name": "IP Details",       "url": "https://whatismyipaddress.com/ip/",                                "desc": "Full IP address details",                             "tags": ["ip"]},
        {"name": "MXToolbox",        "url": "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a",               "desc": "MX, DNS, blacklist lookup",                           "tags": ["url","dns","mx"]},
        {"name": "CrowdSec Intel",   "url": "https://app.crowdsec.net/cti/",                                   "desc": "CrowdSec community threat intelligence",              "tags": ["ip"], "skipSearch": _NAV_SKIP},
        {"name": "Sicehice",         "url": "https://sicehice.com/search/",                                    "desc": "Bulk IP searching & threat data aggregation",         "tags": ["ip"]},
    ],
    "🛡️ Threat Intelligence": [
        {"name": "IBM X-Force",      "url": "https://exchange.xforce.ibmcloud.com/search/",                     "desc": "IP, URL, hash, CVE threat intel",                     "tags": ["url","ip","hash","cve"]},
        {"name": "ThreatMiner",      "url": "https://www.threatminer.org/host.php?q=",                         "desc": "IP, domain, hash, email, APT notes",                  "tags": ["url","ip","hash","email"]},
        {"name": "AlienVault OTX",   "url": "https://otx.alienvault.com/indicator/domain/",                    "desc": "Open Threat Intelligence Community",                  "tags": ["url","ip","hash"]},
        {"name": "Onyphe",           "url": "https://www.onyphe.io/search?q=category:datascan+",               "desc": "Cyber threat & vulnerability intelligence",           "tags": ["url","ip"]},
        {"name": "LeakIX",           "url": "https://leakix.net/search?scope=leak&q=",                         "desc": "Leaked services and assets search",                   "tags": ["url","ip","port"]},
        {"name": "ThreatFox",        "url": "https://threatfox.abuse.ch/browse.php?search=ioc%3A",             "desc": "Community IOC sharing platform",                      "tags": ["ip","url","hash","ioc"]},
        {"name": "ThreatLens",       "url": "https://threatlens.vercel.app/",                                  "desc": "One-stop threat intelligence lookup",                 "tags": ["url","ip","hash"], "skipSearch": _NAV_SKIP},
        {"name": "ThreatView",       "url": "https://threatview.io/",                                          "desc": "Actionable cyber threat intelligence feeds",          "tags": ["c2","blocklist","hash"], "skipSearch": _NAV_SKIP},
        {"name": "FOFA",             "url": "https://en.fofa.info/",                                           "desc": "Cybersecurity search engine for devices & services",  "tags": ["url","ip"], "skipSearch": _NAV_SKIP},
        {"name": "Ransomware.live",  "url": "https://www.ransomware.live/",                                    "desc": "Live ransomware leak site tracker",                   "tags": ["ransomware"], "skipSearch": _NAV_SKIP},
    ],
    "🔑 Hash Lookup": [
        {"name": "VT Hash",          "url": "https://www.virustotal.com/gui/search/",                          "desc": "VirusTotal hash analysis",                            "tags": ["hash","malware"]},
        {"name": "Malshare",         "url": "https://malshare.com/sample.php?action=detail&hash=",             "desc": "Malware samples hash lookup",                         "tags": ["hash","malware"]},
        {"name": "AlienVault File",  "url": "https://otx.alienvault.com/indicator/file/",                      "desc": "AlienVault OTX file/hash lookup",                     "tags": ["hash"]},
        {"name": "Jotti",            "url": "https://virusscan.jotti.org/en-US/search/hash/",                  "desc": "Multi-AV hash scan",                                  "tags": ["hash"]},
        {"name": "Valhalla",         "url": "https://valhalla.nextron-systems.com/info/search?keyword=",        "desc": "YARA / Sigma rule search by hash/keyword",            "tags": ["hash","yara"]},
        {"name": "CIRCL HashLookup", "url": "https://hashlookup.circl.lu/lookup/sha256/",                      "desc": "NSRL-based known-good hash lookup (free, no key)",    "tags": ["hash"]},
        {"name": "MalwareBazaar",    "url": "https://bazaar.abuse.ch/browse.php?search=",                      "desc": "Community malicious file sharing & search",           "tags": ["hash","malware"]},
    ],
    "📧 Email & Breach": [
        {"name": "HaveIBeenPwned",   "url": "https://haveibeenpwned.com/",                                     "desc": "Check email in data breaches",                        "tags": ["email","breach"], "skipSearch": _NAV_SKIP},
        {"name": "Breach.VIP",       "url": "https://breach.vip/",                                             "desc": "Free breach database search engine",                  "tags": ["email","breach"], "skipSearch": _NAV_SKIP},
        {"name": "XposedOrNot",      "url": "https://xposedornot.com/xposed/#",                                "desc": "Email breach check (free)",                           "tags": ["email","breach"]},
        {"name": "Email Hunter",     "url": "https://hunter.io/search/",                                       "desc": "Find emails for a domain",                           "tags": ["email","domain"]},
        {"name": "Epieos",           "url": "https://epieos.com/?q=",                                         "desc": "Email → linked accounts & social lookup",             "tags": ["email"]},
        {"name": "BreachDirectory",  "url": "https://breachdirectory.org/",                                    "desc": "Check email/username compromise",                     "tags": ["email","breach"], "skipSearch": _NAV_SKIP},
        {"name": "LeakCheck",        "url": "https://leakcheck.io/",                                           "desc": "Check leaked credentials",                           "tags": ["email","breach"], "skipSearch": _NAV_SKIP},
        {"name": "EmailRep",         "url": "https://emailrep.io/",                                            "desc": "Email reputation lookup",                            "tags": ["email"], "skipSearch": _NAV_SKIP},
        {"name": "Alerts Bar",       "url": "https://www.alerts.bar/",                                        "desc": "Compromised credentials & breach monitoring",         "tags": ["email","breach"], "skipSearch": _NAV_SKIP},
        {"name": "LeakPeek",         "url": "https://leakpeek.com/",                                          "desc": "Search 8B+ public records for leaks",                "tags": ["email","breach"], "skipSearch": _NAV_SKIP},
        {"name": "ProxyNova COMB",   "url": "https://www.proxynova.com/tools/comb/",                          "desc": "Search compromised combo lists",                      "tags": ["breach"], "skipSearch": _NAV_SKIP},
        {"name": "MX Blacklist",     "url": "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a",        "desc": "Check if domain is blacklisted",                      "tags": ["email","dns"]},
        {"name": "Validate Email",   "url": "https://validateemailaddress.org/",                               "desc": "Validate email address syntax & existence",           "tags": ["email"], "skipSearch": _NAV_SKIP},
    ],
    "📬 Email Headers": [
        {"name": "RFC822 Parser",    "url": "https://www.whatismyip.com/email-header-analyzer/",               "desc": "Email header analyzer & RFC822 parser",              "tags": ["email header"], "skipSearch": _NAV_SKIP},
        {"name": "Mailheader.org",   "url": "https://mailheader.org/",                                        "desc": "Online email header parser & spam analysis",          "tags": ["email header"], "skipSearch": _NAV_SKIP},
        {"name": "Google MsgHeader", "url": "https://toolbox.googleapps.com/apps/messageheader/",              "desc": "Google Message Header Analyzer",                     "tags": ["email header"], "skipSearch": _NAV_SKIP},
        {"name": "Azure MHA",        "url": "https://mha.azurewebsites.net/",                                  "desc": "Microsoft email header analyzer",                    "tags": ["email header"], "skipSearch": _NAV_SKIP},
        {"name": "GlockApps",        "url": "https://glockapps.com/domain-checker/?domain=",                   "desc": "DMARC / SPF / DKIM domain protection check",         "tags": ["email","dmarc","spf"]},
    ],
    "🏗️ Attack Surface": [
        {"name": "Censys",           "url": "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=", "desc": "Search IPs, protocols, certificates", "tags": ["ip","url","attack surface"]},
        {"name": "Netcraft",         "url": "https://searchdns.netcraft.com/?restriction=site+contains&host=","desc": "Domain technology fingerprinting",                    "tags": ["url","attack surface"]},
        {"name": "WhatCMS",          "url": "https://whatcms.org/?s=",                                        "desc": "Identify CMS of a website",                          "tags": ["url","cms"]},
        {"name": "driftnet",         "url": "https://driftnet.io/search/summary?t=search-term%3A%3Ahas+prefix%3A","desc": "Deep domain/IP connections",                      "tags": ["url","ip","cidr"]},
        {"name": "Web Check",        "url": "https://web-check.xyz/check/",                                   "desc": "All-in-one OSINT website analyzer",                  "tags": ["url","ip"]},
        {"name": "SilentPush",       "url": "https://explore.silentpush.com/enrichment/domain/",               "desc": "Domain / IP / ASN enrichment",                      "tags": ["ip","url","asn"]},
        {"name": "FullHunt",         "url": "https://fullhunt.io/",                                           "desc": "Expose your attack surface",                         "tags": ["url","ip"], "skipSearch": _NAV_SKIP},
        {"name": "Netlas",           "url": "https://app.netlas.io/",                                         "desc": "Discover, scan and monitor online assets",           "tags": ["url","ip"], "skipSearch": _NAV_SKIP},
        {"name": "ZoomEye",          "url": "https://www.zoomeye.ai/",                                        "desc": "Cyberspace search engine for assets & vulns",        "tags": ["url","ip"], "skipSearch": _NAV_SKIP},
        {"name": "Shodan",           "url": "https://www.shodan.io/search?query=",                            "desc": "Internet of Everything search engine",               "tags": ["ip","iot"]},
    ],
    "🐛 Vulnerabilities": [
        {"name": "NVD / NIST",       "url": "https://nvd.nist.gov/",                                          "desc": "National Vulnerability Database",                     "tags": ["cve"], "skipSearch": _NAV_SKIP},
        {"name": "CVE.org",          "url": "https://www.cve.org/",                                           "desc": "Official CVE database by MITRE",                      "tags": ["cve"], "skipSearch": _NAV_SKIP},
        {"name": "CISA KEV",         "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",    "desc": "CISA known exploited vulnerabilities catalog",       "tags": ["cve"], "skipSearch": _NAV_SKIP},
        {"name": "ExploitDB",        "url": "https://www.exploit-db.com/",                                    "desc": "Exploit database",                                   "tags": ["cve","exploit"], "skipSearch": _NAV_SKIP},
        {"name": "Vulners",          "url": "https://vulners.com/",                                           "desc": "Search 3M+ vulnerabilities & exploits",              "tags": ["cve","exploit"], "skipSearch": _NAV_SKIP},
        {"name": "CVE Details",      "url": "https://www.cvedetails.com/",                                    "desc": "CVE search with vendor/product breakdown",           "tags": ["cve"], "skipSearch": _NAV_SKIP},
        {"name": "AttackerKB",       "url": "https://attackerkb.com/activity-feed",                           "desc": "Vulnerability insights — attacker perspective",      "tags": ["cve"], "skipSearch": _NAV_SKIP},
        {"name": "CVE Sky (GN)",     "url": "https://cvesky.labs.greynoise.io/",                              "desc": "GreyNoise CVE exploitation data",                     "tags": ["cve","vendor"], "skipSearch": _NAV_SKIP},
    ],
    "🦠 Malware Analysis": [
        {"name": "ANY.RUN",          "url": "https://app.any.run/",                                           "desc": "Interactive malware sandbox (Win/Linux/Android)",     "tags": ["malware","sandbox"], "skipSearch": _NAV_SKIP},
        {"name": "Joe Sandbox",      "url": "https://www.joesandbox.com/",                                    "desc": "Deep malware analysis sandbox",                      "tags": ["malware","sandbox"], "skipSearch": _NAV_SKIP},
        {"name": "Cuckoo (CERT.ee)", "url": "https://cuckoo.cert.ee/",                                        "desc": "Open-source automated malware analysis",             "tags": ["malware","sandbox"], "skipSearch": _NAV_SKIP},
        {"name": "Docguard.io",      "url": "https://www.docguard.io/",                                       "desc": "Document-based malware analysis",                    "tags": ["malware","upload"], "skipSearch": _NAV_SKIP},
        {"name": "FileScan.IO",      "url": "https://www.filescan.io/",                                       "desc": "File scanning & behavioral malware analysis",        "tags": ["malware","upload"], "skipSearch": _NAV_SKIP},
        {"name": "CAPE Sandbox",     "url": "https://capesandbox.com/",                                       "desc": "CAPE custom malware analysis sandbox",              "tags": ["malware","sandbox"], "skipSearch": _NAV_SKIP},
        {"name": "YARAify",          "url": "https://yaraify.abuse.ch/scan/",                                 "desc": "Hunt across abuse.ch with YARA rules",              "tags": ["yara","malware"], "skipSearch": _NAV_SKIP},
        {"name": "Polyswarm",        "url": "https://polyswarm.network/scan",                                 "desc": "Scan files / URLs for threats",                     "tags": ["malware","url"], "skipSearch": _NAV_SKIP},
        {"name": "Kunai Sandbox",    "url": "https://sandbox.kunai.rocks/",                                   "desc": "Linux malware sandbox (eBPF-based)",                "tags": ["linux","malware","sandbox"], "skipSearch": _NAV_SKIP},
    ],
    "🧪 Malware Feeds": [
        {"name": "Abuse.ch",         "url": "https://abuse.ch/",                                              "desc": "Swiss open threat intelligence project",            "tags": ["ioc","malware"], "skipSearch": _NAV_SKIP},
        {"name": "MalwareBazaar",    "url": "https://bazaar.abuse.ch/",                                       "desc": "Malicious file sharing community",                  "tags": ["ioc","malware"], "skipSearch": _NAV_SKIP},
        {"name": "URLhaus Feed",     "url": "https://urlhaus.abuse.ch/",                                      "desc": "Malicious URL distribution tracker",               "tags": ["ioc","url"], "skipSearch": _NAV_SKIP},
        {"name": "ThreatFox Feed",   "url": "https://threatfox.abuse.ch/",                                    "desc": "Community-driven IOC sharing platform",            "tags": ["ioc"], "skipSearch": _NAV_SKIP},
        {"name": "Feodo Tracker",    "url": "https://feodotracker.abuse.ch/",                                  "desc": "C2 associated with Feodo/TrickBot/QakBot/Emotet",  "tags": ["ioc","c2"], "skipSearch": _NAV_SKIP},
        {"name": "SSL Blacklist",    "url": "https://sslbl.abuse.ch/",                                        "desc": "Suspicious SSL certs & JA3 fingerprints",          "tags": ["ioc","ssl"], "skipSearch": _NAV_SKIP},
        {"name": "Malware Traffic",  "url": "https://www.malware-traffic-analysis.net/",                       "desc": "PCAPs & write-ups from real malware captures",     "tags": ["ioc","pcap"], "skipSearch": _NAV_SKIP},
        {"name": "Ransomware.live",  "url": "https://www.ransomware.live/",                                   "desc": "Live ransomware leak site tracker",                "tags": ["ransomware"], "skipSearch": _NAV_SKIP},
    ],
    "🎣 Phishing Analysis": [
        {"name": "PhishTank",        "url": "https://www.phishtank.com/search.php?valid=y&active=y&Search=Search&url=", "desc": "Phishing URL database check",                "tags": ["phishing","url"]},
        {"name": "CheckPhish",       "url": "https://checkphish.bolster.ai/",                                 "desc": "AI-powered phishing URL analysis",                  "tags": ["phishing","url"], "skipSearch": _NAV_SKIP},
        {"name": "OpenPhish",        "url": "https://openphish.com/",                                         "desc": "Active phishing feeds",                            "tags": ["phishing"], "skipSearch": _NAV_SKIP},
        {"name": "PhishStats",       "url": "https://phishstats.info/",                                       "desc": "Phishing statistics & searchable database",        "tags": ["phishing"], "skipSearch": _NAV_SKIP},
        {"name": "Zscaler Zulu",     "url": "https://zulu.zscaler.com/",                                      "desc": "Zulu URL Risk Analyzer",                           "tags": ["url","phishing"], "skipSearch": _NAV_SKIP},
        {"name": "IsLegitSite",      "url": "https://www.islegitsite.com/check/",                              "desc": "Check if a website is legit or a scam",           "tags": ["url","phishing"]},
        {"name": "URLVoid",          "url": "https://www.urlvoid.com/scan/",                                   "desc": "Website online reputation / safety check",        "tags": ["url","phishing"]},
        {"name": "BrightCloud",      "url": "https://www.brightcloud.com/tools/url-ip-lookup.php",            "desc": "URL / IP reputation via BrightCloud",              "tags": ["url","ip"], "skipSearch": _NAV_SKIP},
        {"name": "Palo Alto URL",    "url": "https://urlfiltering.paloaltonetworks.com/",                     "desc": "Palo Alto URL categories & reputation",           "tags": ["url"], "skipSearch": _NAV_SKIP},
    ],
    "👥 Social Media & People": [
        {"name": "WhatsMyName",      "url": "https://whatsmyname.app",                                        "desc": "Find usernames across 500+ websites",              "tags": ["username","social"], "skipSearch": _NAV_SKIP},
        {"name": "NameChk",          "url": "https://namechk.com",                                            "desc": "Username availability across social networks",     "tags": ["username","social"], "skipSearch": _NAV_SKIP},
        {"name": "Epieos",           "url": "https://epieos.com/?q=",                                        "desc": "Email → linked accounts lookup",                  "tags": ["email","social"]},
        {"name": "FaceCheck.ID",     "url": "https://facecheck.id/",                                         "desc": "Facial recognition search engine",               "tags": ["image","face"], "skipSearch": _NAV_SKIP},
        {"name": "TinEye",           "url": "https://tineye.com/",                                           "desc": "Reverse image search engine",                    "tags": ["image"], "skipSearch": _NAV_SKIP},
        {"name": "TrueCaller",       "url": "https://www.truecaller.com/",                                    "desc": "Phone number lookup & spam call protection",     "tags": ["phone","people"], "skipSearch": _NAV_SKIP},
        {"name": "IDCrawl",          "url": "https://www.idcrawl.com/username-search",                       "desc": "Social media profiles by username",              "tags": ["username","social"], "skipSearch": _NAV_SKIP},
        {"name": "osint.rocks",      "url": "https://osint.rocks/",                                          "desc": "Sherlock & Maigret username search",             "tags": ["username","social"], "skipSearch": _NAV_SKIP},
        {"name": "Minerva OSINT",    "url": "https://minervaosint.com/",                                      "desc": "Find social accounts by email",                  "tags": ["email","social"], "skipSearch": _NAV_SKIP},
        {"name": "SynapsInt",        "url": "https://synapsint.com/",                                        "desc": "Multi-source OSINT: IP, URL, email, Twitter",    "tags": ["ip","url","email"], "skipSearch": _NAV_SKIP},
        {"name": "Blockchair",       "url": "https://blockchair.com/",                                       "desc": "Multi-blockchain explorer & analytics",          "tags": ["crypto","blockchain"], "skipSearch": _NAV_SKIP},
        {"name": "IntelX Facebook",  "url": "https://intelx.io/tools?tab=facebook",                         "desc": "Facebook search via IntelligenceX",              "tags": ["social","facebook"], "skipSearch": _NAV_SKIP},
        {"name": "Bitcoin Who's Who","url": "https://www.bitcoinwhoswho.com/",                               "desc": "Bitcoin wallet address lookup & scammer reports", "tags": ["crypto","bitcoin"], "skipSearch": _NAV_SKIP},
    ],
    "🔧 Utilities": [
        {"name": "CyberChef",        "url": "https://gchq.github.io/CyberChef/",                              "desc": "Encode / decode / encrypt / decrypt data",        "tags": ["encode","decode","crypto"], "skipSearch": _NAV_SKIP},
        {"name": "Uncoder IO",       "url": "https://tdm.socprime.com/uncoder-ai",                            "desc": "Translate detection rules between SIEMs",        "tags": ["sigma","siem"], "skipSearch": _NAV_SKIP},
        {"name": "DorkSearch",       "url": "https://dorksearch.com/",                                        "desc": "Google dork search builder",                     "tags": ["search","dork"], "skipSearch": _NAV_SKIP},
        {"name": "CrackStation",     "url": "https://crackstation.net/",                                      "desc": "Free password hash cracker",                     "tags": ["hash","password"], "skipSearch": _NAV_SKIP},
        {"name": "Regex101",         "url": "https://regex101.com/",                                         "desc": "Regular expression tester & debugger",           "tags": ["regex"], "skipSearch": _NAV_SKIP},
        {"name": "Browserling",      "url": "https://www.browserling.com/",                                   "desc": "Browser in the cloud — test URLs safely",        "tags": ["url","browser"], "skipSearch": _NAV_SKIP},
        {"name": "GrayHatWarfare",   "url": "https://buckets.grayhatwarfare.com/",                            "desc": "Open / misconfigured S3 buckets search",        "tags": ["s3","cloud"], "skipSearch": _NAV_SKIP},
        {"name": "DOCX Metadata",    "url": "https://products.groupdocs.app/metadata/docx",                   "desc": "View / edit DOCX file metadata",                "tags": ["metadata","upload"], "skipSearch": _NAV_SKIP},
        {"name": "Steganography",    "url": "https://stylesuxx.github.io/steganography/",                     "desc": "Encode / decode hidden data in images",         "tags": ["steganography"], "skipSearch": _NAV_SKIP},
        {"name": "AADInternals",     "url": "https://aadinternals.com/osint/",                                "desc": "Azure AD tenant OSINT tool",                    "tags": ["azure","tenant","email"], "skipSearch": _NAV_SKIP},
        {"name": "Ransomware DB",    "url": "https://www.ransom-db.com/",                                     "desc": "Searchable ransomware leak database",           "tags": ["ransomware"], "skipSearch": _NAV_SKIP},
        {"name": "OCCRP Aleph",      "url": "https://data.occrp.org/",                                       "desc": "Leaks & databases for financial tracking",      "tags": ["leaks","data breach"], "skipSearch": _NAV_SKIP},
        {"name": "Ransomware.live",  "url": "https://www.ransomware.live/",                                   "desc": "Live ransomware leak site tracker",             "tags": ["ransomware"], "skipSearch": _NAV_SKIP},
    ],
    "🤖 AI Tools": [
        {"name": "ChatGPT",          "url": "https://chatgpt.com/",                                           "desc": "OpenAI GPT conversational AI",                  "tags": ["ai"], "skipSearch": _NAV_SKIP},
        {"name": "Gemini",           "url": "https://gemini.google.com/",                                     "desc": "Google Gemini AI assistant",                    "tags": ["ai"], "skipSearch": _NAV_SKIP},
        {"name": "Claude",           "url": "https://claude.ai/",                                             "desc": "Anthropic Claude AI for research",              "tags": ["ai"], "skipSearch": _NAV_SKIP},
        {"name": "Copilot",          "url": "https://copilot.microsoft.com/",                                 "desc": "Microsoft AI companion",                        "tags": ["ai"], "skipSearch": _NAV_SKIP},
        {"name": "Perplexity",       "url": "https://www.perplexity.ai/",                                     "desc": "AI-powered real-time research engine",          "tags": ["ai","research"], "skipSearch": _NAV_SKIP},
        {"name": "NotebookLM",       "url": "https://notebooklm.google.com/",                                 "desc": "Google AI research notebook",                   "tags": ["ai","research"], "skipSearch": _NAV_SKIP},
        {"name": "Consensus",        "url": "https://consensus.app/",                                         "desc": "AI tool for scientific paper consensus",        "tags": ["ai","research"], "skipSearch": _NAV_SKIP},
    ],
}



# ══════════════════════════════════════════════════════════════════
# iOS-STYLE THEME  +  HELPER CLASSES
# ══════════════════════════════════════════════════════════════════
THEME = {
    "dark": {
        "bg":     "#1C1C1E", "bg2":    "#2C2C2E", "bg3":    "#3A3A3C",
        "bg4":    "#48484A", "accent": "#0A84FF", "green":  "#30D158",
        "red":    "#FF453A", "orange": "#FF9F0A", "yellow": "#FFD60A",
        "fg":     "#FFFFFF", "fg2":    "#EBEBF5", "fg3":    "#8E8E93",
        "border": "#3A3A3C", "card":   "#2C2C2E",
    },
    "light": {
        "bg":     "#F2F2F7", "bg2":    "#FFFFFF", "bg3":    "#E5E5EA",
        "bg4":    "#D1D1D6", "accent": "#007AFF", "green":  "#34C759",
        "red":    "#FF3B30", "orange": "#FF9500", "yellow": "#FFCC00",
        "fg":     "#000000", "fg2":    "#3C3C43", "fg3":    "#6C6C70",
        "border": "#C6C6C8", "card":   "#FFFFFF",
    }
}

def build_stylesheet(mode="dark"):
    t = THEME[mode]
    bg    = t["bg"];   bg2   = t["bg2"]; bg3   = t["bg3"]; bg4   = t["bg4"]
    fg    = t["fg"];   fg3   = t["fg3"]; acc   = t["accent"]
    bdr   = t["border"]; card = t["card"]
    acc2  = "#3395FF" if mode == "dark" else "#1A8AFF"
    return """
QMainWindow,QWidget{background:"""+bg+""";color:"""+fg+""";font-family:'Segoe UI',-apple-system,sans-serif;font-size:13px}
QLabel{color:"""+fg+""";background:transparent}
QLabel[dim="true"]{color:"""+fg3+"""}
QLabel[accent="true"]{color:"""+acc+"""}
QPushButton{background:"""+bg3+""";color:"""+fg+""";border:none;border-radius:10px;padding:7px 16px;font-size:13px;font-weight:500}
QPushButton:hover{background:"""+acc+""";color:#fff}
QPushButton:pressed{background:"""+bg4+"""}
QPushButton:checked{background:"""+acc+""";color:#fff}
QPushButton[accent="true"]{background:"""+acc+""";color:#fff;font-weight:600}
QPushButton[accent="true"]:hover{background:"""+acc2+"""}
QPushButton[danger="true"]{background:"""+t["red"]+""";color:#fff}
QPushButton[success="true"]{background:"""+t["green"]+""";color:#fff}
QPushButton[pill="true"]{border-radius:16px;padding:6px 20px}
QPushButton[nav="true"]{background:transparent;color:"""+fg3+""";border:1px solid """+bdr+""";border-radius:8px;padding:4px 10px;font-size:16px}
QPushButton[nav="true"]:hover{background:"""+acc+""";color:#fff;border-color:"""+acc+"""}
QPushButton[tab="true"]{background:transparent;color:"""+fg3+""";border:none;border-radius:0;padding:8px 14px;font-size:13px}
QPushButton[tab="true"]:checked{color:"""+acc+""";font-weight:600}
QPushButton[section="true"]{background:"""+bg2+""";color:"""+acc+""";border:none;border-left:3px solid """+acc+""";border-radius:8px;padding:6px 12px;text-align:left;font-weight:600;font-size:12px}
QPushButton[section="true"]:hover{background:"""+bg3+"""}
QPushButton[themebtn="true"]{background:"""+bg3+""";color:"""+fg+""";border:1.5px solid """+bdr+""";border-radius:10px;font-size:16px;min-width:38px;min-height:28px;padding:2px 8px;font-weight:600}
QPushButton[themebtn="true"]:hover{background:"""+acc+""";color:#fff;border-color:"""+acc+"""}
QLineEdit,QPlainTextEdit,QTextEdit,QComboBox{background:"""+bg2+""";color:"""+fg+""";border:1.5px solid """+bdr+""";border-radius:10px;padding:6px 10px;selection-background-color:"""+acc+"""}
QLineEdit:focus,QPlainTextEdit:focus,QTextEdit:focus{border-color:"""+acc+"""}
QComboBox::drop-down{border:none;width:24px}
QComboBox QAbstractItemView{background:"""+bg2+""";color:"""+fg+""";border:1px solid """+bdr+""";border-radius:8px;selection-background-color:"""+acc+"""}
QScrollBar:vertical{background:"""+bg2+""";width:6px;border-radius:3px;margin:0}
QScrollBar::handle:vertical{background:"""+bg4+""";border-radius:3px;min-height:30px}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0}
QScrollBar:horizontal{background:"""+bg2+""";height:6px;border-radius:3px}
QScrollBar::handle:horizontal{background:"""+bg4+""";border-radius:3px;min-width:30px}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{width:0}
QProgressBar{background:"""+bg3+""";border:none;border-radius:5px;height:8px;text-align:center;color:transparent}
QProgressBar::chunk{background:"""+acc+""";border-radius:5px}
QSplitter::handle{background:"""+bdr+"""}
QFrame[card="true"]{background:"""+card+""";border:1px solid """+bdr+""";border-radius:14px}
QFrame[sidebar="true"]{background:"""+bg2+""";border-right:1px solid """+bdr+"""}
QFrame[hdr="true"]{background:"""+bg2+""";border-bottom:1px solid """+bdr+"""}
QFrame[sep_line="true"]{background:"""+bdr+""";max-height:1px;border:none}
QScrollArea{border:none;background:transparent}
QScrollArea>QWidget>QWidget{background:transparent}
"""

# ── Thread→Main signaller ─────────────────────────────────────────
class _Sig(QObject):
    _call = pyqtSignal(object)
    def __init__(self):
        super().__init__()
        self._call.connect(lambda fn: fn(), Qt.ConnectionType.QueuedConnection)
    def post(self, fn):
        self._call.emit(fn)

_sig = _Sig()

# ── Animated Tab Widget ───────────────────────────────────────────
class AnimatedTabWidget(QWidget):
    tab_changed = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tabs = []
        self._idx  = 0

        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # Tab bar
        bar_frame = QFrame(); bar_frame.setObjectName("tabBar")
        bar_frame.setProperty("hdr", True)
        self._bar = QHBoxLayout(bar_frame)
        self._bar.setContentsMargins(6,0,6,0); self._bar.setSpacing(2)
        self._bar.addStretch()
        root.addWidget(bar_frame)

        # Sliding indicator line
        self._indicator = QFrame(bar_frame)
        self._indicator.setFixedHeight(2)
        self._indicator.setStyleSheet("background:#0A84FF;border-radius:1px")
        self._indicator.hide()

        # Stacked content
        self._stack = QStackedWidget()
        root.addWidget(self._stack)

        self._btn_list = []

    def add_tab(self, widget, label):
        idx = len(self._tabs)
        self._tabs.append(label)

        btn = QPushButton(label)
        btn.setProperty("tab", True)
        btn.setCheckable(True)
        btn.setChecked(idx == 0)
        btn.clicked.connect(lambda _, i=idx: self.switch_to(i))
        self._btn_list.append(btn)

        # Insert before the trailing stretch
        self._bar.insertWidget(self._bar.count() - 1, btn)
        self._stack.addWidget(widget)

        if idx == 0:
            self._indicator.show()
            QTimer.singleShot(50, self._update_indicator)

    def switch_to(self, idx):
        if idx == self._idx:
            self._btn_list[idx].setChecked(True)
            return
        self._idx = idx
        for i, b in enumerate(self._btn_list):
            b.setChecked(i == idx)

        # Fade animation
        eff = QGraphicsOpacityEffect(self._stack)
        self._stack.setGraphicsEffect(eff)
        anim = QPropertyAnimation(eff, QByteArray(b"opacity"), self)
        anim.setDuration(160)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.setStartValue(0.0); anim.setEndValue(1.0)
        self._stack.setCurrentIndex(idx)
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

        QTimer.singleShot(50, self._update_indicator)
        self.tab_changed.emit(idx)

    def _update_indicator(self):
        if self._idx >= len(self._btn_list): return
        btn = self._btn_list[self._idx]
        bar_frame = self._indicator.parent()
        if bar_frame is None: return
        x = btn.mapTo(bar_frame, QPoint(0, btn.height()-2)).x()
        w = btn.width()
        self._indicator.setGeometry(x, btn.height()-2, w, 2)

    def current_index(self): return self._idx
    def set_stylesheet(self, ss): pass  # handled by parent app

# ── Colored text display (replaces tkinter ScrolledText with tags) ─
class ColoredTextEdit(QTextEdit):
    TAG_COLORS_DARK = {
        "head":   ("#FFFFFF", True,  False),
        "red":    ("#FF453A", False, False),
        "green":  ("#30D158", False, False),
        "orange": ("#FF9F0A", False, False),
        "yellow": ("#FFD60A", False, False),
        "purple": ("#BF5AF2", False, False),
        "dim":    ("#8E8E93", False, False),
        "url":    ("#0A84FF", False, True),
        "sep":    ("#3A3A3C", False, False),
        "bold":   ("#FFFFFF", True,  False),
        "default":("#FFFFFF", False, False),
    }
    TAG_COLORS_LIGHT = {
        "head":   ("#000000", True,  False),
        "red":    ("#FF3B30", False, False),
        "green":  ("#34C759", False, False),
        "orange": ("#FF9500", False, False),
        "yellow": ("#FFCC00", False, False),
        "purple": ("#AF52DE", False, False),
        "dim":    ("#6C6C70", False, False),
        "url":    ("#007AFF", False, True),
        "sep":    ("#C6C6C8", False, False),
        "bold":   ("#000000", True,  False),
        "default":("#000000", False, False),
    }

    def __init__(self, mode="dark", parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 11))
        self._mode = mode
        self._apply_colors()

    def set_mode(self, mode):
        self._mode = mode
        self._apply_colors()

    def _apply_colors(self):
        bg = THEME[self._mode]["bg"]
        fg = THEME[self._mode]["fg"]
        self.setStyleSheet(
            f"QTextEdit{{background:{bg};color:{fg};border:none;"
            f"border-radius:0;padding:6px;font-family:Consolas,monospace}}")

    def _tag_colors(self): 
        return self.TAG_COLORS_DARK if self._mode == "dark" else self.TAG_COLORS_LIGHT

    def insert_tagged(self, text, tag="default"):
        col_table = self._tag_colors()
        entry = col_table.get(tag, col_table["default"])
        color, bold, italic = entry
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        if bold:   fmt.setFontWeight(QFont.Weight.Bold)
        if italic: fmt.setFontItalic(True)
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text, fmt)
        self.setTextCursor(cursor)

    def append_line(self, text="", tag="default"):
        self.insert_tagged(text + "\n", tag)

    def clear_all(self):
        self.clear()


# ══════════════════════════════════════════════════════════════════
# MAIN APPLICATION CLASS
# ══════════════════════════════════════════════════════════════════
class OSINTApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config_data = load_config()
        self.osint       = OSINTModule(self.config_data)
        self.api_results: list  = []
        self.sandbox_images: dict = {}
        self._current_report_url: str | None = None
        self._mode = "osint"
        self._ph_data: dict = {}
        self._ph_url_results: dict  = {}
        self._ph_ip_results:  dict  = {}
        self._ph_pending_scans: list = []
        self._ph_texts: dict = {}
        self._dark = False
        self._nav_idx = 0
        self._nav_iocs: list = []
        self._nav_hdrs: list = []
        self._lookup_running = False

        self.setWindowTitle("MultiOSINT v11  ·  OSINT Multi-Search Platform")
        try:
            _ico = os.path.join(_SCRIPT_DIR, "myicon.ico")
            if os.path.exists(_ico):
                self.setWindowIcon(QIcon(_ico))
        except Exception:
            pass
        self.setMinimumSize(1200, 750)
        self.resize(1400, 880)
        self._apply_theme()
        self._build_ui()
        _splash_win.hide()

    # ─── Theme ──────────────────────────────────────────────────────
    def _apply_theme(self):
        global _current_theme
        mode = "dark" if self._dark else "light"
        _current_theme = mode
        t = THEME[mode]
        self.setStyleSheet(build_stylesheet(mode))
        # Update theme toggle button icon
        if hasattr(self, "_theme_btn"):
            self._theme_btn.setText("☀️" if self._dark else "🌙")
        # Update Consolas text areas (have inline styles, must update manually)
        te_style = (f"QTextEdit{{background:{t['bg']};color:{t['fg']};border:none;"
                    f"border-radius:0;padding:8px;font-family:Consolas,monospace}}")
        if hasattr(self, "_results_te"):
            self._results_te.setStyleSheet(te_style)
        if hasattr(self, "_ai_te"):
            self._ai_te.setStyleSheet(
                f"QTextEdit{{background:{t['bg2']};color:{t['fg']};border:none;"
                f"border-radius:0;padding:8px;font-family:'Segoe UI',sans-serif}}")
        if hasattr(self, "_urls_te"):
            self._urls_te.setStyleSheet(te_style)
        # Update ColoredTextEdit instances in phishing pane
        for te in self._ph_texts.values():
            if isinstance(te, ColoredTextEdit):
                te.set_mode(mode)
        # Update nav section header buttons (hardcoded style cleared by setting explicit property)
        for btn in getattr(self, "_nav_hdrs", []):
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        # Update AnimatedTabWidget accent indicator
        if hasattr(self, "_osint_tabs"):
            self._osint_tabs._indicator.setStyleSheet(
                f"background:{t['accent']};border-radius:1px")

    def _toggle_theme(self):
        self._dark = not self._dark
        self._apply_theme()


    # ─── UI scaffold ────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        root.addWidget(self._build_header())

        body = QSplitter(Qt.Orientation.Horizontal)
        body.setHandleWidth(1)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_main())
        body.setSizes([310, 900])
        root.addWidget(body, 1)

        root.addWidget(self._build_footer())

    # ─── Header ─────────────────────────────────────────────────────
    def _build_header(self):
        hdr = QFrame(); hdr.setProperty("hdr", True)
        lay = QHBoxLayout(hdr); lay.setContentsMargins(18,10,18,10)

        logo = QLabel("⚡  MultiOSINT v11")
        logo.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        logo.setProperty("accent", True)
        lay.addWidget(logo)

        sub = QLabel("OSINT Multi-Search Platform")
        sub.setProperty("dim", True)
        sub.setFont(QFont("Segoe UI", 10))
        lay.addWidget(sub)
        lay.addStretch()

        for label, slot in [("🔍 OSINT Lookup", self._mode_osint),
                             ("🎣 Phishing Analyzer", self._mode_phishing)]:
            btn = QPushButton(label); btn.setCheckable(True)
            btn.setProperty("pill", True)
            btn.clicked.connect(slot)
            lay.addWidget(btn)
            if not hasattr(self, "_mode_btns"): self._mode_btns = []
            self._mode_btns.append(btn)

        self._mode_btns[0].setChecked(True)
        return hdr

    def _mode_osint(self):
        self._mode = "osint"
        self._mode_btns[0].setChecked(True)
        self._mode_btns[1].setChecked(False)
        if hasattr(self, "_panel_stack"): self._panel_stack.setCurrentIndex(0)

    def _mode_phishing(self):
        self._mode = "phishing"
        self._mode_btns[0].setChecked(False)
        self._mode_btns[1].setChecked(True)
        if hasattr(self, "_panel_stack"): self._panel_stack.setCurrentIndex(1)

    # ─── Sidebar ────────────────────────────────────────────────────
    def _build_sidebar(self):
        side = QFrame(); side.setProperty("sidebar", True); side.setMinimumWidth(260); side.setMaximumWidth(380)
        lay  = QVBoxLayout(side); lay.setContentsMargins(12,14,12,12); lay.setSpacing(10)

        title = QLabel("IOC Input"); title.setFont(QFont("Segoe UI",11,QFont.Weight.Bold))
        lay.addWidget(title)

        # IOC entry
        ioc_hint = QLabel("Enter IPs, domains, hashes, emails (one per line)")
        ioc_hint.setProperty("dim", True); ioc_hint.setWordWrap(True)
        ioc_hint.setFont(QFont("Segoe UI",9))
        lay.addWidget(ioc_hint)

        self._ioc_entry = QPlainTextEdit()
        self._ioc_entry.setMinimumHeight(100); self._ioc_entry.setMaximumHeight(160)
        lay.addWidget(self._ioc_entry)

        # Lookup button
        go_btn = QPushButton("🔍  Run Lookup"); go_btn.setProperty("accent","true")
        go_btn.setMinimumHeight(38)
        go_btn.clicked.connect(self._run_lookup)
        lay.addWidget(go_btn)

        # Clear
        cl_btn = QPushButton("⊘  Clear"); cl_btn.clicked.connect(self._clear_results)
        lay.addWidget(cl_btn)

        sep1 = QFrame(); sep1.setFrameShape(QFrame.Shape.HLine)
        sep1.setProperty("sep_line", True); lay.addWidget(sep1)

        # Export
        exp_lbl = QLabel("Export"); exp_lbl.setFont(QFont("Segoe UI",10,QFont.Weight.Bold))
        lay.addWidget(exp_lbl)
        for lbl, slot in [("📄 Export TXT", lambda: self._export("txt")),
                           ("📊 Export CSV", lambda: self._export("csv"))]:
            b = QPushButton(lbl); b.clicked.connect(slot); lay.addWidget(b)

        sep2 = QFrame(); sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setProperty("sep_line", True); lay.addWidget(sep2)

        # AI Summary
        ai_lbl = QLabel("AI Analysis"); ai_lbl.setFont(QFont("Segoe UI",10,QFont.Weight.Bold))
        lay.addWidget(ai_lbl)
        ai_btn = QPushButton("🤖  Gemini AI Summary"); ai_btn.clicked.connect(self._run_ai_summary)
        self._ai_sidebar_btn = ai_btn
        lay.addWidget(ai_btn)

        lay.addStretch()

        # Progress
        self._progress = QProgressBar(); self._progress.setValue(0)
        self._progress.setTextVisible(False); self._progress.setFixedHeight(6)
        lay.addWidget(self._progress)
        self._status_lbl = QLabel("Ready"); self._status_lbl.setProperty("dim",True)
        self._status_lbl.setFont(QFont("Segoe UI",9))
        lay.addWidget(self._status_lbl)

        return side


    # ─── Main panel (OSINT + Phishing stacked) ──────────────────────
    def _build_main(self):
        self._panel_stack = QStackedWidget()
        self._panel_stack.addWidget(self._build_osint_panel())
        self._panel_stack.addWidget(self._build_phishing_panel())
        return self._panel_stack

    # ─── OSINT panel ────────────────────────────────────────────────
    def _build_osint_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
        tabs = AnimatedTabWidget()
        lay.addWidget(tabs)
        tabs.add_tab(self._build_results_tab(), "📋 Results")
        tabs.add_tab(self._build_ai_tab(),      "🤖 AI Summary")
        tabs.add_tab(self._build_urls_tab(),    "🔗 Quick Links")
        tabs.add_tab(self._build_sandbox_tab(), "🖼️ Sandbox")
        tabs.add_tab(self._build_navigator_tab(), "🧭 Navigator")
        tabs.add_tab(self._build_settings_tab(), "⚙️ Settings")
        self._osint_tabs = tabs
        return w

    def _build_results_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w); lay.setContentsMargins(8,8,8,8); lay.setSpacing(6)
        self._results_te = QTextEdit(); self._results_te.setReadOnly(True)
        self._results_te.setFont(QFont("Consolas", 11))
        mode = "dark" if self._dark else "light"
        bg = THEME[mode]["bg"]; fg = THEME[mode]["fg"]
        self._results_te.setStyleSheet(
            f"QTextEdit{{background:{bg};color:{fg};border:none;border-radius:0;padding:8px;font-family:Consolas,monospace}}")
        self._results_te.setPlaceholderText(
            "OSINT results will appear here after running a lookup...\n\n"
            "Enter IOCs in the left panel and click 'Run Lookup'.")
        lay.addWidget(self._results_te)
        return w

    def _build_ai_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w); lay.setContentsMargins(8,8,8,8); lay.setSpacing(6)
        bar = QHBoxLayout()
        lbl = QLabel("Gemini AI Analysis"); lbl.setFont(QFont("Segoe UI",11,QFont.Weight.Bold))
        bar.addWidget(lbl); bar.addStretch()
        mdl_lbl = QLabel("✦ gemini-flash-latest"); mdl_lbl.setProperty("dim",True)
        mdl_lbl.setFont(QFont("Segoe UI",9))
        bar.addWidget(mdl_lbl)
        run_btn = QPushButton("🤖  Analyze"); run_btn.setProperty("accent","true")
        run_btn.clicked.connect(self._run_ai_summary)
        self._ai_run_btn = run_btn
        bar.addWidget(run_btn)
        lay.addLayout(bar)

        self._ai_te = QTextEdit(); self._ai_te.setReadOnly(True)
        self._ai_te.setFont(QFont("Segoe UI",12))
        self._ai_te.setPlaceholderText("AI-generated threat intelligence report will appear here.\n\nRun a lookup first, then click 'Gemini AI Summary'.")
        lay.addWidget(self._ai_te)
        return w

    def _build_urls_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w); lay.setContentsMargins(8,8,8,8); lay.setSpacing(6)
        lbl = QLabel("Quick Links — open OSINT URLs in browser")
        lbl.setProperty("dim",True)
        lay.addWidget(lbl)
        self._urls_te = QTextEdit(); self._urls_te.setReadOnly(True)
        self._urls_te.setFont(QFont("Consolas",11))
        lay.addWidget(self._urls_te)
        open_btn = QPushButton("🌐  Open All in Browser")
        open_btn.setProperty("accent","true")
        open_btn.clicked.connect(self._open_all_urls)
        lay.addWidget(open_btn)
        return w

    def _build_sandbox_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w); lay.setContentsMargins(8,8,8,8); lay.setSpacing(6)
        bar = QHBoxLayout()
        lbl = QLabel("URLScan.io Screenshot"); lbl.setFont(QFont("Segoe UI",11,QFont.Weight.Bold))
        bar.addWidget(lbl); bar.addStretch()
        self._sb_ioc = QLineEdit(); self._sb_ioc.setPlaceholderText("domain or URL to scan")
        self._sb_ioc.setMaximumWidth(300); bar.addWidget(self._sb_ioc)
        sb_btn = QPushButton("📸  Capture Screenshot"); sb_btn.setProperty("accent","true")
        sb_btn.clicked.connect(self._run_sandbox)
        bar.addWidget(sb_btn)
        self._sb_open_btn = QPushButton("🔗  Open Report")
        self._sb_open_btn.setEnabled(False)
        self._sb_open_btn.clicked.connect(self._sb_open_report)
        bar.addWidget(self._sb_open_btn)
        lay.addLayout(bar)
        self._sb_status = QLabel("Enter a domain/URL above and click Capture Screenshot.")
        self._sb_status.setProperty("dim",True); lay.addWidget(self._sb_status)
        self._sb_img_lbl = QLabel(); self._sb_img_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scroll = QScrollArea(); scroll.setWidget(self._sb_img_lbl); scroll.setWidgetResizable(True)
        lay.addWidget(scroll)
        return w

    def _sb_open_report(self):
        if self._current_report_url:
            webbrowser.open_new_tab(self._current_report_url)

    # ─── Navigator tab ──────────────────────────────────────────────
    def _build_navigator_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w); lay.setContentsMargins(10,10,10,10); lay.setSpacing(8)

        # ── Top control bar ──────────────────────────────────────────
        ctrl = QHBoxLayout()
        nav_lbl = QLabel("IOC:"); nav_lbl.setProperty("dim",True)
        ctrl.addWidget(nav_lbl)

        self._nav_ioc_entry = QLineEdit()
        self._nav_ioc_entry.setPlaceholderText("IOC for navigator lookups…")
        self._nav_ioc_entry.setMinimumWidth(220)
        ctrl.addWidget(self._nav_ioc_entry, 1)

        # ← Up arrow
        self._nav_up_btn = QPushButton("▲")
        self._nav_up_btn.setProperty("nav","true")
        self._nav_up_btn.setFixedSize(34,34)
        self._nav_up_btn.setToolTip("Previous IOC")
        self._nav_up_btn.clicked.connect(self._nav_prev)
        ctrl.addWidget(self._nav_up_btn)

        # Counter label
        self._nav_counter = QLabel("0/0")
        self._nav_counter.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._nav_counter.setMinimumWidth(44)
        self._nav_counter.setProperty("dim",True)
        ctrl.addWidget(self._nav_counter)

        # ↓ Down arrow
        self._nav_dn_btn = QPushButton("▼")
        self._nav_dn_btn.setProperty("nav","true")
        self._nav_dn_btn.setFixedSize(34,34)
        self._nav_dn_btn.setToolTip("Next IOC")
        self._nav_dn_btn.clicked.connect(self._nav_next)
        ctrl.addWidget(self._nav_dn_btn)

        # Filter
        filt_lbl = QLabel("Filter:"); filt_lbl.setProperty("dim",True)
        ctrl.addWidget(filt_lbl)
        self._nav_filter = QLineEdit(); self._nav_filter.setPlaceholderText("search tools…")
        self._nav_filter.setMaximumWidth(170)
        self._nav_filter.textChanged.connect(self._nav_apply_filter)
        ctrl.addWidget(self._nav_filter)

        exp_btn = QPushButton("Expand All");   exp_btn.clicked.connect(lambda: self._nav_set_all(True))
        col_btn = QPushButton("Collapse All"); col_btn.clicked.connect(lambda: self._nav_set_all(False))
        ctrl.addWidget(exp_btn); ctrl.addWidget(col_btn)
        lay.addLayout(ctrl)

        # ── Scrollable tool grid ────────────────────────────────────
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        container = QWidget(); scroll.setWidget(container)
        self._nav_vlay = QVBoxLayout(container)
        self._nav_vlay.setContentsMargins(4,4,4,4); self._nav_vlay.setSpacing(6)
        lay.addWidget(scroll, 1)
        self._nav_sections = {}
        self._nav_build_sections()
        return w

    def _nav_build_sections(self):
        for cat, tools in NAV_TOOLS.items():
            # section wrapper
            sec_frame = QFrame()
            sec_lay   = QVBoxLayout(sec_frame); sec_lay.setContentsMargins(0,0,0,0); sec_lay.setSpacing(2)

            # header button - theme-aware via property
            hdr_btn = QPushButton(f"▼  {cat}")
            hdr_btn.setProperty("section", True)
            hdr_btn.setMinimumHeight(32)
            self._nav_hdrs.append(hdr_btn)

            # tool grid
            grid_w = QWidget()
            grid = QGridLayout(grid_w); grid.setContentsMargins(4,4,4,4); grid.setSpacing(4)
            col, row = 0, 0
            btn_list = []
            for tool in tools:
                name = tool["name"]
                desc = tool.get("desc","")
                url  = tool.get("url","")
                skip = tool.get("skipSearch", False)
                b = QPushButton(name)
                b.setToolTip(f"{desc}\n{url}")
                b.setFixedHeight(28)
                b.setFont(QFont("Segoe UI",10))
                b.clicked.connect(lambda _, u=url, s=skip: self._nav_open(u, s))
                grid.addWidget(b, row, col)
                btn_list.append((b, name, desc, tool.get("tags",[])))
                col += 1
                if col >= 5: col = 0; row += 1
            sec_lay.addWidget(hdr_btn)
            sec_lay.addWidget(grid_w)
            self._nav_vlay.addWidget(sec_frame)

            state = {"frame": sec_frame, "hdr": hdr_btn, "grid": grid_w, "btns": btn_list, "open": True}
            self._nav_sections[cat] = state
            hdr_btn.clicked.connect(lambda _, c=cat: self._nav_toggle_section(c))

        self._nav_vlay.addStretch()

    def _nav_toggle_section(self, cat):
        s = self._nav_sections[cat]
        s["open"] = not s["open"]
        s["grid"].setVisible(s["open"])
        arrow = "▼" if s["open"] else "▲"
        s["hdr"].setText(f"{arrow}  {cat}")

    def _nav_set_all(self, open_all):
        for cat, s in self._nav_sections.items():
            s["open"] = open_all
            s["grid"].setVisible(open_all)
            arrow = "▼" if open_all else "▲"
            s["hdr"].setText(f"{arrow}  {cat}")

    def _nav_apply_filter(self, text):
        q = text.lower().strip()
        for cat, s in self._nav_sections.items():
            any_vis = False
            for btn, name, desc, tags in s["btns"]:
                vis = (not q or q in name.lower() or q in desc.lower()
                       or any(q in t.lower() for t in tags))
                btn.setVisible(vis)
                if vis: any_vis = True
            s["frame"].setVisible(any_vis or not q)

    def _nav_open(self, url_base, skip_ioc):
        ioc = self._nav_ioc_entry.text().strip()
        if ioc and not skip_ioc:
            webbrowser.open_new_tab(url_base + ioc)
        else:
            webbrowser.open_new_tab(url_base)

    # IOC navigation with ▲ ▼
    def _nav_refresh_iocs(self):
        raw = self._ioc_entry.toPlainText()
        iocs = [OSINTModule.clean_ioc(ln.strip()) for ln in raw.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        self._nav_iocs = [i for i in iocs if i]
        total = len(self._nav_iocs)
        if total == 0:
            self._nav_counter.setText("0/0")
            return
        self._nav_idx = max(0, min(self._nav_idx, total - 1))
        self._nav_ioc_entry.setText(self._nav_iocs[self._nav_idx])
        self._nav_counter.setText(f"{self._nav_idx + 1}/{total}")

    def _nav_prev(self):
        self._nav_refresh_iocs()
        if not self._nav_iocs: return
        self._nav_idx = (self._nav_idx - 1) % len(self._nav_iocs)
        self._nav_ioc_entry.setText(self._nav_iocs[self._nav_idx])
        self._nav_counter.setText(f"{self._nav_idx + 1}/{len(self._nav_iocs)}")

    def _nav_next(self):
        self._nav_refresh_iocs()
        if not self._nav_iocs: return
        self._nav_idx = (self._nav_idx + 1) % len(self._nav_iocs)
        self._nav_ioc_entry.setText(self._nav_iocs[self._nav_idx])
        self._nav_counter.setText(f"{self._nav_idx + 1}/{len(self._nav_iocs)}")


    # ─── Settings tab ───────────────────────────────────────────────
    def _build_settings_tab(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        container = QWidget(); scroll.setWidget(container)
        lay = QVBoxLayout(container); lay.setContentsMargins(16,16,16,16); lay.setSpacing(14)

        title = QLabel("API Key Configuration")
        title.setFont(QFont("Segoe UI",14,QFont.Weight.Bold))
        lay.addWidget(title)
        sub = QLabel("API keys are stored locally in config.json. They are never sent anywhere except to the respective APIs.")
        sub.setProperty("dim",True); sub.setWordWrap(True)
        lay.addWidget(sub)

        keys = [
            ("virustotal",  "VirusTotal API Key",      "https://www.virustotal.com/gui/user/apikey"),
            ("abuseipdb",   "AbuseIPDB API Key",        "https://www.abuseipdb.com/account/api"),
            ("urlscan",     "URLScan.io API Key",       "https://urlscan.io/user/"),
            ("greynoise",   "GreyNoise API Key",        "https://viz.greynoise.io/account/api-key"),
            ("otx",         "OTX AlienVault API Key",   "https://otx.alienvault.com/api"),
            ("shodan",      "Shodan API Key",            "https://account.shodan.io/"),
            ("abusech",     "Abuse.ch API Key",         "https://auth.abuse.ch/"),
            ("hibp",        "HaveIBeenPwned API Key",   "https://haveibeenpwned.com/API/Key"),
            ("joe_key",     "Joe Sandbox API Key",      "https://www.joesecurity.org/"),
            ("joe_server",  "Joe Sandbox Server URL",   ""),
            ("gemini_key",  "Google Gemini API Key",    "https://makersuite.google.com/app/apikey"),
            ("ipqs",        "IPQualityScore API Key",   "https://www.ipqualityscore.com/user/settings"),
            ("criminalip",  "CriminalIP API Key",       "https://www.criminalip.io/mypage/information"),
            ("pulsedive",   "Pulsedive API Key",        "https://pulsedive.com/account/"),
        ]

        self._cfg_entries = {}
        for cfg_key, label, docs_url in keys:
            row = QHBoxLayout()
            lbl = QLabel(label); lbl.setMinimumWidth(220)
            row.addWidget(lbl)
            entry = QLineEdit(self.config_data.get(cfg_key,""))
            entry.setEchoMode(QLineEdit.EchoMode.Normal if cfg_key == "joe_server" else QLineEdit.EchoMode.Password)
            row.addWidget(entry, 1)
            if docs_url:
                link = QPushButton("Docs"); link.setMaximumWidth(60)
                link.clicked.connect(lambda _, u=docs_url: webbrowser.open_new_tab(u))
                row.addWidget(link)
            self._cfg_entries[cfg_key] = entry
            lay.addLayout(row)

        btn_row = QHBoxLayout()
        save_btn = QPushButton("💾  Save API Keys"); save_btn.setProperty("accent","true")
        save_btn.setMinimumHeight(38)
        save_btn.clicked.connect(self._save_settings)
        btn_row.addWidget(save_btn)
        self._show_keys_btn = QPushButton("👁  Show Keys")
        self._show_keys_btn.setMinimumHeight(38)
        self._show_keys_btn.setCheckable(True)
        self._show_keys_btn.clicked.connect(self._toggle_api_visibility)
        btn_row.addWidget(self._show_keys_btn)
        lay.addLayout(btn_row)
        self._settings_msg = QLabel("")
        self._settings_msg.setProperty("dim",True)
        lay.addWidget(self._settings_msg)
        lay.addStretch()
        return scroll

    def _save_settings(self):
        for k, entry in self._cfg_entries.items():
            self.config_data[k] = entry.text().strip()
        res = save_config(self.config_data)
        self.osint.config = self.config_data
        if res is True:
            self._settings_msg.setText("✅ Saved successfully.")
        else:
            self._settings_msg.setText(f"❌ Save failed: {res}")

    def _toggle_api_visibility(self):
        show = self._show_keys_btn.isChecked()
        self._show_keys_btn.setText("🔒  Hide Keys" if show else "👁  Show Keys")
        for k, entry in self._cfg_entries.items():
            if k != "joe_server":
                entry.setEchoMode(
                    QLineEdit.EchoMode.Normal if show
                    else QLineEdit.EchoMode.Password)

    # ─── Phishing panel ─────────────────────────────────────────────
    def _build_phishing_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
        tabs = AnimatedTabWidget()
        lay.addWidget(tabs)

        sub_tabs = ["📋 Summary","📨 Headers","🔗 URLs","🌐 IPs","📎 Attachments","📝 Work Note"]
        for t in sub_tabs:
            if t == "📝 Work Note":
                fw = QWidget(); fl = QVBoxLayout(fw); fl.setContentsMargins(6,6,6,6); fl.setSpacing(4)
                bar = QHBoxLayout()
                cp_btn = QPushButton("📋 Copy"); cp_btn.clicked.connect(self._ph_copy_worknote)
                bar.addStretch(); bar.addWidget(cp_btn)
                fl.addLayout(bar)
                te = ColoredTextEdit("dark" if self._dark else "light")
                fl.addWidget(te)
                self._ph_texts[t] = te
                tabs.add_tab(fw, t)
            else:
                te = ColoredTextEdit("dark" if self._dark else "light")
                self._ph_texts[t] = te
                tabs.add_tab(te, t)

        # toolbar
        tool_bar = QFrame(); tool_bar.setProperty("hdr",True)
        tb_lay = QHBoxLayout(tool_bar); tb_lay.setContentsMargins(12,8,12,8); tb_lay.setSpacing(8)
        open_btn = QPushButton("📂  Open .eml / .msg"); open_btn.setProperty("accent","true")
        open_btn.clicked.connect(self._ph_open_file)
        tb_lay.addWidget(open_btn)
        self._ph_file_lbl = QLabel("No file loaded")
        self._ph_file_lbl.setProperty("dim",True)
        tb_lay.addWidget(self._ph_file_lbl)
        tb_lay.addStretch()
        refresh_btn = QPushButton("🔄 Refresh Pending Scans")
        refresh_btn.clicked.connect(self._ph_refresh_pending)
        tb_lay.addWidget(refresh_btn)
        self._ph_verdict_lbl = QLabel("")
        self._ph_verdict_lbl.setFont(QFont("Segoe UI",12,QFont.Weight.Bold))
        tb_lay.addWidget(self._ph_verdict_lbl)

        # Stack: toolbar first, then tabs
        container = QWidget()
        cl = QVBoxLayout(container); cl.setContentsMargins(0,0,0,0); cl.setSpacing(0)
        cl.addWidget(tool_bar)
        cl.addWidget(tabs, 1)
        return container

    def _ph_copy_worknote(self):
        te = self._ph_texts.get("📝 Work Note")
        if te:
            QApplication.clipboard().setText(te.toPlainText())

    # ─── Footer ─────────────────────────────────────────────────────
    def _build_footer(self):
        footer = QFrame(); footer.setProperty("hdr",True); footer.setFixedHeight(36)
        lay = QHBoxLayout(footer); lay.setContentsMargins(14,0,14,0)
        copy_lbl = QLabel("MultiOSINT v11  ·  © 2025")
        copy_lbl.setProperty("dim",True); copy_lbl.setFont(QFont("Segoe UI",9))
        lay.addWidget(copy_lbl)
        lay.addStretch()
        self._theme_btn = QPushButton("🌙")
        self._theme_btn.setProperty("themebtn", "true")
        self._theme_btn.setFixedSize(44, 30)
        self._theme_btn.setToolTip("Toggle Light / Dark mode")
        self._theme_btn.clicked.connect(self._toggle_theme)
        lay.addWidget(self._theme_btn)
        return footer

    # ─── Lookup logic ────────────────────────────────────────────────
    def _run_lookup(self):
        if self._lookup_running:
            self._status_lbl.setText("Lookup already running…")
            return
        raw = self._ioc_entry.toPlainText().strip()
        if not raw:
            self._status_lbl.setText("Enter at least one IOC."); return
        iocs = [OSINTModule.clean_ioc(l.strip()) for l in raw.splitlines()
                if l.strip() and not l.strip().startswith("#")]
        iocs = list(dict.fromkeys(i for i in iocs if i))
        if not iocs: return
        self._lookup_running = True
        self.api_results = []
        self._results_te.clear()
        self._status_lbl.setText(f"Running lookup for {len(iocs)} IOC(s)…")
        self._progress.setValue(0); self._progress.setMaximum(len(iocs))

        def worker():
            for i, ioc in enumerate(iocs):
                r = self._lookup_single(ioc)
                self.api_results.append(r)
                text = self._format_result(r)
                _sig.post(lambda t=text: self._append_result(t))
                _sig.post(lambda v=i+1: self._progress.setValue(v))
                _sig.post(lambda v=i+1, total=len(iocs):
                          self._status_lbl.setText(f"Done {v}/{total}"))
            _sig.post(self._lookup_done)

        threading.Thread(target=worker, daemon=True).start()
        # refresh navigator counter whenever lookup runs
        QTimer.singleShot(200, self._nav_refresh_iocs)

    def _append_result(self, text):
        cursor = self._results_te.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self._results_te.setTextCursor(cursor)
        self._results_te.ensureCursorVisible()

    def _lookup_done(self):
        self._lookup_running = False
        total = len(self.api_results)
        self._status_lbl.setText(f"✅ Complete — {total} IOC(s) analyzed")
        self._progress.setValue(self._progress.maximum())
        self._build_url_tab()
        self._nav_refresh_iocs()


    # ─── Core per-IOC lookup (runs in thread) ───────────────────────
    def _lookup_single(self, cleaned):
        ioc_type = self.osint.get_ioc_type(cleaned)
        futures = {}
        ex = ThreadPoolExecutor(max_workers=12)
        if ioc_type == "email":
            futures["xon"]  = ex.submit(self.osint.check_hibp,     cleaned)
            futures["ipqs"] = ex.submit(self.osint.check_ipqs,      cleaned, "email")
            futures["bvip"] = ex.submit(self.osint.check_breachvip, cleaned, "email")
        else:
            futures["vt"]  = ex.submit(self.osint.check_virustotal, cleaned, ioc_type)
            futures["otx"] = ex.submit(self.osint.check_otx,        cleaned, ioc_type)
            futures["pd"]  = ex.submit(self.osint.check_pulsedive,  cleaned, ioc_type)
            if ioc_type == "ip":
                futures["abip"] = ex.submit(self.osint.check_abuseipdb, cleaned)
                futures["gn"]   = ex.submit(self.osint.check_greynoise,  cleaned)
                futures["shd"]  = ex.submit(self.osint.check_shodan,     cleaned)
                futures["cip"]  = ex.submit(self.osint.check_criminalip, cleaned)
                futures["ipqs"] = ex.submit(self.osint.check_ipqs,       cleaned, "ip")
        if ioc_type == "ip":
            futures["geo"]  = ex.submit(self.osint.check_ipapi,       cleaned)
            futures["rdns"] = ex.submit(self.osint.check_reverse_dns, cleaned)
            futures["tf"]   = ex.submit(self.osint.check_threatfox,   cleaned)
            futures["uh"]   = ex.submit(self.osint.check_urlhaus,     cleaned, ioc_type)
        elif ioc_type == "domain":
            futures["dns"]  = ex.submit(self.osint.check_dns,       cleaned)
            futures["wh"]   = ex.submit(self.osint.check_whois,     cleaned)
            futures["tf"]   = ex.submit(self.osint.check_threatfox, cleaned)
            futures["uh"]   = ex.submit(self.osint.check_urlhaus,   cleaned, ioc_type)
            futures["pt"]   = ex.submit(self.osint.check_phishtank, cleaned)
            futures["ipqs"] = ex.submit(self.osint.check_ipqs,      cleaned, "domain")
        elif ioc_type == "hash":
            futures["mb"]  = ex.submit(self.osint.check_malwarebazaar, cleaned)
            futures["tf"]  = ex.submit(self.osint.check_threatfox,     cleaned)
            futures["uh"]  = ex.submit(self.osint.check_urlhaus,       cleaned, ioc_type)
            futures["hl"]  = ex.submit(self.osint.check_hashlookup,    cleaned)
        results = {}
        for key, fut in futures.items():
            try:    results[key] = fut.result(timeout=45)
            except: results[key] = None
        ex.shutdown(wait=False)
        results["_ioc"]      = cleaned
        results["_ioc_type"] = ioc_type
        return results

    def _format_result(self, results):
        cleaned  = results.get("_ioc","?")
        ioc_type = results.get("_ioc_type","?")
        vt   = results.get("vt")
        abip = results.get("abip")
        gn   = results.get("gn")
        otx  = results.get("otx")
        shd  = results.get("shd")
        hibp = results.get("xon")
        geo  = results.get("geo") or {}
        rdns = results.get("rdns","")
        dns_r = results.get("dns") or {}
        wh   = results.get("wh") or {}
        uh   = results.get("uh")
        mb   = results.get("mb")
        tf   = results.get("tf")
        pd   = results.get("pd")
        cip  = results.get("cip")
        ipqs = results.get("ipqs")
        hl   = results.get("hl")
        pt   = results.get("pt")
        bvip = results.get("bvip")

        lines = [f"\n{'='*62}", f"  IOC: {cleaned}  [{ioc_type.upper()}]", f"{'='*62}"]

        if ioc_type == "email":
            if hibp and not hibp.get("xon_error"):
                lines += ["\n▸ Breach Check  (XposedOrNot — free)", f"  {hibp['xon_verdict']}"]
                for br in hibp.get("breaches",[])[:15]:
                    ln = f"  🔴 {br['name']}"
                    if br.get("domain"):  ln += f"  [{br['domain']}]"
                    if br.get("date"):    ln += f"  ({br['date']})"
                    if br.get("records"): ln += f"  ~{br['records']:,} records"
                    lines.append(ln)
                    if br.get("data_classes"): lines.append(f"     Data: {br['data_classes']}")
            if ipqs and not ipqs.get("ipqs_error") and ipqs.get("ipqs_verdict"):
                lines += ["\n▸ IPQualityScore  (Email)",
                          f"  {ipqs.get('ipqs_verdict','')}  ·  Fraud Score: {ipqs.get('ipqs_fraud_score','')}",
                          f"  Disposable: {ipqs.get('ipqs_disposable','?')}"]
            if bvip and not bvip.get("bvip_error") and bvip.get("bvip_count",0) > 0:
                lines += ["\n▸ Breach.VIP  (free)", f"  {bvip['bvip_verdict']}"]
                for item in bvip.get("bvip_results",[])[:20]:
                    cats = item.get("categories","")
                    if isinstance(cats,list): cats=", ".join(cats)
                    ln = f"  🔴 {item['source']}"
                    if cats: ln += f"  [{cats}]"
                    lines.append(ln)
            return "\n".join(lines) + "\n"

        if vt and not vt.get("vt_error"):
            lines += ["\n▸ VirusTotal",
                      f"  {vt['vt_verdict']}  ·  Mal: {vt['malicious']}  Sus: {vt['suspicious']}  OK: {vt['harmless']}",
                      f"  VT Score: {vt['vt_score']}  ·  Last: {vt.get('last_analysis_date') or 'n/a'}"]
            for k,lbl in [("creation_date","Created"),("registrar","Registrar"),("categories","Categories"),
                          ("last_http_code","Last HTTP"),("as_owner","AS Owner"),("network","Network"),
                          ("threat_label","Threat"),("file_names","File"),("file_type","Type")]:
                if vt.get(k): lines.append(f"  {lbl}: {vt[k]}")

        if ioc_type == "ip":
            if abip and not abip.get("abuse_error"):
                lines += ["\n▸ AbuseIPDB",
                          f"  {abip['abuse_verdict']}  ·  Score: {abip['abuse_score']}%  Reports: {abip['total_reports']}",
                          f"  ISP: {abip['isp']}  Country: {abip['country']}"]
            if gn and not gn.get("gn_error"):
                lines += ["\n▸ GreyNoise",
                          f"  {gn['gn_verdict']}  ·  Class: {gn['classification']}  Noise: {gn['noise']}"]
            if shd and not shd.get("shodan_error") and shd.get("org"):
                lines += ["\n▸ Shodan",
                          f"  Org: {shd['org']}  Country: {shd['country']}  OS: {shd['os']}",
                          f"  Ports: {shd.get('ports','n/a')}"]
                if shd.get("vulns") and shd["vulns"]!="None": lines.append(f"  CVEs: {shd['vulns']}")
            if cip and not cip.get("cip_error") and cip.get("cip_score") not in (None,"","0",0):
                lines += ["\n▸ CriminalIP",
                          f"  {cip.get('cip_verdict','')}  Score: {cip.get('cip_score','')}",
                          f"  Type: {cip.get('cip_type','')}  Org: {cip.get('cip_org','')}"]
                if cip.get("cip_open_ports"): lines.append(f"  Ports: {cip['cip_open_ports']}")
            if ipqs and not ipqs.get("ipqs_error") and ipqs.get("ipqs_fraud_score") not in (None,"","0",0):
                lines += ["\n▸ IPQualityScore",
                          f"  {ipqs.get('ipqs_verdict','')}  FraudScore: {ipqs.get('ipqs_fraud_score','')}",
                          f"  VPN: {ipqs.get('ipqs_vpn','?')}  Proxy: {ipqs.get('ipqs_proxy','?')}  Tor: {ipqs.get('ipqs_tor','?')}"]
            if not geo.get("ipapi_error") and geo.get("country"):
                lines += ["\n▸ Geolocation  (ip-api.com)",
                          f"  {geo['city']}, {geo['region']}, {geo['country']}",
                          f"  ISP: {geo['isp']}  Proxy: {geo['proxy']}  Hosting: {geo['hosting']}"]
            if rdns: lines += ["\n▸ Reverse DNS", f"  {rdns}"]

        elif ioc_type == "domain":
            if not dns_r.get("dns_error") and any(dns_r.get(k) for k in ("a_records","mx","ns")):
                lines.append("\n▸ DNS Records")
                if dns_r.get("a_records"):  lines.append(f"  A:  {', '.join(dns_r['a_records'])}")
                if dns_r.get("mx"):         lines.append(f"  MX: {', '.join(dns_r['mx'][:3])}")
                if dns_r.get("ns"):         lines.append(f"  NS: {', '.join(dns_r['ns'][:4])}")
                for t in (dns_r.get("txt") or [])[:2]: lines.append(f"  TXT: {t[:100]}")
            if not wh.get("whois_error") and wh.get("whois_data"):
                lines += ["\n▸ WHOIS", wh["whois_data"]]
            if pt and not pt.get("pt_error") and "not" not in str(pt.get("pt_verdict","")).lower():
                lines += ["\n▸ PhishTank  (free)", f"  {pt.get('pt_verdict','')}"]
            if ipqs and not ipqs.get("ipqs_error") and ipqs.get("ipqs_fraud_score") not in (None,"","0",0):
                lines += ["\n▸ IPQualityScore  (Domain)",
                          f"  {ipqs.get('ipqs_verdict','')}  FraudScore: {ipqs.get('ipqs_fraud_score','')}"]

        if otx and not otx.get("otx_error") and otx.get("pulse_count",0) > 0:
            lines += ["\n▸ OTX AlienVault",
                      f"  {otx['otx_verdict']}  Pulses: {otx['pulse_count']}"]
            if otx.get("malware_families") and otx["malware_families"]!="None":
                lines.append(f"  Malware: {otx['malware_families']}")
        if pd and not pd.get("pd_error"):
            risk = str(pd.get("pd_risk","")).lower().strip()
            if risk and risk not in ("unknown","none","low",""):
                lines += ["\n▸ Pulsedive",
                          f"  {pd.get('pd_verdict','')}  Risk: {pd.get('pd_risk','')}"]
        if uh and not uh.get("uh_error") and uh.get("uh_threat"):
            lines += ["\n▸ URLhaus  (abuse.ch)", f"  {uh['uh_threat']}"]
        if ioc_type == "hash":
            if mb and not mb.get("mb_error") and mb.get("mb_verdict"):
                lines += ["\n▸ MalwareBazaar  (abuse.ch)", f"  {mb['mb_verdict']}"]
                if mb.get("mb_file_name"): lines.append(f"  File: {mb['mb_file_name']}")
            if hl and not hl.get("hl_error") and hl.get("hl_verdict"):
                lines += ["\n▸ CIRCL HashLookup  (free)", f"  {hl.get('hl_verdict','')}"]
        if tf and not tf.get("tf_error") and "not found" not in str(tf.get("tf_verdict","")).lower():
            lines += ["\n▸ ThreatFox  (abuse.ch)", f"  {tf['tf_verdict']}"]
        lines.append("")
        return "\n".join(lines) + "\n"

    # ─── URL tab ────────────────────────────────────────────────────
    def _build_url_tab(self):
        self._urls_te.clear()
        if not self.api_results: return
        for r in self.api_results:
            ioc = r.get("_ioc") or r.get("IOC","")
            ioc_type = r.get("_ioc_type") or r.get("Type","domain")
            if not ioc: continue
            src_list = self.osint.get_sources(ioc_type)
            pairs = self.osint.build_url_pairs(ioc, src_list)
            self._urls_te.append(f"\n{'='*62}")
            self._urls_te.append(f"  {ioc}")
            self._urls_te.append(f"{'='*62}")
            for src, url in pairs:
                self._urls_te.append(f"  {src:<22}  {url}")

    def _open_all_urls(self):
        for r in self.api_results:
            ioc = r.get("_ioc") or r.get("IOC","")
            ioc_type = r.get("_ioc_type") or r.get("Type","domain")
            if not ioc: continue
            for _, url in self.osint.build_url_pairs(ioc, self.osint.get_sources(ioc_type)):
                webbrowser.open_new_tab(url)

    # ─── Clear ──────────────────────────────────────────────────────
    def _clear_results(self):
        self.api_results = []
        self._results_te.clear()
        if hasattr(self, "_urls_te"): self._urls_te.clear()
        if hasattr(self, "_ai_te"):   self._ai_te.clear()
        self._progress.setValue(0)
        self._status_lbl.setText("Cleared.")

    # ─── AI Summary ─────────────────────────────────────────────────
    def _run_ai_summary(self):
        snap = self._results_te.toPlainText()
        if not snap.strip():
            self._ai_te.setPlaceholderText("Run a lookup first."); return
        # Prevent double-click while running
        for btn in (getattr(self, "_ai_run_btn", None), getattr(self, "_ai_sidebar_btn", None)):
            if btn: btn.setEnabled(False); btn.setText("⏳  Analyzing…")
        model = "gemini-flash-latest"
        self._ai_te.setPlainText(f"⏳  Generating report with {model}…")
        def _worker(s=snap, m=model):
            result = self.osint.check_gemini_summary(s, model=m)
            def _done(r=result):
                self._ai_te.setPlainText(r)
                for btn in (getattr(self, "_ai_run_btn", None), getattr(self, "_ai_sidebar_btn", None)):
                    if btn: btn.setEnabled(True); btn.setText("🤖  Analyze" if btn is getattr(self,"_ai_run_btn",None) else "🤖  Gemini AI Summary")
            _sig.post(_done)
        threading.Thread(target=_worker, daemon=True).start()

    # ─── Export ────────────────────────────────────────────────────
    def _export(self, fmt):
        if not self.api_results:
            QMessageBox.warning(self, "Nothing to export", "Run a lookup first."); return
        if fmt == "txt":
            path, _ = QFileDialog.getSaveFileName(self,"Save Text Report","","Text (*.txt)")
            if path:
                with open(path,"w",encoding="utf-8") as fh:
                    fh.write(self._results_te.toPlainText())
        elif fmt == "csv":
            path, _ = QFileDialog.getSaveFileName(self,"Save CSV","","CSV (*.csv)")
            if path:
                keys = list({k for r in self.api_results for k in r})
                with open(path,"w",newline="",encoding="utf-8") as fh:
                    w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
                    w.writeheader(); w.writerows(self.api_results)

    # ─── Sandbox ───────────────────────────────────────────────────
    def _run_sandbox(self):
        domain = self._sb_ioc.text().strip()
        if not domain:
            # try to pull from sidebar
            raw = self._ioc_entry.toPlainText().strip()
            for ln in raw.splitlines():
                c = OSINTModule.clean_ioc(ln.strip())
                if c and OSINTModule.get_ioc_type(c) == "domain":
                    domain = c; break
        if not domain:
            self._sb_status.setText("Enter a domain or URL above."); return
        if not self.osint.urlscan_api_key:
            self._sb_status.setText("Add URLScan.io API key in Settings."); return
        self._sb_status.setText(f"Submitting {domain}…  (up to ~75s)")

        def _callback(img_data, err, doc_url, rep_url):
            if img_data:
                try:
                    img = Image.open(BytesIO(img_data)).convert("RGB")
                    img.thumbnail((900,560))
                    w,h = img.size
                    qimg = QImage(img.tobytes("raw","RGB"), w, h,
                                  w*3, QImage.Format.Format_RGB888)
                    px = QPixmap.fromImage(qimg)
                    self._current_report_url = rep_url
                    _sig.post(lambda p=px, u=doc_url: (
                        self._sb_img_lbl.setPixmap(p),
                        self._sb_status.setText(f"Done  ·  {u or domain}"),
                        self._sb_open_btn.setEnabled(bool(rep_url))))
                except Exception as e:
                    _sig.post(lambda err2=str(e): self._sb_status.setText(f"Image error: {err2}"))
            else:
                _sig.post(lambda m=err: self._sb_status.setText(f"Failed: {m or 'No screenshot'}"))

        threading.Thread(target=self.osint.urlscan_screenshot,
                         args=(domain, _callback), daemon=True).start()


    # ─── Phishing file open ─────────────────────────────────────────
    def _ph_open_file(self):
        path, _ = QFileDialog.getOpenFileName(self,"Open Email File","",
            "Email files (*.eml *.msg);;EML (*.eml);;MSG (*.msg);;All (*.*)")
        if path:
            self._ph_file_path = path
            self._ph_file_lbl.setText(os.path.basename(path))
            self._ph_start_analysis(path)

    def _ph_start_analysis(self, path):
        for te in self._ph_texts.values():
            te.clear_all()
        self._ph_verdict_lbl.setText("⏳ Analysing…")
        threading.Thread(target=self._ph_run_analysis, args=(path,), daemon=True).start()

    def _ph_upd(self, msg):
        _sig.post(lambda m=msg: self._status_lbl.setText(m))

    def _ph_write(self, w, text, tag=None):
        w.insert_tagged(text, tag or "default")

    def _ph_clear(self, w): w.clear_all()
    def _ph_sep(self, w):   w.insert_tagged("─"*72+"\n", "sep")

    def _ph_run_analysis(self, path):
        try:
            cfg = {
                "vt_key":        self.osint.vt_api_key,
                "urlscan_key":   self.osint.urlscan_api_key,
                "abuseipdb_key": self.osint.abuseipdb_api_key,
                "joe_key":       self.osint.joe_api_key,
                "joe_server":    self.osint.joe_server,
            }
            self._ph_upd("Parsing email headers and body…")
            ext = os.path.splitext(path)[1].lower()
            ed  = parse_eml(path) if ext == ".eml" else parse_msg(path)
            if ed.get("_error"):
                _sig.post(lambda e=ed["_error"]: QMessageBox.critical(self,"Parse Error",e))
                return

            urls = ed.get("urls", [])[:20]
            self._ph_upd(f"Found {len(urls)} URLs — deobfuscating…")
            deob_map = {url: ph_unwrap_url(url) for url in urls}
            url_results = {
                url: {"deobfuscation": deob_map[url], "virustotal": {}, "urlscan": {}, "joe_sandbox": {}}
                for url in urls
            }

            def _enrich_url(url):
                deob = deob_map[url]; check_url = deob.get("final_url") or url
                vt_r = us_r = joe_r = {}
                if cfg.get("vt_key") and _ph_valid_url(check_url):
                    vt_r = ph_vt_check_url(check_url, cfg["vt_key"])
                if cfg.get("urlscan_key") and _ph_valid_url(check_url):
                    us_r = ph_urlscan_submit(check_url, cfg["urlscan_key"])
                if cfg.get("joe_key") and _ph_valid_url(check_url):
                    joe_r = ph_joe_submit(check_url, cfg["joe_key"], cfg.get("joe_server",""))
                return url, vt_r, us_r, joe_r

            if urls:
                self._ph_upd(f"Enriching {len(urls)} URLs…")
                ex = ThreadPoolExecutor(max_workers=5)
                futs = {ex.submit(_enrich_url, u): u for u in urls}
                done = 0; deadline = time.time() + 45; pending = set(futs.keys())
                while pending and time.time() < deadline:
                    finished = [f for f in list(pending) if f.done()]
                    if not finished: time.sleep(0.25); continue
                    for fut in finished:
                        pending.remove(fut)
                        try:
                            url, vt_r, us_r, joe_r = fut.result(timeout=0)
                            url_results[url]["virustotal"]  = vt_r
                            url_results[url]["urlscan"]     = us_r
                            url_results[url]["joe_sandbox"] = joe_r
                        except Exception as e:
                            url_results[futs[fut]]["virustotal"] = {"error": str(e)[:60]}
                        done += 1
                        self._ph_upd(f"URLs: {done}/{len(urls)}…")
                for fut in pending: fut.cancel()
                ex.shutdown(wait=False)

            ips_to_check = set()
            if ed.get("sender_ip"):        ips_to_check.add(ed["sender_ip"])
            if ed.get("x_originating_ip"): ips_to_check.add(ed["x_originating_ip"])
            for d in url_results.values():
                ip = (d.get("urlscan") or {}).get("ip")
                if ip: ips_to_check.add(ip)

            ip_results = {}
            def _enrich_ip(ip):
                ab_res = vt_ip = geo = {}
                if cfg.get("abuseipdb_key"):
                    ab_res = ph_abuseipdb_check(ip, cfg["abuseipdb_key"])
                if cfg.get("vt_key"):
                    try:
                        r2 = requests.get(
                            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                            headers={"x-apikey": cfg["vt_key"]}, timeout=15)
                        if r2.status_code == 200:
                            a = r2.json().get("data",{}).get("attributes",{})
                            st = a.get("last_analysis_stats",{}); mal = st.get("malicious",0)
                            vt_ip = {"malicious":mal,"country":a.get("country"),
                                     "verdict":"MALICIOUS" if mal>=1 else "CLEAN"}
                    except: pass
                geo = ph_geolocate_ip(ip)
                return ip, ab_res, vt_ip, geo

            if ips_to_check:
                self._ph_upd(f"Checking {len(ips_to_check)} IP(s)…")
                ex2 = ThreadPoolExecutor(max_workers=5)
                futs2 = {ex2.submit(_enrich_ip, ip): ip for ip in list(ips_to_check)[:5]}
                deadline2 = time.time()+20; pending2 = set(futs2.keys())
                while pending2 and time.time() < deadline2:
                    fin = [f for f in list(pending2) if f.done()]
                    if not fin: time.sleep(0.25); continue
                    for fut in fin:
                        pending2.remove(fut)
                        try:
                            ip, ab_r, vt_r2, g = fut.result(timeout=0)
                            ip_results[ip] = {"abuseipdb":ab_r,"virustotal":vt_r2,"geo":g}
                        except: pass
                for fut in pending2: fut.cancel()
                ex2.shutdown(wait=False)

            hop_table = ph_parse_hop_table(ed.get("received_headers",[]))
            for hop in hop_table:
                hip = hop.get("ip")
                if hip and not _ph_private(hip):
                    hop["geo"] = ip_results.get(hip,{}).get("geo") or ph_geolocate_ip(hip)
            ed["hop_table"] = hop_table
            verdict = ph_compute_verdict(ed, url_results, ip_results)
            note    = ph_generate_worknote(ed, url_results, ip_results, verdict)
            self._ph_data = {"email":ed,"urls":url_results,"ips":ip_results,"verdict":verdict,"note":note}
            _sig.post(self._ph_render_all)
        except Exception:
            err = traceback.format_exc()
            _sig.post(lambda e=err: QMessageBox.critical(self,"Analysis Error",e[:600]))

    def _ph_render_all(self):
        r = self._ph_data; v = r["verdict"]; ed = r["email"]
        lv = v["level"]
        icon = "🚨" if lv=="MALICIOUS" else ("⚠️" if lv=="SUSPICIOUS" else "✅")
        col = "color:#FF453A" if lv=="MALICIOUS" else ("color:#FF9F0A" if lv=="SUSPICIOUS" else "color:#30D158")
        self._ph_verdict_lbl.setText(f"{icon} {lv}  Score: {v['score']}/200")
        self._ph_verdict_lbl.setStyleSheet(col)
        self._ph_render_summary(r)
        self._ph_render_headers(ed)
        self._ph_render_urls(r["urls"])
        self._ph_render_ips(r["ips"])
        self._ph_render_attachments(ed)
        self._ph_render_worknote(r["note"])
        self._status_lbl.setText(f"Phishing analysis complete — {lv}  Score: {v['score']}/200")

    def _ph_render_summary(self, r):
        t = self._ph_texts["📋 Summary"]; self._ph_clear(t)
        v = r["verdict"]; ed = r["email"]
        self._ph_write(t, "ANALYSIS SUMMARY\n", "head"); self._ph_sep(t)
        lv = v["level"]
        self._ph_write(t, "Verdict : ")
        self._ph_write(t, lv+"\n", "red" if lv=="MALICIOUS" else "orange" if lv=="SUSPICIOUS" else "green")
        self._ph_write(t, f"Score   : {v['score']}/200\n\n")
        self._ph_write(t, "THREAT FLAGS\n", "head"); self._ph_sep(t)
        for fl in v["flags"]:
            self._ph_write(t, fl+"\n",
                "red" if "🚨" in fl else "orange" if "⚠️" in fl else "url")
        if not v["flags"]: self._ph_write(t, "  No threat indicators\n", "green")
        self._ph_write(t, "\nEMAIL IDENTITY\n", "head"); self._ph_sep(t)
        for label, key in [("Subject","subject"),("From","from"),("To","to"),
                            ("Reply-To","reply_to"),("Return-Path","return_path"),
                            ("Sender IP","sender_ip"),("Date","date")]:
            val = ed.get(key) or "N/A"
            self._ph_write(t, f"  {label:<14}: ")
            self._ph_write(t, val+"\n", "dim" if val=="N/A" else None)
        self._ph_write(t, "\nAUTHENTICATION\n", "head"); self._ph_sep(t)
        for proto in ("spf","dkim","dmarc","arc"):
            val = ed.get(proto) or "N/A"
            c = "green" if val=="pass" else ("red" if val in ("fail","softfail") else "orange")
            self._ph_write(t, f"  {proto.upper():<8}: "); self._ph_write(t, val.upper()+"\n", c)
        self._ph_write(t, "\nSUMMARY STATS\n", "head"); self._ph_sep(t)
        self._ph_write(t, f"  URLs: {len(r['urls'])}  IPs: {len(r['ips'])}"
                          f"  Attachments: {len(ed.get('attachments',[]))}"
                          f"  Keywords: {len(ed.get('keywords',[]))}\n")

    def _ph_render_headers(self, ed):
        t = self._ph_texts["📨 Headers"]; self._ph_clear(t)
        self._ph_write(t,"EMAIL IDENTITY\n","head"); self._ph_sep(t)
        for label, key in [("Subject","subject"),("From","from"),("To","to"),("CC","cc"),
                            ("Reply-To","reply_to"),("Return-Path","return_path"),
                            ("Date","date"),("Message-ID","message_id")]:
            v2 = ed.get(key) or "N/A"
            self._ph_write(t, f"  {label:<14}: ")
            self._ph_write(t, v2+"\n", "dim" if v2=="N/A" else None)
        self._ph_write(t,"\nAUTHENTICATION\n","head"); self._ph_sep(t)
        for proto in ("spf","dkim","dmarc","arc"):
            val = ed.get(proto) or "N/A"
            c = "green" if val=="pass" else ("red" if val in ("fail","softfail") else "orange")
            self._ph_write(t, f"  {proto.upper():<8}: "); self._ph_write(t, val.upper()+"\n", c)
        if ed.get("domain_mismatches"):
            self._ph_write(t,"\nDOMAIN MISMATCHES\n","head"); self._ph_sep(t)
            for mm in ed["domain_mismatches"]:
                self._ph_write(t, f"  ⚠️ {mm['type']}: From [{mm['from']}] vs [{mm['other']}]\n","orange")
        if ed.get("keywords"):
            self._ph_write(t,"\nSUSPICIOUS KEYWORDS\n","head"); self._ph_sep(t)
            self._ph_write(t,"  "+", ".join(ed["keywords"])+"\n","orange")
        hops = ed.get("hop_table") or []
        if hops:
            self._ph_write(t,"\nMAIL HOP TRACE\n","head"); self._ph_sep(t)
            for i, hop in enumerate(hops,1):
                frm = (hop.get("from") or "—")[:28]; by=(hop.get("by") or "—")[:26]
                ip_c=(hop.get("ip") or "—")[:16]; geo=hop.get("geo") or {}
                delay=hop.get("delay_s")
                d_c=f"{delay:>+6}s" if delay is not None else "     —"
                country=(geo.get("country") or "—")[:14]
                isp=geo.get("isp") or geo.get("org") or "—"
                priv=_ph_private(hop.get("ip",""))
                c="purple" if priv else ("orange" if i==1 else None)
                self._ph_write(t,
                    f"  {i:<3}  {frm:<28}  {by:<26}  {ip_c:<16}  {d_c}  {country}  {isp[:35]}\n",c)

    def _ph_render_urls(self, url_results):
        t = self._ph_texts["🔗 URLs"]; self._ph_clear(t)
        self._ph_write(t, f"EXTRACTED URLS  ({len(url_results)} total)\n","head"); self._ph_sep(t)
        if not url_results: self._ph_write(t,"  No URLs found.\n","dim"); return
        for raw_url, data in url_results.items():
            deob = data.get("deobfuscation",{}) or {}
            vt = data.get("virustotal",{}) or {}
            us = data.get("urlscan",{}) or {}
            js = data.get("joe_sandbox",{}) or {}
            verd = vt.get("verdict","UNKNOWN")
            c = "red" if verd=="MALICIOUS" else "orange" if verd=="SUSPICIOUS" else "green"
            self._ph_write(t,"\n  📎 "); self._ph_write(t,raw_url[:90]+"\n","url")
            if deob.get("wrapper_type"): self._ph_write(t,f"      Wrapper : {deob['wrapper_type']}\n","purple")
            if deob.get("final_url") and deob["final_url"]!=raw_url:
                self._ph_write(t,"      Final   : "); self._ph_write(t,deob["final_url"][:90]+"\n","url")
            if vt.get("error"): self._ph_write(t,f"      VT Err  : {vt['error']}\n","dim")
            else:
                self._ph_write(t,"      VT      : "); self._ph_write(t,verd+"\n",c)
                self._ph_write(t,f"              Mal:{vt.get('malicious',0)} Sus:{vt.get('suspicious',0)} OK:{vt.get('harmless',0)}\n")
            if us.get("error"): self._ph_write(t,f"      URLScan : {us['error']}\n","dim")
            elif us.get("status")=="pending":
                self._ph_write(t,f"      URLScan : ⏳ Pending  UUID:{us.get('uuid','?')[:8]}…\n","dim")
            elif us.get("ip"):
                usv=us.get("verdict","?")
                uc="red" if usv=="MALICIOUS" else "orange" if usv=="SUSPICIOUS" else "green"
                self._ph_write(t,"      URLScan : "); self._ph_write(t,usv+"\n",uc)
                self._ph_write(t,f"              IP={us['ip']}  Score={us.get('score',0)}\n","dim")
            if js.get("status")=="pending": self._ph_write(t,"      Joe     : ⏳ Pending\n","dim")
            elif js.get("status")=="done":
                jv=js.get("verdict","?")
                jc="red" if jv=="MALICIOUS" else "orange" if jv=="SUSPICIOUS" else "green"
                self._ph_write(t,"      Joe     : "); self._ph_write(t,jv+"\n",jc)
            self._ph_sep(t)

    def _ph_render_ips(self, ip_results):
        t = self._ph_texts["🌐 IPs"]; self._ph_clear(t)
        self._ph_write(t,f"IP REPUTATION  ({len(ip_results)} IPs)\n","head"); self._ph_sep(t)
        if not ip_results: self._ph_write(t,"  No IPs.\n","dim"); return
        for ip, data in ip_results.items():
            ab=data.get("abuseipdb",{}) or {}; vt=data.get("virustotal",{}) or {}
            geo=data.get("geo",{}) or {}
            self._ph_write(t,f"\n  🌐 {ip}\n","orange")
            if geo: self._ph_write(t,f"      {geo.get('city','?')}, {geo.get('country','?')}  /  {geo.get('isp','?')}\n","dim")
            sc=ab.get("score",0)
            c="red" if sc>=75 else "orange" if sc>=25 else "green"
            self._ph_write(t,f"      AbuseIPDB: "); self._ph_write(t,f"Score={sc}%  Reports={ab.get('total_reports',0)}\n",c)
            if vt.get("malicious"): self._ph_write(t,f"      VT: 🔴 Mal={vt['malicious']}\n","red")
            self._ph_sep(t)

    def _ph_render_attachments(self, ed):
        t = self._ph_texts["📎 Attachments"]; self._ph_clear(t)
        atts = ed.get("attachments",[]); sus = {".exe",".js",".vbs",".ps1",".bat",".cmd",".hta",".scr",".docm",".xlsm",".jar"}
        self._ph_write(t,f"ATTACHMENTS  ({len(atts)} found)\n","head"); self._ph_sep(t)
        if not atts: self._ph_write(t,"  No attachments.\n","dim"); return
        for att in atts:
            ext=os.path.splitext(att.get("filename",""))[1].lower()
            c="red" if ext in sus else "green"
            self._ph_write(t,f"\n  📎 "); self._ph_write(t,att.get("filename","?")+"\n","url")
            self._ph_write(t,f"      Type: {att.get('content_type','?')}  Size: {att.get('size',0):,} bytes\n","dim")
            self._ph_write(t,"      "); self._ph_write(t,"⚠️ SUSPICIOUS EXT" if ext in sus else "✅ OK\n",c)
            self._ph_write(t,f"      MD5:    {att.get('md5','')}\n","dim")
            self._ph_write(t,f"      SHA256: {att.get('sha256','')}\n","dim")
            self._ph_sep(t)

    def _ph_render_worknote(self, note):
        t = self._ph_texts["📝 Work Note"]; self._ph_clear(t)
        for line in note.split("\n"):
            if line.startswith("="):              self._ph_write(t, line+"\n","sep")
            elif line.startswith("──"):           self._ph_write(t, line+"\n","head")
            elif "MALICIOUS" in line:             self._ph_write(t, line+"\n","red")
            elif "SUSPICIOUS" in line:            self._ph_write(t, line+"\n","orange")
            elif line.strip().startswith("🚨"):   self._ph_write(t, line+"\n","red")
            elif line.strip().startswith("⚠️"):   self._ph_write(t, line+"\n","orange")
            elif line.strip().startswith("✅"):   self._ph_write(t, line+"\n","green")
            else:                                 self._ph_write(t, line+"\n")

    def _ph_refresh_pending(self):
        if not self._ph_data: return
        def _poll():
            for url, data in self._ph_data["urls"].items():
                us = data.get("urlscan",{}); js = data.get("joe_sandbox",{})
                if us.get("status")=="pending" and us.get("uuid"):
                    data["urlscan"] = ph_urlscan_fetch(us["uuid"], self.osint.urlscan_api_key)
                if js.get("status")=="pending" and js.get("webid"):
                    data["joe_sandbox"] = ph_joe_fetch(js["webid"], self.osint.joe_api_key, self.osint.joe_server)
            v = ph_compute_verdict(self._ph_data["email"], self._ph_data["urls"], self._ph_data["ips"])
            n = ph_generate_worknote(self._ph_data["email"], self._ph_data["urls"], self._ph_data["ips"], v)
            self._ph_data["verdict"] = v; self._ph_data["note"] = n
            _sig.post(self._ph_render_all)
        threading.Thread(target=_poll, daemon=True).start()


# ════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    _splash_status("Building interface...", 20)
    window = OSINTApp()
    window.showMaximized()
    _splash_win.close()
    sys.exit(_app_qt.exec())

