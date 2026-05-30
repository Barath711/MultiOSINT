# -*- coding: utf-8 -*-
"""
OSINT MultiSearch v10
======================
Multi-mode security tool:
  • OSINT Lookup  — IPs, Domains, Hashes, Email addresses
  • Phishing Analyzer — .eml / .msg triage with full enrichment

APIs (configured in Settings → saved to config.json):
  VirusTotal, AbuseIPDB, URLScan.io, GreyNoise, OTX AlienVault,
  Shodan, abuse.ch (URLhaus/ThreatFox/MalwareBazaar),
  HaveIBeenPwned, Joe Sandbox,
  IPQualityScore, CriminalIP, Pulsedive

Free (no key): ip-api.com, DNS/rDNS, WHOIS, CIRCL.lu HashLookup, PhishTank
pip install customtkinter pillow requests urllib3 python-whois dnspython xposedornot
"""

import re, os, sys, json, csv, socket, threading, time, base64, hashlib
import quopri, traceback, webbrowser, email
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from io import BytesIO
from tkinter import filedialog, messagebox
from urllib.parse import urlparse, parse_qs, unquote
from email import policy as _epolicy
from email.parser import BytesParser
from email.header import decode_header, make_header

import tkinter as tk
import tkinter.scrolledtext as scrolledtext
import requests, urllib3
import customtkinter as ctk
from PIL import Image, ImageTk

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# ──────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────
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
                             model: str = "gemini-2.0-flash") -> str:
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
# GUI APPLICATION
# ══════════════════════════════════════════════════════════════════
class OSINTApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.config_data = load_config()
        self.osint       = OSINTModule(self.config_data)
        self.api_results: list  = []
        self.sandbox_images: dict = {}
        self._current_report_url: str | None = None
        self._mode = "osint"  # "osint" | "phishing"
        # Phishing state
        self._ph_filepath: str | None = None
        self._ph_results:  dict | None = None
        self._ph_keep_tab  = False
        self._ph_active_tab = "summary"
        # Shared thread pool for all network calls
        self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="osint")
        self.title("⚡ OSINT MultiSearch v10")
        try: self.iconbitmap(os.path.join(_SCRIPT_DIR, "myicon.ico"))
        except Exception: pass
        self.geometry("1380x860")
        self.minsize(1000, 660)
        self._build_ui()

    # ═══════════════════════════════ UI SKELETON ════════════════════
    def _build_ui(self):
        # ── Header ──────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, height=56, corner_radius=12)
        hdr.pack(fill="x", padx=14, pady=(14,6))
        ctk.CTkLabel(hdr, text="⚡ OSINT MultiSearch  v10",
                     font=("Segoe UI",22,"bold")).pack(side="left", padx=16)

        # Mode toggle (replaces dark/light toggle)
        mode_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        mode_frame.pack(side="right", padx=16)
        ctk.CTkLabel(mode_frame, text="Mode:", font=("Segoe UI",11)).pack(side="left", padx=(0,6))
        self._btn_osint_mode = ctk.CTkButton(
            mode_frame, text="🔍 OSINT", width=110, height=32,
            command=lambda: self._switch_mode("osint"),
            font=("Segoe UI",11,"bold"), corner_radius=8)
        self._btn_osint_mode.pack(side="left", padx=2)
        self._btn_phish_mode = ctk.CTkButton(
            mode_frame, text="🎣 Phishing", width=120, height=32,
            command=lambda: self._switch_mode("phishing"),
            font=("Segoe UI",11,"bold"), corner_radius=8,
            fg_color="transparent", border_width=1)
        self._btn_phish_mode.pack(side="left", padx=2)

        # ── Content container ────────────────────────────────────────
        self._content = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self._content.pack(fill="both", expand=True, padx=14, pady=(0,6))

        self._osint_pane   = ctk.CTkFrame(self._content, corner_radius=12)
        self._phishing_pane = ctk.CTkFrame(self._content, corner_radius=12)
        for p in (self._osint_pane, self._phishing_pane):
            p.place(relx=0, rely=0, relwidth=1, relheight=1)

        # ── Status bar ───────────────────────────────────────────────
        self.status_bar = ctk.CTkLabel(
            self, text="✅  Ready — configure API keys in ⚙️ Settings.",
            anchor="w", font=("Segoe UI",11))
        self.status_bar.pack(fill="x", padx=14, pady=(0,8))

        self._build_osint_pane()
        self._build_phishing_pane()
        self._switch_mode("osint")

    def _switch_mode(self, mode):
        self._mode = mode
        if mode == "osint":
            self._osint_pane.lift()
            self._btn_osint_mode.configure(fg_color=("gray75","#1f538d"), border_width=0)
            self._btn_phish_mode.configure(fg_color="transparent", border_width=1)
        else:
            self._phishing_pane.lift()
            self._btn_phish_mode.configure(fg_color=("gray75","#1f538d"), border_width=0)
            self._btn_osint_mode.configure(fg_color="transparent", border_width=1)

    # ═══════════════════════════════ OSINT PANE ═════════════════════
    def _build_osint_pane(self):
        p = self._osint_pane
        main = ctk.CTkFrame(p, corner_radius=0, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=6, pady=6)

        # Left sidebar
        left = ctk.CTkFrame(main, width=290, corner_radius=12)
        left.pack(side="left", fill="y", padx=(0,8), pady=0)
        left.pack_propagate(False)

        ctk.CTkLabel(left, text="Enter IOCs  (one per line)",
                     font=("Segoe UI",13,"bold"), anchor="w").pack(fill="x", padx=12, pady=(12,2))
        ctk.CTkLabel(left,
                     text="IP · Domain · Hash · Email · [dot] OK",
                     font=("Segoe UI",10), text_color="gray", anchor="w").pack(fill="x", padx=12)
        self.ioc_entry = ctk.CTkTextbox(left, height=200, font=("Consolas",12))
        self.ioc_entry.pack(fill="x", padx=12, pady=8)

        self.progress_bar = ctk.CTkProgressBar(left, mode="determinate")
        self.progress_bar.pack(fill="x", padx=12, pady=(2,4))
        self.progress_bar.set(0)

        self.lookup_btn = ctk.CTkButton(
            left, text="🔍  Run Lookup", command=self._lookup_threaded,
            height=38, font=("Segoe UI",13,"bold"))
        self.lookup_btn.pack(fill="x", padx=12, pady=(10,4))

        ctk.CTkButton(left, text="🌐  Open Browser Tabs",
                      command=self._open_tabs, height=32).pack(fill="x", padx=12, pady=4)
        ctk.CTkButton(left, text="💾  Export to CSV",
                      command=self._export_csv, height=32).pack(fill="x", padx=12, pady=4)
        ctk.CTkButton(left, text="📄  Export HTML Report",
                      command=self._export_html_report, height=32).pack(fill="x", padx=12, pady=4)
        ctk.CTkButton(left, text="🌐  OSINT Navigator",
                      command=lambda: self.tabs.set("🌐 OSINT Navigator"), height=32,
                      fg_color="#1a3a6a", hover_color="#1e5a9a").pack(fill="x", padx=12, pady=4)
        ctk.CTkButton(left, text="🗑️  Clear All",
                      command=self._clear_all, height=28,
                      fg_color="transparent", border_width=1).pack(fill="x", padx=12, pady=4)

        # Tabs
        self.tabs = ctk.CTkTabview(main, corner_radius=12)
        self.tabs.pack(side="left", fill="both", expand=True, pady=0)
        for tab in ["📊 Results","🤖 AI Summary","🔗 OSINT URLs","🏖️ Sandbox","🌐 OSINT Navigator","⚙️ Settings"]:
            self.tabs.add(tab)

        self._build_results_tab()
        self._build_ai_tab()
        self._build_urls_tab()
        self._build_sandbox_tab()
        self._build_navigator_tab()
        self._build_settings_tab()

    def _build_results_tab(self):
        t = self.tabs.tab("📊 Results")
        self.results_text = ctk.CTkTextbox(t, wrap="word", font=("Consolas",11))
        self.results_text.pack(fill="both", expand=True, padx=6, pady=6)

    def _build_ai_tab(self):
        t = self.tabs.tab("🤖 AI Summary")
        toolbar = ctk.CTkFrame(t, fg_color="transparent")
        toolbar.pack(fill="x", padx=6, pady=(6,2))
        self.ai_gen_btn = ctk.CTkButton(
            toolbar, text="🤖  Generate AI Summary", width=200, height=32,
            command=self._run_gemini_summary)
        self.ai_gen_btn.pack(side="left", padx=(0,8))
        # Model selector
        self.ai_model_var = ctk.StringVar(value="gemini-flash-latest")
        ctk.CTkOptionMenu(toolbar, variable=self.ai_model_var, width=200, height=32,
                          values=["gemini-flash-latest","gemini-2.0-flash","gemini-2.0-flash-lite","gemini-1.5-pro"]
                          ).pack(side="left", padx=(0,8))
        ctk.CTkButton(toolbar, text="📋  Copy", width=80, height=32,
                      command=self._copy_ai_summary,
                      fg_color="transparent", border_width=1).pack(side="left")
        ctk.CTkLabel(toolbar,
                     text="Auto-runs after lookup if Gemini key is configured",
                     font=("Segoe UI",10), text_color="gray").pack(side="right", padx=6)
        self.ai_text = ctk.CTkTextbox(t, wrap="word", font=("Consolas",11))
        self.ai_text.pack(fill="both", expand=True, padx=6, pady=(2,6))

    def _build_urls_tab(self):
        t = self.tabs.tab("🔗 OSINT URLs")
        top = ctk.CTkFrame(t, fg_color="transparent")
        top.pack(fill="x", padx=6, pady=(6,2))
        self.sources_label = ctk.CTkLabel(top, text="Sources shown for current IOC",
                                          font=("Segoe UI",11), text_color="gray")
        self.sources_label.pack(side="left")
        self.urls_text = ctk.CTkTextbox(t, wrap="word", font=("Consolas",11))
        self.urls_text.pack(fill="both", expand=True, padx=6, pady=(2,6))

    def _build_sandbox_tab(self):
        t = self.tabs.tab("🏖️ Sandbox")
        top = ctk.CTkFrame(t, fg_color="transparent")
        top.pack(fill="x", padx=6, pady=(6,2))
        ctk.CTkLabel(top, text="URLScan.io Screenshot",
                     font=("Segoe UI",12,"bold")).pack(side="left")
        self.sandbox_ioc_list = ctk.CTkComboBox(top, values=[], width=280)
        self.sandbox_ioc_list.pack(side="left", padx=10)
        self.sandbox_submit_btn = ctk.CTkButton(top, text="📸  Scan & Screenshot",
                      command=self._run_sandbox, height=30, width=160)
        self.sandbox_submit_btn.pack(side="left", padx=4)
        self.sandbox_open_btn = ctk.CTkButton(top, text="🌐  Open Report",
                      command=self._open_sandbox_report, height=30, width=120,
                      fg_color="transparent", border_width=1, state="disabled")
        self.sandbox_open_btn.pack(side="left", padx=4)
        self.sandbox_status_lbl = ctk.CTkLabel(top, text="", font=("Segoe UI",11), text_color="gray")
        self.sandbox_status_lbl.pack(side="left", padx=8)
        self.sandbox_img_label = ctk.CTkLabel(t, text="Select a domain and click 📸 Scan & Screenshot",
                                              text_color="gray", font=("Segoe UI",12))
        self.sandbox_img_label.pack(fill="both", expand=True, padx=6, pady=6)

    def _build_navigator_tab(self):
        t = self.tabs.tab("🌐 OSINT Navigator")
        _COLS = 5

        # ── Top control bar ──────────────────────────────────────────
        ctrl = ctk.CTkFrame(t, fg_color="transparent")
        ctrl.pack(fill="x", padx=8, pady=(6,2))

        ctk.CTkLabel(ctrl, text="IOC:", font=("Segoe UI",12,"bold")).pack(side="left", padx=(0,4))
        self.nav_ioc = ctk.CTkEntry(ctrl, width=240, placeholder_text="IP / Domain / Hash / URL…", height=30)
        self.nav_ioc.pack(side="left")
        ctk.CTkButton(ctrl, text="⬆ Sync from Lookup", width=130, height=30,
                      command=self._nav_sync_ioc, fg_color="#1a6a3a", hover_color="#1e8a4a").pack(side="left", padx=6)

        ctk.CTkButton(ctrl, text="⊟ Collapse All", width=100, height=28,
                      command=lambda: self._nav_set_all(False),
                      fg_color="transparent", border_width=1).pack(side="right", padx=2)
        ctk.CTkButton(ctrl, text="⊞ Expand All", width=100, height=28,
                      command=lambda: self._nav_set_all(True),
                      fg_color="transparent", border_width=1).pack(side="right", padx=2)
        self.nav_filter = ctk.CTkEntry(ctrl, width=190, placeholder_text="Filter tools…", height=28)
        self.nav_filter.pack(side="right", padx=(4,0))
        ctk.CTkLabel(ctrl, text="Filter:", font=("Segoe UI",11)).pack(side="right", padx=(12,2))
        self.nav_filter.bind("<KeyRelease>", lambda e: self._nav_filter())

        # ── Hint label ───────────────────────────────────────────────
        ctk.CTkLabel(t,
            text="🔶 = opens directly (no IOC)   ·   All other cards append your IOC to the URL and open in browser",
            font=("Segoe UI",10), text_color="gray").pack(anchor="w", padx=10, pady=(0,2))

        # ── Scrollable content ───────────────────────────────────────
        self.nav_scroll = ctk.CTkScrollableFrame(t, corner_radius=8)
        self.nav_scroll.pack(fill="both", expand=True, padx=8, pady=(0,6))

        self._nav_sections = {}  # cat_name → {wrapper, header, content, buttons[(btn,tool)], open}

        for cat_name, tools in NAV_TOOLS.items():
            total = len(tools)
            wrapper = ctk.CTkFrame(self.nav_scroll, fg_color="transparent")
            wrapper.pack(fill="x", pady=(4,0))

            # Header toggle button
            hdr = ctk.CTkButton(
                wrapper,
                text=f"▾  {cat_name}  ({total} tools)",
                fg_color="#1a2a3a", hover_color="#1e3a5a",
                text_color="#61afef", font=("Segoe UI",12,"bold"),
                anchor="w", corner_radius=6, height=30,
                command=lambda cn=cat_name: self._nav_toggle(cn))
            hdr.pack(fill="x")

            # Content frame (grid of tool buttons)
            cf = ctk.CTkFrame(wrapper, fg_color="#1e1e2e", corner_radius=6)
            cf.pack(fill="x", pady=(2,0))

            buttons = []
            for i, tool in enumerate(tools):
                skip = tool.get("skipSearch", False)
                label = ("🔶 " if skip else "") + tool["name"]
                def _click(t=tool):
                    ioc = self.nav_ioc.get().strip()
                    url = t.get("url","")
                    if t.get("skipSearch") or not ioc:
                        webbrowser.open_new_tab(url)
                    else:
                        webbrowser.open_new_tab(url + ioc)
                btn = ctk.CTkButton(
                    cf, text=label, height=28, corner_radius=5,
                    fg_color="#252535", hover_color="#2a3a5a",
                    font=("Segoe UI",10), anchor="w",
                    command=_click)
                row, col = divmod(i, _COLS)
                btn.grid(row=row, column=col, padx=3, pady=3, sticky="ew")
                buttons.append((btn, tool))

            for c in range(_COLS):
                cf.columnconfigure(c, weight=1)

            self._nav_sections[cat_name] = {
                "wrapper": wrapper, "header": hdr, "content": cf,
                "buttons": buttons, "open": True
            }

    def _nav_toggle(self, cat_name):
        sec = self._nav_sections[cat_name]
        sec["open"] = not sec["open"]
        n = len(sec["buttons"])
        if sec["open"]:
            sec["content"].pack(fill="x", pady=(2,0))
            sec["header"].configure(text=f"▾  {cat_name}  ({n} tools)")
        else:
            sec["content"].pack_forget()
            sec["header"].configure(text=f"▸  {cat_name}  ({n} tools)")

    def _nav_set_all(self, open_state):
        for cat_name, sec in self._nav_sections.items():
            n = len(sec["buttons"])
            sec["open"] = open_state
            if open_state:
                sec["content"].pack(fill="x", pady=(2,0))
                sec["header"].configure(text=f"▾  {cat_name}  ({n} tools)")
            else:
                sec["content"].pack_forget()
                sec["header"].configure(text=f"▸  {cat_name}  ({n} tools)")

    def _nav_filter(self):
        _COLS = 5
        query = self.nav_filter.get().strip().lower()
        for cat_name, sec in self._nav_sections.items():
            visible = 0
            for btn, tool in sec["buttons"]:
                match = (not query
                         or query in tool["name"].lower()
                         or query in tool.get("desc","").lower()
                         or any(query in tag.lower() for tag in tool.get("tags",[])))
                if match:
                    r, c = divmod(visible, _COLS)
                    btn.grid(row=r, column=c, padx=3, pady=3, sticky="ew")
                    visible += 1
                else:
                    btn.grid_remove()
            # Update header count
            label = f"{'▾' if sec['open'] else '▸'}  {cat_name}  ({visible} tools)"
            sec["header"].configure(text=label)

    def _nav_sync_ioc(self):
        raw = self.ioc_entry.get("1.0","end").strip().splitlines()
        ioc = self.osint.clean_ioc(raw[0].strip()) if raw else ""
        self.nav_ioc.delete(0,"end")
        if ioc: self.nav_ioc.insert(0, ioc)
        self.tabs.set("🌐 OSINT Navigator")

    def _build_settings_tab(self):
        t = self.tabs.tab("⚙️ Settings")
        scroll = ctk.CTkScrollableFrame(t, corner_radius=8)
        scroll.pack(fill="both", expand=True, padx=6, pady=6)
        ctk.CTkLabel(scroll, text="API Key Configuration",
                     font=("Segoe UI",16,"bold")).pack(anchor="w", padx=16, pady=(16,4))
        ctk.CTkLabel(scroll,
            text="Keys are saved to  config.json  in the tool's directory.\nAll free OSINT sources work without any API keys.",
            font=("Segoe UI",11), text_color="gray").pack(anchor="w", padx=16, pady=(0,10))
        self._api_key_fields: dict = {}
        services = [
            ("virustotal","VirusTotal",         "https://www.virustotal.com/gui/my-apikey",       "Free 4 req/min"),
            ("abuseipdb", "AbuseIPDB",           "https://www.abuseipdb.com/api",                  "Free 1000 req/day"),
            ("urlscan",   "URLScan.io",           "https://urlscan.io/user/signup",                 "Free 100 scans/day"),
            ("greynoise", "GreyNoise",            "https://viz.greynoise.io/account/signup",         "Free community tier"),
            ("otx",       "OTX AlienVault",       "https://otx.alienvault.com/",                    "Free with registration"),
            ("shodan",    "Shodan",               "https://account.shodan.io/register",              "Paid / limited free"),
            ("abusech",   "abuse.ch  (URLhaus · ThreatFox · MalwareBazaar)",
                          "https://auth.abuse.ch/",                                                   "Free — register at auth.abuse.ch"),
            ("joe_key",   "Joe Sandbox",          "https://www.joesecurity.org",                     "Paid / free trial"),
            ("gemini_key","Google Gemini AI",      "https://aistudio.google.com/app/apikey",           "Free tier available"),
            ("ipqs",      "IPQualityScore",        "https://www.ipqualityscore.com/create-account",    "Free 200 req/day — IPs, Emails, URLs, Domains"),
            ("criminalip","CriminalIP",            "https://www.criminalip.io/signup",                 "Free tier — IP reputation & attack surface"),
            ("pulsedive", "Pulsedive",             "https://pulsedive.com/register/",                  "Free tier — IPs, Domains, Hashes, URLs"),
        ]
        for key, label, url, note in services:
            frame = ctk.CTkFrame(scroll, corner_radius=8, border_width=1)
            frame.pack(fill="x", padx=8, pady=4)
            row = ctk.CTkFrame(frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=(8,2))
            ctk.CTkLabel(row, text=label, font=("Segoe UI",13,"bold")).pack(side="left")
            ctk.CTkLabel(row, text=f"  · {note}", font=("Segoe UI",10), text_color="gray").pack(side="left")
            ctk.CTkButton(row, text="Get Key ↗", width=90, height=24,
                          command=lambda u=url: webbrowser.open_new_tab(u),
                          fg_color="transparent", border_width=1).pack(side="right", padx=4)
            entry = ctk.CTkEntry(frame, placeholder_text=f"Paste {label} API key here…",
                                 show="•", font=("Consolas",12))
            entry.pack(fill="x", padx=12, pady=(2,10))
            if self.config_data.get(key):
                entry.insert(0, self.config_data[key])
            self._api_key_fields[key] = entry
        # Joe server URL (plain text)
        frame_js = ctk.CTkFrame(scroll, corner_radius=8, border_width=1)
        frame_js.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(frame_js, text="Joe Sandbox Server URL", font=("Segoe UI",13,"bold")).pack(
            anchor="w", padx=12, pady=(8,2))
        entry_js = ctk.CTkEntry(frame_js, placeholder_text="https://jbxcloud.joesecurity.org",
                                font=("Consolas",12))
        entry_js.pack(fill="x", padx=12, pady=(2,10))
        if self.config_data.get("joe_server"):
            entry_js.insert(0, self.config_data["joe_server"])
        self._api_key_fields["joe_server"] = entry_js
        self._show_keys = False
        btn_row = ctk.CTkFrame(scroll, fg_color="transparent")
        btn_row.pack(fill="x", padx=8, pady=(4,0))
        ctk.CTkButton(btn_row, text="👁  Show / Hide Keys", width=150, height=28,
                      command=self._toggle_key_visibility,
                      fg_color="transparent", border_width=1).pack(side="left", padx=8)
        save_row = ctk.CTkFrame(scroll, fg_color="transparent")
        save_row.pack(fill="x", padx=8, pady=12)
        ctk.CTkButton(save_row, text="💾  Save API Keys", command=self._save_settings,
                      height=38, font=("Segoe UI",13,"bold"), width=180).pack(side="left", padx=8)
        self.settings_status = ctk.CTkLabel(save_row, text="", font=("Segoe UI",11))
        self.settings_status.pack(side="left", padx=8)
        # Library status
        lib_frame = ctk.CTkFrame(scroll, corner_radius=8, border_width=1)
        lib_frame.pack(fill="x", padx=8, pady=(0,12))
        ctk.CTkLabel(lib_frame, text="Optional Library Status",
                     font=("Segoe UI",12,"bold")).pack(anchor="w", padx=12, pady=(8,2))
        whois_s = "✅ python-whois" if WHOIS_AVAILABLE else "❌ python-whois  (pip install python-whois)"
        dns_s   = "✅ dnspython"    if DNS_AVAILABLE   else "❌ dnspython     (pip install dnspython)"
        msg_s   = "✅ extract-msg"  if HAS_MSG         else "❌ extract-msg   (pip install extract-msg)"
        free_s  = "✅ Free sources  (no key): ip-api.com · CIRCL HashLookup · PhishTank · DNS · WHOIS"
        ctk.CTkLabel(lib_frame, text=f"  {whois_s}\n  {dns_s}\n  {msg_s}\n  {free_s}",
                     font=("Consolas",11), justify="left").pack(anchor="w", padx=12, pady=(0,10))

    def _toggle_key_visibility(self):
        self._show_keys = not self._show_keys
        ch = "" if self._show_keys else "•"
        for key, e in self._api_key_fields.items():
            if key != "joe_server": e.configure(show=ch)

    def _save_settings(self):
        for key, entry in self._api_key_fields.items():
            self.config_data[key] = entry.get().strip()
        result = save_config(self.config_data)
        self.osint = OSINTModule(self.config_data)
        if result is True:
            self.settings_status.configure(text="✅  Saved — keys reloaded.", text_color="green")
            self.after(3500, lambda: self.settings_status.configure(text=""))
        else:
            self.settings_status.configure(text=f"❌  Save failed: {result}", text_color="red")

    # ═══════════════════════════════ OSINT LOOKUP ═══════════════════
    def _lookup_threaded(self):
        raw_text = self.ioc_entry.get("1.0", "end").strip()
        if not raw_text:
            messagebox.showwarning("No IOCs", "Enter at least one IOC.")
            return
        self.lookup_btn.configure(state="disabled", text="⏳  Running…")
        self.api_results.clear()
        self.results_text.delete("1.0","end")
        self.urls_text.delete("1.0","end")
        self.ai_text.delete("1.0","end")
        self.progress_bar.set(0)
        self._executor.submit(self._lookup, raw_text)

    def _lookup(self, raw_text):
        iocs  = [l.strip() for l in raw_text.splitlines() if l.strip()]
        total = len(iocs); domain_iocs = []
        for idx, raw in enumerate(iocs):
            cleaned  = self.osint.clean_ioc(raw)
            ioc_type = self.osint.get_ioc_type(cleaned)
            # ── Parallel API checks ──────────────────────────────────
            futures = {}
            if ioc_type == "email":
                futures["xon"]  = self._executor.submit(self.osint.check_hibp, cleaned)
                futures["ipqs"] = self._executor.submit(self.osint.check_ipqs, cleaned, "email")
                futures["bvip"] = self._executor.submit(self.osint.check_breachvip, cleaned, "email")
            else:
                futures["vt"]   = self._executor.submit(self.osint.check_virustotal, cleaned, ioc_type)
                futures["otx"]  = self._executor.submit(self.osint.check_otx, cleaned, ioc_type)
                futures["pd"]   = self._executor.submit(self.osint.check_pulsedive, cleaned, ioc_type)
                if ioc_type == "ip":
                    futures["abip"] = self._executor.submit(self.osint.check_abuseipdb, cleaned)
                    futures["gn"]   = self._executor.submit(self.osint.check_greynoise, cleaned)
                    futures["shd"]  = self._executor.submit(self.osint.check_shodan, cleaned)
                    futures["cip"]  = self._executor.submit(self.osint.check_criminalip, cleaned)
                    futures["ipqs"] = self._executor.submit(self.osint.check_ipqs, cleaned, "ip")
            # ── Parallel free checks ─────────────────────────────────
            if ioc_type == "ip":
                futures["geo"]  = self._executor.submit(self.osint.check_ipapi, cleaned)
                futures["rdns"] = self._executor.submit(self.osint.check_reverse_dns, cleaned)
                futures["tf"]   = self._executor.submit(self.osint.check_threatfox, cleaned)
                futures["uh"]   = self._executor.submit(self.osint.check_urlhaus, cleaned, ioc_type)
            elif ioc_type == "domain":
                futures["dns"]  = self._executor.submit(self.osint.check_dns, cleaned)
                futures["wh"]   = self._executor.submit(self.osint.check_whois, cleaned)
                futures["tf"]   = self._executor.submit(self.osint.check_threatfox, cleaned)
                futures["uh"]   = self._executor.submit(self.osint.check_urlhaus, cleaned, ioc_type)
                futures["pt"]   = self._executor.submit(self.osint.check_phishtank, cleaned)
                futures["ipqs"] = self._executor.submit(self.osint.check_ipqs, cleaned, "domain")
            elif ioc_type == "hash":
                futures["mb"]   = self._executor.submit(self.osint.check_malwarebazaar, cleaned)
                futures["tf"]   = self._executor.submit(self.osint.check_threatfox, cleaned)
                futures["uh"]   = self._executor.submit(self.osint.check_urlhaus, cleaned, ioc_type)
                futures["hl"]   = self._executor.submit(self.osint.check_hashlookup, cleaned)
            # Gather results (with per-future timeout)
            results = {}
            for key, fut in futures.items():
                try:    results[key] = fut.result(timeout=45)
                except Exception as e: results[key] = None
            # Unpack
            vt   = results.get("vt")
            abip = results.get("abip")
            gn   = results.get("gn")
            otx  = results.get("otx")
            shd  = results.get("shd")
            hibp = results.get("xon")
            geo  = results.get("geo", {})
            rdns = results.get("rdns", "")
            dns_r = results.get("dns", {})
            wh   = results.get("wh", {})
            uh   = results.get("uh")
            mb   = results.get("mb")
            tf   = results.get("tf")
            pd   = results.get("pd")
            cip  = results.get("cip")
            ipqs = results.get("ipqs")
            hl   = results.get("hl")
            pt   = results.get("pt")
            bvip = results.get("bvip")
            # ── Render API results ───────────────────────────────────
            def _ins_api(ic=cleaned, it=ioc_type, v=vt, a=abip, g=gn, o=otx, s=shd, h=hibp,
                         p=pd, ci=cip, iq=ipqs, bv=bvip):
                W = "═"*62
                self.results_text.insert("end", f"\n{W}\n  IOC: {ic}  [{it.upper()}]\n{W}\n")
                # helper: only show a section when there's real data (no error, has content)
                def _has(d, *keys): return d and not any(d.get(k) for k in keys if "error" in k) and any(d.get(k) for k in keys if "error" not in k)

                if it == "email":
                    # XposedOrNot — always show (core breach source)
                    if h is not None and not h.get("xon_error"):
                        self.results_text.insert("end", "\n▸ Breach Check  (XposedOrNot — free)\n")
                        self.results_text.insert("end", f"  {h['xon_verdict']}\n")
                        for br in h.get("breaches",[])[:15]:
                            line = f"  🔴 {br['name']}"
                            if br.get("domain"):   line += f"  [{br['domain']}]"
                            if br.get("date"):     line += f"  ({br['date']})"
                            if br.get("records"):  line += f"  ~{br['records']:,} records"
                            self.results_text.insert("end", line + "\n")
                            if br.get("data_classes"):
                                self.results_text.insert("end", f"     Data: {br['data_classes']}\n")
                            if br.get("industry"):
                                self.results_text.insert("end", f"     Industry: {br['industry']}  ·  Password risk: {br.get('password_risk','?')}\n")
                    # IPQS email — only show if has a real verdict with content
                    if iq is not None and not iq.get("ipqs_error") and iq.get("ipqs_verdict"):
                        self.results_text.insert("end", "\n▸ IPQualityScore  (Email)\n")
                        self.results_text.insert("end",
                            f"  {iq.get('ipqs_verdict','')}  ·  Fraud Score: {iq.get('ipqs_fraud_score','')}\n"
                            f"  Disposable: {iq.get('ipqs_disposable','?')}\n")
                    # Breach.VIP — only show if found breaches
                    if bv is not None and not bv.get("bvip_error") and bv.get("bvip_count",0) > 0:
                        self.results_text.insert("end", "\n▸ Breach.VIP  (free)\n")
                        self.results_text.insert("end", f"  {bv['bvip_verdict']}\n")
                        for item in bv.get("bvip_results", [])[:20]:
                            cats = item.get("categories","")
                            if isinstance(cats, list): cats = ", ".join(cats)
                            line = f"  🔴 {item['source']}"
                            if cats: line += f"  [{cats}]"
                            extra = item.get("extra", {})
                            for k in ("email","username","password","ip","phone"):
                                if extra.get(k): line += f"  {k}: {extra[k]}"
                            self.results_text.insert("end", line + "\n")
                    return
                # ── VirusTotal — always show (primary signal) ──
                if v is not None and not v.get("vt_error"):
                    self.results_text.insert("end", "\n▸ VirusTotal\n")
                    self.results_text.insert("end",
                        f"  {v['vt_verdict']}  ·  🔴 Mal: {v['malicious']}  "
                        f"🟡 Sus: {v['suspicious']}  🟢 OK: {v['harmless']}\n"
                        f"  VT Score: {v['vt_score']}  ·  Last checked: {v.get('last_analysis_date') or 'n/a'}\n")
                    if v.get("creation_date"): self.results_text.insert("end", f"  Created: {v['creation_date']}\n")
                    if v.get("registrar"):     self.results_text.insert("end", f"  Registrar: {v['registrar']}\n")
                    if v.get("categories"):    self.results_text.insert("end", f"  Categories: {v['categories']}\n")
                    if v.get("last_http_code"):self.results_text.insert("end", f"  Last HTTP: {v['last_http_code']}\n")
                    if v.get("as_owner"):      self.results_text.insert("end", f"  AS Owner: {v['as_owner']}  ASN: {v.get('asn','')}\n")
                    if v.get("network"):       self.results_text.insert("end", f"  Network: {v['network']}\n")
                    if v.get("threat_label"):  self.results_text.insert("end", f"  Threat: {v['threat_label']}\n")
                    if v.get("file_type"):
                        self.results_text.insert("end",
                            f"  File: {v.get('file_names') or 'n/a'}  [{v['file_type']}]  {v.get('file_size','')}\n")
                    if v.get("total_votes_mal") or v.get("total_votes_ok"):
                        self.results_text.insert("end",
                            f"  Community: 👍 {v.get('total_votes_ok',0)}  👎 {v.get('total_votes_mal',0)}"
                            + (f"  Reputation: {v['reputation']}" if v.get("reputation") else "") + "\n")
                # ── AbuseIPDB — always show for IPs ──
                if it == "ip" and a is not None and not a.get("abuse_error"):
                    self.results_text.insert("end", "\n▸ AbuseIPDB\n")
                    self.results_text.insert("end",
                        f"  {a['abuse_verdict']}  ·  Score: {a['abuse_score']}%  "
                        f"·  Reports: {a['total_reports']}  ·  Country: {a['country']}\n"
                        f"  ISP: {a['isp']}  ·  Usage: {a['usage_type']}\n")
                # ── GreyNoise — always show for IPs ──
                if it == "ip" and g is not None and not g.get("gn_error"):
                    self.results_text.insert("end", "\n▸ GreyNoise\n")
                    self.results_text.insert("end",
                        f"  {g['gn_verdict']}  ·  Class: {g['classification']}  "
                        f"·  Noise: {g['noise']}  ·  RIOT: {g['riot']}\n")
                    if g.get("name"): self.results_text.insert("end", f"  Name: {g['name']}\n")
                # ── Shodan — only show if data returned without error ──
                if it == "ip" and s is not None and not s.get("shodan_error") and s.get("org"):
                    self.results_text.insert("end", "\n▸ Shodan\n")
                    self.results_text.insert("end",
                        f"  Org: {s['org']}  ·  Country: {s['country']}  ·  OS: {s['os']}\n"
                        f"  Ports: {s['ports'] or 'n/a'}\n")
                    if s.get("vulns") and s["vulns"] != "None": self.results_text.insert("end", f"  ⚠️  CVEs: {s['vulns']}\n")
                    if s.get("hostnames"): self.results_text.insert("end", f"  Hostnames: {s['hostnames']}\n")
                    if s.get("tags"):      self.results_text.insert("end", f"  Tags: {s['tags']}\n")
                # ── CriminalIP — only show if real score returned ──
                if it == "ip" and ci is not None and not ci.get("cip_error") and ci.get("cip_score") not in (None,"","0",0):
                    self.results_text.insert("end", "\n▸ CriminalIP\n")
                    self.results_text.insert("end",
                        f"  {ci.get('cip_verdict','')}  ·  Score: {ci.get('cip_score','')}\n"
                        f"  Type: {ci.get('cip_type','')}  ·  Country: {ci.get('cip_country','')}  "
                        f"·  Org: {ci.get('cip_org','')}\n")
                    if ci.get("cip_open_ports"): self.results_text.insert("end", f"  Ports: {ci['cip_open_ports']}\n")
                    if ci.get("cip_cves") and ci["cip_cves"] != "None":
                        self.results_text.insert("end", f"  ⚠️  CVEs: {ci['cip_cves']}\n")
                    if ci.get("cip_tags"): self.results_text.insert("end", f"  Flags: {ci['cip_tags']}\n")
                # ── IPQS — only show if fraud score > 0 ──
                if it == "ip" and iq is not None and not iq.get("ipqs_error") and iq.get("ipqs_fraud_score") not in (None,"","0",0):
                    self.results_text.insert("end", "\n▸ IPQualityScore\n")
                    self.results_text.insert("end",
                        f"  {iq.get('ipqs_verdict','')}  ·  Fraud Score: {iq.get('ipqs_fraud_score','')}\n"
                        f"  VPN: {iq.get('ipqs_vpn','?')}  ·  Proxy: {iq.get('ipqs_proxy','?')}  "
                        f"·  Tor: {iq.get('ipqs_tor','?')}  ·  Bot: {iq.get('ipqs_bot','?')}\n")
                # ── OTX — only show if has pulses > 0 ──
                if o is not None and not o.get("otx_error") and o.get("pulse_count",0) > 0:
                    self.results_text.insert("end", "\n▸ OTX AlienVault\n")
                    self.results_text.insert("end", f"  {o['otx_verdict']}  ·  Pulses: {o['pulse_count']}\n")
                    if o.get("malware_families") and o["malware_families"] != "None":
                        self.results_text.insert("end", f"  Malware: {o['malware_families']}\n")
                    if o.get("tags") and o["tags"] != "None":
                        self.results_text.insert("end", f"  Tags: {o['tags']}\n")
                # ── Pulsedive — only show if risk is not unknown/none/empty ──
                if p is not None and not p.get("pd_error"):
                    _pd_risk = str(p.get("pd_risk","")).lower().strip()
                    if _pd_risk and _pd_risk not in ("unknown","none","low",""):
                        self.results_text.insert("end", "\n▸ Pulsedive\n")
                        self.results_text.insert("end",
                            f"  {p.get('pd_verdict','')}  ·  Risk: {p.get('pd_risk','')}  "
                            f"·  Type: {p.get('pd_type','')}\n")
                        if p.get("pd_threats") and p["pd_threats"] != "None":
                            self.results_text.insert("end", f"  Threats: {p['pd_threats']}\n")
                        if p.get("pd_feeds") and p["pd_feeds"] != "None":
                            self.results_text.insert("end", f"  Feeds: {p['pd_feeds']}\n")
                        if p.get("pd_tags") and p["pd_tags"] != "None":
                            self.results_text.insert("end", f"  Tags: {p['pd_tags']}\n")
            self.after(0, _ins_api)

            # ── Render free OSINT results ────────────────────────────
            def _ins_free(ic=cleaned, it=ioc_type,
                          g=geo, d=dns_r, rv=rdns, whi=wh, u=uh, m=mb, t=tf,
                          h_=hl, p_=pt, iq_=ipqs):
                if it == "ip":
                    # Geolocation — always show for IPs (no error = useful context)
                    if not g.get("ipapi_error") and g.get("country"):
                        self.results_text.insert("end", "\n▸ Geolocation  (ip-api.com)\n")
                        self.results_text.insert("end",
                            f"  {g['city']}, {g['region']}, {g['country']}\n"
                            f"  ISP: {g['isp']}  ·  Org: {g['org']}\n"
                            f"  ASN: {g['asn']}  ·  TZ: {g['timezone']}\n"
                            f"  Proxy: {g['proxy']}  ·  Hosting/DC: {g['hosting']}\n")
                    if rv: self.results_text.insert("end", f"\n▸ Reverse DNS\n  {rv}\n")
                elif it == "domain":
                    # DNS — always show for domains
                    if not d.get("dns_error") and any(d.get(k) for k in ("a_records","mx","ns","aaaa_records","cname","txt")):
                        self.results_text.insert("end", "\n▸ DNS Records\n")
                        if d.get("a_records"):    self.results_text.insert("end", f"  A:     {', '.join(d['a_records'])}\n")
                        if d.get("aaaa_records"): self.results_text.insert("end", f"  AAAA:  {', '.join(d['aaaa_records'][:3])}\n")
                        if d.get("mx"):           self.results_text.insert("end", f"  MX:    {', '.join(d['mx'][:3])}\n")
                        if d.get("ns"):           self.results_text.insert("end", f"  NS:    {', '.join(d['ns'][:4])}\n")
                        if d.get("cname"):        self.results_text.insert("end", f"  CNAME: {', '.join(d['cname'][:2])}\n")
                        for txt in (d.get("txt") or [])[:3]:
                            self.results_text.insert("end", f"  TXT:   {txt[:100]}\n")
                    # WHOIS — always show for domains
                    if not whi.get("whois_error") and whi.get("whois_data"):
                        self.results_text.insert("end", "\n▸ WHOIS\n")
                        self.results_text.insert("end", whi["whois_data"]+"\n")
                    # PhishTank — only show if marked phishing
                    if p_ is not None and not p_.get("pt_error") and p_.get("pt_verdict") and "not" not in str(p_.get("pt_verdict","")).lower():
                        self.results_text.insert("end", "\n▸ PhishTank  (free)\n")
                        self.results_text.insert("end", f"  {p_.get('pt_verdict','')}\n")
                    # IPQS domain — only show if fraud score > 0
                    if iq_ is not None and not iq_.get("ipqs_error") and iq_.get("ipqs_fraud_score") not in (None,"","0",0):
                        self.results_text.insert("end", "\n▸ IPQualityScore  (Domain)\n")
                        self.results_text.insert("end",
                            f"  {iq_.get('ipqs_verdict','')}  ·  Fraud Score: {iq_.get('ipqs_fraud_score','')}\n")
                # URLhaus — only show if there's an actual threat/match
                if u is not None and not u.get("uh_error") and u.get("uh_threat"):
                    self.results_text.insert("end", "\n▸ URLhaus  (abuse.ch)\n")
                    line = f"  {u['uh_threat']}"
                    if u.get("uh_urls"): line += f"  ({u['uh_urls']} entries)"
                    self.results_text.insert("end", line+"\n")
                    if u.get("uh_tags"): self.results_text.insert("end", f"  Tags: {u['uh_tags']}\n")
                # MalwareBazaar — only show if verdict returned
                if it == "hash" and m is not None and not m.get("mb_error") and m.get("mb_verdict"):
                    self.results_text.insert("end", "\n▸ MalwareBazaar  (abuse.ch)\n")
                    self.results_text.insert("end", f"  {m['mb_verdict']}\n")
                    if m.get("mb_file_name"):
                        self.results_text.insert("end", f"  File: {m['mb_file_name']}  [{m['mb_file_type']}]\n")
                    if m.get("mb_signature"):  self.results_text.insert("end", f"  Sig: {m['mb_signature']}\n")
                    if m.get("mb_tags"):       self.results_text.insert("end", f"  Tags: {m['mb_tags']}\n")
                    if m.get("mb_first_seen"): self.results_text.insert("end", f"  First seen: {m['mb_first_seen']}\n")
                # HashLookup — only show if verdict has content
                if it == "hash" and h_ is not None and not h_.get("hl_error") and h_.get("hl_verdict"):
                    self.results_text.insert("end", "\n▸ CIRCL HashLookup  (free)\n")
                    self.results_text.insert("end", f"  {h_.get('hl_verdict','')}\n")
                    if h_.get("hl_filename"):  self.results_text.insert("end", f"  File: {h_['hl_filename']}\n")
                    if h_.get("hl_filetype"):  self.results_text.insert("end", f"  Type: {h_['hl_filetype']}\n")
                    if h_.get("hl_parents"):   self.results_text.insert("end", f"  Parent packages: {h_['hl_parents']}\n")
                # ThreatFox — only show if IOC actually found
                if t is not None and not t.get("tf_error") and t.get("tf_verdict") and "not found" not in str(t.get("tf_verdict","")).lower():
                    self.results_text.insert("end", "\n▸ ThreatFox  (abuse.ch)\n")
                    self.results_text.insert("end", f"  {t['tf_verdict']}\n")
                    if t.get("tf_threat_type"):
                        self.results_text.insert("end", f"  Threat: {t['tf_threat_type']}  ·  Malware: {t['tf_malware']}\n")
                    if t.get("tf_tags"):
                        self.results_text.insert("end", f"  Tags: {t['tf_tags']}\n")
            self.after(0, _ins_free)
            # ── OSINT URL list ───────────────────────────────────────
            src_list = self.osint.get_sources(ioc_type)
            url_pairs = self.osint.build_url_pairs(cleaned, src_list)
            def _ins_urls(ic=cleaned, pairs=url_pairs):
                self.urls_text.insert("end", f"\n{'═'*62}\n  {ic}\n{'═'*62}\n")
                for src, url in pairs:
                    self.urls_text.insert("end", f"  {src:<20}  {url}\n")
            self.after(0, _ins_urls)
            if ioc_type == "domain": domain_iocs.append(cleaned)

            # ── CSV / HTML row ───────────────────────────────────────
            self.api_results.append({
                "IOC": cleaned, "Type": ioc_type,
                "VT_Verdict":    (vt   or {}).get("vt_verdict",""),
                "VT_Score":      (vt   or {}).get("vt_score",""),
                "Abuse_Score":   (abip or {}).get("abuse_score",""),
                "GN_Verdict":    (gn   or {}).get("gn_verdict",""),
                "OTX_Verdict":   (otx  or {}).get("otx_verdict",""),
                "Shodan_Ports":  (shd  or {}).get("ports",""),
                "Shodan_Vulns":  (shd  or {}).get("vulns",""),
                "CriminalIP":    (cip  or {}).get("cip_verdict",""),
                "CriminalIP_Score": (cip or {}).get("cip_score",""),
                "IPQS_Verdict":  (ipqs or {}).get("ipqs_verdict",""),
                "IPQS_FraudScore": (ipqs or {}).get("ipqs_fraud_score",""),
                "Pulsedive":     (pd   or {}).get("pd_verdict",""),
                "ThreatFox":     (tf   or {}).get("tf_verdict",""),
                "URLhaus":       (uh   or {}).get("uh_threat",""),
                "MalwareBazaar": (mb   or {}).get("mb_verdict",""),
                "HashLookup":    (hl   or {}).get("hl_verdict",""),
                "PhishTank":     (pt   or {}).get("pt_verdict",""),
                "HIBP_Verdict":  (hibp or {}).get("xon_verdict",""),
                "HIBP_Breaches": (hibp or {}).get("breach_count",""),
                "BreachVIP":     (bvip or {}).get("bvip_verdict",""),
                "BreachVIP_Count": (bvip or {}).get("bvip_count",""),
            })
            pct = (idx+1)/total
            stat_txt = f"⏳  Processing {idx+1}/{total}:  {cleaned}"
            self.after(0, lambda p=pct, s=stat_txt: (
                self.progress_bar.set(p), self.status_bar.configure(text=s)))

        def _finish(dl=domain_iocs, tot=total):
            self.sandbox_ioc_list.configure(values=dl)
            self.sandbox_ioc_list.set(dl[0] if dl else "")
            self.progress_bar.set(1.0)
            self.status_bar.configure(text=f"✅  Done — {tot} IOC(s) processed.")
            self.lookup_btn.configure(state="normal", text="🔍  Run Lookup")
            self.tabs.set("📊 Results")
            # Auto comprehensive AI summary when all IOCs are done
            if self.osint.gemini_key:
                model_name = getattr(self, "ai_model_var", None)
                model_name = model_name.get() if model_name else "gemini-flash-latest"
                self.ai_text.delete("1.0", "end")
                self.ai_text.insert("end", f"⏳  Generating comprehensive analysis with {model_name}…\n")
                def _auto_ai(mn=model_name):
                    import time as _t; _t.sleep(0.5)   # let results render first
                    snap = self.results_text.get("1.0", "end")
                    summary = self.osint.check_gemini_summary(snap, model=mn)
                    self.after(0, lambda s=summary: (
                        self.ai_text.delete("1.0", "end"),
                        self.ai_text.insert("end", s + "\n"),
                    ))
                self._executor.submit(_auto_ai)
        self.after(0, _finish)

    # ═══════════════════════════════ SANDBOX ════════════════════════
    def _run_sandbox(self):
        domain = self.sandbox_ioc_list.get().strip()
        if not domain: messagebox.showwarning("No domain","Select a domain first."); return
        if not self.osint.urlscan_api_key:
            messagebox.showwarning("No API Key","Add URLScan.io API key in Settings."); return
        self.sandbox_status_lbl.configure(text=f"⏳  Submitting {domain}…  (up to ~60s)")
        self.sandbox_submit_btn.configure(state="disabled")
        self.sandbox_open_btn.configure(state="disabled")
        self.sandbox_img_label.configure(image=None, text="⏳  Scanning with URLScan.io…")
        self._current_report_url = None

        def _callback(image_data, error_msg, doc_url, rep_url):
            if image_data:
                try:
                    img = Image.open(BytesIO(image_data))
                    img.thumbnail((920, 580))
                    tk_img = ImageTk.PhotoImage(img)
                    self.after(0, lambda: (
                        self.sandbox_img_label.configure(image=tk_img, text=""),
                        setattr(self.sandbox_img_label, "_image", tk_img),
                        self.sandbox_status_lbl.configure(text=f"✅  Done  ·  {doc_url or domain}"),
                        self.sandbox_submit_btn.configure(state="normal"),
                        setattr(self, "_current_report_url", rep_url),
                        self.sandbox_open_btn.configure(state="normal" if rep_url else "disabled")))
                except Exception as exc:
                    self.after(0, lambda e=str(exc): (
                        self.sandbox_img_label.configure(text=f"Image decode error: {e}"),
                        self.sandbox_submit_btn.configure(state="normal")))
            else:
                self.after(0, lambda msg=error_msg: (
                    self.sandbox_img_label.configure(text=msg or "No screenshot.", image=None),
                    self.sandbox_status_lbl.configure(text=f"❌  {msg or 'Failed'}"),
                    self.sandbox_submit_btn.configure(state="normal"),
                    self.sandbox_open_btn.configure(state="normal" if rep_url else "disabled"),
                    setattr(self, "_current_report_url", rep_url)))

        import threading as _threading
        _threading.Thread(
            target=self.osint.urlscan_screenshot,
            args=(domain, _callback), daemon=True).start()

    def _open_sandbox_report(self):
        url = getattr(self, "_current_report_url", None)
        if url: webbrowser.open_new_tab(url)

    # ═══════════════════════════════ UTILITIES ═══════════════════════
    def _open_tabs(self):
        raw_text = self.ioc_entry.get("1.0","end").strip()
        if not raw_text: messagebox.showwarning("No IOCs","Enter IOCs first."); return
        count = 0
        for line in raw_text.splitlines():
            cleaned = self.osint.clean_ioc(line.strip())
            if not cleaned: continue
            ioc_type = self.osint.get_ioc_type(cleaned)
            for _, url in self.osint.build_url_pairs(cleaned, self.osint.get_sources(ioc_type)):
                webbrowser.open_new_tab(url); count += 1
        if count: self.status_bar.configure(text=f"🌐  Opened {count} browser tab(s).")

    def _export_html_report(self):
        if not self.api_results:
            messagebox.showinfo("Nothing to export","Run a lookup first."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML","*.html"),("All","*.*")],
            initialfile="osint_report.html")
        if not path: return
        try:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rows_html = ""
            verdict_colors = {"MALICIOUS": "#e06c75", "HIGH": "#e06c75", "CRITICAL": "#e06c75",
                              "SUSPICIOUS": "#e5c07b", "MEDIUM": "#e5c07b",
                              "Clean": "#98c379", "Low": "#98c379"}
            def _vcolor(v):
                v = str(v)
                for k, c in verdict_colors.items():
                    if k.upper() in v.upper(): return c
                return "#abb2bf"
            for row in self.api_results:
                ioc = row.get("IOC",""); ioc_type = row.get("Type","")
                vt_v = row.get("VT_Verdict",""); vt_s = row.get("VT_Score","")
                rows_html += f"""
  <tr>
    <td><b style="color:#61afef">{ioc}</b></td>
    <td><span style="background:#252535;padding:2px 6px;border-radius:4px">{ioc_type.upper()}</span></td>
    <td style="color:{_vcolor(vt_v)}">{vt_v} {('('+str(vt_s)+')') if vt_s else ''}</td>
    <td style="color:{_vcolor(row.get('Abuse_Score',''))}">Score: {row.get('Abuse_Score','')}</td>
    <td style="color:{_vcolor(row.get('GN_Verdict',''))}">{row.get('GN_Verdict','')}</td>
    <td style="color:{_vcolor(row.get('CriminalIP',''))}">{row.get('CriminalIP','')} {('('+str(row.get('CriminalIP_Score',''))) + ')' if row.get('CriminalIP_Score') else ''}</td>
    <td style="color:{_vcolor(row.get('IPQS_Verdict',''))}">{row.get('IPQS_Verdict','')} {('('+str(row.get('IPQS_FraudScore',''))) + ')' if row.get('IPQS_FraudScore') else ''}</td>
    <td style="color:{_vcolor(row.get('Pulsedive',''))}">{row.get('Pulsedive','')}</td>
    <td style="color:{_vcolor(row.get('OTX_Verdict',''))}">{row.get('OTX_Verdict','')}</td>
    <td style="color:{_vcolor(row.get('ThreatFox',''))}">{row.get('ThreatFox','')}</td>
    <td style="color:{_vcolor(row.get('URLhaus',''))}">{row.get('URLhaus','')}</td>
    <td style="color:{_vcolor(row.get('MalwareBazaar',''))}">{row.get('MalwareBazaar','')}</td>
    <td style="color:{_vcolor(row.get('HashLookup',''))}">{row.get('HashLookup','')}</td>
    <td style="color:{_vcolor(row.get('PhishTank',''))}">{row.get('PhishTank','')}</td>
    <td style="color:{_vcolor(row.get('HIBP_Verdict',''))}">{row.get('HIBP_Verdict','')} {('('+str(row.get('HIBP_Breaches',''))) + ' breaches)' if row.get('HIBP_Breaches') else ''}</td>
    <td style="color:{_vcolor(row.get('BreachVIP',''))}">{row.get('BreachVIP','')} {('('+str(row.get('BreachVIP_Count',''))) + ' sources)' if row.get('BreachVIP_Count') else ''}</td>
  </tr>"""
            html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>OSINT MultiSearch v10 Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#1a1a2e;color:#abb2bf;font-family:'Segoe UI',Arial,sans-serif;padding:24px}}
h1{{color:#61afef;font-size:1.8em;margin-bottom:4px}}
.meta{{color:#5c6370;font-size:.9em;margin-bottom:20px}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}}
th{{background:#252535;color:#61afef;padding:10px 12px;text-align:left;border-bottom:2px solid #3a3a6a;white-space:nowrap}}
td{{padding:9px 12px;border-bottom:1px solid #252535;vertical-align:top}}
tr:hover td{{background:#1f1f35}}
.badge{{display:inline-block;padding:1px 8px;border-radius:4px;font-size:.8em;font-weight:bold}}
</style></head>
<body>
<h1>⚡ OSINT MultiSearch v10 — Report</h1>
<p class="meta">Generated: {ts} &nbsp;|&nbsp; {len(self.api_results)} IOC(s)</p>
<table>
<tr>
  <th>IOC</th><th>Type</th><th>VirusTotal</th><th>AbuseIPDB</th>
  <th>GreyNoise</th><th>CriminalIP</th><th>IPQS</th><th>Pulsedive</th>
  <th>OTX</th><th>ThreatFox</th><th>URLhaus</th><th>MalwareBazaar</th>
  <th>HashLookup</th><th>PhishTank</th><th>HIBP/XposedOrNot</th><th>Breach.VIP</th>
</tr>
{rows_html}
</table>
</body></html>"""
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            self.status_bar.configure(text=f"✅  HTML report saved → {path}")
            webbrowser.open_new_tab(f"file:///{path.replace(os.sep, '/')}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _export_csv(self):
        if not self.api_results:
            messagebox.showinfo("Nothing to export","Run a lookup first."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV","*.csv"),("All","*.*")],
            initialfile="osint_results.csv")
        if not path: return
        try:
            import csv, unicodedata
            def _strip_emoji(s):
                """Remove emoji/non-ASCII symbols, keep plain text."""
                if not isinstance(s, str): return s
                cleaned = []
                for ch in s:
                    cat = unicodedata.category(ch)
                    # Keep standard printable + common punctuation; drop So (symbols/emoji)
                    if cat.startswith("C") or cat == "So":
                        continue
                    cleaned.append(ch)
                return "".join(cleaned).strip()
            keys = list(self.api_results[0].keys())
            clean_rows = [{k: _strip_emoji(str(v)) for k, v in row.items()} for row in self.api_results]
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader(); w.writerows(clean_rows)
            self.status_bar.configure(text=f"✅  Exported {len(self.api_results)} row(s) → {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _copy_ai_summary(self):
        txt = self.ai_text.get("1.0","end-1c")
        if txt.strip():
            self.clipboard_clear(); self.clipboard_append(txt)
            self.status_bar.configure(text="📋  AI summary copied to clipboard ✓")

    def _run_gemini_summary(self):
        """Re-run comprehensive Gemini summary on all current results."""
        if not self.osint.gemini_key:
            self.ai_text.delete("1.0","end")
            self.ai_text.insert("end", "No Gemini API key configured. Add it in Settings.\n")
            self.tabs.set("🤖 AI Summary")
            return
        model_name = getattr(self, "ai_model_var", None)
        model_name = model_name.get() if model_name else "gemini-flash-latest"
        self.ai_text.delete("1.0","end")
        self.ai_text.insert("end", f"⏳  Asking {model_name}…  (comprehensive analysis)\n")
        self.tabs.set("🤖 AI Summary")
        self.ai_gen_btn.configure(state="disabled")
        def _work():
            res = self.results_text.get("1.0","end")
            summary = self.osint.check_gemini_summary(res, model=model_name)
            self.after(0, lambda s=summary: (
                self.ai_text.delete("1.0","end"),
                self.ai_text.insert("end", s + "\n"),
                self.ai_gen_btn.configure(state="normal"),
            ))
        self._executor.submit(_work)

    def _clear_all(self):
        self.ioc_entry.delete("1.0","end")
        for w in (self.results_text, self.ai_text, self.urls_text):
            w.delete("1.0","end")
        self.api_results.clear()
        self.progress_bar.set(0)
        self.status_bar.configure(text="Cleared.")

    # ═══════════════════════════════ PHISHING PANE ══════════════════
    def _build_phishing_pane(self):
        self._phishing_pane = ctk.CTkFrame(self._content, fg_color="transparent")
        self._phishing_pane.place(relx=0,rely=0,relwidth=1,relheight=1)
        # ── File picker row ─────────────────────────────────────────
        file_row = ctk.CTkFrame(self._phishing_pane, corner_radius=0, height=52,
                                fg_color=("#1e1e2e","#1e1e2e"))
        file_row.pack(fill="x", side="top"); file_row.pack_propagate(False)
        ctk.CTkButton(file_row, text="📂  Browse EML / MSG",
                      command=self._ph_browse, height=34, width=180).pack(
            side="left", padx=14, pady=8)
        self._ph_file_label = ctk.CTkLabel(file_row, text="No file selected",
                                           text_color="gray", font=("Segoe UI",11))
        self._ph_file_label.pack(side="left", padx=8)
        self._ph_analyze_btn = ctk.CTkButton(file_row, text="🔬  Analyse",
                                              command=self._ph_start_analysis,
                                              height=34, width=120, state="disabled")
        self._ph_analyze_btn.pack(side="right", padx=14, pady=8)
        # ── Verdict banner ───────────────────────────────────────────
        self._ph_banner = ctk.CTkFrame(self._phishing_pane, corner_radius=0, height=48)
        self._ph_banner.pack(fill="x", side="top"); self._ph_banner.pack_propagate(False)
        self._ph_banner_lbl = ctk.CTkLabel(self._ph_banner, text="— awaiting analysis —",
                                           font=("Segoe UI",14,"bold"), text_color="gray")
        self._ph_banner_lbl.pack(side="left", padx=20, pady=8)
        self._ph_score_lbl = ctk.CTkLabel(self._ph_banner, text="",
                                          font=("Segoe UI",13), text_color="gray")
        self._ph_score_lbl.pack(side="right", padx=20)
        # ── Sub-tab bar ──────────────────────────────────────────────
        tab_names = ["📋 Summary","📨 Headers","🔗 URLs","🌐 IPs","📎 Attachments","📝 Work Note"]
        tab_bar = ctk.CTkFrame(self._phishing_pane, corner_radius=0, height=40,
                               fg_color=("#191927","#191927"))
        tab_bar.pack(fill="x", side="top"); tab_bar.pack_propagate(False)
        self._ph_tab_btns: dict[str,ctk.CTkButton] = {}
        for tname in tab_names:
            btn = ctk.CTkButton(tab_bar, text=tname, width=110, height=32,
                                corner_radius=6, fg_color="transparent",
                                hover_color="#2d2d4d",
                                command=lambda n=tname: self._ph_switch_tab(n))
            btn.pack(side="left", padx=4, pady=4)
            self._ph_tab_btns[tname] = btn
        # ── Sub-tab content frames ───────────────────────────────────
        ph_content = ctk.CTkFrame(self._phishing_pane, corner_radius=0, fg_color="transparent")
        ph_content.pack(fill="both", expand=True)
        self._ph_frames: dict[str, ctk.CTkFrame] = {}
        for tname in tab_names:
            f = ctk.CTkFrame(ph_content, corner_radius=0, fg_color="transparent")
            f.place(relx=0,rely=0,relwidth=1,relheight=1)
            self._ph_frames[tname] = f
        self._ph_active_tab = tab_names[0]
        self._ph_switch_tab(tab_names[0])
        # ── Build sub-tab widgets (ScrolledText for rich color tagging) ──
        _PH_BG = "#13131f"; _PH_FG = "#abb2bf"
        self._ph_texts: dict = {}
        for tname in tab_names:
            if tname == "📝 Work Note":
                outer = ctk.CTkFrame(self._ph_frames[tname], fg_color="transparent")
                outer.pack(fill="both", expand=True)
                btn_copy = ctk.CTkButton(outer, text="📋  Copy Work Note", width=160, height=30,
                                         command=self._ph_copy_worknote,
                                         fg_color="transparent", border_width=1)
                btn_copy.pack(anchor="ne", padx=10, pady=6)
                tb = scrolledtext.ScrolledText(outer, wrap="word", font=("Consolas",11),
                    bg=_PH_BG, fg=_PH_FG, insertbackground=_PH_FG,
                    selectbackground="#3a3a6a", relief="flat", bd=0,
                    padx=12, pady=10, state="disabled")
                tb.pack(fill="both", expand=True, padx=6, pady=(0,4))
            else:
                tb = scrolledtext.ScrolledText(self._ph_frames[tname], wrap="word", font=("Consolas",11),
                    bg=_PH_BG, fg=_PH_FG, insertbackground=_PH_FG,
                    selectbackground="#3a3a6a", relief="flat", bd=0,
                    padx=12, pady=10, state="disabled")
                tb.pack(fill="both", expand=True, padx=6, pady=4)
            tb.tag_config("head",   foreground="#61afef", font=("Consolas",11,"bold"))
            tb.tag_config("red",    foreground="#e06c75")
            tb.tag_config("green",  foreground="#98c379")
            tb.tag_config("orange", foreground="#e5c07b")
            tb.tag_config("purple", foreground="#c678dd")
            tb.tag_config("dim",    foreground="#5c6370")
            tb.tag_config("url",    foreground="#61afef")
            tb.tag_config("sep",    foreground="#3a3a6a")
            tb.tag_config("bold",   font=("Consolas",12,"bold"))
            self._ph_texts[tname] = tb
        self._ph_result: dict = {}

    def _ph_switch_tab(self, name: str):
        self._ph_active_tab = name
        self._ph_frames[name].lift()
        for n, btn in self._ph_tab_btns.items():
            btn.configure(fg_color="#3a3a6a" if n == name else "transparent")

    def _ph_browse(self):
        path = filedialog.askopenfilename(
            title="Select email file",
            filetypes=[("Email files","*.eml *.msg"),("EML","*.eml"),("MSG","*.msg"),("All","*.*")])
        if path:
            self._ph_file_path = path
            self._ph_file_label.configure(
                text=os.path.basename(path), text_color="white")
            self._ph_analyze_btn.configure(state="normal")

    def _ph_start_analysis(self):
        path = getattr(self,"_ph_file_path","")
        if not path: return
        self._ph_analyze_btn.configure(state="disabled", text="⏳  Analysing…")
        self._ph_banner_lbl.configure(text="⏳  Running analysis…", text_color="gray")
        self._ph_score_lbl.configure(text="")
        for tb in self._ph_texts.values():
            tb.config(state="normal"); tb.delete("1.0","end"); tb.config(state="disabled")
        self._executor.submit(self._ph_run_analysis, path)

    def _ph_upd(self, msg):
        self.after(0, lambda m=msg: self.status_bar.configure(text=m))
        time.sleep(0.05)

    def _ph_write(self, w, text, tag=None):
        w.config(state="normal")
        if tag: w.insert("end", text, tag)
        else:   w.insert("end", text)
        w.config(state="disabled")

    def _ph_clear(self, w):
        w.config(state="normal"); w.delete("1.0","end"); w.config(state="disabled")

    def _ph_sep(self, w):
        self._ph_write(w, "─"*72+"\n", "sep")

    def _ph_run_analysis(self, path: str):
        try:
            cfg = {
                "vt_key":       self.osint.vt_api_key,
                "urlscan_key":  self.osint.urlscan_api_key,
                "abuseipdb_key":self.osint.abuseipdb_api_key,
                "joe_key":      self.osint.joe_api_key,
                "joe_server":   self.osint.joe_server,
            }
            self._ph_upd("Parsing email headers and body…")
            ext = os.path.splitext(path)[1].lower()
            ed  = parse_eml(path) if ext == ".eml" else parse_msg(path)
            if ed.get("_error"):
                self.after(0, lambda e=ed["_error"]: messagebox.showerror("Parse Error", e))
                return

            urls = ed.get("urls", [])[:20]
            self._ph_upd(f"Found {len(urls)} URLs — deobfuscating…")
            deob_map = {url: ph_unwrap_url(url) for url in urls}
            url_results = {
                url: {"deobfuscation": deob_map[url],
                      "virustotal": {}, "urlscan": {}, "joe_sandbox": {}}
                for url in urls
            }

            def _enrich_url(url):
                deob = deob_map[url]; check_url = deob.get("final_url") or url
                vt_res = {}; us_res = {}; joe_res = {}
                if cfg.get("vt_key") and _ph_valid_url(check_url):
                    vt_res = ph_vt_check_url(check_url, cfg["vt_key"])
                if cfg.get("urlscan_key") and _ph_valid_url(check_url):
                    us_res = ph_urlscan_submit(check_url, cfg["urlscan_key"])
                if cfg.get("joe_key") and _ph_valid_url(check_url):
                    joe_res = ph_joe_submit(check_url, cfg["joe_key"], cfg.get("joe_server",""))
                return url, vt_res, us_res, joe_res

            if urls:
                self._ph_upd(f"Enriching {len(urls)} URL(s) in parallel…")
                ex = ThreadPoolExecutor(max_workers=min(len(urls), 5))
                try:
                    futures = {ex.submit(_enrich_url, u): u for u in urls}
                    done = 0; deadline = time.time() + 45; pending = set(futures.keys())
                    while pending and time.time() < deadline:
                        finished = [f for f in list(pending) if f.done()]
                        if not finished: time.sleep(0.25); continue
                        for fut in finished:
                            pending.remove(fut)
                            try:
                                url, vt_res, us_res, joe_res = fut.result(timeout=0)
                                url_results[url]["virustotal"] = vt_res
                                url_results[url]["urlscan"]    = us_res
                                url_results[url]["joe_sandbox"]= joe_res
                            except Exception as e:
                                url_results[futures[fut]]["virustotal"] = {"error": str(e)[:60]}
                            done += 1
                            self._ph_upd(f"URL enrichment: {done}/{len(urls)} complete…")
                    for fut in pending:
                        fut.cancel()
                        url_results[futures[fut]]["urlscan"] = {"error": "Timed out"}
                finally:
                    ex.shutdown(wait=False, cancel_futures=True)

            # IP enrichment
            ips_to_check = set()
            if ed.get("sender_ip"):        ips_to_check.add(ed["sender_ip"])
            if ed.get("x_originating_ip"): ips_to_check.add(ed["x_originating_ip"])
            for data in url_results.values():
                ip = (data.get("urlscan") or {}).get("ip")
                if ip: ips_to_check.add(ip)

            ip_results = {}

            def _enrich_ip(ip):
                ab_res = {}; vt_ip = {}; geo = {}
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
                                     "asn":a.get("asn"),
                                     "verdict":"MALICIOUS" if mal>=1 else "CLEAN"}
                    except: pass
                geo = ph_geolocate_ip(ip)
                return ip, ab_res, vt_ip, geo

            if ips_to_check:
                self._ph_upd(f"Checking {len(ips_to_check)} IP(s)…")
                ex = ThreadPoolExecutor(max_workers=5)
                try:
                    futures = {ex.submit(_enrich_ip, ip): ip for ip in list(ips_to_check)[:5]}
                    deadline = time.time() + 20; pending = set(futures.keys())
                    while pending and time.time() < deadline:
                        finished = [f for f in list(pending) if f.done()]
                        if not finished: time.sleep(0.25); continue
                        for fut in finished:
                            pending.remove(fut)
                            try:
                                ip, ab_res, vt_ip, geo = fut.result(timeout=0)
                                ip_results[ip] = {"abuseipdb": ab_res, "virustotal": vt_ip, "geo": geo}
                            except: pass
                    for fut in pending: fut.cancel()
                finally:
                    ex.shutdown(wait=False, cancel_futures=True)

            # Hop table
            self._ph_upd("Building hop table…")
            hop_table = ph_parse_hop_table(ed.get("received_headers", []))
            for hop in hop_table:
                hip = hop.get("ip")
                if hip and not _ph_private(hip):
                    hop["geo"] = ip_results.get(hip, {}).get("geo") or ph_geolocate_ip(hip)
            ed["hop_table"] = hop_table

            # Verdict + work note
            self._ph_upd("Computing verdict…")
            verdict = ph_compute_verdict(ed, url_results, ip_results)
            note    = ph_generate_worknote(ed, url_results, ip_results, verdict)
            self._ph_result = {"email":ed, "urls":url_results, "ips":ip_results,
                               "verdict":verdict, "note":note}
            self.after(0, self._ph_render_all)

        except Exception:
            err = traceback.format_exc()
            self.after(0, lambda: (
                messagebox.showerror("Analysis Error", err[:600]),
                self._ph_banner_lbl.configure(text="❌ Analysis failed", text_color="red")))
        finally:
            self.after(0, lambda: self._ph_analyze_btn.configure(state="normal", text="🔬  Analyse"))

    def _ph_render_all(self):
        r = self._ph_result; v = r["verdict"]; ed = r["email"]
        color = "#e06c75" if v["level"]=="MALICIOUS" else ("#e5c07b" if v["level"]=="SUSPICIOUS" else "#98c379")
        icon  = "🚨" if v["level"]=="MALICIOUS" else ("⚠️" if v["level"]=="SUSPICIOUS" else "✅")
        self._ph_banner_lbl.configure(
            text=f"{icon}  {v['level']}   Score: {v['score']}/200", text_color=color)
        flags_short = "  ".join(v["flags"][:4]) if v["flags"] else ""
        self._ph_score_lbl.configure(text=flags_short[:120], text_color=color)
        self._ph_render_summary(r)
        self._ph_render_headers(ed)
        self._ph_render_urls(r["urls"])
        self._ph_render_ips(r["ips"])
        self._ph_render_attachments(ed)
        self._ph_render_worknote(r["note"])
        self._ph_switch_tab("📋 Summary")
        self.status_bar.configure(
            text=f"Phishing analysis complete — {v['level']}  Score: {v['score']}/200")

    def _ph_render_summary(self, r):
        t = self._ph_texts["📋 Summary"]; self._ph_clear(t)
        v = r["verdict"]; ed = r["email"]
        self._ph_write(t, "ANALYSIS SUMMARY\n", "head"); self._ph_sep(t)
        lv = v["level"]
        self._ph_write(t, "Verdict : ")
        self._ph_write(t, f"{lv}\n",
            "red" if lv=="MALICIOUS" else "orange" if lv=="SUSPICIOUS" else "green")
        self._ph_write(t, f"Score   : {v['score']}/200\n\n")
        self._ph_write(t, "THREAT FLAGS\n", "head"); self._ph_sep(t)
        if v["flags"]:
            for fl in v["flags"]:
                tag = "red" if "🚨" in fl else ("orange" if "⚠️" in fl else "url")
                self._ph_write(t, fl+"\n", tag)
        else:
            self._ph_write(t, "  No threat indicators detected\n", "green")
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
        self._ph_write(t, f"  URLs found     : {len(r['urls'])}\n")
        self._ph_write(t, f"  IPs analyzed   : {len(r['ips'])}\n")
        self._ph_write(t, f"  Attachments    : {len(ed.get('attachments',[]))}\n")
        self._ph_write(t, f"  Keywords found : {len(ed.get('keywords',[]))}\n")
        if ed.get("domain_mismatches"):
            self._ph_write(t,
                f"\n  ⚠️  {len(ed['domain_mismatches'])} domain mismatch(es) detected\n", "orange")

    def _ph_render_headers(self, ed):
        t = self._ph_texts["📨 Headers"]; self._ph_clear(t)
        self._ph_write(t, "EMAIL IDENTITY\n", "head"); self._ph_sep(t)
        for label, key in [("Subject","subject"),("From","from"),("To","to"),("CC","cc"),
                            ("Reply-To","reply_to"),("Return-Path","return_path"),
                            ("Sender","sender"),("Date","date"),("Message-ID","message_id")]:
            v = ed.get(key) or "N/A"
            self._ph_write(t, f"  {label:<14}: ")
            self._ph_write(t, v+"\n", "dim" if v=="N/A" else None)
        self._ph_write(t, "\nAUTHENTICATION\n", "head"); self._ph_sep(t)
        for proto in ("spf","dkim","dmarc","arc"):
            val = ed.get(proto) or "N/A"
            c = "green" if val=="pass" else ("red" if val in ("fail","softfail") else "orange")
            self._ph_write(t, f"  {proto.upper():<8}: "); self._ph_write(t, val.upper()+"\n", c)
        self._ph_write(t, "\nINFRASTRUCTURE\n", "head"); self._ph_sep(t)
        for label, key in [("Sender IP","sender_ip"),("X-Originating-IP","x_originating_ip"),
                            ("X-Mailer","x_mailer"),("DKIM Domain","dkim_domain")]:
            v = ed.get(key) or "N/A"
            c = "orange" if key in ("sender_ip","x_originating_ip") and v!="N/A" else (
                "dim" if v=="N/A" else None)
            self._ph_write(t, f"  {label:<20}: "); self._ph_write(t, v+"\n", c)
        if ed.get("domain_mismatches"):
            self._ph_write(t, "\nDOMAIN MISMATCHES\n", "head"); self._ph_sep(t)
            for mm in ed["domain_mismatches"]:
                self._ph_write(t,
                    f"  ⚠️  {mm['type']}: From [{mm['from']}] vs Other [{mm['other']}]\n", "orange")
        if ed.get("keywords"):
            self._ph_write(t, "\nSUSPICIOUS KEYWORDS\n", "head"); self._ph_sep(t)
            self._ph_write(t, "  " + ", ".join(ed["keywords"]) + "\n", "orange")
        hops = ed.get("hop_table") or []
        if hops:
            self._ph_write(t, "\nMAIL HOP TRACE\n", "head"); self._ph_sep(t)
            HDR = f"  {'#':<3}  {'From':<30}  {'By':<28}  {'IP':<16}  {'Delay':>7}  {'Country':<14}  ISP\n"
            self._ph_write(t, HDR, "dim")
            for i, hop in enumerate(hops, 1):
                frm    = (hop.get("from") or "—")[:30].ljust(30)
                by     = (hop.get("by")   or "—")[:28].ljust(28)
                ip_col = (hop.get("ip")   or "—")[:16].ljust(16)
                geo    = hop.get("geo") or {}
                delay  = hop.get("delay_s")
                d_col  = f"{delay:>+6}s" if delay is not None else "     —"
                country = (geo.get("country") or "—")[:14].ljust(14)
                isp     = geo.get("isp") or geo.get("org") or "—"
                priv    = _ph_private(hop.get("ip",""))
                c       = "purple" if priv else ("orange" if i==1 else None)
                self._ph_write(t,
                    f"  {i:<3}  {frm}  {by}  {ip_col}  {d_col}  {country}  {isp[:40]}\n", c)

    def _ph_render_urls(self, url_results):
        t = self._ph_texts["🔗 URLs"]; self._ph_clear(t)
        self._ph_write(t, f"EXTRACTED URLS  ({len(url_results)} total)\n", "head"); self._ph_sep(t)
        if not url_results:
            self._ph_write(t, "  No URLs found.\n", "dim"); return
        for raw_url, data in url_results.items():
            deob = data.get("deobfuscation",{}) or {}
            vt   = data.get("virustotal",{}) or {}
            us   = data.get("urlscan",{}) or {}
            js   = data.get("joe_sandbox",{}) or {}
            verd = vt.get("verdict","UNKNOWN")
            c    = "red" if verd=="MALICIOUS" else ("orange" if verd=="SUSPICIOUS" else "green")
            self._ph_write(t, "\n  📎 "); self._ph_write(t, raw_url[:90]+"\n", "url")
            if deob.get("wrapper_type"):
                self._ph_write(t, f"      Wrapper     : {deob['wrapper_type']}\n", "purple")
            if deob.get("final_url") and deob["final_url"] != raw_url:
                self._ph_write(t, "      Final URL   : ")
                self._ph_write(t, deob["final_url"][:90]+"\n", "url")
            if vt.get("error"):
                self._ph_write(t, f"      VT Error    : {vt['error']}\n", "dim")
            else:
                self._ph_write(t, "      VT Verdict  : "); self._ph_write(t, verd+"\n", c)
                self._ph_write(t,
                    f"      VT Stats    : 🔴 {vt.get('malicious',0)}  "
                    f"🟡 {vt.get('suspicious',0)}  ✅ {vt.get('harmless',0)}\n")
            if us.get("error"):
                self._ph_write(t, f"      URLScan     : ⚠️ {us['error']}\n", "dim")
            elif us.get("status") == "pending":
                self._ph_write(t, "      URLScan     : ⏳ Pending — ")
                btn_us = tk.Button(t, text="🔄 Refresh", font=("Segoe UI",8),
                    bg="#2d2d4d", fg="#61afef", relief="flat", bd=0, cursor="hand2",
                    activebackground="#3a3a6a", activeforeground="#abb2bf",
                    command=lambda u=raw_url: self._ph_refresh_urlscan(u))
                t.config(state="normal"); t.window_create("end", window=btn_us); t.config(state="disabled")
                self._ph_write(t, f"  UUID: {us.get('uuid','?')[:8]}…\n", "dim")
            elif us.get("ip"):
                usv = us.get("verdict","?")
                uc  = "red" if usv=="MALICIOUS" else ("orange" if usv=="SUSPICIOUS" else "green")
                self._ph_write(t, "      URLScan     : "); self._ph_write(t, usv+"\n", uc)
                self._ph_write(t,
                    f"                   IP={us['ip']}  Score={us.get('score',0)}\n", "dim")
            if js.get("error"):
                self._ph_write(t, f"      Joe Sandbox : ⚠️ {js['error']}\n", "dim")
            elif js.get("status") == "pending":
                self._ph_write(t, "      Joe Sandbox : ⏳ Pending — ")
                btn_joe = tk.Button(t, text="🔄 Refresh", font=("Segoe UI",8),
                    bg="#2d2d4d", fg="#61afef", relief="flat", bd=0, cursor="hand2",
                    activebackground="#3a3a6a", activeforeground="#abb2bf",
                    command=lambda u=raw_url: self._ph_refresh_joe(u))
                t.config(state="normal"); t.window_create("end", window=btn_joe); t.config(state="disabled")
                self._ph_write(t, "\n", "dim")
            elif js.get("status") == "done":
                jv = js.get("verdict","?")
                jc = "red" if jv=="MALICIOUS" else ("orange" if jv=="SUSPICIOUS" else "green")
                self._ph_write(t, "      Joe Sandbox : "); self._ph_write(t, jv+"\n", jc)
            self._ph_sep(t)

    def _ph_render_ips(self, ip_results):
        t = self._ph_texts["🌐 IPs"]; self._ph_clear(t)
        self._ph_write(t, f"IP REPUTATION  ({len(ip_results)} IPs)\n", "head"); self._ph_sep(t)
        if not ip_results:
            self._ph_write(t, "  No IPs analyzed.\n", "dim"); return
        for ip, data in ip_results.items():
            ab  = data.get("abuseipdb",{}) or {}
            vt  = data.get("virustotal",{}) or {}
            geo = data.get("geo",{}) or {}
            self._ph_write(t, f"\n  🌐 {ip}\n", "orange")
            if geo:
                self._ph_write(t,
                    f"      Location   : {geo.get('city','?')}, {geo.get('country','?')}\n","dim")
                self._ph_write(t,
                    f"      ISP / Org  : {geo.get('isp','?')} / {geo.get('org','?')}\n","dim")
            if ab.get("error"):
                self._ph_write(t, f"      AbuseIPDB  : {ab['error']}\n", "dim")
            else:
                sc = ab.get("score",0)
                c  = "red" if sc>=75 else ("orange" if sc>=25 else "green")
                self._ph_write(t, "      AbuseIPDB  : Score="); self._ph_write(t, f"{sc}%", c)
                self._ph_write(t, f"  Reports={ab.get('total_reports',0)}\n")
            if vt.get("malicious"):
                self._ph_write(t,
                    f"      VT         : 🔴 Malicious={vt['malicious']}  Country={vt.get('country','?')}\n","red")
            self._ph_sep(t)

    def _ph_render_attachments(self, ed):
        t = self._ph_texts["📎 Attachments"]; self._ph_clear(t)
        atts = ed.get("attachments",[])
        self._ph_write(t, f"ATTACHMENTS  ({len(atts)} found)\n", "head"); self._ph_sep(t)
        if not atts:
            self._ph_write(t, "  No attachments found.\n", "dim"); return
        sus_exts = {".exe",".js",".vbs",".ps1",".bat",".cmd",".hta",".scr",
                    ".doc",".docm",".xlsm",".xlsb",".jar",".zip",".7z"}
        for att in atts:
            ext = os.path.splitext(att.get("filename",""))[1].lower()
            c   = "red" if ext in sus_exts else "green"
            self._ph_write(t, "\n  📎 "); self._ph_write(t, att.get("filename","unknown")+"\n","url")
            self._ph_write(t, f"      Type   : {att.get('content_type','?')}\n", "dim")
            self._ph_write(t, f"      Size   : {att.get('size',0):,} bytes\n", "dim")
            self._ph_write(t, "      Status : ")
            self._ph_write(t, ("⚠️ SUSPICIOUS EXTENSION" if ext in sus_exts else "✅ OK")+"\n", c)
            self._ph_write(t, f"      MD5    : {att.get('md5','')}\n", "dim")
            self._ph_write(t, f"      SHA256 : {att.get('sha256','')}\n", "dim")
            self._ph_sep(t)

    def _ph_render_worknote(self, note):
        t = self._ph_texts["📝 Work Note"]; self._ph_clear(t)
        for line in note.split("\n"):
            if line.startswith("="):             self._ph_write(t, line+"\n", "sep")
            elif line.startswith("──"):          self._ph_write(t, line+"\n", "head")
            elif "MALICIOUS" in line:            self._ph_write(t, line+"\n", "red")
            elif "SUSPICIOUS" in line:           self._ph_write(t, line+"\n", "orange")
            elif line.strip().startswith("🚨"):  self._ph_write(t, line+"\n", "red")
            elif line.strip().startswith("⚠️"):  self._ph_write(t, line+"\n", "orange")
            elif line.strip().startswith("✅"):  self._ph_write(t, line+"\n", "green")
            else:                               self._ph_write(t, line+"\n")

    def _ph_copy_worknote(self):
        t = self._ph_texts["📝 Work Note"]
        txt = t.get("1.0","end-1c")
        if txt.strip():
            self.clipboard_clear(); self.clipboard_append(txt)
            self.status_bar.configure(text="📋 Work note copied to clipboard ✓")

    def _ph_refresh_urlscan(self, raw_url):
        if not self._ph_result: return
        us = self._ph_result["urls"].get(raw_url, {}).get("urlscan", {})
        uuid = us.get("uuid")
        if not uuid: return
        def _poll():
            result = ph_urlscan_fetch(uuid, self.osint.urlscan_api_key)
            self._ph_result["urls"][raw_url]["urlscan"] = result
            verdict = ph_compute_verdict(
                self._ph_result["email"], self._ph_result["urls"], self._ph_result["ips"])
            note = ph_generate_worknote(
                self._ph_result["email"], self._ph_result["urls"], self._ph_result["ips"], verdict)
            self._ph_result["verdict"] = verdict; self._ph_result["note"] = note
            self.after(0, self._ph_render_all)
        threading.Thread(target=_poll, daemon=True).start()

    def _ph_refresh_joe(self, raw_url):
        if not self._ph_result: return
        js = self._ph_result["urls"].get(raw_url, {}).get("joe_sandbox", {})
        sid = js.get("submission_id") or js.get("webid")
        if not sid: return
        def _poll():
            result = ph_joe_fetch(sid, self.osint.joe_api_key, self.osint.joe_server)
            self._ph_result["urls"][raw_url]["joe_sandbox"] = result
            verdict = ph_compute_verdict(
                self._ph_result["email"], self._ph_result["urls"], self._ph_result["ips"])
            note = ph_generate_worknote(
                self._ph_result["email"], self._ph_result["urls"], self._ph_result["ips"], verdict)
            self._ph_result["verdict"] = verdict; self._ph_result["note"] = note
            self.after(0, self._ph_render_all)
        threading.Thread(target=_poll, daemon=True).start()


# ─────────────────────────── entry point ────────────────────────────────────
if __name__ == "__main__":
    app = OSINTApp()
    app.mainloop()
