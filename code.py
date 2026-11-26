pip install requests python-docx openpyxl matplotlib

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sonar_vapt_report.py
====================
Pulls every finding out of a SonarQube **Community Build** project through its
Web API and produces

    1. <out>/<name>_Source_Code_Review_Report.docx   (VAPT-style Word report)
    2. <out>/<name>_Findings.xlsx                    (severity-wise Excel workbook)

Install once:
    pip install requests python-docx openpyxl matplotlib

Run (minimum):
    python sonar_vapt_report.py --url http://localhost:9000 --token <TOKEN> \
        --project Acig-Source-code --org ACIG --app "ACIG Tech Web Application"

Run `python sonar_vapt_report.py -h` for all options.
"""
import argparse
import collections
import datetime as dt
import html as htmllib
import io
import os
import re
import sys
from html.parser import HTMLParser

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run:  pip install requests python-docx openpyxl matplotlib")

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
SEV_FILL = {"Critical": "C00000", "High": "FF0000", "Medium": "FFC000", "Low": "92D050", "Info": "00B0F0"}
SEV_FONT = {"Critical": "FFFFFF", "High": "FFFFFF", "Medium": "000000", "Low": "000000", "Info": "FFFFFF"}
SEV_TEXT = {"Critical": "C00000", "High": "FF0000", "Medium": "BF8F00", "Low": "548235", "Info": "0070C0"}
NAVY = "002060"

IMPACT_MAP = {"BLOCKER": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
LEGACY_MAP = {"BLOCKER": "Critical", "CRITICAL": "High", "MAJOR": "Medium", "MINOR": "Low", "INFO": "Info"}
HOTSPOT_MAP = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
QUALITY_MAP = {"SECURITY": "Security", "RELIABILITY": "Reliability", "MAINTAINABILITY": "Maintainability"}
QUALITY_ORDER = ["Security", "Reliability", "Maintainability"]
TYPE_QUALITY = {"VULNERABILITY": "Security", "SECURITY_HOTSPOT": "Security",
                "BUG": "Reliability", "CODE_SMELL": "Maintainability"}

RISK_DEFINITIONS = [
    ("Critical", "These vulnerabilities can allow attackers to take complete control of your web applications and web "
                 "servers. In exploiting this type of vulnerability, attackers could carry out a range of malicious acts."),
    ("High", "A High severity vulnerability, which means that on exploiting such vulnerabilities, attackers, can view "
             "information about your system that helps them find or exploit other vulnerabilities that enable them to "
             "access sensitive user and administrator information."),
    ("Medium", "Potential weakness in controls, which could develop into an exposure. Or Issues that represent areas of "
               "concern and may impact controls. They should be addressed reasonably promptly."),
    ("Low", "Potential weaknesses in controls, which in combination with other weaknesses can develop into exposure. "
            "Suggested improvements not immediately/directly affecting controls."),
    ("Info", "Weaknesses mentioned under these sections are informational and are best practices. Either these "
             "weaknesses cannot be exploited directly or are very difficult to exploit due to multiple constrains."),
]

OWASP_2021 = {1: "Broken Access Control", 2: "Cryptographic Failures", 3: "Injection", 4: "Insecure Design",
              5: "Security Misconfiguration", 6: "Vulnerable and Outdated Components",
              7: "Identification and Authentication Failures", 8: "Software and Data Integrity Failures",
              9: "Security Logging and Monitoring Failures", 10: "Server-Side Request Forgery (SSRF)"}

IMPACT_BY_CWE = {
    "79": "An attacker can inject malicious script into pages viewed by other users, leading to session hijacking, "
          "credential theft, defacement or actions performed on behalf of the victim.",
    "80": "Unsanitised content rendered in the browser can execute attacker-controlled script (Cross-Site Scripting), "
          "leading to session hijacking and theft of sensitive data.",
    "89": "An attacker can alter database queries to read, modify or delete data and, in severe cases, take over the "
          "database server.",
    "78": "An attacker may execute arbitrary operating-system commands with the privileges of the application.",
    "94": "An attacker may be able to execute arbitrary code in the context of the application.",
    "95": "An attacker may be able to execute arbitrary code in the context of the application.",
    "798": "Hard-coded credentials can be extracted from the source code or binary and used to gain unauthorised access "
           "to the associated systems and data.",
    "259": "Hard-coded passwords can be recovered by anyone with access to the code and reused to gain unauthorised access.",
    "321": "Hard-coded cryptographic keys allow an attacker to decrypt protected data or forge signed content.",
    "327": "Weak or broken cryptographic algorithms can be defeated, exposing confidential data or allowing tampering.",
    "328": "Weak hash functions can be reversed or collided, undermining password storage and integrity checks.",
    "330": "Predictable random values may be guessed by an attacker, compromising tokens, session IDs or keys.",
    "338": "Predictable random values may be guessed by an attacker, compromising tokens, session IDs or keys.",
    "295": "Improper certificate validation enables man-in-the-middle attacks and interception of sensitive traffic.",
    "297": "Improper host-name validation enables man-in-the-middle attacks and interception of sensitive traffic.",
    "319": "Data transmitted in cleartext can be intercepted or modified by an attacker on the network path.",
    "311": "Sensitive data that is not encrypted may be disclosed to unauthorised parties.",
    "352": "An attacker can trick an authenticated user into performing unintended state-changing actions.",
    "346": "Weak origin validation can allow untrusted sites to interact with the application and its data.",
    "942": "An over-permissive CORS policy can allow untrusted origins to read responses and sensitive data.",
    "614": "Cookies without the Secure attribute may be transmitted over unencrypted connections and intercepted.",
    "1004": "Cookies without the HttpOnly attribute can be read by client-side scripts, increasing the impact of XSS.",
    "22": "An attacker may read or write files outside the intended directory, exposing or tampering with sensitive data.",
    "502": "Deserialising untrusted data may allow remote code execution or denial of service.",
    "611": "XML External Entity processing may expose local files, enable SSRF or cause denial of service.",
    "601": "Users may be redirected to malicious sites, enabling phishing and credential theft.",
    "918": "An attacker may force the server to make requests to internal or third-party systems (SSRF).",
    "200": "Sensitive information may be exposed to unauthorised actors, assisting further attacks.",
    "209": "Verbose error messages may disclose internal details that assist an attacker.",
    "532": "Sensitive information written to logs may be accessed by unauthorised persons.",
    "117": "Unsanitised log data may allow log forging and hamper incident investigations.",
    "20": "Improper input validation may allow malformed or malicious data to reach sensitive functionality.",
    "434": "Unrestricted file upload may allow an attacker to upload and execute malicious content.",
    "400": "Uncontrolled resource consumption can be abused to cause denial of service.",
    "1333": "Inefficient regular expressions can be abused for ReDoS, exhausting CPU and causing denial of service.",
    "770": "Unbounded allocation of resources may be abused to cause denial of service.",
    "489": "Debug code left in production may expose sensitive behaviour or information.",
    "215": "Debug information exposed in production may reveal internals that assist an attacker.",
    "829": "Including functionality from untrusted sources (e.g. third-party scripts without integrity checks) may "
           "compromise the application.",
    "494": "Downloading or including code without integrity verification may allow tampered code to be executed.",
    "525": "Sensitive responses that are cached may be disclosed to other users of a shared device or proxy.",
    "1275": "Cookies with an inappropriate SameSite attribute may expose users to cross-site request attacks.",
}

IMPACT_BY_QUALITY = {
    "Security": "Exploitation of this weakness may allow an attacker to compromise the confidentiality, integrity or "
                "availability of the application and its data. The actual impact depends on the reachability of the "
                "affected code and the surrounding controls.",
    "Reliability": "May cause runtime errors, crashes, incorrect behaviour or an unexpected application state, resulting "
                   "in reduced availability and a degraded user experience. Certain defects can also be abused to "
                   "trigger denial of service.",
    "Maintainability": "Increases technical debt and makes the code harder to read, test and secure, which raises the "
                        "likelihood of defects and vulnerabilities being introduced in future changes.",
}

SLA = {"Critical": "Immediately (within 7 days)", "High": "Within 15 days", "Medium": "Within 30 days",
       "Low": "Within 90 days", "Info": "As part of routine maintenance"}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def log(msg):
    print(msg, flush=True)


def parse_dt(s):
    if not s:
        return None
    try:
        return dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def fmt_date(d):
    return d.strftime("%d-%m-%Y") if d else ""


def effort_to_min(s):
    """'1d 2h 30min' / '45min' / '2h' -> minutes (Sonar day = 8h)."""
    if not s:
        return 0
    tot = 0
    for n, u in re.findall(r"(\d+)\s*(d|h|min)", str(s)):
        n = int(n)
        tot += n * 480 if u == "d" else n * 60 if u == "h" else n
    return tot


def min_to_effort(m):
    m = int(m or 0)
    d, rem = divmod(m, 480)
    h, mi = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if mi or not parts:
        parts.append(f"{mi}min")
    return " ".join(parts)


def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "project"


def rating_letter(v):
    try:
        return "ABCDE"[int(float(v)) - 1]
    except Exception:
        return "-"


# --------------------------------------------------------------------------
# SonarQube client
# --------------------------------------------------------------------------
class Sonar:
    def __init__(self, url, token=None, user=None, password=None, verify=True):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.verify = verify
        if token:
            self.s.auth = (token, "")
        elif user:
            self.s.auth = (user, password or "")

    def get(self, path, **params):
        params = {k: v for k, v in params.items() if v is not None}
        r = self.s.get(self.url + path, params=params, timeout=90)
        if r.status_code == 401:
            sys.exit("ERROR 401: SonarQube rejected the credentials. Use --token (My Account > Security) "
                     "or --user/--password.")
        if r.status_code == 403:
            sys.exit(f"ERROR 403: the account has no permission for {path} (needs 'Browse' on the project).")
        r.raise_for_status()
        return r.json()

    def paged(self, path, key, ps=500, **params):
        out, p = [], 1
        while True:
            d = self.get(path, p=p, ps=ps, **params)
            out.extend(d.get(key, []))
            total = (d.get("paging") or {}).get("total", d.get("total", len(out)))
            if p * ps >= total or p * ps >= 10000 or not d.get(key):
                if total > 10000 and p * ps >= 10000:
                    log(f"  ! {path}: more than 10,000 results; Sonar caps the API at 10,000.")
                break
            p += 1
        return out


# --------------------------------------------------------------------------
# HTML -> blocks (for rule descriptions)
# --------------------------------------------------------------------------
class _Blocks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks, self.buf, self.mode, self.pre = [], [], "p", False
        self.links, self.cur = [], None

    def _flush(self):
        t = "".join(self.buf)
        t = t.strip("\n") if self.pre else re.sub(r"\s+", " ", t).strip()
        if t:
            self.blocks.append((self.mode, t))
        self.buf = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("p", "div", "ul", "ol", "table", "tr", "h1", "h2", "h3", "h4"):
            self._flush()
            self.mode = "h" if tag in ("h1", "h2", "h3", "h4") else "p"
        elif tag == "li":
            self._flush()
            self.mode = "li"
        elif tag == "pre":
            self._flush()
            self.pre, self.mode = True, "code"
        elif tag == "br":
            self.buf.append("\n" if self.pre else " ")
        elif tag == "a" and a.get("href"):
            self.cur = [a["href"], ""]

    def handle_endtag(self, tag):
        if tag in ("p", "div", "ul", "ol", "li", "table", "tr", "h1", "h2", "h3", "h4"):
            self._flush()
            self.mode = "p"
        elif tag == "pre":
            self._flush()
            self.pre, self.mode = False, "p"
        elif tag == "a" and self.cur:
            self.links.append(tuple(self.cur))
            self.cur = None

    def handle_data(self, d):
        self.buf.append(d)
        if self.cur is not None:
            self.cur[1] += d


def html_blocks(h):
    p = _Blocks()
    p.feed(h or "")
    p._flush()
    return p.blocks, p.links


def blocks_text(blocks):
    return " ".join(t for k, t in blocks if k != "code")


# --------------------------------------------------------------------------
# Rule knowledge
# --------------------------------------------------------------------------
def load_rule(sq, key, cache):
    if key in cache:
        return cache[key]
    try:
        r = sq.get("/api/rules/show", key=key)["rule"]
    except Exception:
        r = {"key": key, "name": key}
    secs, links, alltext = {}, [], []
    for s in r.get("descriptionSections") or []:
        blocks, lk = html_blocks(s.get("content", ""))
        links += lk
        alltext.append(blocks_text(blocks))
        k = s.get("key", "")
        if k not in secs or (secs[k][1] and not s.get("context")):
            secs[k] = (blocks, bool(s.get("context")))
    if not secs and r.get("htmlDesc"):                       # legacy layout
        blocks, lk = html_blocks(r["htmlDesc"])
        links += lk
        alltext.append(blocks_text(blocks))
        cur, buckets = "root_cause", collections.defaultdict(list)
        for kind, t in blocks:
            if kind == "h":
                lt = t.lower()
                cur = ("assess_the_problem" if "ask yourself" in lt else
                       "how_to_fix" if ("recommended" in lt or "compliant solution" in lt) else
                       "resources" if lt.startswith("see") else
                       "how_to_fix" if "sensitive code" in lt else cur)
                continue
            buckets[cur].append((kind, t))
        secs = {k: (v, False) for k, v in buckets.items()}
    full = " ".join(alltext)
    cwes = list(dict.fromkeys(re.findall(r"CWE[\s\-:]*(?:CWE-)?(\d{1,4})", full)))
    owasp = []
    for yr, n in re.findall(r"OWASP\s*-?\s*Top\s*10\s*(\d{4})\s*Category\s*A(\d{1,2})", full):
        owasp.append((yr, int(n)))
    info = {
        "key": key, "name": r.get("name", key),
        "secs": {k: v[0] for k, v in secs.items()},
        "links": [(h, t) for h, t in links if h.startswith("http")],
        "cwe": cwes, "owasp": list(dict.fromkeys(owasp)),
        "tags": r.get("sysTags", []) + r.get("tags", []),
        "lang": r.get("langName", ""),
    }
    cache[key] = info
    return info


def describe(info, quality, kind):
    s = info["secs"]
    blocks = [b for b in (s.get("introduction", []) + s.get("root_cause", [])) if b[0] in ("p", "li")]
    if not blocks:
        blocks = [b for b in sum(s.values(), []) if b[0] == "p"][:2]
    out, n = [], 0
    for k, t in blocks:
        if n > 1100:
            break
        out.append((k, t))
        n += len(t)
    prefix = ""
    if kind == "Security Hotspot":
        prefix = "SonarQube flagged this as a Security Hotspot: security-sensitive code that requires manual review " \
                 "to decide whether it is exploitable. "
    return prefix, out


def remediation(info):
    s = info["secs"]
    blocks = [b for b in s.get("how_to_fix", []) if b[0] in ("p", "li", "code", "h")]
    if not blocks:
        blocks = [b for b in s.get("assess_the_problem", []) if b[0] in ("p", "li")]
    out, n = [], 0
    for k, t in blocks:
        if n > 1800 or len(out) >= 10:
            break
        if k == "code":
            t = "\n".join(t.splitlines()[:14])
        out.append((k, t))
        n += len(t)
    return out


def impact_text(cwes, quality, kind):
    for c in cwes:
        if c in IMPACT_BY_CWE:
            return IMPACT_BY_CWE[c]
    if kind == "Security Hotspot":
        return IMPACT_BY_QUALITY["Security"]
    return IMPACT_BY_QUALITY.get(quality, IMPACT_BY_QUALITY["Security"])


def references(info, sq_url):
    refs = []
    for c in info["cwe"][:2]:
        refs.append(f"https://cwe.mitre.org/data/definitions/{c}.html")
    for h, _ in info["links"]:
        if h not in refs and "sonarsource.com/docs" not in h:
            refs.append(h)
    refs.append(f"{sq_url}/coding_rules?open={info['key']}&rule_key={info['key']}")
    return list(dict.fromkeys(refs))[:5]


# --------------------------------------------------------------------------
# Data collection
# --------------------------------------------------------------------------
def collect(args):
    sq = Sonar(args.url, args.token or os.environ.get("SONAR_TOKEN"), args.user, args.password,
               verify=not args.insecure)
    log(f"[1/5] Connecting to {sq.url} ...")
    try:
        ver = sq.s.get(sq.url + "/api/system/status", timeout=30).json().get("version", "unknown")
    except Exception as e:
        sys.exit(f"ERROR: cannot reach SonarQube at {sq.url}: {e}")
    base = {"projects": args.project}
    if args.branch:
        base["branch"] = args.branch

    comp = sq.get("/api/components/show", component=args.project, branch=args.branch).get("component", {})
    log(f"      project: {comp.get('name')} ({args.project}), SonarQube {ver}")

    # ---- issues
    log("[2/5] Downloading issues ...")
    statuses = args.issue_statuses

    def fetch_issues(**extra):
        try:
            return sq.paged("/api/issues/search", "issues", issueStatuses=statuses, **base, **extra)
        except requests.HTTPError as e:                      # older servers
            if e.response is not None and e.response.status_code == 400:
                legacy = {"OPEN": "OPEN", "CONFIRMED": "CONFIRMED", "ACCEPTED": "", "FALSE_POSITIVE": ""}
                st = ",".join(x for x in (legacy.get(s.strip(), s) for s in statuses.split(",")) if x) + ",REOPENED"
                return sq.paged("/api/issues/search", "issues", statuses=st, **base, **extra)
            raise

    probe = sq.get("/api/issues/search", ps=1, issueStatuses=statuses, **base)
    total = (probe.get("paging") or {}).get("total", 0)
    if total > 10000:
        raw = {}
        for sev in ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"):
            for typ in ("VULNERABILITY", "BUG", "CODE_SMELL"):
                for i in fetch_issues(severities=sev, types=typ):
                    raw[i["key"]] = i
        raw = list(raw.values())
    else:
        raw = fetch_issues()
    log(f"      {len(raw)} issues")

    # ---- hotspots
    log("[3/5] Downloading security hotspots ...")
    hs_raw = []
    try:
        hs_status = None if args.include_reviewed_hotspots else "TO_REVIEW"
        hs_raw = sq.paged("/api/hotspots/search", "hotspots", ps=500, projectKey=args.project,
                          status=hs_status, branch=args.branch)
    except Exception as e:
        log(f"      (hotspots skipped: {e})")
    log(f"      {len(hs_raw)} hotspots")

    # ---- measures / quality gate
    log("[4/5] Reading project metrics ...")
    metrics = ["ncloc", "ncloc_language_distribution", "bugs", "vulnerabilities", "code_smells", "security_hotspots",
               "security_hotspots_reviewed", "security_rating", "reliability_rating", "sqale_rating", "coverage",
               "duplicated_lines_density", "sqale_index", "files"]
    meas = {}
    try:
        for m in sq.get("/api/measures/component", component=args.project, branch=args.branch,
                        metricKeys=",".join(metrics)).get("component", {}).get("measures", []):
            meas[m["metric"]] = m.get("value")
    except Exception:
        for m in metrics:
            try:
                for x in sq.get("/api/measures/component", component=args.project, branch=args.branch,
                                metricKeys=m).get("component", {}).get("measures", []):
                    meas[x["metric"]] = x.get("value")
            except Exception:
                pass
    qg = "N/A"
    try:
        qg = sq.get("/api/qualitygates/project_status", projectKey=args.project,
                    branch=args.branch)["projectStatus"]["status"]
    except Exception:
        pass

    # ---- normalise
    log("[5/5] Enriching findings with rule knowledge ...")
    rules, items = {}, []
    prefix = args.project + ":"
    for i in raw:
        impacts = i.get("impacts") or []
        sev, qual = None, None
        if impacts:
            best = max(impacts, key=lambda x: SEV_RANK.get(IMPACT_MAP.get(x.get("severity"), "Info"), 0))
            sev = IMPACT_MAP.get(best.get("severity"))
            qual = QUALITY_MAP.get(best.get("softwareQuality"))
        sev = sev or LEGACY_MAP.get(i.get("severity"), "Medium")
        qual = qual or TYPE_QUALITY.get(i.get("type"), "Maintainability")
        comp_key = i.get("component", "")
        st = i.get("issueStatus") or i.get("status") or "OPEN"
        items.append({
            "kind": "Issue", "key": i["key"], "rule": i["rule"], "severity": sev, "quality": qual,
            "type": i.get("type", ""), "sonar_sev": i.get("severity", ""), "clean": i.get("cleanCodeAttribute", ""),
            "status": {"OPEN": "Open", "CONFIRMED": "Open", "REOPENED": "Open", "ACCEPTED": "Accepted",
                       "FALSE_POSITIVE": "False Positive", "FIXED": "Fixed", "RESOLVED": "Resolved",
                       "CLOSED": "Closed"}.get(st, st.title()),
            "resolution": i.get("resolution", ""),
            "comp": comp_key, "file": comp_key[len(prefix):] if comp_key.startswith(prefix) else comp_key,
            "line": i.get("line") or (i.get("textRange") or {}).get("startLine") or 0,
            "message": i.get("message", ""), "effort": i.get("effort", ""), "created": parse_dt(i.get("creationDate")),
            "tags": ", ".join(i.get("tags", [])), "assignee": i.get("assignee", "") or "",
            "link": f"{sq.url}/project/issues?id={args.project}&issues={i['key']}&open={i['key']}",
            "probability": "", "category": "",
        })
    for h in hs_raw:
        comp_key = h.get("component", "")
        rule = h.get("ruleKey") or ""
        if not rule:
            try:
                rule = sq.get("/api/hotspots/show", hotspot=h["key"])["rule"]["key"]
            except Exception:
                rule = "unknown"
        prob = h.get("vulnerabilityProbability", "MEDIUM")
        status = h.get("status", "TO_REVIEW")
        res = h.get("resolution", "")
        items.append({
            "kind": "Security Hotspot", "key": h["key"], "rule": rule, "severity": HOTSPOT_MAP.get(prob, "Medium"),
            "quality": "Security", "type": "SECURITY_HOTSPOT", "sonar_sev": prob, "clean": "",
            "status": "To Review" if status == "TO_REVIEW" else f"Reviewed - {res.title()}" if res else "Reviewed",
            "resolution": res, "comp": comp_key,
            "file": comp_key[len(prefix):] if comp_key.startswith(prefix) else comp_key,
            "line": h.get("line") or 0, "message": h.get("message", ""), "effort": "",
            "created": parse_dt(h.get("creationDate")), "tags": "", "assignee": h.get("assignee", "") or "",
            "link": f"{sq.url}/security_hotspots?id={args.project}&hotspots={h['key']}",
            "probability": prob.title(), "category": h.get("securityCategory", ""),
        })
    if args.security_only:
        items = [x for x in items if x["quality"] == "Security"]
    if args.min_severity:
        floor = SEV_RANK[args.min_severity]
        items = [x for x in items if SEV_RANK[x["severity"]] >= floor]

    for it in items:
        info = load_rule(sq, it["rule"], rules)
        it["rule_name"] = info["name"]
        it["cwe"] = ", ".join(f"CWE-{c}" for c in info["cwe"]) or "N/A"
        it["owasp"] = ", ".join(f"A{n:02d}:{yr}" for yr, n in info["owasp"])

    items.sort(key=lambda x: (-SEV_RANK[x["severity"]], QUALITY_ORDER.index(x["quality"]), x["file"], x["line"]))

    # ---- group by rule
    groups = collections.OrderedDict()
    for it in items:
        groups.setdefault((it["rule"], it["kind"]), []).append(it)
    findings = []
    for (rule, kind), its in groups.items():
        info = rules[rule]
        top = max(its, key=lambda x: SEV_RANK[x["severity"]])
        qual = collections.Counter(x["quality"] for x in its).most_common(1)[0][0]
        statuses = {x["status"] for x in its}
        pre, desc = describe(info, qual, kind)
        findings.append({
            "title": info["name"], "rule": rule, "kind": kind, "severity": top["severity"], "quality": qual,
            "status": "Open" if "Open" in statuses else sorted(statuses)[0],
            "cwe": [f"CWE-{c}" for c in info["cwe"]], "owasp": info["owasp"], "info": info,
            "desc_prefix": pre, "desc": desc, "impact": impact_text(info["cwe"], qual, kind),
            "fix": remediation(info), "refs": references(info, sq.url), "items": its,
            "effort_min": sum(effort_to_min(x["effort"]) for x in its), "lang": info.get("lang", ""),
        })
    findings.sort(key=lambda f: (-SEV_RANK[f["severity"]], QUALITY_ORDER.index(f["quality"]),
                                 f["kind"] != "Issue", -len(f["items"]), f["title"]))
    for n, f in enumerate(findings, 1):
        f["id"] = f"F-{n:03d}"
        f["no"] = n

    # ---- code evidence
    if args.snippets > 0:
        log(f"      fetching code evidence ({args.snippets} per finding) ...")
        for f in findings:
            seen, f["evidence"] = set(), []
            for it in f["items"]:
                if len(f["evidence"]) >= args.snippets:
                    break
                if it["file"] in seen or not it["line"]:
                    continue
                seen.add(it["file"])
                try:
                    d = sq.get("/api/sources/lines", key=it["comp"], branch=args.branch,
                               **{"from": max(1, it["line"] - 2), "to": it["line"] + 2})
                    lines = [(x["line"], htmllib.unescape(re.sub(r"<[^>]+>", "", x.get("code", ""))))
                             for x in d.get("sources", [])]
                    if lines:
                        f["evidence"].append((it, lines))
                except Exception:
                    pass
    else:
        for f in findings:
            f["evidence"] = []

    langs = []
    for part in (meas.get("ncloc_language_distribution") or "").split(";"):
        if "=" in part:
            a, b = part.split("=")
            langs.append((a, int(b)))
    return {
        "sq": sq, "version": ver, "comp": comp, "items": items, "findings": findings, "measures": meas,
        "quality_gate": qg, "languages": langs, "rules": rules,
    }


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------
def stats(data):
    items, findings = data["items"], data["findings"]
    s = {
        "f_sev": collections.Counter(f["severity"] for f in findings),
        "o_sev": collections.Counter(x["severity"] for x in items),
        "q_sev": collections.defaultdict(collections.Counter),
        "kind": collections.Counter(x["kind"] for x in items),
        "status": collections.Counter(x["status"] for x in items),
        "files": collections.defaultdict(collections.Counter),
        "owasp": collections.defaultdict(lambda: [0, 0]),
    }
    for x in items:
        s["q_sev"][x["quality"]][x["severity"]] += 1
        s["files"][x["file"]][x["severity"]] += 1
    for f in findings:
        for yr, n in f["owasp"]:
            if yr == "2021":
                s["owasp"][n][0] += 1
                s["owasp"][n][1] += len(f["items"])
    s["effort_min"] = sum(effort_to_min(x["effort"]) for x in items)
    return s


# --------------------------------------------------------------------------
# DOCX
# --------------------------------------------------------------------------
def build_docx(data, st, args, path):
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_TAB_ALIGNMENT, WD_TAB_LEADER
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor

    FONT = "Garamond"
    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Inches(8.5), Inches(11)
    sec.left_margin, sec.right_margin = Inches(1.0), Inches(0.75)
    sec.top_margin, sec.bottom_margin = Inches(1.0), Inches(0.8)
    sec.header_distance, sec.footer_distance = Inches(0.6), Inches(0.4)
    W = 6.75  # usable width, inches

    # ---- styles
    def style_font(stl, name, size, bold=None, color="000000", italic=None):
        stl.font.name, stl.font.size = name, Pt(size)
        if bold is not None:
            stl.font.bold = bold
        if italic is not None:
            stl.font.italic = italic
        stl.font.color.rgb = RGBColor.from_string(color)
        rf = stl.element.get_or_add_rPr().find(qn("w:rFonts"))
        for a in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
            rf.attrib.pop(qn(a), None)
        for a in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
            rf.set(qn(a), name)

    style_font(doc.styles["Normal"], FONT, 11.5)
    doc.styles["Normal"].paragraph_format.space_after = Pt(6)
    for nm, sz, bf, af, brk in (("Heading 1", 17, 6, 8, True), ("Heading 2", 14, 12, 6, False),
                                ("Heading 3", 12.5, 10, 4, False)):
        stl = doc.styles[nm]
        style_font(stl, FONT, sz, bold=True)
        stl.paragraph_format.space_before, stl.paragraph_format.space_after = Pt(bf), Pt(af)
        stl.paragraph_format.keep_with_next = True
        stl.paragraph_format.page_break_before = brk
    for nm in ("List Bullet",):
        style_font(doc.styles[nm], FONT, 11.5)

    # ---- low-level helpers
    def shade(cell, fill):
        tcPr = cell._tc.get_or_add_tcPr()
        for old in tcPr.findall(qn("w:shd")):
            tcPr.remove(old)
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), fill)
        tcPr.append(shd)

    def para_shade(p, fill):
        pPr = p._p.get_or_add_pPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), fill)
        pPr.append(shd)

    def para_border(p, side, color=NAVY, sz=8):
        pPr = p._p.get_or_add_pPr()
        b = pPr.find(qn("w:pBdr"))
        if b is None:
            b = OxmlElement("w:pBdr")
            pPr.append(b)
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:val"), "single")
        e.set(qn("w:sz"), str(sz))
        e.set(qn("w:space"), "4")
        e.set(qn("w:color"), color)
        b.append(e)

    def run(p, text, bold=False, italic=False, color=None, size=None, font=None, underline=False):
        r = p.add_run(text)
        r.bold, r.italic, r.underline = bold, italic, underline
        if color:
            r.font.color.rgb = RGBColor.from_string(color)
        if size:
            r.font.size = Pt(size)
        if font:
            r.font.name = font
            r._r.get_or_add_rPr().rFonts.set(qn("w:eastAsia"), font)
        return r

    def field(p, instr, placeholder="1", **kw):
        def fc(t, dirty=False):
            r = p.add_run()
            e = OxmlElement("w:fldChar")
            e.set(qn("w:fldCharType"), t)
            if dirty:
                e.set(qn("w:dirty"), "true")
            r._r.append(e)
            return r
        fc("begin")
        r = p.add_run()
        it = OxmlElement("w:instrText")
        it.set(qn("xml:space"), "preserve")
        it.text = f" {instr} "
        r._r.append(it)
        fc("separate")
        run(p, placeholder, **kw)
        fc("end")

    def P(text="", bold=False, italic=False, align=None, size=None, color=None, after=None, before=None,
          keep=False):
        p = doc.add_paragraph()
        if text:
            run(p, text, bold=bold, italic=italic, size=size, color=color)
        if align == "c":
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        elif align == "j":
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        if after is not None:
            p.paragraph_format.space_after = Pt(after)
        if before is not None:
            p.paragraph_format.space_before = Pt(before)
        if keep:
            p.paragraph_format.keep_with_next = True
        return p

    def LP(label, text="", color=None, bold_val=False, keep=False):
        p = doc.add_paragraph()
        run(p, label, bold=True)
        if text:
            run(p, " " + text, color=color, bold=bold_val)
        if keep:
            p.paragraph_format.keep_with_next = True
        return p

    toc = []

    def H(level, text):
        h = doc.add_heading(text, level=level)
        toc.append((level, text))
        return h

    def code_par(text, size=8.5):
        for ln in text.splitlines() or [""]:
            p = doc.add_paragraph()
            run(p, ln if ln else " ", font="Consolas", size=size)
            pf = p.paragraph_format
            pf.space_after = pf.space_before = Pt(0)
            pf.left_indent = Inches(0.08)
            pf.keep_together = True
            para_shade(p, "F2F2F2")
        sp = doc.add_paragraph()
        sp.paragraph_format.space_after = Pt(2)

    def blocks_out(blocks):
        for kind, t in blocks:
            if kind == "li":
                p = doc.add_paragraph(style="List Bullet")
                run(p, t)
                p.paragraph_format.space_after = Pt(2)
            elif kind == "code":
                code_par(t)
            elif kind == "h":
                P(t, bold=True, italic=True, size=11, after=2, keep=True)
            elif kind == "p":
                p = P(t, align="j", after=4)

    def table(headers, rows, widths, size=10.5, hfill=NAVY, center=True, bold_first=False, left_cols=()):
        t = doc.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        tblPr = t._tbl.tblPr
        lay = OxmlElement("w:tblLayout")
        lay.set(qn("w:type"), "fixed")
        tblPr.append(lay)

        def put(cell, val, header=False, ci=0):
            fill = color = None
            bold = header or (bold_first and ci == 0)
            if isinstance(val, dict):
                fill, color, bold = val.get("fill"), val.get("color"), val.get("bold", bold)
                val = val["text"]
            cell.width = Inches(widths[ci])
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = p.paragraph_format.space_before = Pt(2)
            if center and ci not in left_cols:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run(p, str(val), bold=bold, size=size, color=("FFFFFF" if header else color))
            if header:
                shade(cell, hfill)
            elif fill:
                shade(cell, fill)

        for ci, w_ in enumerate(widths):
            t.columns[ci].width = Inches(w_)
        for ci, h in enumerate(headers):
            put(t.rows[0].cells[ci], h, header=True, ci=ci)
        trPr = t.rows[0]._tr.get_or_add_trPr()
        th = OxmlElement("w:tblHeader")
        trPr.append(th)
        for r in rows:
            cells = t.add_row().cells
            cs = OxmlElement("w:cantSplit")
            t.rows[-1]._tr.get_or_add_trPr().append(cs)
            for ci, v in enumerate(r):
                put(cells[ci], v, ci=ci)
        doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return t

    def sevcell(sv):
        return {"text": sv, "fill": SEV_FILL[sv], "color": SEV_FONT[sv], "bold": True}

    # ---- header / footer
    hp = sec.header.paragraphs[0]
    hp.paragraph_format.tab_stops.add_tab_stop(Inches(W / 2), WD_TAB_ALIGNMENT.CENTER)
    hp.paragraph_format.tab_stops.add_tab_stop(Inches(W), WD_TAB_ALIGNMENT.RIGHT)
    run(hp, "\t" + args.org, bold=True, size=11)
    run(hp, "\t" + args.report_date, bold=True, size=11)
    para_border(hp, "bottom")
    fp = sec.footer.paragraphs[0]
    fp.paragraph_format.tab_stops.add_tab_stop(Inches(W / 2), WD_TAB_ALIGNMENT.CENTER)
    fp.paragraph_format.tab_stops.add_tab_stop(Inches(W), WD_TAB_ALIGNMENT.RIGHT)
    run(fp, "Classification: Confidential", size=9)
    run(fp, "\tPage ", size=10)
    field(fp, "PAGE", "1", size=10, bold=True)
    run(fp, " of ", size=10)
    field(fp, "NUMPAGES", "1", size=10, bold=True)
    para_border(fp, "top")

    # ======================================================== COVER
    for _ in range(9):
        P("", after=12)
    P("Source Code Review Report", bold=True, align="c", size=18, after=4)
    P("Static Application Security Testing (SAST) - SonarQube Community Build", align="c", size=12.5, after=14)
    P(f"Organization: {args.org}", align="c", size=15, after=4)
    P(f"Application: {args.app}", align="c", size=13)
    for _ in range(7):
        P("", after=12)
    P("Document Timestamp", bold=True, size=11.5, after=4)
    table(["Version", "Issued by", "Reviewed by", "Issued Date"],
          [[args.version, args.author, args.reviewer, args.report_date]], [1.0, 1.95, 1.95, 1.85])

    # ======================================================== TOC (filled at the end)
    tp = doc.add_paragraph()
    tp.paragraph_format.page_break_before = True
    run(tp, "Table of Contents", bold=True, size=18)
    toc_anchor = doc.add_paragraph()          # entries are inserted before this paragraph later

    # ======================================================== 1. DOCUMENT CONTROL
    H(1, "1. Document Control")
    H(2, "1.1 Document Approvers")
    P("The individuals who reviewed, verified and approved the content of this document based on the requirements "
      "of the defined services during this document's creation are listed in the table below:", align="j")
    table(["Approver Name", "Approver Designation", "Date Content was Approved"],
          [[args.reviewer, args.designation, args.report_date]], [2.0, 2.45, 2.3])
    H(2, "1.2 Amendment Record")
    P("The following Change History log contains a record of changes made to this document.", align="j")
    table(["Version", "Issuer", "Section / Nature of Change", "Published/ Revised Date"],
          [[args.version, args.author, "Initial Source Code Review", args.report_date]], [0.9, 1.9, 2.25, 1.7])

    # ======================================================== 2. EXECUTIVE SUMMARY
    comp, meas = data["comp"], data["measures"]
    H(1, "2. Executive Summary")
    H(2, "2.1 Scope of Testing")
    P("The following source code repository was in scope and included in this assessment:", align="j")
    table(["Sr. No.", "Application Name", "Project Key", "Review Environment", "Testing Methodology"],
          [[1, args.app, args.project, args.environment, "White Box (SAST)"]],
          [0.6, 1.9, 1.7, 1.2, 1.35])
    langs = ", ".join(f"{a} ({b:,} LOC)" for a, b in data["languages"]) or "N/A"
    rows = [
        ["SonarQube project name", comp.get("name", args.project)],
        ["SonarQube version", f"Community Build {data['version']}"],
        ["Branch analysed", args.branch or "Main branch"],
        ["Application version", comp.get("version", "N/A")],
        ["Last analysis date", fmt_date(parse_dt(comp.get("analysisDate"))) or "N/A"],
        ["Lines of code", f"{int(meas['ncloc']):,}" if meas.get("ncloc") else "N/A"],
        ["Languages", langs],
        ["Files analysed", f"{int(float(meas['files'])):,}" if meas.get("files") else "N/A"],
        ["Quality Gate", {"OK": "Passed", "ERROR": "Failed", "WARN": "Warning"}.get(data["quality_gate"],
                                                                                   data["quality_gate"])],
        ["Security / Reliability / Maintainability rating",
         f"{rating_letter(meas.get('security_rating'))} / {rating_letter(meas.get('reliability_rating'))} / "
         f"{rating_letter(meas.get('sqale_rating'))}"],
        ["Duplicated lines", f"{meas['duplicated_lines_density']}%" if meas.get("duplicated_lines_density") else "N/A"],
        ["Test coverage", f"{meas['coverage']}%" if meas.get("coverage") else "Not reported"],
        ["Estimated remediation effort", min_to_effort(st["effort_min"])],
    ]
    P("Code base profile as reported by SonarQube:", keep=True)
    table(["Attribute", "Value"], rows, [2.8, 3.95], left_cols=(0, 1), bold_first=True)

    H(2, "2.2 Milestone")
    table(["Milestone / Deliverable", "Date"],
          [["Source Code Review Initiation", args.start_date], ["Source Code Review Completion", args.end_date]],
          [4.4, 2.35])

    H(2, "2.3 Risk Classification")
    t = doc.add_table(rows=0, cols=2)
    t.style = "Table Grid"
    t.autofit = False
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.columns[0].width, t.columns[1].width = Inches(1.0), Inches(5.75)
    for sv, txt in RISK_DEFINITIONS:
        c = t.add_row().cells
        t.rows[-1]._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        c[0].width, c[1].width = Inches(1.0), Inches(5.75)
        shade(c[0], SEV_FILL[sv])
        p = c[0].paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run(p, f"{sv} Risk", bold=True, color=SEV_FONT[sv], size=10.5)
        run(c[1].paragraphs[0], txt, size=10.5)
        c[0].vertical_alignment = c[1].vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        for cc in c:
            cc.paragraphs[0].paragraph_format.keep_with_next = True
            cc.paragraphs[0].paragraph_format.space_after = Pt(2)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)

    H(2, "2.4 Methodology and Severity Mapping")
    P("The source code was analysed with SonarQube Community Build using the active Quality Profile of each "
      "language. Every issue and security hotspot reported by the scanner was exported through the SonarQube Web API, "
      "grouped by rule, enriched with the rule's CWE / OWASP references and mapped to the risk scale used in this "
      "report. Issues with the status Open or Confirmed" +
      (" and Security Hotspots still To Review" if st["kind"].get("Security Hotspot") else "") +
      " are included. The SonarQube severity was mapped as follows:", align="j")
    table(["Report Severity", "SonarQube Impact (MQR)", "SonarQube Severity (Standard)", "Hotspot Probability"],
          [[sevcell("Critical"), "Blocker", "Blocker", "-"], [sevcell("High"), "High", "Critical", "High"],
           [sevcell("Medium"), "Medium", "Major", "Medium"], [sevcell("Low"), "Low", "Minor", "Low"],
           [sevcell("Info"), "Info", "Info", "-"]], [1.4, 1.7, 2.0, 1.65])

    # ======================================================== 3. SUMMARY
    fs, os_ = st["f_sev"], st["o_sev"]
    nF, nO = len(data["findings"]), len(data["items"])
    H(1, "3. Summary of Findings")
    n_sec = st["q_sev"]["Security"]
    P(f"This section lists and bifurcates the total number of vulnerabilities reported, based on risk level. The "
      f"source code review was performed on the {args.app} code base. The review revealed {fs['Critical']} Critical, "
      f"{fs['High']} High, {fs['Medium']} Medium, {fs['Low']} Low and {fs['Info']} Informational findings "
      f"({nF} unique rules, {nO} individual occurrences in the code). Of these, {sum(n_sec.values())} occurrences are "
      f"security related, {sum(st['q_sev']['Reliability'].values())} affect reliability and "
      f"{sum(st['q_sev']['Maintainability'].values())} affect maintainability. We recommend implementing the "
      f"measures suggested for mitigation for each finding to improve the security posture of the application.",
      align="j")
    H(2, "3.1 Findings by Risk Level")
    table(SEV_ORDER + ["Total"],
          [[fs[s] for s in SEV_ORDER] + [nF], [os_[s] for s in SEV_ORDER] + [nO]],
          [1.125] * 6, hfill=NAVY)
    # recolour header cells + add row labels via caption
    tb = doc.tables[-1]
    for ci, sv in enumerate(SEV_ORDER):
        shade(tb.rows[0].cells[ci], SEV_FILL[sv])
        for r in tb.rows[0].cells[ci].paragraphs[0].runs:
            r.font.color.rgb = RGBColor.from_string(SEV_FONT[sv])
    shade(tb.rows[0].cells[5], "A6A6A6")
    P("Row 1: unique findings (grouped by rule).  Row 2: total occurrences in the source code.", italic=True,
      size=10, align="c")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(6.2, 3.0), dpi=160)
        vals = [fs[s] for s in SEV_ORDER]
        bars = ax.bar(SEV_ORDER, vals, color=["#" + SEV_FILL[s] for s in SEV_ORDER], width=0.55)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + max(vals + [1]) * 0.02, str(v), ha="center", fontsize=9)
        ax.set_title("Risk Overview (unique findings)", fontsize=11, fontweight="bold")
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=0.3)
        ax.set_axisbelow(True)
        buf = io.BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        doc.add_picture(buf, width=Inches(5.4))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER

        fig, ax = plt.subplots(figsize=(6.2, 2.6), dpi=160)
        left = [0] * 3
        for sv in SEV_ORDER:
            v = [st["q_sev"][q][sv] for q in QUALITY_ORDER]
            ax.barh(QUALITY_ORDER, v, left=left, color="#" + SEV_FILL[sv], label=sv)
            left = [a + b for a, b in zip(left, v)]
        ax.invert_yaxis()
        ax.set_title("Occurrences by Software Quality and Severity", fontsize=11, fontweight="bold")
        ax.legend(ncol=5, fontsize=8, loc="lower right", frameon=False)
        ax.spines[["top", "right"]].set_visible(False)
        buf = io.BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        doc.add_picture(buf, width=Inches(5.4))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
    except ImportError:
        P("(Install matplotlib to include charts: pip install matplotlib)", italic=True)

    H(2, "3.2 Findings by Software Quality")
    rows = []
    for q in QUALITY_ORDER:
        c = st["q_sev"][q]
        rows.append([q] + [c[s] for s in SEV_ORDER] + [sum(c.values())])
    rows.append(["Total"] + [os_[s] for s in SEV_ORDER] + [nO])
    table(["Quality"] + SEV_ORDER + ["Total"], rows, [1.65, 0.85, 0.85, 0.85, 0.85, 0.85, 0.85], bold_first=True)

    H(2, "3.3 Security Hotspots Review")
    hs = [x for x in data["items"] if x["kind"] == "Security Hotspot"]
    if hs:
        P(f"SonarQube reported {len(hs)} security hotspot(s). A hotspot is security-sensitive code that must be "
          f"reviewed manually to decide whether it is a real vulnerability.", align="j")
        c = collections.Counter((x["probability"], x["status"]) for x in hs)
        table(["Review Priority", "Status", "Count"],
              [[p, s, n] for (p, s), n in sorted(c.items(), key=lambda kv: -SEV_RANK.get(kv[0][0], 0))],
              [2.25, 2.5, 2.0])
    else:
        P("No security hotspots are pending review in the analysed project.", align="j")

    H(2, "3.4 Most Affected Files")
    top = sorted(st["files"].items(), key=lambda kv: -sum(kv[1].values()))[:10]
    if top:
        table(["Sr.", "File"] + ["Crit", "High", "Med", "Low", "Info"] + ["Total"],
              [[i, f] + [c[s] for s in SEV_ORDER] + [sum(c.values())] for i, (f, c) in enumerate(top, 1)],
              [0.4, 3.0, 0.5, 0.5, 0.5, 0.5, 0.5, 0.85], size=9, left_cols=(1,))

    # ======================================================== 4. FINDINGS
    H(1, "4. Vulnerability Analysis & Findings")
    H(2, "4.1 Vulnerability Overview")
    if data["findings"]:
        table(["Sr. No", "Vulnerability", "Severity", "CWE/CVE", "Occurrences", "Status"],
              [[f["no"], f["title"], sevcell(f["severity"]), ", ".join(f["cwe"][:2]) or "N/A", len(f["items"]),
                {"text": f["status"], "bold": True}] for f in data["findings"]],
              [0.55, 2.85, 0.85, 1.0, 0.75, 0.75], size=10, left_cols=(1,))
    else:
        P("No findings were reported by SonarQube for the selected scope.")

    H(2, "4.2 Detailed Findings")
    for f in data["findings"]:
        H(3, f"4.2.{f['no']} {f['title']}")
        LP("Severity Level:", f["severity"], color=SEV_TEXT[f["severity"]], bold_val=True, keep=True)
        LP("Status:", f["status"], color="FF0000" if f["status"] in ("Open", "To Review") else "548235",
           bold_val=True, keep=True)
        LP("CVE/CWE:", ", ".join(f["cwe"]) or "N/A", keep=True)
        if f["owasp"]:
            LP("OWASP:", ", ".join(f"Top 10 {y} - A{n:02d} {OWASP_2021.get(n, '')}".strip() if y == "2021"
                                   else f"Top 10 {y} - A{n:02d}" for y, n in f["owasp"]), keep=True)
        LP("Category:", f"{f['quality']} ({f['kind']})  |  Rule: {f['rule']}", keep=True)
        LP("Occurrences:", f"{len(f['items'])} (estimated effort {min_to_effort(f['effort_min'])})"
           if f["effort_min"] else str(len(f["items"])))

        p = LP("Description:", f["desc_prefix"])
        first = True
        for kind, t in f["desc"]:
            if kind == "li":
                q = doc.add_paragraph(style="List Bullet")
                run(q, t)
            elif first:
                run(p, ("" if f["desc_prefix"] else " ") + t)
                p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                first = False
            else:
                P(t, align="j", after=4)
        if first and not f["desc_prefix"]:
            run(p, " " + f["items"][0]["message"])
        LP("Business Impact:", f["impact"]).alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

        LP("Vulnerable Files:", keep=True)
        cap = args.max_locations
        locs = f["items"][:cap]
        table(["Sr.", "File Path", "Line", "Status"],
              [[i, x["file"], x["line"] or "-", x["status"]] for i, x in enumerate(locs, 1)],
              [0.5, 4.45, 0.7, 1.1], size=9.5, left_cols=(1,))
        if len(f["items"]) > cap:
            P(f"... and {len(f['items']) - cap} more occurrence(s). The complete list is available in the "
              f"accompanying Excel workbook.", italic=True, size=10.5)

        LP("Proof of Concept:", f"SonarQube rule {f['rule']} flagged the code below.", keep=True)
        if f["evidence"]:
            for it, lines in f["evidence"]:
                P(f"{it['file']}  (line {it['line']})", italic=True, size=10, after=2, keep=True)
                code_par("\n".join(f"{'>' if n == it['line'] else ' '} {n:>4} | {c.rstrip()[:110]}"
                                   for n, c in lines))
        else:
            P(f"Location: {f['items'][0]['file']}:{f['items'][0]['line']} - {f['items'][0]['message']}", size=11)

        LP("Remediation:", "" if f["fix"] else "Review the flagged code and apply the fix recommended by the rule "
           "(see reference).")
        blocks_out(f["fix"])
        p = LP("Reference:", keep=False)
        for r in f["refs"]:
            q = doc.add_paragraph(style="List Bullet")
            run(q, r, size=10.5, color="0563C1", underline=True)
            q.paragraph_format.space_after = Pt(0)

    # ======================================================== 5. OWASP
    H(1, "5. OWASP Top 10 Mapping")
    P("SonarQube tags its security rules with OWASP Top 10 (2021) categories. The table shows how many findings "
      "of this review map to each category. All categories were covered by the rule set applied during the scan.",
      align="j")
    rows = []
    for n in range(1, 11):
        fcount, ocount = st["owasp"].get(n, [0, 0]) if n in st["owasp"] else (0, 0)
        rows.append([f"A{n:02d}: {OWASP_2021[n]}", fcount, ocount, "\u2713"])
    table(["OWASP Top 10 - 2021", "Findings", "Occurrences", "Performed"], rows, [3.6, 1.0, 1.15, 1.0],
          left_cols=(0,))
    if not st["owasp"]:
        P("No finding in this report carries an OWASP Top 10 2021 tag.", italic=True, size=10.5)

    # ======================================================== 6. RECOMMENDATIONS
    H(1, "6. Conclusion and Remediation Roadmap")
    P("Findings should be fixed in order of risk. The table below gives the suggested remediation window for "
      "each risk level together with the number of findings that fall in it.", align="j")
    table(["Priority", "Findings", "Occurrences", "Suggested Remediation Window"],
          [[sevcell(s), fs[s], os_[s], SLA[s]] for s in SEV_ORDER], [1.2, 1.1, 1.3, 3.15])
    P("General recommendations", bold=True, keep=True)
    for t in [
        "Fix all Critical and High findings first and re-run the SonarQube scan to confirm they are closed.",
        "Review each Security Hotspot manually and mark it Safe, Acknowledged or Fixed with a justification.",
        "Enforce a Quality Gate in the CI/CD pipeline that fails the build on new Blocker/High security issues.",
        "Remove hard-coded secrets from the repository, rotate any exposed credential and use a secrets manager.",
        "Pin and regularly update third-party dependencies and run Software Composition Analysis in addition to SAST.",
        "Provide secure-coding training to the development team based on the recurring rule categories above.",
        "Schedule a re-test after remediation to validate closure of all reported findings.",
    ]:
        q = doc.add_paragraph(style="List Bullet")
        run(q, t)

    H(1, "7. Disclaimer and Limitations")
    P("This report is based on automated static analysis performed by SonarQube Community Build. Static analysis "
      "can produce false positives and cannot detect every class of vulnerability (for example business-logic flaws, "
      "authorisation design issues, runtime configuration or infrastructure weaknesses). Findings should be "
      "validated by the development team before remediation. Community Build analyses a single main branch and does "
      "not include the taint-analysis rules available in commercial editions, so injection-type vulnerabilities "
      "that require inter-procedural data-flow tracking may not be reported. This report reflects the state of the "
      "code at the time of the last analysis and does not constitute a guarantee of security.", align="j")

    # ---- fill TOC (pre-populated; Word refreshes page numbers when the file is opened)
    entries = []
    for lvl, text in toc:
        p = OxmlElement("w:p")
        pPr = OxmlElement("w:pPr")
        ind = OxmlElement("w:ind")
        ind.set(qn("w:left"), str(int((lvl - 1) * 280)))
        sp = OxmlElement("w:spacing")
        sp.set(qn("w:after"), "40")
        pPr.append(sp)
        pPr.append(ind)
        p.append(pPr)
        entries.append((p, text, lvl))
    from docx.text.paragraph import Paragraph
    for idx, (p, text, lvl) in enumerate(entries):
        para = Paragraph(p, toc_anchor._parent)
        if idx == 0:
            for t_, extra in (("begin", True), ("instr", None), ("separate", None)):
                r = para.add_run()
                if t_ == "instr":
                    it = OxmlElement("w:instrText")
                    it.set(qn("xml:space"), "preserve")
                    it.text = ' TOC \\o "1-3" \\h \\z \\u '
                    r._r.append(it)
                else:
                    e = OxmlElement("w:fldChar")
                    e.set(qn("w:fldCharType"), t_)
                    if extra:
                        e.set(qn("w:dirty"), "true")
                    r._r.append(e)
        run(para, text, bold=(lvl == 1), size=11.5)
        if idx == len(entries) - 1:
            r = para.add_run()
            e = OxmlElement("w:fldChar")
            e.set(qn("w:fldCharType"), "end")
            r._r.append(e)
        toc_anchor._p.addprevious(p)

    doc.core_properties.title = f"Source Code Review Report - {args.app}"
    doc.core_properties.author = args.author
    doc.core_properties.subject = "SonarQube Community SAST findings"
    doc.save(path)


# --------------------------------------------------------------------------
# XLSX
# --------------------------------------------------------------------------
def build_xlsx(data, st, args, path):
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, Reference
    from openpyxl.chart.series import DataPoint
    from openpyxl.formatting.rule import CellIsRule
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter as L
    from openpyxl.worksheet.datavalidation import DataValidation

    F = "Arial"
    thin = Side(style="thin", color="BFBFBF")
    box = Border(left=thin, right=thin, top=thin, bottom=thin)
    hdr_font = Font(name=F, bold=True, color="FFFFFF", size=10)
    body = Font(name=F, size=10)
    wrap = Alignment(wrap_text=True, vertical="top")
    ctr = Alignment(horizontal="center", vertical="center", wrap_text=True)
    items, findings = data["items"], data["findings"]
    n = len(items)

    wb = Workbook()
    ws_sum = wb.active
    ws_sum.title = "Summary"

    def header(ws, cols, fills=None, row=1):
        for i, (name, width) in enumerate(cols, 1):
            c = ws.cell(row=row, column=i, value=name)
            c.font, c.border, c.alignment = hdr_font, box, ctr
            c.fill = PatternFill("solid", fgColor=(fills or {}).get(i, NAVY))
            ws.column_dimensions[L(i)].width = width
        ws.row_dimensions[row].height = 30

    def sev_cf(ws, rng):
        for sv in SEV_ORDER:
            ws.conditional_formatting.add(rng, CellIsRule(
                operator="equal", formula=[f'"{sv}"'],
                fill=PatternFill("solid", bgColor=SEV_FILL[sv], fgColor=SEV_FILL[sv]),
                font=Font(name=F, bold=True, color=SEV_FONT[sv])))

    def put_row(ws, r, vals, center_cols=()):
        for i, v in enumerate(vals, 1):
            c = ws.cell(row=r, column=i, value=v)
            c.font, c.border = body, box
            c.alignment = ctr if i in center_cols else wrap

    # ------------------------------------------------ All Findings
    ws = wb.create_sheet("All Findings")
    cols = [("Sr. No", 7), ("Severity", 11), ("Software Quality", 16), ("Kind", 16), ("Rule", 22),
            ("Finding", 48), ("CWE", 14), ("OWASP", 14), ("Status", 14), ("File", 55), ("Line", 7),
            ("Message", 60), ("Effort", 9), ("Created", 16), ("Tags", 22), ("Assignee", 14),
            ("Sonar Severity / Probability", 16), ("Clean Code Attribute", 18), ("Link", 10), ("Issue Key", 24)]
    header(ws, cols)
    for r, x in enumerate(items, 2):
        put_row(ws, r, [r - 1, x["severity"], x["quality"], x["kind"], x["rule"], x["rule_name"], x["cwe"],
                        x["owasp"], x["status"], x["file"], x["line"] or None, x["message"], x["effort"],
                        x["created"], x["tags"], x["assignee"], x["sonar_sev"], x["clean"], "Open" if x["link"] else "",
                        x["key"]], center_cols=(1, 2, 3, 7, 8, 9, 11, 13, 14, 17))
        ws.cell(row=r, column=14).number_format = "dd-mm-yyyy hh:mm"
        c = ws.cell(row=r, column=19)
        c.hyperlink, c.font = x["link"], Font(name=F, size=10, color="0563C1", underline="single")
    ws.freeze_panes = "C2"
    ws.auto_filter.ref = f"A1:{L(len(cols))}{max(n + 1, 2)}"
    sev_cf(ws, f"B2:B{max(n + 1, 2)}")
    last = max(n + 1, 2)
    R = lambda col: f"'All Findings'!${col}$2:${col}${last}"

    # ------------------------------------------------ Vulnerability register
    wr = wb.create_sheet("Vulnerability Register", 1)
    rc = [("Sr. No", 7), ("Finding ID", 10), ("Vulnerability", 46), ("Severity", 11), ("Software Quality", 15),
          ("Kind", 15), ("CWE/CVE", 14), ("OWASP Top 10", 16), ("Rule", 22), ("Occurrences", 12), ("Status", 12),
          ("Est. Effort", 11), ("Description", 70), ("Business Impact", 60), ("Remediation", 80),
          ("Reference", 55), ("Assigned To", 16), ("Target Date", 13), ("Remediation Status", 18),
          ("Retest Result", 16), ("Remarks", 30)]
    header(wr, rc, fills={i: "BF8F00" for i in range(17, 22)})
    for r, f in enumerate(findings, 2):
        fix = "\n".join(("  - " if k == "li" else "") + t for k, t in f["fix"] if k not in ("code", "h"))
        desc = (f["desc_prefix"] + " ".join(t for k, t in f["desc"])).strip() or f["items"][0]["message"]
        put_row(wr, r, [f["no"], f["id"], f["title"], f["severity"], f["quality"], f["kind"],
                        ", ".join(f["cwe"]) or "N/A",
                        ", ".join(f"A{nn:02d}:{y}" for y, nn in f["owasp"]), f["rule"],
                        f"=COUNTIFS({R('E')},I{r},{R('D')},F{r})", f["status"], min_to_effort(f["effort_min"]),
                        desc[:3000], f["impact"], fix[:3000] or "Apply the fix recommended by the rule.",
                        "\n".join(f["refs"]), None, None, "Open", None, None],
                center_cols=(1, 2, 4, 5, 6, 7, 8, 10, 11, 12, 18, 19, 20))
        wr.cell(row=r, column=18).number_format = "dd-mm-yyyy"
        for ci in range(17, 22):
            wr.cell(row=r, column=ci).fill = PatternFill("solid", fgColor="FFF2CC")
    lastr = max(len(findings) + 1, 2)
    wr.freeze_panes = "D2"
    wr.auto_filter.ref = f"A1:{L(len(rc))}{lastr}"
    sev_cf(wr, f"D2:D{lastr}")
    dv = DataValidation(type="list", formula1='"Open,In Progress,Fixed,Accepted Risk,False Positive"',
                        allow_blank=True)
    dv2 = DataValidation(type="list", formula1='"Not Retested,Closed,Re-opened"', allow_blank=True)
    wr.add_data_validation(dv)
    wr.add_data_validation(dv2)
    dv.add(f"S2:S{lastr + 200}")
    dv2.add(f"T2:T{lastr + 200}")

    # ------------------------------------------------ Hotspots
    wh = wb.create_sheet("Security Hotspots")
    hc = [("Sr. No", 7), ("Review Priority", 14), ("Status", 18), ("Rule", 22), ("Hotspot", 55),
          ("Security Category", 18), ("CWE", 14), ("OWASP", 14), ("File", 55), ("Line", 7), ("Message", 60),
          ("Created", 16), ("Link", 10)]
    header(wh, hc)
    hs = [x for x in items if x["kind"] == "Security Hotspot"]
    for r, x in enumerate(hs, 2):
        put_row(wh, r, [r - 1, x["probability"], x["status"], x["rule"], x["rule_name"], x["category"], x["cwe"],
                        x["owasp"], x["file"], x["line"] or None, x["message"], x["created"], "Open"],
                center_cols=(1, 2, 3, 6, 7, 8, 10, 12))
        wh.cell(row=r, column=12).number_format = "dd-mm-yyyy hh:mm"
        c = wh.cell(row=r, column=13)
        c.hyperlink, c.font = x["link"], Font(name=F, size=10, color="0563C1", underline="single")
    wh.freeze_panes = "A2"
    wh.auto_filter.ref = f"A1:{L(len(hc))}{max(len(hs) + 1, 2)}"
    if not hs:
        wh["A2"] = "No security hotspots pending review."
        wh["A2"].font = Font(name=F, italic=True, size=10)

    # ------------------------------------------------ One sheet per severity
    sc = [("Sr. No", 7), ("Finding", 48), ("Software Quality", 16), ("Kind", 16), ("Rule", 22), ("CWE", 14),
          ("Status", 12), ("File", 55), ("Line", 7), ("Message", 60), ("Effort", 9), ("Link", 10)]
    for sv in SEV_ORDER:
        sub = [x for x in items if x["severity"] == sv]
        if not sub:
            continue
        w = wb.create_sheet(sv)
        header(w, sc)
        for r, x in enumerate(sub, 2):
            put_row(w, r, [r - 1, x["rule_name"], x["quality"], x["kind"], x["rule"], x["cwe"], x["status"],
                           x["file"], x["line"] or None, x["message"], x["effort"], "Open"],
                    center_cols=(1, 3, 4, 6, 7, 9, 11))
            c = w.cell(row=r, column=12)
            c.hyperlink, c.font = x["link"], Font(name=F, size=10, color="0563C1", underline="single")
        w.sheet_properties.tabColor = SEV_FILL[sv]
        w.freeze_panes = "A2"
        w.auto_filter.ref = f"A1:{L(len(sc))}{len(sub) + 1}"

    # ------------------------------------------------ By file
    wf = wb.create_sheet("By File")
    fc = [("Sr. No", 7), ("File", 70)] + [(s, 10) for s in SEV_ORDER] + [("Total", 10)]
    header(wf, fc)
    files = sorted(st["files"].items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    for r, (fn, _) in enumerate(files, 2):
        vals = [r - 1, fn] + [f"=COUNTIFS({R('J')},$B{r},{R('B')},{L(3 + i)}$1)" for i in range(5)] + [f"=SUM(C{r}:G{r})"]
        put_row(wf, r, vals, center_cols=(1, 3, 4, 5, 6, 7, 8))
    wf.freeze_panes = "C2"
    wf.auto_filter.ref = f"A1:H{max(len(files) + 1, 2)}"

    # ------------------------------------------------ Code metrics
    wm = wb.create_sheet("Code Metrics")
    header(wm, [("Metric", 40), ("Value", 40)])
    meas, comp = data["measures"], data["comp"]
    mrows = [("Project", comp.get("name", args.project)), ("Project key", args.project),
             ("SonarQube version", f"Community Build {data['version']}"),
             ("Branch", args.branch or "Main branch"), ("Application version", comp.get("version", "")),
             ("Last analysis", fmt_date(parse_dt(comp.get("analysisDate")))),
             ("Quality Gate", data["quality_gate"]), ("Lines of code", meas.get("ncloc", "")),
             ("Files", meas.get("files", "")), ("Bugs", meas.get("bugs", "")),
             ("Vulnerabilities", meas.get("vulnerabilities", "")), ("Code smells", meas.get("code_smells", "")),
             ("Security hotspots", meas.get("security_hotspots", "")),
             ("Hotspots reviewed %", meas.get("security_hotspots_reviewed", "")),
             ("Security rating", rating_letter(meas.get("security_rating"))),
             ("Reliability rating", rating_letter(meas.get("reliability_rating"))),
             ("Maintainability rating", rating_letter(meas.get("sqale_rating"))),
             ("Coverage %", meas.get("coverage", "")), ("Duplicated lines %", meas.get("duplicated_lines_density", "")),
             ("Technical debt (min)", meas.get("sqale_index", "")),
             ("Languages", ", ".join(f"{a}: {b}" for a, b in data["languages"]))]
    for r, (k, v) in enumerate(mrows, 2):
        put_row(wm, r, [k, v])
        wm.cell(row=r, column=1).font = Font(name=F, bold=True, size=10)

    # ------------------------------------------------ Summary sheet
    s = ws_sum
    s.sheet_view.showGridLines = False
    s.column_dimensions["A"].width = 34
    for col in "BCDEFGH":
        s.column_dimensions[col].width = 15
    s["A1"] = f"{args.org} - Source Code Review (SonarQube Community)"
    s["A1"].font = Font(name=F, bold=True, size=16, color=NAVY)
    s["A2"] = f"{args.app}  |  Project key: {args.project}  |  Report date: {args.report_date}"
    s["A2"].font = Font(name=F, italic=True, size=10)

    def section(r, title):
        c = s.cell(row=r, column=1, value=title)
        c.font = Font(name=F, bold=True, size=12, color=NAVY)

    def th(r, labels, fills=None):
        for i, t in enumerate(labels, 1):
            c = s.cell(row=r, column=i, value=t)
            c.font, c.border, c.alignment = hdr_font, box, ctr
            c.fill = PatternFill("solid", fgColor=(fills or {}).get(i, NAVY))

    def td(r, vals, bold=False):
        for i, v in enumerate(vals, 1):
            c = s.cell(row=r, column=i, value=v)
            c.font, c.border = Font(name=F, size=10, bold=bold or i == 1), box
            c.alignment = Alignment(horizontal="left" if i == 1 else "center", vertical="center")

    section(4, "1. Findings by Severity (occurrences)")
    th(5, ["Severity", "Count", "% of total"])
    for i, sv in enumerate(SEV_ORDER):
        r = 6 + i
        td(r, [sv, f"=COUNTIFS({R('B')},A{r})", f"=IF($B$11=0,0,B{r}/$B$11)"])
        s.cell(row=r, column=3).number_format = "0.0%"
        s.cell(row=r, column=1).fill = PatternFill("solid", fgColor=SEV_FILL[sv])
        s.cell(row=r, column=1).font = Font(name=F, bold=True, size=10, color=SEV_FONT[sv])
    td(11, ["Total", "=SUM(B6:B10)", "=SUM(C6:C10)"], bold=True)
    s["C11"].number_format = "0.0%"

    section(13, "2. Software Quality x Severity (occurrences)")
    th(14, ["Software Quality"] + SEV_ORDER + ["Total"])
    for i, q in enumerate(QUALITY_ORDER):
        r = 15 + i
        td(r, [q] + [f"=COUNTIFS({R('C')},$A{r},{R('B')},{L(2 + j)}$14)" for j in range(5)] + [f"=SUM(B{r}:F{r})"])
    td(18, ["Total"] + [f"=SUM({L(2 + j)}15:{L(2 + j)}17)" for j in range(6)], bold=True)

    section(20, "3. Findings by Kind")
    th(21, ["Kind", "Count"])
    td(22, ["Issue (vulnerability / bug / code smell)", f'=COUNTIFS({R("D")},"Issue")'])
    td(23, ["Security Hotspot", f'=COUNTIFS({R("D")},"Security Hotspot")'])

    section(25, "4. Findings by Status")
    th(26, ["Status", "Count"])
    statuses = sorted({x["status"] for x in items}) or ["Open"]
    for i, stt in enumerate(statuses):
        td(27 + i, [stt, f"=COUNTIFS({R('I')},A{27 + i})"])
    r0 = 27 + len(statuses) + 1

    section(r0, "5. Unique Findings (grouped by rule)")
    th(r0 + 1, SEV_ORDER + ["Total"])
    for j, sv in enumerate(SEV_ORDER):
        c = s.cell(row=r0 + 1, column=j + 1)
        c.fill = PatternFill("solid", fgColor=SEV_FILL[sv])
        c.font = Font(name=F, bold=True, size=10, color=SEV_FONT[sv])
    VR = f"'Vulnerability Register'!$D$2:$D${lastr}"
    for j in range(5):
        c = s.cell(row=r0 + 2, column=j + 1, value=f"=COUNTIFS({VR},{L(j + 1)}{r0 + 1})")
    s.cell(row=r0 + 2, column=6, value=f"=SUM(A{r0 + 2}:E{r0 + 2})")
    for j in range(1, 7):
        c = s.cell(row=r0 + 2, column=j)
        c.font, c.border, c.alignment = Font(name=F, size=10, bold=True), box, ctr

    lg = r0 + 4
    section(lg, "Legend & notes")
    notes = [
        "All counts on this sheet are live formulas over the 'All Findings' and 'Vulnerability Register' sheets.",
        "'Vulnerability Register': columns Q-U (amber headers) are inputs for the remediation tracker "
        "(assignee, target date, status, re-test).",
        "Severity mapping: Blocker->Critical, High (Critical in Standard mode)->High, Medium (Major)->Medium, "
        "Low (Minor)->Low, Info->Info. Hotspots use their review priority.",
        "Source: SonarQube Community Build " + data["version"] + " Web API. Generated " + args.report_date + ".",
    ]
    for i, t in enumerate(notes, 1):
        c = s.cell(row=lg + i, column=1, value=t)
        c.font = Font(name=F, size=9, italic=True)

    ch = BarChart()
    ch.type, ch.style, ch.title = "col", 10, "Occurrences by Severity"
    ch.add_data(Reference(s, min_col=2, min_row=5, max_row=10), titles_from_data=True)
    ch.set_categories(Reference(s, min_col=1, min_row=6, max_row=10))
    ch.legend = None
    ch.height, ch.width = 7.5, 13
    ser = ch.series[0]
    for idx, sv in enumerate(SEV_ORDER):
        pt = DataPoint(idx=idx)
        pt.graphicalProperties.solidFill = SEV_FILL[sv]
        ser.dPt.append(pt)
    s.add_chart(ch, "J4")

    wb.move_sheet("All Findings", offset=0)
    wb.save(path)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Generate a VAPT-style Word report and an Excel workbook from SonarQube Community findings.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    g = ap.add_argument_group("SonarQube connection")
    g.add_argument("--url", default="http://localhost:9000")
    g.add_argument("--token", help="User token (or set env SONAR_TOKEN)")
    g.add_argument("--user")
    g.add_argument("--password")
    g.add_argument("--project", required=True, help="Project KEY (the id= value in the Sonar URL)")
    g.add_argument("--branch")
    g.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    g = ap.add_argument_group("Scope")
    g.add_argument("--issue-statuses", default="OPEN,CONFIRMED", help="Issue statuses to include")
    g.add_argument("--include-reviewed-hotspots", action="store_true", help="Also export reviewed hotspots")
    g.add_argument("--security-only", action="store_true", help="Drop reliability/maintainability findings")
    g.add_argument("--min-severity", choices=SEV_ORDER, help="Drop findings below this report severity")
    g.add_argument("--snippets", type=int, default=2, help="Code-evidence snippets per finding (0 = none)")
    g.add_argument("--max-locations", type=int, default=20, help="Max file rows per finding in the Word report")
    g = ap.add_argument_group("Report details")
    g.add_argument("--org", default="ACIG")
    g.add_argument("--app", help="Application name (default: SonarQube project name)")
    g.add_argument("--environment", default="UAT")
    g.add_argument("--author", default="Shivam Dwivedi")
    g.add_argument("--reviewer", default="Shivam Dwivedi")
    g.add_argument("--designation", default="Cybersecurity Consultant")
    g.add_argument("--version", default="1.0")
    g.add_argument("--report-date")
    g.add_argument("--start-date")
    g.add_argument("--end-date")
    g.add_argument("--out", default="./vapt_output")
    g.add_argument("--name", help="Output file prefix (default: project key)")
    args = ap.parse_args()

    today = dt.date.today().strftime("%d-%m-%Y")
    args.report_date = args.report_date or today
    args.start_date = args.start_date or today
    args.end_date = args.end_date or today
    os.makedirs(args.out, exist_ok=True)

    data = collect(args)
    args.app = args.app or data["comp"].get("name", args.project)
    st = stats(data)
    prefix = safe_name(args.name or args.project)
    docx_path = os.path.join(args.out, f"{prefix}_Source_Code_Review_Report.docx")
    xlsx_path = os.path.join(args.out, f"{prefix}_Findings.xlsx")

    log("Building Word report ...")
    build_docx(data, st, args, docx_path)
    log("Building Excel workbook ...")
    build_xlsx(data, st, args, xlsx_path)

    fs = st["f_sev"]
    log("\nDone.")
    log(f"  Findings (unique rules): Critical {fs['Critical']} | High {fs['High']} | Medium {fs['Medium']} | "
        f"Low {fs['Low']} | Info {fs['Info']}  (total {len(data['findings'])})")
    log(f"  Occurrences: {len(data['items'])}")
    log(f"  Word : {docx_path}")
    log(f"  Excel: {xlsx_path}")
    log("  Tip: open the .docx in Word and press Ctrl+A then F9 to refresh the Table of Contents page numbers.")


if __name__ == "__main__":
    main()
