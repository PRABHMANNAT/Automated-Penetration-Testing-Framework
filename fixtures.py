"""Fixed response summaries for two fictional assets. No request payloads or probes."""

TARGETS = {
    "storefront": {"name": "Storefront", "host": "storefront.demo.test", "ip": "192.0.2.10", "port": 443,
                   "path": "/shop", "owner": "Commerce lab", "technology": "Sample storefront"},
    "portal": {"name": "Customer portal", "host": "portal.demo.test", "ip": "192.0.2.20", "port": 443,
               "path": "/account", "owner": "Platform lab", "technology": "Sample customer portal"},
}

TOOLS = {
    "Nmap": "Host and service inventory",
    "OWASP ZAP": "Web application observations",
    "Nikto": "Server configuration observations",
    "Nuclei": "Template detection observations",
}

# id, title, route suffix, parameter, CWE, CVSS, exploit factor, impact,
# classifier probability, recorded verification, evidence summary, remediation
CASES = [
    ("config", "Sensitive configuration in response", "/settings", "", "CWE-200", 9.1, .91, .95, .99, "Confirmed",
     "The recorded response included configuration metadata marked internal. Values were removed from the fixture.",
     "Remove internal settings from response serializers and add an explicit allowlist for public fields."),
    ("cors", "Overly broad cross-origin access", "/preferences", "", "CWE-942", 8.1, .64, .80, .96, "Confirmed",
     "A saved header review found an overly broad origin policy on a sensitive route.",
     "Allow only approved origins and restrict credentialed cross-origin requests."),
    ("session", "Session cookie missing Secure", "/signin", "session", "CWE-614", 6.0, .29, .68, .94, "Confirmed",
     "The cookie summary lists HttpOnly and SameSite. The Secure attribute was absent.",
     "Set Secure on session cookies and redirect all inbound HTTP to HTTPS."),
    ("cache", "Private response marked cacheable", "/overview", "", "CWE-525", 6.5, .35, .72, .87, "Confirmed",
     "The saved cache policy classified an account response as publicly cacheable.",
     "Set Cache-Control: private, no-store for responses containing account information."),
    ("framing", "Missing framing restriction", "/help", "", "CWE-1021", 4.3, .13, .35, .76, "Inconclusive",
     "The recorded response lacked both a frame-ancestors policy and an X-Frame-Options header.",
     "Add a Content-Security-Policy frame-ancestors directive that reflects the allowed embedding policy."),
    ("banner", "Server version disclosed", "", "", "CWE-200", 3.1, .08, .22, .65, "Confirmed",
     "The server header summary included a product version.",
     "Remove unnecessary version information from server headers and error pages."),
    ("component", "Unconfirmed component version alert", "/resources", "", "CWE-1104", 7.5, .41, .62, .23, "Inconclusive",
     "The version hint appeared only in decorative page text. The fixture contains no inventory match.",
     "Confirm the component with the deployment inventory before assigning remediation."),
    ("index", "Unconfirmed directory listing alert", "/library", "", "CWE-548", 5.3, .24, .40, .12, "Inconclusive",
     "The recorded content was a generic index page. It contained no evidence of directory enumeration.",
     "Review the directory indexing setting and verify whether the page is intentionally public."),
]

# Scanner-specific field layouts make the normalization stage reproducible.
# Separate detector rows for the same case make the agreement visible.
ALERTS = [
    ("OWASP ZAP", "config", .92), ("Nuclei", "config", .88),
    ("OWASP ZAP", "cors", .91), ("Nuclei", "cors", .82),
    ("OWASP ZAP", "session", .90), ("Nikto", "session", .79),
    ("OWASP ZAP", "cache", .86), ("Nikto", "framing", .75),
    ("Nikto", "banner", .73), ("Nuclei", "component", .68),
    ("Nikto", "index", .52),
]


def in_path(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def normalize(scanner, fields):
    if scanner == "OWASP ZAP":
        return fields["alert"], fields["uri"], "CWE-" + fields["cweid"], fields["confidence"]
    if scanner == "Nikto":
        return fields["msg"], fields["url"], fields["classification"], fields["certainty"]
    return fields["name"], fields["matched-at"], fields["cwe-id"], fields["confidence"]


def evidence_for(asset, scanners, criticality, profile, scope):
    target = TARGETS[asset]
    cases = {case[0]: case for case in CASES}
    raw, normalized, deduplicated = [], [], {}
    for scanner, key, confidence in ALERTS:
        if scanner not in scanners or (profile == "Headers only" and key not in {"cors", "session", "cache", "framing", "banner"}):
            continue
        _, title, suffix, parameter, cwe, cvss, exploit, impact, gamma, verification, evidence, remediation = cases[key]
        endpoint = target["path"] + suffix
        if not in_path(endpoint, scope):
            continue
        fields = {
            "OWASP ZAP": {"alert": title, "uri": endpoint, "cweid": cwe.removeprefix("CWE-"), "confidence": confidence},
            "Nikto": {"msg": title, "url": endpoint, "classification": cwe, "certainty": confidence},
            "Nuclei": {"name": title, "matched-at": endpoint, "cwe-id": cwe, "confidence": confidence},
        }[scanner]
        raw.append({"scanner": scanner, "record": fields})
        title, endpoint, cwe, confidence = normalize(scanner, fields)
        observation = {"id": key, "title": title, "endpoint": endpoint, "parameter": parameter, "cwe": cwe,
                       "cve": None, "cvss": cvss, "tool_confidence": confidence, "scanner": scanner,
                       "evidence": evidence, "target": target["host"]}
        normalized.append(observation)
        group = (endpoint, parameter, cwe)
        if group not in deduplicated:
            deduplicated[group] = {**observation, "sources": [], "observations": [], "exploit": exploit,
                                  "asset_criticality": criticality, "impact": impact, "gamma": gamma,
                                  "verification": verification, "remediation": remediation}
        finding = deduplicated[group]
        finding["sources"].append(scanner)
        finding["observations"].append({"scanner": scanner, "confidence": confidence, "summary": evidence})
        if confidence > finding["tool_confidence"]:
            finding.update(scanner=scanner, tool_confidence=confidence)

    findings = []
    for finding in deduplicated.values():
        score = finding["gamma"] * (.40 * finding["cvss"] / 10 + .25 * finding["exploit"]
                                     + .20 * criticality + .15 * finding["impact"])
        band = "Critical" if score >= .75 else "High" if score >= .55 else "Medium" if score >= .35 else "Low"
        findings.append({**finding, "score": round(score, 5), "severity": band,
                         "filtered": finding["verification"] != "Confirmed" and finding["gamma"] < .35})
    return {"raw": raw, "normalized": normalized, "findings": sorted(findings, key=lambda item: -item["score"])}


STAGES = [
    (0,  "Scope validation", "Authorization and requested scope matched."),
    (1,  "Reconnaissance", "Loaded a saved Nmap host and service inventory."),
    (3,  "Scanner replay", "Read recorded observations from selected scanners."),
    (6,  "Normalization", "Mapped scanner-specific fields into the common schema."),
    (7,  "Deduplication", "Grouped by endpoint, parameter, and CWE."),
    (8,  "Verification", "Read recorded evidence review outcomes."),
    (9,  "False-positive filtering", "Applied the paper's 0.35 threshold to recorded probabilities."),
    (10, "Risk ranking", "Calculated the confidence-weighted composite scores."),
    (12, "Report ready", "Stored findings and made the report available."),
]

BENCHMARKS = [
    ["Nikto", 74, 58, .561, .308, .398, 12.7, 1.1],
    ["Nuclei", 96, 24, .800, .400, .533, 8.4, .9],
    ["OWASP ZAP", 148, 71, .676, .617, .645, 41.2, 3.6],
    ["Naive union", 198, 148, .572, .825, .676, 62.3, 4.8],
    ["Manual workflow", None, None, None, None, None, 186.5, 22.4],
    ["Proposed pipeline", 192, 36, .842, .800, .821, 47.9, 4.1],
]

CATEGORIES = [
    ["A01", "Broken access control", 38, 27, 6, 11, .818, .711],
    ["A02", "Cryptographic failures", 22, 18, 3, 4, .857, .818],
    ["A03", "Injection", 61, 55, 9, 6, .859, .902],
    ["A04", "Insecure design", 15, 6, 2, 9, .750, .400],
    ["A05", "Security misconfiguration", 44, 40, 8, 4, .833, .909],
    ["A06", "Vulnerable components", 31, 27, 4, 4, .871, .871],
    ["A07", "Authentication failures", 20, 14, 3, 6, .824, .700],
    ["A09", "Logging and monitoring failures", 9, 5, 1, 4, .833, .556],
]
