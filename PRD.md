# Sentinel-CSRF: Product Requirements Document

> **A Verification-Driven CSRF Exploitation Assistant for Real-World VAPT**

---

## Document Metadata

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Status | Ready for Vibe Coding |
| Last Updated | 2024-12-20 |
| Confidence | High (Architecture) / Medium-High (Detection Details) |

---

## 1. Executive Summary

**Sentinel-CSRF** is a precision-first CSRF verification tool designed for VAPT teams and bug bounty hunters. Unlike existing scanners that flood reports with false positives, Sentinel-CSRF operates on a **verification-driven model** — it reports only what it can prove.

> [!IMPORTANT]
> This is **NOT a scanner**. This is a **CSRF exploit verification framework**.

### Core Philosophy
- **Prefer false negatives over false positives**
- **Never report without exploit reasoning**
- **Every finding must answer: "Why does the browser allow this?"**

---

## 2. Problem Statement

Cross-Site Request Forgery (CSRF) remains widely misunderstood and poorly detected by automated tools.

### Why Existing Tools Fail

| Tool | Problem |
|------|---------|
| Burp Scanner | Noisy, flags missing tokens without exploitability check |
| OWASP ZAP | Extremely noisy, no browser awareness |
| Nuclei | Template-based, shallow detection |
| Commercial Scanners | Checkbox CSRF, no verification |

### Root Causes of False Positives

1. **CSRF is contextual, not syntactic** — requires all conditions to be true simultaneously
2. **"Missing token ≠ Vulnerability"** — SameSite, Origin validation, Auth headers can protect
3. **Browser-dependent behavior** — same request may work in Chrome but fail in Firefox
4. **Tools don't execute browsers** — they guess instead of verify

### The Only Valid Model

A finding is CSRF **only if proven**:
- Cross-origin request succeeded with cookies attached, AND
- Server executed the action, AND
- Response confirms the change

**If not proven → DO NOT REPORT**

---

## 3. Target Users

### Primary Audience
| User Type | Use Case |
|-----------|----------|
| VAPT Analysts | Authenticated application testing |
| Bug Bounty Hunters | Verified CSRF submissions |
| Enterprise AppSec Teams | Pre-release security validation |

### Secondary Audience
| User Type | Use Case |
|-----------|----------|
| Security Automation Engineers | CI/CD integration (v2+) |
| DevSecOps Teams | Regression CSRF testing (v3+) |

---

## 4. Scope Definition

### v1.0 Scope (MVP)

> [!NOTE]
> v1.0 focuses **exclusively** on high-confidence, form-based and GET-based CSRF vulnerabilities in cookie-authenticated applications.

#### In-Scope
- Traditional web applications
- Single Page Applications (React/Vue/Angular)
- Cookie-based authentication
- Form-based CSRF (POST)
- GET-based state-changing requests
- Login CSRF

#### Explicitly Out-of-Scope (v1.0)
| Exclusion | Reason |
|-----------|--------|
| Token theft via XSS | Different attack class |
| Browser exploit-based SameSite bypasses | Assumes patched browsers |
| OAuth misbinding | Complex, requires dedicated tooling |
| Stored CSRF | Requires context correlation (v2) |
| JSON API CSRF | Requires CORS analysis (v2) |
| HAR file import | Ambiguous browser artifacts |
| JSON cookie schemas | Reduces complexity |

---

## 5. Threat Model

### Attacker Model
- External attacker
- No XSS on target domain
- No access to victim cookies
- Can host arbitrary attacker-controlled domain
- Can lure victim to visit attacker page

### Victim Model
- Authenticated (logged-in) user
- Modern browser (Chrome/Firefox latest stable)
- Standard security settings

> [!CAUTION]
> Any CSRF that **requires violating these assumptions** is invalid and must not be reported.

---

## 6. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL-CSRF                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   INPUT     │    │   CORE      │    │      OUTPUT         │ │
│  │   LAYER     │───▶│   ENGINE    │───▶│      LAYER          │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│        │                  │                      │              │
│        ▼                  ▼                      ▼              │
│  ┌───────────┐    ┌─────────────┐    ┌─────────────────────┐   │
│  │ Cookies   │    │ Detection   │    │ Findings (JSON/MD)  │   │
│  │ (Netscape)│    │ Pipeline    │    │ HTML PoCs           │   │
│  ├───────────┤    ├─────────────┤    │ CLI Summary         │   │
│  │ Requests  │    │ Browser     │    └─────────────────────┘   │
│  │ (Raw HTTP)│    │ Feasibility │                              │
│  ├───────────┤    ├─────────────┤                              │
│  │ Burp XML  │    │ Exploit     │                              │
│  │ (Adapter) │    │ Verification│                              │
│  └───────────┘    └─────────────┘                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Technical Specifications

### 7.1 Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | **Python 3.10+** | Maximum pentest environment compatibility |
| Interface | **CLI-only** | VAPT workflow compatibility, scripting, CI/CD |
| HTTP Library | `requests` / `httpx` | Reliable, well-documented |
| CLI Framework | **`argparse`** | Dependency-free, audit-friendly, transparent |
| Output Formats | JSON, Markdown | Machine + human readable |

### 7.2 Deployment Model

> [!IMPORTANT]
> **Fully local, CLI-only application.** No cloud services. No external dependencies at runtime.

| Requirement | Implementation |
|-------------|----------------|
| Privacy | All data stays on analyst's machine |
| Network | No telemetry, no auto-updates without consent |
| Authentication | Tool never logs in itself |
| Air-gap Compatible | Works in restricted environments |

#### What We NEVER Do
- ❌ Require login
- ❌ Upload cookies to any service
- ❌ Depend on cloud execution
- ❌ Add telemetry by default
- ❌ Auto-update without consent

---

## 8. Input Specifications

### 8.1 Cookie Import

**Primary Format: Netscape Cookie File**

```
# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	0	session_id	abc123
.example.com	TRUE	/	TRUE	0	auth_token	xyz789
```

| Format | Support Level | Notes |
|--------|---------------|-------|
| Netscape (`cookies.txt`) | **Primary** | Canonical format |
| Key-Value (`name=value; name2=value2`) | Adapter | Normalized to Netscape |
| Burp Cookie Jar | Adapter | Normalized to Netscape |
| JSON schemas | ❌ Excluded | v1.0 complexity reduction |

### 8.2 Request Import

**Primary Format: Raw HTTP Request**

```http
POST /api/user/update HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session_id=abc123

email=attacker@evil.com
```

| Format | Support Level | Notes |
|--------|---------------|-------|
| Raw HTTP | **Primary** | Canonical format |
| Burp XML Export | Adapter | Normalized to Raw HTTP |
| HAR files | ❌ Excluded | Browser artifact ambiguity |

### 8.3 Input Handling & Workflow Optimization

> [!NOTE]
> These mechanisms reduce repetitive file handling while preserving explicit analyst control. They do NOT automate authentication, traffic interception, or browser interaction.

#### Standard Input (STDIN) Support

The tool SHALL support reading raw HTTP requests and authentication cookies directly from standard input when enabled via explicit command-line flags:

| Flag | Purpose |
|------|---------|
| `--request-stdin` | Read raw HTTP request from STDIN |
| `--cookies-stdin` | Read cookies from STDIN |

**Behavior:**
- Accept pasted input until end-of-input (Ctrl+D / EOF)
- Function as direct alternative to file-based input
- SHALL NOT alter parsing, validation, or detection logic
- MUST be explicit and user-initiated

```bash
# Paste request directly
sentinel-csrf scan --request-stdin --cookies cookies.txt

# Pipe from clipboard
xclip -o | sentinel-csrf scan --request-stdin --cookies cookies.txt
```

#### Local Input Caching for Reuse

After a successful scan, the tool MAY automatically persist the most recently used request and cookie inputs to a local, tool-specific directory:

| Item | Location |
|------|----------|
| Cache directory | `~/.sentinel-csrf/cache/` |
| Cached request | `~/.sentinel-csrf/cache/last-request.txt` |
| Cached cookies | `~/.sentinel-csrf/cache/last-cookies.txt` |

**Reuse via explicit flag:**

```bash
# Reuse last request and cookies
sentinel-csrf scan --reuse-last

# Reuse only last cookies
sentinel-csrf scan --request new-request.txt --reuse-last-cookies

# Reuse only last request
sentinel-csrf scan --reuse-last-request --cookies cookies.txt
```

**Security Constraints:**
- Cached inputs SHALL be stored locally only
- SHALL NOT be transmitted externally
- SHALL be readable by user for auditability
- Reuse MUST be opt-in (never implicit)

#### Explicit Non-Goals

> [!CAUTION]
> These input conveniences SHALL NOT perform:
> - ❌ Automatic login or session harvesting
> - ❌ Browser cookie extraction
> - ❌ Background traffic capture
> - ❌ Proxy interception
>
> All authentication material SHALL continue to be provided explicitly by the analyst.

---

## 9. CLI Interface Specification

### 9.1 Command Structure

**Verb-based CLI** for extensibility:

```bash
sentinel-csrf <command> [options]
```

### 9.2 Core Commands

#### `scan` — Primary CSRF Analysis

```bash
sentinel-csrf scan \
  --cookies cookies.txt \
  --request request.txt \
  --output-dir ./results \
  --format json,markdown
```

| Option | Required | Description |
|--------|----------|-------------|
| `--cookies` | Yes | Path to Netscape cookie file |
| `--request` | Yes | Path to raw HTTP request file |
| `--output-dir` | No | Directory for results (default: `./csrf-results`) |
| `--format` | No | Output formats: `json`, `markdown`, `html` |
| `--verbose` | No | Detailed logging |
| `--suppress-informational` | No | Hide low-confidence findings |

#### `import` — Format Conversion

```bash
# Convert Burp XML to raw HTTP
sentinel-csrf import burp \
  --input burp-export.xml \
  --output ./requests/

# Convert cookie string to Netscape format
sentinel-csrf import cookies \
  --input "session=abc123; auth=xyz" \
  --output cookies.txt \
  --domain example.com
```

#### `poc` — PoC Management

```bash
# Generate PoC for specific finding
sentinel-csrf poc generate \
  --finding finding-001.json \
  --output poc.html

# Serve PoCs locally (optional)
sentinel-csrf poc serve \
  --dir ./pocs \
  --port 8080
```

#### `version` — Version Information

```bash
sentinel-csrf version
```

---

## 10. Detection Pipeline

### Phase 1: Authenticated Request Discovery

```
INPUT                      PROCESS                    OUTPUT
─────                      ───────                    ──────
Cookies (Netscape)    ──▶  Identify auth cookies  ──▶  Session tracking
Raw HTTP Request      ──▶  Match cookies to request ──▶  Auth request graph
```

**Outputs:**
- List of authentication cookie names
- Authenticated request classification
- Session rotation detection

---

### Phase 2: State-Change Classification

A request is a **CSRF candidate** only if:

| Condition | Check |
|-----------|-------|
| HTTP verb ≠ GET | POST, PUT, PATCH, DELETE |
| OR GET changes state | Response indicates modification |
| Keywords detected | `update`, `delete`, `modify`, `add`, `remove`, `create` |

**State Verification Strategies:**
1. Response body diffing
2. Idempotency replay checks
3. Success indicator heuristics (`"success": true`, `"status": "ok"`)

---

### Phase 3: Defense Enumeration

For each candidate request, analyze:

#### Token Analysis
| Check | Method |
|-------|--------|
| Presence | Header, body, query parameter |
| Entropy | Shannon entropy calculation |
| Static vs Dynamic | Multi-request comparison |
| Session Binding | Token-session correlation |

#### Header Validation
| Check | Method |
|-------|--------|
| Origin enforcement | Modify Origin header, observe rejection |
| Referer enforcement | Remove/modify Referer, observe rejection |
| Regex-only validation | Subdomain/partial match bypass attempts |

#### Cookie Constraints
| Attribute | CSRF Impact |
|-----------|-------------|
| `SameSite=Strict` | **Blocks CSRF** (modern browsers) |
| `SameSite=Lax` | GET/top-level navigation only |
| `SameSite=None` | Full CSRF possible |
| Missing SameSite | Browser default (Lax in Chrome) |

---

### Phase 4: Browser Feasibility Matrix

For each candidate, compute attack vector feasibility:

| Vector | Condition | CSRF Possible? |
|--------|-----------|----------------|
| `<form>` POST | SameSite=None OR (Lax + top-level) | ✅ Yes |
| `<img>` GET | SameSite=None OR Lax | ✅ Yes |
| `<iframe>` | SameSite=None | ✅ Yes |
| `fetch()` | CORS allows + credentials | ⚠️ Depends |

> If **no vector is feasible** → Stop processing, suppress finding.

---

### Phase 5: Cross-Origin Replay (VERIFICATION)

```
STEP 1: Strip CSRF tokens from request
        ↓
STEP 2: Modify Origin header to attacker domain
        ↓
STEP 3: Replay request with cookies attached
        ↓
STEP 4: Observe server response
        ↓
DECISION:
  ├── Server rejects → NOT CSRF
  └── Server accepts + state changes → CONFIRMED CSRF
```

**Valid Success Indicators:**
- Backend state visibly changed
- Success response body (`200 OK` + confirmation)
- Subsequent request shows modified state

---

## 11. CSRF Types Detected (v1.0)

### 11.1 Reflected (Classic) CSRF

**Definition:** Immediate cross-origin state-changing request.

| Detection Signal | Confidence |
|-----------------|------------|
| No CSRF token | Medium |
| Static/predictable token | Medium |
| Token not session-bound | High |
| + Verified exploitation | **Confirmed** |

---

### 11.2 GET-Based CSRF (State-Changing GET)

**Definition:** Application incorrectly uses GET for state modification.

```http
GET /api/delete-account?confirm=true HTTP/1.1
Cookie: session=abc123
```

| Detection Signal | Confidence |
|-----------------|------------|
| GET + cookies + state change | **Very High** |
| Exploitable via `<img>` or link | **Confirmed** |

---

### 11.3 Login CSRF

**Definition:** Victim is forced to authenticate as attacker.

| Detection Signal | Confidence |
|-----------------|------------|
| Login endpoint without CSRF token | Medium |
| Session replacement on POST | High |
| Verified session takeover | **Confirmed** |

---

## 12. Risk Classification Model

### Dual-Axis Classification

| Axis | Purpose | Values |
|------|---------|--------|
| **Severity** | Business impact | Critical, High, Medium, Low |
| **Confidence** | Exploitability certainty | Confirmed, Likely, Informational |

### Severity Levels (CVSS-Aligned)

| Level | Examples |
|-------|----------|
| **Critical** | Account takeover, admin privilege escalation |
| **High** | Email/password change, payment modification |
| **Medium** | Profile modification, preference changes |
| **Low** | Non-sensitive settings, cosmetic changes |

### Confidence Levels

| Level | Criteria |
|-------|----------|
| **Confirmed** | Browser-executable PoC demonstrates successful exploitation |
| **Likely** | Defense missing, browser allows vector, execution not directly observed |
| **Informational** | Potential issue, but exploitation blocked or uncertain |

### Classification Examples

```
┌─────────────────────────────────────────────────────────────────┐
│ EXAMPLE 1: Confirmed High-Severity CSRF                         │
├─────────────────────────────────────────────────────────────────┤
│ Vulnerability: Cross-Site Request Forgery (Form-based)         │
│ Severity: High                                                  │
│ Confidence: Confirmed                                           │
│ Endpoint: POST /api/user/email                                  │
│ Reason: Auto-submitting HTML form successfully changed user    │
│         email address while authenticated.                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ EXAMPLE 2: Informational (Not Exploitable)                      │
├─────────────────────────────────────────────────────────────────┤
│ Vulnerability: Potential CSRF (Not Exploitable)                 │
│ Severity: High (if exploitable)                                 │
│ Confidence: Informational                                       │
│ Endpoint: GET /api/settings/update                              │
│ Reason: Endpoint lacks CSRF token but cookies are SameSite=Lax │
│         and request requires POST (which blocks exploitation).  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 13. Output Specifications

### 13.1 CLI Output

**Summary Table:**
```
╭──────────────────────────────────────────────────────────────────╮
│                    SENTINEL-CSRF SCAN RESULTS                    │
├──────────────────────────────────────────────────────────────────┤
│ Target: example.com                                              │
│ Requests Analyzed: 47                                            │
│ CSRF Candidates: 12                                              │
│ Confirmed Vulnerabilities: 3                                     │
│ Likely Vulnerabilities: 2                                        │
│ Suppressed (Not Exploitable): 7                                  │
╰──────────────────────────────────────────────────────────────────╯

┌────┬────────────────────────┬──────────┬───────────┬────────────┐
│ ID │ Endpoint               │ Severity │ Confidence│ Vector     │
├────┼────────────────────────┼──────────┼───────────┼────────────┤
│ 01 │ POST /api/user/email   │ High     │ Confirmed │ Form POST  │
│ 02 │ GET /api/delete-item   │ Medium   │ Confirmed │ IMG tag    │
│ 03 │ POST /api/password     │ Critical │ Confirmed │ Form POST  │
│ 04 │ POST /api/preferences  │ Low      │ Likely    │ Form POST  │
│ 05 │ POST /api/notification │ Low      │ Likely    │ Form POST  │
└────┴────────────────────────┴──────────┴───────────┴────────────┘
```

### 13.2 JSON Output

```json
{
  "scan_metadata": {
    "tool": "sentinel-csrf",
    "version": "1.0.0",
    "timestamp": "2024-12-20T15:30:00Z",
    "target": "example.com"
  },
  "summary": {
    "requests_analyzed": 47,
    "csrf_candidates": 12,
    "confirmed": 3,
    "likely": 2,
    "suppressed": 7
  },
  "findings": [
    {
      "id": "CSRF-001",
      "type": "form_based",
      "endpoint": "/api/user/email",
      "method": "POST",
      "severity": "high",
      "confidence": "confirmed",
      "attack_vector": "form_post",
      "authentication": {
        "cookie_name": "session_id",
        "samesite": "none"
      },
      "defense_analysis": {
        "csrf_token_present": false,
        "origin_validated": false,
        "referer_validated": false
      },
      "verification": {
        "status": "exploited",
        "state_change_observed": true,
        "poc_generated": true,
        "poc_path": "./pocs/csrf-001.html"
      },
      "recommendation": "Implement anti-CSRF tokens bound to user session"
    }
  ],
  "suppressed": [
    {
      "endpoint": "/api/settings",
      "reason": "SameSite=Strict blocks cross-origin requests"
    }
  ]
}
```

### 13.3 Markdown Report Output

Generated as `report.md` with:
- Executive summary
- Finding details with severity/confidence
- Technical evidence
- Recommendations
- PoC file references

---

## 14. Proof-of-Concept (PoC) Generation

### Requirements

| Requirement | Implementation |
|-------------|----------------|
| Standalone HTML | No external dependencies |
| Browser-executable | Works directly in Chrome/Firefox |
| No server required | Opens via `file://` protocol |
| Self-contained | All logic inline |
| Realistic | Mimics attacker-controlled page |

### PoC Template (Form-Based)

```html
<!DOCTYPE html>
<html>
<head>
  <title>CSRF PoC - Sentinel-CSRF</title>
</head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <p>Target: POST /api/user/email</p>
  <p>This form will auto-submit in 2 seconds...</p>
  
  <form id="csrf-form" method="POST" action="https://example.com/api/user/email">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  
  <script>
    setTimeout(function() {
      document.getElementById('csrf-form').submit();
    }, 2000);
  </script>
</body>
</html>
```

### Optional Local Hosting Mode

```bash
sentinel-csrf poc serve --dir ./pocs --port 8080
```

| Constraint | Implementation |
|------------|----------------|
| Bind address | `127.0.0.1` only |
| Purpose | SameSite=Lax testing (requires HTTP context) |
| Static files only | No modification, no processing |
| NOT required | PoCs work without server |

> [!CAUTION]
> PoC generation **NEVER** depends on cloud services, remote hosting, or data transmission outside the analyst's environment.

---

## 15. False Positive Suppression

### Auto-Suppress Conditions

| Condition | Reason |
|-----------|--------|
| `SameSite=Strict` cookie | Browser blocks cross-origin |
| Origin strictly validated | Server rejects cross-origin |
| `Authorization` header required | Not cookie-based auth |
| CSRF token validated server-side | Protection working |
| Only GET allowed + no state change | Read-only endpoint |

### Suppression in Reports

Suppressed findings are:
- Logged in verbose output
- Included in JSON with `"suppressed": true`
- Excluded from summary counts
- Available for analyst review if needed

---

## 16. Integration Roadmap

### 🟢 Phase 1 — MVP (v1.0)

| Component | Status | Priority |
|-----------|--------|----------|
| Standalone CLI | **Required** | P0 |
| Cookie import (Netscape) | **Required** | P0 |
| Raw HTTP request import | **Required** | P0 |
| Burp XML adapter | **Required** | P0 |
| JSON output | **Required** | P0 |
| Markdown output | **Required** | P0 |
| HTML PoC generation | **Required** | P0 |

### 🟡 Phase 2 — Precision Upgrade (v2.0)

| Component | Status | Priority |
|-----------|--------|----------|
| Headless browser verification | Optional | P1 |
| Stored CSRF heuristics | Optional | P1 |
| JSON API CSRF (CORS analysis) | Optional | P1 |
| Browser extension cookie sync | Optional | P2 |

### 🔵 Phase 3 — Enterprise/CI (v3.0)

| Component | Status | Priority |
|-----------|--------|----------|
| CI/CD mode | Optional | P2 |
| Regression CSRF testing | Optional | P2 |
| API-first mode | Optional | P2 |
| Burp Extension wrapper | Optional | P3 |

---

## 17. Non-Goals (Explicit)

> [!WARNING]
> These are intentional exclusions. Do not implement.

| Non-Goal | Reason |
|----------|--------|
| Web-based UI | Trust issues, cookie security concerns |
| Full automation | CSRF requires human judgment |
| Replace manual testing | Tool assists, not replaces |
| Claim browser exploits | Assumes patched browsers |
| Detect all logic-based CSRF | Requires business context |
| 100% accuracy | Impossible; verification-driven approach instead |

---

## 18. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| False Positive Rate | < 10% | Manual validation sampling |
| Client Acceptance | > 90% | CSRF findings accepted in reports |
| VAPT Integration | Yes | Usable within standard timelines |
| Analyst Trust | High | Suppression logic trusted |
| Noise Reduction | > 70% vs Burp/ZAP | Comparative testing |

---

## 19. Analyst Interaction Model

### Human-in-the-Loop Design

| Capability | Purpose |
|------------|---------|
| Manual confirmation | Analyst validates finding |
| Evidence injection | Add context/screenshots |
| Finding promotion | Upgrade Likely → Confirmed |
| Finding demotion | Downgrade or suppress |
| PoC customization | Modify generated PoCs |

### What Cannot Be Automated (Honest Acknowledgment)

| CSRF Type | Reason |
|-----------|--------|
| Stored CSRF | Requires render context |
| Logic-based CSRF | Business workflow knowledge |
| Multi-step CSRF | Stateful interaction |
| Business workflow abuse | Domain expertise needed |

**Tool response:** Flag candidates, generate PoC, let analyst confirm.

---

## 20. File Structure (Recommended)

```
sentinel-csrf/
├── sentinel_csrf/
│   ├── __init__.py
│   ├── cli.py                 # CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner.py         # Main scanning logic
│   │   ├── detector.py        # CSRF detection engine
│   │   └── verifier.py        # Exploitation verification
│   ├── input/
│   │   ├── __init__.py
│   │   ├── cookies.py         # Cookie parsing (Netscape)
│   │   ├── requests.py        # HTTP request parsing
│   │   └── burp.py            # Burp XML adapter
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── tokens.py          # CSRF token analysis
│   │   ├── samesite.py        # SameSite analysis
│   │   ├── headers.py         # Origin/Referer validation
│   │   └── browser.py         # Browser feasibility matrix
│   ├── output/
│   │   ├── __init__.py
│   │   ├── json_report.py     # JSON output
│   │   ├── markdown_report.py # Markdown output
│   │   └── poc_generator.py   # HTML PoC generation
│   └── utils/
│       ├── __init__.py
│       ├── http.py            # HTTP utilities
│       └── entropy.py         # Entropy calculations
├── tests/
│   ├── __init__.py
│   ├── test_cookies.py
│   ├── test_detector.py
│   └── test_poc.py
├── examples/
│   ├── cookies.txt            # Example Netscape cookies
│   ├── request.txt            # Example raw HTTP request
│   └── burp-export.xml        # Example Burp export
├── requirements.txt
├── setup.py
├── pyproject.toml
└── README.md
```

---

## 21. Development Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Project setup (Python package structure)
- [ ] CLI framework (`click`)
- [ ] Cookie parser (Netscape format)
- [ ] Raw HTTP request parser
- [ ] Basic test suite

### Phase 2: Core Engine (Week 3-4)
- [ ] State-change detection
- [ ] CSRF token analysis
- [ ] SameSite analysis
- [ ] Origin/Referer validation
- [ ] Browser feasibility matrix

### Phase 3: Verification (Week 5-6)
- [ ] Cross-origin replay engine
- [ ] Exploitation verification
- [ ] False positive suppression
- [ ] Finding classification

### Phase 4: Output (Week 7)
- [ ] JSON report generation
- [ ] Markdown report generation
- [ ] HTML PoC generation
- [ ] CLI summary formatting

### Phase 5: Integration (Week 8)
- [ ] Burp XML adapter
- [ ] End-to-end testing
- [ ] Documentation
- [ ] Example workflows

---

## 22. Final Positioning Statement

> **Sentinel-CSRF is NOT a noise generator.**
> 
> It is a verification-driven CSRF exploitation assistant designed for real-world VAPT accuracy. It reports only what it can prove, suppresses what it cannot exploit, and respects the analyst's time and expertise.

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| CSRF | Cross-Site Request Forgery |
| VAPT | Vulnerability Assessment and Penetration Testing |
| SameSite | Cookie attribute controlling cross-site behavior |
| PoC | Proof of Concept |
| State Change | Server-side modification resulting from request |
| Cross-Origin | Request from different domain than target |

---

## Appendix B: Reference Attacks

### B.1 Classic Form CSRF
```html
<form action="https://bank.com/transfer" method="POST">
  <input name="to" value="attacker">
  <input name="amount" value="10000">
</form>
<script>document.forms[0].submit()</script>
```

### B.2 GET-based CSRF (Image Tag)
```html
<img src="https://bank.com/transfer?to=attacker&amount=10000">
```

### B.3 Login CSRF
```html
<form action="https://app.com/login" method="POST">
  <input name="user" value="attacker">
  <input name="pass" value="password123">
</form>
<script>document.forms[0].submit()</script>
```

---

## Appendix C: Browser Compatibility Matrix

| Browser | SameSite Default | CSRF Impact |
|---------|------------------|-------------|
| Chrome 80+ | Lax | Blocks POST CSRF unless SameSite=None |
| Firefox 69+ | Lax | Same as Chrome |
| Safari 13+ | Strict-ish | More restrictive |
| Edge Chromium | Lax | Same as Chrome |

---

*Document prepared for vibe coding implementation. Build exactly as specified.*
