# Product Requirements Document (PRD)

## Product Name (Working Title)
**Sentinel-CSRF**

## Document Confidence
High-level architecture: **High confidence**  
Detection feasibility details: **Medium–High confidence** (depends on framework behavior and browser nuances)

---

## 1. Problem Statement

Cross-Site Request Forgery (CSRF) remains widely misunderstood and **poorly detected by automated tools**, especially in:
- Authenticated workflows
- APIs using cookies
- SPAs (React / Vue / Angular)
- Legacy apps using GET for state change

Existing scanners:
- Over-report false positives
- Miss logic-based CSRF
- Fail to validate exploitability

**Goal:** Build a **precision-first CSRF testing tool** that assists VAPT teams by identifying *real, exploitable CSRF*, not theoretical risks.

---

## 2. Target Users

Primary:
- VAPT analysts
- Bug bounty hunters
- AppSec teams

Secondary:
- Security automation engineers
- CI/CD security teams

---

## 3. Scope Definition

### In-Scope
- Web applications (traditional + SPA)
- Cookie-based authentication
- Authenticated APIs

### Explicitly Out-of-Scope (v1)
- Token theft via XSS
- Browser exploit–based SameSite bypasses
- OAuth misbinding

---

## 4. CSRF Types the Tool MUST Detect

### 4.1 Reflected (Classic) CSRF
**Definition:** Immediate cross-origin state-changing request.

**Detection Logic:**
- Identify authenticated requests
- Check absence or weakness of CSRF tokens
- Verify cookies auto-attached cross-origin

**Signals:**
- No CSRF token
- Token static or predictable
- Token not bound to session

**Confidence:** High

---

### 4.2 Stored CSRF
**Definition:** CSRF payload stored server-side and executed when viewed by another user.

**Detection Logic:**
- Identify HTML-capable input sinks
- Check for server-side request execution triggered by render
- Combine with stored HTML detection

**Signals:**
- Stored `<img>`, `<iframe>`, `<form>`
- Backend action executed on render

**Confidence:** Medium (requires context correlation)

---

### 4.3 Login CSRF
**Definition:** Victim is forced to authenticate as attacker.

**Detection Logic:**
- Detect login endpoints
- Check for missing CSRF tokens
- Verify session replacement behavior

**Signals:**
- Session overwritten without user intent
- No origin or token validation

**Confidence:** High

---

### 4.4 GET-based CSRF (State-Changing GET)
**Definition:** Application uses GET for actions.

**Detection Logic:**
- Identify GET endpoints that modify state
- Test via cross-origin embedding vectors

**Signals:**
- GET + cookies + state change

**Confidence:** Very High

---

### 4.5 API CSRF (JSON / REST)
**Definition:** APIs authenticated via cookies without CSRF protection.

**Detection Logic:**
- Detect cookie-auth APIs
- Replay requests cross-origin
- Check CORS + token absence

**Signals:**
- `Content-Type: application/json`
- Cookies accepted
- No CSRF token

**Confidence:** Medium–High

---

### 4.6 CORS-assisted CSRF
**Definition:** Misconfigured CORS enables CSRF.

**Detection Logic:**
- Analyze CORS headers
- Detect `Access-Control-Allow-Credentials: true`
- Validate origin reflection

**Signals:**
- ACAO mirrors arbitrary origin

**Confidence:** High

---

### 4.7 SameSite Misconfiguration CSRF
**Definition:** Cookies usable cross-site due to SameSite weakness.

**Detection Logic:**
- Analyze Set-Cookie attributes
- Simulate cross-site requests

**Signals:**
- `SameSite=None` without Secure
- Missing SameSite

**Confidence:** Medium (browser-dependent)

---

## 5. Core Functional Requirements

### 5.1 Authentication-Aware Crawling
- Tool must support:
  - Cookie import
  - Burp/ZAP session replay
  - Manual login capture

---

### 5.2 State-Changing Request Identification

Heuristics:
- POST / PUT / PATCH / DELETE
- GET requests returning 200 + backend change
- Keywords: `update`, `delete`, `modify`, `add`

---

### 5.3 CSRF Protection Detection Engine

Check for:
- CSRF tokens (header, body)
- Token entropy
- Token rotation
- Token–session binding

---

### 5.4 Origin & Referer Validation

Detect:
- Missing checks
- Regex-only validation
- Partial domain matches

---

### 5.5 Exploitability Verification (CRITICAL)

Tool must **not report CSRF unless at least one is true**:
- Cross-origin request succeeds
- Action executed without user interaction

False positives must be suppressed.

---

## 6. Payload Generation Engine

### 6.1 HTML-based
- `<form>` auto-submit
- `<img>`
- `<iframe>`

### 6.2 JavaScript-based
- `fetch()`
- `XMLHttpRequest`

### 6.3 API-specific
- JSON POST bodies
- Header stripping

---

## 7. Reporting Requirements

Each finding MUST include:

- CSRF Type
- Endpoint
- Method
- Authentication mechanism
- Why CSRF protection failed
- Proof of exploitability
- Severity (contextual)

---

## 8. Severity Classification Logic

| Scenario | Severity |
|--------|----------|
| Account takeover action | High |
| Profile modification | Medium |
| Non-sensitive preference | Low |

---

## 9. False Positive Controls

- Do not flag if:
  - Token present and validated
  - Origin strictly validated
  - SameSite=Strict blocks request

---

## 10. Non-Functional Requirements

- CLI-first (v1)
- JSON + Markdown output
- Burp-compatible evidence
- Deterministic scans

---

## 11. Future Enhancements (v2+)

- Browser-based execution engine
- Headless Chrome verification
- CI/CD plugin
- CSRF regression testing mode

---

## 12. Success Metrics

- False positive rate < 10%
- CSRF findings accepted by clients
- Tool usable in real VAPT timelines

---

## Final Positioning Statement

**Sentinel-CSRF is not a noise generator.**  
It is a verification-driven CSRF exploitation assistant designed for real-world VAPT accuracy.


---

# ADDENDUM — FULL DETAILED PRD (VERIFICATION‑DRIVEN CSRF TOOL)

## 13. Product Philosophy (NON‑NEGOTIABLE)

This tool **does not aim to find all CSRF**.
It aims to find **only CSRF that can be defended in a VAPT report**.

Core principles:
- Prefer **false negatives over false positives**
- Never report without exploit reasoning
- Every finding must answer: *"Why does the browser allow this?"*

---

## 14. Threat Model Assumptions

### Attacker Model
- External attacker
- No XSS on target
- No access to victim cookies
- Can host arbitrary attacker-controlled domain

### Victim Model
- Logged-in user
- Modern browser (Chrome / Firefox latest)

Any CSRF that **requires violating these assumptions is invalid**.

---

## 15. Detailed Detection Pipeline (CORE ENGINE)

### Phase 1 — Authenticated Request Discovery

Inputs:
- Burp/ZAP session export
- Raw cookie file
- Manual login capture

Process:
1. Identify requests that include auth cookies
2. Track session cookie name(s)
3. Detect session rotation events

Output:
- Authenticated request graph

---

### Phase 2 — State‑Change Classification

A request is *candidate CSRF* only if **at least one** is true:
- HTTP verb ≠ GET
- GET request changes observable state
- Response contains success indicator

State verification strategies:
- Diff response bodies
- Replay idempotency checks
- Heuristic keyword detection

---

### Phase 3 — Defense Enumeration

For each candidate request, enumerate:

**Token Analysis**
- Location (body/header)
- Entropy check
- Static vs dynamic
- Session binding

**Header Validation**
- Origin enforcement
- Referer enforcement
- Regex-only checks

**Cookie Constraints**
- SameSite value
- Secure flag
- Path / domain scope

---

### Phase 4 — Browser Feasibility Matrix

For each request, compute feasibility:

| Vector | Allowed? | Reason |
|------|--------|--------|
| `<img>` | Yes/No | GET + cookies |
| `<form>` | Yes/No | POST + SameSite |
| fetch() | Yes/No | CORS |

If **no vector is feasible**, stop processing.

---

### Phase 5 — Cross‑Origin Replay (VERIFICATION)

Steps:
1. Strip CSRF tokens
2. Modify Origin to attacker domain
3. Replay with cookies
4. Observe server behavior

Valid success indicators:
- Backend state changed
- Success response

If server rejects → NOT CSRF.

---

## 16. Finding Classification Logic

### Confirmed CSRF
ALL true:
- Browser allows vector
- Cookies attached
- Server executes action

### Likely CSRF
- Defense missing
- Browser likely allows
- Execution not observable

### Not CSRF
- SameSite blocks
- Origin enforced
- Token validated

---

## 17. Payload Engineering (STRICT)

Payloads must:
- Use minimal HTML
- Avoid JS unless required
- Be browser‑accurate

Example form payload:
```html
<form method="POST" action="/endpoint">
<input type="hidden" name="a" value="1">
</form>
<script>document.forms[0].submit()</script>
```

---

## 18. False Positive Suppression Rules

Auto‑suppress if:
- SameSite=Strict
- Origin strictly validated
- Authorization header required
- Token validated server-side

---

## 19. Analyst Interaction Model

Tool MUST allow:
- Manual confirmation
- Evidence injection
- Finding promotion/demotion

This keeps human control.

---

## 20. Output Specification

### CLI Output
- Summary table
- Risk levels
- Confidence score

### Report Output
- Markdown
- JSON
- Burp-ready text

---

## 21. MVP vs Future Roadmap

### MVP (v1)
- Cookie import
- Reflected CSRF
- GET-based CSRF
- Login CSRF

### v2
- Headless browser
- Stored CSRF heuristics

### v3
- CI/CD mode
- Regression CSRF testing

---

## 22. Non‑Goals (IMPORTANT)

This tool will NOT:
- Replace manual testing
- Claim browser exploits
- Detect logic abuse CSRF fully

---

## 23. Success Definition

The tool is successful if:
- Findings are accepted by clients
- Analysts trust suppression logic
- Noise is demonstrably lower than Burp/ZAP

---

## FINAL STATEMENT

This is **not a scanner**.
This is a **CSRF exploit verification framework**.

If built as specified, it will be respected by real VAPT teams.

