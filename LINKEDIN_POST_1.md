# LinkedIn Post - Part 1: Introduction

---

## POST COPY (Ready to paste)

---

🔒 **I Built a CSRF Scanner That Doesn't Lie**

Tired of CSRF scanners that flood your reports with false positives?

I built **Sentinel-CSRF** - a verification-driven CSRF exploitation assistant that reports only what it can PROVE exploitable.

**The Problem:**
Traditional scanners flag "missing CSRF token" without checking:
❌ SameSite cookies blocking attacks
❌ Origin/Referer validation
❌ Browser security features

Result? 50%+ false positive rate.

**My Solution - 5-Phase Detection:**
✅ State-change analysis
✅ Token strength measurement
✅ SameSite cookie analysis
✅ Header validation checks
✅ Browser feasibility matrix

**Only reports what browsers can actually exploit.**

**Simple Commands:**

```
sentinel-csrf scan -R -C          # Scan with STDIN
sentinel-csrf poc generate -R -o poc.html
sentinel-csrf scan -L              # Reuse last
```

📦 **Install now:**

```
pip install sentinel-csrf
```

🔗 **Links:**

- GitHub: github.com/NI54NTH/sentinel-csrf
- PyPI: pypi.org/project/sentinel-csrf/

This is Part 1 of my tool development series.
Next: The detection pipeline explained.

# CyberSecurity #BugBounty #Python #VAPT #OpenSource #Pentesting #AppSec #SecurityTools

---

## HASHTAGS (copy separately if needed)

# CyberSecurity #BugBounty #Python #VAPT #OpenSource #Pentesting #AppSec #SecurityTools #WebSecurity #CSRF #EthicalHacking #InfoSec

---

## EVIDENCE SCREENSHOTS TO CAPTURE

Since image generation is unavailable, take these screenshots yourself:

### Screenshot 1: Tool Banner

Run in terminal:

```bash
sentinel-csrf --help
```

Capture the ASCII banner and help output.

### Screenshot 2: Scan Output

Run:

```bash
sentinel-csrf scan -R -C
# Paste a sample request and cookies
```

Capture the scan results showing findings.

### Screenshot 3: PoC Generation

Run:

```bash
sentinel-csrf poc generate -R -o poc.html -v form_post
```

Capture the PoC generation output.

### Screenshot 4: PyPI Page

Visit: <https://pypi.org/project/sentinel-csrf/>
Capture the package page.

### Screenshot 5: GitHub Repo

Visit: <https://github.com/NI54NTH/sentinel-csrf>
Capture the README with banner.

---

## COVER IMAGE SUGGESTION

Create a simple cover in Canva:

- Dark background (black/navy)
- "SENTINEL-CSRF" in large bold text
- Subtitle: "CSRF Exploit Verification Tool"
- Add shield icon or lock icon
- Your name: "by N15H"

---
