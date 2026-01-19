# LinkedIn Post - "The Personal Utility" Angle

**Headline:** Why I built my own CSRF scanner (despite the trends).

**Hook:** CSRF hasn't disappeared from the OWASP Top 10—it just moved. In 2025, it's now folded under **A01: Broken Access Control**. The risk isn't gone; it's just harder to spot, and for VAPT professionals, investigating false positives is still a major pain.

**The Reality:**
I built **Sentinel-CSRF** purely for my own workflow. I was tired of scanners flagging every "missing token" without checking if the browser's SameSite cookies or header validation would actually block the attack.

I needed a tool that prioritized **verification** over volume. One that answers "Can I actually exploit this?" before I put it in a report.

**What Phase 1 (v1.0.7) Covers:**
 

**What's Next?**
Phase 2 is in development, focusing on complex JSON API and CORS analysis.

**Availability:**
I'm deciding to open-source it in case others face the same fatigue with generic scanner noise.

`pip install sentinel-csrf`

**Repository:**
<https://github.com/NI54NTH/sentinel-csrf>

# AppSec #VAPT #Python #SecurityTools #OffensiveSecurity
