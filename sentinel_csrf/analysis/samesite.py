"""
SameSite cookie attribute analysis for CSRF detection.

Analyzes cookie SameSite attributes to determine if browser-level
CSRF protection is effective.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from sentinel_csrf.input.cookies import Cookie


class SameSiteValue(Enum):
    """SameSite cookie attribute values."""
    STRICT = "strict"
    LAX = "lax"
    NONE = "none"
    MISSING = "missing"  # Not set (browser defaults apply)


class CsrfImpact(Enum):
    """CSRF impact based on SameSite setting."""
    BLOCKED = "blocked"         # CSRF not possible
    PARTIAL = "partial"         # Only specific vectors work
    VULNERABLE = "vulnerable"   # Full CSRF possible


@dataclass
class SameSiteAnalysis:
    """Analysis of SameSite attributes for CSRF impact."""
    
    cookie_name: str
    samesite_value: SameSiteValue
    csrf_impact: CsrfImpact
    allowed_vectors: List[str]
    blocked_vectors: List[str]
    reason: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "cookie_name": self.cookie_name,
            "samesite_value": self.samesite_value.value,
            "csrf_impact": self.csrf_impact.value,
            "allowed_vectors": self.allowed_vectors,
            "blocked_vectors": self.blocked_vectors,
            "reason": self.reason,
        }


@dataclass
class SessionSameSiteAnalysis:
    """Combined SameSite analysis for all session cookies."""
    
    cookies_analyzed: int
    overall_impact: CsrfImpact
    cookie_analyses: List[SameSiteAnalysis] = field(default_factory=list)
    effective_vectors: List[str] = field(default_factory=list)
    blocked_vectors: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    
    @property
    def is_csrf_possible(self) -> bool:
        """Whether any CSRF vector is effective."""
        return self.overall_impact != CsrfImpact.BLOCKED
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "cookies_analyzed": self.cookies_analyzed,
            "overall_impact": self.overall_impact.value,
            "is_csrf_possible": self.is_csrf_possible,
            "effective_vectors": self.effective_vectors,
            "blocked_vectors": self.blocked_vectors,
            "cookie_analyses": [c.to_dict() for c in self.cookie_analyses],
            "reasons": self.reasons,
        }


# CSRF attack vectors
ALL_VECTORS = [
    "form_post",           # <form method="POST">
    "form_get",            # <form method="GET">
    "img_get",             # <img src="...">
    "iframe_get",          # <iframe src="...">
    "link_get",            # Top-level navigation via link
    "fetch_post",          # fetch() with credentials
    "fetch_get",           # fetch() GET with credentials
    "xhr_post",            # XMLHttpRequest POST
    "xhr_get",             # XMLHttpRequest GET
]

# Vectors blocked by each SameSite value
# Based on browser behavior as of 2024
SAMESITE_BLOCKED_VECTORS: Dict[SameSiteValue, List[str]] = {
    SameSiteValue.STRICT: ALL_VECTORS.copy(),  # Blocks all cross-site
    SameSiteValue.LAX: [
        "form_post",       # POST blocked
        "fetch_post",      # POST blocked
        "fetch_get",       # fetch blocked (not top-level)
        "xhr_post",        # POST blocked
        "xhr_get",         # XHR blocked
        "img_get",         # Subresource blocked
        "iframe_get",      # iframe blocked
    ],
    SameSiteValue.NONE: [],  # Blocks nothing (with Secure flag)
    SameSiteValue.MISSING: [
        # Browser defaults to Lax in modern browsers
        "form_post",
        "fetch_post",
        "fetch_get",
        "xhr_post",
        "xhr_get",
        "img_get",
        "iframe_get",
    ],
}

# Browser default SameSite behavior
BROWSER_DEFAULTS = {
    "chrome": SameSiteValue.LAX,    # Chrome 80+
    "firefox": SameSiteValue.LAX,   # Firefox 69+
    "safari": SameSiteValue.LAX,    # Safari 13+ (stricter than Lax in practice)
    "edge": SameSiteValue.LAX,      # Edge Chromium
}


class SameSiteAnalyzer:
    """Analyzes SameSite cookie attributes for CSRF impact."""
    
    @classmethod
    def analyze_cookie(
        cls, 
        cookie: Cookie,
        browser: str = "chrome"
    ) -> SameSiteAnalysis:
        """
        Analyze a single cookie's SameSite attribute.
        
        Returns analysis of CSRF impact based on browser behavior.
        """
        # Determine SameSite value
        samesite_value = cls._parse_samesite(cookie)
        
        # Get blocked vectors for this SameSite value
        blocked = SAMESITE_BLOCKED_VECTORS.get(samesite_value, [])
        allowed = [v for v in ALL_VECTORS if v not in blocked]
        
        # Determine overall impact
        if not allowed:
            impact = CsrfImpact.BLOCKED
            reason = f"SameSite={samesite_value.value} blocks all cross-site requests"
        elif len(allowed) < len(ALL_VECTORS):
            impact = CsrfImpact.PARTIAL
            reason = f"SameSite={samesite_value.value} allows only: {', '.join(allowed)}"
        else:
            impact = CsrfImpact.VULNERABLE
            reason = f"SameSite={samesite_value.value} allows all cross-site requests"
        
        return SameSiteAnalysis(
            cookie_name=cookie.name,
            samesite_value=samesite_value,
            csrf_impact=impact,
            allowed_vectors=allowed,
            blocked_vectors=blocked,
            reason=reason,
        )
    
    @classmethod
    def analyze_session(
        cls,
        cookies: List[Cookie],
        browser: str = "chrome"
    ) -> SessionSameSiteAnalysis:
        """
        Analyze all session cookies for combined CSRF impact.
        
        CSRF requires ALL authentication cookies to be sent.
        The most restrictive SameSite value determines overall protection.
        """
        if not cookies:
            return SessionSameSiteAnalysis(
                cookies_analyzed=0,
                overall_impact=CsrfImpact.BLOCKED,
                reasons=["No cookies to analyze"],
            )
        
        # Analyze each cookie
        analyses = [cls.analyze_cookie(c, browser) for c in cookies]
        
        # Find vectors that work for ALL cookies (intersection)
        effective_vectors = set(ALL_VECTORS)
        for analysis in analyses:
            effective_vectors &= set(analysis.allowed_vectors)
        effective_vectors = list(effective_vectors)
        
        # Blocked vectors are those not in effective set
        blocked_vectors = [v for v in ALL_VECTORS if v not in effective_vectors]
        
        # Determine overall impact
        if not effective_vectors:
            overall_impact = CsrfImpact.BLOCKED
        elif len(effective_vectors) < len(ALL_VECTORS):
            overall_impact = CsrfImpact.PARTIAL
        else:
            overall_impact = CsrfImpact.VULNERABLE
        
        # Build reasons
        reasons = []
        if overall_impact == CsrfImpact.BLOCKED:
            strictest = max(analyses, key=lambda a: len(a.blocked_vectors))
            reasons.append(f"CSRF blocked by SameSite on '{strictest.cookie_name}'")
        elif overall_impact == CsrfImpact.PARTIAL:
            reasons.append(f"CSRF partially possible via: {', '.join(effective_vectors)}")
        else:
            reasons.append("All CSRF vectors possible (SameSite=None or equivalent)")
        
        return SessionSameSiteAnalysis(
            cookies_analyzed=len(cookies),
            overall_impact=overall_impact,
            cookie_analyses=analyses,
            effective_vectors=effective_vectors,
            blocked_vectors=blocked_vectors,
            reasons=reasons,
        )
    
    @classmethod
    def _parse_samesite(cls, cookie: Cookie) -> SameSiteValue:
        """Parse SameSite value from cookie."""
        if cookie.samesite is None:
            return SameSiteValue.MISSING
        
        value = cookie.samesite.lower()
        
        if value == "strict":
            return SameSiteValue.STRICT
        elif value == "lax":
            return SameSiteValue.LAX
        elif value == "none":
            return SameSiteValue.NONE
        else:
            return SameSiteValue.MISSING


def analyze_samesite(cookies: List[Cookie], browser: str = "chrome") -> SessionSameSiteAnalysis:
    """
    Convenience function to analyze SameSite attributes.
    
    This is the main entry point for SameSite analysis.
    """
    return SameSiteAnalyzer.analyze_session(cookies, browser)


def is_samesite_protected(cookies: List[Cookie]) -> bool:
    """
    Quick check if cookies are protected by SameSite.
    
    Returns True if CSRF is blocked by SameSite attributes.
    """
    analysis = analyze_samesite(cookies)
    return analysis.overall_impact == CsrfImpact.BLOCKED
