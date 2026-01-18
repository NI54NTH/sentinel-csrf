"""
Core CSRF detector module.

Combines all analysis components to produce comprehensive
CSRF vulnerability findings.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
import json
from datetime import datetime, timezone

from sentinel_csrf.input.requests import HttpRequest
from sentinel_csrf.input.cookies import Cookie
from sentinel_csrf.analysis.state_change import (
    StateChangeAnalysis,
    classify_state_change,
)
from sentinel_csrf.analysis.tokens import (
    TokenAnalysis,
    TokenStrength,
    analyze_tokens,
)
from sentinel_csrf.analysis.samesite import (
    SessionSameSiteAnalysis,
    CsrfImpact,
    analyze_samesite,
)
from sentinel_csrf.analysis.headers import (
    HeaderValidationAnalysis,
    analyze_header_validation,
)
from sentinel_csrf.analysis.browser import (
    BrowserFeasibilityMatrix,
    AttackVector,
    Feasibility,
    analyze_browser_feasibility,
)


class Severity(Enum):
    """CVSS-aligned severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    """Confidence in exploitability."""
    CONFIRMED = "confirmed"     # Browser-executable PoC worked
    LIKELY = "likely"           # Strong indicators, not tested
    INFORMATIONAL = "informational"  # Potential issue, blocked or uncertain


class CsrfType(Enum):
    """Type of CSRF vulnerability."""
    FORM_BASED = "form_based"
    GET_BASED = "get_based"
    LOGIN_CSRF = "login_csrf"
    # Future: JSON_API, STORED, etc.


@dataclass
class CsrfFinding:
    """A CSRF vulnerability finding."""
    
    id: str
    csrf_type: CsrfType
    severity: Severity
    confidence: Confidence
    
    # Request details
    endpoint: str
    method: str
    url: str
    
    # Analysis results
    state_change: StateChangeAnalysis
    token_analysis: TokenAnalysis
    samesite_analysis: Optional[SessionSameSiteAnalysis]
    header_analysis: HeaderValidationAnalysis
    browser_feasibility: BrowserFeasibilityMatrix
    
    # Best attack vector
    attack_vector: Optional[AttackVector] = None
    
    # Explanations
    reasons: List[str] = field(default_factory=list)
    recommendation: str = ""
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "csrf_type": self.csrf_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "endpoint": self.endpoint,
            "method": self.method,
            "url": self.url,
            "attack_vector": self.attack_vector.value if self.attack_vector else None,
            "analysis": {
                "state_change": self.state_change.to_dict(),
                "token": self.token_analysis.to_dict(),
                "samesite": self.samesite_analysis.to_dict() if self.samesite_analysis else None,
                "headers": self.header_analysis.to_dict(),
                "browser_feasibility": self.browser_feasibility.to_dict(),
            },
            "reasons": self.reasons,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class DetectionResult:
    """Result of CSRF detection on a request."""
    
    is_vulnerable: bool
    finding: Optional[CsrfFinding] = None
    suppression_reason: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "is_vulnerable": self.is_vulnerable,
            "finding": self.finding.to_dict() if self.finding else None,
            "suppression_reason": self.suppression_reason,
        }


class CsrfDetector:
    """
    Core CSRF detection engine.
    
    Implements the 5-phase detection pipeline from PRD §10.
    """
    
    # Counter for finding IDs
    _finding_counter: int = 0
    
    @classmethod
    def detect(
        cls,
        request: HttpRequest,
        cookies: Optional[List[Cookie]] = None,
    ) -> DetectionResult:
        """
        Analyze a request for CSRF vulnerabilities.
        
        Implements the PRD §10 detection pipeline:
        1. Authenticated request discovery
        2. State-change classification
        3. Defense enumeration
        4. Browser feasibility matrix
        5. (Cross-origin replay - future)
        """
        # Phase 1: Check if authenticated
        if not request.cookies:
            return DetectionResult(
                is_vulnerable=False,
                suppression_reason="Request has no cookies (not authenticated)",
            )
        
        # Phase 2: State-change classification
        state_change = classify_state_change(request)
        if not state_change.is_state_changing:
            return DetectionResult(
                is_vulnerable=False,
                suppression_reason=f"Request not state-changing: {state_change.confidence.value}",
            )
        
        # Phase 3: Defense enumeration
        token_analysis = analyze_tokens(request)
        header_analysis = analyze_header_validation(request)
        samesite_analysis = analyze_samesite(cookies) if cookies else None
        
        # Check for strong CSRF protection
        if token_analysis.strength == TokenStrength.STRONG:
            return DetectionResult(
                is_vulnerable=False,
                suppression_reason=f"Strong CSRF token present: {token_analysis.best_candidate.name if token_analysis.best_candidate else 'unknown'}",
            )
        
        # Check SameSite protection
        if samesite_analysis and samesite_analysis.overall_impact == CsrfImpact.BLOCKED:
            return DetectionResult(
                is_vulnerable=False,
                suppression_reason="SameSite cookie attribute blocks CSRF",
            )
        
        # Phase 4: Browser feasibility
        browser_feasibility = analyze_browser_feasibility(request, cookies)
        if not browser_feasibility.is_exploitable:
            return DetectionResult(
                is_vulnerable=False,
                suppression_reason="No feasible browser attack vectors",
            )
        
        # Vulnerability found - build finding
        finding = cls._build_finding(
            request=request,
            state_change=state_change,
            token_analysis=token_analysis,
            samesite_analysis=samesite_analysis,
            header_analysis=header_analysis,
            browser_feasibility=browser_feasibility,
        )
        
        return DetectionResult(
            is_vulnerable=True,
            finding=finding,
        )
    
    @classmethod
    def _build_finding(
        cls,
        request: HttpRequest,
        state_change: StateChangeAnalysis,
        token_analysis: TokenAnalysis,
        samesite_analysis: Optional[SessionSameSiteAnalysis],
        header_analysis: HeaderValidationAnalysis,
        browser_feasibility: BrowserFeasibilityMatrix,
    ) -> CsrfFinding:
        """Build a CsrfFinding from analysis results."""
        cls._finding_counter += 1
        finding_id = f"CSRF-{cls._finding_counter:03d}"
        
        # Determine CSRF type
        csrf_type = cls._determine_csrf_type(request)
        
        # Determine severity
        severity = cls._determine_severity(request, state_change)
        
        # Determine confidence
        confidence = cls._determine_confidence(
            token_analysis, samesite_analysis, browser_feasibility
        )
        
        # Build reasons
        reasons = cls._build_reasons(
            token_analysis, samesite_analysis, header_analysis, browser_feasibility
        )
        
        # Build recommendation
        recommendation = cls._build_recommendation(token_analysis)
        
        return CsrfFinding(
            id=finding_id,
            csrf_type=csrf_type,
            severity=severity,
            confidence=confidence,
            endpoint=request.path,
            method=request.method,
            url=request.url,
            state_change=state_change,
            token_analysis=token_analysis,
            samesite_analysis=samesite_analysis,
            header_analysis=header_analysis,
            browser_feasibility=browser_feasibility,
            attack_vector=browser_feasibility.best_vector,
            reasons=reasons,
            recommendation=recommendation,
        )
    
    @classmethod
    def _determine_csrf_type(cls, request: HttpRequest) -> CsrfType:
        """Determine the type of CSRF vulnerability."""
        method = request.method.upper()
        path = request.path.lower()
        
        # Check for login CSRF
        if any(kw in path for kw in ["login", "signin", "auth"]):
            return CsrfType.LOGIN_CSRF
        
        # GET-based vs form-based
        if method == "GET":
            return CsrfType.GET_BASED
        
        return CsrfType.FORM_BASED
    
    @classmethod
    def _determine_severity(
        cls,
        request: HttpRequest,
        state_change: StateChangeAnalysis
    ) -> Severity:
        """Determine severity based on action impact."""
        path = request.path.lower()
        body = request.body.lower()
        combined = f"{path} {body}"
        
        # Critical: Account takeover actions
        critical_keywords = ["password", "email", "admin", "delete.*account", "transfer"]
        for kw in critical_keywords:
            if kw in combined:
                return Severity.CRITICAL
        
        # High: Sensitive modifications
        high_keywords = ["payment", "purchase", "role", "permission", "settings"]
        for kw in high_keywords:
            if kw in combined:
                return Severity.HIGH
        
        # Medium: Profile/preference modifications
        medium_keywords = ["update", "modify", "profile", "preference"]
        for kw in medium_keywords:
            if kw in combined:
                return Severity.MEDIUM
        
        # Default based on state change score
        if state_change.total_score >= 15:
            return Severity.HIGH
        elif state_change.total_score >= 10:
            return Severity.MEDIUM
        
        return Severity.LOW
    
    @classmethod
    def _determine_confidence(
        cls,
        token_analysis: TokenAnalysis,
        samesite_analysis: Optional[SessionSameSiteAnalysis],
        browser_feasibility: BrowserFeasibilityMatrix,
    ) -> Confidence:
        """Determine confidence level."""
        # If we have feasible vectors and no token, high confidence
        if not token_analysis.has_token and browser_feasibility.feasible_vectors:
            return Confidence.LIKELY
        
        # Weak token with feasible vectors
        if token_analysis.strength == TokenStrength.WEAK and browser_feasibility.feasible_vectors:
            return Confidence.LIKELY
        
        # Conditional vectors only
        if browser_feasibility.conditional_vectors and not browser_feasibility.feasible_vectors:
            return Confidence.INFORMATIONAL
        
        return Confidence.INFORMATIONAL
    
    @classmethod
    def _build_reasons(
        cls,
        token_analysis: TokenAnalysis,
        samesite_analysis: Optional[SessionSameSiteAnalysis],
        header_analysis: HeaderValidationAnalysis,
        browser_feasibility: BrowserFeasibilityMatrix,
    ) -> List[str]:
        """Build explanation reasons."""
        reasons = []
        
        # Token reasons
        if not token_analysis.has_token:
            reasons.append("No CSRF token found in request")
        elif token_analysis.strength == TokenStrength.WEAK:
            reasons.append(f"CSRF token appears weak (entropy: {token_analysis.best_candidate.entropy:.2f})")
        
        # SameSite reasons
        if samesite_analysis:
            if samesite_analysis.overall_impact == CsrfImpact.VULNERABLE:
                reasons.append("Cookies have SameSite=None or missing attribute")
            elif samesite_analysis.overall_impact == CsrfImpact.PARTIAL:
                reasons.append(f"SameSite allows vectors: {', '.join(samesite_analysis.effective_vectors)}")
        
        # Header reasons
        if not header_analysis.has_origin and not header_analysis.has_referer:
            reasons.append("No Origin/Referer headers for validation")
        
        # Feasibility reasons
        if browser_feasibility.best_vector:
            reasons.append(f"Exploitable via {browser_feasibility.best_vector.value}")
        
        return reasons
    
    @classmethod
    def _build_recommendation(cls, token_analysis: TokenAnalysis) -> str:
        """Build remediation recommendation."""
        if not token_analysis.has_token:
            return "Implement anti-CSRF tokens bound to user session. Use framework-provided CSRF protection (e.g., Django CSRFMiddleware, Rails authenticity_token)."
        
        if token_analysis.strength == TokenStrength.WEAK:
            return "Strengthen CSRF token: use cryptographically random values of at least 32 characters with high entropy."
        
        return "Review CSRF protection implementation. Ensure tokens are validated server-side and bound to user session."


def detect_csrf(
    request: HttpRequest,
    cookies: Optional[List[Cookie]] = None,
) -> DetectionResult:
    """
    Convenience function to detect CSRF vulnerabilities.
    
    This is the main entry point for CSRF detection.
    """
    return CsrfDetector.detect(request, cookies)
