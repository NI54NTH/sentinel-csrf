"""
Browser feasibility matrix for CSRF attack vectors.

Determines which CSRF attack vectors are feasible based on
request characteristics and browser behavior.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from sentinel_csrf.input.requests import HttpRequest
from sentinel_csrf.input.cookies import Cookie
from sentinel_csrf.analysis.samesite import (
    SameSiteValue,
    CsrfImpact,
    analyze_samesite,
)


class AttackVector(Enum):
    """CSRF attack vector types."""
    FORM_POST = "form_post"           # <form method="POST" action="...">
    FORM_GET = "form_get"             # <form method="GET" action="...">
    IMG_TAG = "img_tag"               # <img src="...">
    IFRAME = "iframe"                 # <iframe src="...">
    LINK_CLICK = "link_click"         # <a href="..."> (requires user interaction)
    FETCH_SIMPLE = "fetch_simple"     # fetch() without preflight
    FETCH_CORS = "fetch_cors"         # fetch() with CORS preflight
    XHR_SIMPLE = "xhr_simple"         # XMLHttpRequest without preflight
    XHR_CORS = "xhr_cors"             # XMLHttpRequest with CORS


class Feasibility(Enum):
    """Feasibility level for an attack vector."""
    FEASIBLE = "feasible"             # Attack will work
    CONDITIONAL = "conditional"        # Works under certain conditions
    BLOCKED = "blocked"               # Attack will not work
    REQUIRES_INTERACTION = "requires_interaction"  # Needs user action


@dataclass
class VectorAnalysis:
    """Analysis of a single attack vector."""
    
    vector: AttackVector
    feasibility: Feasibility
    blocked_by: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "vector": self.vector.value,
            "feasibility": self.feasibility.value,
            "blocked_by": self.blocked_by,
            "requirements": self.requirements,
            "notes": self.notes,
        }


@dataclass
class BrowserFeasibilityMatrix:
    """Complete feasibility analysis for all attack vectors."""
    
    method: str
    content_type: str
    has_cookies: bool
    
    vector_analyses: Dict[AttackVector, VectorAnalysis] = field(default_factory=dict)
    
    feasible_vectors: List[AttackVector] = field(default_factory=list)
    blocked_vectors: List[AttackVector] = field(default_factory=list)
    conditional_vectors: List[AttackVector] = field(default_factory=list)
    
    best_vector: Optional[AttackVector] = None
    overall_feasibility: Feasibility = Feasibility.BLOCKED
    
    reasons: List[str] = field(default_factory=list)
    
    @property
    def is_exploitable(self) -> bool:
        """Whether any attack vector is feasible."""
        return len(self.feasible_vectors) > 0 or len(self.conditional_vectors) > 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "method": self.method,
            "content_type": self.content_type,
            "has_cookies": self.has_cookies,
            "is_exploitable": self.is_exploitable,
            "overall_feasibility": self.overall_feasibility.value,
            "best_vector": self.best_vector.value if self.best_vector else None,
            "feasible_vectors": [v.value for v in self.feasible_vectors],
            "blocked_vectors": [v.value for v in self.blocked_vectors],
            "conditional_vectors": [v.value for v in self.conditional_vectors],
            "vector_analyses": {k.value: v.to_dict() for k, v in self.vector_analyses.items()},
            "reasons": self.reasons,
        }


# Content types that allow simple requests (no preflight)
SIMPLE_CONTENT_TYPES = {
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
}

# Methods that are "simple" (no preflight required)
SIMPLE_METHODS = {"GET", "HEAD", "POST"}

# Vector priority for selecting "best" (most reliable) vector
VECTOR_PRIORITY = [
    AttackVector.FORM_POST,       # Most common, reliable
    AttackVector.FORM_GET,        # Simpler, works for GET
    AttackVector.IMG_TAG,         # Silent, no user interaction
    AttackVector.IFRAME,          # Can be hidden
    AttackVector.LINK_CLICK,      # Requires interaction
    AttackVector.FETCH_SIMPLE,    # JS required
    AttackVector.XHR_SIMPLE,      # JS required
]


class BrowserFeasibilityAnalyzer:
    """Analyzes which CSRF attack vectors work for a given request."""
    
    @classmethod
    def analyze(
        cls,
        request: HttpRequest,
        cookies: Optional[List[Cookie]] = None,
    ) -> BrowserFeasibilityMatrix:
        """
        Analyze all attack vectors for feasibility.
        
        Takes into account:
        - HTTP method
        - Content-Type
        - Cookie SameSite attributes
        - Browser CORS behavior
        """
        method = request.method.upper()
        content_type = request.content_type.lower()
        has_cookies = bool(request.cookies)
        
        # Analyze SameSite if cookies provided
        samesite_blocked: Set[str] = set()
        if cookies:
            samesite_analysis = analyze_samesite(cookies)
            samesite_blocked = set(samesite_analysis.blocked_vectors)
        
        # Analyze each vector
        analyses: Dict[AttackVector, VectorAnalysis] = {}
        
        analyses[AttackVector.FORM_POST] = cls._analyze_form_post(
            method, content_type, samesite_blocked
        )
        analyses[AttackVector.FORM_GET] = cls._analyze_form_get(
            method, samesite_blocked
        )
        analyses[AttackVector.IMG_TAG] = cls._analyze_img_tag(
            method, samesite_blocked
        )
        analyses[AttackVector.IFRAME] = cls._analyze_iframe(
            method, samesite_blocked
        )
        analyses[AttackVector.LINK_CLICK] = cls._analyze_link_click(
            method, samesite_blocked
        )
        analyses[AttackVector.FETCH_SIMPLE] = cls._analyze_fetch_simple(
            method, content_type, samesite_blocked
        )
        analyses[AttackVector.FETCH_CORS] = cls._analyze_fetch_cors(
            method, content_type
        )
        
        # Categorize vectors
        feasible = []
        blocked = []
        conditional = []
        
        for vector, analysis in analyses.items():
            if analysis.feasibility == Feasibility.FEASIBLE:
                feasible.append(vector)
            elif analysis.feasibility == Feasibility.CONDITIONAL:
                conditional.append(vector)
            elif analysis.feasibility == Feasibility.REQUIRES_INTERACTION:
                conditional.append(vector)
            else:
                blocked.append(vector)
        
        # Determine best vector
        best = cls._select_best_vector(feasible, conditional)
        
        # Overall feasibility
        if feasible:
            overall = Feasibility.FEASIBLE
        elif conditional:
            overall = Feasibility.CONDITIONAL
        else:
            overall = Feasibility.BLOCKED
        
        # Build reasons
        reasons = cls._build_reasons(method, content_type, feasible, blocked)
        
        return BrowserFeasibilityMatrix(
            method=method,
            content_type=content_type,
            has_cookies=has_cookies,
            vector_analyses=analyses,
            feasible_vectors=feasible,
            blocked_vectors=blocked,
            conditional_vectors=conditional,
            best_vector=best,
            overall_feasibility=overall,
            reasons=reasons,
        )
    
    @classmethod
    def _analyze_form_post(
        cls,
        method: str,
        content_type: str,
        samesite_blocked: Set[str]
    ) -> VectorAnalysis:
        """Analyze <form method="POST"> vector."""
        blocked_by = []
        requirements = []
        
        # Check method
        if method != "POST":
            return VectorAnalysis(
                vector=AttackVector.FORM_POST,
                feasibility=Feasibility.BLOCKED,
                blocked_by=["Request method is not POST"],
            )
        
        # Check SameSite
        if "form_post" in samesite_blocked:
            blocked_by.append("SameSite cookie attribute")
        
        # Check content type (forms can only send specific types)
        form_compatible = any(
            ct in content_type for ct in SIMPLE_CONTENT_TYPES
        )
        if not form_compatible and content_type:
            # JSON content type requires fetch/XHR with preflight
            blocked_by.append(f"Content-Type '{content_type}' not submittable via form")
        
        if blocked_by:
            return VectorAnalysis(
                vector=AttackVector.FORM_POST,
                feasibility=Feasibility.BLOCKED,
                blocked_by=blocked_by,
            )
        
        return VectorAnalysis(
            vector=AttackVector.FORM_POST,
            feasibility=Feasibility.FEASIBLE,
            notes="Auto-submitting form can execute CSRF",
        )
    
    @classmethod
    def _analyze_form_get(cls, method: str, samesite_blocked: Set[str]) -> VectorAnalysis:
        """Analyze <form method="GET"> vector."""
        blocked_by = []
        
        if method != "GET":
            return VectorAnalysis(
                vector=AttackVector.FORM_GET,
                feasibility=Feasibility.BLOCKED,
                blocked_by=["Request method is not GET"],
            )
        
        if "form_get" in samesite_blocked:
            blocked_by.append("SameSite cookie attribute")
        
        if blocked_by:
            return VectorAnalysis(
                vector=AttackVector.FORM_GET,
                feasibility=Feasibility.BLOCKED,
                blocked_by=blocked_by,
            )
        
        return VectorAnalysis(
            vector=AttackVector.FORM_GET,
            feasibility=Feasibility.FEASIBLE,
            notes="GET form submission or link navigation",
        )
    
    @classmethod
    def _analyze_img_tag(cls, method: str, samesite_blocked: Set[str]) -> VectorAnalysis:
        """Analyze <img src="..."> vector."""
        blocked_by = []
        
        if method != "GET":
            return VectorAnalysis(
                vector=AttackVector.IMG_TAG,
                feasibility=Feasibility.BLOCKED,
                blocked_by=["Request method is not GET"],
            )
        
        if "img_get" in samesite_blocked:
            blocked_by.append("SameSite cookie attribute (subresource)")
        
        if blocked_by:
            return VectorAnalysis(
                vector=AttackVector.IMG_TAG,
                feasibility=Feasibility.BLOCKED,
                blocked_by=blocked_by,
            )
        
        return VectorAnalysis(
            vector=AttackVector.IMG_TAG,
            feasibility=Feasibility.FEASIBLE,
            notes="Silent execution via image tag",
        )
    
    @classmethod
    def _analyze_iframe(cls, method: str, samesite_blocked: Set[str]) -> VectorAnalysis:
        """Analyze <iframe src="..."> vector."""
        blocked_by = []
        
        if method != "GET":
            return VectorAnalysis(
                vector=AttackVector.IFRAME,
                feasibility=Feasibility.BLOCKED,
                blocked_by=["Request method is not GET"],
            )
        
        if "iframe_get" in samesite_blocked:
            blocked_by.append("SameSite cookie attribute (iframe)")
        
        if blocked_by:
            return VectorAnalysis(
                vector=AttackVector.IFRAME,
                feasibility=Feasibility.BLOCKED,
                blocked_by=blocked_by,
            )
        
        return VectorAnalysis(
            vector=AttackVector.IFRAME,
            feasibility=Feasibility.FEASIBLE,
            notes="Hidden iframe execution",
            requirements=["X-Frame-Options must allow embedding"],
        )
    
    @classmethod
    def _analyze_link_click(cls, method: str, samesite_blocked: Set[str]) -> VectorAnalysis:
        """Analyze link click navigation vector."""
        blocked_by = []
        
        if method != "GET":
            return VectorAnalysis(
                vector=AttackVector.LINK_CLICK,
                feasibility=Feasibility.BLOCKED,
                blocked_by=["Request method is not GET"],
            )
        
        if "link_get" in samesite_blocked:
            blocked_by.append("SameSite=Strict blocks top-level navigation")
        
        if blocked_by:
            return VectorAnalysis(
                vector=AttackVector.LINK_CLICK,
                feasibility=Feasibility.BLOCKED,
                blocked_by=blocked_by,
            )
        
        return VectorAnalysis(
            vector=AttackVector.LINK_CLICK,
            feasibility=Feasibility.REQUIRES_INTERACTION,
            notes="Top-level navigation (works with SameSite=Lax)",
            requirements=["User must click link"],
        )
    
    @classmethod
    def _analyze_fetch_simple(
        cls,
        method: str,
        content_type: str,
        samesite_blocked: Set[str]
    ) -> VectorAnalysis:
        """Analyze fetch() without CORS preflight."""
        blocked_by = []
        
        # Simple fetch only works for simple methods
        if method not in SIMPLE_METHODS:
            return VectorAnalysis(
                vector=AttackVector.FETCH_SIMPLE,
                feasibility=Feasibility.BLOCKED,
                blocked_by=[f"Method {method} triggers CORS preflight"],
            )
        
        # Check content type
        is_simple_content = any(ct in content_type for ct in SIMPLE_CONTENT_TYPES) or not content_type
        if not is_simple_content:
            return VectorAnalysis(
                vector=AttackVector.FETCH_SIMPLE,
                feasibility=Feasibility.BLOCKED,
                blocked_by=[f"Content-Type '{content_type}' triggers CORS preflight"],
            )
        
        # Check SameSite
        vector_key = "fetch_post" if method == "POST" else "fetch_get"
        if vector_key in samesite_blocked:
            blocked_by.append("SameSite cookie attribute")
        
        if blocked_by:
            return VectorAnalysis(
                vector=AttackVector.FETCH_SIMPLE,
                feasibility=Feasibility.BLOCKED,
                blocked_by=blocked_by,
            )
        
        return VectorAnalysis(
            vector=AttackVector.FETCH_SIMPLE,
            feasibility=Feasibility.FEASIBLE,
            notes="fetch() with credentials: 'include'",
        )
    
    @classmethod
    def _analyze_fetch_cors(cls, method: str, content_type: str) -> VectorAnalysis:
        """Analyze fetch() with CORS preflight."""
        # CORS preflight is almost always blocked for cross-origin CSRF
        return VectorAnalysis(
            vector=AttackVector.FETCH_CORS,
            feasibility=Feasibility.BLOCKED,
            blocked_by=["CORS preflight requires server permission"],
            notes="Only works if server has permissive CORS policy",
        )
    
    @classmethod
    def _select_best_vector(
        cls,
        feasible: List[AttackVector],
        conditional: List[AttackVector]
    ) -> Optional[AttackVector]:
        """Select the most reliable attack vector."""
        all_candidates = feasible + conditional
        
        if not all_candidates:
            return None
        
        # Return highest priority feasible vector
        for vector in VECTOR_PRIORITY:
            if vector in all_candidates:
                return vector
        
        return all_candidates[0]
    
    @classmethod
    def _build_reasons(
        cls,
        method: str,
        content_type: str,
        feasible: List[AttackVector],
        blocked: List[AttackVector]
    ) -> List[str]:
        """Build explanation reasons."""
        reasons = []
        
        if feasible:
            vectors = ", ".join(v.value for v in feasible)
            reasons.append(f"CSRF possible via: {vectors}")
        else:
            reasons.append("No feasible CSRF vectors found")
        
        if method not in SIMPLE_METHODS:
            reasons.append(f"Method {method} limits attack vectors")
        
        if content_type and not any(ct in content_type for ct in SIMPLE_CONTENT_TYPES):
            reasons.append(f"Content-Type '{content_type}' limits to CORS-based attacks")
        
        return reasons


def analyze_browser_feasibility(
    request: HttpRequest,
    cookies: Optional[List[Cookie]] = None
) -> BrowserFeasibilityMatrix:
    """
    Convenience function to analyze browser feasibility.
    
    This is the main entry point for feasibility analysis.
    """
    return BrowserFeasibilityAnalyzer.analyze(request, cookies)


def get_best_attack_vector(
    request: HttpRequest,
    cookies: Optional[List[Cookie]] = None
) -> Optional[AttackVector]:
    """
    Get the most reliable attack vector for a request.
    
    Returns None if no vector is feasible.
    """
    analysis = analyze_browser_feasibility(request, cookies)
    return analysis.best_vector
