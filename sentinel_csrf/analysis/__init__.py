"""
Security analysis modules for CSRF detection.

Provides:
- State-change classification
- CSRF token analysis
- SameSite cookie analysis
- Origin/Referer header validation
- Browser feasibility matrix
"""

from sentinel_csrf.analysis.state_change import (
    StateChangeConfidence,
    StateChangeAnalysis,
    StateChangeClassifier,
    classify_state_change,
    is_csrf_candidate,
)

from sentinel_csrf.analysis.tokens import (
    TokenLocation,
    TokenStrength,
    TokenCandidate,
    TokenAnalysis,
    TokenAnalyzer,
    analyze_tokens,
    has_csrf_protection,
    calculate_shannon_entropy,
)

from sentinel_csrf.analysis.samesite import (
    SameSiteValue,
    CsrfImpact,
    SameSiteAnalysis,
    SessionSameSiteAnalysis,
    SameSiteAnalyzer,
    analyze_samesite,
    is_samesite_protected,
)

from sentinel_csrf.analysis.headers import (
    ValidationStatus,
    HeaderValidationAnalysis,
    HeaderValidationAnalyzer,
    analyze_header_validation,
    get_bypass_techniques,
)

from sentinel_csrf.analysis.browser import (
    AttackVector,
    Feasibility,
    VectorAnalysis,
    BrowserFeasibilityMatrix,
    BrowserFeasibilityAnalyzer,
    analyze_browser_feasibility,
    get_best_attack_vector,
)

__all__ = [
    # State change
    "StateChangeConfidence",
    "StateChangeAnalysis",
    "StateChangeClassifier",
    "classify_state_change",
    "is_csrf_candidate",
    # Tokens
    "TokenLocation",
    "TokenStrength",
    "TokenCandidate",
    "TokenAnalysis",
    "TokenAnalyzer",
    "analyze_tokens",
    "has_csrf_protection",
    "calculate_shannon_entropy",
    # SameSite
    "SameSiteValue",
    "CsrfImpact",
    "SameSiteAnalysis",
    "SessionSameSiteAnalysis",
    "SameSiteAnalyzer",
    "analyze_samesite",
    "is_samesite_protected",
    # Headers
    "ValidationStatus",
    "HeaderValidationAnalysis",
    "HeaderValidationAnalyzer",
    "analyze_header_validation",
    "get_bypass_techniques",
    # Browser
    "AttackVector",
    "Feasibility",
    "VectorAnalysis",
    "BrowserFeasibilityMatrix",
    "BrowserFeasibilityAnalyzer",
    "analyze_browser_feasibility",
    "get_best_attack_vector",
]
