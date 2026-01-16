"""
CSRF token analysis for Sentinel-CSRF.

Detects and analyzes anti-CSRF tokens in HTTP requests to determine
if CSRF protection is present and effective.
"""

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from collections import Counter

from sentinel_csrf.input.requests import HttpRequest


class TokenLocation(Enum):
    """Where a CSRF token was found."""
    HEADER = "header"
    BODY = "body"
    QUERY = "query"
    COOKIE = "cookie"


class TokenStrength(Enum):
    """Strength assessment of a CSRF token."""
    STRONG = "strong"           # High entropy, appears dynamic
    MODERATE = "moderate"       # Reasonable entropy, might be static
    WEAK = "weak"              # Low entropy or short
    MISSING = "missing"         # No token found
    INVALID = "invalid"         # Token format issue


@dataclass
class TokenCandidate:
    """A potential CSRF token found in a request."""
    
    name: str
    value: str
    location: TokenLocation
    entropy: float
    is_high_entropy: bool
    length: int
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "value_preview": self.value[:20] + "..." if len(self.value) > 20 else self.value,
            "location": self.location.value,
            "entropy": round(self.entropy, 2),
            "is_high_entropy": self.is_high_entropy,
            "length": self.length,
        }


@dataclass
class TokenAnalysis:
    """Result of CSRF token analysis."""
    
    has_token: bool
    strength: TokenStrength
    candidates: List[TokenCandidate] = field(default_factory=list)
    best_candidate: Optional[TokenCandidate] = None
    reasons: List[str] = field(default_factory=list)
    
    @property
    def is_protected(self) -> bool:
        """Whether the request appears to have CSRF protection."""
        return self.has_token and self.strength in (TokenStrength.STRONG, TokenStrength.MODERATE)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "has_token": self.has_token,
            "strength": self.strength.value,
            "is_protected": self.is_protected,
            "candidates": [c.to_dict() for c in self.candidates],
            "best_candidate": self.best_candidate.to_dict() if self.best_candidate else None,
            "reasons": self.reasons,
        }


# Common CSRF token field names (case-insensitive patterns)
CSRF_TOKEN_PATTERNS = [
    # Standard CSRF tokens
    r'^csrf[-_]?token$',
    r'^_?csrf$',
    r'^xsrf[-_]?token$',
    r'^_?xsrf$',
    r'^anti[-_]?csrf$',
    r'^csrf[-_]?param$',
    
    # Framework-specific
    r'^authenticity[-_]?token$',  # Rails
    r'^__RequestVerificationToken$',  # ASP.NET
    r'^csrfmiddlewaretoken$',  # Django
    r'^_token$',  # Laravel
    r'^__csrf_magic$',  # PHP CSRF Magic
    r'^form[-_]?token$',
    r'^security[-_]?token$',
    r'^sesskey$',  # Moodle
    r'^seqtoken$',  # Various
    r'^formkey$',  # Various
    r'^form[-_]?key$',  # Various
    r'^request[-_]?token$',  # Various
    
    # Generic patterns
    r'^token$',
    r'^_?nonce$',
    r'^state$',
    r'^verify$',
    r'^validation[-_]?token$',
    r'^hash$',  # Some apps use this
]

# Common CSRF header names
CSRF_HEADER_PATTERNS = [
    r'^x[-_]csrf[-_]token$',
    r'^x[-_]xsrf[-_]token$',
    r'^csrf[-_]token$',
    r'^x[-_]request[-_]token$',
]

# Framework tokens that are trusted regardless of length
# These are validated server-side by known frameworks
TRUSTED_FRAMEWORK_TOKENS = [
    'sesskey',               # Moodle
    'authenticity_token',    # Rails
    '__RequestVerificationToken',  # ASP.NET
    'csrfmiddlewaretoken',   # Django
    '_token',                # Laravel
    '__csrf_magic',          # PHP CSRF Magic
]

# Entropy threshold for "high entropy" classification
HIGH_ENTROPY_THRESHOLD = 3.5
MIN_TOKEN_LENGTH = 16
IDEAL_TOKEN_LENGTH = 32


def calculate_shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Higher entropy indicates more randomness.
    Max entropy for alphanumeric is ~5.95 bits/char.
    """
    if not s:
        return 0.0
    
    # Count character frequencies
    freq = Counter(s)
    length = len(s)
    
    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


class TokenAnalyzer:
    """Analyzes HTTP requests for CSRF tokens."""
    
    @classmethod
    def analyze(cls, request: HttpRequest) -> TokenAnalysis:
        """
        Analyze a request for CSRF tokens.
        
        Checks headers, body parameters, and query parameters.
        """
        candidates = []
        reasons = []
        
        # Check headers
        header_candidates = cls._find_header_tokens(request)
        candidates.extend(header_candidates)
        
        # Check body parameters
        body_candidates = cls._find_body_tokens(request)
        candidates.extend(body_candidates)
        
        # Check query parameters
        query_candidates = cls._find_query_tokens(request)
        candidates.extend(query_candidates)
        
        # Check for token in cookies (anti-pattern but exists)
        cookie_candidates = cls._find_cookie_tokens(request)
        candidates.extend(cookie_candidates)
        
        # Determine if token exists and its strength
        if not candidates:
            return TokenAnalysis(
                has_token=False,
                strength=TokenStrength.MISSING,
                candidates=[],
                best_candidate=None,
                reasons=["No CSRF token found in request"],
            )
        
        # Find the best candidate (highest entropy, preferred locations)
        best = cls._select_best_candidate(candidates)
        
        # Assess token strength
        strength = cls._assess_strength(best)
        
        # Build reasons
        reasons = cls._build_reasons(best, strength, len(candidates))
        
        return TokenAnalysis(
            has_token=True,
            strength=strength,
            candidates=candidates,
            best_candidate=best,
            reasons=reasons,
        )
    
    @classmethod
    def _find_header_tokens(cls, request: HttpRequest) -> List[TokenCandidate]:
        """Find CSRF tokens in request headers."""
        candidates = []
        
        for header_name, header_value in request.headers.items():
            for pattern in CSRF_HEADER_PATTERNS:
                if re.match(pattern, header_name, re.IGNORECASE):
                    entropy = calculate_shannon_entropy(header_value)
                    candidates.append(TokenCandidate(
                        name=header_name,
                        value=header_value,
                        location=TokenLocation.HEADER,
                        entropy=entropy,
                        is_high_entropy=entropy >= HIGH_ENTROPY_THRESHOLD,
                        length=len(header_value),
                    ))
                    break
        
        return candidates
    
    @classmethod
    def _find_body_tokens(cls, request: HttpRequest) -> List[TokenCandidate]:
        """Find CSRF tokens in request body."""
        candidates = []
        params = request.get_body_params()
        
        for param_name, param_value in params.items():
            for pattern in CSRF_TOKEN_PATTERNS:
                if re.match(pattern, param_name, re.IGNORECASE):
                    entropy = calculate_shannon_entropy(param_value)
                    candidates.append(TokenCandidate(
                        name=param_name,
                        value=param_value,
                        location=TokenLocation.BODY,
                        entropy=entropy,
                        is_high_entropy=entropy >= HIGH_ENTROPY_THRESHOLD,
                        length=len(param_value),
                    ))
                    break
        
        return candidates
    
    @classmethod
    def _find_query_tokens(cls, request: HttpRequest) -> List[TokenCandidate]:
        """Find CSRF tokens in query parameters."""
        candidates = []
        params = request.get_query_params()
        
        for param_name, param_values in params.items():
            for pattern in CSRF_TOKEN_PATTERNS:
                if re.match(pattern, param_name, re.IGNORECASE):
                    value = param_values[0] if param_values else ""
                    entropy = calculate_shannon_entropy(value)
                    candidates.append(TokenCandidate(
                        name=param_name,
                        value=value,
                        location=TokenLocation.QUERY,
                        entropy=entropy,
                        is_high_entropy=entropy >= HIGH_ENTROPY_THRESHOLD,
                        length=len(value),
                    ))
                    break
        
        return candidates
    
    @classmethod
    def _find_cookie_tokens(cls, request: HttpRequest) -> List[TokenCandidate]:
        """Find CSRF tokens in cookies (double-submit pattern)."""
        candidates = []
        
        for cookie_name, cookie_value in request.cookies.items():
            # Only check explicitly named CSRF cookies
            if any(re.match(pattern, cookie_name, re.IGNORECASE) 
                   for pattern in CSRF_TOKEN_PATTERNS[:6]):  # Only explicit CSRF patterns
                entropy = calculate_shannon_entropy(cookie_value)
                candidates.append(TokenCandidate(
                    name=cookie_name,
                    value=cookie_value,
                    location=TokenLocation.COOKIE,
                    entropy=entropy,
                    is_high_entropy=entropy >= HIGH_ENTROPY_THRESHOLD,
                    length=len(cookie_value),
                ))
        
        return candidates
    
    @classmethod
    def _select_best_candidate(cls, candidates: List[TokenCandidate]) -> TokenCandidate:
        """Select the best CSRF token candidate."""
        # Prefer: header > body > query > cookie
        # Then by entropy
        location_priority = {
            TokenLocation.HEADER: 3,
            TokenLocation.BODY: 2,
            TokenLocation.QUERY: 1,
            TokenLocation.COOKIE: 0,
        }
        
        return max(candidates, key=lambda c: (
            location_priority.get(c.location, 0),
            c.entropy,
            c.length,
        ))
    
    @classmethod
    def _assess_strength(cls, token: TokenCandidate) -> TokenStrength:
        """Assess the strength of a CSRF token."""
        
        # Trust known framework tokens regardless of length
        token_name_lower = token.name.lower()
        for trusted in TRUSTED_FRAMEWORK_TOKENS:
            if token_name_lower == trusted.lower():
                return TokenStrength.STRONG
        
        # Check length
        if token.length < 8:
            return TokenStrength.WEAK
        
        # Check entropy
        if token.is_high_entropy and token.length >= MIN_TOKEN_LENGTH:
            return TokenStrength.STRONG
        
        if token.entropy >= 2.5 and token.length >= 12:
            return TokenStrength.MODERATE
        
        return TokenStrength.WEAK
    
    @classmethod
    def _build_reasons(
        cls, 
        token: TokenCandidate, 
        strength: TokenStrength,
        total_candidates: int
    ) -> List[str]:
        """Build explanation reasons."""
        reasons = []
        
        reasons.append(f"CSRF token '{token.name}' found in {token.location.value}")
        reasons.append(f"Token length: {token.length} characters")
        reasons.append(f"Token entropy: {token.entropy:.2f} bits/char")
        
        if strength == TokenStrength.STRONG:
            reasons.append("Token appears cryptographically strong")
        elif strength == TokenStrength.MODERATE:
            reasons.append("Token has moderate strength")
        else:
            reasons.append("Token appears weak or predictable")
        
        if total_candidates > 1:
            reasons.append(f"Found {total_candidates} potential token fields")
        
        return reasons


def analyze_tokens(request: HttpRequest) -> TokenAnalysis:
    """
    Convenience function to analyze CSRF tokens in a request.
    
    This is the main entry point for token analysis.
    """
    return TokenAnalyzer.analyze(request)


def has_csrf_protection(request: HttpRequest) -> Tuple[bool, TokenAnalysis]:
    """
    Check if a request has CSRF protection.
    
    Returns (is_protected, analysis) tuple.
    """
    analysis = analyze_tokens(request)
    return analysis.is_protected, analysis
