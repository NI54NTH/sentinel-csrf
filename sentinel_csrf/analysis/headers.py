"""
Origin and Referer header validation analysis for CSRF detection.

Analyzes whether the server validates Origin/Referer headers,
which is a common CSRF defense mechanism.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import re

from sentinel_csrf.input.requests import HttpRequest


class ValidationStatus(Enum):
    """Status of Origin/Referer validation."""
    ENFORCED = "enforced"           # Server validates headers
    NOT_ENFORCED = "not_enforced"   # Server doesn't validate
    BYPASSABLE = "bypassable"       # Validation exists but can be bypassed
    UNKNOWN = "unknown"             # Cannot determine


@dataclass
class HeaderValidationAnalysis:
    """Analysis of Origin/Referer header validation."""
    
    has_origin: bool
    has_referer: bool
    origin_value: Optional[str]
    referer_value: Optional[str]
    
    # Validation detection
    origin_validated: ValidationStatus
    referer_validated: ValidationStatus
    
    # Bypass possibilities
    bypass_techniques: List[str] = field(default_factory=list)
    
    reasons: List[str] = field(default_factory=list)
    
    @property
    def is_protected(self) -> bool:
        """Whether headers provide CSRF protection."""
        return (
            self.origin_validated == ValidationStatus.ENFORCED or
            self.referer_validated == ValidationStatus.ENFORCED
        )
    
    @property
    def may_be_bypassable(self) -> bool:
        """Whether validation might be bypassable."""
        return (
            self.origin_validated == ValidationStatus.BYPASSABLE or
            self.referer_validated == ValidationStatus.BYPASSABLE or
            len(self.bypass_techniques) > 0
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "has_origin": self.has_origin,
            "has_referer": self.has_referer,
            "origin_value": self.origin_value,
            "referer_value": self.referer_value,
            "origin_validated": self.origin_validated.value,
            "referer_validated": self.referer_validated.value,
            "is_protected": self.is_protected,
            "may_be_bypassable": self.may_be_bypassable,
            "bypass_techniques": self.bypass_techniques,
            "reasons": self.reasons,
        }


# Common weak Referer validation patterns (regex-based)
WEAK_REFERER_PATTERNS = [
    # Just checking if contains domain (vulnerable to subdomain tricks)
    r'example\.com',  # Matches 'attacker-example.com'
    # Just checking start (vulnerable to prefix tricks)
    r'^https?://example\.com',  # Might miss https://example.com.attacker.com
]

# Techniques to bypass weak Origin/Referer validation
BYPASS_TECHNIQUES = {
    "null_origin": "Set Origin: null (via sandboxed iframe or file://)",
    "missing_referer": "Remove Referer header (Referrer-Policy: no-referrer)",
    "data_uri": "Use data: URI to set null origin",
    "subdomain_prefix": "Use attacker-example.com (if only contains check)",
    "path_injection": "Use example.com.attacker.com (if weak regex)",
    "https_downgrade": "Test HTTP if HTTPS not enforced",
}


class HeaderValidationAnalyzer:
    """Analyzes Origin and Referer header validation for CSRF protection."""
    
    @classmethod
    def analyze(cls, request: HttpRequest) -> HeaderValidationAnalysis:
        """
        Analyze Origin and Referer headers in a request.
        
        Note: This is a static analysis based on the request.
        Full validation testing requires active verification.
        """
        # Extract headers
        origin = cls._get_header(request, "Origin")
        referer = cls._get_header(request, "Referer")
        
        reasons = []
        bypass_techniques = []
        
        # Analyze Origin header
        has_origin = origin is not None
        origin_status = ValidationStatus.UNKNOWN
        
        if has_origin:
            reasons.append(f"Origin header present: {origin}")
            # We can't know if validated without testing
            origin_status = ValidationStatus.UNKNOWN
        else:
            reasons.append("Origin header not present in request")
            bypass_techniques.append("null_origin")
        
        # Analyze Referer header
        has_referer = referer is not None
        referer_status = ValidationStatus.UNKNOWN
        
        if has_referer:
            reasons.append(f"Referer header present: {referer}")
            referer_status = ValidationStatus.UNKNOWN
        else:
            reasons.append("Referer header not present in request")
            bypass_techniques.append("missing_referer")
        
        # Add potential bypass techniques
        if not has_origin and not has_referer:
            reasons.append("Neither Origin nor Referer present - validation cannot be enforced")
            bypass_techniques.extend(["data_uri"])
        
        return HeaderValidationAnalysis(
            has_origin=has_origin,
            has_referer=has_referer,
            origin_value=origin,
            referer_value=referer,
            origin_validated=origin_status,
            referer_validated=referer_status,
            bypass_techniques=bypass_techniques,
            reasons=reasons,
        )
    
    @classmethod
    def analyze_for_bypass(
        cls, 
        request: HttpRequest,
        target_origin: str
    ) -> Tuple[bool, List[str]]:
        """
        Analyze potential bypass techniques for a specific target.
        
        Returns (may_be_bypassable, list of techniques to try).
        """
        techniques = []
        
        # Always try null origin via sandbox
        techniques.append("null_origin")
        
        # Check if Origin/Referer exist
        origin = cls._get_header(request, "Origin")
        referer = cls._get_header(request, "Referer")
        
        if not origin:
            techniques.append("missing_origin")
        
        if not referer:
            techniques.append("missing_referer")
        
        # Parse target to check for subdomain/path tricks
        parsed = urlparse(target_origin)
        target_host = parsed.netloc or parsed.path
        
        # Check for weak domain matching
        if target_host:
            # Suggest subdomain prefix attack
            techniques.append("subdomain_prefix")
            # Suggest path injection
            techniques.append("path_injection")
        
        return len(techniques) > 0, techniques
    
    @classmethod
    def _get_header(cls, request: HttpRequest, name: str) -> Optional[str]:
        """Get header value (case-insensitive)."""
        # Try exact match first
        if name in request.headers:
            return request.headers[name]
        
        # Try case-insensitive
        for key, value in request.headers.items():
            if key.lower() == name.lower():
                return value
        
        return None
    
    @classmethod
    def generate_bypass_payloads(cls, target_url: str) -> Dict[str, str]:
        """
        Generate payloads for testing Origin/Referer bypass.
        
        Returns dict of technique -> payload/instruction.
        """
        parsed = urlparse(target_url)
        target_host = parsed.netloc
        
        return {
            "null_origin": '<iframe sandbox="allow-scripts allow-forms" src="data:text/html,...">',
            "missing_referer": '<meta name="referrer" content="no-referrer">',
            "data_uri": 'data:text/html,<form action="TARGET">...</form>',
            "subdomain_prefix": f"Use host: attacker-{target_host}",
            "path_injection": f"Use host: {target_host}.attacker.com",
        }


def analyze_header_validation(request: HttpRequest) -> HeaderValidationAnalysis:
    """
    Convenience function to analyze header validation.
    
    This is the main entry point for header analysis.
    """
    return HeaderValidationAnalyzer.analyze(request)


def get_bypass_techniques(request: HttpRequest, target: str) -> List[str]:
    """
    Get list of techniques to try for bypassing validation.
    """
    _, techniques = HeaderValidationAnalyzer.analyze_for_bypass(request, target)
    return techniques
