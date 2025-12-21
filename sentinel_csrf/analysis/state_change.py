"""
State-change classification for CSRF detection.

Determines whether an HTTP request is likely to cause state changes
on the server, which is a prerequisite for CSRF exploitability.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple
import re

from sentinel_csrf.input.requests import HttpRequest


class StateChangeConfidence(Enum):
    """Confidence level for state-change classification."""
    CONFIRMED = "confirmed"      # Definitely changes state
    LIKELY = "likely"            # Probably changes state
    UNLIKELY = "unlikely"        # Probably doesn't change state
    SAFE = "safe"               # Definitely doesn't change state


@dataclass
class StateChangeAnalysis:
    """Result of state-change analysis."""
    
    is_state_changing: bool
    confidence: StateChangeConfidence
    reasons: List[str]
    method_score: int       # Score based on HTTP method
    keyword_score: int      # Score based on keywords detected
    content_type_score: int # Score based on content type
    
    @property
    def total_score(self) -> int:
        """Combined score from all factors."""
        return self.method_score + self.keyword_score + self.content_type_score
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "is_state_changing": self.is_state_changing,
            "confidence": self.confidence.value,
            "reasons": self.reasons,
            "scores": {
                "method": self.method_score,
                "keyword": self.keyword_score,
                "content_type": self.content_type_score,
                "total": self.total_score,
            },
        }


# HTTP methods that typically change state
STATE_CHANGING_METHODS = {
    "POST": 10,
    "PUT": 10,
    "PATCH": 10,
    "DELETE": 10,
}

# Methods that are typically safe (read-only)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

# Keywords in URL/body that indicate state changes
STATE_CHANGE_KEYWORDS = [
    # Destructive actions
    (r'\bdelete\b', 8),
    (r'\bremove\b', 8),
    (r'\bdestroy\b', 8),
    (r'\bpurge\b', 7),
    (r'\bclear\b', 6),
    
    # Modification actions
    (r'\bupdate\b', 7),
    (r'\bmodify\b', 7),
    (r'\bedit\b', 6),
    (r'\bchange\b', 6),
    (r'\bset\b', 5),
    (r'\brename\b', 6),
    
    # Creation actions
    (r'\bcreate\b', 7),
    (r'\badd\b', 6),
    (r'\bnew\b', 5),
    (r'\binsert\b', 6),
    (r'\bregister\b', 7),
    (r'\bsignup\b', 7),
    (r'\benroll\b', 6),
    
    # Authentication actions
    (r'\blogin\b', 8),
    (r'\blogout\b', 6),
    (r'\bsignin\b', 8),
    (r'\bsignout\b', 6),
    (r'\bauth\b', 5),
    (r'\bpassword\b', 8),
    (r'\breset\b', 7),
    
    # Financial/sensitive actions
    (r'\btransfer\b', 9),
    (r'\bpayment\b', 9),
    (r'\bpurchase\b', 8),
    (r'\bbuy\b', 7),
    (r'\bcheckout\b', 8),
    (r'\bsubscribe\b', 7),
    (r'\bunsubscribe\b', 6),
    
    # Permission/access actions
    (r'\bgrant\b', 7),
    (r'\brevoke\b', 7),
    (r'\bpermission\b', 6),
    (r'\brole\b', 5),
    (r'\binvite\b', 6),
    
    # Status changes
    (r'\bactivate\b', 6),
    (r'\bdeactivate\b', 6),
    (r'\benable\b', 5),
    (r'\bdisable\b', 5),
    (r'\block\b', 6),
    (r'\bunlock\b', 6),
    (r'\bban\b', 7),
    (r'\bsuspend\b', 7),
    
    # Action verbs
    (r'\bsubmit\b', 6),
    (r'\bsend\b', 5),
    (r'\bpost\b', 4),
    (r'\bconfirm\b', 6),
    (r'\bapprove\b', 7),
    (r'\breject\b', 6),
    (r'\baccept\b', 6),
    (r'\bdecline\b', 6),
]

# Content types that typically contain state-changing requests
STATE_CHANGING_CONTENT_TYPES = {
    "application/x-www-form-urlencoded": 3,
    "multipart/form-data": 3,
    "application/json": 2,
    "text/plain": 1,
}


class StateChangeClassifier:
    """Classifies HTTP requests by their likelihood of changing server state."""
    
    # Thresholds for classification
    CONFIRMED_THRESHOLD = 15
    LIKELY_THRESHOLD = 8
    UNLIKELY_THRESHOLD = 3
    
    @classmethod
    def classify(cls, request: HttpRequest) -> StateChangeAnalysis:
        """
        Analyze an HTTP request for state-changing behavior.
        
        Returns StateChangeAnalysis with confidence level and reasoning.
        """
        reasons = []
        
        # Analyze HTTP method
        method_score = cls._analyze_method(request, reasons)
        
        # Analyze URL and body for keywords
        keyword_score = cls._analyze_keywords(request, reasons)
        
        # Analyze content type
        content_type_score = cls._analyze_content_type(request, reasons)
        
        # Calculate total score
        total_score = method_score + keyword_score + content_type_score
        
        # Determine confidence level
        if total_score >= cls.CONFIRMED_THRESHOLD:
            confidence = StateChangeConfidence.CONFIRMED
            is_state_changing = True
        elif total_score >= cls.LIKELY_THRESHOLD:
            confidence = StateChangeConfidence.LIKELY
            is_state_changing = True
        elif total_score >= cls.UNLIKELY_THRESHOLD:
            confidence = StateChangeConfidence.UNLIKELY
            is_state_changing = False
        else:
            confidence = StateChangeConfidence.SAFE
            is_state_changing = False
        
        return StateChangeAnalysis(
            is_state_changing=is_state_changing,
            confidence=confidence,
            reasons=reasons,
            method_score=method_score,
            keyword_score=keyword_score,
            content_type_score=content_type_score,
        )
    
    @classmethod
    def _analyze_method(cls, request: HttpRequest, reasons: List[str]) -> int:
        """Score based on HTTP method."""
        method = request.method.upper()
        
        if method in STATE_CHANGING_METHODS:
            score = STATE_CHANGING_METHODS[method]
            reasons.append(f"HTTP method {method} typically changes state")
            return score
        
        if method in SAFE_METHODS:
            reasons.append(f"HTTP method {method} is typically safe (read-only)")
            return 0
        
        # Unknown method, slight score
        reasons.append(f"Unknown HTTP method {method}")
        return 2
    
    @classmethod
    def _analyze_keywords(cls, request: HttpRequest, reasons: List[str]) -> int:
        """Score based on state-changing keywords in URL and body."""
        total_score = 0
        found_keywords = []
        
        # Text to analyze: URL path + query + body
        text_to_analyze = f"{request.path} {request.body}".lower()
        
        for pattern, score in STATE_CHANGE_KEYWORDS:
            if re.search(pattern, text_to_analyze, re.IGNORECASE):
                keyword = pattern.replace(r'\b', '').replace('\\b', '')
                found_keywords.append(keyword)
                total_score += score
        
        if found_keywords:
            # Cap keyword score to prevent over-weighting
            capped_score = min(total_score, 15)
            reasons.append(f"State-changing keywords found: {', '.join(found_keywords[:5])}")
            return capped_score
        
        return 0
    
    @classmethod
    def _analyze_content_type(cls, request: HttpRequest, reasons: List[str]) -> int:
        """Score based on Content-Type header."""
        content_type = request.content_type.lower()
        
        for ct, score in STATE_CHANGING_CONTENT_TYPES.items():
            if ct in content_type:
                reasons.append(f"Content-Type '{ct}' often carries state-changing data")
                return score
        
        return 0


def classify_state_change(request: HttpRequest) -> StateChangeAnalysis:
    """
    Convenience function to classify a request's state-changing likelihood.
    
    This is the main entry point for state-change classification.
    """
    return StateChangeClassifier.classify(request)


def is_csrf_candidate(request: HttpRequest) -> Tuple[bool, StateChangeAnalysis]:
    """
    Determine if a request is a candidate for CSRF testing.
    
    Returns (is_candidate, analysis) tuple.
    A request is a CSRF candidate if it:
    - Has authentication cookies, AND
    - Is likely to change server state
    """
    analysis = classify_state_change(request)
    
    # Must have cookies for CSRF
    has_cookies = bool(request.cookies)
    
    # Must be state-changing
    is_candidate = has_cookies and analysis.is_state_changing
    
    return is_candidate, analysis
