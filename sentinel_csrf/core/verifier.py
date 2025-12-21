"""
Cross-origin replay engine for CSRF verification.

Replays HTTP requests with modified headers to verify
if CSRF attacks are actually exploitable.
"""

import requests
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import re

from sentinel_csrf.input.requests import HttpRequest
from sentinel_csrf.input.cookies import Cookie, cookies_to_header


class ReplayResult(Enum):
    """Result of a replay attempt."""
    SUCCESS = "success"           # Request succeeded, action executed
    BLOCKED = "blocked"           # Server blocked the request
    ERROR = "error"               # Network/connection error
    TIMEOUT = "timeout"           # Request timed out
    REDIRECT = "redirect"         # Server redirected (may be login)


@dataclass
class ReplayResponse:
    """Response from a replay attempt."""
    
    result: ReplayResult
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: Optional[str] = None
    
    # Analysis
    appears_successful: bool = False
    state_change_indicators: List[str] = field(default_factory=list)
    rejection_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "result": self.result.value,
            "status_code": self.status_code,
            "appears_successful": self.appears_successful,
            "state_change_indicators": self.state_change_indicators,
            "rejection_indicators": self.rejection_indicators,
            "error": self.error,
        }


# Indicators that suggest the action succeeded
SUCCESS_INDICATORS = [
    r'"success"\s*:\s*true',
    r'"status"\s*:\s*"ok"',
    r'"status"\s*:\s*"success"',
    r'"message"\s*:\s*".*updated',
    r'"message"\s*:\s*".*created',
    r'"message"\s*:\s*".*deleted',
    r'successfully',
    r'has been updated',
    r'has been changed',
    r'has been deleted',
]

# Indicators that the request was rejected
REJECTION_INDICATORS = [
    r'"error"',
    r'"message"\s*:\s*".*forbidden',
    r'"message"\s*:\s*".*denied',
    r'"message"\s*:\s*".*invalid.*token',
    r'"message"\s*:\s*".*csrf',
    r'access denied',
    r'forbidden',
    r'invalid token',
    r'csrf.*invalid',
    r'token.*expired',
    r'authentication required',
]


class CrossOriginReplayer:
    """
    Replays requests with cross-origin modifications to verify CSRF.
    
    This simulates what happens when an attacker page makes
    cross-origin requests to the target application.
    """
    
    # Attacker origin for cross-origin simulation
    ATTACKER_ORIGIN = "https://attacker.evil.com"
    
    # Request timeout
    TIMEOUT = 10
    
    @classmethod
    def replay(
        cls,
        request: HttpRequest,
        cookies: Optional[List[Cookie]] = None,
        strip_csrf_token: bool = True,
        modify_origin: bool = True,
        verify_ssl: bool = True,
    ) -> ReplayResponse:
        """
        Replay a request with cross-origin modifications.
        
        Steps:
        1. Strip CSRF tokens (if enabled)
        2. Modify Origin header to attacker domain
        3. Send request with cookies
        4. Analyze response for success/failure
        """
        try:
            # Build modified request
            url = request.url
            method = request.method.upper()
            headers = cls._build_headers(request, modify_origin)
            body = cls._build_body(request, strip_csrf_token)
            
            # Add cookies
            if cookies:
                cookie_header = cookies_to_header(cookies, url)
                if cookie_header:
                    headers["Cookie"] = cookie_header
            elif request.cookies:
                # Use cookies from original request
                headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in request.cookies.items()
                )
            
            # Make request
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body if method in ("POST", "PUT", "PATCH") else None,
                timeout=cls.TIMEOUT,
                verify=verify_ssl,
                allow_redirects=False,
            )
            
            # Analyze response
            return cls._analyze_response(response)
            
        except requests.Timeout:
            return ReplayResponse(
                result=ReplayResult.TIMEOUT,
                error="Request timed out",
            )
        except requests.RequestException as e:
            return ReplayResponse(
                result=ReplayResult.ERROR,
                error=str(e),
            )
    
    @classmethod
    def _build_headers(
        cls,
        request: HttpRequest,
        modify_origin: bool,
    ) -> Dict[str, str]:
        """Build headers for replay request."""
        headers = {}
        
        # Copy relevant headers
        skip_headers = {
            "host", "content-length", "connection",
            "accept-encoding", "cookie",
        }
        
        for name, value in request.headers.items():
            if name.lower() not in skip_headers:
                headers[name] = value
        
        # Modify Origin if requested
        if modify_origin:
            headers["Origin"] = cls.ATTACKER_ORIGIN
            # Also modify Referer to match
            headers["Referer"] = f"{cls.ATTACKER_ORIGIN}/attack-page.html"
        
        return headers
    
    @classmethod
    def _build_body(
        cls,
        request: HttpRequest,
        strip_csrf_token: bool,
    ) -> str:
        """Build body for replay request, optionally stripping CSRF tokens."""
        body = request.body
        
        if not strip_csrf_token or not body:
            return body
        
        # Common CSRF token parameter names
        csrf_patterns = [
            r'csrf_token=[^&]*&?',
            r'_csrf=[^&]*&?',
            r'csrfmiddlewaretoken=[^&]*&?',
            r'authenticity_token=[^&]*&?',
            r'_token=[^&]*&?',
            r'__RequestVerificationToken=[^&]*&?',
            r'xsrf_token=[^&]*&?',
            r'anti_csrf=[^&]*&?',
        ]
        
        for pattern in csrf_patterns:
            body = re.sub(pattern, '', body, flags=re.IGNORECASE)
        
        # Clean up trailing/leading ampersands
        body = re.sub(r'^&+|&+$', '', body)
        body = re.sub(r'&&+', '&', body)
        
        return body
    
    @classmethod
    def _analyze_response(cls, response: requests.Response) -> ReplayResponse:
        """Analyze response to determine if CSRF was successful."""
        status_code = response.status_code
        body = response.text
        headers = dict(response.headers)
        
        # Check for redirects (often means login required)
        if status_code in (301, 302, 303, 307, 308):
            location = headers.get("Location", "")
            if any(kw in location.lower() for kw in ["login", "signin", "auth"]):
                return ReplayResponse(
                    result=ReplayResult.BLOCKED,
                    status_code=status_code,
                    headers=headers,
                    body=body,
                    rejection_indicators=["Redirected to login"],
                )
            return ReplayResponse(
                result=ReplayResult.REDIRECT,
                status_code=status_code,
                headers=headers,
                body=body,
            )
        
        # Check for explicit errors
        if status_code in (401, 403):
            return ReplayResponse(
                result=ReplayResult.BLOCKED,
                status_code=status_code,
                headers=headers,
                body=body,
                rejection_indicators=[f"HTTP {status_code} response"],
            )
        
        # Analyze body for success/rejection indicators
        success_found = []
        rejection_found = []
        
        for pattern in SUCCESS_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                success_found.append(pattern)
        
        for pattern in REJECTION_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                rejection_found.append(pattern)
        
        # Determine overall result
        if status_code >= 200 and status_code < 300:
            if rejection_found and not success_found:
                result = ReplayResult.BLOCKED
                appears_successful = False
            else:
                result = ReplayResult.SUCCESS
                appears_successful = True
        else:
            result = ReplayResult.BLOCKED
            appears_successful = False
        
        return ReplayResponse(
            result=result,
            status_code=status_code,
            headers=headers,
            body=body[:1000],  # Truncate for storage
            appears_successful=appears_successful,
            state_change_indicators=success_found,
            rejection_indicators=rejection_found,
        )


def replay_for_csrf(
    request: HttpRequest,
    cookies: Optional[List[Cookie]] = None,
) -> ReplayResponse:
    """
    Convenience function to replay a request for CSRF verification.
    
    This is the main entry point for verification testing.
    """
    return CrossOriginReplayer.replay(request, cookies)


def verify_csrf_exploitable(
    request: HttpRequest,
    cookies: Optional[List[Cookie]] = None,
) -> Tuple[bool, ReplayResponse]:
    """
    Verify if CSRF is actually exploitable.
    
    Returns (is_exploitable, replay_response).
    """
    response = replay_for_csrf(request, cookies)
    is_exploitable = (
        response.result == ReplayResult.SUCCESS and
        response.appears_successful
    )
    return is_exploitable, response
