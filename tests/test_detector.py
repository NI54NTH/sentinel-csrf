"""Tests for the core CSRF detector."""

import pytest
from sentinel_csrf.input.requests import HttpRequest
from sentinel_csrf.input.cookies import Cookie
from sentinel_csrf.core.detector import (
    CsrfDetector,
    detect_csrf,
    Severity,
    Confidence,
    CsrfType,
)


class TestCsrfDetector:
    """Tests for the CsrfDetector class."""
    
    def test_detect_no_cookies_suppressed(self):
        """Request without cookies is suppressed."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={"Host": "example.com"},
            body="data=value",
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is False
        assert "not authenticated" in result.suppression_reason.lower()
    
    def test_detect_get_request_no_state_change(self):
        """GET request without state-changing keywords is suppressed."""
        request = HttpRequest(
            method="GET",
            path="/api/view",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
            },
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is False
        assert "not state-changing" in result.suppression_reason.lower()
    
    def test_detect_strong_token_suppressed(self):
        """Request with strong CSRF token is suppressed."""
        # Generate a high-entropy token
        strong_token = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
        
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body=f"email=test@example.com&csrf_token={strong_token}",
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is False
        assert "token" in result.suppression_reason.lower()
    
    def test_detect_vulnerable_no_token(self):
        """POST request without CSRF token is vulnerable."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=attacker@evil.com",
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is True
        assert result.finding is not None
        assert result.finding.csrf_type == CsrfType.FORM_BASED
    
    def test_detect_vulnerable_weak_token(self):
        """Request with weak token is vulnerable."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com&csrf_token=abc",  # Very short token
        )
        
        result = detect_csrf(request)
        
        # Short token should be flagged as vulnerable
        assert result.is_vulnerable is True
    
    def test_detect_get_state_changing(self):
        """GET request with delete action is detected."""
        request = HttpRequest(
            method="GET",
            path="/api/account/delete?confirm=true",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
            },
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is True
        assert result.finding.csrf_type == CsrfType.GET_BASED
    
    def test_detect_login_csrf(self):
        """Login endpoint without token is detected."""
        request = HttpRequest(
            method="POST",
            path="/auth/login",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="username=admin&password=secret",
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is True
        assert result.finding.csrf_type == CsrfType.LOGIN_CSRF
    
    def test_severity_critical_password(self):
        """Password change gets critical severity."""
        request = HttpRequest(
            method="POST",
            path="/api/change-password",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="new_password=hacked123",
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is True
        assert result.finding.severity == Severity.CRITICAL
    
    def test_finding_has_recommendation(self):
        """Finding includes remediation recommendation."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com",
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is True
        assert result.finding.recommendation != ""
        assert "csrf" in result.finding.recommendation.lower() or "token" in result.finding.recommendation.lower()
    
    def test_finding_to_json(self):
        """Finding can be serialized to JSON."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com",
        )
        
        result = detect_csrf(request)
        
        assert result.is_vulnerable is True
        json_str = result.finding.to_json()
        assert '"csrf_type": "form_based"' in json_str
        # Check the finding dict has correct structure
        finding_dict = result.finding.to_dict()
        assert finding_dict["csrf_type"] == "form_based"
        assert "analysis" in finding_dict


class TestWithSameSiteCookies:
    """Tests with SameSite cookie analysis."""
    
    def test_samesite_strict_blocks(self):
        """SameSite=Strict cookies block CSRF."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com",
        )
        
        cookies = [
            Cookie(
                domain=".example.com",
                include_subdomains=True,
                path="/",
                secure=True,
                expiry=0,
                name="session",
                value="abc123",
                samesite="Strict",
            ),
        ]
        
        result = detect_csrf(request, cookies)
        
        assert result.is_vulnerable is False
        assert "samesite" in result.suppression_reason.lower()
    
    def test_samesite_none_vulnerable(self):
        """SameSite=None cookies allow CSRF."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com",
        )
        
        cookies = [
            Cookie(
                domain=".example.com",
                include_subdomains=True,
                path="/",
                secure=True,
                expiry=0,
                name="session",
                value="abc123",
                samesite="None",
            ),
        ]
        
        result = detect_csrf(request, cookies)
        
        assert result.is_vulnerable is True
