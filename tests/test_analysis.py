"""Tests for the analysis modules."""

import pytest
from sentinel_csrf.input.requests import HttpRequest
from sentinel_csrf.input.cookies import Cookie
from sentinel_csrf.analysis.state_change import (
    StateChangeConfidence,
    classify_state_change,
)
from sentinel_csrf.analysis.tokens import (
    TokenStrength,
    analyze_tokens,
    calculate_shannon_entropy,
)
from sentinel_csrf.analysis.samesite import (
    SameSiteValue,
    CsrfImpact,
    analyze_samesite,
)
from sentinel_csrf.analysis.browser import (
    AttackVector,
    Feasibility,
    analyze_browser_feasibility,
)


class TestStateChangeClassification:
    """Tests for state-change classification."""
    
    def test_post_is_state_changing(self):
        """POST method is state-changing."""
        request = HttpRequest(
            method="POST",
            path="/api/data",
            http_version="HTTP/1.1",
            headers={"Host": "example.com"},
        )
        
        result = classify_state_change(request)
        
        assert result.is_state_changing is True
        assert result.method_score > 0
    
    def test_get_is_not_state_changing(self):
        """Simple GET is not state-changing."""
        request = HttpRequest(
            method="GET",
            path="/api/view",
            http_version="HTTP/1.1",
            headers={"Host": "example.com"},
        )
        
        result = classify_state_change(request)
        
        assert result.is_state_changing is False
    
    def test_get_with_delete_keyword(self):
        """GET with delete keyword is state-changing."""
        request = HttpRequest(
            method="GET",
            path="/api/delete-account",
            http_version="HTTP/1.1",
            headers={"Host": "example.com"},
        )
        
        result = classify_state_change(request)
        
        assert result.is_state_changing is True
        assert result.keyword_score > 0
    
    def test_put_is_state_changing(self):
        """PUT method is state-changing."""
        request = HttpRequest(
            method="PUT",
            path="/api/resource",
            http_version="HTTP/1.1",
            headers={"Host": "example.com"},
        )
        
        result = classify_state_change(request)
        
        assert result.is_state_changing is True


class TestTokenAnalysis:
    """Tests for CSRF token analysis."""
    
    def test_no_token_detected(self):
        """Request without token is detected."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com",
        )
        
        result = analyze_tokens(request)
        
        assert result.has_token is False
        assert result.strength == TokenStrength.MISSING
    
    def test_token_in_body_detected(self):
        """Token in body is detected."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com&csrf_token=abcdef123456",
        )
        
        result = analyze_tokens(request)
        
        assert result.has_token is True
        assert result.best_candidate is not None
        assert result.best_candidate.name == "csrf_token"
    
    def test_token_in_header_detected(self):
        """Token in header is detected."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRF-Token": "abcdef123456789012345678",
            },
            body="email=test@example.com",
        )
        
        result = analyze_tokens(request)
        
        assert result.has_token is True
        assert result.best_candidate.name == "X-CSRF-Token"
    
    def test_high_entropy_detection(self):
        """High entropy tokens are classified as strong."""
        # High entropy token (random-looking)
        high_entropy = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
        
        entropy = calculate_shannon_entropy(high_entropy)
        
        assert entropy > 3.5  # High entropy threshold


class TestSameSiteAnalysis:
    """Tests for SameSite analysis."""
    
    def test_strict_blocks_csrf(self):
        """SameSite=Strict blocks all CSRF."""
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
        
        result = analyze_samesite(cookies)
        
        assert result.overall_impact == CsrfImpact.BLOCKED
        assert len(result.effective_vectors) == 0
    
    def test_none_allows_csrf(self):
        """SameSite=None allows all CSRF vectors."""
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
        
        result = analyze_samesite(cookies)
        
        assert result.overall_impact == CsrfImpact.VULNERABLE
        assert len(result.effective_vectors) > 0
    
    def test_lax_partial_protection(self):
        """SameSite=Lax provides partial protection."""
        cookies = [
            Cookie(
                domain=".example.com",
                include_subdomains=True,
                path="/",
                secure=True,
                expiry=0,
                name="session",
                value="abc123",
                samesite="Lax",
            ),
        ]
        
        result = analyze_samesite(cookies)
        
        assert result.overall_impact == CsrfImpact.PARTIAL
        # Top-level GET navigation should still work
        assert "link_get" in result.effective_vectors or "form_get" in result.effective_vectors


class TestBrowserFeasibility:
    """Tests for browser feasibility matrix."""
    
    def test_post_form_feasible(self):
        """POST with form-compatible content is feasible via form."""
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
        
        result = analyze_browser_feasibility(request)
        
        assert result.is_exploitable is True
        assert AttackVector.FORM_POST in result.feasible_vectors
    
    def test_get_img_tag_feasible(self):
        """GET is feasible via img tag."""
        request = HttpRequest(
            method="GET",
            path="/api/delete?confirm=true",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
            },
        )
        
        result = analyze_browser_feasibility(request)
        
        assert result.is_exploitable is True
        assert AttackVector.IMG_TAG in result.feasible_vectors
    
    def test_json_content_type_limited(self):
        """JSON content type limits to CORS-based vectors."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123",
                "Content-Type": "application/json",
            },
            body='{"email": "test@example.com"}',
        )
        
        result = analyze_browser_feasibility(request)
        
        # Form-based vectors should be blocked
        assert AttackVector.FORM_POST in result.blocked_vectors
