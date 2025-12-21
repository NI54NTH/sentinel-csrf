"""Tests for the HTTP request parser module."""

import pytest
from pathlib import Path
from sentinel_csrf.input.requests import (
    HttpRequest,
    HttpRequestParser,
    parse_request,
    parse_requests_from_file,
)


class TestHttpRequest:
    """Tests for the HttpRequest dataclass."""
    
    def test_basic_request(self):
        """Test basic request creation."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={"Host": "example.com", "Content-Type": "application/x-www-form-urlencoded"},
            body="email=test@example.com",
        )
        
        assert request.method == "POST"
        assert request.path == "/api/update"
        assert request.host == "example.com"
        assert request.content_type == "application/x-www-form-urlencoded"
    
    def test_cookie_extraction(self):
        """Test cookie extraction from headers."""
        request = HttpRequest(
            method="GET",
            path="/",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Cookie": "session=abc123; auth=xyz789",
            },
        )
        
        assert request.cookies == {"session": "abc123", "auth": "xyz789"}
    
    def test_is_state_changing(self):
        """Test state-changing method detection."""
        post_request = HttpRequest(
            method="POST",
            path="/",
            http_version="HTTP/1.1",
            headers={"Host": "example.com"},
        )
        
        get_request = HttpRequest(
            method="GET",
            path="/",
            http_version="HTTP/1.1",
            headers={"Host": "example.com"},
        )
        
        assert post_request.is_state_changing() is True
        assert get_request.is_state_changing() is False
    
    def test_get_body_params(self):
        """Test body parameter extraction."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com&name=John",
        )
        
        params = request.get_body_params()
        assert params == {"email": "test@example.com", "name": "John"}
    
    def test_has_csrf_token_candidate_positive(self):
        """Test CSRF token detection when present."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRF-Token": "abc123",
            },
            body="email=test@example.com",
        )
        
        has_token, candidates = request.has_csrf_token_candidate()
        assert has_token is True
        assert "header:X-CSRF-Token" in candidates
    
    def test_has_csrf_token_candidate_in_body(self):
        """Test CSRF token detection in body."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={
                "Host": "example.com",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="email=test@example.com&csrf_token=abc123",
        )
        
        has_token, candidates = request.has_csrf_token_candidate()
        assert has_token is True
        assert "body:csrf_token" in candidates
    
    def test_has_csrf_token_candidate_negative(self):
        """Test CSRF token detection when absent."""
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
        
        has_token, candidates = request.has_csrf_token_candidate()
        assert has_token is False
        assert candidates == []
    
    def test_to_raw(self):
        """Test conversion back to raw format."""
        request = HttpRequest(
            method="POST",
            path="/api/update",
            http_version="HTTP/1.1",
            headers={"Host": "example.com"},
            body="data=value",
        )
        
        raw = request.to_raw()
        assert "POST /api/update HTTP/1.1" in raw
        assert "Host: example.com" in raw
        assert "data=value" in raw


class TestHttpRequestParser:
    """Tests for the HttpRequestParser class."""
    
    def test_parse_simple_get(self):
        """Test parsing simple GET request."""
        raw = """GET /page HTTP/1.1
Host: example.com
User-Agent: Test"""
        
        request = HttpRequestParser.parse(raw)
        
        assert request.method == "GET"
        assert request.path == "/page"
        assert request.headers["Host"] == "example.com"
        assert request.body == ""
    
    def test_parse_post_with_body(self):
        """Test parsing POST request with body."""
        raw = """POST /api/update HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

email=test@example.com"""
        
        request = HttpRequestParser.parse(raw)
        
        assert request.method == "POST"
        assert request.path == "/api/update"
        assert request.body == "email=test@example.com"
    
    def test_parse_with_cookies(self):
        """Test parsing request with cookies."""
        raw = """GET / HTTP/1.1
Host: example.com
Cookie: session=abc123; auth=xyz"""
        
        request = HttpRequestParser.parse(raw)
        
        assert request.cookies == {"session": "abc123", "auth": "xyz"}
    
    def test_parse_crlf_line_endings(self):
        """Test parsing with CRLF line endings."""
        raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        request = HttpRequestParser.parse(raw)
        
        assert request.method == "GET"
        assert request.host == "example.com"
    
    def test_parse_file(self, tmp_path):
        """Test parsing from file."""
        request_file = tmp_path / "request.txt"
        request_file.write_text("""POST /api/update HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

email=test@example.com""")
        
        request = HttpRequestParser.parse_file(request_file)
        
        assert request.method == "POST"
        assert request.body == "email=test@example.com"
    
    def test_parse_multiple(self):
        """Test parsing multiple requests."""
        raw = """GET /page1 HTTP/1.1
Host: example.com

---

POST /page2 HTTP/1.1
Host: example.com

data=value"""
        
        requests = HttpRequestParser.parse_multiple(raw)
        
        assert len(requests) == 2
        assert requests[0].method == "GET"
        assert requests[1].method == "POST"


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_parse_request_from_string(self):
        """Test parse_request with string input."""
        raw = "GET / HTTP/1.1\nHost: example.com"
        request = parse_request(raw)
        
        assert request.method == "GET"
    
    def test_parse_request_from_file(self, tmp_path):
        """Test parse_request with file path."""
        request_file = tmp_path / "request.txt"
        request_file.write_text("GET / HTTP/1.1\nHost: example.com")
        
        request = parse_request(request_file)
        
        assert request.method == "GET"
