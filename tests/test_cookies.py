"""Tests for the cookie parser module."""

import pytest
from pathlib import Path
from sentinel_csrf.input.cookies import (
    Cookie,
    CookieParser,
    parse_cookies,
    cookies_to_netscape,
    cookie_string_to_netscape,
    cookies_to_header,
)


class TestCookie:
    """Tests for the Cookie dataclass."""
    
    def test_to_netscape_line(self):
        """Test conversion to Netscape format."""
        cookie = Cookie(
            domain=".example.com",
            include_subdomains=True,
            path="/",
            secure=False,
            expiry=0,
            name="session",
            value="abc123",
        )
        
        line = cookie.to_netscape_line()
        assert line == ".example.com\tTRUE\t/\tFALSE\t0\tsession\tabc123"
    
    def test_to_header_value(self):
        """Test conversion to Cookie header format."""
        cookie = Cookie(
            domain=".example.com",
            include_subdomains=True,
            path="/",
            secure=False,
            expiry=0,
            name="session",
            value="abc123",
        )
        
        assert cookie.to_header_value() == "session=abc123"
    
    def test_is_applicable_to_matching_domain(self):
        """Test cookie applicability with matching domain."""
        cookie = Cookie(
            domain=".example.com",
            include_subdomains=True,
            path="/",
            secure=False,
            expiry=0,
            name="session",
            value="abc123",
        )
        
        assert cookie.is_applicable_to("http://example.com/page") is True
        assert cookie.is_applicable_to("http://sub.example.com/page") is True
    
    def test_is_applicable_to_non_matching_domain(self):
        """Test cookie not applicable to different domain."""
        cookie = Cookie(
            domain=".example.com",
            include_subdomains=True,
            path="/",
            secure=False,
            expiry=0,
            name="session",
            value="abc123",
        )
        
        assert cookie.is_applicable_to("http://other.com/page") is False
    
    def test_secure_cookie_requires_https(self):
        """Test secure cookie only sent over HTTPS."""
        cookie = Cookie(
            domain=".example.com",
            include_subdomains=True,
            path="/",
            secure=True,
            expiry=0,
            name="session",
            value="abc123",
        )
        
        assert cookie.is_applicable_to("https://example.com/page") is True
        assert cookie.is_applicable_to("http://example.com/page") is False


class TestCookieParser:
    """Tests for the CookieParser class."""
    
    def test_parse_cookie_string(self):
        """Test parsing cookie header string."""
        cookie_str = "session=abc123; auth=xyz789"
        cookies = CookieParser.parse_cookie_string(cookie_str, "example.com")
        
        assert len(cookies) == 2
        assert cookies[0].name == "session"
        assert cookies[0].value == "abc123"
        assert cookies[1].name == "auth"
        assert cookies[1].value == "xyz789"
    
    def test_parse_cookie_string_single(self):
        """Test parsing single cookie."""
        cookie_str = "session=abc123"
        cookies = CookieParser.parse_cookie_string(cookie_str, "example.com")
        
        assert len(cookies) == 1
        assert cookies[0].name == "session"
        assert cookies[0].value == "abc123"
    
    def test_parse_set_cookie_header_simple(self):
        """Test parsing simple Set-Cookie header."""
        set_cookie = "session=abc123; Path=/; Secure"
        cookie = CookieParser.parse_set_cookie_header(set_cookie, "example.com")
        
        assert cookie is not None
        assert cookie.name == "session"
        assert cookie.value == "abc123"
        assert cookie.path == "/"
        assert cookie.secure is True
    
    def test_parse_set_cookie_header_with_samesite(self):
        """Test parsing Set-Cookie with SameSite attribute."""
        set_cookie = "session=abc123; SameSite=Strict; HttpOnly"
        cookie = CookieParser.parse_set_cookie_header(set_cookie, "example.com")
        
        assert cookie is not None
        assert cookie.samesite == "Strict"
        assert cookie.httponly is True
    
    def test_parse_netscape_file(self, tmp_path):
        """Test parsing Netscape cookie file."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text("""# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	0	session	abc123
.example.com	TRUE	/api	TRUE	0	auth	xyz789
""")
        
        cookies = CookieParser.parse_netscape_file(cookie_file)
        
        assert len(cookies) == 2
        assert cookies[0].name == "session"
        assert cookies[0].domain == ".example.com"
        assert cookies[1].name == "auth"
        assert cookies[1].secure is True


class TestConversionFunctions:
    """Tests for conversion utility functions."""
    
    def test_cookies_to_netscape(self):
        """Test converting cookies to Netscape format."""
        cookies = [
            Cookie(
                domain=".example.com",
                include_subdomains=True,
                path="/",
                secure=False,
                expiry=0,
                name="session",
                value="abc123",
            ),
        ]
        
        result = cookies_to_netscape(cookies)
        
        assert "# Netscape HTTP Cookie File" in result
        assert ".example.com\tTRUE\t/\tFALSE\t0\tsession\tabc123" in result
    
    def test_cookie_string_to_netscape(self):
        """Test converting cookie string to Netscape format."""
        result = cookie_string_to_netscape("session=abc123", "example.com")
        
        assert "# Netscape HTTP Cookie File" in result
        assert "session\tabc123" in result
    
    def test_cookies_to_header(self):
        """Test converting cookies to header value."""
        cookies = [
            Cookie(
                domain=".example.com",
                include_subdomains=True,
                path="/",
                secure=False,
                expiry=0,
                name="session",
                value="abc123",
            ),
            Cookie(
                domain=".example.com",
                include_subdomains=True,
                path="/",
                secure=False,
                expiry=0,
                name="auth",
                value="xyz789",
            ),
        ]
        
        result = cookies_to_header(cookies)
        
        assert result == "session=abc123; auth=xyz789"
