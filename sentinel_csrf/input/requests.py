"""
HTTP request parsing module for Sentinel-CSRF.

Parses raw HTTP requests into structured format for CSRF analysis.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import re


@dataclass
class HttpRequest:
    """Represents a parsed HTTP request."""
    
    method: str
    path: str
    http_version: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    
    # Derived fields
    host: str = ""
    url: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    
    def __post_init__(self):
        """Extract derived fields after initialization."""
        # Extract host from headers
        if not self.host:
            self.host = self.headers.get("Host", self.headers.get("host", ""))
        
        # Build full URL
        if not self.url:
            scheme = "https" if self.is_secure() else "http"
            self.url = f"{scheme}://{self.host}{self.path}"
        
        # Extract cookies
        if not self.cookies:
            cookie_header = self.headers.get("Cookie", self.headers.get("cookie", ""))
            if cookie_header:
                self.cookies = self._parse_cookie_header(cookie_header)
        
        # Extract content type
        if not self.content_type:
            self.content_type = self.headers.get(
                "Content-Type", 
                self.headers.get("content-type", "")
            )
    
    def _parse_cookie_header(self, cookie_header: str) -> Dict[str, str]:
        """Parse Cookie header into dictionary."""
        cookies = {}
        for pair in cookie_header.split(';'):
            pair = pair.strip()
            if '=' in pair:
                name, value = pair.split('=', 1)
                cookies[name.strip()] = value.strip()
        return cookies
    
    def is_secure(self) -> bool:
        """Check if request should be HTTPS."""
        # Heuristics for HTTPS detection
        if self.headers.get("X-Forwarded-Proto", "").lower() == "https":
            return True
        if ":443" in self.host:
            return True
        # Default to HTTPS for security
        return True
    
    def is_state_changing(self) -> bool:
        """Check if request method typically changes state."""
        return self.method.upper() in ("POST", "PUT", "PATCH", "DELETE")
    
    def get_query_params(self) -> Dict[str, List[str]]:
        """Extract query parameters from URL."""
        parsed = urlparse(self.path)
        return parse_qs(parsed.query)
    
    def get_body_params(self) -> Dict[str, str]:
        """Extract body parameters (for form-urlencoded)."""
        if "application/x-www-form-urlencoded" in self.content_type:
            params = {}
            for pair in self.body.split('&'):
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    params[name] = value
            return params
        return {}
    
    def has_csrf_token_candidate(self) -> Tuple[bool, List[str]]:
        """
        Check if request contains potential CSRF token.
        
        Returns (has_candidate, list of candidate field names)
        """
        candidates = []
        
        # Common CSRF token field names
        csrf_patterns = [
            r'csrf',
            r'xsrf',
            r'token',
            r'authenticity',
            r'_token',
            r'nonce',
            r'state',
        ]
        
        # Check headers
        for header_name in self.headers:
            for pattern in csrf_patterns:
                if re.search(pattern, header_name, re.IGNORECASE):
                    candidates.append(f"header:{header_name}")
        
        # Check body parameters
        body_params = self.get_body_params()
        for param_name in body_params:
            for pattern in csrf_patterns:
                if re.search(pattern, param_name, re.IGNORECASE):
                    candidates.append(f"body:{param_name}")
        
        # Check query parameters
        query_params = self.get_query_params()
        for param_name in query_params:
            for pattern in csrf_patterns:
                if re.search(pattern, param_name, re.IGNORECASE):
                    candidates.append(f"query:{param_name}")
        
        return (len(candidates) > 0, candidates)
    
    def to_raw(self) -> str:
        """Convert back to raw HTTP request format."""
        lines = [f"{self.method} {self.path} {self.http_version}"]
        
        for name, value in self.headers.items():
            lines.append(f"{name}: {value}")
        
        lines.append("")  # Empty line before body
        
        if self.body:
            lines.append(self.body)
        
        return "\r\n".join(lines)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
            "cookies": self.cookies,
            "content_type": self.content_type,
            "is_state_changing": self.is_state_changing(),
        }


class HttpRequestParser:
    """Parser for raw HTTP requests."""
    
    @classmethod
    def parse(cls, raw_request: str) -> HttpRequest:
        """
        Parse a raw HTTP request string.
        
        Expected format:
        METHOD PATH HTTP/VERSION
        Header-Name: Header-Value
        ...
        
        Body content
        """
        # Normalize line endings
        raw_request = raw_request.replace('\r\n', '\n')
        
        # Split headers and body
        if '\n\n' in raw_request:
            header_section, body = raw_request.split('\n\n', 1)
        else:
            header_section = raw_request
            body = ""
        
        lines = header_section.split('\n')
        
        if not lines:
            raise ValueError("Empty request")
        
        # Parse request line
        request_line = lines[0].strip()
        parts = request_line.split(' ')
        
        if len(parts) < 2:
            raise ValueError(f"Invalid request line: {request_line}")
        
        method = parts[0].upper()
        path = parts[1]
        http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"
        
        # Parse headers
        headers = {}
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            
            if ':' in line:
                name, value = line.split(':', 1)
                headers[name.strip()] = value.strip()
        
        return HttpRequest(
            method=method,
            path=path,
            http_version=http_version,
            headers=headers,
            body=body.strip(),
        )
    
    @classmethod
    def parse_file(cls, filepath: Path) -> HttpRequest:
        """Parse HTTP request from file."""
        content = filepath.read_text()
        return cls.parse(content)
    
    @classmethod
    def parse_multiple(cls, raw_requests: str, separator: str = "---") -> List[HttpRequest]:
        """Parse multiple requests separated by delimiter."""
        requests = []
        for raw in raw_requests.split(separator):
            raw = raw.strip()
            if raw:
                try:
                    requests.append(cls.parse(raw))
                except ValueError:
                    continue
        return requests


def parse_request(source: Path | str) -> HttpRequest:
    """
    Parse HTTP request from file or string.
    
    Convenience function for common use case.
    """
    if isinstance(source, Path) and source.exists():
        return HttpRequestParser.parse_file(source)
    elif isinstance(source, str):
        return HttpRequestParser.parse(source)
    else:
        raise ValueError(f"Invalid request source: {source}")


def parse_requests_from_file(filepath: Path) -> List[HttpRequest]:
    """Parse multiple requests from a file (separated by ---)."""
    content = filepath.read_text()
    return HttpRequestParser.parse_multiple(content)
