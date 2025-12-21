"""
Cookie parsing module for Sentinel-CSRF.

Supports:
- Netscape cookie file format (primary)
- Key-value cookie strings (normalized to Netscape)
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import re


@dataclass
class Cookie:
    """Represents a parsed HTTP cookie."""
    
    domain: str
    include_subdomains: bool
    path: str
    secure: bool
    expiry: int
    name: str
    value: str
    
    # Optional attributes for CSRF analysis
    samesite: Optional[str] = None  # Strict, Lax, None
    httponly: bool = False
    
    def to_netscape_line(self) -> str:
        """Convert cookie to Netscape format line."""
        subdomain_flag = "TRUE" if self.include_subdomains else "FALSE"
        secure_flag = "TRUE" if self.secure else "FALSE"
        return f"{self.domain}\t{subdomain_flag}\t{self.path}\t{secure_flag}\t{self.expiry}\t{self.name}\t{self.value}"
    
    def to_header_value(self) -> str:
        """Convert cookie to Cookie header format."""
        return f"{self.name}={self.value}"
    
    def is_applicable_to(self, url: str) -> bool:
        """Check if this cookie should be sent to the given URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        # Check domain
        if self.include_subdomains:
            if not (parsed.netloc == self.domain.lstrip('.') or 
                    parsed.netloc.endswith(self.domain)):
                return False
        else:
            if parsed.netloc != self.domain:
                return False
        
        # Check path
        if not parsed.path.startswith(self.path):
            return False
        
        # Check secure flag
        if self.secure and parsed.scheme != "https":
            return False
        
        return True


class CookieParser:
    """Parser for various cookie file formats."""
    
    # Netscape cookie file header
    NETSCAPE_HEADER = "# Netscape HTTP Cookie File"
    
    @classmethod
    def parse_netscape_file(cls, filepath: Path) -> List[Cookie]:
        """
        Parse a Netscape cookie file.
        
        Format:
        domain  subdomain_flag  path  secure_flag  expiry  name  value
        
        Lines starting with # are comments.
        """
        cookies = []
        content = filepath.read_text()
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Split by tabs
            parts = line.split('\t')
            
            if len(parts) < 7:
                # Try splitting by whitespace for malformed files
                parts = line.split()
            
            if len(parts) < 7:
                # Skip malformed lines
                continue
            
            try:
                cookie = Cookie(
                    domain=parts[0],
                    include_subdomains=parts[1].upper() == "TRUE",
                    path=parts[2],
                    secure=parts[3].upper() == "TRUE",
                    expiry=int(parts[4]) if parts[4].isdigit() else 0,
                    name=parts[5],
                    value=parts[6] if len(parts) > 6 else "",
                )
                cookies.append(cookie)
            except (IndexError, ValueError) as e:
                # Skip malformed lines
                continue
        
        return cookies
    
    @classmethod
    def parse_cookie_string(cls, cookie_string: str, domain: str) -> List[Cookie]:
        """
        Parse a Cookie header value or key=value string.
        
        Input: "session=abc123; auth=xyz789"
        """
        cookies = []
        
        # Split by semicolon
        pairs = cookie_string.split(';')
        
        for pair in pairs:
            pair = pair.strip()
            if not pair:
                continue
            
            # Split by first equals sign
            if '=' in pair:
                name, value = pair.split('=', 1)
                name = name.strip()
                value = value.strip()
            else:
                # Cookie without value
                name = pair.strip()
                value = ""
            
            cookie = Cookie(
                domain=f".{domain}" if not domain.startswith('.') else domain,
                include_subdomains=True,
                path="/",
                secure=False,
                expiry=0,
                name=name,
                value=value,
            )
            cookies.append(cookie)
        
        return cookies
    
    @classmethod
    def parse_set_cookie_header(cls, set_cookie: str, default_domain: str) -> Optional[Cookie]:
        """
        Parse a Set-Cookie response header.
        
        Input: "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"
        """
        parts = set_cookie.split(';')
        
        if not parts:
            return None
        
        # First part is name=value
        first_part = parts[0].strip()
        if '=' not in first_part:
            return None
        
        name, value = first_part.split('=', 1)
        
        # Default values
        domain = default_domain
        path = "/"
        secure = False
        httponly = False
        samesite = None
        expiry = 0
        
        # Parse attributes
        for part in parts[1:]:
            part = part.strip().lower()
            
            if part.startswith("domain="):
                domain = part.split("=", 1)[1].strip()
            elif part.startswith("path="):
                path = part.split("=", 1)[1].strip()
            elif part == "secure":
                secure = True
            elif part == "httponly":
                httponly = True
            elif part.startswith("samesite="):
                samesite_value = part.split("=", 1)[1].strip()
                samesite = samesite_value.capitalize()
            elif part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                    import time
                    expiry = int(time.time()) + max_age
                except ValueError:
                    pass
        
        return Cookie(
            domain=domain if domain.startswith('.') else f".{domain}",
            include_subdomains=True,
            path=path,
            secure=secure,
            expiry=expiry,
            name=name.strip(),
            value=value.strip(),
            samesite=samesite,
            httponly=httponly,
        )


def parse_cookies(source: Path | str, domain: Optional[str] = None) -> List[Cookie]:
    """
    Parse cookies from file or string.
    
    Automatically detects format:
    - If Path and file exists: Netscape format
    - If string: Cookie header format (requires domain)
    """
    if isinstance(source, Path) and source.exists():
        return CookieParser.parse_netscape_file(source)
    elif isinstance(source, str):
        if domain is None:
            raise ValueError("Domain required when parsing cookie string")
        return CookieParser.parse_cookie_string(source, domain)
    else:
        raise ValueError(f"Invalid cookie source: {source}")


def cookies_to_netscape(cookies: List[Cookie]) -> str:
    """Convert list of cookies to Netscape file format."""
    lines = [
        "# Netscape HTTP Cookie File",
        "# https://curl.se/docs/http-cookies.html",
        "# Generated by Sentinel-CSRF",
        "",
    ]
    
    for cookie in cookies:
        lines.append(cookie.to_netscape_line())
    
    return "\n".join(lines)


def cookie_string_to_netscape(cookie_string: str, domain: str) -> str:
    """Convert a cookie string to Netscape file format."""
    cookies = CookieParser.parse_cookie_string(cookie_string, domain)
    return cookies_to_netscape(cookies)


def cookies_to_header(cookies: List[Cookie], url: Optional[str] = None) -> str:
    """
    Convert list of cookies to Cookie header value.
    
    If URL provided, only includes applicable cookies.
    """
    if url:
        applicable = [c for c in cookies if c.is_applicable_to(url)]
    else:
        applicable = cookies
    
    return "; ".join(c.to_header_value() for c in applicable)
