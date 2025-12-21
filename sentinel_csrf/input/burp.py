"""
Burp Suite XML export parser for Sentinel-CSRF.

Converts Burp XML exports to raw HTTP requests.
"""

import base64
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class BurpItem:
    """Represents a single item from Burp XML export."""
    
    host: str
    port: int
    protocol: str
    method: str
    path: str
    request_raw: str
    response_raw: Optional[str] = None
    status: Optional[int] = None
    mimetype: Optional[str] = None
    
    @property
    def url(self) -> str:
        """Get full URL."""
        return f"{self.protocol}://{self.host}:{self.port}{self.path}"


class BurpXmlParser:
    """Parser for Burp Suite XML exports."""
    
    @classmethod
    def parse(cls, filepath: Path) -> List[BurpItem]:
        """
        Parse Burp XML export file.
        
        Expected format:
        <items>
          <item>
            <host>example.com</host>
            <port>443</port>
            <protocol>https</protocol>
            <method>POST</method>
            <path>/api/endpoint</path>
            <request base64="true">BASE64_ENCODED_REQUEST</request>
            <response base64="true">BASE64_ENCODED_RESPONSE</response>
          </item>
        </items>
        """
        items = []
        
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML: {e}")
        
        # Handle both <items> wrapper and direct <item> elements
        if root.tag == "items":
            item_elements = root.findall("item")
        else:
            item_elements = root.findall(".//item")
        
        for item_elem in item_elements:
            try:
                burp_item = cls._parse_item(item_elem)
                if burp_item:
                    items.append(burp_item)
            except Exception:
                # Skip malformed items
                continue
        
        return items
    
    @classmethod
    def _parse_item(cls, item_elem: ET.Element) -> Optional[BurpItem]:
        """Parse a single <item> element."""
        # Required fields
        host = cls._get_text(item_elem, "host")
        if not host:
            return None
        
        port_str = cls._get_text(item_elem, "port", "443")
        try:
            port = int(port_str)
        except ValueError:
            port = 443
        
        protocol = cls._get_text(item_elem, "protocol", "https")
        method = cls._get_text(item_elem, "method", "GET")
        path = cls._get_text(item_elem, "path", "/")
        
        # Parse request (may be base64 encoded)
        request_elem = item_elem.find("request")
        if request_elem is not None:
            request_raw = cls._decode_content(request_elem)
        else:
            # Reconstruct minimal request if not present
            request_raw = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        
        # Parse response (optional)
        response_elem = item_elem.find("response")
        response_raw = None
        if response_elem is not None:
            response_raw = cls._decode_content(response_elem)
        
        # Optional metadata
        status = None
        status_str = cls._get_text(item_elem, "status")
        if status_str:
            try:
                status = int(status_str)
            except ValueError:
                pass
        
        mimetype = cls._get_text(item_elem, "mimetype")
        
        return BurpItem(
            host=host,
            port=port,
            protocol=protocol,
            method=method,
            path=path,
            request_raw=request_raw,
            response_raw=response_raw,
            status=status,
            mimetype=mimetype,
        )
    
    @classmethod
    def _get_text(cls, elem: ET.Element, tag: str, default: str = "") -> str:
        """Get text content of child element."""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default
    
    @classmethod
    def _decode_content(cls, elem: ET.Element) -> str:
        """Decode element content (handles base64)."""
        if elem.text is None:
            return ""
        
        content = elem.text
        
        # Check if base64 encoded
        is_base64 = elem.get("base64", "").lower() == "true"
        
        if is_base64:
            try:
                decoded = base64.b64decode(content)
                # Try to decode as UTF-8, fallback to latin-1
                try:
                    return decoded.decode('utf-8')
                except UnicodeDecodeError:
                    return decoded.decode('latin-1')
            except Exception:
                return content
        
        return content


def parse_burp_xml(filepath: Path) -> List[str]:
    """
    Parse Burp XML and return list of raw HTTP requests.
    
    This is the main function called by the CLI.
    """
    items = BurpXmlParser.parse(filepath)
    return [item.request_raw for item in items]


def parse_burp_xml_full(filepath: Path) -> List[BurpItem]:
    """
    Parse Burp XML and return full BurpItem objects.
    
    Use this when you need access to response and metadata.
    """
    return BurpXmlParser.parse(filepath)
