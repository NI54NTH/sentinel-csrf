"""Tests for the Burp XML parser module."""

import pytest
from pathlib import Path
from sentinel_csrf.input.burp import (
    BurpItem,
    BurpXmlParser,
    parse_burp_xml,
    parse_burp_xml_full,
)


class TestBurpItem:
    """Tests for the BurpItem dataclass."""
    
    def test_url_property(self):
        """Test URL construction."""
        item = BurpItem(
            host="example.com",
            port=443,
            protocol="https",
            method="POST",
            path="/api/update",
            request_raw="POST /api/update HTTP/1.1",
        )
        
        assert item.url == "https://example.com:443/api/update"


class TestBurpXmlParser:
    """Tests for the BurpXmlParser class."""
    
    def test_parse_simple_item(self, tmp_path):
        """Test parsing simple Burp XML."""
        xml_file = tmp_path / "burp.xml"
        xml_file.write_text("""<?xml version="1.0"?>
<items>
  <item>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <path>/api/update</path>
    <request base64="false">POST /api/update HTTP/1.1
Host: example.com

data=value</request>
    <status>200</status>
  </item>
</items>""")
        
        items = BurpXmlParser.parse(xml_file)
        
        assert len(items) == 1
        assert items[0].host == "example.com"
        assert items[0].method == "POST"
        assert items[0].path == "/api/update"
        assert items[0].status == 200
    
    def test_parse_multiple_items(self, tmp_path):
        """Test parsing multiple items."""
        xml_file = tmp_path / "burp.xml"
        xml_file.write_text("""<?xml version="1.0"?>
<items>
  <item>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/page1</path>
    <request base64="false">GET /page1 HTTP/1.1</request>
  </item>
  <item>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <path>/page2</path>
    <request base64="false">POST /page2 HTTP/1.1</request>
  </item>
</items>""")
        
        items = BurpXmlParser.parse(xml_file)
        
        assert len(items) == 2
        assert items[0].method == "GET"
        assert items[1].method == "POST"
    
    def test_parse_base64_encoded(self, tmp_path):
        """Test parsing base64 encoded request."""
        import base64
        
        raw_request = "POST /api/update HTTP/1.1\nHost: example.com\n\ndata=value"
        encoded = base64.b64encode(raw_request.encode()).decode()
        
        xml_file = tmp_path / "burp.xml"
        xml_file.write_text(f"""<?xml version="1.0"?>
<items>
  <item>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <path>/api/update</path>
    <request base64="true">{encoded}</request>
  </item>
</items>""")
        
        items = BurpXmlParser.parse(xml_file)
        
        assert len(items) == 1
        assert "POST /api/update" in items[0].request_raw
        assert "data=value" in items[0].request_raw
    
    def test_parse_with_missing_optional_fields(self, tmp_path):
        """Test parsing with missing optional fields."""
        xml_file = tmp_path / "burp.xml"
        xml_file.write_text("""<?xml version="1.0"?>
<items>
  <item>
    <host>example.com</host>
    <method>GET</method>
    <path>/page</path>
    <request base64="false">GET /page HTTP/1.1</request>
  </item>
</items>""")
        
        items = BurpXmlParser.parse(xml_file)
        
        assert len(items) == 1
        assert items[0].port == 443  # Default
        assert items[0].protocol == "https"  # Default
    
    def test_parse_invalid_xml(self, tmp_path):
        """Test handling invalid XML."""
        xml_file = tmp_path / "burp.xml"
        xml_file.write_text("not valid xml")
        
        with pytest.raises(ValueError, match="Invalid XML"):
            BurpXmlParser.parse(xml_file)


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_parse_burp_xml(self, tmp_path):
        """Test parse_burp_xml returns raw requests."""
        xml_file = tmp_path / "burp.xml"
        xml_file.write_text("""<?xml version="1.0"?>
<items>
  <item>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <path>/api/update</path>
    <request base64="false">POST /api/update HTTP/1.1
Host: example.com

data=value</request>
  </item>
</items>""")
        
        requests = parse_burp_xml(xml_file)
        
        assert len(requests) == 1
        assert "POST /api/update" in requests[0]
    
    def test_parse_burp_xml_full(self, tmp_path):
        """Test parse_burp_xml_full returns BurpItem objects."""
        xml_file = tmp_path / "burp.xml"
        xml_file.write_text("""<?xml version="1.0"?>
<items>
  <item>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <path>/api/update</path>
    <request base64="false">POST /api/update HTTP/1.1</request>
    <status>200</status>
  </item>
</items>""")
        
        items = parse_burp_xml_full(xml_file)
        
        assert len(items) == 1
        assert isinstance(items[0], BurpItem)
        assert items[0].status == 200
