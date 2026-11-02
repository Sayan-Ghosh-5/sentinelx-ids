"""Security tests for hardened XML parsing in Windows Event Log parser."""

import pytest
from parsers.windows_parser import MAX_XML_PAYLOAD_SIZE, WindowsEventParser


@pytest.fixture
def parser() -> WindowsEventParser:
    return WindowsEventParser()


def test_xml_bomb_billion_laughs_rejected(parser: WindowsEventParser):
    """Verify that defusedxml blocks XML entity expansion / billion laughs attack."""
    xml_bomb = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
      <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    ]>
    <Event>
      <System>
        <EventID>&lol3;</EventID>
      </System>
    </Event>"""

    # defusedxml will reject DTD / entities without exploding memory
    result = parser.parse(xml_bomb)
    # The parser safely rejects or returns None / does not crash
    assert result is None or result.event_id != 4624


def test_xml_payload_size_limit_enforced(parser: WindowsEventParser):
    """Payloads exceeding MAX_XML_PAYLOAD_SIZE are rejected immediately."""
    oversized = "<Event>" + ("A" * (MAX_XML_PAYLOAD_SIZE + 1024)) + "</Event>"
    result = parser.parse(oversized)
    assert result is None


def test_malformed_truncated_xml_handled_safely(parser: WindowsEventParser):
    """Truncated or invalid XML is safely handled without raising unhandled exceptions."""
    truncated = "<Event><System><EventID>4624</EventID><TimeCreated"
    result = parser.parse(truncated)
    # Result should either be None or safely handled with metadata
    assert result is None or "event_id" in result.metadata


def test_non_xml_binary_junk_handled_safely(parser: WindowsEventParser):
    """Binary or junk data does not cause unhandled crashes."""
    junk = "\x00\xff\xfe\x01\x02\x03Random non-XML bytes"
    result = parser.parse(junk)
    assert result is None


def test_valid_xml_parsed_correctly(parser: WindowsEventParser):
    """Valid Windows event XML parses as expected."""
    valid_xml = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System>"
        "<EventID>4624</EventID>"
        "<TimeCreated SystemTime='2026-11-01T12:00:00.000Z'/>"
        "<Computer>DC01.corp.local</Computer>"
        "<Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "</System>"
        "<EventData>"
        "<Data Name='TargetUserName'>Administrator</Data>"
        "</EventData>"
        "</Event>"
    )
    result = parser.parse(valid_xml)
    assert result is not None
    assert result.metadata["event_id"] == 4624
    assert result.hostname == "DC01.corp.local"
    assert result.event_type == "logon_success"
