"""Tests for log parsers (Syslog, Windows, Firewall, WebServer, Suricata)."""

import json
from parsers import (
    SyslogParser,
    WindowsEventParser,
    FirewallParser,
    WebServerParser,
    SuricataParser,
)


def test_syslog_parser_auth_failure():
    """SyslogParser extracts timestamp, hostname, service, IP and failure type."""
    parser = SyslogParser()
    raw = "Oct 11 22:14:15 myhost sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 2222 ssh2"
    event = parser.parse(raw)

    assert event is not None
    assert event.source_ip == "192.168.1.100"
    assert event.hostname == "myhost"
    assert "sshd" in event.service
    assert "auth_failure" in event.event_type
    assert event.severity in ("high", "medium", "critical")


def test_web_server_parser_combined():
    """WebServerParser parses Nginx/Apache combined access log line."""
    parser = WebServerParser()
    raw = '10.0.0.50 - frank [10/Oct/2026:13:55:36 +0000] "GET /api/v1/users HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"'
    event = parser.parse(raw)

    assert event is not None
    assert event.source_ip == "10.0.0.50"
    assert event.metadata.get("status_code") == 200 or "200" in event.message
    assert "web" in event.source


def test_firewall_parser_ufw():
    """FirewallParser extracts source IP, destination IP, and protocol from UFW block."""
    parser = FirewallParser()
    raw = "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=192.168.1.10 PROTO=TCP SPT=54321 DPT=22"
    event = parser.parse(raw)

    assert event is not None
    assert event.source_ip == "203.0.113.5"
    assert event.dest_ip == "192.168.1.10"
    assert event.metadata.get("protocol") == "TCP" or "TCP" in event.message


def test_suricata_parser_eve_json():
    """SuricataParser parses EVE JSON alerts."""
    parser = SuricataParser()
    eve = {
        "timestamp": "2026-10-11T22:14:15.000000+0000",
        "event_type": "alert",
        "src_ip": "198.51.100.12",
        "dest_ip": "10.0.0.1",
        "alert": {
            "signature": "ET SCAN Suspicious Inbound to MSSQL",
            "severity": 1,
            "category": "Potentially Bad Traffic",
        },
    }
    raw = json.dumps(eve)
    event = parser.parse(raw)

    assert event is not None
    assert event.source_ip == "198.51.100.12"
    assert event.dest_ip == "10.0.0.1"
    assert "Suspicious" in event.message


def test_windows_parser_logon_failure():
    """WindowsEventParser parses 4625 failed logon events in XML."""
    parser = WindowsEventParser()
    raw = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><EventID>4625</EventID><Computer>WIN-01</Computer>'
        '<TimeCreated SystemTime="2026-10-11T22:14:15.000Z"/></System>'
        '<EventData><Data Name="TargetUserName">Administrator</Data>'
        '<Data Name="IpAddress">192.168.1.88</Data></EventData></Event>'
    )
    event = parser.parse(raw)

    assert event is not None
    assert event.source_ip == "192.168.1.88"
    assert event.event_type == "logon_failure"
    assert event.hostname == "WIN-01"
