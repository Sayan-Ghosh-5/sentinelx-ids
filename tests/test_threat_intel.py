"""Tests for threat intelligence scoring, IOC types, and GeoIP enrichment."""

from threat_intel.geo import GeoInfo
from threat_intel.scorer import (
    ThreatVerdict,
    _infer_threat_type,
    _severity_from_score,
    score_ip,
)


def test_severity_from_score():
    """Verify threat score severity mapping."""
    assert _severity_from_score(90.0) == "critical"
    assert _severity_from_score(70.0) == "high"
    assert _severity_from_score(50.0) == "medium"
    assert _severity_from_score(25.0) == "low"
    assert _severity_from_score(5.0) == "clean"


def test_infer_threat_type():
    """Threat type is correctly inferred from tags and context."""
    assert _infer_threat_type({"botnet": True}, {}, {}) == "botnet"
    assert _infer_threat_type({"scanner": True}, {}, {}) == "scanner"
    assert _infer_threat_type({"malware": True}, {}, {}) == "malware"
    assert _infer_threat_type({}, {"usage_type": "Data Center/Web Hosting"}, {}) == "scanner"
    assert _infer_threat_type({}, {}, {}) == "unknown"


def test_score_ip_calculation():
    """score_ip aggregates abuse scores and tags into a composite ThreatVerdict."""
    abuse_data = {"available": True, "abuse_confidence_score": 85, "usage_type": "Data Center"}
    vt_data = {"available": False}
    geo = GeoInfo(ip="185.220.101.5", country="Germany", country_code="DE", success=True)

    verdict = score_ip(
        ip="185.220.101.5",
        local_score=50.0,
        abuseipdb_data=abuse_data,
        virustotal_data=vt_data,
        geo=geo,
    )

    assert isinstance(verdict, ThreatVerdict)
    assert verdict.indicator == "185.220.101.5"
    assert verdict.indicator_type == "ip"
    assert verdict.final_score > 40
    assert verdict.country == "Germany"


def test_geo_info_to_dict():
    """GeoInfo serializes to expected dictionary schema."""
    geo = GeoInfo(
        ip="8.8.8.8",
        country="United States",
        country_code="US",
        city="Mountain View",
        isp="Google LLC",
        asn="AS15169",
        success=True,
    )
    d = geo.to_dict()
    assert d["ip"] == "8.8.8.8"
    assert d["country"] == "United States"
    assert d["city"] == "Mountain View"
    assert d["isp"] == "Google LLC"
    assert d["success"] is True
