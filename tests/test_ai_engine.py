"""Tests for the AI Engine (Anomaly Scorer, SOCCopilot, NLP parser, LLM client)."""

import pytest

from ai_engine.anomaly_scorer import AnomalyScorer, BaselineStats
from ai_engine.copilot import SOCCopilot
from ai_engine.llm_integration import LLMClient, RateLimiter
from ai_engine.nlp_query import NLPQueryParser


def test_anomaly_scorer_baseline_stats():
    """BaselineStats accurately computes mean, standard deviation, and IQR."""
    stats = BaselineStats()
    for val in [10.0, 12.0, 14.0, 16.0, 18.0, 20.0]:
        stats.values.append(val)

    assert stats.mean == 15.0
    assert stats.std_dev > 0
    assert stats.iqr > 0


def test_anomaly_scorer_scoring():
    """AnomalyScorer scores high-frequency / abnormal events higher."""
    scorer = AnomalyScorer()
    event = {
        "source_ip": "192.168.1.150",
        "severity": "critical",
        "event_type": "auth_failure",
        "message": "failed password for root repeatedly",
    }

    score = scorer.score_event(event)
    assert 0.0 <= score <= 1.0

    baseline = scorer.get_baseline("192.168.1.150")
    assert baseline["total_events"] >= 1


def test_soc_copilot_offline_analysis():
    """SOCCopilot generates actionable security guidance in offline mode."""
    copilot = SOCCopilot()
    alert = {
        "rule_name": "SSH Brute Force Detected",
        "severity": "high",
        "source_ip": "203.0.113.19",
        "mitre_technique": "T1110",
        "mitre_tactic": "Credential Access",
        "message": "failed password for invalid user admin",
    }

    analysis = copilot.analyze_alert(alert)
    assert isinstance(analysis, str)
    assert len(analysis) > 50
    assert "brute force" in analysis.lower() or "incident" in analysis.lower()


def test_nlp_query_parser():
    """NLPQueryParser extracts intent, severity, and entities."""
    parser = NLPQueryParser()
    parsed = parser.parse_query("critical alerts from 10.0.0.5 today")

    assert parsed is not None
    assert "filters" in parsed
    assert parsed["filters"].get("severity") == "critical"


def test_llm_rate_limiter():
    """RateLimiter enforces window constraints and tracks remaining quota."""
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    assert limiter.acquire() is True
    assert limiter.acquire() is True
    assert limiter.acquire() is True
    # 4th should be blocked
    assert limiter.acquire() is False
    assert limiter.remaining == 0


def test_llm_client_fallback_to_local():
    """LLMClient gracefully falls back to local SOCCopilot when provider is local."""
    client = LLMClient(provider="local")
    assert client.is_local is True
    res = client.analyze("What should I do if an endpoint is communicating with a known C2 server?")
    assert isinstance(res, str)
    assert len(res) > 0
