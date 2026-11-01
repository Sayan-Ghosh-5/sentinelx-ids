"""Tests for Alert Notification channels, rate limiting, and severity filtering."""

import pytest

from alerts.notifier import (
    _above_threshold,
    _is_rate_limited,
    _record,
    get_notification_history,
    notify_alert,
)


def test_alert_severity_threshold():
    """Verify threshold filtering for alerts."""
    assert _above_threshold("critical", "medium") is True
    assert _above_threshold("high", "high") is True
    assert _above_threshold("low", "medium") is False
    assert _above_threshold("info", "low") is False


def test_alert_rate_limiting():
    """Rate limiter allows the first alert for an IP and throttles subsequent alerts within window."""
    ip = "192.0.2.199"
    # First alert should pass
    assert _is_rate_limited(ip) is False
    # Second immediate alert for same IP should be rate limited
    assert _is_rate_limited(ip) is True
    # Different IP should not be rate limited
    assert _is_rate_limited("192.0.2.201") is False


def test_notification_history():
    """Notification history records channel dispatches and returns buffered entries."""
    _record("slack", "sent", "SSH Brute Force", "Delivered to #soc-alerts")
    history = get_notification_history()
    assert len(history) > 0
    assert any(h["alert_title"] == "SSH Brute Force" for h in history)


@pytest.mark.asyncio
async def test_notify_alert_skips_below_threshold():
    """notify_alert skips dispatch when alert severity is below configured threshold."""
    alert = {
        "title": "Low Priority Scan",
        "severity": "info",
        "source_ip": "10.0.0.99",
    }
    result = await notify_alert(alert, min_severity="high")
    assert result["skipped"] is True
    assert "below threshold" in result["reason"]
