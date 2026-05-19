from collections import Counter

from alert_model import Alert, DeduplicatedAlert


def _count_by_tool(alerts: list[Alert]) -> dict[str, int]:
    return dict(Counter(alert.tool for alert in alerts))


def _count_by_category_raw(alerts: list[Alert]) -> dict[str, int]:
    return dict(Counter(alert.category for alert in alerts))


def _count_by_category_dedup(alerts: list[DeduplicatedAlert]) -> dict[str, int]:
    return dict(Counter(alert.category for alert in alerts))


def _count_by_severity_raw(alerts: list[Alert]) -> dict[str, int]:
    return dict(Counter(alert.severity for alert in alerts))


def _count_by_severity_dedup(alerts: list[DeduplicatedAlert]) -> dict[str, int]:
    return dict(Counter(alert.severity for alert in alerts))


def generate_statistics(
    raw_alerts: list[Alert],
    deduplicated_alerts: list[DeduplicatedAlert],
) -> dict:
    return {
        "before_deduplication": {
            "total_alerts": len(raw_alerts),
            "by_tool": _count_by_tool(raw_alerts),
            "by_category": _count_by_category_raw(raw_alerts),
            "by_severity": _count_by_severity_raw(raw_alerts),
        },
        "after_deduplication": {
            "total_alerts": len(deduplicated_alerts),
            "by_category": _count_by_category_dedup(deduplicated_alerts),
            "by_severity": _count_by_severity_dedup(deduplicated_alerts),
        },
        "deduplication_summary": {
            "duplicates_removed": len(raw_alerts) - len(deduplicated_alerts),
        },
    }
