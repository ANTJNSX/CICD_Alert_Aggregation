from collections import defaultdict

from alert_model import Alert, DeduplicatedAlert

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _highest_severity(severities: list[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


def _canonical_dependency_name(package_name: str) -> str:
    value = package_name.strip().lower()

    # Normalize purl-style package identifiers (e.g. pkg:maven/g:a@1.0, pkg:javascript/jquery@3.7.1)
    if value.startswith("pkg:"):
        core = value[4:]
        if "/" in core:
            _, core = core.split("/", 1)
        if "?" in core:
            core = core.split("?", 1)[0]
        if "#" in core:
            core = core.split("#", 1)[0]
        if "@" in core:
            core = core.split("@", 1)[0]
        value = core

    # Strip trailing version suffixes for non purl names like `jquery@1.10.2.min`.
    if "@" in value and ":" not in value:
        value = value.split("@", 1)[0]

    return value


def _dependency_dedup_key(alert: Alert) -> str | None:
    if alert.category != "dependency":
        return None
    if not alert.package_name or not alert.cve:
        return None
    package = _canonical_dependency_name(alert.package_name)
    return f"{package}::{alert.cve.upper()}"


def _code_dedup_key(alert: Alert) -> str | None:
    if alert.category != "code":
        return None
    # For now, keep Semgrep findings distinct unless you later add more code tools
    if not alert.file_path or alert.line is None or not alert.rule_id:
        return None
    return f"{alert.file_path}:{alert.line}:{alert.rule_id}"


def deduplicate_alerts(alerts: list[Alert]) -> list[DeduplicatedAlert]:
    grouped: dict[str, list[Alert]] = defaultdict(list)
    unique_alerts: list[Alert] = []

    for alert in alerts:
        if alert.category == "dependency":
            key = _dependency_dedup_key(alert)
        elif alert.category == "code":
            key = _code_dedup_key(alert)
        else:
            key = None

        if key is None:
            unique_alerts.append(alert)
        else:
            grouped[key].append(alert)

    deduplicated: list[DeduplicatedAlert] = []

    # Merge grouped alerts
    for key, group in grouped.items():
        first = group[0]
        merged = DeduplicatedAlert(
            dedup_id=key,
            category=first.category,
            title=first.title,
            description=first.description,
            severity=_highest_severity([a.severity for a in group]),
            cve=first.cve,
            cwe=first.cwe,
            package_name=first.package_name,
            installed_version=first.installed_version,
            fixed_version=first.fixed_version,
            file_path=first.file_path,
            line=first.line,
            tools=sorted({a.tool for a in group}),
            source_alert_ids=[a.id for a in group],
            metadata={"group_size": len(group)},
        )
        deduplicated.append(merged)

    # Keep ungrouped alerts as one-to-one deduplicated alerts
    for alert in unique_alerts:
        deduplicated.append(
            DeduplicatedAlert(
                dedup_id=alert.id,
                category=alert.category,
                title=alert.title,
                description=alert.description,
                severity=alert.severity,
                cve=alert.cve,
                cwe=alert.cwe,
                package_name=alert.package_name,
                installed_version=alert.installed_version,
                fixed_version=alert.fixed_version,
                file_path=alert.file_path,
                line=alert.line,
                tools=[alert.tool],
                source_alert_ids=[alert.id],
                metadata={"group_size": 1},
            )
        )

    return deduplicated
