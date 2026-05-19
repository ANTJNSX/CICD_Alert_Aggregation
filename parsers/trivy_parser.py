import json
from pathlib import Path

from alert_model import Alert

TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def normalize_trivy_severity(severity: str | None) -> str:
    if not severity:
        return "info"
    return TRIVY_SEVERITY_MAP.get(severity.upper(), "info")


def parse_trivy(file_path: Path) -> list[Alert]:
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    alerts: list[Alert] = []
    results = data.get("Results", [])

    counter = 1

    for result in results:
        target = result.get("Target")
        vulnerabilities = result.get("Vulnerabilities", [])

        for vuln in vulnerabilities:
            alert = Alert(
                id=f"trivy-{counter}",
                tool="trivy",
                category="dependency",
                rule_id=vuln.get("VulnerabilityID"),
                title=vuln.get("Title") or vuln.get("VulnerabilityID"),
                description=vuln.get("Description"),
                severity=normalize_trivy_severity(vuln.get("Severity")),
                cve=vuln.get("VulnerabilityID"),
                cwe=None,
                package_name=vuln.get("PkgName"),
                installed_version=vuln.get("InstalledVersion"),
                fixed_version=vuln.get("FixedVersion"),
                file_path=target,
                line=None,
                raw_source=str(file_path),
                metadata={
                    "target": target,
                    "primary_url": vuln.get("PrimaryURL"),
                    "data_source": vuln.get("DataSource"),
                },
            )
            alerts.append(alert)
            counter += 1

    return alerts
