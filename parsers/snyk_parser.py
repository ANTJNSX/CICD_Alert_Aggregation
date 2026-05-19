import json
from pathlib import Path

from alert_model import Alert

SNYK_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def normalize_snyk_severity(severity: str | None) -> str:
    if not severity:
        return "info"
    return SNYK_SEVERITY_MAP.get(severity.lower(), "info")


def _extract_project_entries(data):
    """
    Snyk JSON may be:
    - a single project result object
    - a list of project result objects
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _extract_vulnerabilities(project: dict) -> list[dict]:
    """
    Snyk Open Source JSON commonly stores issues in `vulnerabilities`.
    """
    vulns = project.get("vulnerabilities", [])
    if isinstance(vulns, list):
        return vulns
    return []


def _extract_package_name(vuln: dict) -> str | None:
    return vuln.get("packageName") or vuln.get("name")


def _extract_installed_version(vuln: dict) -> str | None:
    return vuln.get("version")


def _extract_fixed_version(vuln: dict) -> str | None:
    fixed = vuln.get("fixedIn")
    if isinstance(fixed, list) and fixed:
        return ", ".join(str(x) for x in fixed)
    if isinstance(fixed, str):
        return fixed
    return None


def _extract_rule_id(vuln: dict) -> str | None:
    identifiers = vuln.get("identifiers", {})
    cves = identifiers.get("CVE", [])
    if isinstance(cves, list) and cves:
        return cves[0]
    return vuln.get("id")


def _extract_cve(vuln: dict) -> str | None:
    identifiers = vuln.get("identifiers", {})
    cves = identifiers.get("CVE", [])
    if isinstance(cves, list) and cves:
        return cves[0]
    return None


def _extract_cwe(vuln: dict) -> str | None:
    identifiers = vuln.get("identifiers", {})
    cwes = identifiers.get("CWE", [])
    if isinstance(cwes, list) and cwes:
        return cwes[0]
    return None


def _extract_file_path(project: dict) -> str | None:
    return project.get("displayTargetFile") or project.get("targetFile")


def parse_snyk(file_path: Path) -> list[Alert]:
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    alerts: list[Alert] = []
    projects = _extract_project_entries(data)

    counter = 1

    for project in projects:
        target_file = _extract_file_path(project)
        vulnerabilities = _extract_vulnerabilities(project)

        for vuln in vulnerabilities:
            alert = Alert(
                id=f"snyk-{counter}",
                tool="snyk",
                category="dependency",
                rule_id=_extract_rule_id(vuln),
                title=vuln.get("title") or vuln.get("id"),
                description=vuln.get("description"),
                severity=normalize_snyk_severity(vuln.get("severity")),
                cve=_extract_cve(vuln),
                cwe=_extract_cwe(vuln),
                package_name=_extract_package_name(vuln),
                installed_version=_extract_installed_version(vuln),
                fixed_version=_extract_fixed_version(vuln),
                file_path=target_file,
                line=None,
                raw_source=str(file_path),
                metadata={
                    "project_name": project.get("packageManager"),
                    "target_file": target_file,
                    "from": vuln.get("from"),
                    "upgrade_path": vuln.get("upgradePath"),
                    "is_upgradable": vuln.get("isUpgradable"),
                    "is_patchable": vuln.get("isPatchable"),
                    "snyk_id": vuln.get("id"),
                },
            )
            alerts.append(alert)
            counter += 1

    return alerts
