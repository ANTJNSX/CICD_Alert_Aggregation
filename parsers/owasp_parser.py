import json
import re
from pathlib import Path

from alert_model import Alert

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

OWASP_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
    "INFO": "info",
}


def normalize_owasp_severity(
    severity: str | None, cvss_score: float | None = None
) -> str:
    if severity:
        normalized = OWASP_SEVERITY_MAP.get(severity.upper())
        if normalized:
            return normalized

    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "critical"
        if cvss_score >= 7.0:
            return "high"
        if cvss_score >= 4.0:
            return "medium"
        return "low"

    return "info"


def extract_package_name(dependency: dict) -> str | None:
    packages = dependency.get("packages", [])
    if packages:
        pkg_id = packages[0].get("id")
        if pkg_id:
            return pkg_id

    return dependency.get("fileName") or dependency.get("filePath")


def extract_cvss_score(vulnerability: dict) -> float | None:
    cvssv3 = vulnerability.get("cvssv3")
    if isinstance(cvssv3, dict):
        score = cvssv3.get("baseScore")
        if isinstance(score, (int, float)):
            return float(score)

    cvssv2 = vulnerability.get("cvssv2")
    if isinstance(cvssv2, dict):
        score = cvssv2.get("score")
        if isinstance(score, (int, float)):
            return float(score)

    return None


def extract_cwe(vulnerability: dict) -> str | None:
    cwes = vulnerability.get("cwes", [])
    if cwes and isinstance(cwes, list):
        return cwes[0]
    return None


def extract_cve(vulnerability: dict) -> str | None:
    # OWASP `name` may be a CVE, GHSA, or free-text. Keep only normalized CVE IDs.
    for candidate in (vulnerability.get("name"), vulnerability.get("description")):
        if not isinstance(candidate, str):
            continue
        match = CVE_PATTERN.search(candidate)
        if match:
            return match.group(0).upper()
    return None


def parse_owasp(file_path: Path) -> list[Alert]:
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    alerts: list[Alert] = []
    dependencies = data.get("dependencies", [])

    counter = 1

    for dependency in dependencies:
        vulnerabilities = dependency.get("vulnerabilities", [])
        if not vulnerabilities:
            continue

        package_name = extract_package_name(dependency)
        file_path_value = dependency.get("fileName") or dependency.get("filePath")

        for vuln in vulnerabilities:
            cvss_score = extract_cvss_score(vuln)
            cve = extract_cve(vuln)

            alert = Alert(
                id=f"owasp-{counter}",
                tool="owasp",
                category="dependency",
                rule_id=vuln.get("name"),
                title=vuln.get("name"),
                description=vuln.get("description"),
                severity=normalize_owasp_severity(vuln.get("severity"), cvss_score),
                cve=cve,
                cwe=extract_cwe(vuln),
                package_name=package_name,
                installed_version=None,
                fixed_version=None,
                file_path=file_path_value,
                line=None,
                raw_source=str(file_path),
                metadata={
                    "cvss_score": cvss_score,
                    "owasp_vulnerability_name": vuln.get("name"),
                    "is_virtual": dependency.get("isVirtual"),
                    "file_path": dependency.get("filePath"),
                },
            )
            alerts.append(alert)
            counter += 1

    return alerts
