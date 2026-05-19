import json
from pathlib import Path

from alert_model import Alert

SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def normalize_semgrep_severity(severity: str | None) -> str:
    if not severity:
        return "info"
    return SEMGREP_SEVERITY_MAP.get(severity.upper(), "info")


def extract_cwe(metadata: dict) -> str | None:
    cwe_list = metadata.get("cwe")
    if isinstance(cwe_list, list) and cwe_list:
        return cwe_list[0]
    return None


def parse_semgrep(file_path: Path) -> list[Alert]:
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    alerts: list[Alert] = []
    results = data.get("results", [])

    counter = 1

    for result in results:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        start = result.get("start", {})

        alert = Alert(
            id=f"semgrep-{counter}",
            tool="semgrep",
            category="code",
            rule_id=result.get("check_id"),
            title=extra.get("message") or result.get("check_id"),
            description=extra.get("message"),
            severity=normalize_semgrep_severity(extra.get("severity")),
            cve=None,
            cwe=extract_cwe(metadata),
            package_name=None,
            installed_version=None,
            fixed_version=None,
            file_path=result.get("path"),
            line=start.get("line"),
            raw_source=str(file_path),
            metadata={
                "start_col": start.get("col"),
                "end": result.get("end"),
                "metadata": metadata,
            },
        )
        alerts.append(alert)
        counter += 1

    return alerts
