import json
from pathlib import Path

from aggregator import aggregate_alerts
from deduplicator import deduplicate_alerts
from parsers import PARSER_REGISTRY
from statistics import generate_statistics


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main() -> None:
    input_files = {
        "trivy": Path("ScanOutputs/WebGoat/trivy.json"),
        "owasp": Path("ScanOutputs/WebGoat/dependency-check-report.json"),
        "semgrep": Path("ScanOutputs/WebGoat/semgrep.json"),
        "snyk": Path("ScanOutputs/WebGoat/snyk.json"),
    }

    parsed_alert_groups = []

    for tool_name, file_path in input_files.items():
        parser = PARSER_REGISTRY.get(tool_name)
        if parser is None:
            raise ValueError(f"No parser registered for tool '{tool_name}'")

        if not file_path.exists():
            if tool_name == "snyk":
                # Snyk output is optional in the current scan workflow.
                continue
            raise FileNotFoundError(f"Input file not found: {file_path}")

        alerts = parser(file_path)
        parsed_alert_groups.append(alerts)

    raw_alerts = aggregate_alerts(parsed_alert_groups)
    deduplicated_alerts = deduplicate_alerts(raw_alerts)
    stats = generate_statistics(raw_alerts, deduplicated_alerts)

    save_json(
        Path("data/normalized/WebGoat-normalized.json"),
        [alert.to_dict() for alert in raw_alerts],
    )
    save_json(
        Path("data/deduplicated/WebGoat-deduplicated.json"),
        [alert.to_dict() for alert in deduplicated_alerts],
    )
    save_json(
        Path("data/reports/WebGoat-statistics.json"),
        stats,
    )

    print("Pipeline completed successfully.")
    print(f"Raw alerts: {len(raw_alerts)}")
    print(f"Deduplicated alerts: {len(deduplicated_alerts)}")
    print(f"Duplicates removed: {stats['deduplication_summary']['duplicates_removed']}")


if __name__ == "__main__":
    main()
