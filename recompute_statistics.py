import argparse
import json
from pathlib import Path

from alert_model import Alert, DeduplicatedAlert
from statistics import generate_statistics


def _load_json(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array in {path}, got {type(data).__name__}")

    return data


def _load_raw_alerts(path: Path) -> list[Alert]:
    return [Alert(**item) for item in _load_json(path)]


def _load_deduplicated_alerts(path: Path) -> list[DeduplicatedAlert]:
    return [DeduplicatedAlert(**item) for item in _load_json(path)]


def _save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute statistics from existing normalized and deduplicated JSON "
            "without re-running scanners."
        )
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="WebGoat",
        help="Target name used in data file names (default: WebGoat)",
    )
    args = parser.parse_args()

    target = args.target
    normalized_path = Path(f"data/normalized/{target}-normalized.json")
    deduplicated_path = Path(f"data/deduplicated/{target}-deduplicated.json")
    report_path = Path(f"data/reports/{target}-statistics.json")

    if not normalized_path.exists():
        raise FileNotFoundError(f"Missing normalized file: {normalized_path}")
    if not deduplicated_path.exists():
        raise FileNotFoundError(f"Missing deduplicated file: {deduplicated_path}")

    raw_alerts = _load_raw_alerts(normalized_path)
    deduplicated_alerts = _load_deduplicated_alerts(deduplicated_path)

    stats = generate_statistics(raw_alerts, deduplicated_alerts)
    _save_json(report_path, stats)

    print(f"Recomputed statistics for {target}.")
    print(f"Report written to: {report_path}")
    print(f"Raw alerts: {len(raw_alerts)}")
    print(f"Deduplicated alerts: {len(deduplicated_alerts)}")


if __name__ == "__main__":
    main()
