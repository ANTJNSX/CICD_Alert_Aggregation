from typing import Iterable

from alert_model import Alert


def aggregate_alerts(alert_collections: Iterable[list[Alert]]) -> list[Alert]:
    aggregated: list[Alert] = []

    for collection in alert_collections:
        for alert in collection:
            if not isinstance(alert, Alert):
                raise TypeError(f"Expected Alert instance, got {type(alert).__name__}")
            aggregated.append(alert)

    return aggregated
