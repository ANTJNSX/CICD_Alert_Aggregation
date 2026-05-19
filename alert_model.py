from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Alert:
    id: str
    tool: str
    category: str  # e.g. "dependency" or "code"
    rule_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    severity: str = "info"  # normalized: critical/high/medium/low/info
    cve: Optional[str] = None
    cwe: Optional[str] = None
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    raw_source: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DeduplicatedAlert:
    dedup_id: str
    category: str
    title: Optional[str]
    description: Optional[str]
    severity: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    tools: list[str] = field(default_factory=list)
    source_alert_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
