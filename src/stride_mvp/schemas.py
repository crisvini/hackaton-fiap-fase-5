from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["critical", "high", "medium", "low"]
Likelihood = Literal["high", "medium", "low"]
Impact = Literal["high", "medium", "low"]
StrideCategory = Literal[
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
]


class Component(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    kind: str = Field(description="Tipo de componente: api, database, user, queue, etc.")
    description: str | None = None
    technologies: list[str] = Field(default_factory=list)
    trust_zone: str | None = None
    exposed_to_internet: bool | None = None
    notes: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    bbox: list[float] | None = Field(
        default=None,
        description="Bounding box aproximado [x_min,y_min,x_max,y_max] normalizado (0-1).",
    )


class DataFlow(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    source_id: str
    target_id: str
    label: str | None = None
    protocol: str | None = None
    data_types: list[str] = Field(default_factory=list)
    auth_mechanism: str | None = None
    encryption: str | None = None
    trust_boundary_crossing: bool | None = None
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class TrustBoundary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    description: str | None = None
    component_ids: list[str] = Field(default_factory=list)


class ArchitectureAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")

    system_name: str = "Sistema analisado"
    summary: str
    components: list[Component] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    ambiguities: list[str] = Field(default_factory=list)
    overall_confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class ThreatItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    title: str
    stride_category: StrideCategory
    severity: Severity
    likelihood: Likelihood
    impact: Impact
    affected_component_ids: list[str] = Field(default_factory=list)
    related_flow_ids: list[str] = Field(default_factory=list)
    attack_scenario: str
    business_impact: str
    evidence_from_diagram: str
    vulnerabilities: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    detection_monitoring: list[str] = Field(default_factory=list)
    residual_risk: str | None = None


class ThreatReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    system_name: str
    executive_summary: str
    threats: list[ThreatItem] = Field(default_factory=list)
    prioritized_actions: list[str] = Field(default_factory=list)
    generated_at_utc: str = Field(default_factory=lambda: utc_now_iso())
    methodology: str = "STRIDE"
    limitations: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class OutputArtifacts(BaseModel):
    model_config = ConfigDict(extra="ignore")

    architecture_json: str
    threat_report_json: str
    threat_report_markdown: str


class PipelineResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    architecture: ArchitectureAnalysis
    threat_report: ThreatReport
    artifacts: OutputArtifacts


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

