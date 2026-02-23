from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .config import Settings
from .kb import build_kb_hints, load_catalog, normalize_kind
from .openai_client import LLMClientError, OpenAIJsonClient
from .prompts import (
    architecture_extraction_system_prompt,
    architecture_extraction_user_prompt,
    threat_generation_system_prompt,
    threat_generation_user_prompt,
)
from .reporting import save_outputs
from .schemas import (
    ArchitectureAnalysis,
    PipelineResult,
    ThreatItem,
    ThreatReport,
    utc_now_iso,
)


class ThreatModelPipeline:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._llm = OpenAIJsonClient(settings) if settings.openai_api_key else None

    def extract_architecture(self, image_path: Path) -> ArchitectureAnalysis:
        if not image_path.exists():
            raise FileNotFoundError(f"Imagem nao encontrada: {image_path}")
        if not self._llm:
            raise RuntimeError(
                "OPENAI_API_KEY e obrigatoria para extrair arquitetura a partir de imagem."
            )

        raw = self._llm.complete_json(
            model=self.settings.openai_model_vision,
            system_prompt=architecture_extraction_system_prompt(),
            user_prompt=architecture_extraction_user_prompt(),
            image_path=image_path,
            temperature=0.0,
        )
        return _validate_architecture(raw)

    def load_architecture_json(self, path: Path) -> ArchitectureAnalysis:
        data = json.loads(path.read_text(encoding="utf-8"))
        return _validate_architecture(data)

    def generate_threat_report(
        self,
        architecture: ArchitectureAnalysis,
        *,
        use_llm: bool = True,
    ) -> ThreatReport:
        kb_hints = build_kb_hints(architecture)

        if use_llm and self._llm:
            try:
                raw = self._llm.complete_json(
                    model=self.settings.openai_model_threats,
                    system_prompt=threat_generation_system_prompt(),
                    user_prompt=threat_generation_user_prompt(
                        architecture=architecture.model_dump(),
                        kb_hints=kb_hints,
                    ),
                    temperature=0.0,
                )
                report = _validate_threat_report(raw, fallback_system_name=architecture.system_name)
                if not report.limitations and architecture.ambiguities:
                    report.limitations = [
                        "O diagrama possui ambiguidades; valide manualmente os pontos destacados."
                    ]
                if "Catálogo local de componentes STRIDE (kb/stride_component_catalog.yaml)" not in report.sources:
                    report.sources.append(
                        "Catalogo local de componentes STRIDE (kb/stride_component_catalog.yaml)"
                    )
                return _sort_and_normalize_report(report)
            except (LLMClientError, ValidationError, RuntimeError, ValueError):
                pass

        return self._generate_threat_report_fallback(architecture, kb_hints)

    def analyze_image(
        self,
        image_path: Path,
        *,
        output_dir: Path,
        use_llm_threats: bool = True,
    ) -> PipelineResult:
        architecture = self.extract_architecture(image_path)
        threat_report = self.generate_threat_report(architecture, use_llm=use_llm_threats)
        artifacts = save_outputs(output_dir, architecture, threat_report)
        return PipelineResult(
            architecture=architecture,
            threat_report=threat_report,
            artifacts=artifacts,
        )

    def analyze_architecture(
        self,
        architecture: ArchitectureAnalysis,
        *,
        output_dir: Path,
        use_llm_threats: bool = True,
    ) -> PipelineResult:
        threat_report = self.generate_threat_report(architecture, use_llm=use_llm_threats)
        artifacts = save_outputs(output_dir, architecture, threat_report)
        return PipelineResult(
            architecture=architecture,
            threat_report=threat_report,
            artifacts=artifacts,
        )

    def _generate_threat_report_fallback(
        self,
        architecture: ArchitectureAnalysis,
        kb_hints: dict[str, Any],
    ) -> ThreatReport:
        catalog = load_catalog().get("components", {})
        flow_index: dict[str, list[str]] = {}
        for flow in architecture.data_flows:
            flow_index.setdefault(flow.source_id, []).append(flow.id)
            flow_index.setdefault(flow.target_id, []).append(flow.id)

        threats: list[ThreatItem] = []
        counter = 1

        for comp in architecture.components:
            kind = normalize_kind(comp.kind)
            entry = catalog.get(kind, {})
            stride_entries = entry.get("stride", {})
            for stride_category, details in stride_entries.items():
                vulnerabilities = list(details.get("vulnerabilities", []))
                mitigations = list(details.get("mitigations", []))
                if not vulnerabilities and not mitigations:
                    continue

                severity = _fallback_severity(stride_category, comp.exposed_to_internet)
                likelihood = "medium" if comp.exposed_to_internet else "low"
                impact = "high" if stride_category in {
                    "information_disclosure",
                    "elevation_of_privilege",
                    "denial_of_service",
                } else "medium"

                threats.append(
                    ThreatItem(
                        id=f"T-{counter:03d}",
                        title=f"{_stride_title_pt(stride_category)} em {comp.name}",
                        stride_category=stride_category,  # type: ignore[arg-type]
                        severity=severity,
                        likelihood=likelihood,  # type: ignore[arg-type]
                        impact=impact,  # type: ignore[arg-type]
                        affected_component_ids=[comp.id],
                        related_flow_ids=flow_index.get(comp.id, [])[:3],
                        attack_scenario=(
                            f"Um atacante explora fragilidades tipicas de {kind} para "
                            f"comprometer {comp.name} e afetar o fluxo do sistema."
                        ),
                        business_impact=(
                            "Pode causar indisponibilidade, vazamento de dados ou acesso "
                            "indevido dependendo do componente e dos dados tratados."
                        ),
                        evidence_from_diagram=(
                            f"Componente identificado como '{comp.kind}'"
                            + (" exposto externamente" if comp.exposed_to_internet else "")
                            + "."
                        ),
                        vulnerabilities=vulnerabilities[:3],
                        mitigations=mitigations[:4],
                        detection_monitoring=[
                            "Logs estruturados com correlation-id e alertas para falhas/autorizacao.",
                            "Monitorar taxa de erro, latencia e picos de chamadas.",
                        ],
                        residual_risk="Requer validacao manual apos confirmar detalhes de configuracao.",
                    )
                )
                counter += 1
                if counter > 24:
                    break
            if counter > 24:
                break

        prioritized_actions = _build_prioritized_actions_from_kb(kb_hints)
        limitations = []
        if architecture.ambiguities:
            limitations.append(
                "A extracao da arquitetura contem ambiguidades; valide componentes, fluxos e trust boundaries manualmente."
            )
        limitations.append(
            "Relatorio gerado em modo fallback (catalogo local) para as ameacas; revise severidades e cenarios."
        )

        report = ThreatReport(
            system_name=architecture.system_name,
            executive_summary=(
                f"Foram identificadas {len(threats)} ameacas potenciais com base no diagrama "
                "e em um catalogo STRIDE local por tipo de componente. Priorize validacao de "
                "autenticacao/autorizacao, protecao de dados e resiliencia dos fluxos criticos."
            ),
            threats=threats,
            prioritized_actions=prioritized_actions[:10],
            limitations=limitations,
            sources=["Catalogo local de componentes STRIDE (kb/stride_component_catalog.yaml)"],
            generated_at_utc=utc_now_iso(),
        )
        return _sort_and_normalize_report(report)


def _validate_architecture(data: dict[str, Any]) -> ArchitectureAnalysis:
    data = _normalize_architecture_payload(data)
    try:
        return ArchitectureAnalysis.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"JSON de arquitetura invalido: {exc}") from exc


def _validate_threat_report(
    data: dict[str, Any],
    *,
    fallback_system_name: str,
) -> ThreatReport:
    data = dict(data)
    data.setdefault("system_name", fallback_system_name)
    data.setdefault("methodology", "STRIDE")
    data.setdefault("generated_at_utc", utc_now_iso())
    report = ThreatReport.model_validate(data)
    return report


def _severity_order(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(value, 99)


def _sort_and_normalize_report(report: ThreatReport) -> ThreatReport:
    report.threats = sorted(
        report.threats,
        key=lambda t: (_severity_order(t.severity), t.stride_category, t.id),
    )
    if not report.generated_at_utc:
        report.generated_at_utc = utc_now_iso()
    return report


def _fallback_severity(stride_category: str, internet_exposed: bool | None) -> str:
    if stride_category == "elevation_of_privilege":
        return "high"
    if stride_category == "information_disclosure":
        return "high" if internet_exposed else "medium"
    if stride_category == "denial_of_service":
        return "high" if internet_exposed else "medium"
    if stride_category in {"spoofing", "tampering"}:
        return "high" if internet_exposed else "medium"
    return "medium"


def _stride_title_pt(category: str) -> str:
    mapping = {
        "spoofing": "Falsificacao de identidade",
        "tampering": "Manipulacao de dados",
        "repudiation": "Repudio / ausencia de rastreabilidade",
        "information_disclosure": "Divulgacao de informacoes",
        "denial_of_service": "Negacao de servico",
        "elevation_of_privilege": "Elevacao de privilegio",
    }
    return mapping.get(category, category)


def _build_prioritized_actions_from_kb(kb_hints: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    for item in kb_hints.get("components", {}).values():
        catalog_entry = item.get("catalog_entry", {})
        for stride_info in (catalog_entry.get("stride") or {}).values():
            for mitigation in stride_info.get("mitigations", []):
                if mitigation not in seen:
                    seen.add(mitigation)
                    actions.append(mitigation)
    if not actions:
        actions = [
            "Validar autenticacao, autorizacao e segredos em todos os fluxos expostos.",
            "Habilitar logs estruturados e monitoracao com alertas para eventos criticos.",
            "Aplicar criptografia em transito e revisar segmentacao de rede/trust boundaries.",
        ]
    return actions


def _normalize_architecture_payload(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        return data

    normalized = dict(data)
    components = normalized.get("components") or []
    data_flows = normalized.get("data_flows") or []

    if "summary" not in normalized or not normalized.get("summary"):
        normalized["summary"] = (
            f"Arquitetura extraida com {len(components)} componentes e {len(data_flows)} fluxos."
        )

    if "system_name" not in normalized or not normalized.get("system_name"):
        normalized["system_name"] = "Sistema analisado"

    normalized_flows: list[dict[str, Any]] = []
    for idx, raw_flow in enumerate(data_flows, 1):
        if not isinstance(raw_flow, dict):
            continue
        flow = dict(raw_flow)

        # Compatibilidade com respostas do modelo que usam source/target.
        if "source_id" not in flow and "source" in flow:
            flow["source_id"] = flow.get("source")
        if "target_id" not in flow and "target" in flow:
            flow["target_id"] = flow.get("target")
        if "source_id" not in flow and "from" in flow:
            flow["source_id"] = flow.get("from")
        if "target_id" not in flow and "to" in flow:
            flow["target_id"] = flow.get("to")
        if "label" not in flow and "description" in flow:
            flow["label"] = flow.get("description")
        if "id" not in flow or not flow.get("id"):
            flow["id"] = f"F{idx}"

        normalized_flows.append(flow)
    normalized["data_flows"] = normalized_flows

    normalized_components: list[dict[str, Any]] = []
    for idx, raw_component in enumerate(components, 1):
        if not isinstance(raw_component, dict):
            continue
        comp = dict(raw_component)
        if "id" not in comp or not comp.get("id"):
            comp["id"] = f"C{idx}"
        if "name" not in comp or not comp.get("name"):
            comp["name"] = comp.get("id", f"Componente {idx}")
        if "kind" not in comp or not comp.get("kind"):
            comp["kind"] = "unknown"
        normalized_components.append(comp)
    normalized["components"] = normalized_components

    if "trust_boundaries" not in normalized or normalized.get("trust_boundaries") is None:
        normalized["trust_boundaries"] = []

    if "assumptions" not in normalized or normalized.get("assumptions") is None:
        normalized["assumptions"] = []

    if "ambiguities" not in normalized or normalized.get("ambiguities") is None:
        normalized["ambiguities"] = []

    return normalized
