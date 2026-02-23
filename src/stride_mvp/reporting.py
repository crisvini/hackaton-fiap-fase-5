from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .schemas import ArchitectureAnalysis, OutputArtifacts, ThreatReport


def render_markdown_report(
    architecture: ArchitectureAnalysis,
    threat_report: ThreatReport,
) -> str:
    severity_counts = Counter(t.severity for t in threat_report.threats)
    stride_counts = Counter(t.stride_category for t in threat_report.threats)

    lines: list[str] = []
    lines.append(f"# Relatorio de Modelagem de Ameacas - {threat_report.system_name}")
    lines.append("")
    lines.append(f"- Metodologia: {threat_report.methodology}")
    lines.append(f"- Gerado em (UTC): {threat_report.generated_at_utc}")
    lines.append(f"- Componentes identificados: {len(architecture.components)}")
    lines.append(f"- Fluxos identificados: {len(architecture.data_flows)}")
    lines.append(f"- Ameacas identificadas: {len(threat_report.threats)}")
    lines.append("")
    lines.append("## Resumo Executivo")
    lines.append("")
    lines.append(threat_report.executive_summary)
    lines.append("")
    lines.append("## Resumo de Risco")
    lines.append("")
    lines.append(
        "- Severidade: "
        + ", ".join(
            f"{sev}={severity_counts.get(sev, 0)}"
            for sev in ("critical", "high", "medium", "low")
        )
    )
    lines.append(
        "- STRIDE: "
        + ", ".join(
            f"{cat}={stride_counts.get(cat, 0)}"
            for cat in (
                "spoofing",
                "tampering",
                "repudiation",
                "information_disclosure",
                "denial_of_service",
                "elevation_of_privilege",
            )
        )
    )
    lines.append("")
    lines.append("## Arquitetura Extraida")
    lines.append("")
    lines.append(f"- Sistema: {architecture.system_name}")
    lines.append(f"- Resumo: {architecture.summary}")
    if architecture.assumptions:
        lines.append("- Hipoteses:")
        for item in architecture.assumptions:
            lines.append(f"  - {item}")
    if architecture.ambiguities:
        lines.append("- Ambiguidades:")
        for item in architecture.ambiguities:
            lines.append(f"  - {item}")
    lines.append("")
    lines.append("### Componentes")
    lines.append("")
    for c in architecture.components:
        lines.append(
            f"- `{c.id}` | {c.name} | kind=`{c.kind}` | trust_zone=`{c.trust_zone or '-'}'"
        )
    lines.append("")
    lines.append("### Fluxos")
    lines.append("")
    for f in architecture.data_flows:
        label = f" ({f.label})" if f.label else ""
        proto = f" [{f.protocol}]" if f.protocol else ""
        lines.append(f"- `{f.id}` | {f.source_id} -> {f.target_id}{label}{proto}")
    lines.append("")
    lines.append("## Ameacas STRIDE")
    lines.append("")
    for t in threat_report.threats:
        lines.append(f"### {t.id} - {t.title}")
        lines.append("")
        lines.append(
            f"- Categoria STRIDE: `{t.stride_category}` | Severidade: `{t.severity}` | "
            f"Probabilidade: `{t.likelihood}` | Impacto: `{t.impact}`"
        )
        if t.affected_component_ids:
            lines.append(
                "- Componentes afetados: " + ", ".join(f"`{x}`" for x in t.affected_component_ids)
            )
        if t.related_flow_ids:
            lines.append("- Fluxos relacionados: " + ", ".join(f"`{x}`" for x in t.related_flow_ids))
        lines.append(f"- Evidencia no diagrama: {t.evidence_from_diagram}")
        lines.append(f"- Cenario de ataque: {t.attack_scenario}")
        lines.append(f"- Impacto de negocio: {t.business_impact}")
        if t.vulnerabilities:
            lines.append("- Vulnerabilidades relacionadas:")
            for v in t.vulnerabilities:
                lines.append(f"  - {v}")
        if t.mitigations:
            lines.append("- Contramedidas:")
            for m in t.mitigations:
                lines.append(f"  - {m}")
        if t.detection_monitoring:
            lines.append("- Deteccao/monitoracao:")
            for d in t.detection_monitoring:
                lines.append(f"  - {d}")
        if t.residual_risk:
            lines.append(f"- Risco residual: {t.residual_risk}")
        lines.append("")
    if threat_report.prioritized_actions:
        lines.append("## Acoes Priorizadas")
        lines.append("")
        for action in threat_report.prioritized_actions:
            lines.append(f"- {action}")
        lines.append("")
    if threat_report.limitations:
        lines.append("## Limitacoes")
        lines.append("")
        for item in threat_report.limitations:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def save_outputs(
    output_dir: Path,
    architecture: ArchitectureAnalysis,
    threat_report: ThreatReport,
) -> OutputArtifacts:
    output_dir.mkdir(parents=True, exist_ok=True)

    architecture_path = output_dir / "architecture.json"
    threat_json_path = output_dir / "threat_report.json"
    threat_md_path = output_dir / "threat_report.md"

    architecture_path.write_text(
        json.dumps(architecture.model_dump(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    threat_json_path.write_text(
        json.dumps(threat_report.model_dump(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    threat_md_path.write_text(
        render_markdown_report(architecture, threat_report),
        encoding="utf-8",
    )

    return OutputArtifacts(
        architecture_json=str(architecture_path),
        threat_report_json=str(threat_json_path),
        threat_report_markdown=str(threat_md_path),
    )

