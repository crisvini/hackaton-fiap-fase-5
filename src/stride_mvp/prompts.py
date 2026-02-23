from __future__ import annotations

import json
from typing import Any


def architecture_extraction_system_prompt() -> str:
    return (
        "Voce e um especialista em arquitetura de software e modelagem de ameacas. "
        "Analise diagramas de arquitetura e extraia uma representacao estruturada em JSON. "
        "Se houver ambiguidade, registre em 'ambiguities' e use confianca menor."
    )


def architecture_extraction_user_prompt() -> str:
    return (
        "Analise a imagem do diagrama de arquitetura e responda APENAS com JSON valido. "
        "Identifique componentes, fluxos de dados e fronteiras de confianca. "
        "Use nomes de tipos padronizados em 'kind' como: user, web_app, api, "
        "auth_service, database, cache, queue, external_service, object_storage, "
        "load_balancer, gateway, worker, mobile_app, admin_console. "
        "Quando possivel, preencha 'bbox' com [x_min,y_min,x_max,y_max] normalizado (0-1). "
        "Nao invente detalhes tecnicos que nao estejam implicitos no diagrama; use 'assumptions' "
        "para hipoteses razoaveis. Em 'data_flows', referencia os componentes por id."
    )


def threat_generation_system_prompt() -> str:
    return (
        "Voce e um especialista senior em AppSec e threat modeling. "
        "Gere um relatorio STRIDE em portugues (pt-BR), com foco pratico, objetivo e acionavel. "
        "Responda APENAS com JSON valido."
    )


def threat_generation_user_prompt(
    architecture: dict[str, Any],
    kb_hints: dict[str, Any],
    max_threats: int = 24,
) -> str:
    return (
        "Com base na arquitetura abaixo, gere um relatorio STRIDE priorizado.\n\n"
        f"Limite de ameacas: {max_threats} (priorize risco realista e cobertura STRIDE).\n\n"
        "Arquitetura (JSON):\n"
        f"{json.dumps(architecture, ensure_ascii=False, indent=2)}\n\n"
        "Catalogo local de ameacas/mitigacoes por tipo de componente (use como referencia, "
        "sem copiar cegamente):\n"
        f"{json.dumps(kb_hints, ensure_ascii=False, indent=2)}\n\n"
        "Regras:\n"
        "1) Relacione cada ameaca a componentes e/ou fluxos existentes.\n"
        "2) Descreva cenario de ataque e impacto de negocio.\n"
        "3) Inclua mitigacoes tecnicas especificas e monitoracao.\n"
        "4) Indique limitacoes se o diagrama estiver ambiguo.\n"
        "5) Use ids de ameaca unicos como T-001, T-002, etc.\n"
        "6) Executive summary e acoes priorizadas devem ser objetivas.\n"
    )

