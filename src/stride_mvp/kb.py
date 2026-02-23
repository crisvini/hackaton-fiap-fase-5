from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .config import repo_root
from .schemas import ArchitectureAnalysis


KB_PATH = repo_root() / "kb" / "stride_component_catalog.yaml"


def normalize_kind(kind: str) -> str:
    text = (kind or "").strip().lower()
    text = text.replace("-", "_").replace(" ", "_")
    text = re.sub(r"[^a-z0-9_]", "", text)
    aliases = {
        "frontend": "web_app",
        "ui": "web_app",
        "web": "web_app",
        "browser": "web_app",
        "service": "api",
        "backend": "api",
        "microservice": "api",
        "db": "database",
        "sql": "database",
        "nosql": "database",
        "mq": "queue",
        "message_broker": "queue",
        "user_client": "user",
        "client": "user",
        "s3": "object_storage",
        "storage": "object_storage",
        "third_party": "external_service",
        "third_party_api": "external_service",
        "identity_provider": "auth_service",
        "idp": "auth_service",
    }
    return aliases.get(text, text)


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    if not KB_PATH.exists():
        raise FileNotFoundError(f"Catalogo KB nao encontrado em {KB_PATH}")
    with KB_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("Catalogo KB invalido.")
    return data


def build_kb_hints(architecture: ArchitectureAnalysis) -> dict[str, Any]:
    catalog = load_catalog()
    component_catalog = catalog.get("components", {})
    hints: dict[str, Any] = {"components": {}, "global_notes": catalog.get("global_notes", [])}

    for component in architecture.components:
        normalized = normalize_kind(component.kind)
        entry = component_catalog.get(normalized)
        if entry:
            hints["components"][component.id] = {
                "component_name": component.name,
                "component_kind": normalized,
                "catalog_entry": entry,
            }
    return hints

