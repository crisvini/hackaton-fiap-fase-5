from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(slots=True)
class Settings:
    openai_api_key: str | None
    openai_model_vision: str = "gpt-4.1-mini"
    openai_model_threats: str = "gpt-4.1-mini"
    openai_base_url: str | None = None
    report_language: str = "pt-BR"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        return cls(
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            openai_model_vision=os.getenv("OPENAI_MODEL_VISION", "gpt-4.1-mini"),
            openai_model_threats=os.getenv("OPENAI_MODEL_THREATS", "gpt-4.1-mini"),
            openai_base_url=os.getenv("OPENAI_BASE_URL") or None,
        )

    def require_openai_key(self) -> None:
        if not self.openai_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY nao configurada. Defina no ambiente ou em .env."
            )


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]

