from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from openai import AuthenticationError, OpenAI

from .config import Settings
from .image_utils import to_data_url


class LLMClientError(RuntimeError):
    pass


class OpenAIJsonClient:
    def __init__(self, settings: Settings):
        settings.require_openai_key()
        kwargs: dict[str, Any] = {"api_key": settings.openai_api_key}
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url
        self._client = OpenAI(**kwargs)

    def validate_api_key(self) -> None:
        """Valida rapidamente a chave da OpenAI antes do processamento pesado."""
        try:
            # Requisicao leve para confirmar autenticacao.
            self._client.models.list()
        except AuthenticationError as exc:  # pragma: no cover - network/runtime behavior
            raise LLMClientError(
                "OPENAI_API_KEY invalida ou sem permissao. Verifique a chave cadastrada no arquivo .env."
            ) from exc
        except Exception as exc:  # pragma: no cover - network/runtime behavior
            raise LLMClientError(
                f"Nao foi possivel validar a OPENAI_API_KEY neste momento: {exc}"
            ) from exc

    def complete_json(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        image_path: Path | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        if image_path:
            user_content: list[dict[str, Any]] = [
                {"type": "text", "text": user_prompt},
                {"type": "image_url", "image_url": {"url": to_data_url(image_path)}},
            ]
            messages: list[dict[str, Any]] = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ]
        else:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]

        try:
            response = self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                response_format={"type": "json_object"},
            )
        except AuthenticationError as exc:  # pragma: no cover - network/runtime behavior
            raise LLMClientError(
                "OPENAI_API_KEY invalida ou sem permissao. Verifique a chave cadastrada no arquivo .env."
            ) from exc
        except Exception as exc:  # pragma: no cover - network/runtime behavior
            raise LLMClientError(f"Falha na chamada OpenAI: {exc}") from exc

        content = _extract_message_content(response)
        json_text = _strip_code_fences(content)
        try:
            return json.loads(json_text)
        except json.JSONDecodeError as exc:
            raise LLMClientError(
                f"Resposta do modelo nao veio em JSON valido: {exc}"
            ) from exc


def _extract_message_content(response: Any) -> str:
    try:
        message = response.choices[0].message
        content = message.content
    except Exception as exc:  # pragma: no cover - defensive
        raise LLMClientError(f"Formato de resposta inesperado: {exc}") from exc

    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") in {"text", "output_text"}:
                if item.get("text"):
                    chunks.append(str(item["text"]))
        if chunks:
            return "\n".join(chunks)
    raise LLMClientError("Resposta sem conteudo textual.")


def _strip_code_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped
