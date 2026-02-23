from __future__ import annotations

import base64
from pathlib import Path


def guess_mime_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".jpg", ".jpeg"}:
        return "image/jpeg"
    if suffix == ".png":
        return "image/png"
    if suffix == ".webp":
        return "image/webp"
    if suffix == ".gif":
        return "image/gif"
    raise ValueError(f"Formato de imagem nao suportado: {path.suffix}")


def to_data_url(path: Path) -> str:
    mime = guess_mime_type(path)
    raw = path.read_bytes()
    encoded = base64.b64encode(raw).decode("ascii")
    return f"data:{mime};base64,{encoded}"

