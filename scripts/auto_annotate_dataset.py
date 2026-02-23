from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from stride_mvp.config import Settings
from stride_mvp.pipeline import ThreatModelPipeline


SUPPORTED_EXTS = {".png", ".jpg", ".jpeg", ".webp"}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Auto-anota imagens de diagramas usando OpenAI Vision e salva JSONs "
            "com componentes, tipos e bbox aproximados (quando disponiveis)."
        )
    )
    parser.add_argument("--input-dir", required=True, help="Pasta com imagens do dataset.")
    parser.add_argument(
        "--output-dir",
        default="outputs/dataset_annotations",
        help="Pasta para salvar anotacoes JSON.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Pula arquivos ja anotados.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    settings = Settings.from_env()
    if not settings.openai_api_key:
        print(
            "Erro: OPENAI_API_KEY nao configurada. Crie o arquivo .env com as variaveis do .env.example e informe uma chave valida da OpenAI.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    pipeline = ThreatModelPipeline(settings)
    try:
        pipeline.validate_openai_api_key()
    except Exception as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        raise SystemExit(1)

    images = sorted(
        p for p in input_dir.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_EXTS
    )
    if not images:
        raise SystemExit("Nenhuma imagem encontrada no diretorio informado.")

    for img in images:
        out_path = output_dir / f"{img.stem}.annotation.json"
        if args.skip_existing and out_path.exists():
            print(f"[skip] {img.name}")
            continue

        architecture = pipeline.extract_architecture(img)
        payload = {
            "image": str(img),
            "system_name": architecture.system_name,
            "summary": architecture.summary,
            "components": [
                {
                    "id": c.id,
                    "name": c.name,
                    "kind": c.kind,
                    "bbox": c.bbox,
                    "confidence": c.confidence,
                }
                for c in architecture.components
            ],
            "data_flows": [f.model_dump() for f in architecture.data_flows],
            "trust_boundaries": [tb.model_dump() for tb in architecture.trust_boundaries],
            "assumptions": architecture.assumptions,
            "ambiguities": architecture.ambiguities,
        }
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[ok] {img.name} -> {out_path.name}")


if __name__ == "__main__":
    main()
