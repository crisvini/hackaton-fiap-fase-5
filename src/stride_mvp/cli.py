from __future__ import annotations

import json
from pathlib import Path

import typer

from .config import Settings
from .pipeline import ThreatModelPipeline


app = typer.Typer(help="MVP de modelagem de ameacas STRIDE a partir de diagramas.")


@app.command()
def analyze(
    image: Path | None = typer.Option(
        None,
        "--image",
        "-i",
        help="Caminho da imagem do diagrama (.png/.jpg/.webp).",
    ),
    architecture_json: Path | None = typer.Option(
        None,
        "--architecture-json",
        help="Usa arquitetura ja extraida (JSON) para gerar relatorio STRIDE.",
    ),
    output_dir: Path = typer.Option(
        Path("outputs/latest"),
        "--output-dir",
        "-o",
        help="Diretorio de saida para os artefatos (JSON + Markdown).",
    ),
    skip_threat_llm: bool = typer.Option(
        False,
        "--skip-threat-llm",
        help="Nao usar LLM na geracao das ameacas; usa fallback local (catalogo KB).",
    ),
    vision_model: str | None = typer.Option(
        None, "--vision-model", help="Override do modelo de visao OpenAI."
    ),
    threats_model: str | None = typer.Option(
        None, "--threats-model", help="Override do modelo para geracao de ameacas."
    ),
) -> None:
    if bool(image) == bool(architecture_json):
        raise typer.BadParameter("Informe exatamente um entre --image ou --architecture-json.")

    settings = Settings.from_env()
    if vision_model:
        settings.openai_model_vision = vision_model
    if threats_model:
        settings.openai_model_threats = threats_model

    if image and not settings.openai_api_key:
        typer.secho(
            "Erro: OPENAI_API_KEY nao configurada. Crie o arquivo .env com as variaveis do .env.example e informe uma chave valida da OpenAI.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    pipeline = ThreatModelPipeline(settings)

    if image:
        try:
            pipeline.validate_openai_api_key()
        except Exception as exc:
            typer.secho(f"Erro: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        result = pipeline.analyze_image(
            image_path=image,
            output_dir=output_dir,
            use_llm_threats=not skip_threat_llm,
        )
    else:
        architecture = pipeline.load_architecture_json(architecture_json)  # type: ignore[arg-type]
        result = pipeline.analyze_architecture(
            architecture=architecture,
            output_dir=output_dir,
            use_llm_threats=not skip_threat_llm,
        )

    summary = {
        "system_name": result.architecture.system_name,
        "components": len(result.architecture.components),
        "data_flows": len(result.architecture.data_flows),
        "threats": len(result.threat_report.threats),
        "artifacts": result.artifacts.model_dump(),
    }
    typer.echo(json.dumps(summary, ensure_ascii=False, indent=2))


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload", help="Hot reload (desenvolvimento)."),
) -> None:
    import uvicorn

    uvicorn.run("stride_mvp.api:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
