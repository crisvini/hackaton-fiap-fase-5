from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from .config import Settings
from .pipeline import ThreatModelPipeline


app = FastAPI(title="STRIDE Threat Modeling MVP", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_diagram(
    file: UploadFile = File(...),
    output_dir: str = Form("outputs/api"),
    skip_threat_llm: bool = Form(False),
) -> dict:
    suffix = Path(file.filename or "diagram.png").suffix or ".png"
    tmp_dir = Path("tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = tmp_dir / f"{uuid.uuid4().hex}{suffix}"

    try:
        with tmp_path.open("wb") as fh:
            shutil.copyfileobj(file.file, fh)

        settings = Settings.from_env()
        pipeline = ThreatModelPipeline(settings)
        result = pipeline.analyze_image(
            image_path=tmp_path,
            output_dir=Path(output_dir),
            use_llm_threats=not skip_threat_llm,
        )
        return result.model_dump()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            await file.close()
        except Exception:
            pass


def run() -> None:
    import uvicorn

    uvicorn.run("stride_mvp.api:app", host="127.0.0.1", port=8000, reload=False)

