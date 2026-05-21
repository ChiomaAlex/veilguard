from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .scanners import scan_generic_file, scan_image_file, scan_link

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
HEATMAP_DIR = BASE_DIR / "heatmaps"
HEATMAP_DIR.mkdir(exist_ok=True)

app = FastAPI(title="VeilGuard API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/heatmaps", StaticFiles(directory=HEATMAP_DIR), name="heatmaps")


@app.get("/")
def serve_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "product": "VeilGuard"}


@app.post("/api/scan-link")
def api_scan_link(url: str = Form(...)) -> dict:
    return scan_link(url).as_dict()


@app.post("/api/scan-file")
async def api_scan_file(file: UploadFile = File(...)) -> dict:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    filename = file.filename
    suffix = Path(filename).suffix.lower()

    if suffix in {".png", ".jpg", ".jpeg", ".bmp", ".webp"}:
        result = scan_image_file(content, filename, HEATMAP_DIR)
    else:
        result = scan_generic_file(filename, content)

    return result.as_dict()
