# VeilGuard v1

VeilGuard is a web-based communication threat detection platform prototype.

## Features
- Link Guard: explainable risk scoring for suspicious URLs
- Image Guard: suspicious-image analysis with heatmap overlays
- File Guard: risky file-type and content pattern detection
- Premium landing page + product UI in one deployable app
- Brand assets included as SVG for crisp use across web, desktop, and mobile

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`

## Notes
- This v1 uses explainable heuristics, not a threat-intel feed or sandbox.
- Email capture is stored locally in browser storage for now. Connect to Supabase, HubSpot, or another backend next.
- Heatmaps are generated for image uploads and written to `app/heatmaps/`.

## Recommended next steps
1. Add persistence for scans and early-access signups.
2. Add admin dashboard and user auth.
3. Add browser extension and desktop wrapper.
4. Add SMS/email ingestion and enterprise API keys.
