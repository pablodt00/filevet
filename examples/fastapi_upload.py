from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile

from filevet import Policy, ascan

MAX_BYTES = 20 << 20
STORE = Path("uploads")
POLICY = Policy.load("default")

app = FastAPI()


@app.post("/documents")
async def upload(file: UploadFile) -> dict[str, str]:
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "file too large")
    report = await ascan(data, name=file.filename or "", policy=POLICY)
    if report.verdict == "block":
        raise HTTPException(422, f"rejected: {report.decision.reason}")
    STORE.mkdir(exist_ok=True)
    target = STORE / report.artifacts[0].sha256
    target.write_bytes(data)
    return {"id": target.name, "verdict": report.verdict}
