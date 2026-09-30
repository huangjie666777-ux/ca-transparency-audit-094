from fastapi import FastAPI

app = FastAPI(title="Local Test CA")


@app.get("/health")
def health():
    return {"status": "ok"}
