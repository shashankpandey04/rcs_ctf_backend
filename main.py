from Routes.Auth import router as authRouter
from fastapi import FastAPI
from Utils.Mongo import db
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime
import pytz

app = FastAPI(
    title="RCS CTF 2026 - EncryptEdge LPU Backend",
    description="Backend API for RCS CTF 2026 - EncryptEdge LPU",
    version="2.0.1"
)

up_time = datetime.now(pytz.timezone("Asia/Kolkata"))

app.include_router(authRouter, prefix="/auth", tags=["auth"])

@app.get("/")
async def root():
    return {
        "message": "RCS CTF 2026 - EncryptEdge LPU",
        "version": "2.0.1",
        "status": 200,
        "up_time": up_time.strftime("%Y-%m-%d %H:%M:%S %Z%z")
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)