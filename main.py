from Routes.Auth import router as authRouter
from Routes.Ticket import router as ticketRouter
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from Utils.Mongo import db
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime
import pytz
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="RCS CTF 2026 - EncryptEdge LPU Backend",
    description="Backend API for RCS CTF 2026 - EncryptEdge LPU",
    version="2.0.1"
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://encryptedge.in", "http://127.0.0.1:3000"],  # Change to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

up_time = datetime.now(pytz.timezone("Asia/Kolkata"))

app.include_router(authRouter, prefix="/auth", tags=["auth"])
app.include_router(ticketRouter, prefix="/ticket", tags=["ticket"])

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