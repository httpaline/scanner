from fastapi import FastAPI
from .routes import auth, users

app = FastAPI()

app.include_router(auth.router)
app.include_router(users.router)

@app.middleware("http")
async def add_security_headers(request, call_next):
  response = await call_next(request)
  response.headers["X-Content-Type-Options"] = "nosniff"
  response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
  return response