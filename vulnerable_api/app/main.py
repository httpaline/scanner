import traceback

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from .routes import admin, auth, misc, users

app = FastAPI()

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(misc.router)


@app.exception_handler(Exception)
async def expose_traceback(request: Request, exc: Exception):
  return PlainTextResponse("".join(traceback.format_exception(exc)), status_code=500)


@app.middleware("http")
async def add_security_headers(request, call_next):
  response = await call_next(request)
  response.headers["X-Content-Type-Options"] = "nosniff"
  response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
  return response