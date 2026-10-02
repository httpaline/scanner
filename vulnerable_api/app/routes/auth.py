import jwt
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
import os

from ..seed_data import USERS

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "eu_amo_guacamole_chave_de_teste_local_tcc")

router = APIRouter()

class LoginRequest(BaseModel):
  username: str
  password: str

FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5


def _authenticate(username: str, password: str) -> dict:
  attempts = FAILED_ATTEMPTS.get(username, 0)
  if attempts >= MAX_ATTEMPTS:
    raise HTTPException(status_code=429, detail="Too many login attempts.")

  user = None
  for u in USERS.values():
    if u["username"] == username:
      user = u
      break

  if user is None or user["password"] != password:
    FAILED_ATTEMPTS[username] = attempts + 1
    raise HTTPException(status_code=401, detail="Invalid credentials.")

  FAILED_ATTEMPTS[username] = 0
  return user


def _issue_token(user: dict) -> str:
  payload = {"user_id": user["id"], "exp": datetime.now(timezone.utc) + timedelta(hours=1)}
  return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


@router.post("/auth/login")
def login(credentials: LoginRequest):
  user = _authenticate(credentials.username, credentials.password)
  return {"token": _issue_token(user)}


@router.get("/auth/login")
def login_query(username: str, password: str):
  user = _authenticate(username, password)
  return {"token": _issue_token(user)}
