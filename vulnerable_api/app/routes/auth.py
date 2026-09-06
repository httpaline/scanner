import jwt
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
import os

from ..seed_data import USERS

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "eu_amo_guacamole")
router = APIRouter()

class LoginRequest(BaseModel):
  username: str
  password: str

@router.post("/auth/login")
def login(credentials: LoginRequest):
  user = None
  for u in USERS.values():
    if u["username"] == credentials.username:
      user = u
      break
  
  if user is None or user["password"] != credentials.password:
    raise HTTPException(status_code=401, detail="Invalid credentials.")  
  
  payload = {"user_id": user["id"], "exp": datetime.now(timezone.utc) + timedelta(hours=1)}
  token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
  return {"token": token}

    
