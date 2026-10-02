import jwt 
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .auth import SECRET_KEY
from ..seed_data import USERS

router = APIRouter()
security = HTTPBearer()

@router.get("/users/{id}")
def get_user(id: int, credentials: HTTPAuthorizationCredentials = Depends(security)):
  token = credentials.credentials
  try:
    jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
  except jwt.PyJWTError:
    raise HTTPException(status_code=401, detail="Invalid token.")
  
  user = USERS.get(id)
  if user is None:
    raise HTTPException(status_code=404, detail="User not found.")
  
  return {"id": user["id"], "username": user["username"], "name": user["name"]}

  
@router.put("/users/{id}")
def update_user(id: int, body: dict, credentials: HTTPAuthorizationCredentials = Depends(security)):
  token = credentials.credentials
  try:
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
  except jwt.PyJWTError:
    raise HTTPException(status_code=401, detail="Invalid token.")

  if payload["user_id"] != id:
    raise HTTPException(status_code=403, detail="Cannot update another user.")

  user = USERS.get(id)
  if user is None:
    raise HTTPException(status_code=404, detail="User not found.")

  user.update(body)

  return {"id": user["id"], "username": user["username"], "name": user["name"], "is_admin": user["is_admin"]}
  