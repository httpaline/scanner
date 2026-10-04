import jwt
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .auth import SECRET_KEY
from ..seed_data import USERS

router = APIRouter()
security = HTTPBearer()


@router.get("/admin/users")
def list_users(credentials: HTTPAuthorizationCredentials = Depends(security)):
  token = credentials.credentials
  try:
    jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
  except jwt.PyJWTError:
    raise HTTPException(status_code=401, detail="Invalid token.")

  return [{"id": u["id"], "username": u["username"], "name": u["name"], "is_admin": u["is_admin"]} for u in USERS.values()]
