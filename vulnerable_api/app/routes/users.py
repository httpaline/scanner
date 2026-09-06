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
  
  return user
  