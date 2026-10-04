from fastapi import APIRouter

router = APIRouter()


@router.get("/debug/crash")
def crash():
  raise RuntimeError("Falha simulada para teste de tratamento de erro.")
