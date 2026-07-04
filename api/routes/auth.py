from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import secrets
from typing import Dict, Any

router = APIRouter(prefix="/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    email: str
    password: str

@router.post("/login")
def login(req: LoginRequest) -> Dict[str, Any]:
    """
    Concise email and password authentication.
    Validates against the hardcoded admin analyst credentials.
    """
    if req.email == "analyst@banksentinel.ai" and req.password == "admin123":
        return {
            "accessToken": f"bs_token_{secrets.token_hex(16)}",
            "user": {
                "id": "u-admin",
                "email": req.email,
                "name": "Lead Analyst",
                "role": "ADMIN"
            }
        }
    raise HTTPException(status_code=401, detail="Invalid email or password")
