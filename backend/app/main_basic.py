"""
Versión básica de CyberShield AI Backend - Compatible con Python 3.13
"""

import os
import hashlib
import json
import re
from typing import List, Optional
from datetime import datetime

try:
    from fastapi import FastAPI, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import httpx
    import uvicorn
    from python_dotenv import load_dotenv
except ImportError as e:
    print(f"Error importando librerías: {e}")
    print("Por favor ejecuta: pip install fastapi uvicorn pydantic httpx python-dotenv")
    exit(1)

# Cargar variables de entorno
load_dotenv()

# Configuración
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "00000000000000000000000000000000000")
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_PASSWORDS_URL = "https://api.pwnedpasswords.com"
USER_AGENT = "CyberShield-AI/1.0"

# Crear aplicación FastAPI
app = FastAPI(
    title="CyberShield AI Backend",
    version="1.0.0",
    description="API básica para integración con Have I Been Pwned"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Modelos básicos
class Breach(BaseModel):
    name: str
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    added_date: str = ""
    modified_date: str = ""
    pwn_count: int = 0
    description: str = ""
    logo_path: Optional[str] = None
    data_classes: List[str] = []
    is_verified: bool = False
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    is_malware: bool = False
    is_stealer_log: bool = False
    is_subscription_free: bool = False

class BreachedAccountResponse(BaseModel):
    breaches: List[Breach] = []
    total_breaches: int = 0
    email: str
    risk_score: int = 0

class PasswordCheckRequest(BaseModel):
    password: str
    include_padding: bool = True

class PasswordCheckResponse(BaseModel):
    is_compromised: bool = False
    occurrence_count: int = 0
    password_hash_prefix: str = ""
    risk_level: str = "bajo"
    recommendations: List[str] = []

class HealthCheck(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    timestamp: datetime
    hibp_api_status: str = "unknown"

# Headers comunes para HIBP API
def get_hibp_headers():
    return {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": USER_AGENT,
        "accept": "application/json"
    }

# Función para calcular score de riesgo
def calculate_risk_score(breaches: List[Breach]) -> int:
    if not breaches:
        return 0
    
    score = 0
    breach_count = len(breaches)
    
    # Puntos por cantidad
    if breach_count >= 10:
        score += 40
    elif breach_count >= 5:
        score += 25
    elif breach_count >= 2:
        score += 15
    else:
        score += 5
    
    # Puntos por datos sensibles
    sensitive_data = ["Email addresses", "Passwords", "Password hints", "Social security numbers"]
    for breach in breaches:
        for data_class in breach.data_classes:
            if data_class in sensitive_data:
                score += 8
                break
    
    # Puntos por brechas verificadas
    verified_count = sum(1 for b in breaches if b.is_verified)
    if verified_count >= 5:
        score += 20
    elif verified_count >= 2:
        score += 10
    
    return min(score, 100)

# Endpoints
@app.get("/")
async def root():
    return {
        "message": "CyberShield AI Backend API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health",
        "status": "Funcionando con clave de prueba"
    }

@app.get("/api/v1/health", response_model=HealthCheck)
async def health_check():
    try:
        headers = {"user-agent": USER_AGENT}
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{HIBP_PASSWORDS_URL}/range/00000", headers=headers)
            hibp_status = "healthy" if response.status_code == 200 else "unhealthy"
    except:
        hibp_status = "unhealthy"
    
    return HealthCheck(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow(),
        hibp_api_status=hibp_status
    )

@app.get("/api/v1/breaches/email/{email}", response_model=BreachedAccountResponse)
async def check_breached_account(email: str):
    # Validar email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Formato de email inválido")
    
    try:
        headers = get_hibp_headers()
        params = {"truncateResponse": "true"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # URL encode email
            from urllib.parse import quote
            encoded_email = quote(email.lower().strip())
            
            response = await client.get(
                f"{HIBP_BASE_URL}/breachedaccount/{encoded_email}",
                headers=headers,
                params=params
            )
            response.raise_for_status()
            
            breach_names = response.json()
            breaches = []
            
            # Crear brechas básicas para demostración
            for breach_name in breach_names:
                breach = Breach(
                    name=breach_name.get("Name", ""),
                    title=f"Brecha: {breach_name.get('Name', '')}",
                    domain=breach_name.get("Domain", ""),
                    breach_date=breach_name.get("BreachDate", ""),
                    added_date=breach_name.get("AddedDate", ""),
                    modified_date=breach_name.get("ModifiedDate", ""),
                    pwn_count=breach_name.get("PwnCount", 0),
                    description=breach_name.get("Description", ""),
                    data_classes=breach_name.get("DataClasses", []),
                    is_verified=breach_name.get("IsVerified", False),
                    is_fabricated=breach_name.get("IsFabricated", False),
                    is_sensitive=breach_name.get("IsSensitive", False),
                    is_retired=breach_name.get("IsRetired", False),
                    is_spam_list=breach_name.get("IsSpamList", False),
                    is_malware=breach_name.get("IsMalware", False),
                    is_stealer_log=breach_name.get("IsStealerLog", False),
                    is_subscription_free=breach_name.get("IsSubscriptionFree", False)
                )
                breaches.append(breach)
            
            risk_score = calculate_risk_score(breaches)
            
            return BreachedAccountResponse(
                breaches=breaches,
                total_breaches=len(breaches),
                email=email.lower(),
                risk_score=risk_score
            )
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # Email no encontrado
            return BreachedAccountResponse(
                breaches=[],
                total_breaches=0,
                email=email.lower(),
                risk_score=0
            )
        else:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error HIBP API: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.post("/api/v1/password/check", response_model=PasswordCheckResponse)
async def check_pwned_password(request: PasswordCheckRequest):
    try:
        # SHA-1 hash
        sha1_hash = hashlib.sha1(request.password.encode('utf-8')).hexdigest().upper()
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]
        
        # Headers para passwords API (gratuito)
        headers = {
            "user-agent": USER_AGENT,
            "accept": "text/plain"
        }
        
        if request.include_padding:
            headers["add-padding"] = "true"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{HIBP_PASSWORDS_URL}/range/{hash_prefix}", headers=headers)
            response.raise_for_status()
            
            # Procesar respuesta
            lines = response.text.strip().split('\n')
            occurrence_count = 0
            
            for line in lines:
                parts = line.split(':')
                if len(parts) == 2:
                    line_suffix, count = parts
                    if line_suffix == hash_suffix:
                        occurrence_count = int(count)
                        break
            
            is_compromised = occurrence_count > 0
            
            # Nivel de riesgo
            if occurrence_count == 0:
                risk_level = "bajo"
            elif occurrence_count <= 10:
                risk_level = "medio"
            elif occurrence_count <= 100:
                risk_level = "alto"
            else:
                risk_level = "crítico"
            
            # Recomendaciones
            recommendations = []
            if is_compromised:
                recommendations.append("Cambie esta contraseña inmediatamente")
                recommendations.append("No reutilice esta contraseña en otros sitios")
                recommendations.append("Habilite autenticación de dos factores donde sea posible")
                if occurrence_count > 100:
                    recommendations.append("Esta contraseña es muy común, considere usar un gestor de contraseñas")
            else:
                recommendations.append("Esta contraseña no aparece en brechas conocidas")
                recommendations.append("Asegúrese de que sea lo suficientemente compleja")
                recommendations.append("Considere usar autenticación de dos factores")
            
            return PasswordCheckResponse(
                is_compromised=is_compromised,
                occurrence_count=occurrence_count,
                password_hash_prefix=hash_prefix,
                risk_level=risk_level,
                recommendations=recommendations
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error verificando contraseña: {str(e)}")

if __name__ == "__main__":
    print("🚀 Iniciando CyberShield AI Backend...")
    print(f"📅 API Key: {HIBP_API_KEY[:8]}...{HIBP_API_KEY[-8:]}")
    print(f"🌐 Servidor: http://localhost:8000")
    print(f"📚 Documentación: http://localhost:8000/docs")
    
    uvicorn.run(
        "main_basic:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
