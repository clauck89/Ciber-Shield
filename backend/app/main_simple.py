"""
Versión simplificada de CyberShield AI Backend para compatibilidad con Python 3.13
"""

import os
import hashlib
import httpx
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from python_dotenv import load_dotenv

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
    description="API simplificada para integración con Have I Been Pwned"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500", "http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Modelos Pydantic simplificados
class Breach(BaseModel):
    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str
    modified_date: str
    pwn_count: int
    description: str
    logo_path: Optional[str] = None
    data_classes: List[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    is_malware: bool
    is_stealer_log: bool
    is_subscription_free: bool

class BreachedAccountResponse(BaseModel):
    breaches: List[Breach] = []
    total_breaches: int
    email: str
    risk_score: int

class PasswordCheckRequest(BaseModel):
    password: str
    include_padding: bool = True

class PasswordCheckResponse(BaseModel):
    is_compromised: bool
    occurrence_count: int
    password_hash_prefix: str
    risk_level: str
    recommendations: List[str]

class HealthCheck(BaseModel):
    status: str
    version: str
    timestamp: datetime
    hibp_api_status: str

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
    
    # Puntos por cantidad de brechas
    breach_count = len(breaches)
    if breach_count >= 10:
        score += 40
    elif breach_count >= 5:
        score += 25
    elif breach_count >= 2:
        score += 15
    else:
        score += 5
    
    # Puntos por tipos de datos sensibles
    sensitive_data_classes = [
        "Email addresses", "Passwords", "Password hints", 
        "Social security numbers", "Credit card numbers",
        "Bank account numbers", "Phone numbers"
    ]
    
    for breach in breaches:
        for data_class in breach.data_classes:
            if data_class in sensitive_data_classes:
                score += 8
                break
    
    # Puntos por brechas verificadas
    verified_breaches = sum(1 for b in breaches if b.is_verified)
    if verified_breaches >= 5:
        score += 20
    elif verified_breaches >= 2:
        score += 10
    
    # Limitar a máximo 100
    return min(score, 100)

# Endpoints
@app.get("/")
async def root():
    return {
        "message": "CyberShield AI Backend API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health"
    }

@app.get("/api/v1/health", response_model=HealthCheck)
async def health_check():
    try:
        # Verificar conexión con API de passwords (gratuito)
        headers = {"user-agent": USER_AGENT}
        async with httpx.AsyncClient(timeout=10.0) as client:
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
async def check_breached_account(
    email: str,
    include_sensitive: bool = Query(default=False),
    include_unverified: bool = Query(default=True),
    truncate: bool = Query(default=True)
):
    # Validar formato de email
    import re
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Formato de email inválido")
    
    try:
        headers = get_hibp_headers()
        params = {}
        if truncate:
            params["truncateResponse"] = "true"
        if include_sensitive:
            params["includeSensitive"] = "true"
        if not include_unverified:
            params["unverified"] = "false"
        
        async with httpx.AsyncClient() as client:
            # URL encode el email
            from urllib.parse import quote
            encoded_email = quote(email.lower().strip())
            
            response = await client.get(
                f"{HIBP_BASE_URL}/breachedaccount/{encoded_email}",
                headers=headers,
                params=params
            )
            response.raise_for_status()
            
            if truncate:
                # Respuesta truncada: solo nombres de brechas
                breach_names = response.json()
                # Para simplificar, devolvemos brechas vacías con nombres
                breaches = []
                for breach_name in breach_names:
                    breach = Breach(
                        name=breach_name["Name"],
                        title=f"Brecha: {breach_name['Name']}",
                        domain="",
                        breach_date="",
                        added_date="",
                        modified_date="",
                        pwn_count=0,
                        description="",
                        data_classes=[],
                        is_verified=False,
                        is_fabricated=False,
                        is_sensitive=False,
                        is_retired=False,
                        is_spam_list=False,
                        is_malware=False,
                        is_stealer_log=False,
                        is_subscription_free=False
                    )
                    breaches.append(breach)
            else:
                # Respuesta completa
                breaches_data = response.json()
                breaches = [Breach(**breach) for breach in breaches_data]
            
            risk_score = calculate_risk_score(breaches)
            
            return BreachedAccountResponse(
                breaches=breaches,
                total_breaches=len(breaches),
                email=email.lower(),
                risk_score=risk_score
            )
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # Email no encontrado en brechas
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
        # Convertir password a SHA-1 hash
        sha1_hash = hashlib.sha1(request.password.encode('utf-8')).hexdigest().upper()
        
        # Obtener primeros 5 caracteres para k-anonymity
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]
        
        # Construir headers para passwords API (no necesita API key)
        headers = {
            "user-agent": USER_AGENT,
            "accept": "text/plain"
        }
        
        if request.include_padding:
            headers["add-padding"] = "true"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{HIBP_PASSWORDS_URL}/range/{hash_prefix}", headers=headers)
            response.raise_for_status()
            
            # Procesar respuesta
            lines = response.text.strip().split('\n')
            occurrence_count = 0
            
            for line in lines:
                # Formato: hash_suffix:count
                parts = line.split(':')
                if len(parts) == 2:
                    line_suffix, count = parts
                    if line_suffix == hash_suffix:
                        occurrence_count = int(count)
                        break
            
            is_compromised = occurrence_count > 0
            
            # Calcular nivel de riesgo
            if occurrence_count == 0:
                risk_level = "bajo"
            elif occurrence_count <= 10:
                risk_level = "medio"
            elif occurrence_count <= 100:
                risk_level = "alto"
            else:
                risk_level = "crítico"
            
            # Generar recomendaciones
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
    import uvicorn
    uvicorn.run(
        "main_simple:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
