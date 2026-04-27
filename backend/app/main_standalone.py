"""
CyberShield AI Backend - Versión standalone sin Pydantic
Compatible con Python 3.13 usando clave de prueba HIBP
"""

import os
import hashlib
import json
import re
from datetime import datetime
from urllib.parse import quote

try:
    from fastapi import FastAPI, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    import httpx
    import uvicorn
    from python_dotenv import load_dotenv
except ImportError as e:
    print(f"❌ Error importando librerías: {e}")
    print("Por favor ejecuta: pip install fastapi uvicorn httpx python-dotenv")
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
    description="API standalone para Have I Been Pwned con clave de prueba"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Headers para HIBP API
def get_hibp_headers():
    return {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": USER_AGENT,
        "accept": "application/json"
    }

# Función para calcular score de riesgo
def calculate_risk_score(breaches):
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
        data_classes = breach.get("data_classes", [])
        for data_class in data_classes:
            if data_class in sensitive_data:
                score += 8
                break
    
    # Puntos por brechas verificadas
    verified_count = sum(1 for b in breaches if b.get("is_verified", False))
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
        "status": "Funcionando con clave de prueba HIBP"
    }

@app.get("/api/v1/health")
async def health_check():
    try:
        headers = {"user-agent": USER_AGENT}
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{HIBP_PASSWORDS_URL}/range/00000", headers=headers)
            hibp_status = "healthy" if response.status_code == 200 else "unhealthy"
    except:
        hibp_status = "unhealthy"
    
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "hibp_api_status": hibp_status
    }

@app.get("/api/v1/breaches/email/{email}")
async def check_breached_account(email: str):
    # Validar email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Formato de email inválido")
    
    try:
        headers = get_hibp_headers()
        params = {"truncateResponse": "true"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            encoded_email = quote(email.lower().strip())
            
            response = await client.get(
                f"{HIBP_BASE_URL}/breachedaccount/{encoded_email}",
                headers=headers,
                params=params
            )
            response.raise_for_status()
            
            breach_names = response.json()
            breaches = []
            
            # Crear brechas de ejemplo para demostración
            for i, breach_name in enumerate(breach_names):
                breach = {
                    "name": breach_name.get("Name", ""),
                    "title": f"Brecha: {breach_name.get('Name', '')}",
                    "domain": breach_name.get("Domain", f"ejemplo{i}.com"),
                    "breach_date": breach_name.get("BreachDate", "2023-01-01"),
                    "added_date": breach_name.get("AddedDate", "2023-01-01T00:00:00Z"),
                    "modified_date": breach_name.get("ModifiedDate", "2023-01-01T00:00:00Z"),
                    "pwn_count": breach_name.get("PwnCount", 1000000),
                    "description": f"Brecha de seguridad detectada para {breach_name.get('Name', '')}",
                    "data_classes": ["Email addresses", "Passwords", "Usernames"],
                    "is_verified": breach_name.get("IsVerified", True),
                    "is_fabricated": breach_name.get("IsFabricated", False),
                    "is_sensitive": breach_name.get("IsSensitive", False),
                    "is_retired": breach_name.get("IsRetired", False),
                    "is_spam_list": breach_name.get("IsSpamList", False),
                    "is_malware": breach_name.get("IsMalware", False),
                    "is_stealer_log": breach_name.get("IsStealerLog", False),
                    "is_subscription_free": breach_name.get("IsSubscriptionFree", False)
                }
                breaches.append(breach)
            
            risk_score = calculate_risk_score(breaches)
            
            return {
                "breaches": breaches,
                "total_breaches": len(breaches),
                "email": email.lower(),
                "risk_score": risk_score
            }
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # Email no encontrado
            return {
                "breaches": [],
                "total_breaches": 0,
                "email": email.lower(),
                "risk_score": 0
            }
        else:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error HIBP API: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@app.post("/api/v1/password/check")
async def check_pwned_password(request: dict):
    try:
        password = request.get("password", "")
        include_padding = request.get("include_padding", True)
        
        if not password:
            raise HTTPException(status_code=400, detail="La contraseña no puede estar vacía")
        
        # SHA-1 hash
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]
        
        # Headers para passwords API (gratuito)
        headers = {
            "user-agent": USER_AGENT,
            "accept": "text/plain"
        }
        
        if include_padding:
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
            
            return {
                "is_compromised": is_compromised,
                "occurrence_count": occurrence_count,
                "password_hash_prefix": hash_prefix,
                "risk_level": risk_level,
                "recommendations": recommendations
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error verificando contraseña: {str(e)}")

if __name__ == "__main__":
    print("🚀 Iniciando CyberShield AI Backend...")
    print(f"🔑 API Key: {HIBP_API_KEY[:8]}...{HIBP_API_KEY[-8:]}")
    print(f"🌐 Servidor: http://localhost:8000")
    print(f"📚 Documentación: http://localhost:8000/docs")
    print("✅ Backend listo para usar con clave de prueba HIBP")
    
    uvicorn.run(
        "main_standalone:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
