"""
Servidor simple de CyberShield AI - Compatible con Python 3.13
Usa clave de prueba HIBP: 00000000000000000000000000000000000
"""

import os
import hashlib
import json
import re
from datetime import datetime
from urllib.parse import quote

try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import httpx
    from urllib.parse import urlparse, parse_qs
except ImportError as e:
    print(f"Error importando librerías: {e}")
    print("Por favor ejecuta: pip install httpx")
    exit(1)

# Configuración
HIBP_API_KEY = "00000000000000000000000000000000000"
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_PASSWORDS_URL = "https://api.pwnedpasswords.com"
USER_AGENT = "CyberShield-AI/1.0"

def get_hibp_headers():
    return {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": USER_AGENT,
        "accept": "application/json"
    }

def calculate_risk_score(breaches):
    if not breaches:
        return 0
    
    score = 0
    breach_count = len(breaches)
    
    if breach_count >= 10:
        score += 40
    elif breach_count >= 5:
        score += 25
    elif breach_count >= 2:
        score += 15
    else:
        score += 5
    
    sensitive_data = ["Email addresses", "Passwords", "Password hints"]
    for breach in breaches:
        data_classes = breach.get("data_classes", [])
        for data_class in data_classes:
            if data_class in sensitive_data:
                score += 8
                break
    
    verified_count = sum(1 for b in breaches if b.get("is_verified", False))
    if verified_count >= 5:
        score += 20
    elif verified_count >= 2:
        score += 10
    
    return min(score, 100)

class CyberShieldHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url_path = self.path
        query = urlparse(self.path).query
        query_params = parse_qs(query)
        
        # CORS headers
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        try:
            if url_path == '/':
                response = {
                    "message": "CyberShield AI Backend",
                    "version": "1.0.0",
                    "status": "Funcionando con clave de prueba HIBP",
                    "endpoints": {
                        "health": "/api/v1/health",
                        "check_email": "/api/v1/breaches/email/{email}",
                        "check_password": "/api/v1/password/check"
                    }
                }
            
            elif url_path == '/api/v1/health':
                try:
                    headers = {"user-agent": USER_AGENT}
                    with httpx.Client(timeout=5.0) as client:
                        response = client.get(f"{HIBP_PASSWORDS_URL}/range/00000", headers=headers)
                        hibp_status = "healthy" if response.status_code == 200 else "unhealthy"
                except:
                    hibp_status = "unhealthy"
                
                response = {
                    "status": "healthy",
                    "version": "1.0.0",
                    "timestamp": datetime.utcnow().isoformat(),
                    "hibp_api_status": hibp_status
                }
            
            elif url_path.startswith('/api/v1/breaches/email/'):
                email = url_path.split('/')[-1]
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_pattern, email):
                    response = {"error": "Formato de email inválido"}
                else:
                    try:
                        headers = get_hibp_headers()
                        params = {"truncateResponse": "true"}
                        
                        with httpx.Client(timeout=30.0) as client:
                            encoded_email = quote(email.lower().strip())
                            response = client.get(
                                f"{HIBP_BASE_URL}/breachedaccount/{encoded_email}",
                                headers=headers,
                                params=params
                            )
                            response.raise_for_status()
                            
                            breach_names = response.json()
                            breaches = []
                            
                            for i, breach_name in enumerate(breach_names):
                                breach = {
                                    "name": breach_name.get("Name", ""),
                                    "title": f"Brecha: {breach_name.get('Name', '')}",
                                    "domain": breach_name.get("Domain", ""),
                                    "breach_date": breach_name.get("BreachDate", ""),
                                    "added_date": breach_name.get("AddedDate", ""),
                                    "modified_date": breach_name.get("ModifiedDate", ""),
                                    "pwn_count": breach_name.get("PwnCount", 0),
                                    "description": breach_name.get("Description", ""),
                                    "data_classes": breach_name.get("DataClasses", []),
                                    "is_verified": breach_name.get("IsVerified", False),
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
                            
                            response = {
                                "breaches": breaches,
                                "total_breaches": len(breaches),
                                "email": email.lower(),
                                "risk_score": risk_score
                            }
                    
                    except httpx.HTTPStatusError as e:
                        if e.response.status_code == 404:
                            response = {
                                "breaches": [],
                                "total_breaches": 0,
                                "email": email.lower(),
                                "risk_score": 0
                            }
                        else:
                            response = {"error": f"Error HIBP API: {e.response.status_code}"}
                    except Exception as e:
                        response = {"error": f"Error interno: {str(e)}"}
            
            else:
                response = {"error": "Endpoint no encontrado"}
            
            self.wfile.write(json.dumps(response, indent=2).encode())
            
        except Exception as e:
            error_response = {"error": f"Error del servidor: {str(e)}"}
            self.wfile.write(json.dumps(error_response, indent=2).encode())
    
    def do_POST(self):
        if self.path == '/api/v1/password/check':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                request_data = json.loads(post_data.decode('utf-8'))
                
                password = request_data.get("password", "")
                include_padding = request_data.get("include_padding", True)
                
                if not password:
                    response = {"error": "La contraseña no puede estar vacía"}
                else:
                    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
                    hash_prefix = sha1_hash[:5]
                    hash_suffix = sha1_hash[5:]
                    
                    headers = {
                        "user-agent": USER_AGENT,
                        "accept": "text/plain"
                    }
                    
                    if include_padding:
                        headers["add-padding"] = "true"
                    
                    with httpx.Client(timeout=30.0) as client:
                        response = client.get(f"{HIBP_PASSWORDS_URL}/range/{hash_prefix}", headers=headers)
                        response.raise_for_status()
                        
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
                        
                        if occurrence_count == 0:
                            risk_level = "bajo"
                        elif occurrence_count <= 10:
                            risk_level = "medio"
                        elif occurrence_count <= 100:
                            risk_level = "alto"
                        else:
                            risk_level = "crítico"
                        
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
                        
                        response = {
                            "is_compromised": is_compromised,
                            "occurrence_count": occurrence_count,
                            "password_hash_prefix": hash_prefix,
                            "risk_level": risk_level,
                            "recommendations": recommendations
                        }
                
            except Exception as e:
                response = {"error": f"Error verificando contraseña: {str(e)}"}
        else:
            response = {"error": "Endpoint no encontrado"}
        
        # CORS headers
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        self.wfile.write(json.dumps(response, indent=2).encode())
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, CyberShieldHandler)
    
    print("🚀 CyberShield AI Backend - Servidor Simple")
    print(f"🔑 API Key: {HIBP_API_KEY[:8]}...{HIBP_API_KEY[-8:]}")
    print(f"🌐 Servidor: http://localhost:8000")
    print(f"📚 Health Check: http://localhost:8000/api/v1/health")
    print(f"📧 Email Check: http://localhost:8000/api/v1/breaches/email/tu@email.com")
    print(f"🔐 Password Check: http://localhost:8000/api/v1/password/check")
    print("✅ Servidor listo para usar con clave de prueba HIBP")
    print("Presiona Ctrl+C para detener el servidor")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
