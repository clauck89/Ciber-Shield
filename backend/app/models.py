from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class Breach(BaseModel):
    """Modelo para una brecha de seguridad del API HIBP."""
    
    name: str = Field(..., description="Nombre de la brecha")
    title: str = Field(..., description="Título de la brecha")
    domain: str = Field(..., description="Dominio afectado")
    breach_date: str = Field(..., description="Fecha de la brecha (YYYY-MM-DD)")
    added_date: str = Field(..., description="Fecha de adición al sistema (ISO 8601)")
    modified_date: str = Field(..., description="Fecha de modificación (ISO 8601)")
    pwn_count: int = Field(..., description="Número de cuentas comprometidas")
    description: str = Field(..., description="Descripción detallada de la brecha")
    logo_path: Optional[str] = Field(None, description="Ruta del logo")
    data_classes: List[str] = Field(..., description="Tipos de datos comprometidos")
    is_verified: bool = Field(..., description="Si la brecha está verificada")
    is_fabricated: bool = Field(..., description="Si la brecha es fabricada")
    is_sensitive: bool = Field(..., description="Si la brecha es sensible")
    is_retired: bool = Field(..., description="Si la brecha está retirada")
    is_spam_list: bool = Field(..., description="Si es una lista de spam")
    is_malware: bool = Field(..., description="Si es malware")
    is_stealer_log: bool = Field(..., description="Si es un stealer log")
    is_subscription_free: bool = Field(..., description="Si es gratuita para suscriptores")


class BreachedAccountResponse(BaseModel):
    """Respuesta para búsqueda de brechas por email."""
    
    breaches: List[Breach] = Field(default=[], description="Lista de brechas encontradas")
    total_breaches: int = Field(..., description="Total de brechas encontradas")
    email: str = Field(..., description="Email consultado")
    risk_score: int = Field(..., ge=0, le=100, description="Score de riesgo (0-100)")


class PasswordCheckRequest(BaseModel):
    """Solicitud para verificar si una contraseña está comprometida."""
    
    password: str = Field(..., min_length=1, description="Contraseña a verificar")
    include_padding: bool = Field(default=True, description="Incluir padding para privacidad")


class PasswordCheckResponse(BaseModel):
    """Respuesta para verificación de contraseñas."""
    
    is_compromised: bool = Field(..., description="Si la contraseña está comprometida")
    occurrence_count: int = Field(..., description="Número de veces que aparece")
    password_hash_prefix: str = Field(..., description="Prefijo del hash usado")
    risk_level: str = Field(..., description="Nivel de riesgo: bajo, medio, alto, crítico")
    recommendations: List[str] = Field(..., description="Recomendaciones de seguridad")


class Paste(BaseModel):
    """Modelo para un paste del API HIBP."""
    
    id: str = Field(..., description="ID del paste")
    source: str = Field(..., description="Fuente del paste")
    title: Optional[str] = Field(None, description="Título del paste")
    date: str = Field(..., description="Fecha del paste")
    email_count: int = Field(..., description="Número de emails encontrados")


class PasteResponse(BaseModel):
    """Respuesta para búsqueda de pastes por email."""
    
    pastes: List[Paste] = Field(default=[], description="Lista de pastes encontrados")
    total_pastes: int = Field(..., description="Total de pastes encontrados")
    email: str = Field(..., description="Email consultado")


class ErrorResponse(BaseModel):
    """Modelo estándar para respuestas de error."""
    
    error: str = Field(..., description="Tipo de error")
    message: str = Field(..., description="Mensaje de error detallado")
    status_code: int = Field(..., description="Código HTTP de error")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp del error")


class HealthCheck(BaseModel):
    """Modelo para respuesta de health check."""
    
    status: str = Field(..., description="Estado del servicio")
    version: str = Field(..., description="Versión de la API")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp")
    hibp_api_status: str = Field(..., description="Estado del API HIBP")
