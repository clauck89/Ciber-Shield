from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
import re

from ..models import (
    BreachedAccountResponse, PasswordCheckRequest, PasswordCheckResponse,
    PasteResponse, ErrorResponse, HealthCheck, Breach
)
from ..services.hibp_service import hibp_service


router = APIRouter()


@router.get("/health", response_model=HealthCheck)
async def health_check():
    """
    Verifica el estado del servicio y del API HIBP.
    """
    from ..config import settings
    
    hibp_status = "healthy" if await hibp_service.health_check() else "unhealthy"
    
    return HealthCheck(
        status="healthy",
        version=settings.app_version,
        hibp_api_status=hibp_status
    )


@router.get("/breaches/email/{email}", response_model=BreachedAccountResponse)
async def check_breached_account(
    email: str,
    include_sensitive: bool = Query(default=False, description="Incluir brechas sensibles"),
    include_unverified: bool = Query(default=True, description="Incluir brechas no verificadas"),
    truncate: bool = Query(default=True, description="Respuesta truncada (solo nombres)")
):
    """
    Busca todas las brechas asociadas a un email address.
    
    Args:
        email: Email a consultar
        include_sensitive: Incluir brechas sensibles
        include_unverified: Incluir brechas no verificadas  
        truncate: Devolver solo nombres o datos completos
        
    Returns:
        Lista de brechas encontradas con score de riesgo
    """
    # Validar formato de email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(
            status_code=400,
            detail="Formato de email inválido"
        )
    
    try:
        breaches = await hibp_service.check_breached_account(
            email=email,
            include_sensitive=include_sensitive,
            include_unverified=include_unverified,
            truncate=truncate
        )
        
        # Calcular score de riesgo basado en cantidad y tipo de brechas
        risk_score = calculate_risk_score(breaches)
        
        return BreachedAccountResponse(
            breaches=breaches,
            total_breaches=len(breaches),
            email=email.lower(),
            risk_score=risk_score
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al consultar brechas: {str(e)}"
        )


@router.get("/breaches/all", response_model=List[Breach])
async def get_all_breaches():
    """
    Obiene todas las brechas del sistema.
    
    Returns:
        Lista completa de todas las brechas conocidas
    """
    try:
        return await hibp_service.get_all_breaches()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener todas las brechas: {str(e)}"
        )


@router.get("/breach/{breach_name}", response_model=Breach)
async def get_breach_details(breach_name: str):
    """
    Obtiene detalles completos de una brecha específica.
    
    Args:
        breach_name: Nombre de la brecha
        
    Returns:
        Detalles completos de la brecha
    """
    try:
        breach = await hibp_service.get_breach_details(breach_name)
        if not breach:
            raise HTTPException(
                status_code=404,
                detail=f"Brecha '{breach_name}' no encontrada"
            )
        return breach
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener detalles de la brecha: {str(e)}"
        )


@router.post("/password/check", response_model=PasswordCheckResponse)
async def check_pwned_password(request: PasswordCheckRequest):
    """
    Verifica si una contraseña está comprometida usando k-anonymity.
    
    Args:
        request: Objeto con contraseña y opciones
        
    Returns:
        Información sobre si la contraseña está comprometida
    """
    if len(request.password) < 1:
        raise HTTPException(
            status_code=400,
            detail="La contraseña no puede estar vacía"
        )
    
    try:
        return await hibp_service.check_pwned_password(
            password=request.password,
            include_padding=request.include_padding
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al verificar contraseña: {str(e)}"
        )


@router.get("/pastes/email/{email}", response_model=PasteResponse)
async def get_pastes_for_email(email: str):
    """
    Busca todos los pastes asociados a un email.
    
    Args:
        email: Email a consultar
        
    Returns:
        Lista de pastes encontrados
    """
    # Validar formato de email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(
            status_code=400,
            detail="Formato de email inválido"
        )
    
    try:
        pastes = await hibp_service.get_pastes_for_email(email)
        
        return PasteResponse(
            pastes=pastes,
            total_pastes=len(pastes),
            email=email.lower()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al consultar pastes: {str(e)}"
        )


@router.get("/dataclasses", response_model=List[str])
async def get_data_classes():
    """
    Obtiene todos los tipos de datos comprometidos en el sistema.
    
    Returns:
        Lista de tipos de datos disponibles
    """
    try:
        return await hibp_service.get_data_classes()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener clases de datos: {str(e)}"
        )


def calculate_risk_score(breaches: List[Breach]) -> int:
    """
    Calcula un score de riesgo (0-100) basado en las brechas encontradas.
    
    Args:
        breaches: Lista de brechas del usuario
        
    Returns:
        Score de riesgo de 0 a 100
    """
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
    
    # Puntos por brechas sensibles
    sensitive_breaches = sum(1 for b in breaches if b.is_sensitive)
    if sensitive_breaches > 0:
        score += 15
    
    # Limitar a máximo 100
    return min(score, 100)
