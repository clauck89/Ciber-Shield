import re
from typing import Optional


def validate_email(email: str) -> bool:
    """
    Valida si un string tiene formato de email válido.
    
    Args:
        email: Email a validar
        
    Returns:
        True si el formato es válido
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def sanitize_email(email: str) -> str:
    """
    Limpia y normaliza un email.
    
    Args:
        email: Email a limpiar
        
    Returns:
        Email en minúsculas y sin espacios
    """
    return email.lower().strip()


def mask_email(email: str) -> str:
    """
    Enmascara un email para mostrarlo parcialmente.
    
    Args:
        email: Email a enmascarar
        
    Returns:
        Email enmascarado (ej: u***@example.com)
    """
    if not validate_email(email):
        return email
    
    local, domain = email.split('@', 1)
    if len(local) <= 2:
        masked_local = '*' * len(local)
    else:
        masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
    
    return f"{masked_local}@{domain}"


def calculate_password_strength(password: str) -> dict:
    """
    Calcula la fortaleza de una contraseña.
    
    Args:
        password: Contraseña a evaluar
        
    Returns:
        Diccionario con métricas de fortaleza
    """
    score = 0
    feedback = []
    
    # Longitud
    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
    elif len(password) >= 6:
        score += 10
    else:
        feedback.append("Usa al menos 8 caracteres")
    
    # Complejidad
    if re.search(r'[a-z]', password):
        score += 10
    else:
        feedback.append("Incluye letras minúsculas")
    
    if re.search(r'[A-Z]', password):
        score += 15
    else:
        feedback.append("Incluye letras mayúsculas")
    
    if re.search(r'\d', password):
        score += 15
    else:
        feedback.append("Incluye números")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 20
    else:
        feedback.append("Incluye caracteres especiales")
    
    # Patrones comunes
    if re.search(r'(.)\1{2,}', password):  # 3+ caracteres repetidos
        score -= 10
        feedback.append("Evita caracteres repetidos")
    
    # Patrones de teclado
    keyboard_patterns = ['qwerty', 'asdf', '123456', 'abcdef']
    if any(pattern in password.lower() for pattern in keyboard_patterns):
        score -= 15
        feedback.append("Evita patrones comunes de teclado")
    
    # Determinar nivel
    if score >= 80:
        level = "muy fuerte"
    elif score >= 60:
        level = "fuerte"
    elif score >= 40:
        level = "moderada"
    elif score >= 20:
        level = "débil"
    else:
        level = "muy débil"
    
    return {
        "score": max(0, min(100, score)),
        "level": level,
        "feedback": feedback
    }


def format_occurrence_count(count: int) -> str:
    """
    Formatea el número de ocurrencias para mostrarlo de forma legible.
    
    Args:
        count: Número de ocurrencias
        
    Returns:
        String formateado
    """
    if count == 0:
        return "Nunca"
    elif count == 1:
        return "1 vez"
    elif count < 1000:
        return f"{count} veces"
    elif count < 1000000:
        return f"{count/1000:.1f}K veces"
    else:
        return f"{count/1000000:.1f}M veces"


def generate_security_recommendations(breaches_count: int, has_sensitive_data: bool) -> list:
    """
    Genera recomendaciones de seguridad basadas en el perfil de riesgo.
    
    Args:
        breaches_count: Número de brechas encontradas
        has_sensitive_data: Si hay datos sensibles comprometidos
        
    Returns:
        Lista de recomendaciones personalizadas
    """
    recommendations = []
    
    if breaches_count == 0:
        recommendations.append("Tu email parece seguro. Mantén buenas prácticas de seguridad.")
        return recommendations
    
    # Recomendaciones básicas
    recommendations.append("Revisa todas tus cuentas y cambia contraseñas")
    recommendations.append("Habilita autenticación de dos factores donde sea posible")
    
    # Según cantidad de brechas
    if breaches_count >= 10:
        recommendations.append("Tienes muchas brechas. Considera cambiar tu email principal")
        recommendations.append("Usa un gestor de contraseñas para generar claves únicas")
    elif breaches_count >= 5:
        recommendations.append("Tienes múltiples brechas. Prioriza cambiar contraseñas importantes")
    
    # Según datos sensibles
    if has_sensitive_data:
        recommendations.append("Tienes datos sensibles comprometidos. Monitorea tu identidad")
        recommendations.append("Considera servicios de monitoreo de crédito")
        recommendations.append("Revisa tus estados de cuenta bancarios regularmente")
    
    # Recomendaciones generales
    recommendations.append("Sé cuidadoso con emails de phishing")
    recommendations.append("No reutilices contraseñas entre diferentes sitios")
    recommendations.append("Mantén tu software actualizado")
    
    return recommendations
