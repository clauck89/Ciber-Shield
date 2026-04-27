import os
from typing import List
from pydantic import BaseSettings


class Settings(BaseSettings):
    """Configuración de la aplicación usando variables de entorno."""
    
    # HIBP API Configuration
    hibp_api_key: str
    hibp_base_url: str = "https://haveibeenpwned.com/api/v3"
    hibp_passwords_url: str = "https://api.pwnedpasswords.com"
    
    # FastAPI Configuration
    app_name: str = "CyberShield AI Backend"
    app_version: str = "1.0.0"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Security
    cors_origins: List[str] = []
    
    # User Agent for HIBP API (required)
    user_agent: str = "CyberShield-AI/1.0"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Instancia global de configuración
settings = Settings()
