import hashlib
import httpx
from typing import List, Optional, Tuple
from urllib.parse import quote

from ..config import settings
from ..models import Breach, Paste, PasswordCheckResponse


class HIBPService:
    """Servicio para interactuar con el API Have I Been Pwned."""
    
    def __init__(self):
        self.base_url = settings.hibp_base_url
        self.passwords_url = settings.hibp_passwords_url
        self.api_key = settings.hibp_api_key
        self.user_agent = settings.user_agent
        
        # Headers comunes para todas las peticiones
        self.headers = {
            "hibp-api-key": self.api_key,
            "user-agent": self.user_agent,
            "accept": "application/json"
        }
    
    async def check_breached_account(self, email: str, include_sensitive: bool = False, 
                                   include_unverified: bool = True, truncate: bool = True) -> List[Breach]:
        """
        Busca todas las brechas asociadas a un email address.
        
        Args:
            email: Email a consultar
            include_sensitive: Incluir brechas sensibles
            include_unverified: Incluir brechas no verificadas
            truncate: Devolver solo nombres de brechas o datos completos
            
        Returns:
            Lista de brechas encontradas
            
        Raises:
            httpx.HTTPError: Si hay error en la petición HTTP
        """
        # URL encode el email
        encoded_email = quote(email.lower().strip())
        
        # Construir query parameters
        params = {}
        if truncate:
            params["truncateResponse"] = "true"
        if include_sensitive:
            params["includeSensitive"] = "true"
        if not include_unverified:
            params["unverified"] = "false"
        
        url = f"{self.base_url}/breachedaccount/{encoded_email}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            if truncate:
                # Respuesta truncada: solo nombres de brechas
                breach_names = response.json()
                breaches = []
                for item in breach_names:
                    if isinstance(item, dict):
                        breach_name = item.get("Name") or item.get("name")
                    else:
                        breach_name = str(item)

                    if not breach_name:
                        continue

                    breach_details = await self.get_breach_details(breach_name)
                    if breach_details:
                        breaches.append(breach_details)
                return breaches
            else:
                # Respuesta completa
                breaches_data = response.json()
                return [Breach(**breach) for breach in breaches_data]
    
    async def get_breach_details(self, breach_name: str) -> Optional[Breach]:
        """
        Obtiene detalles completos de una brecha específica.
        
        Args:
            breach_name: Nombre de la brecha
            
        Returns:
            Detalles de la brecha o None si no existe
        """
        encoded_name = quote(str(breach_name), safe='')
        url = f"{self.base_url}/breach/{encoded_name}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            
            breach_data = response.json()
            return Breach(**breach_data)
    
    async def get_all_breaches(self) -> List[Breach]:
        """
        Obtiene todas las brechas del sistema.
        
        Returns:
            Lista de todas las brechas
        """
        url = f"{self.base_url}/breaches"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            response.raise_for_status()
            
            breaches_data = response.json()
            return [Breach(**breach) for breach in breaches_data]
    
    async def check_pwned_password(self, password: str, include_padding: bool = True) -> PasswordCheckResponse:
        """
        Verifica si una contraseña está comprometida usando k-anonymity.
        
        Args:
            password: Contraseña a verificar
            include_padding: Incluir padding para privacidad
            
        Returns:
            Información sobre si la contraseña está comprometida
        """
        # Convertir password a SHA-1 hash
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Obtener primeros 5 caracteres para k-anonymity
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]
        
        # Construir headers para passwords API (no necesita API key)
        headers = {
            "user-agent": self.user_agent,
            "accept": "text/plain"
        }
        
        if include_padding:
            headers["add-padding"] = "true"
        
        url = f"{self.passwords_url}/range/{hash_prefix}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
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
    
    async def get_pastes_for_email(self, email: str) -> List[Paste]:
        """
        Busca todos los pastes asociados a un email.
        
        Args:
            email: Email a consultar
            
        Returns:
            Lista de pastes encontrados
        """
        encoded_email = quote(email.lower().strip())
        url = f"{self.base_url}/pasteaccount/{encoded_email}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            response.raise_for_status()
            
            pastes_data = response.json()
            return [Paste(**paste) for paste in pastes_data]
    
    async def get_data_classes(self) -> List[str]:
        """
        Obtiene todos los tipos de datos comprometidos en el sistema.
        
        Returns:
            Lista de tipos de datos
        """
        url = f"{self.base_url}/dataclasses"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
    
    async def health_check(self) -> bool:
        """
        Verifica si el API HIBP está accesible.
        
        Returns:
            True si el API está accesible
        """
        try:
            # Usar endpoint gratuito de passwords para verificar conexión
            headers = {"user-agent": self.user_agent}
            url = f"{self.passwords_url}/range/00000"
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
                return response.status_code == 200
        except:
            return False


# Instancia global del servicio
hibp_service = HIBPService()
