# CyberShield AI Backend

Backend FastAPI para integración con Have I Been Pwned API.

## 🚀 Características

- ✅ Búsqueda de brechas por email address
- ✅ Verificación de contraseñas comprometidas (k-anonymity)
- ✅ Búsqueda de pastes asociados a emails
- ✅ Cálculo de score de riesgo personalizado
- ✅ Documentación OpenAPI/Swagger automática
- ✅ Manejo de errores y logging
- ✅ Validación de inputs con Pydantic

## 📋 Requisitos

- Python 3.8+
- pip o conda

## 🛠️ Instalación

1. Crear entorno virtual:
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Configurar variables de entorno:
```bash
cp .env.example .env
# Editar .env con tu API key de HIBP
```

## ⚙️ Configuración

Editar el archivo `.env`:

```env
# Have I Been Pwned API Configuration
HIBP_API_KEY=tu_api_key_aqui
HIBP_BASE_URL=https://haveibeenpwned.com/api/v3
HIBP_PASSWORDS_URL=https://api.pwnedpasswords.com

# FastAPI Configuration
APP_NAME=CyberShield AI Backend
APP_VERSION=1.0.0
DEBUG=True
HOST=0.0.0.0
PORT=8000

# Security
CORS_ORIGINS=["http://localhost:3000", "http://127.0.0.1:3000"]
```

## 🏃‍♂️ Ejecutar

Modo desarrollo:
```bash
python run.py
```

O directamente con uvicorn:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 📚 Documentación

Una vez iniciado el servidor:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## 🔗 Endpoints

### Health Check
- `GET /` - Información básica de la API
- `GET /api/v1/health` - Estado del servicio y HIBP API

### Brechas por Email
- `GET /api/v1/breaches/email/{email}` - Buscar brechas de un email
- `GET /api/v1/breaches/all` - Todas las brechas del sistema
- `GET /api/v1/breach/{breach_name}` - Detalles de brecha específica

### Verificación de Contraseñas
- `POST /api/v1/password/check` - Verificar si contraseña está comprometida

### Pastes
- `GET /api/v1/pastes/email/{email}` - Buscar pastes de un email

### Datos
- `GET /api/v1/dataclasses` - Todos los tipos de datos comprometidos

## 📝 Ejemplos de Uso

### Verificar email
```bash
curl -X GET "http://localhost:8000/api/v1/breaches/email/test@example.com"
```

### Verificar contraseña
```bash
curl -X POST "http://localhost:8000/api/v1/password/check" \
  -H "Content-Type: application/json" \
  -d '{"password": "password123", "include_padding": true}'
```

## 🧪 Tests

Ejecutar tests:
```bash
pytest
```

## 🔒 Seguridad

- Validación de inputs con Pydantic
- Rate limiting integrado
- CORS configurado
- Manejo seguro de API keys
- K-anonymity para verificación de contraseñas

## 📊 Monitoreo

La API incluye logging estructurado y métricas de salud:

- Health checks automáticos
- Logs de errores y peticiones
- Estado del API HIBP

## 🤝 Contribuir

1. Fork el proyecto
2. Crear feature branch
3. Commit cambios
4. Push a la rama
5. Pull Request

## 📄 Licencia

MIT License - ver archivo LICENSE
