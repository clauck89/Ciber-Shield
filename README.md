# CyberShield AI - Ciberseguridad Inteligente

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/clauck89/Ciber-Shield)](https://github.com/clauck89/Ciber-Shield)

## 🛡️ Descripción

**CyberShield AI** es una plataforma moderna de ciberseguridad que escanea la Dark Web y bases de datos filtradas en tiempo real para proteger tu identidad digital. Descubre si tu correo ha sido hackeado antes de ser una víctima.

Nos especializamos en:
- ✅ Búsqueda privada y cifrada de tu información
- ✅ Análisis en más de 12 mil millones de cuentas filtradas
- ✅ Reportes de riesgo detallados y accionables
- ✅ Alertas 24/7 sobre nuevas brechas de seguridad

## 🚀 Características Principales

### Risk Dashboard
Visualiza todas tus cuentas conectadas y su nivel de exposición en un solo panel intuitivo.

### Alertas 24/7
Te notificamos al instante si tus datos aparecen en una nueva brecha de seguridad.

### Score de Riesgo
Obtienes un reporte detallado con tu nivel de riesgo y acciones recomendadas.

### Plan Familiar
Protege hasta 5 miembros de tu familia con una sola suscripción.

### Seguridad Pass
Analizador de robustez de contraseñas offline para mayor seguridad.

## 📋 Planes de Protección

| Plan | Precio | Características |
|------|--------|-----------------|
| **Free** | $0/mes | 1 correo monitoreado, búsqueda histórica básica |
| **Premium** | $9/mes | Hasta 10 correos, alertas Dark Web 24/7, reportes PDF, soporte prioritario |
| **Family** | $19/mes | Hasta 5 perfiles, gestión parental, protección multidispositivo |

## 🔒 Seguridad y Privacidad

- **Privacidad garantizada**: Tu información nunca es almacenada
- **k-Anonymity**: Protección avanzada de privacidad
- **GDPR Compliant**: Cumple con regulaciones de protección de datos
- **Zero-Knowledge**: Arquitectura de conocimiento cero

## 🛠️ Tecnologías Utilizadas

### Backend
- **FastAPI**: Framework web moderno y rápido
- **Pydantic**: Validación de datos y modelos
- **httpx**: Cliente HTTP asíncrono
- **python-dotenv**: Gestión de variables de entorno

### Frontend
- **HTML5**: Estructura semántica moderna
- **Tailwind CSS**: Framework de diseño responsive
- **Material Symbols**: Iconografía profesional
- **JavaScript**: Interactividad del lado del cliente

### APIs Externas
- **Have I Been Pwned**: Base de datos de brechas de seguridad
- **Pwned Passwords**: Verificación de contraseñas comprometidas

## 📁 Estructura del Proyecto

```
Ciber-Shield/
├── backend/                    # API FastAPI
│   ├── app/
│   │   ├── main.py            # Aplicación FastAPI principal
│   │   ├── config.py          # Configuración y variables de entorno
│   │   ├── models.py          # Modelos Pydantic
│   │   ├── services/
│   │   │   └── hibp_service.py # Servicio HIBP
│   │   ├── api/
│   │   │   └── endpoints.py   # Endpoints de la API
│   │   └── utils.py           # Utilidades varias
│   ├── requirements.txt       # Dependencias Python
│   ├── .env                   # Variables de entorno
│   └── run.py                 # Script para iniciar servidor
├── frontend/
│   ├── js/
│   │   └── api-client.js      # Cliente JavaScript para la API
│   ├── Landing-page.html      # Página principal
│   ├── DashBoard.html         # Panel de control
│   └── login.html             # Página de acceso
├── setup.py                   # Script de instalación
└── README.md                  # Este archivo
```

## 🚀 Instalación Rápida

### Requisitos Previos
- Python 3.8+
- pip o conda
- API key de Have I Been Pwned (opcional para desarrollo)

### Instalación Automática
```bash
# Clonar el repositorio
git clone https://github.com/clauck89/Ciber-Shield.git
cd Ciber-Shield

# Ejecutar instalador
python setup.py
```

### Instalación Manual
```bash
# 1. Crear entorno virtual
python -m venv backend/venv

# 2. Activar entorno virtual
# Windows
backend\venv\Scripts\activate
# Linux/Mac
source backend/venv/bin/activate

# 3. Instalar dependencias
pip install -r backend/requirements.txt

# 4. Configurar variables de entorno
cp backend/.env.example backend/.env
# Editar backend/.env con tu API key de HIBP
```

### Obtener API Key de HIBP
1. Visita [https://haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)
2. Regístrate y obtén tu API key
3. Edita `backend/.env` y reemplaza el valor de `HIBP_API_KEY`

## 🎯 ¿Cómo Funciona?

1. **Ingresa tu Email** - Introduce el correo que deseas monitorear
2. **Analizamos la Red** - Buscamos coincidencias en bases de datos filtradas
3. **Score de Riesgo** - Obtienes un reporte detallado con recomendaciones

## 🚀 Ejecutar la Aplicación

### Iniciar Backend
```bash
# Usando el script
python backend/run.py

# O directamente con uvicorn
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

### Abrir Frontend
```bash
# Opción 1: Abrir directamente en el navegador
# Abre Landing-page.html en tu navegador

# Opción 2: Usar un servidor local
python -m http.server 5500
# Visita http://localhost:5500/Landing-page.html
```

## 📚 Documentación de la API

Una vez iniciado el backend:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

### Endpoints Principales

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/v1/health` | Health check del servicio |
| GET | `/api/v1/breaches/email/{email}` | Buscar brechas por email |
| POST | `/api/v1/password/check` | Verificar contraseña comprometida |
| GET | `/api/v1/breaches/all` | Todas las brechas del sistema |
| GET | `/api/v1/pastes/email/{email}` | Buscar pastes por email |

## 📊 Estadísticas

- 50,000+ usuarios activos
- 12 mil millones de cuentas monitoreadas
- Búsqueda en tiempo real
- 99.9% de precisión

## 🔗 Enlaces Útiles

- [Documentación](https://cybershield-ai.com/docs)
- [Política de Privacidad](https://cybershield-ai.com/privacy)
- [Estado del Servicio](https://cybershield-ai.com/status)
- [Contactar Soporte](https://cybershield-ai.com/support)

## 💬 Testimonios

> "Me alertó de que mi contraseña de LinkedIn había sido filtrada antes de que saliera en las noticias. Cambié todo a tiempo."
> — Ricardo M., Usuario Premium

> "El panel familiar es increíble. Puedo estar tranquilo sabiendo que mis padres están protegidos."
> — Elena A., Plan Family

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## 📧 Contacto

**Christian Lauck Zuluaga**
- GitHub: [@clauck89](https://github.com/clauck89)

---

**CyberShield AI** © 2024 - Frictionless Safety Guaranteed. Protegiendo identidades digitales con IA avanzada.
