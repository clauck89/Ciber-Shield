#!/usr/bin/env python3
"""
Script de instalación para CyberShield AI Backend
"""

import os
import sys
import subprocess
from pathlib import Path

def run_command(command, description):
    """Ejecuta un comando y muestra el resultado."""
    print(f"\n🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completado")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error en {description}: {e}")
        print(f"Salida: {e.stdout}")
        print(f"Error: {e.stderr}")
        return False

def check_python_version():
    """Verifica la versión de Python."""
    print("🐍 Verificando versión de Python...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ es requerido")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} encontrado")
    return True

def create_venv():
    """Crea entorno virtual."""
    venv_path = Path("backend/venv")
    if venv_path.exists():
        print("✅ Entorno virtual ya existe")
        return True
    
    print("📦 Creando entorno virtual...")
    try:
        subprocess.run([sys.executable, "-m", "venv", "backend/venv"], check=True)
        print("✅ Entorno virtual creado")
        return True
    except subprocess.CalledProcessError:
        print("❌ Error creando entorno virtual")
        return False

def install_dependencies():
    """Instala dependencias."""
    venv_python = "backend/venv/Scripts/python.exe" if os.name == "nt" else "backend/venv/bin/python"
    requirements_file = "backend/requirements.txt"
    
    if not os.path.exists(requirements_file):
        print("❌ requirements.txt no encontrado")
        return False
    
    return run_command(f"{venv_python} -m pip install -r {requirements_file}", "Instalando dependencias")

def setup_env_file():
    """Configura archivo .env si no existe."""
    env_file = "backend/.env"
    env_example = "backend/.env.example"
    
    if os.path.exists(env_file):
        print("✅ Archivo .env ya existe")
        return True
    
    if os.path.exists(env_example):
        print("📝 Creando .env desde .env.example")
        try:
            with open(env_example, 'r') as src, open(env_file, 'w') as dst:
                dst.write(src.read())
            print("✅ Archivo .env creado")
            print("⚠️  Por favor edita backend/.env con tu API key de HIBP")
            return True
        except Exception as e:
            print(f"❌ Error creando .env: {e}")
            return False
    else:
        print("⚠️  No se encontró .env.example, usando configuración por defecto")
        default_env = """# Have I Been Pwned API Configuration
HIBP_API_KEY=00000000000000000000000000000000
HIBP_BASE_URL=https://haveibeenpwned.com/api/v3
HIBP_PASSWORDS_URL=https://api.pwnedpasswords.com

# FastAPI Configuration
APP_NAME=CyberShield AI Backend
APP_VERSION=1.0.0
DEBUG=True
HOST=0.0.0.0
PORT=8000

# Security
CORS_ORIGINS=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5500", "http://127.0.0.1:5500"]
"""
        try:
            with open(env_file, 'w') as f:
                f.write(default_env)
            print("✅ Archivo .env creado con configuración por defecto")
            print("⚠️  Por favor edita backend/.env con tu API key de HIBP")
            return True
        except Exception as e:
            print(f"❌ Error creando .env: {e}")
            return False

def print_next_steps():
    """Muestra los siguientes pasos."""
    print("\n" + "="*60)
    print("🎉 INSTALACIÓN COMPLETADA")
    print("="*60)
    print("\n📋 Siguientes pasos:")
    print("\n1. 📝 Edita backend/.env con tu API key de HIBP:")
    print("   - Obtén tu key en: https://haveibeenpwned.com/API/Key")
    print("   - Reemplaza '00000000000000000000000000000000'")
    print("\n2. 🚀 Inicia el servidor backend:")
    print("   Windows: backend\\venv\\Scripts\\python backend\\run.py")
    print("   Linux/Mac: backend/venv/bin/python backend/run.py")
    print("\n3. 🌐 Abre tu navegador:")
    print("   - Frontend: Abre Landing-page.html")
    print("   - API Docs: http://localhost:8000/docs")
    print("\n4. ✅ Verifica la instalación:")
    print("   - Health check: http://localhost:8000/api/v1/health")
    print("\n📚 Para más información:")
    print("   - README.md del backend")
    print("   - Documentación en /docs")
    print("="*60)

def main():
    """Función principal."""
    print("🛡️  CyberShield AI Backend - Instalador")
    print("="*50)
    
    # Cambiar al directorio del script
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Pasos de instalación
    steps = [
        ("Verificando Python", check_python_version),
        ("Creando entorno virtual", create_venv),
        ("Instalando dependencias", install_dependencies),
        ("Configurando variables de entorno", setup_env_file),
    ]
    
    for step_name, step_func in steps:
        if not step_func():
            print(f"\n❌ Falló: {step_name}")
            print("Por favor revisa los errores e intenta nuevamente")
            sys.exit(1)
    
    print_next_steps()

if __name__ == "__main__":
    main()
