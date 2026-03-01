# CryptoLock - Sistema de Gestión de Identidad y Acceso (IAM)

Sistema de autenticación **passwordless** con gestión segura de llaves criptográficas y registro de auditoría inmutable mediante blockchain.

## Características Principales

- **Autenticación sin contraseñas** (Passwordless) usando firmas digitales
- **Múltiples métodos de autenticación**: Firma criptográfica, OTP, Biometría
- **Bóveda de llaves segura** con claves privadas cifradas (nunca expuestas)
- **Blockchain de auditoría** inmutable para trazabilidad
- **Control de acceso basado en roles** (RBAC)
- **API REST** completa con documentación Swagger

## Requisitos

- Python 3.12.3
- Redis (opcional, para caché y sesiones)

## Instalación

### 1. Clonar y configurar entorno virtual

```bash
cd cryptolock
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o
venv\Scripts\activate  # Windows
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```


## Flujo de Autenticación

```
1. Usuario envía email → Sistema genera challenge
2. Usuario firma challenge con clave privada
3. Sistema verifica firma con clave pública
4. Si válida → Genera tokens JWT
5. Acceso registrado en blockchain
```



## Equipo de Desarrollo

- Pedro Hubert Arroyo Cuellar
- Williams Charlie Cruz Gomez
- Ayrton Aldair Ramos Chambilla

