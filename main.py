from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from uuid import uuid4

app = FastAPI(title="Logística Global Orquestador API", version="0.2")

# ======== Modelos de datos ========

class Servicio(BaseModel):
    id: str
    nombre: str
    descripcion: str
    endpoints: List[str]

class ServicioCreate(BaseModel):
    nombre: str = Field(..., example="Servicio de Tracking")
    descripcion: str = Field(..., example="Permite rastrear los envíos")
    endpoints: List[str] = Field(..., example=["https://example.com/api/v1/track"])

class OrquestarRequest(BaseModel):
    servicio_destino: str
    parametros_adicionales: Optional[dict] = None

class ReglaOrquestacionUpdate(BaseModel):
    reglas: Dict[str, str]

class LoginRequest(BaseModel):
    nombre_usuario: str
    contrasena: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AccesoRequest(BaseModel):
    recursos: List[str]
    rol_usuario: str

class Usuario(BaseModel):  # sólo para la "BD" en memoria
    nombre_usuario: str
    contrasena: str
    rol: str

# ======== Almacenamiento en memoria ========

usuarios_db: Dict[str, Usuario] = {
    "admin": Usuario(nombre_usuario="admin", contrasena="admin123", rol="Administrador"),
    "orquestador": Usuario(nombre_usuario="orquestador", contrasena="orq123", rol="Orquestador"),
    "user": Usuario(nombre_usuario="user", contrasena="user123", rol="Usuario")
}

servicios_db: Dict[str, Servicio] = {}
reglas_orquestacion: Dict[str, str] = {}

# ======== Seguridad sencilla ========

bearer = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> Usuario:
    """Obtiene el usuario a partir del token `usuario:rol`."""
    token = credentials.credentials
    try:
        username, role = token.split(":")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token malformado")
    user = usuarios_db.get(username)
    if not user or user.rol.lower() != role.lower():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    return user


def require_roles(*roles):
    """Dependencia que comprueba si el usuario posee alguno de los roles requeridos."""
    def dependency(user: Usuario = Depends(get_current_user)):
        if user.rol not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tiene permisos suficientes")
        return user

    return dependency

# ======== Endpoints ========


@app.post("/autenticar-usuario", response_model=Token, tags=["Seguridad"])
def autenticar_usuario(datos: LoginRequest):
    """Devuelve un token muy sencillo con formato `usuario:rol`."""
    user = usuarios_db.get(datos.nombre_usuario)
    if not user or user.contrasena != datos.contrasena:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Nombre de usuario o contraseña incorrectos")
    token = f"{user.nombre_usuario}:{user.rol}"
    return Token(access_token=token)


@app.post("/autorizar-acceso", tags=["Seguridad"])
def autorizar_acceso(req: AccesoRequest, _: Usuario = Depends(get_current_user)):
    """Ejemplo didáctico: bloquea recursos que contengan la palabra 'confidencial' si el rol no es Administrador."""
    permitido = True
    if req.rol_usuario.lower() != "administrador":
        permitido = all("confidencial" not in r.lower() for r in req.recursos)
    return {"acceso_permitido": permitido, "recursos": req.recursos}


@app.post("/registrar-servicio", response_model=Servicio, tags=["Servicios"])
def registrar_servicio(servicio: ServicioCreate, _: Usuario = Depends(require_roles("Administrador"))):
    servicio_id = str(uuid4())
    nuevo_servicio = Servicio(id=servicio_id, **servicio.dict())
    servicios_db[servicio_id] = nuevo_servicio
    return nuevo_servicio


@app.get("/informacion-servicio/{id}", response_model=Servicio, tags=["Servicios"])
def informacion_servicio(id: str, _: Usuario = Depends(get_current_user)):
    servicio = servicios_db.get(id)
    if not servicio:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Servicio no encontrado")
    return servicio


@app.post("/orquestar", tags=["Servicios"])
def orquestar(req: OrquestarRequest, _: Usuario = Depends(require_roles("Orquestador", "Administrador"))):
    servicio = servicios_db.get(req.servicio_destino)
    if not servicio:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Servicio destino no encontrado")
    resultado = {
        "mensaje": f"Servicio {servicio.nombre} orquestado exitosamente.",
        "parametros_usados": req.parametros_adicionales or {}
    }
    return resultado


@app.put("/actualizar-reglas-orquestacion", tags=["Servicios"])
def actualizar_reglas(req: ReglaOrquestacionUpdate, _: Usuario = Depends(require_roles("Orquestador"))):
    reglas_orquestacion.update(req.reglas)
    return {"mensaje": "Reglas de orquestación actualizadas", "total_reglas": len(reglas_orquestacion)}


# ======== Ejecución ========
# uvicorn main:app --reload
