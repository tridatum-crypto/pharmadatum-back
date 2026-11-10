import os
import re
import uuid
import duckdb
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from passlib.context import CryptContext
import gdown

app = FastAPI(title="PharmaDatum API")

# --- CONFIGURACIÓN DE CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")

# --- GESTIÓN DINÁMICA DE LA RUTA DE LA BASE DE DATOS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "pharmadatum.duckdb")
DB_PATH = os.getenv("DUCKDB_PATH", DEFAULT_DB_PATH)

# Descarga automática si no existe localmente (para Render/Nube)
DRIVE_FILE_ID = os.getenv("DRIVE_FILE_ID", "1fMvvLNspMlSoi_InipPIMLm8GFuycAGF")

if not os.path.exists(DB_PATH) and DRIVE_FILE_ID != "1fMvvLNspMlSoi_InipPIMLm8GFuycAGF":
    print(f"--> [Iniciando descarga de base de datos desde la nube ({DB_PATH})...]")
    url = f"https://drive.google.com/uc?id={DRIVE_FILE_ID}"
    gdown.download(url, DB_PATH, quiet=False)
    print("--> [Descarga completada exitosamente]")

# 1. Crear tabla de usuarios si no existe
def init_users_db():
    con = None
    try:
        con = duckdb.connect(DB_PATH)
        con.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id VARCHAR PRIMARY KEY,
                nombre VARCHAR,
                empresa VARCHAR,
                telefono VARCHAR,
                email VARCHAR UNIQUE,
                password_hash VARCHAR,
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("--> [DB Users] Tabla 'usuarios' verificada/creada exitosamente.")
    except Exception as e:
        print("Error inicializando tabla usuarios:", e)
    finally:
        if con:
            con.close()

init_users_db()

# Modelos Pydantic
class RegisterModel(BaseModel):
    nombre: str
    empresa: str
    telefono: str
    email: str
    password: str

class LoginModel(BaseModel):
    email: str
    password: str

class ForgotPasswordModel(BaseModel):
    email: str
    nueva_password: Optional[str] = None


# --- MAPEO DIRECTO Y EXACTO DE COLUMNAS ---
PARAM_MAP = {
    "EXPEDIENTE": {
        "invima": "expediente",
        "sismed": "NoExpediente",
        "exact": True
    },
    "REGISTRO_SANITARIO": {
        "invima": "cod_registro_sanitario",
        "sismed": "registrosanitario",
        "exact": False
    },
    "PRINCIPIO_ACTIVO": {
        "invima": "sustancia",
        "sismed": "PRINCIPIO_RESUMEN",
        "exact": False
    },
    "NOMBRE_PRODUCTO": {
        "invima": "nombre_comercial",
        "sismed": "NOMBRE_RESUMEN",
        "exact": False
    }
}

def get_column_config(param_key: str):
    """Resuelve la clave enviada desde el frontend al grupo correcto sin falsos positivos."""
    key = (param_key or "EXPEDIENTE").upper().strip().replace(" ", "_")
    
    # Coincidencia directa por clave exacta
    if key in PARAM_MAP:
        return PARAM_MAP[key]
    
    # Evaluación por palabras clave si vienen variaciones de formato
    if "REGISTRO" in key or "SANITARI" in key or "COD" in key:
        return PARAM_MAP["REGISTRO_SANITARIO"]
    elif "PRINCIPIO" in key or "SUSTANCIA" in key or "ACTIVO" in key:
        return PARAM_MAP["PRINCIPIO_ACTIVO"]
    elif "NOMBRE" in key or "PRODUCTO" in key or "COMERCIAL" in key:
        return PARAM_MAP["NOMBRE_PRODUCTO"]
    else:
        return PARAM_MAP["EXPEDIENTE"]


# --- ENDPOINTS DE AUTENTICACIÓN ---

@app.post("/api/auth/registro")
def registrar_usuario(data: RegisterModel):
    con = None
    try:
        con = duckdb.connect(DB_PATH)
        clean_email = data.email.strip().lower()

        user_exists = con.execute("SELECT email FROM usuarios WHERE LOWER(email) = ?", [clean_email]).fetchone()
        if user_exists:
            return {"ok": False, "message": "El correo ya se encuentra registrado."}

        hashed_password = pwd_context.hash(data.password)
        user_id = str(uuid.uuid4())

        con.execute("""
            INSERT INTO usuarios (id, nombre, empresa, telefono, email, password_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [user_id, data.nombre.strip(), data.empresa.strip(), data.telefono.strip(), clean_email, hashed_password])
        
        return {
            "ok": True, 
            "message": "Usuario registrado exitosamente.", 
            "user": {"id": user_id, "nombre": data.nombre, "email": clean_email}
        }
    except Exception as e:
        return {"ok": False, "message": f"Error interno al registrar el usuario: {str(e)}"}
    finally:
        if con:
            con.close()


@app.post("/api/auth/login")
def login_usuario(data: LoginModel):
    con = None
    try:
        con = duckdb.connect(DB_PATH)
        clean_email = data.email.strip().lower()

        user = con.execute("""
            SELECT id, nombre, empresa, password_hash FROM usuarios WHERE LOWER(email) = ?
        """, [clean_email]).fetchone()

        if not user:
            return {"ok": False, "message": "Credenciales inválidas (correo no encontrado)."}

        user_id, nombre, empresa, password_hash = user

        if not pwd_context.verify(data.password, password_hash):
            return {"ok": False, "message": "Contraseña incorrecta."}

        return {
            "ok": True,
            "message": "Autenticación exitosa",
            "token": f"token-session-{user_id}",
            "user": {"id": user_id, "nombre": nombre, "empresa": empresa, "email": clean_email}
        }
    except Exception as e:
        return {"ok": False, "message": f"Error en el servidor al autenticar: {str(e)}"}
    finally:
        if con:
            con.close()


@app.post("/api/auth/recuperar")
def recuperar_password(data: ForgotPasswordModel):
    con = None
    try:
        con = duckdb.connect(DB_PATH)
        clean_email = data.email.strip().lower()

        user = con.execute("SELECT id FROM usuarios WHERE LOWER(email) = ?", [clean_email]).fetchone()

        if not user:
            return {"ok": False, "message": "El correo ingresado no existe en el sistema."}

        if data.nueva_password:
            new_hash = pwd_context.hash(data.nueva_password)
            con.execute("UPDATE usuarios SET password_hash = ? WHERE LOWER(email) = ?", [new_hash, clean_email])
            return {"ok": True, "message": "Contraseña actualizada correctamente."}

        return {"ok": True, "message": "Solicitud de restablecimiento procesada correctamente."}
    except Exception as e:
        return {"ok": False, "message": f"Error al procesar la solicitud: {str(e)}"}
    finally:
        if con:
            con.close()


# --- CONSULTAS DE DATOS ---

@app.get("/api/invima/total")
def total_invima():
    con = None
    try:
        con = duckdb.connect(DB_PATH, read_only=True)
        count = con.execute("SELECT COUNT(*) FROM registros_invima;").fetchone()[0]
        return {"total": count}
    except Exception as e:
        print("Error en total_invima:", e)
        return {"total": 0}
    finally:
        if con:
            con.close()


@app.get("/api/sismed/total")
def total_sismed(anio: Optional[str] = Query(None)):
    con = None
    try:
        con = duckdb.connect(DB_PATH, read_only=True)
        
        where_clause = ""
        params = []

        if (
            anio and 
            str(anio).strip() and 
            str(anio).strip().upper() not in ["2020-2026", "TODOS LOS AÑOS", "TODOS"]
        ):
            where_clause = " WHERE CAST(\"AnnioCorte\" AS VARCHAR) ILIKE ?"
            params.append(f"%{str(anio).strip()}%")

        count_sql = f"SELECT COUNT(*) FROM precios_sismed{where_clause}"
        total = con.execute(count_sql, params).fetchone()[0]

        return {"total": total}
    except Exception as e:
        print("Error en total_sismed:", e)
        return {"total": 15000000}
    finally:
        if con:
            con.close()


@app.get("/api/sismed/buscar")
def buscar_sismed(
    query: Optional[str] = Query(None), 
    param: Optional[str] = Query('EXPEDIENTE'),
    anio: Optional[str] = Query(None), 
    limit: int = Query(5)
):
    con = None
    try:
        con = duckdb.connect(DB_PATH, read_only=True)
        
        where_conditions = []
        params = []

        # 1. Filtro por Año sobre 'AnnioCorte'
        if (
            anio and 
            str(anio).strip() and 
            str(anio).strip().upper() not in ["2020-2026", "TODOS LOS AÑOS", "TODOS"]
        ):
            where_conditions.append("CAST(\"AnnioCorte\" AS VARCHAR) ILIKE ?")
            params.append(f"%{str(anio).strip()}%")

        # 2. Búsqueda dirigida sobre la columna asignada al parámetro
        if query and query.strip():
            clean_query = query.strip().lower()
            config = get_column_config(param)
            col_name = config["sismed"]
            col_sql = f"LOWER(CAST(\"{col_name}\" AS VARCHAR))"

            print(f"--> [SISMED] Query: '{clean_query}' | Param: '{param}' -> Columna SQL: '{col_name}'")

            if config["exact"]:
                where_conditions.append(f"{col_sql} = ?")
                params.append(clean_query)
            else:
                where_conditions.append(f"{col_sql} ILIKE ?")
                params.append(f"%{clean_query}%")

        where_clause = f" WHERE {' AND '.join(where_conditions)}" if where_conditions else ""

        count_sql = f"SELECT COUNT(*) FROM precios_sismed{where_clause}"
        total = con.execute(count_sql, params).fetchone()[0]

        data_sql = f"SELECT * FROM precios_sismed{where_clause} LIMIT ?"
        df = con.execute(data_sql, params + [limit]).df()
        
        if 'registrosanitario' in df.columns:
            df['registrosanitario'] = df['registrosanitario'].fillna('0').replace('', '0')
            
        df = df.fillna('')

        return {
            "total": int(total),
            "data": df.to_dict(orient="records")
        }
    except Exception as e:
        print("Error en buscar_sismed:", e)
        return {"total": 0, "data": []}
    finally:
        if con:
            con.close()


@app.get("/api/invima/buscar")
def buscar_invima(
    query: Optional[str] = Query(None), 
    param: Optional[str] = Query('EXPEDIENTE'),
    limit: int = Query(5)
):
    con = None
    try:
        con = duckdb.connect(DB_PATH, read_only=True)

        where_conditions = []
        params = []

        if query and query.strip():
            clean_query = query.strip().lower()
            config = get_column_config(param)
            col_name = config["invima"]
            col_sql = f"LOWER(CAST(\"{col_name}\" AS VARCHAR))"

            print(f"--> [INVIMA] Query: '{clean_query}' | Param: '{param}' -> Columna SQL: '{col_name}'")

            if config["exact"]:
                where_conditions.append(f"{col_sql} = ?")
                params.append(clean_query)
            else:
                where_conditions.append(f"{col_sql} ILIKE ?")
                params.append(f"%{clean_query}%")

        where_clause = f" WHERE {' AND '.join(where_conditions)}" if where_conditions else ""

        count_sql = f"SELECT COUNT(*) FROM registros_invima{where_clause}"
        total = con.execute(count_sql, params).fetchone()[0]

        data_sql = f"SELECT * FROM registros_invima{where_clause} LIMIT ?"
        df = con.execute(data_sql, params + [limit]).df()
        df = df.fillna('')

        return {
            "total": int(total),
            "data": df.to_dict(orient="records")
        }
    except Exception as e:
        print("Error en buscar_invima:", e)
        return {"total": 0, "data": []}
    finally:
        if con:
            con.close()


# DENTRO DE main.py

@app.get("/api/sismed/exportar")
def exportar_sismed(
    query: Optional[str] = Query(None), 
    param: Optional[str] = Query('EXPEDIENTE'),
    anio: Optional[str] = Query(None)
):
    # Bloqueo de seguridad: No permitir descarga sin búsqueda previa
    if not query or not query.strip():
        raise HTTPException(
            status_code=400, 
            detail="Debe proporcionar un término de búsqueda para exportar datos."
        )

    con = None
    try:
        con = duckdb.connect(DB_PATH, read_only=True)

        where_conditions = []
        params = []

        # 1. Filtro por Año
        if (
            anio and 
            str(anio).strip() and 
            str(anio).strip().upper() not in ["2020-2026", "TODOS LOS AÑOS", "TODOS"]
        ):
            where_conditions.append("CAST(\"AnnioCorte\" AS VARCHAR) ILIKE ?")
            params.append(f"%{str(anio).strip()}%")

        # 2. Filtro obligatorio por consulta y parámetro
        clean_query = query.strip().lower()
        config = get_column_config(param)
        col_name = config["sismed"]
        col_sql = f"LOWER(CAST(\"{col_name}\" AS VARCHAR))"

        if config["exact"]:
            where_conditions.append(f"{col_sql} = ?")
            params.append(clean_query)
        else:
            where_conditions.append(f"{col_sql} ILIKE ?")
            params.append(f"%{clean_query}%")

        where_clause = f" WHERE {' AND '.join(where_conditions)}"

        df = con.execute(f"SELECT * FROM precios_sismed{where_clause}", params).df()
        
        if 'registrosanitario' in df.columns:
            df['registrosanitario'] = df['registrosanitario'].fillna('0').replace('', '0')
            
        df = df.fillna('')

        csv_data = '\uFEFF' + df.to_csv(index=False)
        return Response(
            content=csv_data,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=Reporte_SISMED_Filtrado.csv"}
        )
    except HTTPException:
        raise
    except Exception as e:
        print("Error en exportar_sismed:", e)
        return Response(content="Error generando el reporte", status_code=500)
    finally:
        if con:
            con.close()


@app.get("/api/invima/exportar")
def exportar_invima(
    query: Optional[str] = Query(None),
    param: Optional[str] = Query('EXPEDIENTE')
):
    # Bloqueo de seguridad: No permitir descarga sin búsqueda previa
    if not query or not query.strip():
        raise HTTPException(
            status_code=400, 
            detail="Debe proporcionar un término de búsqueda para exportar datos."
        )

    con = None
    try:
        con = duckdb.connect(DB_PATH, read_only=True)

        where_conditions = []
        params = []

        clean_query = query.strip().lower()
        config = get_column_config(param)
        col_name = config["invima"]
        col_sql = f"LOWER(CAST(\"{col_name}\" AS VARCHAR))"

        if config["exact"]:
            where_conditions.append(f"{col_sql} = ?")
            params.append(clean_query)
        else:
            where_conditions.append(f"{col_sql} ILIKE ?")
            params.append(f"%{clean_query}%")

        where_clause = f" WHERE {' AND '.join(where_conditions)}"

        df = con.execute(f"SELECT * FROM registros_invima{where_clause}", params).df()
        df = df.fillna('')

        csv_data = '\uFEFF' + df.to_csv(index=False)
        return Response(
            content=csv_data,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=Reporte_INVIMA_Filtrado.csv"}
        )
    except HTTPException:
        raise
    except Exception as e:
        print("Error en exportar_invima:", e)
        return Response(content="Error generando el reporte", status_code=500)
    finally:
        if con:
            con.close()