#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os

from dotenv import load_dotenv, find_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from mysql.connector import pooling
from starlette.responses import JSONResponse

from web_app.routers.auth import router as auth

# Load environment variables
load_dotenv(find_dotenv())

# Validate environment variables
REQUIRED_ENV_VARS = [
    "DB_HOST", "DB_PORT", "DB_USER", "DB_PASS", "DB_NAME",
    "WRITE_DB_HOST", "WRITE_DB_PORT", "WRITE_DB_USER", "WRITE_DB_PASS", "WRITE_DB_NAME",
    "READ_DB_HOST", "READ_DB_PORT", "READ_DB_USER", "READ_DB_PASS", "READ_DB_NAME",
    "JWT_REFRESH_SECRET_KEY"
]
for var in REQUIRED_ENV_VARS:
    if not os.environ.get(var):
        raise EnvironmentError(f"Missing required environment variable: {var}")

# Logger configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("uvicorn")


# Singleton MySQL Connection Pool
class MySQLConnector:
    _instances = {}

    def __new__(cls, role="read"):
        if role not in cls._instances:
            logger.info(f"Initializing MySQL connection pool for {role} role.")
            if role == "read":
                cls._instances[role] = pooling.MySQLConnectionPool(
                    pool_name="read_pool",
                    pool_size=10,
                    host=os.environ["READ_DB_HOST"],
                    port=int(os.environ["READ_DB_PORT"]),
                    user=os.environ["READ_DB_USER"],
                    password=os.environ["READ_DB_PASS"],
                    database=os.environ["READ_DB_NAME"],
                )
            elif role == "write":
                cls._instances[role] = pooling.MySQLConnectionPool(
                    pool_name="write_pool",
                    pool_size=5,
                    host=os.environ["WRITE_DB_HOST"],
                    port=int(os.environ["WRITE_DB_PORT"]),
                    user=os.environ["WRITE_DB_USER"],
                    password=os.environ["WRITE_DB_PASS"],
                    database=os.environ["WRITE_DB_NAME"],
                )
            else:
                raise ValueError("Invalid role specified for MySQLConnector.")
        return cls._instances[role]

    @staticmethod
    def get_connection(role="read"):
        pool = MySQLConnector(role)
        logger.info(f"Acquiring connection from {role} pool.")
        return pool.get_connection()


# Initialize FastAPI app
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None,
              version='2025.1.1v', description='mbsr application')

# Middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth)


@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint():
    return JSONResponse(get_openapi(title="FastAPI", version="1", routes=app.routes))


@app.get("/docs", include_in_schema=False)
async def get_documentation():
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")


@app.get("/")
async def welcome():
    logger.info("Welcome endpoint called")
    return {"message": "FastAPI Running"}


@app.get("/test-db-read")
async def test_db_read():
    try:
        conn = MySQLConnector.get_connection("read")
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT NOW() AS current_time;")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return {"success": True, "current_time": result["current_time"]}
    except Exception as e:
        logger.error("Error during DB read operation", exc_info=True)
        return {"success": False, "error": str(e)}


@app.get("/test-db-write")
async def test_db_write():
    try:
        conn = MySQLConnector.get_connection("write")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO test_table (test_col) VALUES ('test_value');")
        conn.commit()
        cursor.close()
        conn.close()
        return {"success": True, "message": "Write operation successful."}
    except Exception as e:
        logger.error("Error during DB write operation", exc_info=True)
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        log_level="info",
        reload=True,
    )
