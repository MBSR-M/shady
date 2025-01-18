#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from pydantic import ValidationError
from starlette.responses import JSONResponse

from main import MySQLConnector
from web_app.authentication import (
    create_access_token,
    create_refresh_token,
    JWT_REFRESH_SECRET_KEY,
    ALGORITHM,
    get_hashed_password,
    verify_password
)
from web_app.authentication.auth import get_current_user
from web_app.models.auth_model import TokenPayload, TokenSchema, UserAuth, SystemUser, UserOut

# Initialize APIRouter
router = APIRouter(
    prefix='/api',
    tags=['API Auth'],
)

# Logger configuration
gunicorn_error_logger = logging.getLogger("gunicorn.error")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@router.post('/client-signup', description='Signup user for API client', status_code=201)
async def create_user(data: UserAuth):
    conn = MySQLConnector.get_connection("read")
    connWrite = MySQLConnector.get_connection("write")
    try:
        logger.info("Checking if user already exists with email: %s", data.email)
        query = f"""
        SELECT name, email, password, status FROM api_users WHERE email='{data.email}' LIMIT 1;
        """
        result = await conn.execute_query_dict(query)
        if result:
            logger.warning("User already exists: %s", data.email)
            return JSONResponse(status_code=200, content={"success": False, "message": "User already exists"})

        hashed_password = get_hashed_password(data.password)
        logger.info("Creating new user: %s", data.email)
        insert_query = f"""
        INSERT INTO api_users (name, email, password, status) VALUES ('{data.name}', '{data.email}', '{hashed_password}', '{data.status}');
        """
        await connWrite.execute_query_dict(insert_query)

        logger.info("User created successfully: %s", data.email)
        return {
            "success": True,
            "message": "User created successfully",
            "name": data.name,
            "email": data.email
        }

    except Exception as e:
        logger.error("Error during user signup", exc_info=True)
        return JSONResponse(status_code=400, content={"error": str(e), "success": False})


@router.post('/client-login', summary="Create access and refresh tokens for user", response_model=TokenSchema)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = MySQLConnector.get_connection("read")
    try:
        logger.info("Attempting login for email: %s", form_data.username)
        query = f"""
        SELECT name, email, password, status FROM api_users WHERE email='{form_data.username}' LIMIT 1;
        """
        result = await conn.execute_query_dict(query)
        if not result:
            logger.warning("Login failed: Email not found: %s", form_data.username)
            return JSONResponse(status_code=400, content={"success": False, "message": "Incorrect email or password"})

        user_data = result[0]
        if not verify_password(form_data.password, user_data['password']):
            logger.warning("Login failed: Incorrect password for email: %s", form_data.username)
            return JSONResponse(status_code=400, content={"success": False, "message": "Incorrect email or password"})

        logger.info("Login successful for email: %s", form_data.username)
        return {
            "access_token": create_access_token(user_data['email']),
            "refresh_token": create_refresh_token(user_data['email']),
        }

    except Exception as e:
        logger.error("Error during login", exc_info=True)
        return JSONResponse(status_code=400, content={"error": str(e), "success": False})


@router.post('/client-reset-password', summary="Reset password", response_model=dict)
async def reset_password(name: str, email: str, password: str):
    connWrite = MySQLConnector.get_connection("write")
    try:
        logger.info("Resetting password for user: %s", email)
        hashed_password = get_hashed_password(password)
        update_query = f"""
        UPDATE api_users SET password='{hashed_password}' WHERE name='{name}' AND email='{email}';
        """
        await connWrite.execute_query_dict(update_query)
        logger.info("Password reset successfully for user: %s", email)
        return {"success": True, "message": "Password reset successfully"}

    except Exception as e:
        logger.error("Error during password reset", exc_info=True)
        return JSONResponse(status_code=400, content={"error": str(e), "success": False})


@router.get('/test-token', summary='Get details of currently logged-in user', response_model=UserOut)
async def get_client_user(user: SystemUser = Depends(get_current_user)):
    logger.info("Fetching current user details for: %s", user.email)
    return user


@router.post('/refresh', summary="Refresh token", response_model=TokenSchema)
async def refresh_token(refresh_user_token: str = Body(...)):
    conn = MySQLConnector.get_connection("read")
    try:
        logger.info("Refreshing token.")
        payload = jwt.decode(refresh_user_token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        token_data = TokenPayload(**payload)
    except (jwt.JWTError, ValidationError):
        logger.warning("Invalid refresh token.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    query = f"""
    SELECT id, name, email FROM api_users WHERE email='{token_data.sub}';
    """
    result = await conn.execute_query_dict(query)
    if not result:
        logger.warning("User not found for token refresh: %s", token_data.sub)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    user = result[0]
    logger.info("Token refreshed successfully for user: %s", user['email'])
    return {
        "access_token": create_access_token(user["email"]),
        "refresh_token": create_refresh_token(user["email"]),
    }
