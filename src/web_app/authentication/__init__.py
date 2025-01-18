#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
from datetime import datetime, timedelta
from typing import Union, Any

from dotenv import load_dotenv
from jose import jwt, JWTError
from passlib.context import CryptContext

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Password hashing configuration
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
ALGORITHM = "HS256"
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
JWT_REFRESH_SECRET_KEY = os.environ.get('JWT_REFRESH_SECRET_KEY')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES', 15))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.environ.get('REFRESH_TOKEN_EXPIRE_MINUTES', 1440))

if not JWT_SECRET_KEY or not JWT_REFRESH_SECRET_KEY:
    logger.critical("JWT secret keys are missing from the environment variables.")
    raise EnvironmentError("JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY must be set.")


def get_hashed_password(password: str) -> str:
    """Hash a plain password."""
    if not password:
        logger.error("Password cannot be empty.")
        raise ValueError("Password cannot be empty.")

    hashed = password_context.hash(password)
    logger.info("Password hashed successfully.")
    return hashed


def verify_password(password: str, hashed_pass: str) -> bool:
    """Verify a plain password against its hash."""
    result = password_context.verify(password, hashed_pass)
    logger.info("Password verification %s.", "succeeded" if result else "failed")
    return result


def create_access_token(subject: Union[str, Any], expires_delta: timedelta = None) -> str:
    """Create a new access token."""
    try:
        if not subject:
            logger.error("Subject is required to create an access token.")
            raise ValueError("Subject cannot be empty.")

        expires_at = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        payload = {"exp": expires_at, "sub": str(subject)}
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)
        logger.info("Access token created successfully.")
        return token
    except Exception as e:
        logger.error(f"Error creating access token: {e}")
        raise


def create_refresh_token(subject: Union[str, Any], expires_delta: timedelta = None) -> str:
    """Create a new refresh token."""
    try:
        if not subject:
            logger.error("Subject is required to create a refresh token.")
            raise ValueError("Subject cannot be empty.")

        expires_at = datetime.utcnow() + (expires_delta or timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES))
        payload = {"exp": expires_at, "sub": str(subject)}
        token = jwt.encode(payload, JWT_REFRESH_SECRET_KEY, algorithm=ALGORITHM)
        logger.info("Refresh token created successfully.")
        return token
    except Exception as e:
        logger.error(f"Error creating refresh token: {e}")
        raise


def decode_token(token: str, secret_key: str) -> dict:
    """Decode a JWT token and validate its payload."""
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        logger.info("Token decoded successfully.")
        return payload
    except JWTError as e:
        logger.error(f"Invalid token: {e}")
        raise ValueError("Invalid token.")


# Example usage
if __name__ == "__main__":
    try:
        test_subject = "user123"
        access_token = create_access_token(test_subject)
        logger.info(f"Access Token: {access_token}")

        refresh_token = create_refresh_token(test_subject)
        logger.info(f"Refresh Token: {refresh_token}")

        decoded_access = decode_token(access_token, JWT_SECRET_KEY)
        logger.info(f"Decoded Access Token: {decoded_access}")

        decoded_refresh = decode_token(refresh_token, JWT_REFRESH_SECRET_KEY)
        logger.info(f"Decoded Refresh Token: {decoded_refresh}")
    except Exception as e:
        logger.critical(f"Critical error: {e}")
