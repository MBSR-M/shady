#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
import logging
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError

from web_app.authentication import ALGORITHM, JWT_SECRET_KEY
from web_app.models.auth_model import SystemUser, TokenPayload

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OAuth2 password bearer configuration
reusable_oauth = OAuth2PasswordBearer(
    tokenUrl="api/client-login",
    scheme_name="JWT"
)


async def get_current_user(token: str = Depends(reusable_oauth)) -> SystemUser:
    """
    Validates the provided JWT token and retrieves the current user.

    Args:
        token (str): JWT token extracted from the Authorization header.

    Returns:
        SystemUser: The user corresponding to the token.

    Raises:
        HTTPException: If the token is invalid, expired, or fails validation.
    """
    try:
        logger.debug("Decoding JWT token.")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        logger.info("JWT token successfully decoded.")

        # Validate token payload
        token_data = TokenPayload(**payload)
        if datetime.fromtimestamp(token_data.exp) < datetime.utcnow():
            logger.warning("Token has expired.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Return the user (placeholder for actual user lookup logic)
        user = SystemUser(**token_data.dict())
        logger.info("User validated successfully: %s", user.username)
        return user

    except JWTError as e:
        logger.error("JWT decoding failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except ValidationError as e:
        logger.error("Validation error in token payload: %s", e)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as e:
        logger.critical("Unexpected error occurred during token validation: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
