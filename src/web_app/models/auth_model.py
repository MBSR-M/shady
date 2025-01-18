#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pydantic import BaseModel, Field


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str


class TokenPayload(BaseModel):
    sub: str = None
    exp: int = None


class UserAuth(BaseModel):
    name: str = Field(..., description="user name")
    email: str = Field(..., description="user email")
    password: str = Field(..., min_length=5, max_length=24, description="user password")
    status: bool = Field(..., description="user status")


class UserOut(BaseModel):
    id: int
    email: str


class SystemUser(UserOut):
    password: str
