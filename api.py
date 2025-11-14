import os
from datetime import datetime, timedelta, timezone
from typing import List

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from model import Role, User, get_db
from schema import RefreshTokenModel, TokenModel, TokenScope, TokenType, UserModel

load_dotenv()

JWT_ACCESS_SECRET = os.getenv("JWT_ACCESS_SECRET", "default_access_secret")
JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET", "default_refresh_secret")
JWT_ACCESS_EXPIRES = int(os.getenv("JWT_ACCESS_EXPIRES_S", "900"))
JWT_REFRESH_EXPIRES = int(os.getenv("JWT_REFRESH_EXPIRES_S", "2592000"))
SALT = os.getenv("SALT", "default_salt")


api_router = APIRouter()
router = api_router


async def get_user_by_username(email: str, db: AsyncSession):
    query = select(User).where(User.username == email)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def create_user(user: UserModel, db: AsyncSession):
    hashed_password = hash_password(user.password)
    query = insert(User).values(
        username=user.username,
        hashed_password=hashed_password,
        user_role=user.role,
    )
    await db.execute(query)
    await db.commit()
    return await get_user_by_username(user.username, db)


def create_token(payload: dict, key):
    return jwt.encode(payload, key, algorithm="HS256")


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def validate_token(token: str, key):
    return jwt.decode(token, key, algorithms="HS256")


def create_access_token(data: dict):
    data["exp"] = datetime.now(timezone.utc) + timedelta(seconds=JWT_ACCESS_EXPIRES)
    data["type"] = TokenType.access
    return create_token(data, JWT_ACCESS_SECRET)


def create_refresh_token(data: dict):
    data["exp"] = datetime.now(timezone.utc) + timedelta(seconds=JWT_REFRESH_EXPIRES)
    data["type"] = TokenType.refresh
    return create_token(data, JWT_REFRESH_SECRET)


def get_scopes_for_role(role: Role):
    match role:
        case Role.admin:
            return [
                TokenScope.read_admin,
                TokenScope.write_admin,
            ]
        case Role.user:
            return [TokenScope.read_user, TokenScope.write_user]


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = auth_header.replace("Bearer ", "").strip()

    try:
        payload = validate_token(token, JWT_ACCESS_SECRET)
        if payload.get("type") != TokenType.access:
            raise HTTPException(status_code=401, detail="Invalid token type")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid access token")

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    db_user = await get_user_by_username(username, db)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"user": db_user, "scope": payload.get("scope")}


def require_all_scopes(required_scopes: List[TokenScope]):
    async def scope_checker(context: dict = Depends(get_current_user)):
        token_scopes = context.get("scope", [])
        if not all(scope in token_scopes for scope in required_scopes):
            raise HTTPException(status_code=403, detail="Missing required scopes")
        return context["user"]

    return scope_checker


@router.post("/login", response_model=TokenModel)
async def login(user: UserModel, db=Depends(get_db)):
    db_user = await get_user_by_username(user.username, db)

    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_payload = {
        "sub": db_user.username,
        "scope": get_scopes_for_role(db_user.user_role),
    }

    refresh_payload = {"sub": db_user.username}

    access_token = create_access_token(access_payload)
    refresh_token = create_refresh_token(refresh_payload)

    return TokenModel(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=JWT_ACCESS_EXPIRES,
    )


@router.post("/register", response_model=TokenModel)
async def register(user: UserModel, db=Depends(get_db)):
    db_user = await get_user_by_username(user.username, db)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    result = await create_user(user, db)

    access_payload = {
        "sub": result.username,
        "scope": get_scopes_for_role(result.user_role),
    }

    refresh_payload = {
        "sub": result.username,
    }

    access_token = create_access_token(access_payload)
    refresh_token = create_refresh_token(refresh_payload)

    return TokenModel(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=JWT_ACCESS_EXPIRES,
    )


@router.get("/logout")
async def logout():
    return {"message": "Logout successful"}


@router.post("/refresh", response_model=TokenModel)
async def refresh_token(
    token_data: RefreshTokenModel, db: AsyncSession = Depends(get_db)
):
    try:
        payload = validate_token(token_data.refresh_token, JWT_REFRESH_SECRET)
        if payload.get("type") != TokenType.refresh:
            raise HTTPException(status_code=401, detail="Invalid token type")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    db_user = await get_user_by_username(username, db)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    new_access_payload = {
        "sub": db_user.username,
        "scope": get_scopes_for_role(db_user.user_role),
    }

    new_refresh_payload = {
        "sub": db_user.username,
    }

    new_access_token = create_access_token(new_access_payload)
    new_refresh_token = create_refresh_token(new_refresh_payload)

    return TokenModel(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=JWT_ACCESS_EXPIRES,
    )


@router.get("/full_admin")
async def full_admin_route(
    current_user: User = Depends(
        require_all_scopes([TokenScope.read_admin, TokenScope.write_admin])
    ),
):
    return {"message": f"Welcome, {current_user.username}. You have full-admin access."}


@router.get("/read_admin")
async def read_admin_route(
    current_user: User = Depends(require_all_scopes([TokenScope.write_admin])),
):
    return {"message": f"Welcome, {current_user.username}. You have semi-admin access."}


@router.get("/read_user")
async def read_user_route(
    current_user: User = Depends(require_all_scopes([TokenScope.read_user])),
):
    return {"message": f"Welcome, {current_user.username}. You have user access."}


@router.get("/health")
async def health_check():
    return {"status": "Hello World"}
