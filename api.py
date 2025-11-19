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
JWT_ACCESS_EXPIRES = int(os.getenv("JWT_ACCESS_EXPIRES", "90"))
JWT_REFRESH_EXPIRES = int(os.getenv("JWT_REFRESH_EXPIRES", "2592000"))


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
                TokenScope.data_0mb,
                TokenScope.data_2mb,
                TokenScope.data_10mb,
                TokenScope.data_unlimited,
            ]
        case Role.user:
            return [
                #TokenScope.data_0mb,
                TokenScope.data_2mb,
                #TokenScope.data_10mb,
            ]


def get_max_data_size(scopes: List[TokenScope]) -> int:
    max_size = 0
    
    if TokenScope.data_unlimited in scopes:
        return -1
    
    if TokenScope.data_10mb in scopes:
        max_size = max(max_size, 10 * 1024 * 1024)
    
    if TokenScope.data_2mb in scopes:
        max_size = max(max_size, 2 * 1024 * 1024)
    
    if TokenScope.data_0mb in scopes:
        max_size = max(max_size, 0)
    
    return max_size


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


def require_scope(required_scope: TokenScope):
    async def scope_checker(context: dict = Depends(get_current_user)):
        token_scopes = context.get("scope", [])
        if required_scope not in token_scopes:
            raise HTTPException(status_code=403, detail=f"Missing required scope: {required_scope}")
        return context["user"]

    return scope_checker


def validate_data_size(data_size: int, scopes: List[TokenScope]) -> bool:
    max_allowed = get_max_data_size(scopes)
    
    if max_allowed == -1:
        return True
    
    return data_size <= max_allowed


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

@router.post("/upload")
async def upload_data(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    content_length = request.headers.get("content-length")
    if not content_length:
        raise HTTPException(status_code=411, detail="Content-Length header required")
    
    data_size = int(content_length)
    scopes = current_user.get("scope", [])
    
    if not validate_data_size(data_size, scopes):
        max_allowed = get_max_data_size(scopes)
        raise HTTPException(
            status_code=413, 
            detail=f"Data size ({data_size} bytes) exceeds allowed limit ({max_allowed} bytes)"
        )
    
    return {
        "message": f"Successfully uploaded {data_size} bytes",
        "max_allowed": get_max_data_size(scopes)
    }


@router.get("/my_limits")
async def get_my_limits(current_user: dict = Depends(get_current_user)):
    scopes = current_user.get("scope", [])
    max_size = get_max_data_size(scopes)
    
    return {
        "username": current_user["user"].username,
        "scopes": scopes,
        "max_data_size_bytes": max_size,
        "max_data_size_human": "unlimited" if max_size == -1 else f"{max_size / (1024*1024):.1f} MB"
    }


@router.get("/data_0mb")
async def data_0mb_route(current_user: User = Depends(require_scope(TokenScope.data_0mb))):
    return {"message": f"Welcome, {current_user.username}. You have access to 0MB data scope."}


@router.get("/data_2mb") 
async def data_2mb_route(current_user: User = Depends(require_scope(TokenScope.data_2mb))):
    return {"message": f"Welcome, {current_user.username}. You have access to 2MB data scope."}


@router.get("/data_10mb")
async def data_10mb_route(current_user: User = Depends(require_scope(TokenScope.data_10mb))):
    return {"message": f"Welcome, {current_user.username}. You have access to 10MB data scope."}


@router.get("/data_unlimited")
async def data_unlimited_route(current_user: User = Depends(require_scope(TokenScope.data_unlimited))):
    return {"message": f"Welcome, {current_user.username}. You have unlimited data access."}

@router.get("/health")
async def health_check():
    return {"status": "Hello World check"}
