from enum import Enum

from pydantic import BaseModel

from model import Role


class TokenModel(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int


class RefreshTokenModel(BaseModel):
    refresh_token: str


class TokenScope(str, Enum):
    read_user = "user:read"
    write_user = "user:write"
    read_admin = "admin:read"
    write_admin = "admin:write"


class TokenType(str, Enum):
    access = "access"
    refresh = "refresh"


class UserModel(BaseModel):
    username: str
    password: str
    role: Role = Role.user

    class Config:
        orm_mode = True


class UserResponseModel(BaseModel):
    id: int
    username: str
    role: Role

    class Config:
        orm_mode = True
