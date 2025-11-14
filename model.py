import os
from enum import Enum

from dotenv import load_dotenv
from sqlalchemy import Integer, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, declarative_base, mapped_column

load_dotenv()

SQL_URL = os.getenv(
    "DATABASE_URL", "sqlite+aiosqlite:///./auth.db"
)


engine = create_async_engine(SQL_URL, echo=True)
db_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db():
    async with db_session() as session:
        try:
            yield session
        finally:
            await session.close()


Base = declarative_base()


async def init_db():
    async with engine.begin() as conn:
        # # Drop all tables (be careful in production!)
        # await conn.run_sync(Base.metadata.drop_all)
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)


class Role(str, Enum):
    user = "user"
    admin = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(128))
    user_role: Mapped[Role] = mapped_column(String(50))
