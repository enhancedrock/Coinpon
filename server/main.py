import os
from contextlib import asynccontextmanager
import bcrypt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import yaml
import aiosqlite

VERSION = "1.0.0"
DB_PATH = os.getenv("DB_PATH", "database.db")

with open("config.yml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

class UserAuth(BaseModel):
    username: str
    password: str

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        await db.commit()

async def user_exists(username: str) -> bool:
    """Check if a user already exists in the database."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        result = await cursor.fetchone()
        return result is not None

async def create_user(username: str, password_hash: bytes):
    """Create a new user in the database."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash.decode('utf-8'))
        )
        await db.commit()

async def get_user_hash(username: str) -> str | None:
    """Get password hash for a user"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = await cursor.fetchone()
        return result[0] if result else None

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    pass

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def read_root():
    return {
        "coinpon": VERSION,
        "estrogen": True
    }

@app.post("/register")
async def register(user: UserAuth):
    if not config["registrations"]:
        raise HTTPException(status_code=403, detail="Registrations are currently disabled.")
    if len(user.username) < 3 or len(user.username) > 16:
        raise HTTPException(status_code=400, detail="Username must be between 3 and 16 characters.")
    if len(user.password) < 8 or len(user.password) > 32:
        raise HTTPException(status_code=400, detail="Password must be between 8 and 32 characters.")

    if await user_exists(user.username):
        raise HTTPException(status_code=400, detail="Username already exists.")

    passhash = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())

    try:
        await create_user(user.username, passhash)
        return {"message": "User registered successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error.") from e

@app.post("/login")
async def login(user: UserAuth):
    stored_hash = await get_user_hash(user.username)
    if not stored_hash:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if not bcrypt.checkpw(user.password.encode('utf-8'), stored_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    return {"message": "Login successful."}
