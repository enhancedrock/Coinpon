"""Main coinpoin server"""
import os
from typing import Optional
import re
from contextlib import asynccontextmanager
import secrets
import bcrypt
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse
from pydantic import BaseModel
import yaml
import aiosqlite

VERSION = "1.0.0"
DB_PATH = os.getenv("DB_PATH", "database.db")

with open("config.yml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

class UserAuth(BaseModel):
    """Use authentication model"""
    username: str
    password: str

class TokenModel(BaseModel):
    """Token check model"""
    token: str

async def init_db():
    """Initialize the database and create tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        tokenhash = bcrypt.hashpw(secrets.token_hex(32).encode('utf-8'), bcrypt.gensalt())
        await db.execute(
            "INSERT INTO users (username, password_hash, token) VALUES (?, ?, ?)",
            (username, password_hash.decode('utf-8'), tokenhash.decode('utf-8'))
        )
        await db.commit()

async def get_user_hash(username: str) -> Optional[str]:
    """Get password hash for a user"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = await cursor.fetchone()
        return result[0] if result else None

async def verify_token(username: str, token: str) -> bool:
    """Verify if token is valid for a user"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT token FROM users WHERE username = ?", (username,))
        result = await cursor.fetchone()
        if result is None or result[0] is None:
            return False
        stored_token_hash = result[0]
        if bcrypt.checkpw(token.encode('utf-8'), stored_token_hash.encode('utf-8')):
            return True
        else:
            return False
        
async def identify_user(token: str) -> Optional[str]:
    """Identify a user by their token"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT username, token FROM users")
        async for row in cursor:
            username, stored_token_hash = row
            if bcrypt.checkpw(token.encode('utf-8'), stored_token_hash.encode('utf-8')):
                return username
    return None

async def generate_token(username: str) -> str:
    """Generate a new token for a user"""
    token = secrets.token_hex(32)
    tokenhash = bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET token = ? WHERE username = ?",
                         (tokenhash.decode('utf-8'), username))
        await db.commit()
    return token

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database on startup."""
    await init_db()
    yield

app = FastAPI(lifespan=lifespan)

@app.post("/api/account/whoami")
async def account_details(token: TokenModel):
    """Get account details"""
    username = await identify_user(token.token)
    if username is None:
        raise HTTPException(status_code=404, detail="User not found or invalid token.")
    return {"username": username}

@app.get("/api/hello")
async def hello():
    """Get server information"""
    return {
        "coinpon": VERSION,
        "estrogen": True,
        "motd": config.get("motd", "Welcome to Coinpon!")
    }

@app.post("/api/register")
async def register(user: UserAuth):
    """Register a new user"""
    if not config["registrations"]:
        raise HTTPException(status_code=403, detail="Registrations are currently disabled.")
    if len(user.username) < 3 or len(user.username) > 16:
        raise HTTPException(status_code=400, detail="Username must be between 3 and 16 characters.")
    if not re.match("^[a-zA-Z0-9_]+$", user.username):
        raise HTTPException(status_code=400,
                            detail="Username can only contain letters, numbers, and underscores.")
    if len(user.password) < 8 or len(user.password) > 32:
        raise HTTPException(status_code=400, detail="Password must be between 8 and 32 characters.")

    if await user_exists(user.username):
        raise HTTPException(status_code=400, detail="Username already exists.")

    passhash = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())

    try:
        await create_user(user.username, passhash)
        return {"detail": "User registered successfully."}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal server error.") from e

@app.post("/api/login")
async def login(user: UserAuth):
    """Login a user"""
    stored_hash = await get_user_hash(user.username)
    if not stored_hash:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if not bcrypt.checkpw(user.password.encode('utf-8'), stored_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    return {"token": await generate_token(user.username)}

@app.get("/")
async def redirect_to_auth():
    """Redirect to login page"""
    return RedirectResponse(
        url="/client/pon.html",
        status_code=302
    )

@app.get("/favicon.ico")
async def favicon():
    """Serve favicon"""
    return FileResponse("client/favicon.ico")

app.mount("/client", StaticFiles(directory="client", html=True), name="client")
