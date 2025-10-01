from contextlib import asynccontextmanager
import bcrypt
from fastapi import FastAPI
from pydantic import BaseModel
import yaml

VERSION = "1.0.0"

with open("config.yml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

class UserRegistration(BaseModel):
    username: str
    password: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    pass
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
async def register(user: UserRegistration):
    if config["registrations"]:
        if len(user.username) < 3 or len(user.username) > 16:
            return {
                "error": "Username must be between 3 and 16 characters."
            }
        if len(user.password) < 8 or len(user.password) > 32:
            return {
                "error": "Password must be between 8 and 32 characters."
            }
        # converting password to array of bytes
        bytes = user.password.encode('utf-8')

        # generating the salt
        salt = bcrypt.gensalt()

        # Hashing the password
        hash = bcrypt.hashpw(bytes, salt)

        return(hash)
            
    else:
        return {
            "error": "Registrations are currently disabled."
        }