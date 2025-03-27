from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
import mysql.connector
import bcrypt
import jwt
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "mysecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI App
app = FastAPI()

# OAuth2PasswordBearer extracts token from request
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# MySQL Database Connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="password",
    database="fastapi_auth"
)
cursor = db.cursor()

# Create Users Table (If Not Exists)
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fullname VARCHAR(100),
        username VARCHAR(50) UNIQUE,
        email VARCHAR(100) UNIQUE,
        password VARCHAR(255)
    )
""")
db.commit()

# Pydantic Models
class UserCreate(BaseModel):
    fullname: str
    username: str
    email: str
    password: str

class TokenData(BaseModel):
    username: str | None = None

# Function to Hash Password
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

# Function to Verify Password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

# Function to Create JWT Token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# User Signup Route
@app.post("/signup/")
async def signup(user: UserCreate):
    cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (user.username, user.email))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username or Email already registered")
    
    hashed_password = hash_password(user.password)
    cursor.execute("INSERT INTO users (fullname, username, email, password) VALUES (%s, %s, %s, %s)",
                   (user.fullname, user.username, user.email, hashed_password))
    db.commit()
    
    return {"message": "User registered successfully"}

# User Login Route
@app.post("/login/")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    cursor.execute("SELECT * FROM users WHERE username = %s", (form_data.username,))
    user = cursor.fetchone()

    if not user or not verify_password(form_data.password, user[4]):  # Password stored at index 4
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user[2]})  # Username stored at index 2
    return {"access_token": access_token, "token_type": "bearer"}

# Function to Verify JWT Token
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# Protected Route
@app.get("/protected/")
async def protected_route(username: str = Depends(verify_token)):
    return {"message": f"Hello, {username}! You have access to this protected page."}
