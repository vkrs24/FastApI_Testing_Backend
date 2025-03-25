from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import mysql.connector as connector
from passlib.context import CryptContext

app = FastAPI()

# Enabling the CORS policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True
)

# Database connection
try:
    db = connector.connect(
        host="sql.freedb.tech",
        user="freedb_ListenX",
        port=3306,
        password="#C!H7sRcvTr9vFU",
        database="freedb_ListenX"
    )
    cursor = db.cursor()
    print("✅ Connected to MySQL Database successfully")

    # Create users table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            fullname VARCHAR(255) NOT NULL,
            username VARCHAR(255) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        )
    """)
    db.commit()

except Exception as e:
    print(f"❌ Database Connection Failed: {e}")
    raise HTTPException(status_code=500, detail="Database connection failed")

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Handle Signup userdata 
class userData(BaseModel):
    fullname: str
    username: str
    email: EmailStr
    password: str

@app.post("/signup/")
async def user_Data(user: userData):
    hashed_password = hash_password(user.password)

    try:
        # Check if the username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (user.username, user.email))
        existing_user = cursor.fetchone()

        if existing_user:
            return {"status": "error", "message": "⚠️ Username or Email already exists. Please use a different one."}

        # Insert the new user
        cursor.execute("INSERT INTO users (fullname, username, email, password) VALUES (%s, %s, %s, %s)",
                       (user.fullname, user.username, user.email, hashed_password))
        db.commit()
        return {"status": "success", "message": "✅ Account created successfully"}
    
    except Exception as e:
        print(f"⚠️ Error Occurred: {str(e)}")
        return {"status": "error", "message": "❌ Something went wrong! Please try again later."}
