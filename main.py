from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import mysql.connector as connector
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

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
        host="localhost",
        user="root",
        port="3306",
        password="@Admin2424",
        database="ListenX"
    )
    cursor = db.cursor()
    print("✅ Connected to MySQL Database successfully")

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
        print("✅ Account created successfully")
        return {"status": "success", "message": "✅ Account created successfully"}
        
    
    except Exception as e:
        print(f"⚠️ Error Occurred: {str(e)}")
        return {"status": "error", "message": "❌ Something went wrong! Please try again later."}

# Handle login data (formData) 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")

# Verifying user entered password and stored hash_password
def verify_password(password,hash_password):
    return pwd_context.verify(password,hash_password)

# Global Variable
Secret_Key="MyDearDevil"
token_expire_mins = 15

# Creating Access Token
def create_access_token(data: dict,expire_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expire_delta or timedelta(minutes= token_expire_mins ))
    to_encode.update({'exp':expire})
    return jwt.encode(to_encode,Secret_Key,algorithm="HS256")
 
@app.post("/login/")
async def login(form_data : OAuth2PasswordRequestForm = Depends()):
    cursor.execute("select * from users where username = %s or email = %s",(form_data.username,form_data.username))
    user = cursor.fetchone()
    if(not user or not verify_password(form_data.password,user[4])):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token=create_access_token(data={'sub':user[2]})

    return {"access_token": access_token, "token_type": "bearer", "message":"✅ Login successfully"}

# Verifying Token

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, Secret_Key, algorithms="HS256")
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.get("/protected/")
async def protected_user(username : str = Depends(verify_token)):
    return {"message": f"Hello, {username}! You have access to this protected page."}