from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from starlette.requests import Request
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field
import sqlite3
import logging

from database import init_db, get_db_connection
from auth import get_password_hash, verify_password, create_access_token, get_current_user

# Task 6: Defensive Logging Setup
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.WARNING)
handler = logging.FileHandler("security.log")
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
security_logger.addHandler(handler)

app = FastAPI(title="Secure Auth API", description="Simulates a secure backend system with JWT and RBAC.")

@app.middleware("http")
async def security_logging_middleware(request: Request, call_next):
    """
    Task 6: Defensive Logging Middleware
    Intercepts responses. If a 403 Forbidden is returned, logs the attempt.
    """
    response = await call_next(request)
    if response.status_code == status.HTTP_403_FORBIDDEN:
        # User attempted to access an admin route without proper role
        action = f"{request.method} {request.url.path}"
        security_logger.warning(f"Unauthorized (403) attempt on action: {action}")
    return response

class UserRegister(BaseModel):
    username: str = Field(default="testuser")
    password: str = Field(default="123")
    role: str = Field(default="User", description="Must be 'Admin' or 'User'")

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/")
def read_root():
    return {"message": "Welcome to the Secure Auth API. System is running."}

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegister):
    """Task 1: Secure Password Storage"""
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pwd = get_password_hash(user.password)
    
    try:
        if user.role not in ["Admin", "User"]:
            raise HTTPException(status_code=400, detail="Invalid role. Must be 'Admin' or 'User'.")
            
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (user.username, hashed_pwd, user.role)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    
    conn.close()
    return {"message": f"User '{user.username}' registered successfully."}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Task 2: JWT Issuance"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (form_data.username,))
    user_row = cursor.fetchone()
    conn.close()
    
    if not user_row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
        
    if not verify_password(form_data.password, user_row['password_hash']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
        
    access_token = create_access_token(
        data={"username": user_row['username'], "role": user_row['role']}
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/profile")
def get_profile(current_user: dict = Depends(get_current_user)):
    """
    Task 4: Role-Based Routing
    Accessible by both User and Admin roles.
    """
    return {"message": "Profile accessed successfully.", "user_data": current_user}

@app.delete("/user/{user_id}")
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    """
    Task 4: Role-Based Routing
    Accessible ONLY by the Admin role.
    """
    if current_user["role"] != "Admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges to delete a user.")
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    
    if deleted == 0:
        raise HTTPException(status_code=404, detail="User not found")
        
    return {"message": f"User {user_id} deleted successfully."}

@app.post("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    """
    Task 5: Token Revocation (Blacklisting)
    Invalidates the JWT before its natural expiry.
    """
    token = current_user["token"]
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO token_blacklist (token) VALUES (?)", (token,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # If already blacklisted
    finally:
        conn.close()
        
    return {"message": "Successfully logged out. Token has been revoked."}

