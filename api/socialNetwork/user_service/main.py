from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr
from datetime import datetime
import bcrypt
import jwt
import psycopg2
import os
from psycopg2.extras import RealDictCursor

# Создаем FastAPI приложение
app = FastAPI()

# Получаем переменные окружения
DATABASE_URL = os.getenv("DATABASE_URL", "dbname=users user=postgres password=postgres host=db")
SECRET_KEY = os.getenv("SECRET_KEY", "mysecretkey")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

# Подключение к базе данных
conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor(cursor_factory=RealDictCursor)


# Модели данных для запросов
class UserRegister(BaseModel):
    username: str
    password: str
    email: EmailStr
    first_name: str
    last_name: str
    birth_date: str
    phone: str


class UserLogin(BaseModel):
    username: str
    password: str

# Функция извлечения user_id из JWT
def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format")

    token = authorization.split(" ")[1]  # Берем токен после "Bearer "

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")  # Достаем user_id из токена

        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        return user_id

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")

    except jwt.DecodeError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Функция хеширования пароля
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


# Функция проверки пароля
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


@app.get("/")
def root():
    return {"message": "Welcome to User Service API"}


# Регистрация нового пользователя
@app.post("/register")
def register(user: UserRegister):
    cursor.execute("SELECT id FROM users WHERE username=%s", (user.username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = hash_password(user.password)
    cursor.execute("""
        INSERT INTO users (username, password, email, first_name, last_name, birth_date, phone, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
    """, (user.username, hashed_password, user.email, user.first_name, user.last_name, user.birth_date, user.phone,
          datetime.utcnow(), datetime.utcnow()))
    conn.commit()

    return {"message": "User registered successfully"}


# Аутентификация пользователя и выдача JWT токена
@app.post("/login")
def login(user: UserLogin):
    cursor.execute("SELECT id, password FROM users WHERE username=%s", (user.username,))
    result = cursor.fetchone()

    if not result or not verify_password(user.password, result["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = jwt.encode({"user_id": result["id"]}, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": token, "token_type": "bearer"}


# Маршрут для получения профиля пользователя
@app.get("/profile")
def get_profile(user_id: int = Depends(get_current_user)):
    cursor.execute("""
        SELECT username, email, first_name, last_name, birth_date, phone, created_at, updated_at 
        FROM users WHERE id=%s
    """, (user_id,))
    user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user