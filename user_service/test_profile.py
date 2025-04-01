import uuid
from fastapi.testclient import TestClient
from main import app
import jwt
from utils import create_token


client = TestClient(app)

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

def test_profile_success():
    # Сначала регистрируем нового пользователя
    unique_username = f"profileuser_{uuid.uuid4().hex[:6]}"
    reg_response = client.post("/api/v1/register", json={
        "username": unique_username,
        "password": "profilepassword123",
        "email": f"{unique_username}@example.com",
        "first_name": "Profile",
        "last_name": "User",
        "birth_date": "1990-01-01",
        "phone": "+79998887766"
    })
    assert reg_response.status_code == 200

    # Логинимся и получаем токен
    login_response = client.post("/api/v1/login", json={
        "username": unique_username,
        "password": "profilepassword123"
    })
    token = login_response.json()["access_token"]

    # Получаем профиль
    profile_response = client.get("/api/v1/profile", headers={
        "Authorization": f"Bearer {token}"
    })
    assert profile_response.status_code == 200
    profile_data = profile_response.json()
    assert profile_data["username"] == unique_username
    assert profile_data["email"] == f"{unique_username}@example.com"

def test_profile_invalid_token():
    invalid_token = "invalid.token.value"
    response = client.get("/api/v1/profile", headers={
        "Authorization": f"Bearer {invalid_token}"
    })
    assert response.status_code == 401  # Unauthorized

def test_profile_no_token():
    response = client.get("/api/v1/profile")
    assert response.status_code == 422 or response.status_code == 401  # Нет заголовка Authorization

def test_profile_nonexistent_user():
    # Создадим валидный токен с несуществующим user_id
    fake_token = create_token(user_id=999999)
    response = client.get("/api/v1/profile", headers={
        "Authorization": f"Bearer {fake_token}"
    })
    assert response.status_code == 404  # Пользователь не найден
