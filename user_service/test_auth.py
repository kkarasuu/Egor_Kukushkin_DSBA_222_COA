import uuid
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_login_success():
    # Сначала регистрируем уникального пользователя
    unique_username = f"loginuser_{uuid.uuid4().hex[:6]}"
    client.post("api/v1/register", json={
        "username": unique_username,
        "password": "securepassword123",
        "email": f"{unique_username}@example.com",
        "first_name": "Login",
        "last_name": "Test",
        "birth_date": "1990-01-01",
        "phone": "+79998887766"
    })

    # Теперь пытаемся залогиниться
    response = client.post("/api/v1/login", json={
        "username": unique_username,
        "password": "securepassword123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password():
    unique_username = f"wrongpass_{uuid.uuid4().hex[:6]}"
    client.post("api/v1/register", json={
        "username": unique_username,
        "password": "correctpassword",
        "email": f"{unique_username}@example.com",
        "first_name": "Wrong",
        "last_name": "Password",
        "birth_date": "1990-01-01",
        "phone": "+79998887766"
    })

    response = client.post("/api/v1/login", json={
        "username": unique_username,
        "password": "wrongpassword"
    })
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_login_nonexistent_user():
    response = client.post("/api/v1/login", json={
        "username": "nonexistent_user_1234",
        "password": "somepassword"
    })
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_login_missing_fields():
    response = client.post("/api/v1/login", json={
        "username": "someuser"
        # пароля нет
    })
    assert response.status_code == 422  # Ошибка валидации
