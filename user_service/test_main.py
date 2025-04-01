from fastapi.testclient import TestClient
from main import app
import pytest
import uuid


client = TestClient(app)


def test_register_user():
    unique_username = f"testuser_{uuid.uuid4().hex[:6]}"
    response = client.post("/api/v1/register", json={
        "username": unique_username,
        "password": "password123",
        "email": f"{unique_username}@example.com",
        "first_name": "Test",
        "last_name": "User",
        "birth_date": "1995-05-05",
        "phone": "+79998887766"
    })
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}


def test_register_existing_username():
    client.post("/api/v1/register", json={
        "username": "newuser",
        "password": "newpassword",
        "email": "new@example.com",
        "first_name": "Kakashi",
        "last_name": "Hatake",
        "birth_date": "1990-01-01",
        "phone": "+123456789"
    })

    # Предполагаем, что пользователь testuser_unique уже существует
    response = client.post("/api/v1/register", json={
        "username": "newuser",
        "password": "newpassword",
        "email": "new@example.com",
        "first_name": "Kakashi",
        "last_name": "Hatake",
        "birth_date": "1990-01-01",
        "phone": "+123456789"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "Username already exists"


def test_register_missing_fields():
    response = client.post("/api/v1/register", json={
        "username": "losho4ek",
        # нет пароля и других полей
    })
    assert response.status_code == 422  # Unprocessable Entity, ошибка валидации


def test_register_invalid_email():
    response = client.post("/api/v1/register", json={
        "username": "pupsik",
        "password": "joopsik228",
        "email": "notanemail",
        "first_name": "Test",
        "last_name": "User",
        "birth_date": "1990-01-01",
        "phone": "+79998887766"
    })
    assert response.status_code == 422  # ошибка валидации email
