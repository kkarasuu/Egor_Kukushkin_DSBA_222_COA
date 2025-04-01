from fastapi import FastAPI, Depends, Header, HTTPException
from database import SessionLocal, engine
from models import Base
from routes_v1 import router_v1

Base.metadata.create_all(bind=engine)
# Создаем FastAPI приложение
app = FastAPI()
app.include_router(router_v1)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def root():
    return {"message": "Welcome to User Service API"}
