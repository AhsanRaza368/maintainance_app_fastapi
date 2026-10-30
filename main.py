from fastapi import FastAPI
from database import Base, engine
import models
from routes import auth
from fastapi.staticfiles import StaticFiles

app = FastAPI()

app.mount(
    "/uploads",
    StaticFiles(directory="uploads"),
    name="uploads"
)

app.include_router(auth.route)


Base.metadata.create_all(bind=engine)
