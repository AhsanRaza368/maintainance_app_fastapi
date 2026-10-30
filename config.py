from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    database_username: str
    database_password: str
    database_hostname: str
    database_port: str
    database_name: str
    owner_code: str

    owner_secret_key: str
    admin_secret_key: str
    algorithm: str
    owner_code: str

    # SMTP settings
    smtp_email: str
    smtp_password: str
    smtp_host: str
    smtp_port: int

    class Config:
        env_file = ".env"


settings = Settings()
