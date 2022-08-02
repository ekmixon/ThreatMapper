import os
import datetime
from celery import Celery




class ProdConfig:
    debug = os.environ.get("DEBUG")
    DEBUG = debug in ["true", "True"]
    SQLALCHEMY_DATABASE_URI = f'postgresql://{os.environ.get("POSTGRES_USER_DB_USER")}:{os.environ.get("POSTGRES_USER_DB_PASSWORD")}@{os.environ.get("POSTGRES_USER_DB_HOST")}:{os.environ.get("POSTGRES_USER_DB_PORT")}/{os.environ.get("POSTGRES_USER_DB_NAME")}'

    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_timeout': 60,
        'pool_size': 50,
        'max_overflow': 5,
    }
    TEMPLATES_AUTO_RELOAD = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM")
    JWT_PUBLIC_KEY = open('/app/code/rs256.pub').read()
    JWT_PRIVATE_KEY = open('/app/code/rs256.pem').read()
    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    # celery
    CELERY_BROKER_URL = 'redis://{host}:{port}/{db_number}'.format(
        host=os.environ.get("REDIS_HOST"),
        port=os.environ.get("REDIS_PORT"),
        db_number=os.environ.get("REDIS_DB_NUMBER")
    )



celery_app = Celery(__name__, broker=ProdConfig.CELERY_BROKER_URL)
