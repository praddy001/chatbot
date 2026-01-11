# extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()

# Create Limiter but do not bind app here; bind in create_app to allow config
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
