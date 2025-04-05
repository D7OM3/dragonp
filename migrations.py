from flask_migrate import Migrate
from web_interface import app
from models import db

migrate = Migrate(app, db)
