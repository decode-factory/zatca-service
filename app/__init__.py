from flask import Flask
from app.config import config

def create_app(config_name='development'):
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Register blueprints
    from app.routes.api import api_bp
    app.register_blueprint(api_bp)
    
    return app