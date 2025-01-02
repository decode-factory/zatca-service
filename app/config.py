import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Base configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    BASEDIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    
    # ZATCA Environment
    ENVIRONMENT = os.getenv('ZATCA_ENV', 'sandbox')
    
    # ZATCA API URLs
    ZATCA_API_URLS = {
        'sandbox': {
            'reporting': os.getenv('ZATCA_SANDBOX_REPORTING_URL'),
            'clearance': os.getenv('ZATCA_SANDBOX_CLEARANCE_URL')
        },
        'production': {
            'reporting': os.getenv('ZATCA_PROD_REPORTING_URL'),
            'clearance': os.getenv('ZATCA_PROD_CLEARANCE_URL')
        }
    }
    
    # Certificate paths with environment variable support and absolute path handling
    CERT_PATH = {
        'sandbox': {
            'certificate': os.path.abspath(os.path.join(BASEDIR, os.getenv('ZATCA_SANDBOX_CERT_PATH'))),
            'private_key': os.path.abspath(os.path.join(BASEDIR, os.getenv('ZATCA_SANDBOX_PRIVATE_KEY_PATH'))),
            'public_key': os.path.abspath(os.path.join(BASEDIR, os.getenv('ZATCA_SANDBOX_PUBLIC_KEY_PATH')))
        },
        'production': {
            'certificate': os.path.abspath(os.path.join(BASEDIR, os.getenv('ZATCA_PROD_CERT_PATH'))),
            'private_key': os.path.abspath(os.path.join(BASEDIR, os.getenv('ZATCA_PROD_PRIVATE_KEY_PATH'))),
            'public_key': os.path.abspath(os.path.join(BASEDIR, os.getenv('ZATCA_PROD_PUBLIC_KEY_PATH')))
        }
    }
    
    # API Authentication
    API_KEY = os.getenv('ZATCA_API_KEY')
    API_SECRET = os.getenv('ZATCA_API_SECRET')
    
    # Debug and Testing flags
    DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
    TESTING = os.getenv('TESTING', 'False').lower() in ('true', '1', 't')
    
    @property
    def active_cert_path(self):
        cert_paths = self.CERT_PATH[self.ENVIRONMENT]
        
        # Validate certificate files exist
        for key, path in cert_paths.items():
            if not os.path.exists(path):
                raise FileNotFoundError(f"Certificate file not found: {path}")
                
        return cert_paths

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

class TestingConfig(Config):
    TESTING = True

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}