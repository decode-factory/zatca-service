import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # Base directory of the project
    BASEDIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    
    # ZATCA API URLs
    ZATCA_API_URLS = {
        'sandbox': {
            'reporting': 'https://gw-apic-gov.gazt.gov.sa/e-invoicing/developer-portal/reporting',
            'clearance': 'https://gw-apic-gov.gazt.gov.sa/e-invoicing/developer-portal/clearance'
        },
        'production': {
            'reporting': 'https://gw-apic-gov.gazt.gov.sa/e-invoicing/portal/reporting',
            'clearance': 'https://gw-apic-gov.gazt.gov.sa/e-invoicing/portal/clearance'
        }
    }
    
    # Certificate paths
    CERT_PATH = {
        'sandbox': {
            'certificate': os.path.join(BASEDIR, 'certs', 'sandbox', 'cert.pem'),
            'private_key': os.path.join(BASEDIR, 'certs', 'sandbox', 'private-key.pem'),
            'public_key': os.path.join(BASEDIR, 'certs', 'sandbox', 'public-key.pem')
        },
        'production': {
            'certificate': os.path.join(BASEDIR, 'certs', 'production', 'cert.pem'),
            'private_key': os.path.join(BASEDIR, 'certs', 'production', 'private-key.pem'),
            'public_key': os.path.join(BASEDIR, 'certs', 'production', 'public-key.pem')
        }
    }
    
    # Environment (sandbox/production)
    ENVIRONMENT = os.environ.get('ZATCA_ENV') or 'sandbox'
    
    # Get certificate paths based on environment
    @property
    def active_cert_path(self):
        return self.CERT_PATH[self.ENVIRONMENT]
    
    # API Authentication
    API_KEY = os.environ.get('ZATCA_API_KEY')
    API_SECRET = os.environ.get('ZATCA_API_SECRET')
    
    DEBUG = False
    TESTING = False

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