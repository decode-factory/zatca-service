from flask import Blueprint, request, jsonify, current_app, send_file
from app.services import ZATCAService
import traceback
import os
from functools import wraps
import logging
from datetime import datetime

api_bp = Blueprint('api', __name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def handle_errors(f):
    """Error handling decorator for API routes"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as ve:
            logger.warning(f"Validation error: {str(ve)}")
            return jsonify({
                'status': 'error',
                'error_type': 'validation',
                'message': str(ve)
            }), 400
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'status': 'error',
                'error_type': 'system',
                'message': str(e),
                'trace': traceback.format_exc() if current_app.debug else None
            }), 500
    return wrapped


@api_bp.route('/health', methods=['GET'])
@handle_errors
def health_check():
    """Enhanced health check endpoint"""
    zatca_service = ZATCAService(current_app.config)
    cert_status = zatca_service.check_certificate_status()
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'environment': current_app.config.get('ENVIRONMENT', 'sandbox'),
        'certificate_status': cert_status,
        'debug_mode': current_app.debug,
        'api_version': '1.0.0'
    })

@api_bp.route('/process-invoice', methods=['POST'])
def process_invoice():
    """Process and submit invoice to ZATCA"""
    try:
        # Get invoice data from request
        invoice_data = request.get_json()
        if not invoice_data:
            return jsonify({
                'status': 'error',
                'error_type': 'validation',
                'message': "No invoice data provided"
            }), 400

        # Initialize ZATCA service
        zatca_service = ZATCAService(current_app.config)
        
        try:
            # Convert data if it's in ZATCA format
            if 'Invoice' in invoice_data:
                processed_data = zatca_service.convert_zatca_json(invoice_data)
            else:
                processed_data = invoice_data

            # Validate converted data
            zatca_service.validate_invoice(processed_data)
            
        except ValueError as ve:
            return jsonify({
                'status': 'error',
                'error_type': 'validation',
                'message': str(ve)
            }), 400
        
        try:
            # Generate QR code
            qr_image, qr_string = zatca_service.generate_qr_code(processed_data)
        except Exception as e:
            return jsonify({
                'status': 'error',
                'error_type': 'qr_generation',
                'message': f"Error generating QR code: {str(e)}"
            }), 400
        
        try:
            # Submit to ZATCA
            invoice_type = 'B2B' if processed_data.get('customerType') == 'business' else 'B2C'
            zatca_response = zatca_service.submit_to_zatca(processed_data, invoice_type)
            
            # Add QR code to response
            zatca_response['qr_code'] = qr_string
            
            return jsonify(zatca_response)
            
        except Exception as e:
            return jsonify({
                'status': 'error',
                'error_type': 'submission',
                'message': f"Error submitting to ZATCA: {str(e)}"
            }), 400
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error_type': 'system',
            'message': str(e),
            'trace': traceback.format_exc() if current_app.debug else None
        }), 500

@api_bp.route('/generate-compliance', methods=['POST'])
def generate_compliance():
    """Generate compliance invoice without submission"""
    try:
        invoice_data = request.get_json()
        zatca_service = ZATCAService(current_app.config)
        result = zatca_service.process_compliance_invoice(invoice_data)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'trace': traceback.format_exc() if current_app.debug else None
        }), 400

@api_bp.route('/api-status', methods=['GET'])
def api_status():
    """Check ZATCA API status"""
    try:
        zatca_service = ZATCAService(current_app.config)
        status = zatca_service.get_api_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    
@api_bp.route('/check-certificates', methods=['GET'])
def check_certificates():
    """Check if certificates are properly loaded"""
    try:
        zatca_service = ZATCAService(current_app.config)
        environment = current_app.config.get('ENVIRONMENT', 'sandbox')
        cert_paths = current_app.config.get('CERT_PATH', {}).get(environment, {})
        
        return jsonify({
            'status': 'success',
            'environment': environment,
            'certificate_path': cert_paths.get('certificate'),
            'private_key_path': cert_paths.get('private_key'),
            'public_key_path': cert_paths.get('public_key'),
            'certificate_exists': os.path.exists(cert_paths.get('certificate', '')),
            'private_key_exists': os.path.exists(cert_paths.get('private_key', '')),
            'public_key_exists': os.path.exists(cert_paths.get('public_key', ''))
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'trace': traceback.format_exc()
        }), 400   

@api_bp.route('/validate-certificates', methods=['GET'])
def validate_certificates():
    """Validate certificate and private key files"""
    try:
        environment = current_app.config.get('ENVIRONMENT', 'sandbox')
        cert_paths = current_app.config.get('CERT_PATH', {}).get(environment, {})
        
        cert_path = cert_paths.get('certificate')
        key_path = cert_paths.get('private_key')
        
        # Check file existence
        results = {
            'certificate_exists': os.path.exists(cert_path),
            'private_key_exists': os.path.exists(key_path),
            'certificate_path': cert_path,
            'private_key_path': key_path,
            'certificate_format': None,
            'private_key_format': None
        }
        
        # Check certificate format
        if results['certificate_exists']:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                results['certificate_format'] = {
                    'starts_correctly': cert_data.startswith(b'-----BEGIN CERTIFICATE-----'),
                    'ends_correctly': cert_data.strip().endswith(b'-----END CERTIFICATE-----'),
                    'length': len(cert_data),
                    'content_sample': cert_data[:50].decode('utf-8', errors='ignore')
                }
        
        # Check private key format
        if results['private_key_exists']:
            with open(key_path, 'rb') as f:
                key_data = f.read()
                results['private_key_format'] = {
                    'starts_correctly': key_data.startswith(b'-----BEGIN EC PRIVATE KEY-----'),
                    'ends_correctly': key_data.strip().endswith(b'-----END EC PRIVATE KEY-----'),
                    'length': len(key_data),
                    'content_sample': key_data[:50].decode('utf-8', errors='ignore')
                }
        
        return jsonify({
            'status': 'success',
            'validation_results': results
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'trace': traceback.format_exc()
        }), 400

@api_bp.route('/files/<invoice_number>', methods=['GET'])
@handle_errors
def get_invoice_files(invoice_number):
    """Get all files associated with an invoice with additional metadata"""
    zatca_service = ZATCAService(current_app.config)
    
    files = {
        'xml': zatca_service.file_handler.get_file_path(invoice_number, 'xml'),
        'qr': zatca_service.file_handler.get_file_path(invoice_number, 'qr'),
        'response': zatca_service.file_handler.get_file_path(invoice_number, 'response')
    }
    
    file_info = {}
    for file_type, path in files.items():
        if path and os.path.exists(path):
            stats = os.stat(path)
            file_info[file_type] = {
                'filename': os.path.basename(path),
                'size': stats.st_size,
                'created_at': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                'modified_at': datetime.fromtimestamp(stats.st_mtime).isoformat()
            }
        else:
            file_info[file_type] = None
    
    return jsonify({
        'status': 'success',
        'invoice_number': invoice_number,
        'files': file_info
    })

@api_bp.route('/files/<invoice_number>/<file_type>', methods=['GET'])
def get_invoice_file(invoice_number, file_type):
    """Get specific file for an invoice"""
    try:
        zatca_service = ZATCAService(current_app.config)
        file_path = zatca_service.file_handler.get_file_path(invoice_number, file_type)
        
        if not file_path or not os.path.exists(file_path):
            return jsonify({
                'status': 'error',
                'message': f'File not found for invoice {invoice_number}'
            }), 404
            
        return send_file(file_path)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400 

@api_bp.route('/validate-invoice', methods=['POST'])
@handle_errors
def validate_invoice():
    """Validate invoice data without submission"""
    invoice_data = request.get_json()
    if not invoice_data:
        raise ValueError("No invoice data provided")
    
    zatca_service = ZATCAService(current_app.config)
    validation_result = zatca_service.validate_invoice(invoice_data)
    
    return jsonify({
        'status': 'success',
        'message': 'Invoice data is valid',
        'validation_result': validation_result
    })

@api_bp.route('/certificate-info', methods=['GET'])
@handle_errors
def certificate_info():
    """Get detailed certificate information"""
    zatca_service = ZATCAService(current_app.config)
    environment = current_app.config.get('ENVIRONMENT', 'sandbox')
    cert_paths = current_app.config.get('CERT_PATH', {}).get(environment, {})
    
    cert_info = zatca_service.get_certificate_info()
    return jsonify({
        'status': 'success',
        'environment': environment,
        'paths': {
            'certificate': cert_paths.get('certificate'),
            'private_key': cert_paths.get('private_key'),
            'public_key': cert_paths.get('public_key')
        },
        'certificate_info': cert_info
    })

@api_bp.route('/metrics', methods=['GET'])
@handle_errors
def get_metrics():
    """Get service metrics"""
    zatca_service = ZATCAService(current_app.config)
    return jsonify(zatca_service.get_service_metrics())

# Error handlers
@api_bp.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Resource not found'
    }), 404

@api_bp.errorhandler(405)
def method_not_allowed_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Method not allowed'
    }), 405

# Before request handler
@api_bp.before_request
def before_request():
    """Log incoming requests"""
    logger.info(f"Incoming {request.method} request to {request.path}")