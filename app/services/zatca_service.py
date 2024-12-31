import base64
import hashlib
import os
from datetime import datetime
import requests
import qrcode
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from .xml_service import XMLService
from ..utils.file_handler import FileHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ZATCAService:
    def __init__(self, config):
        self.config = config
        self.xml_service = XMLService()
        self.certificate = None
        self.private_key = None
        
        # Initialize file handler
        self.file_handler = FileHandler(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Load certificates
        environment = config.get('ENVIRONMENT', 'sandbox')
        cert_paths = config.get('CERT_PATH', {}).get(environment, {})
        
        if cert_paths:
            try:
                self.load_certificate(
                    cert_paths.get('certificate'),
                    cert_paths.get('private_key')
                )
            except Exception as e:
                print(f"Warning: Failed to load certificates: {str(e)}")

    def load_certificate(self, cert_path, private_key_path):
        """Load the EC certificate and private key"""
        try:
            logger.info(f"Attempting to load private key from: {private_key_path}")
            # Load private key first
            with open(private_key_path, 'rb') as key_file:
                key_data = key_file.read()
                if not key_data.startswith(b'-----BEGIN EC PRIVATE KEY-----'):
                    raise ValueError("Invalid private key format. Must be an EC private key.")
                
                self.private_key = serialization.load_pem_private_key(
                    key_data,
                    password=None
                )
                
                # Verify it's an EC key
                if not isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                    raise ValueError("Private key must be an EC key")
                
                logger.info("Successfully loaded private key")

            logger.info(f"Attempting to load certificate from: {cert_path}")
            # Load certificate
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                if not cert_data.startswith(b'-----BEGIN CERTIFICATE-----'):
                    logger.warning("Certificate not in correct format. Attempting to convert...")
                    
                    # Create self-signed certificate
                    subject = issuer = x509.Name([
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "SA"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "TSTZATCA-Code-Signing"),
                    ])

                    cert = x509.CertificateBuilder().subject_name(
                        subject
                    ).issuer_name(
                        issuer
                    ).public_key(
                        self.private_key.public_key()
                    ).serial_number(
                        x509.random_serial_number()
                    ).not_valid_before(
                        datetime.utcnow()
                    ).not_valid_after(
                        datetime.utcnow() + datetime.timedelta(days=365)
                    ).add_extension(
                        x509.BasicConstraints(ca=False, path_length=None), critical=True
                    ).sign(self.private_key, hashes.SHA256())
                    
                    # Save and load the new certificate
                    cert_data = cert.public_bytes(serialization.Encoding.PEM)
                    with open(cert_path, 'wb') as f:
                        f.write(cert_data)
                
                self.certificate = x509.load_pem_x509_certificate(cert_data)
                logger.info("Successfully loaded certificate")

            return True
            
        except Exception as e:
            logger.error(f"Error loading certificates: {str(e)}")
            raise

    def generate_invoice_hash(self, xml_content):
        """Generate hash of the invoice XML"""
        hash_obj = hashlib.sha256()
        hash_obj.update(xml_content if isinstance(xml_content, bytes) else xml_content.encode('utf-8'))
        return hash_obj.hexdigest()

    def sign_invoice(self, invoice_hash):
        """Sign the invoice hash using EC private key"""
        if not self.private_key:
            raise Exception("Private key not loaded")
        
        try:
            # Convert hash to bytes if it's a string
            hash_bytes = invoice_hash.encode() if isinstance(invoice_hash, str) else invoice_hash
            
            # Sign the hash
            signature = self.private_key.sign(
                hash_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            
            return base64.b64encode(signature).decode()
        except Exception as e:
            raise Exception(f"Error signing invoice: {str(e)}")

    def generate_qr_code(self, invoice_data, cert_info=None):
        """Generate QR code with required ZATCA fields"""
        try:
            # Generate XML with certificate info
            xml_content = self.xml_service.generate_ubl_xml(invoice_data, cert_info)
            
            # Make sure invoice number is available
            invoice_number = invoice_data.get('invoiceNumber', '')
            if not invoice_number:
                raise ValueError("Invoice number is required")
            
            try:
                # Save XML first
                xml_path = self.file_handler.save_invoice_xml(invoice_number, xml_content)
                logger.info(f"XML saved to: {xml_path}")
            except Exception as e:
                logger.error(f"Error saving XML: {str(e)}")
                raise
            
            # Generate hash using the signed XML content
            invoice_hash = self.generate_invoice_hash(xml_content)
            
            # Prepare QR data
            qr_data = {
                'seller_name': invoice_data['supplier']['name'],
                'vat_number': invoice_data['supplier'].get('vatNumber', ''),
                'timestamp': invoice_data.get('timestamp', 
                    f"{invoice_data['issueDate']}T{invoice_data.get('issueTime', '00:00:00')}"),
                'total_amount': invoice_data['totals']['taxInclusiveAmount'],
                'vat_amount': invoice_data['taxTotal'],
                'invoice_hash': invoice_hash,
                'signature': cert_info.get('signature_value', '') if cert_info else ''
            }
            
            # Create QR string
            qr_string = f"{qr_data['seller_name']}|{qr_data['vat_number']}|" \
                    f"{qr_data['timestamp']}|{qr_data['total_amount']}|" \
                    f"{qr_data['vat_amount']}|{qr_data['invoice_hash']}|" \
                    f"{qr_data['signature']}"
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4
            )
            qr.add_data(qr_string)
            qr.make(fit=True)
            qr_image = qr.make_image()
            
            try:
                # Save QR code
                qr_path = self.file_handler.save_qr_code(invoice_number, qr_image)
                logger.info(f"QR code saved to: {qr_path}")
            except Exception as e:
                logger.error(f"Error saving QR code: {str(e)}")
                raise
            
            return qr_image, qr_string
                
        except Exception as e:
            logger.error(f"Error generating QR code: {str(e)}")
            raise Exception(f"Error generating QR code: {str(e)}")

    def submit_to_zatca(self, invoice_data, invoice_type='B2B', cert_info=None):
        """Submit invoice to ZATCA"""
        try:
            # Generate XML with certificate info
            xml_content = self.xml_service.generate_ubl_xml(invoice_data, cert_info)
            invoice_hash = self.generate_invoice_hash(xml_content)
            
            # Prepare payload
            payload = {
                "invoiceHash": invoice_hash,
                "invoice": base64.b64encode(xml_content).decode(),
                "uuid": invoice_data.get('uuid', '')
            }
            
            # Get API URL
            environment = self.config.get('ENVIRONMENT', 'sandbox')
            api_type = 'clearance' if invoice_type == 'B2B' else 'reporting'
            api_url = self.config['ZATCA_API_URLS'][environment][api_type]
            
            # Submit to ZATCA
            response = requests.post(
                api_url,
                json=payload,
                headers={
                    'Accept': 'application/json',
                    'Accept-Language': 'en',
                    'Content-Type': 'application/json',
                    'Authorization': f"Bearer {self.config.get('API_KEY', '')}"
                }
            )
            response.raise_for_status()
            
            # Process and save response
            zatca_response = self.process_zatca_response(response.json())
            response_path = self.file_handler.save_zatca_response(
                invoice_data['invoiceNumber'], 
                zatca_response
            )
            logger.info(f"ZATCA response saved to: {response_path}")
            
            return zatca_response
            
        except Exception as e:
            raise Exception(f"Error submitting to ZATCA: {str(e)}")

    def process_zatca_response(self, zatca_response):
        """Process ZATCA response"""
        try:
            return {
                'status': zatca_response.get('status'),
                'clearance_status': zatca_response.get('clearanceStatus'),
                'reporting_status': zatca_response.get('reportingStatus'),
                'validation_results': zatca_response.get('validationResults', []),
                'warning_messages': zatca_response.get('warningMessages', []),
                'error_messages': zatca_response.get('errorMessages', []),
                'invoice_hash': zatca_response.get('invoiceHash'),
                'submission_id': zatca_response.get('submissionId'),
                'qr_code': zatca_response.get('qrCode')
            }
        except Exception as e:
            raise Exception(f"Error processing ZATCA response: {str(e)}")
        

    def validate_invoice(self, invoice_data):
        """Validate invoice data before submission"""
        try:
            # Check if we need to convert the data first
            if 'Invoice' in invoice_data:
                invoice_data = self.convert_zatca_json(invoice_data)

            # Required top-level fields
            required_fields = [
                'invoiceNumber',
                'issueDate',
                'supplier',
                'customer',
                'items',
                'totals',
                'taxTotal'
            ]
            
            # Check required fields existence and non-emptiness
            missing_fields = []
            for field in required_fields:
                if field not in invoice_data or not invoice_data[field]:
                    missing_fields.append(field)
                elif isinstance(invoice_data[field], (dict, list)):
                    if not invoice_data[field]:  # Check if dict/list is empty
                        missing_fields.append(field)

            if missing_fields:
                raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

            # Validate supplier information
            required_supplier_fields = ['name', 'address']
            if 'supplier' in invoice_data:
                missing_supplier_fields = [
                    field for field in required_supplier_fields 
                    if field not in invoice_data['supplier'] or not invoice_data['supplier'][field]
                ]
                if missing_supplier_fields:
                    raise ValueError(f"Missing supplier fields: {', '.join(missing_supplier_fields)}")

                # Validate supplier address
                required_address_fields = ['street', 'city', 'country']
                missing_address_fields = [
                    field for field in required_address_fields 
                    if field not in invoice_data['supplier']['address'] or not invoice_data['supplier']['address'][field]
                ]
                if missing_address_fields:
                    raise ValueError(f"Missing supplier address fields: {', '.join(missing_address_fields)}")

            # Validate customer information
            required_customer_fields = ['name', 'address']
            if 'customer' in invoice_data:
                missing_customer_fields = [
                    field for field in required_customer_fields 
                    if field not in invoice_data['customer'] or not invoice_data['customer'][field]
                ]
                if missing_customer_fields:
                    raise ValueError(f"Missing customer fields: {', '.join(missing_customer_fields)}")

            # Validate items
            if 'items' in invoice_data:
                if not isinstance(invoice_data['items'], list):
                    raise ValueError("Items must be a list")
                if not invoice_data['items']:
                    raise ValueError("Items list cannot be empty")

                required_item_fields = ['name', 'quantity', 'price', 'lineExtensionAmount']
                for idx, item in enumerate(invoice_data['items']):
                    missing_item_fields = [
                        field for field in required_item_fields 
                        if field not in item or not item[field]
                    ]
                    if missing_item_fields:
                        raise ValueError(f"Missing fields in item {idx + 1}: {', '.join(missing_item_fields)}")

            # Validate totals
            required_total_fields = [
                'lineExtensionAmount',
                'taxExclusiveAmount',
                'taxInclusiveAmount',
                'payableAmount'
            ]
            if 'totals' in invoice_data:
                missing_total_fields = [
                    field for field in required_total_fields 
                    if field not in invoice_data['totals'] or not invoice_data['totals'][field]
                ]
                if missing_total_fields:
                    raise ValueError(f"Missing total fields: {', '.join(missing_total_fields)}")

            # Validate tax total
            if 'taxTotal' in invoice_data:
                try:
                    float(invoice_data['taxTotal'])
                except (ValueError, TypeError):
                    raise ValueError("Tax total must be a valid number")

            # Validate dates
            if 'issueDate' in invoice_data:
                try:
                    datetime.strptime(invoice_data['issueDate'], '%Y-%m-%d')
                except ValueError:
                    raise ValueError("Issue date must be in YYYY-MM-DD format")

            if 'issueTime' in invoice_data:
                try:
                    datetime.strptime(invoice_data['issueTime'], '%H:%M:%S')
                except ValueError:
                    raise ValueError("Issue time must be in HH:MM:SS format")

            return True

        except ValueError as ve:
            raise ve
        except Exception as e:
            raise ValueError(f"Invoice validation failed: {str(e)}")

    def get_service_metrics(self):
        """Get service metrics"""
        try:
            # Get certificate info
            cert_info = self.get_certificate_info()
            
            # Get file statistics
            file_stats = self.file_handler.get_statistics()
            
            # Calculate API usage
            api_usage = self._calculate_api_usage()
            
            return {
                'certificate': {
                    'status': cert_info.get('status'),
                    'expiry': cert_info.get('expiry'),
                    'issuer': cert_info.get('issuer')
                },
                'files': {
                    'total_invoices': file_stats.get('total_invoices', 0),
                    'total_size': file_stats.get('total_size', 0),
                    'storage_usage': file_stats.get('storage_usage', '0%')
                },
                'api': {
                    'total_requests': api_usage.get('total_requests', 0),
                    'successful_submissions': api_usage.get('successful_submissions', 0),
                    'failed_submissions': api_usage.get('failed_submissions', 0),
                    'average_response_time': api_usage.get('average_response_time', 0)
                },
                'environment': self.config.get('ENVIRONMENT', 'sandbox'),
                'uptime': self._get_uptime()
            }
        except Exception as e:
            logger.error(f"Error getting service metrics: {str(e)}")
            return {
                'status': 'error',
                'message': f"Error getting metrics: {str(e)}"
            }
    
    def _calculate_api_usage(self):
        """Calculate API usage statistics"""
        # Implement your API usage calculation logic here
        return {
            'total_requests': 0,
            'successful_submissions': 0,
            'failed_submissions': 0,
            'average_response_time': 0
        }

    def _get_uptime(self):
        """Get service uptime"""
        # Implement your uptime calculation logic here
        return "0 days, 0 hours"

    def get_certificate_info(self):
        """Get detailed certificate information"""
        try:
            if not self.certificate:
                return {
                    'status': 'not_loaded',
                    'message': 'Certificate not loaded'
                }
                
            return {
                'status': 'loaded',
                'subject': self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                'issuer': self.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                'serial_number': self.certificate.serial_number,
                'not_valid_before': self.certificate.not_valid_before.isoformat(),
                'not_valid_after': self.certificate.not_valid_after.isoformat(),
                'fingerprint': self.certificate.fingerprint(hashes.SHA256()).hex()
            }
        except Exception as e:
            logger.error(f"Error getting certificate info: {str(e)}")
            return {
                'status': 'error',
                'message': f"Error getting certificate info: {str(e)}"
            }
        
    def convert_zatca_json(self, invoice_data):
        """Wrapper for XMLService convert_zatca_json method"""
        try:
            return self.xml_service.convert_zatca_json(invoice_data)
        except Exception as e:
            logger.error(f"Error converting ZATCA JSON: {str(e)}")
            raise ValueError(f"Error converting invoice data: {str(e)}")
        
    def prepare_certificate_info(self, invoice_data=None):
        """Prepare certificate information for XML signing"""
        try:
            if not self.certificate or not self.private_key:
                return None
                
            cert_info = {}
            
            # Get certificate data
            cert_info['certificate'] = base64.b64encode(
                self.certificate.public_bytes(serialization.Encoding.DER)
            ).decode('utf-8')
            
            # Get certificate digest
            cert_digest = hashlib.sha256()
            cert_digest.update(self.certificate.public_bytes(serialization.Encoding.DER))
            cert_info['cert_digest'] = base64.b64encode(cert_digest.digest()).decode('utf-8')
            
            # Get issuer info
            issuer = self.certificate.issuer
            issuer_cn = next(
                (attr.value for attr in issuer if isinstance(attr, x509.NameAttribute) 
                and attr.oid == NameOID.COMMON_NAME),
                None
            )
            cert_info['issuer_name'] = issuer_cn or 'CN=Unknown'
            cert_info['serial_number'] = str(self.certificate.serial_number)
            
            # If invoice data is provided, calculate signature
            if invoice_data:
                # Generate hash of invoice data
                invoice_hash = hashlib.sha256()
                invoice_hash.update(str(invoice_data).encode())
                digest_value = invoice_hash.hexdigest()
                cert_info['digest_value'] = digest_value
                
                # Sign the hash
                signature = self.private_key.sign(
                    invoice_hash.digest(),
                    ec.ECDSA(hashes.SHA256())
                )
                cert_info['signature_value'] = base64.b64encode(signature).decode('utf-8')
            
            return cert_info
            
        except Exception as e:
            logger.error(f"Error preparing certificate info: {str(e)}")
            return None    