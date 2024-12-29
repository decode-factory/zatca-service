import os
import json
from datetime import datetime
from PIL import Image
import io
import logging

logger = logging.getLogger(__name__)

class FileHandler:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.generated_dir = os.path.join(base_dir, 'generated')
        self.invoices_dir = os.path.join(self.generated_dir, 'invoices')
        self.qrcodes_dir = os.path.join(self.generated_dir, 'qrcodes')
        self.responses_dir = os.path.join(self.generated_dir, 'responses')
        
        # Create directories if they don't exist
        self.ensure_directories()

    def ensure_directories(self):
        """Ensure all required directories exist"""
        try:
            for directory in [self.generated_dir, self.invoices_dir, 
                            self.qrcodes_dir, self.responses_dir]:
                if not os.path.exists(directory):
                    os.makedirs(directory)
                    logger.info(f"Created directory: {directory}")
        except Exception as e:
            logger.error(f"Error creating directories: {str(e)}")
            raise

    def sanitize_filename(self, filename):
        """Sanitize filename by replacing invalid characters"""
        # Replace invalid characters with underscores
        invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        sanitized = filename
        for char in invalid_chars:
            sanitized = sanitized.replace(char, '_')
        return sanitized

    def generate_filename(self, invoice_number, timestamp=None):
        """Generate filename with timestamp"""
        # Sanitize invoice number
        safe_invoice_number = self.sanitize_filename(invoice_number)
        
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        return f"{safe_invoice_number}_{timestamp}"

    def save_invoice_xml(self, invoice_number, xml_content):
        """Save invoice XML file"""
        try:
            filename = self.generate_filename(invoice_number) + '.xml'
            filepath = os.path.join(self.invoices_dir, filename)
            
            # Ensure the content is in bytes
            if isinstance(xml_content, str):
                content = xml_content.encode('utf-8')
            else:
                content = xml_content
            
            with open(filepath, 'wb') as f:
                f.write(content)
            
            logger.info(f"Saved invoice XML to: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error saving invoice XML: {str(e)}")
            raise

    def save_qr_code(self, invoice_number, qr_image):
        """Save QR code image"""
        try:
            filename = self.generate_filename(invoice_number) + '.png'
            filepath = os.path.join(self.qrcodes_dir, filename)
            
            qr_image.save(filepath)
            logger.info(f"Saved QR code to: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error saving QR code: {str(e)}")
            raise

    def save_zatca_response(self, invoice_number, response_data):
        """Save ZATCA response"""
        try:
            filename = self.generate_filename(invoice_number) + '_response.json'
            filepath = os.path.join(self.responses_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(response_data, f, indent=2)
            
            logger.info(f"Saved ZATCA response to: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error saving ZATCA response: {str(e)}")
            raise

    def get_file_path(self, invoice_number, file_type='xml'):
        """Get latest file path for an invoice"""
        try:
            # Sanitize invoice number for file searching
            safe_invoice_number = self.sanitize_filename(invoice_number)
            
            directory = {
                'xml': self.invoices_dir,
                'qr': self.qrcodes_dir,
                'response': self.responses_dir
            }.get(file_type)
            
            if not directory:
                raise ValueError(f"Invalid file type: {file_type}")
                
            files = [f for f in os.listdir(directory) 
                    if f.startswith(safe_invoice_number) and f.endswith(
                        {
                            'xml': '.xml',
                            'qr': '.png',
                            'response': '_response.json'
                        }[file_type]
                    )]
            
            if not files:
                logger.warning(f"No {file_type} files found for invoice: {invoice_number}")
                return None
                
            latest_file = sorted(files)[-1]
            return os.path.join(directory, latest_file)
            
        except Exception as e:
            logger.error(f"Error getting file path: {str(e)}")
            raise

    def get_all_files(self, invoice_number):
        """Get all files associated with an invoice"""
        try:
            files = {}
            for file_type in ['xml', 'qr', 'response']:
                file_path = self.get_file_path(invoice_number, file_type)
                if file_path:
                    files[file_type] = file_path
            return files
        except Exception as e:
            logger.error(f"Error getting all files: {str(e)}")
            raise