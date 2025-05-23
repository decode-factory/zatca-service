# ZATCA E-Invoice Service

A Python service for generating, validating, and submitting electronic invoices according to ZATCA (Zakat, Tax and Customs Authority) specifications in Saudi Arabia.

## Features

- Generate ZATCA-compliant UBL 2.1 XML invoices
- Generate QR codes for invoices
- Validate invoice data and structure
- Handle digital signatures and certificates
- Submit invoices to ZATCA API
- Support for both B2B and B2C invoicing
- File handling for invoices, QR codes, and API responses

## Prerequisites

- Python 3.8 or higher
- Required Python packages (see requirements.txt)
- ZATCA API credentials
- Valid certificates for production environment

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/zatca-service.git
cd zatca-service
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure your environment variables or update config.py with your settings.

## Project Structure

```
zatca-service/
├── app/
│   ├── __init__.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── zatca_service.py
│   │   └── xml_service.py
│   ├── utils/
│   │   ├── __init__.py
│   │   └── file_handler.py
│   └── routes/
│       ├── __init__.py
│       └── api.py
├── certs/
│   ├── sandbox/
│   │   ├── cert.pem
│   │   └── private-key.pem
│   └── production/
├── generated/
│   ├── invoices/
│   ├── qrcodes/
│   └── responses/
├── config.py
├── requirements.txt
└── README.md
```

## Configuration

Create a `config.py` file with your ZATCA settings:

```python
class Config:
    SECRET_KEY = 'your-secret-key'
    ENVIRONMENT = 'sandbox'  # or 'production'
    
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
    
    CERT_PATH = {
        'sandbox': {
            'certificate': 'path/to/sandbox/cert.pem',
            'private_key': 'path/to/sandbox/private-key.pem'
        },
        'production': {
            'certificate': 'path/to/production/cert.pem',
            'private_key': 'path/to/production/private-key.pem'
        }
    }
```

## Usage

### API Endpoints

1. Process Invoice
```bash
POST /api/process-invoice
Content-Type: application/json

{
    "Invoice": {
        // Invoice data in ZATCA format
    }
}
```

2. Generate Compliance Invoice
```bash
POST /api/generate-compliance
Content-Type: application/json

{
    // Invoice data
}
```

3. Check API Status
```bash
GET /api/api-status
```

4. Validate Certificates
```bash
GET /api/validate-certificates
```

### Example Usage

```python
from app.services import ZATCAService
from config import Config

# Initialize service
zatca_service = ZATCAService(Config)

# Process invoice
invoice_data = {
    "Invoice": {
        "ID": {"__text": "INV-001"},
        "IssueDate": {"__text": "2023-12-30"},
        # ... more invoice data
    }
}

# Validate invoice
zatca_service.validate_invoice(invoice_data)

# Generate QR code
qr_image, qr_string = zatca_service.generate_qr_code(invoice_data)

# Submit to ZATCA
response = zatca_service.submit_to_zatca(invoice_data, "B2B")
```

## Development

To run the development server:

```bash
flask run --debug
```

## Testing

Run tests using:

```bash
python -m pytest tests/
```

## Production Deployment

1. Set up your production certificates in the `certs/production/` directory
2. Configure your production environment variables
3. Use a production-grade WSGI server (e.g., Gunicorn)

```bash
gunicorn app:app
```

## Error Handling

The service includes comprehensive error handling for:
- Invalid invoice data
- Certificate errors
- API submission failures
- File handling errors

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please contact [your-email@domain.com]