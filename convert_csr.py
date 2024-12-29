from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import datetime

def convert_csr_to_cert():
    # Load private key
    with open('certs/sandbox/private-key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

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
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256())

    # Write the certificate
    with open('certs/sandbox/cert.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Certificate generated successfully")

if __name__ == "__main__":
    convert_csr_to_cert()