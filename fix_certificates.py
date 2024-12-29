import os

def fix_pem_file(file_path):
    """Remove BOM and fix line endings in PEM files"""
    try:
        # Read the file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Remove BOM if present
        if content.startswith(b'\xef\xbb\xbf'):
            content = content[3:]
        
        # Normalize line endings and whitespace
        content = content.decode('utf-8').strip()
        lines = [line.strip() for line in content.splitlines()]
        normalized_content = '\n'.join(lines)
        
        # Write back the fixed content
        with open(file_path, 'w', newline='\n') as f:
            f.write(normalized_content)
            f.write('\n')  # Add final newline
            
        print(f"Successfully fixed {file_path}")
        return True
        
    except Exception as e:
        print(f"Error fixing {file_path}: {str(e)}")
        return False

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cert_dir = os.path.join(base_dir, 'certs', 'sandbox')
    
    # Fix certificate
    cert_path = os.path.join(cert_dir, 'cert.pem')
    if os.path.exists(cert_path):
        fix_pem_file(cert_path)
    
    # Fix private key
    key_path = os.path.join(cert_dir, 'private-key.pem')
    if os.path.exists(key_path):
        fix_pem_file(key_path)

if __name__ == "__main__":
    main()