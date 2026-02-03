# encrypt_key.py - Run this locally to encrypt your API key
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt_key(api_key, password="el_agent_secure_password_2026"):
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'el_agent_salt_12345',  # Fixed salt
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # Encrypt API key
    fernet = Fernet(key)
    encrypted = fernet.encrypt(api_key.encode())
    
    # Return base64 encoded
    return base64.b64encode(encrypted).decode()

if __name__ == "__main__":
    print("🔒 API Key Encryption Tool")
    print("=" * 40)
    
    your_api_key = input("Enter your SJTU API key: ").strip()
    
    if your_api_key:
        encrypted = encrypt_key(your_api_key)
        print(f"\n✅ Encrypted API Key:")
        print(f"ENCRYPTED_API_KEY = \"{encrypted}\"")
        print(f"\n📋 Copy the above line and replace in app.py")
    else:
        print("❌ No API key provided")