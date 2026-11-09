from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypt raw file data (PDF, image, etc.) using AES-GCM.
    Returns the encrypted bytes (nonce + tag + ciphertext).
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Combine nonce + tag + ciphertext into a single blob
    encrypted_data = cipher.nonce + tag + ciphertext
    
    return encrypted_data

def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt file data using AES-GCM.
    """
    nonce = encrypted_data[:16]       # First 16 bytes = nonce
    tag = encrypted_data[16:32]       # Next 16 bytes = tag
    ciphertext = encrypted_data[32:]  # Rest = ciphertext
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    
    return decrypted