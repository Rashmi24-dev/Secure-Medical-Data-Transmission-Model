from security.aes import decrypt as aes_decrypt
from security.rsa_keys import decrypt_key as rsa_decrypt_key
from security.hash import verify_hash
from security.dwt import extract_data


def decrypt_report(stego_image_path, encrypted_aes_key_path, private_key_path, original_sha256_hash):
    """
    Full decryption process:
    1. Extract encrypted data from Stego Image
    2. Decrypt the AES key using RSA
    3. Decrypt the report using AES
    4. Verify SHA-256 hash integrity
    """
    
    # 1. Read the encrypted AES key from file
    with open(encrypted_aes_key_path, 'rb') as f:
        encrypted_aes_key = f.read()
    
    # 2. Read the RSA private key
    with open(private_key_path, 'rb') as f:
        private_key_pem = f.read()
    
    # 3. Decrypt the AES key using RSA
    aes_key = rsa_decrypt_key(encrypted_aes_key, private_key_pem)
    
    # 4. Extract the encrypted data from the Stego Image (Need to know data length)
    # Note: You need to know the length of the encrypted data. 
    # For a real system, you might store the length in the database or 
    # embed the length as metadata in the image. For now, we assume it's in the DB.
    # (In this demo, we will use a fixed length or get it from the database)
    
    # Placeholder: Get the encrypted data length from database or pass it as argument
    # (You will need to modify this based on your database structure)
    encrypted_data_length = 4096  # Example, replace with actual length from DB
    
    # 5. Extract hidden encrypted data from Stego Image
    encrypted_data = extract_data(stego_image_path, encrypted_data_length)
    
    # 6. Decrypt the report using AES
    decrypted_report = aes_decrypt(encrypted_data, aes_key)
    
    # 7. Verify SHA-256 Hash
    original_data = decrypted_report  # The decrypted report data
    is_valid = verify_hash(original_data, original_sha256_hash)
    
    return decrypted_report, is_valid