from security.aes import encrypt, decrypt
from security.rsa_keys import generate_keys, encrypt_key, decrypt_key

# Medical report
report = """Patient Name : Rahul
Age : 42
Diagnosis : Pneumonia"""

# AES Encryption
cipher_text, aes_key = encrypt(report)

print("Encrypted Report:")
print(cipher_text)

# RSA Key Generation
private_key, public_key = generate_keys()

print("\nRSA Keys Generated Successfully!")

# Encrypt AES Key
encrypted_aes_key = encrypt_key(aes_key, public_key)

print("\nAES Key Encrypted with RSA")

# Decrypt AES Key
decrypted_aes_key = decrypt_key(encrypted_aes_key, private_key)

print("\nAES Key Decrypted Successfully")

# AES Decryption
original = decrypt(cipher_text, decrypted_aes_key)

print("\nRecovered Report:")
print(original)