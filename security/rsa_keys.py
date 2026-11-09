from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keys():
    key = RSA.generate(2048)

    private_key = key.export_key()

    public_key = key.publickey().export_key()

    return private_key, public_key


def encrypt_key(aes_key, public_key):

    rsa_public = RSA.import_key(public_key)

    cipher = PKCS1_OAEP.new(rsa_public)

    encrypted_key = cipher.encrypt(aes_key)

    return encrypted_key


def decrypt_key(encrypted_key, private_key):

    rsa_private = RSA.import_key(private_key)

    cipher = PKCS1_OAEP.new(rsa_private)

    decrypted = cipher.decrypt(encrypted_key)

    return decrypted