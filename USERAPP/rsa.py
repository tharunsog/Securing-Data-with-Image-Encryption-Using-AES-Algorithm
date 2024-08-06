# rsa.py

import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key


def save_key_to_file(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


def load_private_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        key_data = key_file.read()
        return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())


def save_public_key_to_file(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(
            key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_public_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        key_data = key_file.read()
        return serialization.load_pem_public_key(key_data, backend=default_backend())


def encrypted(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')


def decrypted(ciphertext, private_key):
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')
