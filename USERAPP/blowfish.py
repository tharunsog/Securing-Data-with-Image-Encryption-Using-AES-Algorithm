# blowfish.py
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes


def encryptbf(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return cipher.nonce, tag, ciphertext


def decryptbf(nonce, tag, ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')
