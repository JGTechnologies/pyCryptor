import os

from Crypto.Cipher import (
    AES,
    PKCS1_OAEP,
)
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from hashlib import sha256

class EncryptionHelper:
    def __init__(self, key, path):
        self.key = key

        if not os.path.exists(path):
            raise Exception("Path does not exist")

        self.path = path

    def encrypt(self, path = ""):
        if path == "":
            path = self.path

        if os.path.isdir(path):
            contents = os.listdir(path)
            for content in contents:
                self.encrypt(os.path.join(path, content).replace('\\', '/'))

            return

        with open(path, "rb") as hFile:
            data = hFile.read()

        rsa_key = RSA.importKey(self.key)
        aes_key = get_random_bytes(16)

        # encrypt session key with RSA key
        rsa_engine = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_engine.encrypt(aes_key)

        # encrypt data with AES key
        aes_engine = AES.new(aes_key, AES.MODE_EAX)
        cipher_text, cipher_tag = aes_engine.encrypt_and_digest(data)

        with open(path, "wb") as hFile:
            [hFile.write(x) for x in (encrypted_aes_key, aes_engine.nonce, cipher_tag, cipher_text)]

    def decrypt(self, path = ""):
        if path == "":
            path = self.path

        if os.path.isdir(path):
            contents = os.listdir(path)
            for content in contents:
                self.decrypt(os.path.join(path, content))

            return

        rsa_key = RSA.import_key(self.key)

        with open(path, "rb") as hFile:
            encrypted_aes_key, nonce, cipher_text_tag, cipher_text = [hFile.read(x) for x in (rsa_key.size_in_bytes(), 16, 16, -1)]

        # decrypt AES key with RSA key
        rsa_engine = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_engine.decrypt(encrypted_aes_key)

        # decrypt data with AES key
        aes_engine = AES.new(aes_key, AES.MODE_EAX, nonce)
        data = aes_engine.decrypt_and_verify(cipher_text, cipher_text_tag)

        with open(path, "wb") as hFile:
            hFile.write(data)