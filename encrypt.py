import os
import hashlib
import struct
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from Crypto.Cipher import Salsa20 
from Crypto.Cipher import Blowfish
from cryptography.hazmat.primitives import padding
from secrets import token_bytes

CIPHER_CONFIG = {
    "AES-CTR-LIB":   {"KEY_SIZE": 32, "BLOCK_SIZE": 16, "NONCE_SIZE": 16},
    "CHACHA20-LIB":  {"KEY_SIZE": 32, "BLOCK_SIZE": 16, "NONCE_SIZE": 16},
    "SALSA20-LIB":   {"KEY_SIZE": 32, "BLOCK_SIZE": 16, "NONCE_SIZE": 8},
    "BLOWFISH-LIB":  {"KEY_SIZE": 32, "BLOCK_SIZE": 8, "NONCE_SIZE": 8},
    "CAMELLIA-LIB":  {"KEY_SIZE": 32, "BLOCK_SIZE": 16, "NONCE_SIZE": 8}
}


def aes_ctr_mode_lib(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def chacha20_lib(data: bytes, key: bytes, nonce: bytes) -> bytes:
   
    if len(nonce) < 16:
        nonce = nonce.ljust(16, b'\x00')
    elif len(nonce) > 16:
        nonce = nonce[:16]
        
    algorithm = ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)
    
def salsa20_lib(data: bytes, key: bytes, nonce: bytes) -> bytes:
    if isinstance(data, str):
        data = data.encode('utf-8')
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)
    
def blowfish_lib(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = Blowfish.new(key, Blowfish.MODE_CTR, nonce=nonce[:4])
    return cipher.encrypt(data)

def camellia_encrypt_lib(data: bytes, key: bytes, nonce: bytes) -> bytes:
   
    iv = nonce.ljust(16, b'\x00')[:16]
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    algorithm = algorithms.Camellia(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def camellia_decrypt_lib(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    
    iv = nonce.ljust(16, b'\x00')[:16]
    
    algorithm = algorithms.Camellia(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt_dataA(key: bytes, data: bytes, mode: str, nonce: bytes) -> bytes:
    global chave_publica
    if mode == "AES-CTR-LIB":
        return aes_ctr_mode_lib(data, key, nonce)
    elif mode == "CHACHA20-LIB":
        return chacha20_lib(data, key, nonce)
    elif mode == "SALSA20-LIB":
        return salsa20_lib(data, key, nonce)
    elif mode == "BLOWFISH-LIB":
        return blowfish_lib(data, key, nonce)
    elif mode == "CAMELLIA-LIB":
        return camellia_encrypt_lib(data, key, nonce)
    raise ValueError(f"Modo de cifra '{mode}' não suportado.")

def decrypt_dataA(key: bytes, data: bytes, mode: str, nonce: bytes) -> bytes:
    global chave_privada
    if mode == "AES-CTR-LIB":
        return aes_ctr_mode_lib(data, key, nonce)
    elif mode == "CHACHA20-LIB":
        return chacha20_lib(data, key, nonce)
    elif mode == "SALSA20-LIB":
        return salsa20_lib(data, key, nonce)
    elif mode == "BLOWFISH-LIB":
        return blowfish_lib(data, key, nonce)
    elif mode == "CAMELLIA-LIB":
        return camellia_decrypt_lib(data, key, nonce)
    raise ValueError(f"Modo de cifra '{mode}' não suportado.")

AVAILABLE_CIPHERS = ["AES-CTR-LIB", "CHACHA20-LIB", "SALSA20-LIB", "BLOWFISH-LIB", "CAMELLIA-LIB"]

