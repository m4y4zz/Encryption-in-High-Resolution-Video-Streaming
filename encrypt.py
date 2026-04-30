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

# Choose the key size and block size values that correspond to the cipher that will be tested, confirm Table I. on the readme file.
###################
KEY_SIZE = 16
#KEY_SIZE = 32

#BLOCK_SIZE = 8
BLOCK_SIZE = 16
####################

GLOBAL_KEY = token_bytes(KEY_SIZE)
POLYNOMIAL = 0x11B



S_BOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
)

MIX_MATRIX = (
    (0x02, 0x03, 0x01, 0x01),
    (0x01, 0x02, 0x03, 0x01),
    (0x01, 0x01, 0x02, 0x03),
    (0x03, 0x01, 0x01, 0x02)
)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def g_mul(a, b):
    
    p = 0
    a &= 0xFF 
    b &= 0xFF

    for _ in range(8):
        if b & 1:
            p ^= a
        
        high_bit_set = (a & 0x80)
        
        a <<= 1
        
        if high_bit_set:
            a ^= POLYNOMIAL
            
        a &= 0xFF
        b >>= 1
        
    return p & 0xFF

def sub_bytes(state: bytes) -> bytes:
    return bytes(S_BOX[b] for b in state)

def shift_rows(state: bytes) -> bytes:
   
    s = list(state)
    new_s = [0] * 16

    new_s[0] = s[0]
    new_s[4] = s[4]
    new_s[8] = s[8]
    new_s[12] = s[12]

   
    new_s[1] = s[5]
    new_s[5] = s[9]
    new_s[9] = s[13]
    new_s[13] = s[1]
    
    
    new_s[2] = s[10]
    new_s[6] = s[14]
    new_s[10] = s[2]
    new_s[14] = s[6]

    
    new_s[3] = s[15]
    new_s[7] = s[3]
    new_s[11] = s[7]
    new_s[15] = s[11]

    return bytes(new_s)

def mix_columns(state: bytes) -> bytes:
    
    s = list(state)
    new_s = [0] * 16

    for c in range(4): 
        for r in range(4): 
            
            temp = 0
            
            for i in range(4):
                
                m = MIX_MATRIX[r][i] 
                
                
                s_byte = s[4 * c + i] 
                
                temp ^= g_mul(m, s_byte)
                
            new_s[4 * c + r] = temp
            
    return bytes(new_s)

def add_round_key(state, round_key):
    return xor_bytes(state, round_key)

def expand_key(key):
    
   
    w = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
    
    for i in range(4, 44):
        temp = w[i-1]
        
       
        if i % 4 == 0:
            temp = (temp << 8) & 0xFFFFFFFF | (temp >> 24) 
            
            b = temp.to_bytes(4, 'big')
            b = sub_bytes(b)
            temp = int.from_bytes(b, 'big')
            
            rcon = RCON[i // 4] << 24 
            temp ^= rcon
            
        w.append(w[i-4] ^ temp)

    expanded_key = b''
    for word in w:
        expanded_key += word.to_bytes(4, 'big')
        
    return expanded_key

def aes_encrypt_block(block: bytes, expanded_key: bytes) -> bytes:
    
    state = block
    
    NUM_ROUNDS = 10
    
    round_key = expanded_key[0:16]
    state = add_round_key(state, round_key)
    
    for r in range(1, NUM_ROUNDS):
        key_start = r * 16
        round_key = expanded_key[key_start:key_start + 16]
        
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state) 
        state = add_round_key(state, round_key)
        
    key_start = NUM_ROUNDS * 16
    round_key = expanded_key[key_start:key_start + 16]
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key)
    
    return state
    
def manual_aes_encrypt(block: bytes, expanded_key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("The block must be 16 bytes for AES-128.")
    return aes_encrypt_block(block, expanded_key)
	
def aes_ctr_mode(data: bytes, key: bytes, nonce: bytes) -> bytes:
  
    expanded_key = expand_key(key)
    output = bytearray()
    NONCE_SIZE = len(nonce)
    COUNTER_SIZE = BLOCK_SIZE - NONCE_SIZE
    initial_counter_block = nonce + (0).to_bytes(COUNTER_SIZE, 'big')
    if NONCE_SIZE >= BLOCK_SIZE:
        raise ValueError("Nonce too large. There should be room for the counter.")
    counter_value = 0
    
    for i in range(0, len(data), BLOCK_SIZE):
                
        counter_part = counter_value.to_bytes(COUNTER_SIZE, 'big')
        counter_block_in = nonce + counter_part
        
        keystream_block = aes_encrypt_block(counter_block_in, expanded_key)
        
        data_block = data[i : i + BLOCK_SIZE]
        keystream_for_block = keystream_block[:len(data_block)] 
        
        encrypted_part = xor_bytes(data_block, keystream_for_block)
        output.extend(encrypted_part)
        
        counter_value += 1
        
    return bytes(output)

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
    if mode == "AES-128-CTR-MAN":
        return aes_ctr_mode(data, key, nonce)
    elif mode == "AES-CTR-LIB":
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
    if mode == "AES-128-CTR-MAN":
        return aes_ctr_mode(data, key, nonce)
    elif mode == "AES-CTR-LIB":
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

AVAILABLE_CIPHERS = ["AES-128-CTR-MAN", "AES-CTR-LIB", "CHACHA20-LIB", "SALSA20-LIB", "BLOWFISH-LIB", "CAMELLIA-LIB"]

