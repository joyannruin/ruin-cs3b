import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
import os
from Crypto.Cipher import DES, DES3

# Define symmetric encryption functions
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

def des_encrypt(plaintext, key):
    des = DES.new(key, DES.MODE_ECB)
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = des.encrypt(padded_data)
    return ciphertext

def des_decrypt(ciphertext, key):
    des = DES.new(key, DES.MODE_ECB)
    padded_data = des.decrypt(ciphertext)
    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

def triple_des_encrypt(plaintext, key):
    triple_des = DES3.new(key, DES3.MODE_ECB)
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = triple_des.encrypt(padded_data)
    return ciphertext

def triple_des_decrypt(ciphertext, key):
    triple_des = DES3.new(key, DES3.MODE_ECB)
    padded_data = triple_des.decrypt(ciphertext)
    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

# Define RSA encryption and decryption functions
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Define hashing functions
def hash_text(text, algorithm):
    hash_func = hashlib.new(algorithm)
    hash_func.update(text.encode())
    return hash_func.hexdigest()

def hash_file(file, algorithm):
    hash_func = hashlib.new(algorithm)
    while chunk := file.read(8192):
        hash_func.update(chunk)
    return hash_func.hexdigest()

# Streamlit Interface
st.title("Applied Cryptography Application")

# Symmetric Encryption Section
st.header("Symmetric Encryption")

sym_plaintext = st.text_area("Plaintext (Symmetric):")
sym_key = st.text_area("Key (AES: 16/24/32 bytes, DES: 8 bytes, Triple DES: 16/24 bytes):")
sym_algorithm = st.selectbox("Algorithm (Symmetric)", ["AES", "DES", "Triple DES"])

if st.button("Encrypt (Symmetric)"):
    try:
        if sym_algorithm == "AES":
            if len(sym_key) not in [16, 24, 32]:
                st.error("AES key must be 16, 24, or 32 bytes long")
            else:
                encrypted = aes_encrypt(sym_plaintext.encode(), sym_key.encode())
                st.write('Ciphertext:', encrypted.hex())
        elif sym_algorithm == "DES":
            if len(sym_key) != 8:
                st.error("DES key must be 8 bytes long")
            else:
                encrypted = des_encrypt(sym_plaintext.encode(), sym_key.encode())
                st.write('Ciphertext:', encrypted.hex())
        elif sym_algorithm == "Triple DES":
            if len(sym_key) not in [16, 24]:
                st.error("Triple DES key must be 16 or 24 bytes long")
            else:
                encrypted = triple_des_encrypt(sym_plaintext.encode(), sym_key.encode())
                st.write('Ciphertext:', encrypted.hex())
    except Exception as e:
        st.error("Encryption failed: " + str(e))

if st.button("Decrypt (Symmetric)"):
    try:
        if sym_algorithm == "AES":
            decrypted = aes_decrypt(bytes.fromhex(sym_plaintext), sym_key.encode())
            st.write('Decrypted:', decrypted.decode())
        elif sym_algorithm == "DES":
            decrypted = des_decrypt(bytes.fromhex(sym_plaintext), sym_key.encode())
            st.write('Decrypted:', decrypted.decode())
        elif sym_algorithm == "Triple DES":
            decrypted = triple_des_decrypt(bytes.fromhex(sym_plaintext), sym_key.encode())
            st.write('Decrypted:', decrypted.decode())
    except Exception as e:
        st.error("Decryption failed: " + str(e))

# Asymmetric Encryption Section
st.header("Asymmetric Encryption")

private_key, public_key = generate_rsa_keys()
st.write("Public Key:", public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode())
st.write("Private Key:", private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode())

asym_plaintext = st.text_area("Plaintext (Asymmetric):")

if st.button("Encrypt (RSA)"):
    try:
        encrypted = rsa_encrypt(asym_plaintext, public_key)
        st.write('Ciphertext:', encrypted.hex())
    except Exception as e:
        st.error("Encryption failed: " + str(e))

if st.button("Decrypt (RSA)"):
    try:
        decrypted = rsa_decrypt(bytes.fromhex(asym_plaintext), private_key)
        st.write('Decrypted:', decrypted)
    except Exception as e:
        st.error("Decryption failed: " + str(e))

# Hashing Functions Section
st.header("Hashing Functions")

text_to_hash = st.text_area("Text to Hash:")
hash_algo = st.selectbox("Hash Algorithm", ["MD5", "SHA-1", "SHA-256", "SHA-512"])

if st.button("Hash Text"):
    hashed_text = hash_text(text_to_hash, hash_algo)
    st.write('Hashed Text:', hashed_text)

file_to_hash = st.file_uploader("File to Hash")

if st.button("Hash File"):
    if file_to_hash:
        try:
            hashed_file = hash_file(file_to_hash, hash_algo)
            st.write('Hashed File:', hashed_file)
        except Exception as e:
            st.error("Hashing failed: " + str(e))
    else:
        st.error("Please upload a file to hash")
