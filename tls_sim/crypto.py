from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

def generate_rsa(bits=2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(pub_bytes: bytes, plaintext: bytes) -> bytes:
    pub = RSA.import_key(pub_bytes)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return cipher.encrypt(plaintext)

def rsa_decrypt(priv_bytes: bytes, ciphertext: bytes) -> bytes:
    priv = RSA.import_key(priv_bytes)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext)

def derive_keys(client_random: bytes, server_random: bytes, premaster: bytes, length=32) -> bytes:
    salt = client_random + server_random
    return PBKDF2(premaster, salt, dkLen=length, count=1000, hmac_hash_module=SHA256)

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes=b'') -> bytes:
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad: cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ct

def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes=b'') -> bytes:
    iv = blob[:12]; tag = blob[12:28]; ct = blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad: cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)
