# from base64 import b64encode
from Crypto.Cipher import AES
# from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def ecb_encrypt(keysize, message_bytes):
    keysize_bytes = keysize/8
    aes_key = get_random_bytes(keysize_bytes)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
    return aes_key, ct_bytes


def ecb_decrypt(aes_key, message_bytes):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    pt_bytes = unpad(cipher.decrypt(message_bytes), AES.block_size)
    return pt_bytes


def cbc_encrypt(keysize, message_bytes):
    keysize_bytes = keysize/8
    aes_key = get_random_bytes(keysize_bytes)
    iv = get_random_bytes(keysize_bytes)
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
    return aes_key, iv, ct_bytes


def cbc_decrypt(aes_key, iv, message_bytes):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt_bytes = unpad(cipher.decrypt(message_bytes), AES.block_size)
    return pt_bytes

# def ctr_encrypt(messageBytes):
# def cfb_encrypt(messageBytes):
# def ofb_encrypt(messageBytes):
