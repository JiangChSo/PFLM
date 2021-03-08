#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

# Reference: https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41
class AESCipher:

    def __init__(self, key):
        # Hash the given passkey to have a 16-bytes compatible AES key
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw) # input should also be multiple of 16 bytes
        iv = get_random_bytes(AES.block_size) # IV should be random each time
        cipher = AES.new(self.key, AES.MODE_CBC, iv) # We use mode CBC
        c = iv + cipher.encrypt(raw) # Prepend the IV to the encryption object
        return b64encode(c).decode('utf8') # Base64 it to send it as an ASCII string (e.g over the network)

    def decrypt(self, enc):
        enc = b64decode(enc) # Base64 decode the string
        iv = enc[:16] # The 16 first bytes are the random initialization vector
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        m = unpad(cipher.decrypt(enc[16:]))
        return m.decode('utf8') # Returns an unicode string



### Example: ###
# key = 'ThisIsMySecretPassword!@#123'
# msg = 'Here is the message I want to encrypt, it is a unicode string.'
#
# ciphertext = AESCipher(key).encrypt(msg)
# print(ciphertext) # The ciphertext will be in bytes
#
# recovered_msg = AESCipher(key).decrypt(ciphertext)
# print(recovered_msg) # recovered_msg == msg
