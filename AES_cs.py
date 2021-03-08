#!/usr/bin/env python
# -*- coding:utf-8 -*-


from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


class PrpCrypt(object):
    def __init__(self, key):
        key = md5(key.encode('utf8')).hexdigest()
        self.key = key.encode('utf-8')

        self.mode = AES.MODE_CBC

    # Encryption function. If the text is less than 16 bits, fill it with Spaces.
    # If it's greater than 16 and it's not a multiple of 16, then it's a multiple of 16.
    def encrypt(self, text):
        text = text.encode('utf-8')
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        # Here the key length must be 16 (AES-128),
        # 24 (AES-192), or 32 (AES-256) Bytes
        # The present AES-128 is sufficient for current use
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            # \0 backspace
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        elif count > length:
            add = (length - (count % length))
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        self.ciphertext = cryptor.encrypt(text)
        # Because the string obtained by AES encryption is not necessarily the ASCII character set, there may be problems when output to the terminal or save
        # So here we uniformly convert the encrypted string to hexadecimal string
        return b2a_hex(self.ciphertext)

    # After decrypting, strip() is used to remove padding Spaces
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        plain_text = cryptor.decrypt(a2b_hex(text))
        # return plain_text.rstrip('\0')
        return bytes.decode(plain_text).rstrip('\0')

from hashlib import md5
if __name__ == '__main__':
    k = 'keyskessssssssssswskesssssyskeys'
    pc = PrpCrypt(k)  # Initialization key

    e = pc.encrypt("aaa")  # encrypt
    d = pc.decrypt(e)  # decrypt
    print("加密:", e)
    print("解密:", d)