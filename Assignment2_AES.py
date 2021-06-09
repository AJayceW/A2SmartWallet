#!/usr/bin/python3 
 
# This is version 2.0
 
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode
from binascii import unhexlify
 
class AESCrypt(object):
    def __init__(self, key, bank="no"): 
        self.blockSize = AES.block_size
        self.char = 'utf-8'
 
        if type(key) == str:
            if bank == "no":
                self.key = hashlib.sha256(key.encode(self.char)).hexdigest()
            
            else:
                self.key = unhexlify(key)
 
        if type(key) == int:
            self.key = hashlib.sha256(bytes(key)).hexdigest()
 
        if type(key) == bytes:
            self.key = key
 
    def encrypt(self, plaintext):
        if type(plaintext) == int:
            plaintext = bytes(plaintext)
 
        if type(plaintext) == str:
            plaintext = plaintext.encode(self.char)
 
        iv = Random.new().read(AES.block_size)
 
        if type(self.key) == bytes:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        else:
            cipher = AES.new(unhexlify(self.key), AES.MODE_CBC, iv)
 
        return b64encode(iv + cipher.encrypt(pad(plaintext, self.blockSize)))
 
    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:AES.block_size]
 
        if type(self.key) == bytes:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        else:
            cipher = AES.new(unhexlify(self.key), AES.MODE_CBC, iv)
 
        return unpad(cipher.decrypt(enc[AES.block_size:]), self.blockSize).decode(self.char)
 
    def getKey(self):
        return self.key