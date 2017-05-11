import Crypto.Cipher.AES
import os
import binascii

key2 = bytearray[32]
cipher = Crypto.Cipher.AES.new(key2, Crypto.Cipher.AES.MODE_ECB)
ciphertext = cipher.encrypt("hellohellohelloh");
print binascii.hexlify(ciphertext)
