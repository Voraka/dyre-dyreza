#Original from lexi https://www.lexsi.com/securityhub/dyrezas-anticrypt/?lang=en
#! /usr/bin/env python

import sys
from hashlib import sha256
from Crypto.Cipher import AES

def get_crypto(buffer, loops):
    current = sha256(buffer).digest()
    for i in range(loops):
        plusone = "".join([chr(((ord(x) + 1) & 0xff)) for x in current[:16]])
        current = sha256(current + plusone).digest()
    return current

data = open("dyre.bin").read()
key = get_crypto(data[:32]  , 0x80)[:32]
iv  = get_crypto(data[32:48], 0x40)[:16]

print "Dyreza decryption tool, CERT-LEXSI 2015"
print "Key " + key.encode("hex")
print "IV  " + iv.encode("hex")
print "Decrypting buffer..."

aes = AES.new(key, AES.MODE_CBC, iv)
print aes.decrypt(data[48:])
