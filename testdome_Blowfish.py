#In this file, in cipherBlowfish_Decrypt() function, the error is "Incorrect padding".

#the something() function works and cipherBlowfishCBC_encrypt() function is fixed , both are same but different forms of code.

#If cipherBlowfish_Decrypt() function is fixed then the code structure will be similar to AES. The cipherBlowfishCBC_encrypt() function code structure is similar to AES

from Crypto.Cipher import Blowfish
from struct import pack
from base64 import b64encode, b64decode, encode
import json
from Crypto.Util.Padding import pad, unpad
 
bs = Blowfish.block_size
key = input("Enter the key: ")
key = bytes(key, 'utf-8')
plaintext = input("Enter the plaintext to be encrypted: ")
plaintext = bytes(plaintext, 'utf-8')

def something():
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    plen = bs - len(plaintext) % bs
    padding = [plen]*plen
    padding = pack('b'*plen, *padding)
    msg = cipher.iv + cipher.encrypt(plaintext + padding)
    msg = b64encode(msg).decode('utf-8')
    iv = b64encode(cipher.iv).decode('utf-8')
    print(msg, iv)



#hkJ4iRXigyuHNwQ1RIgXmg== = ct
#hkJ4iRXigys= = iv

def cipherBlowfishCBC_encrypt():
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, Blowfish.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)  
#cipherBlowfishCBC_encrypt()

def cipherBlowfishCBC_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), Blowfish.block_size)
    print("The message was: ", pt)
    
cipherBlowfishCBC_decrypt()