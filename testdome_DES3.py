#KEY - 16 
#CTR Mode - Encrypt function is fixed, Decrypt function is not working

from Crypto.Cipher import DES3
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import json
from struct import pack
from Crypto import Random
from Crypto.Util import Counter

key = input("Enter the key: ")
key = bytes(key, 'utf-8')
plaintext = input("Enter the plaintext to be encrypted: ")
plaintext = bytes(plaintext, 'utf-8')

def DES3CBCencrypt():
    cipher = DES3.new(key, DES3.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, DES3.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)
    


def DES3CBCdecrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES3.block_size)
    pt = pt.decode()
    print("The message was: ", pt)
    
def cipherDES3CFB_encrypt():
     cipher = DES3.new(key, DES3.MODE_CFB)
     ct_bytes = cipher.encrypt(plaintext)
     iv = b64encode(cipher.iv).decode('utf-8')
     ct = b64encode(ct_bytes).decode('utf-8')
     result = json.dumps({'iv':iv, 'ciphertext':ct})
     print(result)


def cipherDES3CFB_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)
    
def cipherDES3OFB_encrypt():
    cipher = DES3.new(key, DES3.MODE_OFB)
    ct_bytes = cipher.encrypt(plaintext)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)
    
def cipherDES3OFB_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)
    
    
    
    

    
def cipherDES3CTR_encrypt():
    bs = DES3.block_size
    plen = bs - len(plaintext) % bs
    padding = [plen] * plen
    padding = pack('b' * plen, *padding)
    nonce = Random.get_random_bytes(4)
    ctr = Counter.new(32, prefix=nonce)
    cipher = DES3.new(key, DES3.MODE_CTR,counter=ctr)
    ciphertext = cipher.encrypt(plaintext+padding)
    ciphertext = b64encode(ciphertext).decode('utf-8')
    nonce = b64encode(nonce).decode('utf-8')
    print(ciphertext, nonce)
     
cipherDES3CTR_encrypt()

def cipherDES3CTR_decrypt():
    initial = input("Enter the nonce: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    nonce = b64decode(dict_input['nonce'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = DES3.new(key, DES3.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)

