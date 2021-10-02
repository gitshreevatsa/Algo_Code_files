#KEY - 16 
#CTR Mode - Encrypt function is fixed, Decrypt function is not working , Error : 'utf-8' codec can't decode byte 0xf2 in position 1: invalid continuation byte

from Crypto import Cipher
from Crypto.Cipher import ARC2
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from base64 import b64encode, b64decode
import json
from struct import pack
from Crypto import Random
from Crypto.Util import Counter

index = input("Enter the key: ")
key = bytes(index, 'utf-8')
user = input("Enter the data: ")
data = bytes(user, 'utf-8')

def encryptRC2CBC():
    iv = Random.new().read(ARC2.block_size)
    cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
    msg = cipher.encrypt(pad(data, ARC2.block_size))
    iv = b64encode(iv).decode('utf-8')
    ct = b64encode(msg).decode('utf-8')
    print(iv)
    print(ct)


def decryptRC2CBC():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': data}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), ARC2.block_size)
    pt = pt.decode()
    print("The message was: ", pt)
    

#5EAmE2pBrjc= = iv
#oE937jwP1Po= = data
    
def encryptRC2CFB():
     cipher = ARC2.new(key, ARC2.MODE_CFB)
     ct_bytes = cipher.encrypt(data)
     iv = b64encode(cipher.iv).decode('utf-8')
     ct = b64encode(ct_bytes).decode('utf-8')
     print(iv)
     print(ct)
     
def decryptRC2CFB():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': data}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = ARC2.new(key, ARC2.MODE_CFB, iv=iv)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)
    

def cipherARC2OFB_encrypt():
    cipher = ARC2.new(key, ARC2.MODE_OFB)
    ct_bytes = cipher.encrypt(data)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)
    

    
def cipherARC2OFB_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': data}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = ARC2.new(key, ARC2.MODE_OFB, iv=iv)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)
       

def cipherARC2CTR_encrypt():
    bs = ARC2.block_size
    plen = bs - len(data) % bs
    padding = [plen] * plen
    padding = pack('b' * plen, *padding)
    nonce = Random.get_random_bytes(4)
    ctr = Counter.new(32, prefix=nonce)
    cipher = ARC2.new(key, ARC2.MODE_CTR,counter=ctr)
    ciphertext = cipher.encrypt(data+padding)
    ciphertext = b64encode(ciphertext).decode('utf-8')
    nonce = b64encode(nonce).decode('utf-8')
    print(ciphertext, nonce)  


     
def cipherARC2CTR_decrypt():
    initial = input("Enter the nonce: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'nonce': initialVector, 'ciphertext': data}
    nonce = b64decode(dict_input['nonce'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = ARC2.new(key, ARC2.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)
    
cipherARC2CTR_decrypt()   
    
