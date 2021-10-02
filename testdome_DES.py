#KEY - 8
#CTR Mode - Encrypt function is fixed, Decrypt function is not working


from Crypto.Cipher import DES
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import json
from Crypto.Util import Counter
from struct import pack

key = input("Enter the key: ")
key = bytes(key, 'utf-8')
plaintext = input("Enter the plaintext to be encrypted: ")
plaintext = bytes(plaintext, 'utf-8')

def DESCBCencrypt():
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, DES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)

def DESCBCdecrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    pt = pt.decode()
    print("The message was: ", pt)

    
def cipherDESCFB_encrypt():
     cipher = DES.new(key, DES.MODE_CFB)
     ct_bytes = cipher.encrypt(plaintext)
     iv = b64encode(cipher.iv).decode('utf-8')
     ct = b64encode(ct_bytes).decode('utf-8')
     result = json.dumps({'iv':iv, 'ciphertext':ct})
     print(result)


def cipherDESCFB_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = DES.new(key, DES.MODE_CFB, iv=iv)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)
    
def cipherDESOFB_encrypt():
    cipher = DES.new(key, DES.MODE_OFB)
    ct_bytes = cipher.encrypt(plaintext)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)
    
def cipherDESOFB_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)
    
    
    
    

   
def cipherDESCTR_encrypt():
    bs = DES.block_size
    plen = bs - len(plaintext) % bs
    padding = [plen] * plen
    padding = pack('b' * plen, *padding)
    nonce = Random.get_random_bytes(4)
    ctr = Counter.new(32, prefix=nonce)
    cipher = DES.new(key, DES.MODE_CTR,counter=ctr)
    ciphertext = cipher.encrypt(plaintext+padding)
    ciphertext = b64encode(ciphertext).decode('utf-8')
    nonce = b64encode(nonce).decode('utf-8')
    print(ciphertext, nonce)
    
   
    """
     cipher = DES.new(key, DES.MODE_CTR)
     ct_bytes = cipher.encrypt(plaintext)
     nonce = b64encode(cipher.nonce).decode('utf-8')
     ct = b64encode(ct_bytes).decode('utf-8')
     result = json.dumps({'nonce':nonce, 'ciphertext':ct})
     print(result)
     """
     
cipherDESCTR_encrypt()
     
def cipherDESCTR_decrypt():
    initial = input("Enter the nonce: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': plaintext}
    nonce = b64decode(dict_input['nonce'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = DES.new(key, DES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)

