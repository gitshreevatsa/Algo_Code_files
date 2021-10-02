#KEY - 16 
#CTR Mode - Encrypt function is fixed, Decrypt function is not working


import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from struct import pack
from Crypto import Random


inp = input("Enter The data: ")
data = bytes(inp, 'utf-8')
index = input("Enter the key: ")
key = bytes(index, 'utf-8')

#operation_dictionary = {1:'encrypt', 2:'decrypt'}                                                                                                                                  
#operation_index = int(input("Enter 1 for Encryption:\nEnter 2 for decryption:\n"))
#operation = operation_dictionary.get(operation_index)

def cipherAESCBC_encrypt():
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)


def cipherAESCBC_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': data}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    pt = pt.decode()
    print("The message was: ", pt)

def cipherAESCFB_encrypt():
     cipher = AES.new(key, AES.MODE_CFB)
     ct_bytes = cipher.encrypt(data)
     iv = b64encode(cipher.iv).decode('utf-8')
     ct = b64encode(ct_bytes).decode('utf-8')
     result = json.dumps({'iv':iv, 'ciphertext':ct})
     print(result)


def cipherAESCFB_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': data}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)
    
def cipherAESOFB_encrypt():
    cipher = AES.new(key, AES.MODE_OFB)
    ct_bytes = cipher.encrypt(data)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)
    
def cipherAESOFB_decrypt():
    initial = input("Enter the Vector: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': data}
    iv = b64decode(dict_input['iv'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)







def cipherAESCTR_encrypt():
    bs = AES.block_size
    plen = bs - len(data) % bs
    padding = [plen] * plen
    padding = pack('b' * plen, *padding)
    nonce = Random.get_random_bytes(4)
    ctr = Counter.new(96, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR,counter=ctr)
    ciphertext = cipher.encrypt(data+padding)
    ciphertext = b64encode(ciphertext).decode('utf-8')
    nonce = b64encode(nonce).decode('utf-8')
    print(ciphertext, nonce)
    
    """
     cipher = AES.new(key, AES.MODE_CTR)
     ct_bytes = cipher.encrypt(data)
     nonce = b64encode(cipher.nonce).decode('utf-8')
     ct = b64encode(ct_bytes).decode('utf-8')
     result = json.dumps({'nonce':nonce, 'ciphertext':ct})
     print(result)
     """
     
cipherAESCTR_encrypt()

def cipherAESCTR_decrypt():
    initial = input("Enter the nonce: ")
    initialVector = bytes(initial, 'utf-8')
    dict_input = {'iv': initialVector, 'ciphertext': data}
    nonce = b64decode(dict_input['nonce'])
    ct = b64decode(dict_input['ciphertext'])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    pt = pt.decode('utf-8')
    print("The message was: ", pt)

    
    
#method = AES_CBC
#input = shreyas
#key = somesomesomesome
#iv = kjGwWrtG0Exm9H379CJfUQ==
#ct = pGrsBNfARX+DDFUtRzFaxA==

