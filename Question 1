from Crypto.Hash import SHA256
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES 

def key_generation(password,shamd5):
    if(shamd5.lower() == 'y'):
        return SHA256.new(password.encode()).digest()
    elif(shamd5.lower() =='n'):
        return MD5.new(password.encode()).digest()
    else:
        print("Error in input, neither SHA-256 or MD5 selected")
        quit()

def encryption(message,password, shamd5) -> bytes:
    key = key_generation(password,shamd5)
    iv = get_random_bytes(16)
    cipher = AES.new(key,AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(message.encode(),16))
    return iv+ct   

def decryption(blob,password, shamd5) -> str:
    key = key_generation(password,shamd5)
    iv, ct = blob[:16], blob[16:]
    cipher = AES.new(key,AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct),16)
    return pt.decode()

print("AES Encryption & Decryption with Integrity Check")

EorD = input("Do you want to (E)ncrypt or (D)ecrypt a message? ")
username = input("Enter your username: ")
password = input("Enter your password: ")
YorN = input("Use SHA-256 (Y) or MD5 (N)? ")


if(EorD.lower() == 'e'):
    message = input("Enter message to encrypt: ")
    blob = encryption(message,password,YorN)
    with open("encrypted_output.txt", "w") as f:
        f.write(blob.hex())
    print("[INFO] Encrypted data message stored successfully")
elif(EorD.lower() == 'd'):
    with open("encrypted_output.txt", "r") as f:
        blob_hex = f.read().strip()
    try:
        blob = bytes.fromhex(blob_hex)
        plaintext = decryption(blob, password, YorN)
        print("Decrypted message:", plaintext)
    except Exception as e:
        print("[ERROR] Decryption failed:", e)
else:
    print("ERROR in input program execution terminated")
    quit()


