

from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

def key_generation(password: str, shamd5: str) -> bytes:
    
    # creating the AES Encryption key with your choice of either SHA256 or MD5 
    if shamd5.lower() == 'y': # use SHA256
        return SHA256.new(password.encode('utf-8')).digest()
    elif shamd5.lower() == 'n': # use MD5
        return MD5.new(password.encode('utf-8')).digest()
    else:
        print("Error in input, neither SHA-256 or MD5 selected")
        raise SystemExit(1)

def _hash_module(shamd5: str):
    return SHA256 if shamd5.lower() == 'y' else MD5

def _mac_key(password: str, shamd5: str) -> bytes:
    # create a MAC key from the provided password 
    Hash = _hash_module(shamd5)
    return Hash.new(password.encode('utf-8') + b"|MAC|").digest()

def _tag_len(shamd5: str) -> int:
    return 32 if shamd5.lower() == 'y' else 16

def encryption(message: str, password: str, shamd5: str) -> bytes:
    # Encrypts the message with the provided AES key and Mac key. 
    key = key_generation(password, shamd5)
    mac_key = _mac_key(password, shamd5)
    Hash = _hash_module(shamd5)

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(message.encode('utf-8'), 16))

    tag = HMAC.new(mac_key, iv + ct, digestmod=Hash).digest()
    return iv + ct + tag

def decryption(blob: bytes, password: str, shamd5: str) -> str:
    # Encrypts the message with the provided AES key and Mac key
    key = key_generation(password, shamd5)
    mac_key = _mac_key(password, shamd5)
    Hash = _hash_module(shamd5)
    tag_len = _tag_len(shamd5)

    if len(blob) < 16 + tag_len:
        raise ValueError("Ciphertext too short")

    iv = blob[:16]
    tag = blob[-tag_len:]
    ct = blob[16:-tag_len]

    # verifies integrity before decrypting/unpadding, both different password or altered text file
    hmac_obj = HMAC.new(mac_key, iv + ct, digestmod=Hash)
    hmac_obj.verify(tag)
    print("[INFO] Hash verified! Decrypting message...")  # ✅ Added line

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), 16)
    return pt.decode('utf-8')

def main():
    print("AES Encryption & Decryption with Integrity Check")

    EorD = input("Do you want to (E)ncrypt or (D)ecrypt a message? ")
    username = input("Enter your username: ")  # kept for parity; not used in crypto
    password = input("Enter your password: ")
    YorN = input("Use SHA-256 (Y) or MD5 (N)? ")

    if EorD.lower() == 'e':
        message = input("Enter message to encrypt: ")
        try:
            blob = encryption(message, password, YorN)
            with open("encrypted_output.txt", "w", encoding="utf-8") as f:
                f.write(blob.hex())
            print("[INFO] Encrypted message stored successfully")
        except Exception as e:
            print("[ERROR] Encryption failed:", e)

    elif EorD.lower() == 'd':
        try:
            with open("encrypted_output.txt", "r", encoding="utf-8") as f:
                blob_hex = f.read().strip()
            blob = bytes.fromhex(blob_hex)
        except Exception as e:
            print("[ERROR] Could not read encrypted_output.txt:", e)
            return

        try:
            plaintext = decryption(blob, password, YorN)
            print("Decrypted message:", plaintext)
        except ValueError as e:
            print("[ERROR] Integrity check failed (wrong password or tampered data):", e)
        except Exception as e:
            print("[ERROR] Decryption failed:", e)

    else:
        print("ERROR in input, program execution terminated")

if __name__ == "__main__":
    main()
