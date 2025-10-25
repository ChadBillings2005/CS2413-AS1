#!/usr/bin/env python3
# AES CBC encryption/decryption with integrity verification using HMAC (MD5 or SHA-256)
# Requires: PyCryptodome

from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES


# -------------------- Keying & helpers --------------------

def key_generation(password: str, shamd5: str) -> bytes:
    """
    Derive the AES encryption key directly from the password using the chosen hash.
    (For learning/demo purposes. For production, use PBKDF2/scrypt/Argon2 with a salt.)
    """
    if shamd5.lower() == 'y':
        return SHA256.new(password.encode('utf-8')).digest()
    elif shamd5.lower() == 'n':
        return MD5.new(password.encode('utf-8')).digest()
    else:
        print("Error in input, neither SHA-256 or MD5 selected")
        raise SystemExit(1)

def _hash_module(shamd5: str):
    return SHA256 if shamd5.lower() == 'y' else MD5

def _mac_key(password: str, shamd5: str) -> bytes:
    """
    Derive a separate MAC key from the password using the same hash.
    Using simple domain separation to avoid key reuse across purposes.
    """
    Hash = _hash_module(shamd5)
    return Hash.new(password.encode('utf-8') + b"|MAC|").digest()

def _tag_len(shamd5: str) -> int:
    return 32 if shamd5.lower() == 'y' else 16


# -------------------- Encrypt / Decrypt with integrity --------------------

def encryption(message: str, password: str, shamd5: str) -> bytes:
    """
    Encrypts the message with AES-CBC and appends an HMAC tag over IV||ciphertext.
    Output blob layout: [IV (16 bytes)] [ciphertext] [TAG (16 or 32 bytes)].
    """
    key = key_generation(password, shamd5)
    mac_key = _mac_key(password, shamd5)
    Hash = _hash_module(shamd5)

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(message.encode('utf-8'), 16))

    tag = HMAC.new(mac_key, iv + ct, digestmod=Hash).digest()
    return iv + ct + tag

def decryption(blob: bytes, password: str, shamd5: str) -> str:
    """
    Verifies HMAC (integrity) BEFORE decrypting.
    If integrity fails, raises ValueError from HMAC.verify.
    """
    key = key_generation(password, shamd5)
    mac_key = _mac_key(password, shamd5)
    Hash = _hash_module(shamd5)
    tag_len = _tag_len(shamd5)

    if len(blob) < 16 + tag_len:
        raise ValueError("Ciphertext too short")

    iv = blob[:16]
    tag = blob[-tag_len:]
    ct = blob[16:-tag_len]

    # Verify integrity BEFORE decrypting/unpadding
    hmac_obj = HMAC.new(mac_key, iv + ct, digestmod=Hash)
    hmac_obj.verify(tag)
    print("[INFO] Hash verified! Decrypting message...")  # ✅ Added line
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), 16)
    return pt.decode('utf-8')


# -------------------- CLI-style driver --------------------

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
            # HMAC.verify raises ValueError on mismatch
            print("[ERROR] Integrity check failed (wrong password or tampered data):", e)
        except Exception as e:
            print("[ERROR] Decryption failed:", e)

    else:
        print("ERROR in input, program execution terminated")

if __name__ == "__main__":
    main()
