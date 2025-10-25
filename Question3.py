from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
import base64

with open("private_key.pem", "rb") as f:
		private_key = f.read()

#print(private_key[:50])

sha256_hash = SHA256.new(private_key).hexdigest()
print("\nSHA-256 hash from file: ", sha256_hash, "\n")





