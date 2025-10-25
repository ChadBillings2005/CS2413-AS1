from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
import base64


with open("private_key.pem", "rb") as f:
		private_key = f.read()

#print(private_key[:50])

sha256_hash = SHA256.new(private_key).hexdigest()
print("\nSHA-256 hash from file: ", sha256_hash, "\n")


hash_options = {
	"A": "1a4c8b9d847b3e2fa2d5f9d31c8e5f8b7c91a5d0f4e5b2f7d8c6e2a9b4d5e1c3",
    "B": "9e427f6bea8af1fc9d2d332312338cf538759ebe5f71843af205c18d726623f9",
    "C": "3f4b5c2d9a8e7f1c5d3b2a9c6e1d4f7b8a2c5e9f1d0b3a7c8e6d2f5b9a4c3e1d",
    "D": "0d09a513353e632b068a1a49e6ecc0b2c753ccc1c95cb1751745ba576d1396c8"
}

print("Options:")

for key, value in hash_options.items():
	print(f"{key}: {value}")
	if sha256_hash.lower() == value.lower():
		print(f"\nOption {key} is correct!\n")






