#Candice Inman, Chad Billings CS2413

from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
import base64

with open("private_key.pem", "rb") as f:
		private_key = RSA.import_key(f.read())

with open("encrypted_message.txt", "r") as f:
		encrypted_data = base64.b64decode(f.read().strip())

print("\nEncrypted cipher text loaded from file:\n", encrypted_data)

rsa_cipher = PKCS1_OAEP.new(private_key)

decrypted_data = rsa_cipher.decrypt(encrypted_data)

print("\nDecrypted message: \n", decrypted_data.decode(), "\n")


