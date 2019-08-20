from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# Generates keys
def GenerateKeys(bits):
   private_key = RSA.generate(bits)
   public_key = private_key.publickey()
   return private_key, public_key

# Encrypts message with public_key
def Encrypt(message, public_key):
   cipher_rsa = PKCS1_v1_5.new(public_key) 
   ciphertext = cipher_rsa.encrypt(message)
   return ciphertext

# Decrypts ciphertext with private key
def Decrypt(ciphertext, private_key):
   sentinel = "Error"  
   cipher_rsa = PKCS1_v1_5.new(private_key)
   message = cipher_rsa.decrypt(ciphertext, sentinel)
   return message

def Oracle(ciphertext):
        try:
                message = Decrypt(ciphertext, private_key)
                if message == "Error": return False
                else: return True
        except: return False