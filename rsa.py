from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

class RSA_Cipher:
   def __init__(self, bits):
      self.bits = bits
      self.private_key = RSA.generate(bits)
      self.public_key = self.private_key.publickey()
   
   def PublicKey(self):
      return self.public_key
   
   def Bits(self):
      return self.bits
   
   def Encrypt(self, message):
      cipher_rsa = PKCS1_v1_5.new(self.public_key) 
      ciphertext = cipher_rsa.encrypt(message)
      return ciphertext

   def Oracle(self, ciphertext):
      try:
         sentinel = "Error"  
         cipher_rsa = PKCS1_v1_5.new(self.private_key)
         message = cipher_rsa.decrypt(ciphertext, sentinel)
         if message == "Error": return False
         else: return True
      except: return False
