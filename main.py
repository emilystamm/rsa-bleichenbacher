from rsa import RSA_Cipher
from attack import Bleichenbacher

if __name__ == "__main__":
        # Initial Message
        message = "AES Session Key = 1234567890ABCDEF"
        encoded = "AES Session Key = 1234567890ABCDEF".encode("utf-8")   
        # Create RSA Cipher
        bits = 2048 # Choose bits (1024, 2048, ...)
        RSA_Cipher = RSA_Cipher(bits) 
        # Encryption 
        ciphertext = RSA_Cipher.Encrypt(encoded)        
        # Attack 
        stolen_message = Bleichenbacher(ciphertext, RSA_Cipher)
        print("\nBleichenbacher Stolen Message:", stolen_message)
        print("\nOriginal Message:", message)
        print("\nStolen Message == Original Message:",  message == stolen_message)




