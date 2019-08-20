from rsa import GenerateKeys, Encrypt

# Choose bits (1024, 2048, ...)
bits = 2048
# Generate Keys
private_key, public_key = GenerateKeys(bits)

# Initial Message
message = "AES Session Key = 1234567890ABCDEF"
encoded = "AES Session Key = 1234567890ABCDEF".encode("utf-8")

# Encrypt Message
ciphertext = Encrypt(encoded, public_key)

# Attack 
stolen_message = Bleichenbacher(ciphertext, public_key)
print("\nBleichenbacher Stolen Message = ", stolen_message)
print("\nOriginal Message = ", message)
print("\nStolen Message == Original Message:",  message == stolen_message)
        
        
                


