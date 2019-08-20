from Crypto.Util.number import bytes_to_long, long_to_bytes
from main import Oracle
import intervals as I
import time

def ceil(a, b): return  a // b + (a % b > 0)
def floor(a,b): return  a // b

# Decode message 
def PKCS1_decode(encoded):
    encoded = encoded[2:]
    idx = encoded.index(b'\x00')
    message = encoded[idx + 1:]
    return message.decode("utf-8") 

# Call oracle with integer c to determine if corresponding plaintext conforms
def CallOracle(c):
    ciphertext = long_to_bytes(c)
    return Oracle(ciphertext)

# Calculate c_i 
def CalculateC_i(c,e,n, lower, upper, calls_to_oracle, Oracle):
    s_i = lower
    c_i = (c * pow(s_i,e,n)) % n
    while not CallOracle(c_i) and s_i <= upper:
        # To keep track of iterations
        if calls_to_oracle % 10000 == 0: print("Calls to Oracle : ", calls_to_oracle)
        calls_to_oracle += 1 
        # Increment s_i
        s_i += 1
        # Calculate the new c_i
        c_i = (c * pow(s_i,e,n)) % n

    if s_i > upper: return 0, calls_to_oracle
    else: return s_i, calls_to_oracle

# Bleichenbacher attack
def Bleichenbacher(ciphertext,public_key):
    # Get number of bits and public key intergers e, n
    pk_str = str(public_key)

    # Initialize variables
    bits = int(pk_str[pk_str.find("(")+1:pk_str.find(")")])
    e = public_key.e
    n = public_key.n
    i = 1
    calls_to_oracle = 0
    start_time = time.time()

    # Compute constant variable B and initial interval M_0 = [a,b]
    B = pow(2, 8 * (bits // 8 - 2))
    a = 2 * B
    b = 3 * B - 1
    M_i_1 = I.closed(a,b)

    # Step 1: Calculate c, s_0
    c = bytes_to_long(ciphertext)
    s_i_1 = 1

    #  Printing
    print("\n\n======================================================\n",
    "Bleichenbacher Attack on RSA PKCS v1.5", 
    "\n======================================================\n",
    "\nPublic Key\ne =", e, "\nn =", n, "  (", bits, "bits )\n\nCiphertext")
    print(ciphertext)
    print("\n\nIteration 0\n---------------------------------------------")
    print("\nStep 1: find ciphertext c in integer form\nc =", c)
    print("\nConfirm Call Oracle on Given Ciphertext:", CallOracle(c))  # Check that CallOracle works 
    print("\nM_0 =", M_i_1)

    # Repeat until you M_i a single interval with one element
    while M_i_1.lower != M_i_1.upper:
        print("\n\nIteration ", i,
        "\n---------------------------------------------")

        # Step 2 : Find s_i 
        # Step 2a: Calculate s_i, smallest int >= n/3B that conforms
        if i == 1: 
            print("\nStep 2a: find smallest s_1 >= n/3B such that plaintext corresponding to c(s_1^e) mod n conforms")
            s_i, calls_to_oracle = CalculateC_i(c, e, n, ceil(n, 3 * B), n-1, calls_to_oracle, Oracle)
            print("s_" + str(i),  " = ", s_i, "\n")

        # Step 2b: If M_i-1 has multiple disjoint intervals,
        # Calculate smallest s_i > s_i_1 that conforms
        elif len(M_i_1) > 1: 
            print("\nStep 2b: find smallest s_i > s_(i-1) such that plaintext corresponding to c(s_i^e) mod n conforms\ns_i_1 = ", s_i_1)
            s_i, calls_to_oracle  = CalculateC_i(c, e, n, s_i_1 + 1, n-1, calls_to_oracle, Oracle) #change to s_i + 1
            print("s_" + str(i),  " = ", s_i, "\n")

        # Step 2c: Number of intervals = 1 -> find s_i
        else:
            print("\nStep 2c: vary integer r_i and s_i until find s_i such that plaintext corresponding to c(s_i^e) mod n conforms")
            a , b = M_i_1.lower , M_i_1.upper
            r_i = ceil(2 * b * s_i_1 - 2 * B, n)
            s_i = 0
            # While s_i corresponding plaintext to c(s_i)^e mod n does not conform
            while s_i == 0:
                lower = ceil(2 * B + r_i * n, b)
                upper = ceil(3 * B + r_i * n, a) - 1
                s_i, calls_to_oracle  = CalculateC_i(c, e, n, lower,  upper, calls_to_oracle, Oracle)
                r_i += 1
            print("s_" + str(i),  " = ", s_i, "\n")

        # Step 3: Reduce M_i_1 to M_i and store
        # Initialize M_i
        print("\nStep 3: after s_i found, reduce set M_(i-1) to M_i")
        M_i = I.empty()
        # For each disjoint interval [a,b] in M_(i-1)
        for interval in M_i_1:
            a , b = interval.lower , interval.upper
            low_r = ceil(a * s_i - 3 * B + 1, n)
            high_r = ceil(b * s_i - 2 * B, n) 
            for r in range(low_r, high_r): 
                i_low = max(a , ceil(2 * B + r * n, s_i))
                i_high = min(b , floor(3 * B - 1 + r * n, s_i))
                M_new = I.closed(i_low, i_high)
                M_i = M_i | M_new
        print("M_" + str(i),  " = ", M_i)
        # Reset variables for next round
        M_i_1 = M_i
        s_i_1 = s_i
        i += 1

    # Step 4: single remaining element (M_i.lower = M_i.upper) * (s_0 ^-1 mod n) 
    print("Calls to Oracle: ", calls_to_oracle)
    print("\nStep 4: M_i.lower = M_i.higher = m, the message in integer form")
    m =  M_i.lower
    print("\nRecovered Message Integer = ", m)
    sbytes = long_to_bytes(m)
    print("\nMessage Converted to Bytes", sbytes)
    message = PKCS1_decode(sbytes)
    elapsed_time = time.time() - start_time
    print("\n---------------------------------------------\nTime Elapsed:", elapsed_time / 60, " minutes\n")
    return message


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