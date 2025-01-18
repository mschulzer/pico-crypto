from ufastrsa.rsa import RSA, genrsa

"""
    The RSA-process:
    ----------------
    1. Generate two large prime numbers, p and q.
    2. Compute n = p*q.
    3. Compute the totient of n, φ(n) = (p-1)(q-1).
    4. Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1; i.e., e and φ(n) are coprime.
"""

bits = 1024
r = RSA(*genrsa(bits, e=65537))

if r:
    print("RSA OK")

    # DISPLAY PEM
    my_pem = r.public_key_to_pem()
    print(my_pem)
    
    data = b"her er en lille besked"

    # VERIFY AND SIGN
    assert r.pkcs_verify(r.pkcs_sign(data)) == data
    print("pkcs_verify OK")
    print(r.pkcs_sign(data))
    
    # DECRYPT
    assert r.pkcs_decrypt(r.pkcs_encrypt(data)) == data
    print("pkcs_decrypt OK")
