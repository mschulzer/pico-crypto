from ufastrsa.genprime import genrsa
from ufastrsa.rsa import RSA

# Generate RSA key pair for Person A
key_bits = 1024
#_, n, e, d = genrsa(key_bits)
#private_key = RSA(key_bits, n=n, e=e, d=d)

private_key = RSA(*genrsa(key_bits, e=65537))

# Serialize the public key to PEM format
public_key_pem = private_key.public_key_to_pem()

print("Person A's Public Key (PEM):")
print(public_key_pem)