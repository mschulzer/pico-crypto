#from ufastrsa.genprime import genrsa
from ufastrsa.rsa import RSA, genrsa

# Generate RSA key pair for Person A
key_bits = 1024
private_key_data = genrsa(key_bits)
private_key = RSA(key_bits, **private_key_data)

# Serialize the public key to PEM format
public_key_pem = private_key.public_key_to_pem()

print("Person A's Public Key (PEM):")
print(public_key_pem)