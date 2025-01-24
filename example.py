from ufastrsa.genprime import genrsa
from ufastrsa.rsa import RSA

# Generér RSA-nøglepar til Person A
key_bits = 1024
private_key = RSA(*genrsa(key_bits, e=65537))

# Konvertér den offentlige nøgle til PEM-format
public_key_pem = private_key.public_key_to_pem()

print("Person A's Offentlige nøgle (PEM):")
print(public_key_pem)
