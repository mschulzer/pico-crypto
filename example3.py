from ufastrsa.genprime import genrsa
from ufastrsa.rsa import RSA
import ubinascii as binascii

other_pem_data = """
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ0FAmVO1bzjKtuO6yHXE0AYneulHfUH
0mSdO90j89syZLRmCH4EeEHNN2U47mzCUJK4wy6cxuCXk008+budFkECAwEAAQ==
-----END PUBLIC KEY-----
"""


# Egen PEM
bits = 512
r = RSA(*genrsa(bits, e=65537))
my_pem = r.public_key_to_pem()
print(my_pem)


# Import the public key into RSA
other_person_rsa = r.import_public_key_from_pem(my_pem)

# Encrypt a message
message = b"Hello, RSA!"

encrypted_message = other_person_rsa.pkcs_encrypt(message)
encrypted_message_encoded = binascii.b2a_base64(encrypted_message).decode().strip()
print("Encrypted:", encrypted_message_encoded)

decrypted_message_decoded = r.pkcs_decrypt(binascii.a2b_base64(encrypted_message_encoded))
print("Decrypted:", decrypted_message_decoded.decode('utf8'))
