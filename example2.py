import ubinascii as binascii
import ure as re
import ustruct as struct


def import_public_key_from_pem(pem_data):
    """
    Indlæser en PEM-encoded RSA offentlig nøgle - og ekstraherer modulus (n) og eksponent (e).
    Returnerer et RSA-object initialiseret med førnævnte værdier.
    """

    pem_data = re.sub(r"-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s", "", pem_data)

    # Decode fra Base64
    der_data = binascii.a2b_base64(pem_data)

    # Funktion til at parse ASN.1-structuren
    def parse_asn1(data):
        """ Ekstraherer modulus og eksponent fra ASN.1-sekvensen. """
        def read_length(data, offset):
            length = data[offset]
            offset += 1
            if length & 0x80:
                num_bytes = length & 0x7F
                length = int.from_bytes(data[offset:offset+num_bytes], "big")
                offset += num_bytes
            return length, offset

        def read_integer(data, offset):
            """ ASN.1 INTEGER. """
            if data[offset] != 0x02:
                raise ValueError("ASN.1 format error: Expected INTEGER tag.")
            length, offset = read_length(data, offset + 1)
            value = int.from_bytes(data[offset:offset+length], "big")
            offset += length
            return value, offset

        # Sørg for, at vi har en ASN.1 SEQUENCE (0x30)
        if data[0] != 0x30:
            raise ValueError("Invalid ASN.1 format: Expected SEQUENCE.")

        _, offset = read_length(data, 1)  # Skip længde

        # Algorithm Identifier (rsaEncryption OID: 1.2.840.113549.1.1.1)
        if data[offset:offset+15] != b"\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00":
            raise ValueError("Invalid RSA key format.")

        offset += 15  # Læs forbi Algorithm Identifier

        # Sørg for, at en BIT STRING (0x03) følger
        if data[offset] != 0x03:
            raise ValueError("Invalid ASN.1 format: Expected BIT STRING.")

        _, offset = read_length(data, offset + 1)
        offset += 1  # Skip unused bits indicator

        # Parse den egentlige RSA-nøgle (modulus og eksponent)
        if data[offset] != 0x30:
            raise ValueError("Invalid ASN.1 format: Expected nested SEQUENCE.")

        _, offset = read_length(data, offset + 1)  # Skip længde

        # modulus (n)
        modulus, offset = read_integer(data, offset)

        # eksponent (e)
        exponent, offset = read_integer(data, offset)

        return modulus, exponent

    # Ekstraher nøgle-komponenter
    n, e = parse_asn1(der_data)

    # Returner RSA-objekt med den offentlige nøgle initialiseret
    return RSA(bits=n.bit_length(), n=n, e=e)


# Eksempel på brug:
pem_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArFQ7VqjOEtZJ4zdm3QKZ
R+zJ+huLT1M5Uq/TvhCjBWl2Us3Fz9n9pN35F2t49fuwnAklLSuL3ThPqD+qB8Ft
3fE2q3L8pA+tCdl4Kn5rV9n2T3sK9YrP06rMuSw7O7Z+vGnP0NLBwlU6DeeZ2+d7
2p28FqHaUcsWY+AGIuAAmelZ1Ry+JW1xDmuFVoMBBZBwWQGwnMCGF1L8IW2YNhO1
oRoAXKH7+IbmCM4ZR7VDA+eZilob0b6Bgyf9v+3yT2y+9oDBk4Pxr0egNU5tcmzF
AkDNkPWhq8uC5ZXm1eVpWNRwlXjse87UJlzHHEPKcGF57IefvY+VtAW7cm2gUbSz
wQIDAQAB
-----END PUBLIC KEY-----
"""

rsa_obj = import_public_key_from_pem(pem_key)

print("Modulus (n):", rsa_obj.n)
print("Exponent (e):", rsa_obj.e)
