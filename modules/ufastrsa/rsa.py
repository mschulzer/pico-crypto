from ufastrsa.srandom import rndsrcnz
from ufastrsa.genprime import pow3
import ustruct as struct
import ubinascii as binascii
import ure as re


class RSA:
    # Constructor - initialize RSA object with key components
    def __init__(self, bits, n=None, e=None, d=None):
        self.bits = bits
        self.bytes = (bits + 7) >> 3
        self.n = n
        self.e = e
        self.d = d
        self.rndsrcnz = rndsrcnz

    def pkcs_encrypt(self, value):
        len_padding = self.bytes - 3 - len(value)
        if len_padding < 0:
            raise ValueError("Padding length must be non-negative")
        base = int.from_bytes(
            b"\x00\x02" + self.rndsrcnz(len_padding) + b"\x00" + value, "big"
        )
        return int.to_bytes(pow3(base, self.e, self.n), self.bytes, "big")

    def pkcs_decrypt(self, value):
        if len(value) != self.bytes:
            raise ValueError(f"Value length must be exactly {self.bytes}, but got {len(value)}")
        decrypted = int.to_bytes(
            pow3(int.from_bytes(value, "big"), self.d, self.n), self.bytes, "big"
        )
        idx = decrypted.find(b"\0", 2)
        assert idx != -1 and decrypted[:2] == b"\x00\x02"
        return decrypted[idx + 1 :]

    def public_key_to_pem(self):
        if self.n is None or self.e is None:
            raise ValueError("Public key components (n, e) are not set.")

        rsa_public_key_der = self._encode_asn1_public_key()

        # Base64 encode
        pem_body = binascii.b2a_base64(rsa_public_key_der).decode("ascii").strip()
        pem_formatted = (
            "-----BEGIN PUBLIC KEY-----\n"
            + "\n".join(pem_body[i:i+64] for i in range(0, len(pem_body), 64))
            + "\n-----END PUBLIC KEY-----"
        )
        return pem_formatted

    # Manually encode the public key (n, e) into ASN.1 DER format.
    def _encode_asn1_public_key(self):
        def encode_length(length):
            if length < 0x80:
                return struct.pack("B", length)
            elif length < 0x100:
                return b"\x81" + struct.pack("B", length)
            elif length < 0x10000:
                return b"\x82" + struct.pack(">H", length)
            else:
                raise ValueError("Length too long to encode.")

        def encode_integer(value):
            value_bytes = []
            while value > 0:
                value_bytes.insert(0, value & 0xFF)
                value >>= 8
            value_bytes = bytes(value_bytes)
            if len(value_bytes) > 0 and value_bytes[0] & 0x80:
                value_bytes = b"\x00" + value_bytes
            return b"\x02" + encode_length(len(value_bytes)) + value_bytes

        modulus = encode_integer(self.n)
        exponent = encode_integer(self.e)
        sequence = b"\x30" + encode_length(len(modulus) + len(exponent)) + modulus + exponent

        algorithm_identifier = b"\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00"
        public_key_bitstring = b"\x03" + encode_length(len(sequence) + 1) + b"\x00" + sequence
        public_key_sequence = b"\x30" + encode_length(len(algorithm_identifier) + len(public_key_bitstring)) + algorithm_identifier + public_key_bitstring

        return public_key_sequence

    @classmethod
    def import_public_key_from_pem(cls, pem_data):
        """
        Imports a PEM-encoded RSA public key, extracts modulus (n) and exponent (e),
        and returns an RSA object initialized with these values.
        """

        pem_data = re.sub(r"-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s", "", pem_data)

        # Decode from Base64
        der_data = binascii.a2b_base64(pem_data)

        # Function to parse ASN.1 structure
        def parse_asn1(data):
            """ Extracts modulus and exponent from ASN.1 sequence. """
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

            if data[0] != 0x30:
                raise ValueError("Invalid ASN.1 format: Expected SEQUENCE.")

            _, offset = read_length(data, 1)  # Skip length

            # Algorithm Identifier (rsaEncryption OID: 1.2.840.113549.1.1.1)
            if data[offset:offset+15] != b"\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00":
                raise ValueError("Invalid RSA key format.")

            offset += 15  # Skip Algorithm Identifier

            if data[offset] != 0x03:
                raise ValueError("Invalid ASN.1 format: Expected BIT STRING.")

            _, offset = read_length(data, offset + 1)
            offset += 1  # Skip unused bits indicator

            if data[offset] != 0x30:
                raise ValueError("Invalid ASN.1 format: Expected nested SEQUENCE.")

            _, offset = read_length(data, offset + 1)

            # Extract modulus (n)
            modulus, offset = read_integer(data, offset)

            # Extract exponent (e)
            exponent, offset = read_integer(data, offset)

            return modulus, exponent

        # Extract key components
        n, e = parse_asn1(der_data)

        # Return an RSA object with the public key initialized
        return cls(bits=512, n=n, e=e)

