from ufastrsa.srandom import rndsrcnz
from ufastrsa.genprime import pow3
import ustruct as struct
import ubinascii as binascii


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

        # Keep these functions as inner functions to avoid polluting the namespace
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
            # Compute the byte length of the integer manually
            value_bytes = []
            while value > 0:
                value_bytes.insert(0, value & 0xFF)
                value >>= 8
            value_bytes = bytes(value_bytes)
            # Add a zero-byte if the most significant bit is set (to ensure positive integer)
            if len(value_bytes) > 0 and value_bytes[0] & 0x80:
                value_bytes = b"\x00" + value_bytes
            return b"\x02" + encode_length(len(value_bytes)) + value_bytes

        # Encode modulus (n) and exponent (e) as SEQUENCE
        modulus = encode_integer(self.n)
        exponent = encode_integer(self.e)
        sequence = b"\x30" + encode_length(len(modulus) + len(exponent)) + modulus + exponent

        # Wrap in BIT STRING and algorithm identifier SEQUENCE
        algorithm_identifier = b"\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00"  # rsaEncryption OID
        public_key_bitstring = b"\x03" + encode_length(len(sequence) + 1) + b"\x00" + sequence
        public_key_sequence = b"\x30" + encode_length(len(algorithm_identifier) + len(public_key_bitstring)) + algorithm_identifier + public_key_bitstring

        return public_key_sequence