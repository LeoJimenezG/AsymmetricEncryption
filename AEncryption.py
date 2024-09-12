from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey


class AsymmetricEncryption:
    def __init__(self):
        # Set the size of the key (2048 bits or 256 bytes)
        self.size: int = 2048
        # Generate the private key (decrypt) using the RSA (Rivest Shamir Adleman) algorithm
        self.private_key: RSAPrivateKey = rsa.generate_private_key(key_size=self.size, public_exponent=65537)
        # Generate the public key (encrypt) using the generated private key
        self.public_key: RSAPublicKey = self.private_key.public_key()

    def asymmetric_encrypt(self, message: bytes):
        # Encrypt the message using the public key
        encrypted_message: bytes = self.public_key.encrypt(
            message,
            padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        # Return the encrypted message
        return encrypted_message

    def asymmetric_decrypt(self, message: bytes):
        try:
            # Decrypt the message using the private key
            decrypted_message: bytes = self.private_key.decrypt(
                message,
                padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            # Return the decrypted message
            return decrypted_message
        # If the decryption process is not successful
        except ValueError:
            # Return an error message
            return "Decryption failed!"
