from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import os

KEY_FILE = "rsa_keypair.pem"

# =====================================
# LOAD or GENERATE RSA KEY (PERSISTENT)
# =====================================
def npm_20221310083_load_or_generate_key():
    if os.path.exists(KEY_FILE):
        # LOAD KEY
        with open(KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        public_key = private_key.public_key()
    else:
        # GENERATE KEY
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # SAVE KEY
        with open(KEY_FILE, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    return private_key, public_key


# =====================================
# HASH MESSAGE (SHA-256)
# =====================================
def npm_20221310083_hash_message(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    return digest.finalize()


# =====================================
# DIGITAL SIGNATURE (PRIVATE KEY)
# =====================================
def npm_20221310083_sign_message(private_key, message):
    message_hash = npm_20221310083_hash_message(message)
    signature = private_key.sign(
        message_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


# =====================================
# VERIFY SIGNATURE (PUBLIC KEY)
# =====================================
def npm_20221310083_verify_signature(public_key, message, signature):
    try:
        signature = base64.b64decode(signature)
        message_hash = npm_20221310083_hash_message(message)
        public_key.verify(
            signature,
            message_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False
