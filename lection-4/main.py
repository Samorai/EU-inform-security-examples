from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def generate_keys():
    # Generate a pair of RSA keys (private and public)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key):
    # Sign the message using the private key
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    try:
        # Verify the signature using the public key
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        # Print the exception if verification fails
        print(f"Verification failed: {e}")
        return False

# Demonstration
private_key, public_key = generate_keys()
message = "Цей документ підписаний електронним підписом"
signature = sign_message(message, private_key)
is_valid = verify_signature(message, signature, public_key)

print(f"Підпис валідний: {is_valid}")
