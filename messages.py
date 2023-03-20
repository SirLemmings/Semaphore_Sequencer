import ecdsa
import params as pm
from wrappers import Sig


def concatenate_bytes(*args: bytes) -> bytes:
    """given a list of bytes, concatenate them into a single byte string"""
    message = b""
    for content in args:
        if type(content) != bytes:
            raise Exception("Invalid content type", type(content))
        message += content
    return message


def format_message(message_type: bytes, *args: bytes) -> bytes:
    """given a message type and list of contents, generate a message"""
    message = message_type
    message += concatenate_bytes(*args)
    message_header = len(message).to_bytes(pm.HEADER_LENGTH, "big")
    return message_header + message


def calc_data_signature(
    private_key: ecdsa.SigningKey | bytes, *args: bytes) -> bytes:
    """given a private key and list of contents, generate a signature"""
    if type(private_key) == bytes:
        private_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    message = concatenate_bytes(*args)
    signature = private_key.sign(message)#type: ignore
    return signature


def verify_data_signature(
    public_key: ecdsa.VerifyingKey | bytes, signature: Sig, *args: bytes) -> bool:
    """given a public key, signature, and list of contents, verify the signature"""
    if type(public_key) == bytes:
        public_key = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    message = concatenate_bytes(*args)
    try:
        public_key.verify(bytes(signature), message)#type: ignore
        return True
    except:
        return False
