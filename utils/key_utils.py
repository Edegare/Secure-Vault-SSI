from cryptography.hazmat.primitives import serialization


def pubkey_bytes(pubkey):
    return pubkey.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
