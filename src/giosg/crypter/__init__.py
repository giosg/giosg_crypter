from .crypto import CryptographySymmetric, CryptographyAsymmetric, AESKey  # noqa


def symmetric_encrypt(encrypt_key, plaintext):
    return CryptographySymmetric(encrypt_key).encrypt(plaintext)


def symmetric_decrypt(decrypt_key, ciphertext):
    return CryptographySymmetric(decrypt_key).decrypt(ciphertext)


def asymmetric_encrypt(public_key, plaintext):
    return CryptographyAsymmetric(public_key).encrypt(plaintext)


def asymmetric_decrypt(private_key, ciphertext):
    return CryptographyAsymmetric(private_key).decrypt(ciphertext)
