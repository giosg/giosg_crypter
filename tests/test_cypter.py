from unittest import TestCase
from giosg.crypter import (
    symmetric_encrypt, symmetric_decrypt,
    asymmetric_encrypt, asymmetric_decrypt)
from giosg.crypter import AESKey
from Cryptodome.PublicKey import RSA


class CrypterTest(TestCase):

    def setUp(self):
        self.plaintext = "The Line is Open!"

    def test_encrypt_and_decrypt(self):
        key = AESKey.generate(key_size=256)

        crypted = symmetric_encrypt(key, self.plaintext)
        self.assertNotIn(self.plaintext, crypted)
        self.assertNotEqual(len(self.plaintext), len(crypted))

        decrypted = symmetric_decrypt(key, crypted)
        self.assertEqual(self.plaintext, decrypted)

    def test_encrypt_and_decrypt_with_bytes(self):
        key = AESKey.generate(key_size=256)

        crypted = symmetric_encrypt(key, self.plaintext.encode('utf-8'))
        self.assertNotIn(self.plaintext, crypted)
        self.assertNotEqual(len(self.plaintext), len(crypted))

        decrypted = symmetric_decrypt(key, crypted.encode('utf-8'))
        self.assertEqual(self.plaintext, decrypted)

    def test_decrypt_is_backwards_compatible(self):
        encrypted = (
            "AJxNkp3ZS9McVTYPDyckR7ub7ri5oIObzl0a45t13owvG8ou"
            "GfAdfZiosw4hxCgc1iYg88v1xZRLFf0/UJr/CcqfCzJjSA4ZWg=="
        )
        key = """{
            "hmacKey": {
                "hmacKeyString": "Wf7oZEWQTpspt0g1ZISN0SNFS21w5DdVOp579RqBg20",
                "size": 256
            },
            "aesKeyString": "dIz4N3wn4V3RfRjyteWRS5_fkXzuo8fFP1ZLMgck_wg",
            "mode": "CBC",
            "size": 256
        }"""
        self.aes_key = AESKey.from_json(key)
        decrypted = symmetric_decrypt(self.aes_key, encrypted)
        self.assertEqual(decrypted, self.plaintext)

    def test_encrypt_rsa(self):
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        plaintext = 'i am an AES key that needs to be encrypted'

        ciphertext = asymmetric_encrypt(public_key, plaintext)
        self.assertNotIn(plaintext, ciphertext)
        self.assertNotEqual(len(plaintext), len(ciphertext))

        decrypted_plaintext = asymmetric_decrypt(private_key, ciphertext)
        self.assertEqual(decrypted_plaintext, plaintext)

    def test_encrypt_rsa_message_with_bytes(self):
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        plaintext = 'i am an AES key that needs to be encrypted'

        ciphertext = asymmetric_encrypt(public_key, plaintext.encode('utf-8'))
        self.assertNotIn(plaintext, ciphertext)
        self.assertNotEqual(len(plaintext), len(ciphertext))

        decrypted_plaintext = asymmetric_decrypt(private_key, ciphertext)
        self.assertEqual(decrypted_plaintext, plaintext)

    def test_encrypt_rsa_key_with_bytes(self):
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key()
        public_key = rsa_key.publickey().export_key()
        plaintext = 'i am an AES key that needs to be encrypted'

        ciphertext = asymmetric_encrypt(public_key, plaintext)
        self.assertNotIn(plaintext, ciphertext)
        self.assertNotEqual(len(plaintext), len(ciphertext))

        decrypted_plaintext = asymmetric_decrypt(private_key, ciphertext)
        self.assertEqual(decrypted_plaintext, plaintext)

    def test_encrypt_rsa_key_with_strings(self):
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key().decode('utf-8')
        public_key = rsa_key.publickey().export_key().decode('utf-8')
        plaintext = 'i am an AES key that needs to be encrypted'

        ciphertext = asymmetric_encrypt(public_key, plaintext)
        self.assertNotIn(plaintext, ciphertext)
        self.assertNotEqual(len(plaintext), len(ciphertext))

        decrypted_plaintext = asymmetric_decrypt(private_key, ciphertext)
        self.assertEqual(decrypted_plaintext, plaintext)
