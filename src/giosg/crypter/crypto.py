# -*- coding: utf-8 -*-
# Licensed to the StackStorm, Inc ('StackStorm') under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Module for handling symmetric encryption and decryption of short text values (mostly used for
encrypted datastore values aka secrets).

Symmetric_encrypt and symmetric_decrypt functions use AES in CBC mode
with SHA1 HMAC signature.
"""


import os
import json
import base64

from hashlib import sha1

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


# Crypting/decrypting constants
HEADER_SIZE = 5
AES_BLOCK_SIZE = 16
HLEN = sha1().digest_size

# Minimum key size which can be used for symmetric crypto
MINIMUM_AES_KEY_SIZE = 128
DEFAULT_AES_KEY_SIZE = 256
assert DEFAULT_AES_KEY_SIZE >= MINIMUM_AES_KEY_SIZE


class AESKey(object):
    """
    Class representing AES key object.
    """

    aes_key_string = None
    hmac_key_string = None
    hmac_key_size = None
    mode = None
    size = None

    def __init__(self, aes_key_string, hmac_key_string, hmac_key_size, mode='CBC',
                 size=DEFAULT_AES_KEY_SIZE):
        if mode not in ['CBC']:
            raise ValueError('Unsupported mode: %s' % (mode))

        if size < MINIMUM_AES_KEY_SIZE:
            raise ValueError('Unsafe key size: %s' % (size))

        self.aes_key_string = aes_key_string
        self.hmac_key_string = hmac_key_string
        self.hmac_key_size = int(hmac_key_size)
        self.mode = mode.upper()
        self.size = int(size)

        # We also store bytes version of the key since bytes are needed by encrypt and decrypt
        self.hmac_key_bytes = Base64WS.decode(self.hmac_key_string)
        self.aes_key_bytes = Base64WS.decode(self.aes_key_string)

    @classmethod
    def generate(self, key_size=DEFAULT_AES_KEY_SIZE):
        """
        Generate a new AES key with the corresponding HMAC key.

        :rtype: :class:`AESKey`
        """
        if key_size < MINIMUM_AES_KEY_SIZE:
            raise ValueError('Unsafe key size: %s' % (key_size))

        aes_key_bytes = os.urandom(int(key_size / 8))
        aes_key_string = Base64WS.encode(aes_key_bytes)

        hmac_key_bytes = os.urandom(int(key_size / 8))
        hmac_key_string = Base64WS.encode(hmac_key_bytes)

        return AESKey(aes_key_string=aes_key_string, hmac_key_string=hmac_key_string,
                      hmac_key_size=key_size, mode='CBC', size=key_size)

    def to_json(self):
        """
        Return JSON representation of this key.

        :rtype: ``str``
        """
        data = {
            'hmacKey': {
                'hmacKeyString': self.hmac_key_string,
                'size': self.hmac_key_size
            },
            'aesKeyString': self.aes_key_string,
            'mode': self.mode.upper(),
            'size': int(self.size)
        }
        return json.dumps(data)

    @classmethod
    def from_json(self, aes_key_json):
        """
        Read crypto key from JSON key file format and return parsed AESKey object.

        :param aes_key_json: Crypto key in JSON format.
        :type aes_key_json: ``json``

        :rtype: :class:`AESKey`
        """
        content = json.loads(aes_key_json)

        try:
            aes_key = AESKey(aes_key_string=content['aesKeyString'],
                             hmac_key_string=content['hmacKey']['hmacKeyString'],
                             hmac_key_size=content['hmacKey']['size'],
                             mode=content['mode'].upper(),
                             size=content['size'])
        except KeyError as e:
            msg = 'Invalid or malformed key "%s": %s' % (aes_key_json, str(e))
            raise KeyError(msg)

        return aes_key

    def __repr__(self):
        return ('<AESKey hmac_key_size=%s,mode=%s,size=%s>' % (self.hmac_key_size, self.mode,
                                                               self.size))


class CryptographySymmetric(object):

    def __init__(self, key):
        assert isinstance(key, AESKey), 'encrypt_key needs to be AESKey class instance'
        assert isinstance(key.aes_key_bytes, bytes)
        assert isinstance(key.hmac_key_bytes, bytes)
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext):
        """
        Encrypt the provided plaintext using AES encryption.

        NOTE: This function is loosely based on keyczar AESKey.Encrypt() (Apache 2.0 license).

        The final encrypted string value consists of:

        [message bytes][HMAC signature bytes for the message] where message consists of
        [header plaintext][IV bytes][ciphertext bytes]

        :rtype: ``str``
        """
        ascii_plaintext = encode_if_not_bytes(plaintext)
        encoded = self.encrypt_bytes(ascii_plaintext)
        return base64.encodebytes(encoded).decode("utf-8")

    def encrypt_bytes(self, plaintext):
        """
        :rtype: ``bytes``
        """
        assert isinstance(plaintext, (str, bytes)), \
            'plaintext needs to either be a string/unicode or bytes'

        data = self._pkcs5_pad(plaintext)
        header_bytes = b'00000'
        iv_bytes = os.urandom(AES_BLOCK_SIZE)

        ciphertext_bytes = self._encrypt_ciphertext(iv_bytes, data)
        msg_bytes = header_bytes + iv_bytes + ciphertext_bytes

        return self._sign(msg_bytes)

    def _encrypt_ciphertext(self, iv_bytes, data):
        """
        AES encrypt using CBC mode.
        """
        cipher = Cipher(algorithms.AES(self.key.aes_key_bytes), modes.CBC(iv_bytes), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def _sign(self, msg_bytes):
        """
        SHA1 HMAC signature.
        """
        h = hmac.HMAC(self.key.hmac_key_bytes, hashes.SHA1(), backend=self.backend)
        h.update(msg_bytes)
        return msg_bytes + h.finalize()

    def _pkcs5_pad(self, data):
        """
        Pad data using PKCS5
        """
        data = encode_if_not_bytes(data)
        pad = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        data = data + pad * encode_if_not_bytes(chr(pad))
        return data

    def decrypt(self, ciphertext):
        """
        Decrypt the provided ciphertext which has been encrypted using encrypt() method (it
        assumes input is in hex notation as returned by binascii.hexlify).

        NOTE: This function is loosely based on keyczar AESKey.Decrypt() (Apache 2.0 license).

        :rtype: ``str``
        """
        ascii_ciphertext = encode_if_not_bytes(ciphertext)
        byte_ciphertext = base64.decodebytes(ascii_ciphertext)
        return self.decrypt_bytes(byte_ciphertext).decode('utf-8')

    def decrypt_bytes(self, ciphertext):
        """
        :rtype: ``bytes``
        """
        assert isinstance(ciphertext, (str, bytes)), \
            'ciphertext needs to either be a string/unicode or bytes'

        data_bytes = ciphertext[HEADER_SIZE:]

        # Verify ciphertext contains IV + HMAC signature
        if len(data_bytes) < (AES_BLOCK_SIZE + HLEN):
            raise ValueError('Invalid or malformed ciphertext (too short)')

        iv_bytes = data_bytes[:AES_BLOCK_SIZE]
        ciphertext_bytes = data_bytes[AES_BLOCK_SIZE:-HLEN]
        signature_bytes = data_bytes[-HLEN:]

        self._verify_signature(ciphertext, signature_bytes)
        decrypted = self._decrypt_ciphertext(iv_bytes, ciphertext_bytes)
        return self._pkcs5_unpad(decrypted)

    def _decrypt_ciphertext(self, iv_bytes, ciphertext_bytes):
        """
        AES decrypt using CDC mode.
        """
        cipher = Cipher(algorithms.AES(self.key.aes_key_bytes), modes.CBC(iv_bytes), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext_bytes) + decryptor.finalize()

    def _verify_signature(self, ciphertext, signature_bytes):
        """
        Verify SHA1 HMAC signature.
        """
        h = hmac.HMAC(self.key.hmac_key_bytes, hashes.SHA1(), backend=self.backend)
        h.update(ciphertext[:-HLEN])
        h.verify(signature_bytes)

    def _pkcs5_unpad(self, data):
        """
        Unpad data padded using PKCS5.
        """
        pad = data[-1]
        data = data[:-pad]
        return data


class CryptographyAsymmetric(object):

    def __init__(self, rsa_key):
        if isinstance(rsa_key, RSA.RsaKey):
            self.key = rsa_key
        elif isinstance(rsa_key, (str, bytes)):
            try:
                self.key = RSA.import_key(rsa_key)
            except ValueError:
                raise ValueError('key needs to be RSA key class instance or a string in valid RSA format')

    def encrypt(self, plaintext):
        '''
        Encrypts plaintext using an RSA public key. Encryption uses PKCS#1 OAEP protocol.
        Returns base64 encoded ciphertext bytes.

        @rtype: string
        '''
        cipher = PKCS1_OAEP.new(self.key)
        encrypted = cipher.encrypt(encode_if_not_bytes(plaintext))
        return base64.encodebytes(encrypted).decode('utf-8')

    def decrypt(self, ciphertext):
        """
        Decrypts ciphertext using an RSA private key. Encryption uses PKCS#1 OAEP protocol.

        @rtype: string
        """
        cipher_bytes = base64.decodebytes(encode_if_not_bytes(ciphertext))
        c = PKCS1_OAEP.new(self.key)
        return c.decrypt(cipher_bytes).decode('utf-8')


class Base64WS(object):
    """
    NOTE: Based on keyczar (Apache 2.0 license)
    """

    @classmethod
    def encode(self, s):
        """
        Return Base64 web safe encoding of s. Suppress padding characters (=).

        Uses URL-safe alphabet: - replaces +, _ replaces /. Will convert s of type
        unicode to string type first.

        @param s: string to encode as Base64
        @type s: string

        @return: Base64 representation of s.
        @rtype: string
        """
        s = encode_if_not_bytes(s)
        return base64.urlsafe_b64encode(s).decode('utf-8').replace("=", "")

    @classmethod
    def decode(self, s):
        """
        Return decoded version of given Base64 string. Ignore whitespace.

        Uses URL-safe alphabet: - replaces +, _ replaces /. Will convert s of type
        unicode to string type first.

        @param s: Base64 string to decode
        @type s: string

        @return: original string that was encoded as Base64
        @rtype: string

        @raise Base64DecodingError: If length of string (ignoring whitespace) is one
        more than a multiple of four.
        """
        s = ''.join(s.splitlines())
        s = str(s.replace(" ", ""))  # kill whitespace, make string (not unicode)
        d = len(s) % 4

        if d == 1:
            raise ValueError('Base64 decoding errors')
        elif d == 2:
            s += "=="
        elif d == 3:
            s += "="

        try:
            return base64.urlsafe_b64decode(s)
        except TypeError as e:
            # Decoding raises TypeError if s contains invalid characters.
            raise ValueError('Base64 decoding error: %s' % (str(e)))


def encode_if_not_bytes(text):
    if isinstance(text, str):
        text = text.encode('utf-8')
    return text
