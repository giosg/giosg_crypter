import subprocess
import json
import argparse
from . import AESKey, asymmetric_decrypt, symmetric_decrypt


class DecryptChatSession(object):

    def __init__(self, private_key):
        self.private_key = private_key

    def decrypt(self, chat_session):
        # Chat session API contains three encryption specific fields:
        # is_encrypted is a self-explanatory boolean value
        # encrypted_aes_key contains the RSA encrypted AES key required to decrypt chat logs
        # public_key contains the RSA public_key used in encrypting the AES key, useful in determining
        # which private key to use
        if chat_session['is_encrypted']:
            # This is the AES key encrypted with customer's RSA public key
            encrypted_key = chat_session['encrypted_aes_key']

            # Decrypt the stored AES key with RSA private key
            aes_key = asymmetric_decrypt(self.private_key, encrypted_key)

            # Use AesKey class to do the AES magic
            key = AESKey.from_json(aes_key)

            for log in chat_session['logs']:
                log['msg'] = symmetric_decrypt(key, log['msg'])

            # Now the logs in chat_session should be plaintext

            # Let's do the same to API data
            if chat_session['api_data']:

                # Key used in encrypting API data is different from the key used in encrypting conversation
                # but the functionality is identical

                # Let's dig the AES key from the API data, it is saved same way as any other API data parameter
                encrypted_key = None
                for data in chat_session['api_data']:
                    if data['name'] == '_encrypted_aes_key':
                        encrypted_key = data['value']

                # Naturally the decryption requires that the key was found
                if encrypted_key is not None:
                    aes_key = asymmetric_decrypt(self.private_key, encrypted_key)
                    key = AESKey.from_json(aes_key)

                    for data in chat_session['api_data']:
                        if data['name'] != '_encrypted_aes_key':
                            data['value'] = symmetric_decrypt(key, data['value'])
        return chat_session


class CommandLine(object):
    def __init__(self):
        self.parser = argparse.ArgumentParser(usage='decrypt key chat',
                                              description='Decrypt Giosg chat.')
        self.parser.add_argument('private_key', metavar='key', type=str,
                                 help='path to the private key file')
        self.parser.add_argument('chat_session', metavar='chat', type=str,
                                 help='path to chat session json file')

    def arguments(self):
        return self.parser.parse_args()


class Client(object):

    def __init__(self, args):
        self.private_key = args.private_key
        self.chat_session = args.chat_session

    def run(self):
        private_key = subprocess.check_output(['openssl', 'rsa', '-in', self.private_key])
        with open(self.chat_session, 'r') as f:
            chat_session = json.loads(f.read())

        print(DecryptChatSession(private_key).decrypt(chat_session))


def run():
    Client(CommandLine().arguments()).run()
