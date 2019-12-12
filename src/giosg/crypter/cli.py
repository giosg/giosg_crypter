import subprocess
import json
import argparse
from . import AESKey, asymmetric_decrypt, symmetric_decrypt


class DecryptChatSession(object):

    def __init__(self, private_key):
        self.private_key = private_key

    def decrypt(self, chat_session, messages):
        # Chat session API contains three encryption specific fields:
        # is_encrypted is a self-explanatory boolean value
        # encrypted_aes_key contains the RSA encrypted AES key required to decrypt chat logs
        # public_key contains the RSA public_key used in encrypting the AES key, useful in determining
        # which private key to use
        if chat_session['is_encrypted']:
            # This is the AES key encrypted with customer's RSA public key
            encrypted_key = chat_session['encrypted_symmetric_key']

            # Decrypt the stored AES key with RSA private key
            aes_key = asymmetric_decrypt(self.private_key, encrypted_key)

            # Use AesKey class to do the AES magic
            key = AESKey.from_json(aes_key)

            for message in messages:
                if message['message']:
                    message['message'] = symmetric_decrypt(key, message['message'])

        return messages


class CommandLine(object):
    def __init__(self):
        self.parser = argparse.ArgumentParser(usage='decrypt key chat messages',
                                              description='Decrypt Giosg chat.')
        self.parser.add_argument('private_key', metavar='key', type=str,
                                 help='path to the private key file')
        self.parser.add_argument('chat_session', metavar='chat', type=str,
                                 help='path to chat session json file')
        self.parser.add_argument('messages', metavar='messages', type=str,
                                 help='path to chat sessions messages json file')

    def arguments(self):
        return self.parser.parse_args()


class Client(object):

    def __init__(self, args):
        self.private_key = args.private_key
        self.chat_session = args.chat_session
        self.messages = args.messages

    def run(self):
        private_key = subprocess.check_output(['openssl', 'rsa', '-in', self.private_key])
        with open(self.chat_session, 'r') as f:
            chat_session = json.loads(f.read())

        with open(self.messages, 'r') as f:
            messages = json.loads(f.read())

        print(DecryptChatSession(private_key).decrypt(chat_session, messages))


def run():
    Client(CommandLine().arguments()).run()
