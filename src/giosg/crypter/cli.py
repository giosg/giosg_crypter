import subprocess
import json
import argparse
import pprint

import requests

from ._version import get_version
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
                if message['encrypted_message']:
                    message['message'] = symmetric_decrypt(key, message['encrypted_message'])

        return messages


class CommandLine(object):
    def __init__(self):
        self.parser = argparse.ArgumentParser(usage='decrypt key chat [-m --messages]',
                                              description='Decrypt Giosg chat.')
        self.parser.add_argument(
            'private_key',
            metavar='key',
            type=str,
            help='path to the private key file'
        )
        self.parser.add_argument(
            'chat_session',
            metavar='chat',
            type=str,
            help='path to chat session json file or url of the resource'
        )
        self.parser.add_argument(
            '-m',
            '--messages',
            type=str,
            help='path to chat sessions messages json file. Required if chat_session is file path'
        )
        self.parser.add_argument(
            "-v",
            "--version",
            action="version",
            version="%(prog)s " + get_version()
        )
        self.parser.add_argument(
            "-o",
            "--output",
            choices=['file', 'stdout'],
            default='file',
            help='How the results are returned: file or stdout. Defaults to file.'
        )
        self.parser.add_argument(
            "-f",
            "--filename",
            type=str,
            default='decrypted_messages.json',
            help='Name of the file, where output is written. Defaults to decrypted_messages.json'
        )
        self.parser.add_argument(
            "-t",
            "--token",
            help='If chat_session is a url resource, token for accessing giosg resources is required.'
        )

    def arguments(self):
        return self.parser.parse_args()


class Input(object):
    def __init__(self, args):
        if args.chat_session[:4] == 'http':
            self._reader = UrlInputReader(args)
        else:
            self._reader = FileInputReader(args)

    def reader(self):
        return self._reader


class InputReader(object):
    def __init__(self, args):
        self.private_key = args.private_key
        self.chat_session = args.chat_session

    def read_private_key(self):
        return subprocess.check_output(['openssl', 'rsa', '-in', self.private_key])


class FileInputReader(InputReader):
    def __init__(self, args):
        super().__init__(args)
        self.messages = args.messages

    def read_chat_session(self):
        with open(self.chat_session, 'r') as f:
            return json.loads(f.read())

    def read_messages(self):
        with open(self.messages, 'r') as f:
            return json.loads(f.read())


class UrlInputReader(InputReader):
    def __init__(self, args):
        super().__init__(args)
        self.token = args.token

    def read_chat_session(self):
        return self._get_response(self.chat_session)

    def read_messages(self):
        path = "messages" if self.chat_session[-1] == "/" else "/messages"
        return self._get_response(self.chat_session + path)["results"]

    def _get_response(self, url):
        print("Fetching:", url)
        response = requests.get(url, headers={"Authorization": "Token %s" % self.token})
        response.raise_for_status()
        return json.loads(response.content)


class OutputWriter(object):

    def __init__(self, args):
        self.output_type = args.output
        self.filename = args.filename

    def write_output(self, output):
        if self.output_type == 'file':
            self._write_file(output)
        else:
            pprint.pprint(output)

    def _write_file(self, output):
        with open(self.filename, 'w') as f:
            f.write(json.dumps(output, indent=4))


class Client(object):

    def __init__(self, input_reader, output_writer):
        self.output_writer = output_writer
        self.private_key = input_reader.read_private_key()
        self.chat_session = input_reader.read_chat_session()
        self.messages = input_reader.read_messages()

    def run(self):
        self.output_writer.write_output(DecryptChatSession(self.private_key).decrypt(self.chat_session, self.messages))


def run():
    cmd_line_args = CommandLine().arguments()
    inputs = Input(cmd_line_args).reader()
    outputs = OutputWriter(cmd_line_args)
    Client(inputs, outputs).run()
