import json
import os
import subprocess
from unittest import TestCase
from giosg.crypter.cli import DecryptChatSession

TESTDATA_FILEPATH = os.path.join(os.path.dirname(__file__), 'fixtures/')


class DecryptChatTest(TestCase):

    def setUp(self):
        self.private_key = subprocess.check_output(['openssl', 'rsa', '-in', TESTDATA_FILEPATH + '/private.pem'])
        with open(TESTDATA_FILEPATH + '/chat.json', 'r') as f:
            self.chat_session = json.loads(f.read())

        with open(TESTDATA_FILEPATH + '/messages.json', 'r') as f:
            self.messages = json.loads(f.read())

    def test_encrypt_and_decrypt(self):
        message1 = DecryptChatSession(self.private_key).decrypt(self.chat_session, self.messages)[0]["message"]
        self.assertEqual("The Line is Open!", message1)
