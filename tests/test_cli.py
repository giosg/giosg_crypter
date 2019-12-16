import json
import os
import subprocess
from unittest import TestCase
from unittest.mock import Mock, patch, ANY
from giosg.crypter.cli import DecryptChatSession, Input

TESTDATA_FILEPATH = os.path.join(os.path.dirname(__file__), 'fixtures/')


class ClientTest(TestCase):

    def setUp(self):
        self.private_key = subprocess.check_output(['openssl', 'rsa', '-in', TESTDATA_FILEPATH + '/private.pem'])
        with open(TESTDATA_FILEPATH + '/chat.json', 'r') as f:
            self.chat_session = json.loads(f.read())

        with open(TESTDATA_FILEPATH + '/messages.json', 'r') as f:
            self.messages = json.loads(f.read())

    def test_encrypt_and_decrypt(self):
        message1 = DecryptChatSession(self.private_key).decrypt(self.chat_session, self.messages)[0]["message"]
        self.assertEqual("The Line is Open!", message1)

    def test_file_input(self):
        cmd_line_args = self.mock_cmd_line(chat=TESTDATA_FILEPATH + 'chat.json',
                                           messages=TESTDATA_FILEPATH + 'messages.json')
        input_reader = Input(cmd_line_args).reader()
        self.assert_input(input_reader)

    @patch('requests.get')
    def test_url_input(self, mock_requests):
        cmd_line_args = self.mock_cmd_line(chat="https://www.something.com")
        mock_requests.side_effect = [self.mock_response(
            json.dumps(self.chat_session)), self.mock_response(json.dumps({"results": self.messages}))]
        input_reader = Input(cmd_line_args).reader()
        self.assert_input(input_reader)
        mock_requests.assert_called_with("https://www.something.com/messages", headers=ANY)
        self.assertEqual(len(mock_requests.mock_calls), 2)

    @patch('requests.get')
    def test_url_input_trailing_slash(self, mock_requests):
        cmd_line_args = self.mock_cmd_line(chat="https://www.something.com/")
        mock_requests.side_effect = [self.mock_response(
            json.dumps(self.chat_session)), self.mock_response(json.dumps({"results": self.messages}))]
        input_reader = Input(cmd_line_args).reader()
        self.assert_input(input_reader)
        mock_requests.assert_called_with("https://www.something.com/messages", headers=ANY)
        self.assertEqual(len(mock_requests.mock_calls), 2)

    def mock_cmd_line(self, chat=None, messages=None):
        cmd_line_args = Mock()
        cmd_line_args.private_key = TESTDATA_FILEPATH + 'private.pem'
        cmd_line_args.chat_session = chat
        cmd_line_args.messages = messages
        return cmd_line_args

    def mock_response(self, content):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = content
        return mock_response

    def assert_input(self, input_reader):
        self.assertEqual(self.private_key, input_reader.read_private_key())
        self.assertEqual(self.chat_session, input_reader.read_chat_session())
        self.assertEqual(self.messages, input_reader.read_messages())
