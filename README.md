[![Build Status](https://dronev1.int.giosg.com/api/badges/giosg/giosg_crypter/status.svg)](https://dronev1.int.giosg.com/giosg/giosg_crypter)

# Giosg Crypter

![Giosg Crypter logo](https://github.com/giosg/giosg_crypter/blob/master/awesome_logo_image.png?raw=true)

## Install

`pip install git+https://github.com/giosg/giosg_crypter.git#egg=giosg-crypter==<version number>`

Where `<version number>` is the release version that user wants to install.

## Usage

### Command line

#### File inputs

Provide paths to the files that contain chat_session and messages in file format.
Flag the messages with `-m` or `--messages`.

`decrypt path/to/private/key/file path/to/chatsession/json/file -m path/to/messages/json/file`

#### Url inputs

By providing a url that starts with `https`, the chat session and the messages can be fetched online.
The API Token needs to be given with  `-t` or `--token` flag.
In this case, url to the messages is not required.

`decrypt path/to/private/key/file https://service.giosg.com/api/v5/path/to/chats/<chat_session_id> -t qef1h3iu2hfiu2h4ri2u3hri2u3hr`

#### Choosing output

By default, output is written in a file with default name `decrypted_messages.json`.
The filename can be changed using `-f` or `--filename` flag:

`decrypt path/to/private/key/file path/to/chatsession/json/file pat/to/messages/json/file -f new_filename.json`

The output can also be changed to stdout with `-o` or `--output` flag:

`decrypt path/to/private/key/file path/to/chatsession/json/file pat/to/messages/json/file -o stdout`

#### Version

`decrypt --version` or `decrypt -v` 

#### Help

`decrypt --help` or `decrypt -h` 

## As library

```python
from giosg.crypter import AESKey, asymmetric_decrypt, symmetric_decrypt

aes_key = asymmetric_decrypt(private_key, encrypted_key_from_chat_session)
key = AESKey.from_json(aes_key)
symmetric_decrypt(key, message_field_to_be_decrypted])
```
