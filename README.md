[![Build Status](https://dronev1.int.giosg.com/api/badges/giosg/giosg_crypter/status.svg)](https://dronev1.int.giosg.com/giosg/giosg_crypter)

# Giosg Crypter

![Giosg Crypter logo](https://github.com/giosg/giosg_crypter/blob/master/awesome_logo_image.png?raw=true)

## Install

`pip install git+https://github.com/giosg/giosg_crypter.git#egg=giosg-crypter==<version number>`

## Usage

### Command line

`decrypt path/to/private/key/file path/to/chatsession/json/file`

## As library

```python
from giosg.crypter import AESKey, asymmetric_decrypt, symmetric_decrypt

aes_key = asymmetric_decrypt(private_key, encrypted_key_from_chat_session)
key = AESKey.from_json(aes_key)
symmetric_decrypt(key, data["field_to_decrypt"])
```
