# AES Cipher
[![PyPI version](https://badge.fury.io/py/aes-cipher.svg)](https://badge.fury.io/py/aes-cipher)
[![Build Status](https://www.travis-ci.com/ebellocchia/aes_cipher.svg?branch=main)](https://travis-ci.com/ebellocchia/aes_cipher)
[![codecov](https://codecov.io/gh/ebellocchia/aes_cipher/branch/main/graph/badge.svg)](https://codecov.io/gh/ebellocchia/aes_cipher)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/9afd9788aa0e43faa491edcf6ed29d5e)](https://www.codacy.com/gh/ebellocchia/aes_cipher/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ebellocchia/aes_cipher&amp;utm_campaign=Badge_Grade)
[![CodeFactor](https://www.codefactor.io/repository/github/ebellocchia/aes_cipher/badge)](https://www.codefactor.io/repository/github/ebellocchia/aes_cipher)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/ebellocchia/bip_utils/master/LICENSE)

## Introduction

AES cipher is a simple application to encrypt/decrypt using AES256-CBC. It is possible to encrypt/decrypt both files and data (string or bytes).

A master key and IV are derived from the given password and salt using PBKDF2-SHA512. Then a random key and IV are generated and used to encrypt the actual data (in this way, if the same file is encrypted with the same password multiple times, the encrypted file will always be different). Finally, these random key and IV are encrypted with the master key and IV.

It is possible to specify a single password or a list of passwords, in this case the file will be encrypted multiple times with a different password each time. The integrity of the encrypted key , IV and file data are ensured using HMAC-SHA256.

*pycryptodome* is used as crypto library.

## Installation

The package requires Python 3, it is not compatible with Python 2.
To install it:
- Using *setuptools*:

        python setup.py install

- Using *pip*:

        pip install aes_cipher

To run tests:

    python -m unittest discover

Or you can install *tox*:

    pip install tox

And then simply run *tox*:

    tox

To run tests and get the code coverage and report.

## APIs

`DataEncrypter` class:

- `DataEncrypter.Encrypt(data, passwords [, salt, itr_num])`: encrypt data with the specified passwords, salt and iteration number
    - `data`: input data (string or bytes)
    - `passwords`: single password (string) or multiple passwords (array of strings)
    - `salt`: custom salt. If not specified, the default salt `[]=?AeS_CiPhEr><()` will be used.
    - `itr_num`: number of iterations for PBKDF2-SHA512 algorithm. If not specified, the default value of 524288 (1024 * 512) will be used.
- `DataEncrypter.GetEncryptedData()`: get encrypted data (bytes)

`FileEncrypter` class: encrypt file

- `FileEncrypter.Encrypt(file_in, passwords [, salt, itr_num])`: encrypt file with the specified passwords, salt and iteration number
    - `file_in`: input file
    - `passwords`: see `DataEncrypter.Encrypt`
    - `salt`: see `DataEncrypter.Encrypt`
    - `itr_num`: see `DataEncrypter.Encrypt`
- `FileEncrypter.GetEncryptedData()`: get encrypted data (bytes)
- `FileEncrypter.SaveTo(file_out)`: save to file
    - `file_out`: output file to be saved

`DataDecrypter` class:

- `DataDecrypter.Decrypt(data, passwords [, salt, itr_num])`: decrypt data with the specified passwords, salt and iteration number
    - `data`: input data (string or bytes)
    - `passwords`: see `DataEncrypter.Encrypt`
    - `salt`: see `DataEncrypter.Encrypt`
    - `itr_num`: see `DataEncrypter.Encrypt`
- `DataDecrypter.GetDecryptedData()`: get decrypted data (bytes)

`FileDecrypter` class:

- `FileDecrypter.Decrypt(file_in, passwords [, salt, itr_num])`
    - `file_in`: input file
    - `passwords`: see `DataDecrypter.Decrypt`
    - `salt`: see `DataDecrypter.Decrypt`
    - `itr_num`: see `DataDecrypter.Decrypt`
- `FileDecrypter.GetDecryptedData()`: get decrypted data (bytes)
- `FileDecrypter.SaveTo(file_out)`: save to file
    - `file_out`: output file to be saved

## Examples

Data encryption with single password and default salt:

    data_encrypter = DataEncrypter()
    data_encrypter.Encrypt(data, "test_pwd")
    enc_data = data_encrypter.GetEncryptedData()

Data encryption with single password and custom salt:

    data_encrypter = DataEncrypter()
    data_encrypter.Encrypt(data, "test_pwd", "test_salt")
    enc_data = data_encrypter.GetEncryptedData()

Data encryption with multiple passwords, default salt and custom number of iterations:

    data_encrypter = DataEncrypter()
    data_encrypter.Encrypt(data, ["test_pwd_1", "test_pwd_2", "test_pwd_3"], itr_num=1048576)
    enc_data = data_encrypter.GetEncryptedData()

Data decryption with single password and default salt:

    data_decrypter = DataDecrypter()
    data_decrypter.Decrypt(data, "test_pwd")
    dec_data = data_decrypter.GetDecryptedData()

Data decryption with multiple passwords and custom salt:

    data_decrypter = DataDecrypter()
    data_decrypter.Decrypt(data, ["test_pwd_1", "test_pwd_2", "test_pwd_3"], "test_salt")
    dec_data = data_decrypter.GetDecryptedData()

File encryption with single password and default salt:

    file_encrypter = FileEncrypter()
    file_encrypter.Encrypt(file_in, "test_pwd")
    file_encrypter.SaveTo(file_out)

Enable logging:

    data_encrypter = DataEncrypter()
    data_encrypter.Logger().SetLevel(logging.INFO)

    data_decrypter = DataDecrypter()
    data_decrypter.Logger().SetLevel(logging.INFO)
