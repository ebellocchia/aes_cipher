# AES Cipher
[![Build Status](https://www.travis-ci.com/ebellocchia/aes_cipher.svg?branch=main)](https://travis-ci.com/ebellocchia/aes_cipher)
[![codecov](https://codecov.io/gh/ebellocchia/aes_cipher/branch/main/graph/badge.svg)](https://codecov.io/gh/ebellocchia/aes_cipher)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/ebellocchia/bip_utils/master/LICENSE)

## Introduction

AES cipher is a simple application to encrypt/decrypt files using AES256-CBC.

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

To run the tests:

- Without code coverage

        python -m unittest discover

- With code coverage and report:

        pip install coverage
        coverage run -m unittest discover
        coverage report

## APIs

*FileEncrypter* class:

- **FileEncrypter.Encrypt(file_in, passwords [, salt, itr_num])**
    - file_in: input file
    - passwords: single password (string) or multiple passwords (array of passwords)
    - salt: custom salt. If not specified, the default salt "[]=?AeS_CiPhEr><()" will be used.
    - itr_num: number of iterations for PBKDF2-SHA512 algorithm. If not specified, the default value of 524288 (1024 * 512) will be used.
- **FileEncrypter.GetEncryptedData(data_encoding)**
    - data_encoding: *FileDataEncodings.BINARY* for binary file, *FileDataEncodings.BASE64* for base64
- **FileEncrypter.SaveTo(file_out [, data_encoding])**
    - file_out: output file to be saved
    - data_encoding: *FileDataEncodings.BINARY* for binary file (default value), *FileDataEncodings.BASE64* for base64

*FileDecrypter* class:

- **FileDecrypter.Decrypt(file_in, passwords [, salt, itr_num])**
    - file_in: input file
    - passwords: single password (string) or multiple passwords (array of passwords)
    - salt: custom salt. If not specified the default salt "[]=?AeS_CiPhEr><()" will be used.
    - itr_num: number of iterations for PBKDF2-SHA512 algorithm. If not specified, the default value of 524288 (1024 * 512) will be used.
- **FileDecrypter.GetDecryptedData(data_encoding)**
    - data_encoding: *FileDataEncodings.BINARY* for binary file, *FileDataEncodings.BASE64* for base64
- **FileDecrypter.SaveTo(file_out)**
    - file_out: output file to be saved

## Examples

Basic encryption with single password and default salt. The output is a binary file.

    file_encrypter = FileEncrypter()
    file_encrypter.Encrypt(file_in, "test_pwd")
    file_encrypter.SaveTo(file_out)

Basic encryption with single password and custom salt (output is in base64 format):

    file_encrypter = FileEncrypter()
    file_encrypter.Encrypt(file_in, "test_pwd", "test_salt")
    file_encrypter.SaveTo(file_out, FileDataEncodings.BASE64)

Basic encryption with multiple passwords, default salt and custom number of iterations:

    file_encrypter = FileEncrypter()
    file_encrypter.Encrypt(file_in, [ "test_pwd_1", "test_pwd_2", "test_pwd_3" ], itr_num=1048576)
    file_encrypter.SaveTo(file_out)

Basic decryption with single password and default salt:

    file_decrypter = FileDecrypter()
    file_decrypter.Decrypt(file_in, "test_pwd")
    file_decrypter.SaveTo(file_out)

Basic decryption with multiple password and custom salt:

    file_decrypter = FileDecrypter()
    file_decrypter.Decrypt(file_in, [ "test_pwd_1", "test_pwd_2", "test_pwd_3" ], "test_salt")
    file_decrypter.SaveTo(file_out)

Enable verbose mode:

    logger = Logger()
    logger.SetVerbose(True)

    file_encrypter = FileEncrypter(logger)
    file_encrypter = FileDecrypter(logger)
