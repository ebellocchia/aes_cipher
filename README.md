# AES Cipher

| |
|---|
| [![PyPI - Version](https://img.shields.io/pypi/v/aes_cipher.svg?logo=pypi&label=PyPI&logoColor=gold)](https://pypi.org/project/aes_cipher/) [![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aes_cipher.svg?logo=python&label=Python&logoColor=gold)](https://pypi.org/project/aes_cipher/) [![GitHub License](https://img.shields.io/github/license/ebellocchia/aes_cipher?label=License)](https://github.com/ebellocchia/aes_cipher?tab=MIT-1-ov-file) |
| [![Code Coverage](https://github.com/ebellocchia/aes_cipher/actions/workflows/codecov.yml/badge.svg)](https://github.com/ebellocchia/aes_cipher/actions/workflows/codecov.yml) [![Code Analysis](https://github.com/ebellocchia/aes_cipher/actions/workflows/code-analysis.yml/badge.svg)](https://github.com/ebellocchia/aes_cipher/actions/workflows/code-analysis.yml) [![Build & Test](https://github.com/ebellocchia/aes_cipher/actions/workflows/test.yml/badge.svg)](https://github.com/ebellocchia/aes_cipher/actions/workflows/test.yml) |
| [![Codecov](https://img.shields.io/codecov/c/github/ebellocchia/aes_cipher?label=Code%20Coverage)](https://codecov.io/gh/ebellocchia/aes_cipher) [![Codacy grade](https://img.shields.io/codacy/grade/9afd9788aa0e43faa491edcf6ed29d5e?label=Codacy%20Grade)](https://app.codacy.com/gh/ebellocchia/aes_cipher/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade) [![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/ebellocchia/aes_cipher?label=CodeFactor%20Grade)](https://www.codefactor.io/repository/github/ebellocchia/aes_cipher) |
| |

## Introduction

AES cipher is a library to encrypt/decrypt using AES256-CBC. It is possible to encrypt/decrypt both files and raw data (string or bytes).

# How it works

1. A master key and IV are derived from the given password and (optionally) salt using a key derivation function. The key derivation function can be chosen among the provided ones:
   - PBKDF2-SHA512
   - Scrypt

    Alternatively, it can also be customized by the user by simply implementing the `IKeyDerivator` interface.\
    Salt is randomly generated (16-byte long) if not specified.
2. A random key and IV are generated and used to encrypt the actual data. In this way, if the same file is encrypted with the same password multiple times, the encrypted file will always be different.
3. The random key and IV are encrypted with the master key and IV
4. HMAC-SHA256 of the encrypted key/IV and file data is computed to ensure integrity, using the master key as key

It is possible to specify either a single password or a list of passwords.
In the last case, the file will be encrypted multiple times with a different password and salt each time.

## Installation

The package requires Python >= 3.7.\
To install it:

    pip install aes_cipher

## Test and Coverage

Install develop dependencies:

    pip install -r requirements-dev.txt

To run tests:

    python -m unittest discover

To run tests with coverage:

    coverage run -m unittest discover
    coverage report

## APIs

### Key derivation

`Pbkdf2Sha512` class: derive keys using PBKDF2-SHA512 algorithm
  - `Pbkdf2Sha512(itr_num)`: construct the class
    - `itr_num`: iterations number

For default values, the `Pbkdf2Sha512Default` class instance can be used:

    Pbkdf2Sha512Default = Pbkdf2Sha512(512 * 1024)

`Scrypt` class: derive keys using Scrypt algorithm
  - `Scrypt(n, p, r)`: construct the class
    - `n`: CPU/Memory cost parameter
    - `p`: block size parameter
    - `r`: parallelization parameter

For default values, the `ScryptDefault` class instance can be used:

    ScryptDefault = Scrypt(16384, 8, 8)

To add a custom key derivation function, the `IKeyDerivator` interface shall be implemented:

    class IKeyDerivator(ABC):
        @abstractmethod
        def DeriveKey(self,
                      password: Union[str, bytes],
                      salt: Union[str, bytes]) -> bytes:
            pass

The only requirement is that the output of the `DeriveKey` method is at least 48-byte long.\
A constructor can be added to customize the algorithm.

### Encryption

`DataEncrypter` class: encrypt bytes or string data

- `DataEncrypter(key_derivator)`: construct the class
  - `key_derivator`: key derivator to be used for master key and IV generation, it shall be an instance of the `IKeyDerivator` interface. Default value: `Pbkdf2Sha512Default`.
- `DataEncrypter.Encrypt(data, passwords [, salts])`: encrypt data with the specified passwords and salts
    - `data`: input data (string or bytes)
    - `passwords`: list of passwords (list of strings)
    - `salts` (optional): list of salts (list of strings). The number of salts shall be the same of the passwords. If not specified, salts will be randomly generated (16-byte long).
- `DataEncrypter.GetEncryptedData()`: get encrypted data (bytes)

`FileEncrypter` class: encrypt a file

- `FileEncrypter(key_derivator)`: construct the class
  - `key_derivator`: see `DataEncrypter` constructor
- `FileEncrypter.Encrypt(file_in, passwords [, salts])`: encrypt file with the specified passwords and salts
    - `file_in`: input file
    - `passwords`: see `DataEncrypter.Encrypt`
    - `salts`: see `DataEncrypter.Encrypt`
- `FileEncrypter.GetEncryptedData()`: get encrypted data (bytes)
- `FileEncrypter.SaveTo(file_out)`: save to file
    - `file_out`: output file to be saved

### Decryption

`DataDecrypter` class: decrypt bytes or string data

- `DataDecrypter(key_derivator)`: construct the class
  - `key_derivator`: key derivator to be used for master key and IV generation, it shall be an instance of the `IKeyDerivator` interface. Default value: `Pbkdf2Sha512Default`.
- `DataDecrypter.Decrypt(data, passwords)`: decrypt data with the specified passwords
    - `data`: input data (string or bytes)
    - `passwords`: see `DataEncrypter.Encrypt`
- `DataDecrypter.GetDecryptedData()`: get decrypted data (bytes)

`FileDecrypter` class: decrypt a file

- `FileDecrypter(key_derivator)`: construct the class
  - `key_derivator`: see `DataDecrypter` constructor
- `FileDecrypter.Decrypt(file_in, passwords)`
    - `file_in`: input file
    - `passwords`: see `DataDecrypter.Decrypt`
- `FileDecrypter.GetDecryptedData()`: get decrypted data (bytes)
- `FileDecrypter.SaveTo(file_out)`: save to file
    - `file_out`: output file to be saved

## Examples

Data encryption with single password and random salt, using PBKDF2-SHA512 algorithm with default values:

    data_encrypter = DataEncrypter(Pbkdf2Sha512Default)
    data_encrypter.Encrypt(data, "test_pwd")
    enc_data = data_encrypter.GetEncryptedData()

Data encryption with single password and custom salt, using PBKDF2-SHA512 algorithm with custom values:

    data_encrypter = DataEncrypter(
        Pbkdf2Sha512(1024 * 1024)
    )
    data_encrypter.Encrypt(data, ["test_pwd"], ["test_salt"])
    enc_data = data_encrypter.GetEncryptedData()

Data encryption with multiple passwords and custom salts, using Scrypt algorithm with default values:

    data_encrypter = DataEncrypter(ScryptDefault)
    data_encrypter.Encrypt(data, ["test_pwd_1", "test_pwd_2"], ["test_salt_1", "test_salt_2"])
    enc_data = data_encrypter.GetEncryptedData()

Data decryption with single password and random salt:

    data_decrypter = DataDecrypter()
    data_decrypter.Decrypt(data, ["test_pwd"])
    dec_data = data_decrypter.GetDecryptedData()

Data decryption with multiple passwords and custom salts:

    data_decrypter = DataDecrypter()
    data_decrypter.Decrypt(data, ["test_pwd_1", "test_pwd_2"], ["test_salt_1", "test_salt_2"])
    dec_data = data_decrypter.GetDecryptedData()

File encryption with single password and random salt:

    file_encrypter = FileEncrypter()
    file_encrypter.Encrypt(file_in, "test_pwd")
    file_encrypter.SaveTo(file_out)

Enable logging:

    data_encrypter = DataEncrypter()
    data_encrypter.Logger().SetLevel(logging.INFO)

    data_decrypter = DataDecrypter()
    data_decrypter.Logger().SetLevel(logging.INFO)

## Sample Application

A sample application based on the library using the PBKDF2-SHA512 algorithm can be found in the *app* folder.

Basic usage:

    python aes_cipher_app.py -m <enc:dec> -p <password1,password2,...> -i <input_files_or_folder> -o <output_folder> [-s <salt1,salt2,...>] [-t <itr_num>] [-v] [-h]

Parameters description:

|Short name|Long name| Description                                                                                                                                                                   |
|---|---|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`-m`|`--mode`| Operational mode: `enc` for encrypting, `dec` for decrypting                                                                                                                  |
|`-p`|`--password`| Password used for encrypting/decrypting. It can be a single password or a list of passwords separated by a comma                                                              |
|`-i`|`--input`| Input to be encrypted/decrypted. It can be a single file, a list of files separated by a comma or a folder (in this case all files in the folder will be encrypted/decrypted) |
|`-o`|`--output`| Output folder where the encrypted/decrypted files will be saved                                                                                                               |
|`-s`|`--salt`| Optional: custom salts for master key and IV derivation, random if not specified`                                                                                             |
|`-t`|`--iteration`| Optional: number of iteration for the PBKDF2-SHA512 algorithm, default value: 524288                                                                                          |
|`-v`|`--verbose`| Optional: enable verbose mode                                                                                                                                                 |
|`-h`|`--help`| Optional: print usage and exit                                                                                                                                                |

**NOTE:** the password shall not contain spaces or commas (in this case it will be interpreted as multiple passwords)

Examples:

- Encrypt a file one time with the given password and salt. If *input_file* is a folder, all the files inside the folder will be encrypted:

        python aes_cipher_app.py -m enc -p test_pwd -i input_file -o encrypted -s test_salt

- Decrypt the previous file:

        python aes_cipher_app.py -m dec -p test_pwd -i encrypted -o decrypted -s test_salt

- Encrypt multiple files one time with the given password and salt. If one of the input files is a directory, it will be discarded:

        python aes_cipher_app.py -m enc -p test_pwd -i input_file1,input_file2,input_file3 -o encrypted -s test_salt

- Encrypt a file 3 times using 3 passwords with random salts and custom number of iteration:

        python aes_cipher_app.py -m enc -p test_pwd_1,test_pwd_2,test_pwd_3 -t 131072 -i input_file -o encrypted

- Decrypt the previous file:

        python aes_cipher_app.py -m dec -p test_pwd_1,test_pwd_2,test_pwd_3 -t 131072 -i encrypted -o decrypted
