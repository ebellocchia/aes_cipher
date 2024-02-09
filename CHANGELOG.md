# 2.0.1

- Update Python versions

# 2.0.0

- Add possibility to use a custom key derivation function
- Add _Scrypt_ as key derivation function
- A list of salts are required when encrypting, instead of a single one
- If not specified, salts are randomly generated instead of using a default one
- Salts are written to the encrypted file
- No need to specify salts when decrypting anymore, since they are written in the file

**NOTE:** files or data encrypted with the old version cannot be decrypted with the new one

# 1.0.5

- Fix setting of logging level

# 1.0.4

- Add configuration for _isort_ and run it on project
- Logger set to `None` if not specified (avoid conflicting with other logger config)

# 1.0.3

- Add configuration files for _flake8_ and _prospector_
- Fix all _flake8_ and _prospector_ warnings

# 1.0.2

- Add typing to class members
- Fix _mypy_ errors

# 1.0.1

- Add Python typing

# 1.0.0

- Add possibility to encrypt/decrypt data (string or bytes) in addition to files
- Remove file output encodings (it can be done externally by the user, it's not a responsibility of the encrypter/decrypter classes)

# 0.2.0

- Add exception for decrypting error

# 0.1.1

- Add validity check for PBKDF2-SHA512 iteration number

# 0.1.0

First release
