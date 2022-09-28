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
