# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#
# Imports
#
import binascii, io
from aes_cipher.aes_cbc_encrypter import AesCbcEncrypter
from aes_cipher.file_data_encodings import FileDataEncodings, FileDataEncoder
from aes_cipher.key_iv_generator import KeyIvGenerator
from aes_cipher.hmac_sha256 import HmacSha256
from aes_cipher.logger import Logger
from aes_cipher.utils import Utils


#
# Classes
#

# File encrypter class
class FileEncrypter:
    # Constructor
    def __init__(self, logger = Logger()):
        self.encrypted_data = b""
        self.logger = logger

    # Encrypt
    def Encrypt(self, file_in, passwords, salt = None, itr_num = None):
        # Read file
        curr_data = self.__ReadFile(file_in)
        # Log
        self.logger.GetLogger().info("Salt: %s" % salt)

        # Encrypt multiple times, one for each given password
        for password in passwords:
            # Log
            self.logger.GetLogger().info("Encrypting with password: %s" % password)
            self.logger.GetLogger().info("  Current data: %s" % binascii.hexlify(Utils.Encode(curr_data)))

            # Generate keys and IVs
            key_iv_gen = KeyIvGenerator()
            key_iv_gen.GenerateMaster(password, salt, itr_num)
            key_iv_gen.GenerateInternal()

            # Process internal key and IV
            key_iv_encrypted, key_iv_digest = self.__ProcessInternalKeyIv(key_iv_gen)
            # Process data
            data_encrypted, data_digest = self.__ProcessData(curr_data, key_iv_gen)

            # Write to buffer
            data_buffer = io.BytesIO()
            data_buffer.write(key_iv_encrypted)
            data_buffer.write(key_iv_digest)
            data_buffer.write(data_encrypted)
            data_buffer.write(data_digest)

            # Log
            self.logger.GetLogger().info("  Buffer: %s" % binascii.hexlify(data_buffer.getvalue()))

            # Update current data
            curr_data = data_buffer.getvalue()

        self.encrypted_data = curr_data

    # Save to file
    def SaveTo(self, file_out, data_encoding = FileDataEncodings.BINARY):
        with open(file_out, "wb" if data_encoding == FileDataEncodings.BINARY else "w") as fout:
            fout.write(self.GetEncryptedData(data_encoding))

    # Get encrypted data
    def GetEncryptedData(self, data_encoding):
        return FileDataEncoder.EncodeData(self.encrypted_data, data_encoding)

    # Process internal key and IV
    def __ProcessInternalKeyIv(self, key_iv_gen):
        # Encrypt internal key and IV with master key and IV
        aes_encrypter = AesCbcEncrypter(key_iv_gen.GetMasterKey(), key_iv_gen.GetMasterIV())
        aes_encrypter.Encrypt(key_iv_gen.GetInternalKey() + key_iv_gen.GetInternalIV())
        key_iv_encrypted = aes_encrypter.GetEncryptedData()
        # Compute their digest
        key_iv_digest = HmacSha256.QuickDigest(key_iv_gen.GetMasterKey(), key_iv_gen.GetInternalKey() + key_iv_gen.GetInternalIV())

        # Log
        self.logger.GetLogger().info("  Encrypted internal key/IV: %s" % binascii.hexlify(key_iv_encrypted))
        self.logger.GetLogger().info("  Internal key/IV digest: %s" % binascii.hexlify(key_iv_digest))

        return key_iv_encrypted, key_iv_digest

    # Process data
    def __ProcessData(self, data, key_iv_gen):
        # Encrypt data with internal key and IV
        aes_encrypter = AesCbcEncrypter(key_iv_gen.GetInternalKey(), key_iv_gen.GetInternalIV())
        aes_encrypter.Encrypt(data)
        data_encrypted = aes_encrypter.GetEncryptedData()
        # Compute its digest
        data_digest = HmacSha256.QuickDigest(key_iv_gen.GetInternalKey(), data)

        # Log
        self.logger.GetLogger().info("  Encrypted data: %s" % binascii.hexlify(data_encrypted))
        self.logger.GetLogger().info("  Data digest: %s" % binascii.hexlify(data_digest))

        return data_encrypted, data_digest

    # Read file and get content
    @staticmethod
    def __ReadFile(file_in):
        # Read file
        with open(file_in, "rb") as fin:
            file_data = fin.read()

        return file_data
