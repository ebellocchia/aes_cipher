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
import binascii
from aes_cipher.aes_const import AesConst
from aes_cipher.aes_cbc_decrypter import AesCbcDecrypter
from aes_cipher.file_ex import FileHmacError
from aes_cipher.file_data_encodings import FileDataEncodings, FileDataEncoder
from aes_cipher.key_iv_generator import KeyIvGenerator
from aes_cipher.hmac_sha256 import HmacSha256
from aes_cipher.logger import Logger
from aes_cipher.utils import Utils


#
# Classes
#

# Constants for file decrypter
class FileDecrypterConst:
    INT_KEY_OFF = 0
    INT_IV_OFF = AesConst.KeySize()
    INT_KEY_IV_PAD_OFF = AesConst.KeySize() + AesConst.IvSize()
    INT_KEY_IV_DIG_OFF = AesConst.KeySize() + AesConst.IvSize() + AesConst.PadSize()
    DATA_ENC_OFF = AesConst.KeySize() + AesConst.IvSize() + AesConst.PadSize() + HmacSha256.DigestSize()
    DATA_DIG_OFF = -1 * HmacSha256.DigestSize()


# File decrypter class
class FileDecrypter:
    # Constructor
    def __init__(self, logger = Logger()):
        self.decrypted_data = ""
        self.logger = logger

    # Decrypt
    def Decrypt(self, file_in, passwords, salt = None, itr_num = None):
        # Read file
        curr_data = self.__ReadFile(file_in)
        # Log
        self.logger.GetLogger().info("Salt: %s" % salt)

        # Decrypt multiple times, one for each given password in reverse order
        for password in reversed(passwords):
            # Log
            self.logger.GetLogger().info("Decrypting with password: %s" % password)
            self.logger.GetLogger().info("  Current data: %s" % binascii.hexlify(Utils.Encode(curr_data)))

            # Generate keys and IVs
            key_iv_gen = KeyIvGenerator()
            key_iv_gen.GenerateMaster(password, salt, itr_num)

            # Read internal key and IV
            internal_key, internal_iv = self.__ReadInternalKeyIv(curr_data, key_iv_gen)
            # Read data
            curr_data = self.__ReadData(curr_data, internal_key, internal_iv)

        self.decrypted_data = curr_data

    # Save to file
    def SaveTo(self, file_out):
        with open(file_out, "wb") as fout:
            fout.write(self.GetDecryptedData(FileDataEncodings.BINARY))

    # Get decrypted data
    def GetDecryptedData(self, data_encoding):
        return FileDataEncoder.EncodeData(self.decrypted_data, data_encoding)

    # Read internal key and IV
    def __ReadInternalKeyIv(self, data, key_iv_gen):
        # Get encrypted bytes and digest
        key_iv_encrypted = data[FileDecrypterConst.INT_KEY_OFF : FileDecrypterConst.INT_KEY_IV_DIG_OFF]
        key_iv_digest = data[FileDecrypterConst.INT_KEY_IV_DIG_OFF : FileDecrypterConst.DATA_ENC_OFF]

        # Log
        self.logger.GetLogger().info("  Encrypted internal key/IV: %s" % binascii.hexlify(key_iv_encrypted))
        self.logger.GetLogger().info("  Internal key/IV digest: %s" % binascii.hexlify(key_iv_digest))

        # Decrypt internal key and IV with master key and IV
        aes_decrypter = AesCbcDecrypter(key_iv_gen.GetMasterKey(), key_iv_gen.GetMasterIV())
        aes_decrypter.Decrypt(key_iv_encrypted)
        key_iv_decrypted = aes_decrypter.GetDecryptedData()
        # Verify their digest
        if not HmacSha256.QuickVerify(key_iv_gen.GetMasterKey(), key_iv_decrypted, key_iv_digest):
            raise FileHmacError("Invalid HMAC for internal key and IV")

        return key_iv_decrypted[FileDecrypterConst.INT_KEY_OFF : FileDecrypterConst.INT_IV_OFF], key_iv_decrypted[FileDecrypterConst.INT_IV_OFF : FileDecrypterConst.INT_KEY_IV_PAD_OFF]

    # Read data
    def __ReadData(self, data, internal_key, internal_iv):
        # Get encrypted bytes and digest
        data_encrypted = data[FileDecrypterConst.DATA_ENC_OFF : FileDecrypterConst.DATA_DIG_OFF]
        data_digest = data[FileDecrypterConst.DATA_DIG_OFF:]

        # Log
        self.logger.GetLogger().info("  Encrypted data: %s" % binascii.hexlify(data_encrypted))
        self.logger.GetLogger().info("  Data digest: %s" % binascii.hexlify(data_digest))

        # Decrypt data with internal key and IV
        aes_decrypter = AesCbcDecrypter(internal_key, internal_iv)
        aes_decrypter.Decrypt(data_encrypted)
        data_decrypted = aes_decrypter.GetDecryptedData()
        # Verify its digest
        if not HmacSha256.QuickVerify(internal_key, data_decrypted, data_digest):
            raise FileHmacError("Invalid HMAC for data")

        # Log
        self.logger.GetLogger().info("  Decrypted data: %s" % binascii.hexlify(data_decrypted))

        return data_decrypted

    # Read file and get content
    @staticmethod
    def __ReadFile(file_in):
        # Read file
        with open(file_in, "rb") as fin:
            file_data = fin.read()

        # Decode if necessary
        if Utils.IsBase64(file_data):
            file_data = Utils.Base64Decode(file_data)

        return file_data
