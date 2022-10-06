# Copyright (c) 2020 Emanuele Bellocchia
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


# Imports
import os
import unittest
from pathlib import Path

from aes_cipher import (
    DataDecrypter, DataDecryptError, DataEncrypter, DataHmacError, FileDecrypter, FileEncrypter, Logger, Pbkdf2Sha512,
    Scrypt
)
from aes_cipher.data_decrypter import DataDecrypterConst
from aes_cipher.file_reader import FileReader
from aes_cipher.file_writer import FileWriter
from aes_cipher.key_iv_generator import KeyIvGeneratorConst
from aes_cipher.utils import Utils


#
# Constants
#

# Paths
TEST_FILES_PATH = Path("tests/files")
TEST_TXT_FILE = TEST_FILES_PATH / "test_file.txt"
TEST_ZIP_FILE = TEST_FILES_PATH / "test_file.zip"
TEST_DEC_FILE = TEST_FILES_PATH / "dec"
TEST_ENC_FILE = TEST_FILES_PATH / "enc"
# Passwords and salts
TEST_SINGLE_PWD_1 = ["test_pwd_1"]
TEST_SINGLE_PWD_2 = ["test_pwd_2"]
TEST_MULTIPLE_PWD_1 = ["test_pwd_1", "test_pwd_2", "test_pwd_3"]
TEST_MULTIPLE_PWD_2 = ["test_pwd_1", "test_pwd_4", "test_pwd_3"]
TEST_SINGLE_SALT_1 = ["test_salt_1"]
TEST_MULTIPLE_SALT_1 = ["test_salt_1", "test_salt_2", "test_salt_3"]
# Input data
TEST_STR = """Hello,
This a test string for encrypting/decrypting a string.

Thank you!"""
TEST_BIN = b"\x91\x11\xa4\xe5\xa7\x81\x1f\x14\x0b\xb3\x83\xad\x04\xdf\xba\x98\x18\xb2\xd5\x01\xf6\xf6\xeb\x0f\xc8\xe6\xa9\x18\xb5\xa1\x16\x1a\xe2\n\x03\xd0\xd7"
# For speeding up tests
TEST_ITR = 1024 * 16


#
# Helper class for testing
#
class TestHelper:
    # Decrypt data
    @staticmethod
    def decrypt_data(data, passwords, itr_num=TEST_ITR):
        data_decrypter = DataDecrypter(Pbkdf2Sha512(itr_num))
        data_decrypter.Decrypt(data, passwords)
        return data_decrypter.GetDecryptedData()

    # Encrypt data
    @staticmethod
    def encrypt_data(data, passwords, salts=None, itr_num=TEST_ITR):
        data_encrypter = DataEncrypter(Pbkdf2Sha512(itr_num))
        data_encrypter.Encrypt(data, passwords, salts)
        return data_encrypter.GetEncryptedData()

    # Decrypt file
    @staticmethod
    def decrypt_file(file_in, file_out, passwords, itr_num=TEST_ITR):
        file_decrypter = FileDecrypter(Pbkdf2Sha512(itr_num))
        file_decrypter.Decrypt(file_in, passwords)
        file_decrypter.SaveTo(file_out)

    # Encrypt file
    @staticmethod
    def encrypt_file(file_in, file_out, passwords, salts=None, itr_num=TEST_ITR):
        file_encrypter = FileEncrypter(Pbkdf2Sha512(itr_num))
        file_encrypter.Encrypt(file_in, passwords, salts)
        file_encrypter.SaveTo(file_out)

    # Compare files
    @staticmethod
    def compare_files(ut_class, file_in_1, file_in_2):
        file_data_1 = FileReader.Read(file_in_1)
        file_data_2 = FileReader.Read(file_in_2)
        ut_class.assertEqual(file_data_1, file_data_2)

    # Corrupt file
    @staticmethod
    def corrupt_file(file_in, idx):
        file_data = bytearray(FileReader.Read(file_in))
        file_data[idx] = 0 if file_data[idx] != 0 else 1
        FileWriter.Write(file_in, file_data)

    # Corrupt data
    @staticmethod
    def corrupt_data(data, idx):
        if isinstance(data, bytes):
            data_tmp = bytearray(data)
            data_tmp[idx] = 0 if data_tmp[idx] != 0 else 1
            data = bytes(data_tmp)
        elif isinstance(data, str):
            data[idx] = "0" if data[idx] != "0" else "1"

        return data


#
# Tests
#
class CipherTests(unittest.TestCase):
    # Tear down
    def tearDown(self):
        if os.path.exists(TEST_ENC_FILE):
            os.remove(TEST_ENC_FILE)
        if os.path.exists(TEST_DEC_FILE):
            os.remove(TEST_DEC_FILE)

    # Test salt error
    def test_salt_error(self):
        # Data
        enc_data = TestHelper.encrypt_data(TEST_STR, TEST_SINGLE_PWD_1)
        enc_data = TestHelper.corrupt_data(enc_data, DataDecrypterConst.SALT_OFF)
        self.assertRaises(DataDecryptError, TestHelper.decrypt_data, enc_data, TEST_SINGLE_PWD_1)
        # File
        TestHelper.encrypt_file(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.corrupt_file(TEST_ENC_FILE, DataDecrypterConst.SALT_OFF)
        self.assertRaises(DataDecryptError, TestHelper.decrypt_file, TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD_1)

    # Test HMAC error for key/IV
    def test_keyiv_hmac_error(self):
        # Data
        enc_data = TestHelper.encrypt_data(TEST_STR, TEST_SINGLE_PWD_1)
        enc_data = TestHelper.corrupt_data(
            enc_data,
            DataDecrypterConst.SALT_OFF + KeyIvGeneratorConst.SALT_DEF_SIZE + DataDecrypterConst.INT_KEY_OFF
        )
        self.assertRaises(DataHmacError, TestHelper.decrypt_data, enc_data, TEST_SINGLE_PWD_1)
        # File
        TestHelper.encrypt_file(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.corrupt_file(
            TEST_ENC_FILE,
            DataDecrypterConst.SALT_OFF + KeyIvGeneratorConst.SALT_DEF_SIZE + DataDecrypterConst.INT_KEY_OFF
        )
        self.assertRaises(DataHmacError, TestHelper.decrypt_file, TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD_1)

    # Test HMAC error for data
    def test_data_hmac_error(self):
        # Data
        enc_data = TestHelper.encrypt_data(TEST_STR, TEST_SINGLE_PWD_1)
        enc_data = TestHelper.corrupt_data(enc_data, DataDecrypterConst.DATA_ENC_OFF)
        self.assertRaises(DataHmacError, TestHelper.decrypt_data, enc_data, TEST_SINGLE_PWD_1)
        # File
        TestHelper.encrypt_file(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.corrupt_file(TEST_ENC_FILE, DataDecrypterConst.DATA_ENC_OFF)
        self.assertRaises(DataHmacError, TestHelper.decrypt_file, TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD_1)

    # Test error when decrypting with wrong single password
    def test_wrong_single_password(self):
        enc_data = TestHelper.encrypt_data(TEST_STR, TEST_SINGLE_PWD_1)
        self.assertRaises(DataDecryptError, TestHelper.decrypt_data, enc_data, TEST_SINGLE_PWD_2)

    # Test error when decrypting with wrong multiple password
    def test_wrong_multiple_password(self):
        enc_data = TestHelper.encrypt_data(TEST_STR, TEST_MULTIPLE_PWD_1)
        self.assertRaises(DataDecryptError, TestHelper.decrypt_data, enc_data, TEST_MULTIPLE_PWD_2)

    # Test error when encrypting with wrong salts length
    def test_wrong_salt_num(self):
        self.assertRaises(ValueError, TestHelper.encrypt_data, TEST_STR, TEST_MULTIPLE_PWD_1, TEST_SINGLE_SALT_1)

    # Test basic encryption/decryption with string data
    def test_data_str(self):
        enc_data = TestHelper.encrypt_data(TEST_STR, TEST_SINGLE_PWD_1)
        dec_data = TestHelper.decrypt_data(enc_data, TEST_SINGLE_PWD_1)
        self.assertEqual(TEST_STR, Utils.Decode(dec_data))

    # Test basic encryption/decryption with empty string data
    def test_data_str_empty(self):
        enc_data = TestHelper.encrypt_data("", TEST_SINGLE_PWD_1)
        dec_data = TestHelper.decrypt_data(enc_data, TEST_SINGLE_PWD_1)
        self.assertEqual("", Utils.Decode(dec_data))

    # Test basic encryption/decryption with binary data
    def test_data_bin(self):
        enc_data = TestHelper.encrypt_data(TEST_BIN, TEST_SINGLE_PWD_1)
        dec_data = TestHelper.decrypt_data(enc_data, TEST_SINGLE_PWD_1)
        self.assertEqual(TEST_BIN, dec_data)

    # Test basic encryption/decryption with empty binary data
    def test_data_bin_empty(self):
        enc_data = TestHelper.encrypt_data(b"", TEST_SINGLE_PWD_1)
        dec_data = TestHelper.decrypt_data(enc_data, TEST_SINGLE_PWD_1)
        self.assertEqual(b"", dec_data)

    # Test encryption/decryption with single password and default salt (text file as input)
    def test_file_txt_single_pwd_def_salt(self):
        TestHelper.encrypt_file(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.decrypt_file(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with single password and custom salt (text file as input)
    def test_file_txt_single_pwd_custom_salt(self):
        TestHelper.encrypt_file(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD_1, TEST_SINGLE_SALT_1)
        TestHelper.decrypt_file(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with multiple passwords and default salt (text file as input)
    def test_file_txt_multiple_pwd_def_salt(self):
        TestHelper.encrypt_file(TEST_TXT_FILE, TEST_ENC_FILE, TEST_MULTIPLE_PWD_1)
        TestHelper.decrypt_file(TEST_ENC_FILE, TEST_DEC_FILE, TEST_MULTIPLE_PWD_1)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with multiple passwords and custom salt (text file as input)
    def test_file_txt_multiple_pwd_custom_salt(self):
        TestHelper.encrypt_file(TEST_TXT_FILE, TEST_ENC_FILE, TEST_MULTIPLE_PWD_1, TEST_MULTIPLE_SALT_1)
        TestHelper.decrypt_file(TEST_ENC_FILE, TEST_DEC_FILE, TEST_MULTIPLE_PWD_1)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with single password and default salt (binary file as input)
    def test_file_bin_single_pwd_def_salt(self):
        TestHelper.encrypt_file(TEST_ZIP_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.decrypt_file(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.compare_files(self, TEST_ZIP_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with single password and custom salt (binary file as input)
    def test_file_bin_single_pwd_custom_salt(self):
        TestHelper.encrypt_file(TEST_ZIP_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD_1, TEST_SINGLE_SALT_1)
        TestHelper.decrypt_file(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD_1)
        TestHelper.compare_files(self, TEST_ZIP_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with multiple passwords and default salt (binary file as input)
    def test_file_bin_multiple_pwd_def_salt(self):
        TestHelper.encrypt_file(TEST_ZIP_FILE, TEST_ENC_FILE, TEST_MULTIPLE_PWD_1)
        TestHelper.decrypt_file(TEST_ENC_FILE, TEST_DEC_FILE, TEST_MULTIPLE_PWD_1)
        TestHelper.compare_files(self, TEST_ZIP_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with multiple passwords and custom salt (binary file as input)
    def test_file_bin_multiple_pwd_custom_salt(self):
        TestHelper.encrypt_file(TEST_ZIP_FILE, TEST_ENC_FILE, TEST_MULTIPLE_PWD_1, TEST_MULTIPLE_SALT_1)
        TestHelper.decrypt_file(TEST_ENC_FILE, TEST_DEC_FILE, TEST_MULTIPLE_PWD_1)
        TestHelper.compare_files(self, TEST_ZIP_FILE, TEST_DEC_FILE)

    # Test key derivator error
    def test_key_derivator_error(self):
        self.assertRaises(ValueError, Pbkdf2Sha512, 0)
        self.assertRaises(ValueError, Scrypt, 0, 1, 1)
        self.assertRaises(ValueError, Scrypt, 1, 0, 1)
        self.assertRaises(ValueError, Scrypt, 1, 1, 0)

    # Test logger
    def test_logger(self):
        data_dec = DataDecrypter()
        data_enc = DataEncrypter()
        self.assertTrue(isinstance(data_dec.Logger(), Logger))
        self.assertTrue(isinstance(data_enc.Logger(), Logger))

        file_dec = FileDecrypter()
        file_enc = FileEncrypter()
        self.assertTrue(isinstance(file_dec.Logger(), Logger))
        self.assertTrue(isinstance(file_enc.Logger(), Logger))
