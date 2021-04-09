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
import os, unittest
from pathlib import Path
from aes_cipher import FileDecrypter, FileEncrypter, FileDataEncodings, FileHmacError
from aes_cipher.file_decrypter import FileDecrypterConst

#
# Constants
#
TEST_FILES_PATH = Path("tests/files")
TEST_TXT_FILE = TEST_FILES_PATH / "test_file.txt"
TEST_ZIP_FILE = TEST_FILES_PATH / "test_file.zip"
TEST_DEC_FILE = TEST_FILES_PATH / "dec"
TEST_ENC_FILE = TEST_FILES_PATH / "enc"
TEST_SINGLE_PWD = "test_pwd"
TEST_MULTIPLE_PWD = [ "test_pwd_1", "test_pwd_2", "test_pwd_3" ]
TEST_SALT = "test_salt"

#
# Helper class for testing
#
class TestHelper:
    # Decrypt file (binary output)
    @staticmethod
    def decrypt_file_bin(file_in, file_out, passwords, salt = None):
        TestHelper.__decrypt_file(file_in, file_out, passwords, salt, FileDataEncodings.BINARY)

    # Decrypt file (base64 output)
    @staticmethod
    def decrypt_file_b64(file_in, file_out, passwords, salt = None):
        TestHelper.__decrypt_file(file_in, file_out, passwords, salt, FileDataEncodings.BASE64)

    # Encrypt file (binary output)
    @staticmethod
    def encrypt_file_bin(file_in, file_out, passwords, salt = None):
        TestHelper.__encrypt_file(file_in, file_out, passwords, salt, FileDataEncodings.BINARY)

    # Encrypt file (base64 output)
    @staticmethod
    def encrypt_file_b64(file_in, file_out, passwords, salt = None):
        TestHelper.__encrypt_file(file_in, file_out, passwords, salt, FileDataEncodings.BASE64)

    # Compare files
    @staticmethod
    def compare_files(ut_class, file_in_1, file_in_2):
        file_data_1 = TestHelper.__read_file(file_in_1)
        file_data_2 = TestHelper.__read_file(file_in_2)
        ut_class.assertEqual(file_data_1, file_data_2)

    # Corrupt file
    @staticmethod
    def corrupt_file(file_in, idx):
        file_data = bytearray(TestHelper.__read_file(file_in))
        file_data[idx] = 0 if file_data[idx] != 0 else 1;
        TestHelper.__write_file(file_in, file_data)

    # Read file
    @staticmethod
    def __read_file(file_in):
        with open(file_in, "rb") as fin:
            file_data = fin.read()
        return file_data

    # Write file
    @staticmethod
    def __write_file(file_out, file_data):
        with open(file_out, "wb") as fout:
            fout.write(file_data)

    # Decrypt file
    @staticmethod
    def __decrypt_file(file_in, file_out, passwords, salt, enc):
        file_decrypter = FileDecrypter()
        file_decrypter.Decrypt(file_in, passwords, salt)
        file_decrypter.SaveTo(file_out)

    # Encrypt file
    @staticmethod
    def __encrypt_file(file_in, file_out, passwords, salt, enc):
        file_encrypter = FileEncrypter()
        file_encrypter.Encrypt(file_in, passwords, salt)
        file_encrypter.SaveTo(file_out, enc)


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

    # Test HMAC error for key/IV
    def test_keyiv_hmac_error(self):
        TestHelper.encrypt_file_bin(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD)
        TestHelper.corrupt_file(TEST_ENC_FILE, FileDecrypterConst.INT_KEY_OFF)
        self.assertRaises(FileHmacError, TestHelper.decrypt_file_bin, TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD)

    # Test HMAC error for data
    def test_data_hmac_error(self):
        TestHelper.encrypt_file_bin(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD)
        TestHelper.corrupt_file(TEST_ENC_FILE, FileDecrypterConst.DATA_ENC_OFF)
        self.assertRaises(FileHmacError, TestHelper.decrypt_file_bin, TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD)

    # Test encryption/decryption with single password and default salt (text file as input)
    def test_txt_single_pwd_def_salt(self):
        TestHelper.encrypt_file_bin(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD)
        TestHelper.decrypt_file_bin(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with single password and custom salt (text file as input)
    def test_txt_single_pwd_custom_salt(self):
        TestHelper.encrypt_file_bin(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD, TEST_SALT)
        TestHelper.decrypt_file_bin(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD, TEST_SALT)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with multiple passwords and default salt (text file as input)
    def test_txt_multiple_pwd_def_salt(self):
        TestHelper.encrypt_file_bin(TEST_TXT_FILE, TEST_ENC_FILE, TEST_MULTIPLE_PWD)
        TestHelper.decrypt_file_bin(TEST_ENC_FILE, TEST_DEC_FILE, TEST_MULTIPLE_PWD)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with multiple passwords and custom salt (text file as input)
    def test_txt_multiple_pwd_custom_salt(self):
        TestHelper.encrypt_file_bin(TEST_TXT_FILE, TEST_ENC_FILE, TEST_MULTIPLE_PWD, TEST_SALT)
        TestHelper.decrypt_file_bin(TEST_ENC_FILE, TEST_DEC_FILE, TEST_MULTIPLE_PWD, TEST_SALT)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with single password and default salt (binary file as input)
    def test_bin_single_pwd_def_salt(self):
        TestHelper.encrypt_file_bin(TEST_ZIP_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD)
        TestHelper.decrypt_file_bin(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD)
        TestHelper.compare_files(self, TEST_ZIP_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with single password and custom salt (binary file as input)
    def test_bin_single_pwd_custom_salt(self):
        TestHelper.encrypt_file_bin(TEST_ZIP_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD, TEST_SALT)
        TestHelper.decrypt_file_bin(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD, TEST_SALT)
        TestHelper.compare_files(self, TEST_ZIP_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with multiple passwords and default salt (binary file as input)
    def test_bin_multiple_pwd_def_salt(self):
        TestHelper.encrypt_file_bin(TEST_ZIP_FILE, TEST_ENC_FILE, TEST_MULTIPLE_PWD)
        TestHelper.decrypt_file_bin(TEST_ENC_FILE, TEST_DEC_FILE, TEST_MULTIPLE_PWD)
        TestHelper.compare_files(self, TEST_ZIP_FILE, TEST_DEC_FILE)

    # Test encryption/decryption with multiple passwords and custom salt (binary file as input)
    def test_bin_multiple_pwd_custom_salt(self):
        TestHelper.encrypt_file_bin(TEST_ZIP_FILE, TEST_ENC_FILE, TEST_MULTIPLE_PWD, TEST_SALT)
        TestHelper.decrypt_file_bin(TEST_ENC_FILE, TEST_DEC_FILE, TEST_MULTIPLE_PWD, TEST_SALT)
        TestHelper.compare_files(self, TEST_ZIP_FILE, TEST_DEC_FILE)

    # Test using base64 as encryption output
    def test_base64(self):
        TestHelper.encrypt_file_b64(TEST_TXT_FILE, TEST_ENC_FILE, TEST_SINGLE_PWD)
        TestHelper.decrypt_file_b64(TEST_ENC_FILE, TEST_DEC_FILE, TEST_SINGLE_PWD)
        TestHelper.compare_files(self, TEST_TXT_FILE, TEST_DEC_FILE)
