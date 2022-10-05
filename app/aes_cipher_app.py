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
import getopt
import logging
import sys
from enum import Enum, auto, unique
from pathlib import Path
from typing import Any, Dict, List, Tuple
from aes_cipher import FileDecrypter, FileEncrypter, DataHmacError, DataDecryptError


#
# Classes
#

# Argument types
@unique
class ArgumentTypes(Enum):
    MODE = auto(),
    PASSWORDS = auto(),
    INPUT_PATHS = auto(),
    OUTPUT_PATH = auto(),
    SALT = auto(),
    ITR_NUM = auto(),
    VERBOSE = auto(),
    HELP = auto(),


# Arguments
class Arguments:
    MODES: Tuple[str, str] = ("dec", "enc")

    args_val: Dict[ArgumentTypes, Any]

    # Constructor
    def __init__(self) -> None:
        self.Reset()

    # Get argument value
    def GetValue(self,
                 arg_type: ArgumentTypes) -> Any:
        if not isinstance(arg_type, ArgumentTypes):
            raise TypeError("Invalid argument type")
        return self.args_val[arg_type]

    # Set argument value
    def SetValue(self,
                 value: Any,
                 arg_type: ArgumentTypes) -> None:
        if not isinstance(arg_type, ArgumentTypes):
            raise TypeError("Invalid argument type")

        if arg_type == ArgumentTypes.PASSWORDS:
            self.args_val[arg_type] = value.split(",")
        elif arg_type == ArgumentTypes.INPUT_PATHS:
            self.args_val[arg_type] = self.__ParseInputPaths(value)
        elif arg_type == ArgumentTypes.OUTPUT_PATH:
            self.args_val[arg_type] = Path(value)
        elif arg_type == ArgumentTypes.ITR_NUM:
            try:
                self.args_val[arg_type] = int(value)
            except ValueError:
                self.args_val[arg_type] = 0
        else:
            self.args_val[arg_type] = value

    # Get if verbose
    def IsVerbose(self) -> bool:
        return self.GetValue(ArgumentTypes.VERBOSE)

    # Get if help is needed
    def IsHelpNeeded(self) -> bool:
        return self.GetValue(ArgumentTypes.HELP)

    # Get if decrypt mode
    def IsDecryptMode(self) -> bool:
        return self.GetValue(ArgumentTypes.MODE) == self.MODES[0]

    # Get if encrypt mode
    def IsEncryptMode(self) -> bool:
        return self.GetValue(ArgumentTypes.MODE) == self.MODES[1]

    # Get if arguments are valid
    def AreValid(self) -> bool:
        return ((self.GetValue(ArgumentTypes.MODE) in self.MODES) and
                (self.GetValue(ArgumentTypes.PASSWORDS) != "") and
                (self.GetValue(ArgumentTypes.INPUT_PATHS) is not None) and
                (self.GetValue(ArgumentTypes.OUTPUT_PATH) is not None) and
                (
                 (self.GetValue(ArgumentTypes.ITR_NUM) is None) or
                 (self.GetValue(ArgumentTypes.ITR_NUM) > 0)
                ))

    # Reset
    def Reset(self) -> None:
        self.args_val = {
            ArgumentTypes.MODE: "",
            ArgumentTypes.PASSWORDS: "",
            ArgumentTypes.INPUT_PATHS: None,
            ArgumentTypes.OUTPUT_PATH: None,
            ArgumentTypes.SALT: None,
            ArgumentTypes.ITR_NUM: None,
            ArgumentTypes.VERBOSE: False,
            ArgumentTypes.HELP: False,
        }

    # Parse input files
    @staticmethod
    def __ParseInputPaths(value: str) -> List[Path]:
        curr_path = Path(value)
        if curr_path.is_dir():
            files = [p for p in curr_path.iterdir() if p.is_file() and not p.name.startswith(".")]
        else:
            files = [Path(p) for p in value.split(",") if Path(p).is_file()]

        return files


# Argument parser
class ArgumentsParser:

    args: Arguments

    # Constructor
    def __init__(self) -> None:
        self.args = Arguments()

    # Parse arguments
    def Parse(self,
              argv: List[str]) -> None:
        # Reset arguments
        self.args.Reset()

        # Parse arguments
        try:
            opts, _ = getopt.getopt(argv, "m:p:i:o:s:t:vh", ["mode=", "password=", "input=", "output=", "salt=", "iteration=", "verbose", "help"])
        # Handle error
        except getopt.GetoptError:
            return

        # Get arguments
        for opt, arg in opts:
            if opt in ("-m", "--mode"):
                self.args.SetValue(arg.lower(), ArgumentTypes.MODE)
            elif opt in ("-p", "--password"):
                self.args.SetValue(arg, ArgumentTypes.PASSWORDS)
            elif opt in ("-i", "--input"):
                self.args.SetValue(arg, ArgumentTypes.INPUT_PATHS)
            elif opt in ("-o", "--output"):
                self.args.SetValue(arg, ArgumentTypes.OUTPUT_PATH)
            elif opt in ("-s", "--salt"):
                self.args.SetValue(arg, ArgumentTypes.SALT)
            elif opt in ("-t", "--iteration"):
                self.args.SetValue(arg, ArgumentTypes.ITR_NUM)
            elif opt in ("-v", "--verbose"):
                self.args.SetValue(True, ArgumentTypes.VERBOSE)
            elif opt in ("-h", "--help"):
                self.args.SetValue(True, ArgumentTypes.HELP)

    # Get arguments
    def GetArguments(self) -> Arguments:
        return self.args


#
# Functions
#

# Print usage
def PrintUsage() -> None:
    usage_str = """
Description:
    Simple utility for encrypting/decrypting files using AES256-CBC.

Usage:
    Encrypt: aes_cipher_app.py -m enc -p <PASSWORDS> -i <INPUT_FILE_OR_DIRECTORY> -o <OUTPUT_DIRECTORY> [-s <SALT>] [-t <ITR_NUM>] [-v]
    Decrypt: aes_cipher_app.py -m dec -p <PASSWORDS> -i <INPUT_FILE_OR_DIRECTORY> -o <OUTPUT_DIRECTORY> [-s <SALT>] [-t <ITR_NUM>] [-v]

Parameters:
    -m, --mode : operation mode, enc for encrypting, dec for decrypting.
    -p, --password : password used for encrypting/decrypting. It can be a single password or a list of passwords separated by a comma.
    -i, --input : input to be encrypted/decrypted. It can be a single file, a list of files separated by a comma or a folder (in this case all files in the folder will be encrypted/decrypted).
    -o, --output : output folder where the encrypted/decrypted files will be saved.
    -s, --salt : (optional) specify a custom salt for master key and IV derivation, otherwise the default salt "[]=?AeS_CiPhEr><()" will be used.
    -t, --iteration : (optional) specify the number of iteration for algorithm, otherwise the default value 524288 will be used.
    -v, --verbose : (optional) enable verbose mode.
"""
    print(usage_str)


# Run application
def RunApp(args: Arguments) -> None:
    enc_suffix: str = "_enc"

    # Get input files
    input_paths = args.GetValue(ArgumentTypes.INPUT_PATHS)
    if len(input_paths) == 0:
        print("No input files specified, exiting...")
        sys.exit(1)

    print("Input files: %s" % ", ".join([str(p) for p in input_paths]))

    # Get output path
    output_path = args.GetValue(ArgumentTypes.OUTPUT_PATH)

    # Creating output directory
    print("Creating output directory...")
    output_path.mkdir(parents=True, exist_ok=True)

    # Encrypt files
    if args.IsEncryptMode():
        for curr_path in input_paths:
            out_path = output_path / curr_path.with_stem(curr_path.stem + enc_suffix).name

            print("Encrypting file: '%s'..." % curr_path)

            file_encrypter = FileEncrypter()
            if args.IsVerbose():
                file_encrypter.Logger().SetLevel(logging.INFO)
            file_encrypter.Encrypt(
                curr_path,
                args.GetValue(ArgumentTypes.PASSWORDS),
                args.GetValue(ArgumentTypes.SALT),
                args.GetValue(ArgumentTypes.ITR_NUM))
            file_encrypter.SaveTo(out_path)

            print("Output file saved to: '%s'" % out_path)

    # Decrypt files
    elif args.IsDecryptMode():
        for curr_path in input_paths:
            out_path = output_path / curr_path.with_stem(curr_path.stem.replace(enc_suffix, "")).name

            print("Decrypting file: '%s'..." % curr_path)

            try:
                file_decrypter = FileDecrypter()
                if args.IsVerbose():
                    file_decrypter.Logger().SetLevel(logging.INFO)
                file_decrypter.Decrypt(
                    curr_path,
                    args.GetValue(ArgumentTypes.PASSWORDS),
                    args.GetValue(ArgumentTypes.SALT),
                    args.GetValue(ArgumentTypes.ITR_NUM))
                file_decrypter.SaveTo(out_path)

                print("Output file saved to: '%s'" % out_path)
            except DataHmacError:
                print("ERROR: file HMAC is not valid '%s'" % curr_path)
            except DataDecryptError:
                print("ERROR: unable to decrypt file '%s'" % curr_path)

    # Output text
    print("Operation completed")


# Main
def main(argv: List[str]) -> None:
    # Get arguments
    args_parser = ArgumentsParser()
    args_parser.Parse(argv)
    args = args_parser.GetArguments()

    # Check arguments
    if not args.AreValid():
        PrintUsage()
        sys.exit(1)

    # Print help if needed
    if args.IsHelpNeeded():
        PrintUsage()
        sys.exit(0)

    # Run application
    RunApp(args)


# Execute main
if __name__ == "__main__":
    main(sys.argv[1:])
