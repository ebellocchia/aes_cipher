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
import logging


#
# Classes
#

# Constant for logger class
class LoggerConst:
    LOG_FORMAT: str = "  LOG %(levelname)s - %(message)s"


# Logger class
class Logger:
    # Constructor
    def __init__(self,
                 name: str = "") -> None:
        self.__CreateLogger(name)
        self.__ConfigureLogger()
        self.SetVerbose(False)

    # Get logger
    def GetLogger(self) -> logging.Logger:
        return self.logger

    # Set verbose
    def SetVerbose(self,
                   is_verbose: bool) -> None:
        self.logger.setLevel(logging.INFO if is_verbose else logging.WARNING)

    # Create logger
    def __CreateLogger(self,
                       name: str) -> None:
        self.logger = logging.getLogger(name)

    # Configure logger
    @staticmethod
    def __ConfigureLogger() -> None:
        logging.basicConfig(format=LoggerConst.LOG_FORMAT)
