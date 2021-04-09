import setuptools
import re

VERSION_FILE = "aes_cipher/_version.py"

with open("README.md", "r") as f:
    long_description = f.read()

def load_version():
    version_line = open(VERSION_FILE).read().rstrip()
    vre = re.compile(r'__version__ = "([^"]+)"')
    matches = vre.findall(version_line)

    if matches and len(matches) > 0:
        return matches[0]
    else:
        raise RuntimeError("Cannot find version string in %s" % VERSION_FILE)

version = load_version()

setuptools.setup(
    name="aes_cipher",
    version=version,
    author="Emanuele Bellocchia",
    author_email="ebellocchia@gmail.com",
    maintainer="Emanuele Bellocchia",
    maintainer_email="ebellocchia@gmail.com",
    description="Cipher based on AES256-CBC",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ebellocchia/aes_cipher",
    download_url="https://github.com/ebellocchia/aes_cipher/archive/v%s.tar.gz" % version,
    license="MIT",
    test_suite="tests",
    install_requires = ["pycryptodome"],
    packages=setuptools.find_packages(exclude=["tests"]),
    keywords="cipher, aes, aes256, sha, sha256, sha512, pbkdf2, pbkdf2-sha512, hmac, hmac-sha256",
    platforms = ["any"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.7",
)
