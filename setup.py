import os
import setuptools
import re


# Load long description
def load_long_description(desc_file):
    return open(desc_file).read()


# Load version
def load_version(*path_parts):
    version_file = os.path.join(*path_parts)
    version_line = open(os.path.join(*path_parts)).read().rstrip()
    vre = re.compile(r'__version__: str = "([^"]+)"')
    matches = vre.findall(version_line)

    if matches and len(matches) > 0:
        return matches[0]

    raise RuntimeError(f"Cannot find version string in {version_file}")


# Load requirements
def load_requirements(req_file):
    with open(req_file, "r") as fin:
        return [line for line in map(str.strip, fin.read().splitlines())
                if len(line) > 0 and not line.startswith("#")]


# Load version
version = load_version("aes_cipher", "_version.py")

setuptools.setup(
    name="aes_cipher",
    version=version,
    author="Emanuele Bellocchia",
    author_email="ebellocchia@gmail.com",
    maintainer="Emanuele Bellocchia",
    maintainer_email="ebellocchia@gmail.com",
    description="Cipher based on AES256-CBC",
    long_description=load_long_description("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/ebellocchia/aes_cipher",
    download_url="https://github.com/ebellocchia/aes_cipher/archive/v%s.tar.gz" % version,
    license="MIT",
    test_suite="tests",
    install_requires=load_requirements("requirements.txt"),
    packages=setuptools.find_packages(exclude=["tests"]),
    keywords="cipher, aes, aes256, sha, sha256, sha512, pbkdf2, pbkdf2-sha512, hmac, hmac-sha256",
    platforms=["any"],
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.7",
)
