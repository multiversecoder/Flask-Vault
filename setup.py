"""
Flask-Vault Setup.py
"""
from typing import List
from setuptools import (
    find_packages,
    setup,
)


def parse_requirements(filename: str) -> List[str]:
    """load requirements from a pip requirements file"""
    liter = (line.strip() for line in open(filename))
    return [line for line in liter if line and not line.startswith("#")]


readme = "./README.md"
requirements = parse_requirements("./requirements.txt")
LICENSE = "MIT License"
VERSION = "0.2.0"

with open(readme) as f:
    long_description = f.read()


setup(
    include_package_data=True,
    name="Flask-Vault",
    version=VERSION,
    description="Secure Credential Storage for Flask",
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires="!=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    keywords="Flask, Flask-Vault, Flask Vault, Flask Credentials, AES GCM Encryption, Flask AES",
    author="Adriano Romanazzo (multiversecoder)",
    author_email="pythonmultiverse@gmx.com",
    url="https://github.com/multiversecoder/Flask-Vault",
    project_urls={"Issue Tracker": "https://github.com/multiversecoder/Flask-Vault/issues"},
    license=LICENSE,
    packages=find_packages(".", exclude=["test*", "*test*"]),
    zip_safe=False,
    install_requires=requirements,
    package_dir={"flask_vault": "flask_vault"},
)
