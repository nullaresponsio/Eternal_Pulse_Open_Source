# setup.py
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="eternal_pulse",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced SMB scanner and security toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/eternal_pulse",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking"
    ],
    python_requires='>=3.8',
    install_requires=[
        'cryptography>=3.4',
        'ipaddress>=1.0.23',
        'python-dateutil>=2.8.2'
    ],
    extras_require={
        'full': [
            'scapy>=2.4.5',
            'python-nmap>=0.7.1',
            'smbprotocol>=1.6.0'
        ]
    },
    entry_points={
        'console_scripts': [
            'eternal-pulse=eternal_pulse.__main__:main'
        ]
    }
)