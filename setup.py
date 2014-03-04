#!/usr/bin/python
from setuptools import setup, find_packages
import os

setup(name='python-ldap-vlv',
        version='1.0',
        license='AGPLv3',
        description='LDAP VLV Extension support',
        author="Entr'ouvert",
        author_email="info@entrouvert.com",
        packages=find_packages(os.path.dirname(__file__) or '.'),
        install_requires=[
            'python-ldap',
            'pyasn1',
        ],
)
