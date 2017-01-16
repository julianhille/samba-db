# -*- coding: utf-8 -*-
"""Packaging logic for Sambadb."""

import ast
import re

from setuptools import setup


_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('sambadb/__init__.py', 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))


setup(
    name='sambadb',
    version=version,
    url='https://github.com/julianhille/samba-db',
    author='Julian Hille',
    description='Read and write samba *.tbd files and its packed content.',
    packages=['sambadb'],
    include_package_data=True,
    zip_safe=True,
    platforms='any',
    install_requires=[],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking'
    ],
    tests_requires=['mock >= 2.0.0', 'pytest'],
    setup_requires=['pytest-runner'],
)
