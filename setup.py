#!/usr/bin/env python

import re
from os import path
from setuptools import setup, find_packages

__folder__ = path.dirname(__file__)

with open(path.join(__folder__, 'README.md')) as ld_file:
    long_description = ld_file.read()
    ld_file.flush()

with open(path.join(__folder__, 'pymultitor.py')) as lib_file:
    r = re.search(r'__version__\s+=\s+(?P<q>["\'])(?P<ver>\d+(?:\.\d+)*)(?P=q)', lib_file.read())
    version = r.group('ver')

setup(
    name='PyMultitor',
    version=version,
    description='PyMultitor - Never Stop Even If Your IP Dropped.',
    long_description=long_description,
    author='RealGame (Tomer Zait)',
    author_email='realgam3@gmail.com',
    packages=find_packages(exclude=['examples', 'tests']),
    py_modules=['pymultitor'],
    entry_points={
        'console_scripts': [
            'pymultitor = pymultitor:main',
        ]
    },
    install_requires=[
        'stem >= 1.5.4',
        'PySocks >= 1.5.6, != 1.5.7',
        'requests >= 2.9.1, < 2.12.0',
        'mitmproxy >= 0.18.3, < 3.0.0',
    ],
    license="GPLv3",
    platforms='any',
    url='https://github.com/realgam3/pymultitor',
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Natural Language :: English',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Software Development :: Testing',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
