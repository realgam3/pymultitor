#!/usr/bin/env python

import re
from os import path
from setuptools import setup, find_packages

__folder__ = path.dirname(__file__)

with open(path.join(__folder__, "README.md")) as ld_file:
    long_description = ld_file.read()
    ld_file.flush()

with open(path.join(__folder__, "pymultitor.py")) as lib_file:
    r = re.search(r"__version__\s+=\s+(?P<q>[\"'])(?P<ver>\d+(?:\.\d+)*)(?P=q)", lib_file.read())
    version = r.group('ver')

with open(path.join(__folder__, "requirements.txt")) as req_file:
    install_requires = req_file.read()

setup(
    name="PyMultitor",
    version=version,
    description="PyMultitor - Never Stop Even If Your IP Dropped.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Tomer Zait (realgam3)",
    author_email="realgam3@gmail.com",
    packages=find_packages(exclude=["examples", "tests"]),
    py_modules=["pymultitor"],
    entry_points={
        "console_scripts": [
            "pymultitor = pymultitor:main",
        ]
    },
    python_requires=">=3.10",
    install_requires=install_requires,
    license="GPLv3",
    platforms="any",
    url="https://github.com/realgam3/pymultitor",
    zip_safe=False,
    classifiers=[
        "Environment :: Console",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
        "Topic :: Internet",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    project_urls={
        'Source': "https://github.com/realgam3/pymultitor",
    },
)
