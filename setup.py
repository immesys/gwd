#!/usr/bin/env python

from setuptools import setup

setup(
    name="gwd",
    version="1.0.0",
    description="Global Watch Dog",
    author="Michael Andersen",
    url="https://github.com/immesys/gwd-python",
    packages=["gwd"],
    install_requires = ['requests']
    )
