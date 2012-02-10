#!/usr/bin/env python

from setuptools import setup
import kestrelpy

setup(name="python-kestrel",
      version=kestrelpy.__version__,
      description="Pure python kestrel client",
      long_description=open("README").read(),
      author="Eric Moritz",
      author_email="eric@themoritzfamily.com",
      py_modules=["kestrelpy"],
      #classifiers=[
      #  "Development Status :: 1 - Production/Stable",
      #  "Intended Audience :: Developers",
      #  "License :: OSI Approved :: Python Software Foundation License",
      #  "Operating System :: OS Independent",
      #  "Programming Language :: Python",
      #  "Topic :: Internet",
      #  "Topic :: Software Development :: Libraries :: Python Modules",
      #  ]
)

