#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ast
import codecs
import os
import re

from setuptools import find_packages, setup

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))
init = os.path.join(ROOT, 'src', 'flower_oauth_azure', '__init__.py')

_version_re = re.compile(r'__version__\s+=\s+(.*)')
_name_re = re.compile(r'NAME\s+=\s+(.*)')

with open(init, 'rb') as f:
    content = f.read().decode('utf-8')
    version = str(ast.literal_eval(_version_re.search(content).group(1)))
    name = str(ast.literal_eval(_name_re.search(content).group(1)))

readme = codecs.open('README.md').read()

setup(name=name,
      version=version,
      description="""Azure Oauth support for Flower""",
      long_description=readme,
      author='',
      author_email='',
      url='https://github.com/saxix/flower_oauth_azure',
      package_dir={'': 'src'},
      packages=find_packages('src'),
      install_requires=['pyjwt', ],
      extras_require={'verification': ['cryptography']},
      include_package_data=True,
      license="MIT",
      zip_safe=False,
      keywords='',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: MIT',
          'Natural Language :: English',
          'Programming Language :: Python :: 3.6',
      ])
