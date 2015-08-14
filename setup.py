#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='rivr-jwt',
    version='0.1.0',
    description='Making authentication with JWT (JSON Web Token) and rivr simple.',
    url='https://github.com/rivrproject/rivr-jwt',
    packages=find_packages(),
    install_requires=[
        'rivr',
        'PyJWT',
    ],
    author='Kyle Fuller',
    author_email='kyle@fuller.li',
    license='BSD',
    classifiers=(
      'Programming Language :: Python :: 2',
      'Programming Language :: Python :: 2.7',
      'Programming Language :: Python :: 3',
      'Programming Language :: Python :: 3.2',
      'Programming Language :: Python :: 3.3',
      'Programming Language :: Python :: 3.4',
      'License :: OSI Approved :: BSD License',
    )
)

