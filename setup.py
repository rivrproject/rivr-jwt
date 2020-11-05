#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='rivr-jwt',
    version='0.2.0',
    description='Making authentication with JWT (JSON Web Token) and rivr simple.',
    url='https://github.com/rivrproject/rivr-jwt',
    packages=find_packages(),
    package_data={
        'rivr_jwt': ['py.typed'],
    },
    install_requires=[
        'rivr>=0.9.0',
        'PyJWT',
    ],
    author='Kyle Fuller',
    author_email='kyle@fuller.li',
    license='BSD',
    classifiers=(
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'License :: OSI Approved :: BSD License',
    ),
)
