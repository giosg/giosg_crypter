import os
from setuptools import setup, find_packages


__copyright__ = 'Copyright (C) 2019, Giosg.com'

VERSIONFILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'src', 'giosg', 'crypter', '_version.py')


def version():
    import importlib
    spec = importlib.util.spec_from_file_location('_version', VERSIONFILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.get_version()


def readme():
    with open(os.path.join(os.path.dirname(__file__), 'README.md')) as f:
        return f.read()


setup(
    name='giosg.crypter',
    version=version(),
    packages=find_packages('src'),
    package_dir={'': 'src'},
    namespace_packages=['giosg'],
    entry_points={
        'console_scripts': ['decrypt=giosg.crypter.cli:run'],
    },
    author='Giosg.com',
    license='Apache License 2.0',
    description='Decrypt helper for Giosg products',
    url='https://github.com/giosg/giosg_crypter',
    long_description=readme(),
    install_requires=[
        'cryptography',
        'pycryptodomex',
        'requests'
    ],
    tests_require=[
        'tox',
        'flake8'
    ]
)
