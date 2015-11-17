
from setuptools import setup, find_packages

setup(
    name="riffle",
    version="0.1.50",
    author="damouse",
    description="Client libraries for ",
    install_requires=[
        'docopt>=0.6.2',
        'twisted>=14.2',
        'autobahn==0.10.5.post2',
        'pycrypto==2.6.1',
        'pyOpenSSL==0.15.1',
        'bcrypt==2.0.0',
        'service-identity==14.0.0'
    ],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'riffle=riffle.main:main',
        ],
    },
)
